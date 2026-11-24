import { findTerm, indexTexts, termWords, type IndexedText } from "./match";
import { RANSOMWARE, targetGroups } from "./targets";
import type {
  Attribution,
  Country,
  Exclusion,
  GroupReason,
  Hit,
  Location,
  Suggestion,
  T2aDataset,
  T2aGroup,
  T2aProfile,
  TargetGroup,
  TargetMatch,
  Tier,
} from "./types";

export type * from "./types";
export { RANSOMWARE };

/** Everything derived from the dataset once, independent of the profile. */
export interface Context {
  dataset: T2aDataset;
  targets: TargetGroup[];
  targetsById: Map<string, TargetGroup>;
  countryNames: Map<string, string>;
  countriesByCode: Map<string, Country>;
  index: Map<string, IndexedText[]>;
  /** Per group: every region and country its texts name, except the countries it is attributed to. */
  places: Map<string, TargetMatch[]>;
}

export function prepare(dataset: T2aDataset): Context {
  const targets = targetGroups(dataset.countries);
  const ctx: Context = {
    dataset,
    targets,
    targetsById: new Map(targets.map((t) => [t.id, t])),
    countryNames: new Map(dataset.countries.map((c) => [c.code, c.name])),
    countriesByCode: new Map(dataset.countries.map((c) => [c.code, c])),
    index: indexTexts(dataset.groups, dataset.countries),
    places: new Map(),
  };
  const placeIds = targets.filter((t) => t.kind === "region" || t.kind === "country").map((t) => t.id);
  for (const group of dataset.groups) {
    const own = ownCountries(group);
    ctx.places.set(group.id, matchGroup(ctx, group, placeIds, [], own).filter((m) => !own.has(m.target.replace(/^country:/, ""))));
  }
  return ctx;
}

export const CUSTOM = "custom:";

type Term = { term: string; country?: string };

/** What a target group searches for: its own terms, and for a region its countries' terms (minus `skip`). */
function searchTerms(ctx: Context, t: TargetGroup, skip: Set<string> = new Set()): Term[] {
  const members = (t.countries ?? [])
    .filter((code) => !skip.has(code))
    .flatMap((code) => (ctx.countriesByCode.get(code)?.terms ?? []).map((term) => ({ term, country: code })));
  return [...t.terms.map((term) => ({ term, country: t.country })), ...members];
}

/** The countries a group is attributed to: naming them says where it is from, not whom it targets. */
function ownCountries(group: T2aGroup): Set<string> {
  return new Set(group.attribution.map((a) => a.country));
}

/**
 * Target matches of one group for the ticked target groups and custom terms, in the order given.
 * A region also matches the terms of its countries, except those in `skipCountries`.
 */
export function matchGroup(
  ctx: Context,
  group: T2aGroup,
  targetIds: string[],
  customTerms: string[],
  skipCountries: Set<string> = new Set(),
): TargetMatch[] {
  const texts = ctx.index.get(group.id) ?? [];
  const wanted: { id: string; label: string; terms: Term[] }[] = [
    ...targetIds.flatMap((id) => {
      const t = ctx.targetsById.get(id);
      return t ? [{ id, label: t.label, terms: searchTerms(ctx, t, skipCountries) }] : [];
    }),
    ...[...new Set(customTerms.map((t) => t.trim()).filter(Boolean))].map((term) => ({ id: CUSTOM + term, label: `“${term}”`, terms: [{ term }] })),
  ];
  const matches: TargetMatch[] = [];
  for (const target of wanted) {
    const hits: Hit[] = [];
    texts.forEach((text, i) => {
      for (const { term, country } of target.terms) {
        for (const [start, end] of findTerm(term, text, country)) {
          hits.push({ target: target.id, term, source: text.source, sourceName: text.sourceName, text: i, start, end });
        }
      }
    });
    if (!hits.length) continue;
    hits.sort((a, b) => a.text - b.text || a.start - b.start || b.end - a.end);
    // a region's own term and one of its countries' terms can hit the same words ("United States")
    const unique = hits.filter((h, i) => i === 0 || h.text !== hits[i - 1]!.text || h.start !== hits[i - 1]!.start);
    hits.splice(0, hits.length, ...unique);
    matches.push({ target: target.id, label: target.label, terms: [...new Set(hits.map((h) => h.term))], hits });
  }
  return matches;
}

const LOCATION_RANK: Record<Location, number> = { area: 0, unknown: 1, elsewhere: 2 };

/** Ranked suggestions for a profile: only shown tiers, after the last-seen and elsewhere filters. */
export function suggest(ctx: Context, profile: T2aProfile): Suggestion[] {
  const countries = new Set(profile.countries);
  const tiers = new Set(profile.tiers);
  const area = new Set(profile.area);
  const suggestions: Suggestion[] = [];
  for (const group of ctx.dataset.groups) {
    if (!seenOk(group, profile)) continue;
    const countryMatches = group.attribution.filter((a) => countries.has(a.country));
    const ransomwareMatch = profile.ransomware ? (matchGroup(ctx, group, [RANSOMWARE], [])[0] ?? null) : null;
    const targetMatches = matchGroup(ctx, group, profile.targets, profile.customTerms);
    const threat = countryMatches.length > 0 || ransomwareMatch !== null;
    const tier = tierOf(threat, targetMatches.length > 0);
    if (!tier || !tiers.has(tier)) continue;
    const places = ctx.places.get(group.id) ?? [];
    const inArea = places.filter((m) => area.has(m.target));
    const location: Location | null = !area.size ? null : inArea.length ? "area" : places.length ? "elsewhere" : "unknown";
    if (location === "elsewhere" && profile.hideElsewhere) continue;
    const excludedBy = exclusionsFor(ctx, group, countryMatches, ransomwareMatch !== null, profile.exclusions);
    // attributed, but only to countries the threat assessment doesn't name
    const foreign = !threat && group.attribution.length > 0;
    const defaultPicked =
      !excludedBy.length &&
      (!location ? tier === 1 : location === "area" ? !foreign : location === "unknown" && ransomwareMatch !== null);
    suggestions.push({
      group,
      tier,
      countryMatches,
      ransomwareMatch,
      targetMatches,
      location,
      locationMatches: location === "elsewhere" ? places : inArea,
      excludedBy,
      defaultPicked,
      picked: profile.picks[group.id] ?? defaultPicked,
    });
  }
  return suggestions.sort(
    (a, b) =>
      a.tier - b.tier ||
      (a.location ? LOCATION_RANK[a.location] : 0) - (b.location ? LOCATION_RANK[b.location] : 0) ||
      b.targetMatches.length - a.targetMatches.length ||
      (b.group.lastSeen ?? "").localeCompare(a.group.lastSeen ?? "") ||
      a.group.name.localeCompare(b.group.name),
  );
}

/** The exclusion rules of the group's threats (ticked countries, ransomware) that its texts match. */
function exclusionsFor(
  ctx: Context,
  group: T2aGroup,
  countryMatches: Attribution[],
  ransomware: boolean,
  exclusions: T2aProfile["exclusions"],
): Exclusion[] {
  const out: Exclusion[] = [];
  const threats = new Set(countryMatches.map((a) => a.country));
  if (ransomware) threats.add("ransomware");
  for (const country of threats) {
    const ids = exclusions[country] ?? [];
    const matches = ids.length ? matchGroup(ctx, group, ids, [], ownCountries(group)) : [];
    if (matches.length) out.push({ country, matches });
  }
  return out;
}

export function tierOf(country: boolean, target: boolean): Tier | null {
  if (country && target) return 1;
  if (target) return 2;
  if (country) return 3;
  return null;
}

function seenOk(group: T2aGroup, profile: T2aProfile): boolean {
  if (profile.seenSince === null) return true;
  if (group.lastSeen === null) return !profile.hideUnknownSeen;
  return Number(group.lastSeen.slice(0, 4)) >= profile.seenSince;
}

/** Number of groups attributed to each country. */
export function countryCounts(dataset: T2aDataset): Map<string, number> {
  const counts = new Map<string, number>();
  for (const g of dataset.groups) for (const a of g.attribution) counts.set(a.country, (counts.get(a.country) ?? 0) + 1);
  return counts;
}

/** Number of groups each target group matches on its own. Uses a word index: most terms occur in few groups. */
export function targetCounts(ctx: Context): Map<string, number> {
  const groupsWithWord = new Map<string, Set<string>>();
  for (const [groupId, texts] of ctx.index) {
    for (const text of texts) {
      for (const w of text.words) {
        let set = groupsWithWord.get(w);
        if (!set) groupsWithWord.set(w, (set = new Set()));
        set.add(groupId);
      }
    }
  }
  const counts = new Map<string, number>();
  for (const target of ctx.targets) {
    const matched = new Set<string>();
    for (const { term, country } of searchTerms(ctx, target)) {
      const sets = termWords(term).map((w) => groupsWithWord.get(w) ?? new Set<string>());
      if (!sets.length) continue;
      sets.sort((a, b) => a.size - b.size);
      for (const groupId of sets[0]!) {
        if (matched.has(groupId) || !sets.every((s) => s.has(groupId))) continue;
        if (ctx.index.get(groupId)!.some((text) => findTerm(term, text, country).length)) matched.add(groupId);
      }
    }
    if (matched.size) counts.set(target.id, matched.size);
  }
  return counts;
}

export function reasonFor(ctx: Context, s: Suggestion, profile: T2aProfile, date: string): GroupReason {
  return {
    source: "threat2apt",
    date,
    profile: profile.name,
    attackVersion: ctx.dataset.attack.version,
    tier: s.tier,
    countries: s.countryMatches.map((a) => ({ code: a.country, name: ctx.countryNames.get(a.country) ?? a.country, evidence: a.evidence, source: a.source })),
    ...(s.ransomwareMatch ? { ransomware: s.ransomwareMatch.terms } : {}),
    matched: s.targetMatches.map((m) => ({ target: m.label, terms: m.terms })),
    ...(s.location ? { location: { status: s.location, places: s.locationMatches.map((m) => m.label) } } : {}),
    lastSeen: s.group.lastSeen,
  };
}

/** "your area: Europe", "elsewhere: Japan", "unknown"; empty without an area. */
export function locationLabel(s: Suggestion): string {
  if (!s.location) return "";
  const places = s.locationMatches.map((m) => m.label).join(", ");
  return s.location === "area" ? `your area: ${places}` : s.location === "elsewhere" ? `elsewhere: ${places}` : "unknown";
}

export function attributionLabel(ctx: Context, attribution: Attribution[]): string {
  return attribution.map((a) => ctx.countryNames.get(a.country) ?? a.country).join(", ") || "unknown";
}

/** The picked suggestions as a Markdown table and CSV, for the threat analysis report. */
export function buildTable(ctx: Context, suggestions: Suggestion[]): { markdown: string; csv: string } {
  const header = ["Group", "ATT&CK ID", "Tier", "Attributed to", "Attribution evidence", "Ransomware", "Matched sectors", "Location", "Last seen"];
  const rows = suggestions.map((s) => [
    s.group.name,
    s.group.id,
    String(s.tier),
    attributionLabel(ctx, s.group.attribution),
    s.countryMatches.map((a) => `${a.evidence} (${a.source})`).join(" "),
    s.ransomwareMatch?.terms.join(", ") ?? "",
    s.targetMatches.map((m) => `${m.label}: ${m.terms.join(", ")}`).join("; "),
    locationLabel(s),
    s.group.lastSeen ?? "unknown",
  ]);
  const md = (cell: string) => cell.replace(/\|/g, "\\|").replace(/\s+/g, " ");
  const markdown = [header, header.map(() => "---"), ...rows].map((r) => `| ${r.map(md).join(" | ")} |`).join("\n") + "\n";
  const csvCell = (cell: string) => (/[",\n]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell);
  const csv = [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
  return { markdown, csv };
}

/** The tier names, as shown in the page and in reasons. */
export const TIER_LABELS: Record<Tier, string> = {
  1: "Tier 1: threat and sector",
  2: "Tier 2: sector only",
  3: "Tier 3: threat only",
};
