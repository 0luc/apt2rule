import { findTerm, indexTexts, termWords, type IndexedText } from "./match";
import { targetGroups } from "./targets";
import type { Attribution, GroupReason, Hit, Suggestion, T2aDataset, T2aGroup, T2aProfile, TargetGroup, TargetMatch, Tier } from "./types";

export type * from "./types";

/** Everything derived from the dataset once, independent of the profile. */
export interface Context {
  dataset: T2aDataset;
  targets: TargetGroup[];
  targetsById: Map<string, TargetGroup>;
  countryNames: Map<string, string>;
  index: Map<string, IndexedText[]>;
}

export function prepare(dataset: T2aDataset): Context {
  const targets = targetGroups(dataset.countries);
  return {
    dataset,
    targets,
    targetsById: new Map(targets.map((t) => [t.id, t])),
    countryNames: new Map(dataset.countries.map((c) => [c.code, c.name])),
    index: indexTexts(dataset.groups, dataset.countries),
  };
}

export const CUSTOM = "custom:";

/** Target matches of one group for the ticked target groups and custom terms, in the order given. */
export function matchGroup(ctx: Context, group: T2aGroup, targetIds: string[], customTerms: string[]): TargetMatch[] {
  const texts = ctx.index.get(group.id) ?? [];
  const wanted: { id: string; label: string; terms: string[]; country?: string }[] = [
    ...targetIds.flatMap((id) => {
      const t = ctx.targetsById.get(id);
      return t ? [{ id, label: t.label, terms: t.terms, country: t.country }] : [];
    }),
    ...[...new Set(customTerms.map((t) => t.trim()).filter(Boolean))].map((term) => ({ id: CUSTOM + term, label: `“${term}”`, terms: [term] })),
  ];
  const matches: TargetMatch[] = [];
  for (const target of wanted) {
    const hits: Hit[] = [];
    texts.forEach((text, i) => {
      for (const term of target.terms) {
        for (const [start, end] of findTerm(term, text, target.country)) {
          hits.push({ target: target.id, term, source: text.source, sourceName: text.sourceName, text: i, start, end });
        }
      }
    });
    if (!hits.length) continue;
    hits.sort((a, b) => a.text - b.text || a.start - b.start);
    matches.push({ target: target.id, label: target.label, terms: [...new Set(hits.map((h) => h.term))], hits });
  }
  return matches;
}

/** Ranked suggestions for a profile: only shown tiers, after the last-seen filter. */
export function suggest(ctx: Context, profile: T2aProfile): Suggestion[] {
  const countries = new Set(profile.countries);
  const tiers = new Set(profile.tiers);
  const suggestions: Suggestion[] = [];
  for (const group of ctx.dataset.groups) {
    if (!seenOk(group, profile)) continue;
    const countryMatches = group.attribution.filter((a) => countries.has(a.country));
    const targetMatches = matchGroup(ctx, group, profile.targets, profile.customTerms);
    const tier = tierOf(countryMatches.length > 0, targetMatches.length > 0);
    if (!tier || !tiers.has(tier)) continue;
    suggestions.push({ group, tier, countryMatches, targetMatches, picked: profile.picks[group.id] ?? tier === 1 });
  }
  return suggestions.sort(
    (a, b) =>
      a.tier - b.tier ||
      b.targetMatches.length - a.targetMatches.length ||
      (b.group.lastSeen ?? "").localeCompare(a.group.lastSeen ?? "") ||
      a.group.name.localeCompare(b.group.name),
  );
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
    for (const term of target.terms) {
      const sets = termWords(term).map((w) => groupsWithWord.get(w) ?? new Set<string>());
      if (!sets.length) continue;
      sets.sort((a, b) => a.size - b.size);
      for (const groupId of sets[0]!) {
        if (matched.has(groupId) || !sets.every((s) => s.has(groupId))) continue;
        if (ctx.index.get(groupId)!.some((text) => findTerm(term, text, target.country).length)) matched.add(groupId);
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
    matched: s.targetMatches.map((m) => ({ target: m.label, terms: m.terms })),
    lastSeen: s.group.lastSeen,
  };
}

export function attributionLabel(ctx: Context, attribution: Attribution[]): string {
  return attribution.map((a) => ctx.countryNames.get(a.country) ?? a.country).join(", ") || "unknown";
}

/** The picked suggestions as a Markdown table and CSV, for the threat analysis report. */
export function buildTable(ctx: Context, suggestions: Suggestion[]): { markdown: string; csv: string } {
  const header = ["Group", "ATT&CK ID", "Tier", "Attributed to", "Attribution evidence", "Matched targets", "Last seen"];
  const rows = suggestions.map((s) => [
    s.group.name,
    s.group.id,
    String(s.tier),
    attributionLabel(ctx, s.group.attribution),
    s.countryMatches.map((a) => `${a.evidence} (${a.source})`).join(" "),
    s.targetMatches.map((m) => `${m.label}: ${m.terms.join(", ")}`).join("; "),
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
  1: "Tier 1: country and target",
  2: "Tier 2: target only",
  3: "Tier 3: country only",
};
