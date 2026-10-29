import { buildCsv, buildMarkdown, ruleIdList, type ReportInput } from "./report";
import { buildRequests, DEFAULT_CHUNK_SIZE, renderSnippets, tagNames } from "./snippet";
import type { Dataset, Group, Profile, Provenance, Result, Rule, RunOptions, TechniqueRow } from "./types";

export type * from "./types";
export { techniqueStatus } from "./report";

export function run(dataset: Dataset, profile: Profile, date: string, options: RunOptions = {}): Result {
  const { groups, overrides, warnings } = resolveProfile(dataset, profile);
  const provenances: Provenance[] = profile.includeSoftware ? ["direct", "campaign", "software"] : ["direct", "campaign"];
  const techniqueNames = new Map(dataset.techniques.map((t) => [t.id, t.name]));

  const rows = new Map<string, TechniqueRow>();
  for (const group of groups) {
    for (const via of provenances) {
      for (const id of group.techniques[via]) {
        let row = rows.get(id);
        if (!row) {
          row = { id, name: techniqueNames.get(id) ?? id, groups: [], count: 0, included: false, selectedRuleIds: [], filteredRuleIds: [] };
          rows.set(id, row);
        }
        const entry = row.groups.find((g) => g.id === group.id);
        if (entry) {
          if (!entry.via.includes(via)) entry.via.push(via);
        } else {
          row.groups.push({ id: group.id, via: [via] });
        }
      }
    }
  }
  for (const row of rows.values()) {
    row.count = row.groups.length;
    const override = overrides.get(row.id);
    row.included = override ? override === "include" : row.count >= profile.minGroups;
  }
  const techniqueRows = [...rows.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  const techniques = new Set(techniqueRows.filter((t) => t.included).map((t) => t.id));

  const isCandidate = (r: Rule) =>
    r.techniques.some((t) => techniques.has(t)) &&
    (profile.includeBuildingBlocks || !r.buildingBlock) &&
    (profile.includeMl || r.type !== "machine_learning");
  const passesTagFilter = tagFilter(profile.tagFilters);

  const selected: Rule[] = [];
  const filtered: Rule[] = [];
  const noApt: Rule[] = [];
  for (const rule of dataset.rules) {
    if (!isCandidate(rule)) noApt.push(rule);
    else if (passesTagFilter(rule)) selected.push(rule);
    else filtered.push(rule);
  }
  for (const [list, key] of [[selected, "selectedRuleIds"], [filtered, "filteredRuleIds"]] as const) {
    for (const rule of list) {
      for (const t of rule.techniques) {
        const row = rows.get(t);
        if (row?.included) row[key].push(rule.ruleId);
      }
    }
  }

  const requests = buildRequests(
    selected.map((r) => r.ruleId),
    noApt.map((r) => r.ruleId),
    date,
    options.chunkSize ?? DEFAULT_CHUNK_SIZE,
  );

  const tags = tagNames(date);
  const report: ReportInput = { dataset, profile, date, groups, techniques: techniqueRows, selected, filtered, noApt, tags };

  return {
    warnings,
    techniques: techniqueRows,
    selected,
    filtered,
    noApt,
    tags,
    requests,
    snippets: renderSnippets(requests, dataset, profile, date),
    report: { markdown: buildMarkdown(report), csv: buildCsv(report) },
    ruleIdList: ruleIdList(selected),
  };
}

/** Maps the profile's saved IDs onto this dataset, following ATT&CK redirects. */
function resolveProfile(dataset: Dataset, profile: Profile) {
  const attack = `ATT&CK ${dataset.attack.version}`;
  const warnings: string[] = [];
  const groupsById = new Map(dataset.groups.map((g) => [g.id, g]));
  const groups: Group[] = [];
  for (const savedId of profile.groups) {
    const id = dataset.groupRedirects[savedId] ?? savedId;
    const group = groupsById.get(id);
    if (!group) {
      warnings.push(`Group ${savedId} does not exist in ${attack} and was ignored.`);
      continue;
    }
    if (id !== savedId) warnings.push(`Group ${savedId} was replaced by ${id} (${group.name}) in ${attack}.`);
    if (!groups.includes(group)) groups.push(group);
  }

  const known = new Set(dataset.techniques.map((t) => t.id));
  const overrides = new Map<string, "include" | "exclude">();
  for (const [savedId, value] of Object.entries(profile.techniqueOverrides)) {
    const id = dataset.techniqueRedirects[savedId] ?? savedId;
    if (!known.has(id)) {
      warnings.push(`Technique ${savedId} does not exist in ${attack}; its override was ignored.`);
      continue;
    }
    if (id !== savedId) warnings.push(`Technique ${savedId} was replaced by ${id} in ${attack}.`);
    overrides.set(id, value);
  }

  const tags = new Set(dataset.tags);
  for (const tag of profile.tagFilters) {
    if (!tags.has(tag)) warnings.push(`Tag ${tag} does not exist in Elastic ruleset ${dataset.ruleset.packageVersion} and was ignored.`);
  }
  return { groups, overrides, warnings };
}

/** The category of a Kibana tag: the text before the first ":" ("Data Source", "OS", ...). */
export function tagCategory(tag: string): string {
  const i = tag.indexOf(":");
  return i === -1 ? "Other" : tag.slice(0, i).trim();
}

/** Within a category any ticked tag matches; every category with ticked tags must match. */
function tagFilter(ticked: string[]): (rule: Rule) => boolean {
  const byCategory = new Map<string, Set<string>>();
  for (const tag of ticked) {
    const category = tagCategory(tag);
    byCategory.set(category, (byCategory.get(category) ?? new Set()).add(tag));
  }
  return (rule) => [...byCategory.values()].every((wanted) => rule.tags.some((t) => wanted.has(t)));
}
