import type { BulkTagRequest, Dataset, Profile } from "./types";

const BULK_ACTION = "kbn:/api/detection_engine/rules/_bulk_action";
// Saved-object fields of a detection rule in Kibana's rules KQL (rule_id verified on Kibana 9.x).
const RULE_ID_FIELD = "alert.attributes.params.ruleId";
const TAGS_FIELD = "alert.attributes.tags";

export function tagName(date: string) {
  return `apt2rule:${date}`;
}

/**
 * Builds the add_tags bulk requests for the selected rules, listed by rule_id: one dry run and one
 * apply, each a single request. Rules carrying an ignored tag are excluded by Kibana itself:
 * apt2rule can't see tags added in the cluster.
 */
export function buildRequests(selectedIds: string[], ignoreTags: string[], date: string): BulkTagRequest[] {
  if (!selectedIds.length) return [];
  const query = ruleIdQuery([...selectedIds].sort()) + ignoreClause(ignoreTags);
  return [true, false].map((dryRun) => ({
    dryRun,
    expected: selectedIds.length,
    method: "POST" as const,
    path: dryRun ? `${BULK_ACTION}?dry_run=true` : BULK_ACTION,
    body: { action: "edit" as const, query, edit: [{ type: "add_tags" as const, value: [tagName(date)] }] },
  }));
}

/** The ignore-tag patterns that actually filter: trimmed, blanks dropped. */
export function ignorePatterns(ignoreTags: string[]): string[] {
  return ignoreTags.map((t) => t.trim()).filter(Boolean);
}

/** " AND NOT tags: (...)": a trailing * is a prefix match (unquoted, escaped KQL), anything else an exact tag. */
function ignoreClause(ignoreTags: string[]): string {
  const values = ignorePatterns(ignoreTags).map((t) =>
    t.endsWith("*") ? t.slice(0, -1).replace(/[\\():<>"*\s]/g, (c) => `\\${c}`) + "*" : JSON.stringify(t),
  );
  return values.length ? ` AND NOT ${TAGS_FIELD}: (${values.join(" OR ")})` : "";
}

/** The dry-run and production snippets, each ready to paste into Kibana Dev Tools. */
export function renderSnippets(requests: BulkTagRequest[], dataset: Dataset, profile: Profile, date: string) {
  const context =
    `# Profile ${JSON.stringify(profile.name)} · Elastic prebuilt rules ${dataset.ruleset.packageVersion} ` +
    `(stack ${dataset.ruleset.stackMinor}) · ATT&CK ${dataset.attack.version} · generated ${date}`;
  const patterns = ignorePatterns(profile.ignoreTags);
  const ignored = patterns.length
    ? [`# Rules with an ignored tag (${patterns.join(", ")}) are skipped, so Kibana can report fewer than expected.`]
    : [];
  const install = "# Before running: install all Elastic prebuilt rules in Kibana (Rules > Add Elastic rules)";
  const render = (dryRun: boolean, header: string[]) =>
    [...header, "", ...requests.filter((r) => r.dryRun === dryRun).flatMap((r) => [renderRequest(r, dataset, profile), ""])].join("\n");
  return {
    dryRun: render(true, [
      "# apt2rule DRY RUN: changes nothing",
      context,
      `${install}. They install disabled.`,
      "# Each response lists the rules Kibana would tag. Compare the counts with the comments below.",
      ...ignored,
    ]),
    apply: render(false, [
      "# apt2rule PRODUCTION: adds tags",
      context,
      `${install} and run the dry run first.`,
      "# These requests only add tags. They do not change, enable or disable any rule.",
      ...ignored,
    ]),
  };
}

/** One request as Dev Tools text, with a comment saying what it does and where it comes from. */
export function renderRequest(request: BulkTagRequest, dataset: Dataset, profile: Profile): string {
  const tag = JSON.stringify(request.body.edit[0]?.value[0]);
  const count = `${request.expected} rule${request.expected === 1 ? "" : "s"}`;
  return [
    `# Tag ${tag} on selected rules: expect ${count}`,
    `# Profile ${JSON.stringify(profile.name)} · Elastic ${dataset.ruleset.packageVersion} · ATT&CK ${dataset.attack.version}`,
    `${request.method} ${request.path}`,
    JSON.stringify(request.body, null, 2),
  ].join("\n");
}

function ruleIdQuery(ids: string[]): string {
  return `${RULE_ID_FIELD}: (${ids.map((id) => JSON.stringify(id)).join(" OR ")})`;
}
