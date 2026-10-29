import type { BulkTagRequest, Dataset, Profile } from "./types";

const BULK_ACTION = "kbn:/api/detection_engine/rules/_bulk_action";
// Saved-object field of a detection rule's rule_id in Kibana's rules KQL. To verify on a real cluster (see README).
const RULE_ID_FIELD = "alert.attributes.params.ruleId";
export const DEFAULT_CHUNK_SIZE = 500;

export function tagNames(date: string) {
  return { selected: `apt2rule:${date}`, noApt: `apt2rule(no-APT):${date}` };
}

/**
 * Builds the add_tags bulk requests. Both tag sets list their rules by rule_id, chunked so each
 * KQL query stays well below Elasticsearch's clause limit.
 */
export function buildRequests(selectedIds: string[], noAptIds: string[], date: string, chunkSize: number): BulkTagRequest[] {
  const tags = tagNames(date);
  const plan = (kind: BulkTagRequest["kind"], ids: string[], tag: string) => {
    const sorted = [...ids].sort();
    const chunks: string[][] = [];
    for (let i = 0; i < sorted.length; i += chunkSize) chunks.push(sorted.slice(i, i + chunkSize));
    return chunks.map((chunk, i) => ({ kind, part: i + 1, parts: chunks.length, expected: chunk.length, query: ruleIdQuery(chunk), tag }));
  };
  const plans = [...plan("selected", selectedIds, tags.selected), ...plan("noApt", noAptIds, tags.noApt)];
  return [true, false].flatMap((dryRun) =>
    plans.map(({ query, tag, ...rest }) => ({
      ...rest,
      dryRun,
      method: "POST" as const,
      path: dryRun ? `${BULK_ACTION}?dry_run=true` : BULK_ACTION,
      body: { action: "edit" as const, query, edit: [{ type: "add_tags" as const, value: [tag] }] },
    })),
  );
}

/** The dry-run and production snippets, each ready to paste into Kibana Dev Tools. */
export function renderSnippets(requests: BulkTagRequest[], dataset: Dataset, profile: Profile, date: string) {
  const context =
    `# Profile ${JSON.stringify(profile.name)} · Elastic prebuilt rules ${dataset.ruleset.packageVersion} ` +
    `(stack ${dataset.ruleset.stackMinor}) · ATT&CK ${dataset.attack.version} · generated ${date}`;
  const install = "# Before running: install all Elastic prebuilt rules in Kibana (Rules > Add Elastic rules)";
  const render = (dryRun: boolean, header: string[]) =>
    [...header, "", ...requests.filter((r) => r.dryRun === dryRun).flatMap((r) => [renderRequest(r, dataset, profile), ""])].join("\n");
  return {
    dryRun: render(true, [
      "# apt2rule DRY RUN: changes nothing",
      context,
      `${install}. They install disabled.`,
      "# Each response lists the rules Kibana would tag. Compare the counts with the comments below.",
    ]),
    apply: render(false, [
      "# apt2rule PRODUCTION: adds tags",
      context,
      `${install} and run the dry run first.`,
      "# These requests only add tags. They do not change, enable or disable any rule.",
    ]),
  };
}

/** One request as Dev Tools text, with a comment saying what it does and where it comes from. */
export function renderRequest(request: BulkTagRequest, dataset: Dataset, profile: Profile): string {
  const tag = JSON.stringify(request.body.edit[0]?.value[0]);
  const target = request.kind === "selected" ? "selected rules" : "all other rules";
  const part = request.parts > 1 ? ` (part ${request.part} of ${request.parts})` : "";
  const count = `${request.expected} rule${request.expected === 1 ? "" : "s"}`;
  return [
    `# Tag ${tag} on ${target}${part}: expect ${count}`,
    `# Profile ${JSON.stringify(profile.name)} · Elastic ${dataset.ruleset.packageVersion} · ATT&CK ${dataset.attack.version}`,
    `${request.method} ${request.path}`,
    JSON.stringify(request.body, null, 2),
  ].join("\n");
}

function ruleIdQuery(ids: string[]): string {
  return `${RULE_ID_FIELD}: (${ids.map((id) => JSON.stringify(id)).join(" OR ")})`;
}
