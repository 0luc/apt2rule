import { ignorePatterns } from "./snippet";
import type { Dataset, Group, Profile, Rule, TechniqueRow } from "./types";

export interface ReportInput {
  dataset: Dataset;
  profile: Profile;
  date: string;
  groups: Group[];
  techniques: TechniqueRow[];
  selected: Rule[];
  filtered: Rule[];
  tag: string;
}

type Status = "covered" | "filtered out" | "no rule";

export function techniqueStatus(row: TechniqueRow): Status {
  if (row.selectedRuleIds.length) return "covered";
  return row.filteredRuleIds.length ? "filtered out" : "no rule";
}

export function ruleIdList(selected: Rule[]): string {
  return selected.map((r) => r.ruleId).sort().map((id) => `${id}\n`).join("");
}

export function buildCsv({ dataset, techniques }: ReportInput): string {
  const groupNames = new Map(dataset.groups.map((g) => [g.id, g.name]));
  const rows = [
    ["technique_id", "technique_name", "group_count", "groups", "status", "selected_rule_ids", "filtered_rule_ids"],
    ...techniques
      .filter((t) => t.included)
      .map((t) => [
        t.id,
        t.name,
        String(t.count),
        t.groups.map((g) => `${groupNames.get(g.id)} (${g.id})`).join("; "),
        techniqueStatus(t),
        [...t.selectedRuleIds].sort().join("; "),
        [...t.filteredRuleIds].sort().join("; "),
      ]),
  ];
  return rows.map((row) => row.map(csvField).join(",") + "\r\n").join("");
}

export function buildMarkdown(input: ReportInput): string {
  const { dataset, profile, date, groups, selected, filtered, tag } = input;
  const included = input.techniques.filter((t) => t.included);
  const groupNames = new Map(dataset.groups.map((g) => [g.id, g.name]));
  const covered = included.filter((t) => techniqueStatus(t) === "covered").length;
  const out: string[] = [];
  const table = (header: string[], rows: string[][]) => {
    out.push(`| ${header.join(" | ")} |`, `| ${header.map(() => "---").join(" | ")} |`);
    for (const row of rows) out.push(`| ${row.map(mdCell).join(" | ")} |`);
    out.push("");
  };

  out.push(
    `# apt2rule coverage report: ${profile.name}`,
    "",
    `Generated ${date} · Elastic prebuilt rules ${dataset.ruleset.packageVersion} (stack ${dataset.ruleset.stackMinor}) · ATT&CK ${dataset.attack.version}`,
    "",
    "## Summary",
    "",
    `- Groups: ${groups.map((g) => `${g.name} (${g.id})`).join(", ") || "none"}`,
    `- Tag filter: ${profile.tagFilters.join(", ") || "none"}`,
    `- Techniques included: ${included.length} of ${input.techniques.length}`,
    `- Techniques covered by selected rules: ${covered}; gaps: ${included.length - covered}`,
    `- Selected rules (tag \`${tag}\`): ${selected.length}`,
    `- Matching rules removed by the tag filter (no tag): ${filtered.length}`,
    `- Ignored tags (skipped in Kibana): ${ignorePatterns(profile.ignoreTags).join(", ") || "none"}`,
    `- Rules disabled after running: ${profile.skipDisabledAfterRun ? "skipped in Kibana" : "tagged"}`,
    "",
    "## Coverage per group",
    "",
  );
  table(
    ["Group", "Techniques", "Covered", "Gaps"],
    groups.map((g) => {
      const own = included.filter((t) => t.groups.some((x) => x.id === g.id));
      const ok = own.filter((t) => techniqueStatus(t) === "covered").length;
      return [`${g.name} (${g.id})`, String(own.length), String(ok), String(own.length - ok)];
    }),
  );

  out.push("## Coverage per technique", "");
  table(
    ["Technique", "Name", "Groups", "Selected rules", "Status"],
    included.map((t) => [
      t.id,
      t.name,
      t.groups.map((g) => `${groupNames.get(g.id)} (${g.via.join(", ")})`).join("; "),
      String(t.selectedRuleIds.length),
      techniqueStatus(t),
    ]),
  );

  const includedIds = new Set(included.map((t) => t.id));
  out.push("## Matching rules removed by the tag filter", "");
  table(
    ["rule_id", "Name", "Techniques", "Tags"],
    [...filtered]
      .sort((a, b) => a.ruleId.localeCompare(b.ruleId))
      .map((r) => [r.ruleId, r.name, r.techniques.filter((t) => includedIds.has(t)).join(", "), r.tags.join(", ")]),
  );

  out.push("## Selected rules", "");
  table(
    ["rule_id", "Name", "Severity", "Techniques", "Tags", "Notes"],
    [...selected]
      .sort((a, b) => a.ruleId.localeCompare(b.ruleId))
      .map((r) => [
        r.ruleId,
        r.name,
        r.severity,
        r.techniques.filter((t) => includedIds.has(t)).join(", "),
        r.tags.join(", "),
        [r.type === "machine_learning" ? "requires ML job" : "", r.buildingBlock ? "building block" : ""]
          .filter(Boolean)
          .join(", "),
      ]),
  );
  return out.join("\n");
}

function csvField(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function mdCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}
