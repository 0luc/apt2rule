import type { Dataset, Group, Profile, Rule, TechniqueRow } from "./types";

export interface ReportInput {
  dataset: Dataset;
  profile: Profile;
  date: string;
  groups: Group[];
  techniques: TechniqueRow[];
  selected: Rule[];
  noData: Rule[];
  noApt: Rule[];
  tags: { selected: string; noApt: string };
}

type Status = "covered" | "needs integration" | "no rule";

export function techniqueStatus(row: TechniqueRow): Status {
  if (row.selectedRuleIds.length) return "covered";
  return row.noDataRuleIds.length ? "needs integration" : "no rule";
}

export function ruleIdList(selected: Rule[]): string {
  return selected.map((r) => r.ruleId).sort().map((id) => `${id}\n`).join("");
}

export function buildCsv({ dataset, techniques }: ReportInput): string {
  const groupNames = new Map(dataset.groups.map((g) => [g.id, g.name]));
  const rows = [
    ["technique_id", "technique_name", "group_count", "groups", "status", "selected_rule_ids", "missing_integration_rule_ids"],
    ...techniques
      .filter((t) => t.included)
      .map((t) => [
        t.id,
        t.name,
        String(t.count),
        t.groups.map((g) => `${groupNames.get(g.id)} (${g.id})`).join("; "),
        techniqueStatus(t),
        [...t.selectedRuleIds].sort().join("; "),
        [...t.noDataRuleIds].sort().join("; "),
      ]),
  ];
  return rows.map((row) => row.map(csvField).join(",") + "\r\n").join("");
}

export function buildMarkdown(input: ReportInput): string {
  const { dataset, profile, date, groups, selected, noData, noApt, tags } = input;
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
    `- Techniques included: ${included.length} of ${input.techniques.length}`,
    `- Techniques covered by selected rules: ${covered}; gaps: ${included.length - covered}`,
    `- Selected rules (tag \`${tags.selected}\`): ${selected.length}`,
    `- Rules needing an integration you don't have (no tag): ${noData.length}`,
    `- Other prebuilt rules (tag \`${tags.noApt}\`): ${noApt.length}`,
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

  out.push("## Coverage you'd gain with additional integrations", "");
  const includedIds = new Set(included.map((t) => t.id));
  const gain = new Map<string, { rules: number; techniques: Set<string> }>();
  for (const rule of noData) {
    for (const integration of rule.integrations) {
      const entry = gain.get(integration) ?? { rules: 0, techniques: new Set<string>() };
      entry.rules++;
      for (const t of rule.techniques) if (includedIds.has(t)) entry.techniques.add(t);
      gain.set(integration, entry);
    }
  }
  table(
    ["Integration", "Rules", "Techniques"],
    [...gain.entries()]
      .sort((a, b) => b[1].rules - a[1].rules || a[0].localeCompare(b[0]))
      .map(([name, e]) => [name, String(e.rules), [...e.techniques].sort().join(", ")]),
  );

  out.push("## Selected rules", "");
  table(
    ["rule_id", "Name", "Severity", "Techniques", "Integrations", "Notes"],
    [...selected]
      .sort((a, b) => a.ruleId.localeCompare(b.ruleId))
      .map((r) => [
        r.ruleId,
        r.name,
        r.severity,
        r.techniques.filter((t) => includedIds.has(t)).join(", "),
        r.integrations.join(", ") || "unknown",
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
