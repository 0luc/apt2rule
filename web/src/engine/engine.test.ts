import { describe, expect, it } from "vitest";
import { run } from "./index";
import { fixtureDataset, fixtureProfile } from "./fixture";

const DATE = "2026-10-29";
const ids = (rules: { ruleId: string }[]) => rules.map((r) => r.ruleId).sort();

describe("rule selection", () => {
  it("selects rules mapped exactly to the group's direct and campaign techniques", () => {
    const result = run(fixtureDataset(), fixtureProfile({ includeBuildingBlocks: true }), DATE);
    expect(ids(result.selected)).toEqual(["r-bb", "r-lsass", "r-ml", "r-phish", "r-ps"]);
  });

  it("does not match parent-technique rules for a sub-technique (exact IDs only)", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(ids(result.selected)).not.toContain("r-cmd-parent");
  });

  it("excludes building block rules by default", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(ids(result.selected)).not.toContain("r-bb");
  });

  it("can exclude machine learning rules", () => {
    const result = run(fixtureDataset(), fixtureProfile({ includeMl: false }), DATE);
    expect(ids(result.selected)).toEqual(["r-lsass", "r-phish", "r-ps"]);
  });

  it("adds techniques from the group's software only when enabled", () => {
    const without = run(fixtureDataset(), fixtureProfile(), DATE);
    const withSoftware = run(fixtureDataset(), fixtureProfile({ includeSoftware: true }), DATE);
    expect(ids(without.selected)).not.toContain("r-ingress");
    expect(ids(withSoftware.selected)).toContain("r-ingress");
  });
});

describe("tag filter", () => {
  const DEFEND = "Data Source: Elastic Defend";

  it("filters nothing when no tag is ticked", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(result.filtered).toEqual([]);
  });

  it("moves matched rules without a ticked tag to filtered", () => {
    const result = run(fixtureDataset(), fixtureProfile({ tagFilters: [DEFEND] }), DATE);
    expect(ids(result.selected)).toEqual(["r-lsass", "r-ps"]);
    expect(ids(result.filtered)).toEqual(["r-ml", "r-phish"]);
  });

  it("keeps a rule when any ticked tag of the same category matches", () => {
    const result = run(fixtureDataset(), fixtureProfile({ tagFilters: [DEFEND, "Data Source: Microsoft 365"] }), DATE);
    expect(ids(result.selected)).toEqual(["r-lsass", "r-phish", "r-ps"]);
  });

  it("requires a match in every category that has ticked tags", () => {
    const profile = fixtureProfile({ includeBuildingBlocks: true, tagFilters: [DEFEND, "OS: Linux"] });
    const result = run(fixtureDataset(), profile, DATE);
    expect(ids(result.selected)).toEqual(["r-bb"]);
    expect(ids(result.filtered)).toEqual(["r-lsass", "r-ml", "r-phish", "r-ps"]);
  });
});

describe("technique frequency table", () => {
  const both = { groups: ["G0001", "G0002"] };

  it("counts how many selected groups use each technique, most common first", () => {
    const result = run(fixtureDataset(), fixtureProfile(both), DATE);
    expect(result.techniques.map((t) => [t.id, t.count])).toEqual([
      ["T1059.001", 2],
      ["T1003", 1],
      ["T1027", 1],
      ["T1566.001", 1],
    ]);
    expect(result.techniques[0]?.name).toBe("PowerShell");
  });

  it("records which provenances brought a technique in per group", () => {
    const result = run(fixtureDataset(), fixtureProfile({ includeSoftware: true }), DATE);
    const t1003 = result.techniques.find((t) => t.id === "T1003");
    const t1566 = result.techniques.find((t) => t.id === "T1566.001");
    expect(t1003?.groups).toEqual([{ id: "G0001", via: ["direct", "software"] }]);
    expect(t1566?.groups).toEqual([{ id: "G0001", via: ["campaign"] }]);
  });

  it("only includes techniques used by at least minGroups groups", () => {
    const result = run(fixtureDataset(), fixtureProfile({ ...both, minGroups: 2 }), DATE);
    expect(result.techniques.filter((t) => t.included).map((t) => t.id)).toEqual(["T1059.001"]);
    expect(ids(result.selected)).toEqual(["r-ps"]);
  });

  it("lets per-technique overrides win over the slider", () => {
    const result = run(
      fixtureDataset(),
      fixtureProfile({ ...both, minGroups: 2, techniqueOverrides: { "T1003": "include", "T1059.001": "exclude" } }),
      DATE,
    );
    expect(result.techniques.filter((t) => t.included).map((t) => t.id)).toEqual(["T1003"]);
    expect(ids(result.selected)).toEqual(["r-lsass", "r-ml"]);
  });

  it("lists the selected and filtered rules per technique", () => {
    const result = run(fixtureDataset(), fixtureProfile({ tagFilters: ["Rule Type: ML"] }), DATE);
    const t1003 = result.techniques.find((t) => t.id === "T1003");
    expect(t1003?.selectedRuleIds).toEqual(["r-ml"]);
    expect(t1003?.filteredRuleIds).toEqual(["r-lsass"]);
  });
});

describe("profile resolution", () => {
  it("follows group redirects for revoked groups and warns about it", () => {
    const result = run(fixtureDataset(), fixtureProfile({ groups: ["G0099"] }), DATE);
    expect(ids(result.selected)).toEqual(["r-obf", "r-ps"]);
    expect(result.warnings).toEqual(["Group G0099 was replaced by G0002 (APT2) in ATT&CK 19.1."]);
  });

  it("warns about and ignores groups missing from the dataset", () => {
    const result = run(fixtureDataset(), fixtureProfile({ groups: ["G0001", "G0500"] }), DATE);
    expect(ids(result.selected)).toEqual(["r-lsass", "r-ml", "r-phish", "r-ps"]);
    expect(result.warnings).toEqual(["Group G0500 does not exist in ATT&CK 19.1 and was ignored."]);
  });

  it("follows technique redirects in overrides and warns about unknown techniques", () => {
    const result = run(
      fixtureDataset(),
      fixtureProfile({ techniqueOverrides: { T1086: "exclude", T9999: "exclude" } }),
      DATE,
    );
    expect(ids(result.selected)).not.toContain("r-ps");
    expect(result.warnings).toEqual([
      "Technique T1086 was replaced by T1059.001 in ATT&CK 19.1.",
      "Technique T9999 does not exist in ATT&CK 19.1; its override was ignored.",
    ]);
  });
});

describe("tag warnings", () => {
  it("warns about ticked tags missing from the ruleset", () => {
    const result = run(fixtureDataset(), fixtureProfile({ tagFilters: ["OS: Linux", "OS: Solaris"] }), DATE);
    expect(result.warnings).toEqual(["Tag OS: Solaris does not exist in Elastic ruleset 9.5.9 and was ignored."]);
  });
});

describe("Dev Tools requests", () => {
  const BULK = "kbn:/api/detection_engine/rules/_bulk_action";
  const SELECTED = 'alert.attributes.params.ruleId: ("r-lsass" OR "r-ml" OR "r-phish" OR "r-ps")';

  it("names the tag after the date", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(result.tag).toBe("apt2rule:2026-10-29");
  });

  it("only tags the selected rules, by rule_id, dry run first", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(result.requests).toEqual([
      {
        dryRun: true,
        part: 1,
        parts: 1,
        expected: 4,
        method: "POST",
        path: `${BULK}?dry_run=true`,
        body: { action: "edit", query: SELECTED, edit: [{ type: "add_tags", value: ["apt2rule:2026-10-29"] }] },
      },
      {
        dryRun: false,
        part: 1,
        parts: 1,
        expected: 4,
        method: "POST",
        path: BULK,
        body: { action: "edit", query: SELECTED, edit: [{ type: "add_tags", value: ["apt2rule:2026-10-29"] }] },
      },
    ]);
  });

  it("splits large selections into several requests", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE, { chunkSize: 3 });
    const dry = result.requests.filter((r) => r.dryRun);
    expect(dry.map((r) => [r.part, r.parts, r.expected, r.body.query])).toEqual([
      [1, 2, 3, 'alert.attributes.params.ruleId: ("r-lsass" OR "r-ml" OR "r-phish")'],
      [2, 2, 1, 'alert.attributes.params.ruleId: ("r-ps")'],
    ]);
  });

  it("emits no requests when nothing is selected", () => {
    const result = run(fixtureDataset(), fixtureProfile({ groups: [] }), DATE);
    expect(result.requests).toEqual([]);
  });

  it("makes Kibana skip rules carrying an ignored tag; a trailing * matches a prefix", () => {
    const result = run(fixtureDataset(), fixtureProfile({ ignoreTags: ["disabled-*", "Keep off"] }), DATE);
    expect(result.requests[0]?.body.query).toBe(`${SELECTED} AND NOT alert.attributes.tags: (disabled-* OR "Keep off")`);
  });

  it("escapes KQL special characters in ignored tag prefixes", () => {
    const result = run(fixtureDataset(), fixtureProfile({ ignoreTags: ['my tag (old):"x"*'] }), DATE);
    expect(result.requests[0]?.body.query).toBe(`${SELECTED} AND NOT alert.attributes.tags: (my\\ tag\\ \\(old\\)\\:\\"x\\"*)`);
  });

  it("ignores blank ignore-tag entries", () => {
    const result = run(fixtureDataset(), fixtureProfile({ ignoreTags: ["", "  "] }), DATE);
    expect(result.requests[0]?.body.query).toBe(SELECTED);
  });

  it("renders a dry-run snippet that changes nothing", () => {
    const result = run(fixtureDataset(), fixtureProfile({ groups: ["G0003"], ignoreTags: ["disabled-*"] }), DATE);
    expect(result.snippets.dryRun).toBe(`# apt2rule DRY RUN: changes nothing
# Profile "Test profile" · Elastic prebuilt rules 9.5.9 (stack 9.5) · ATT&CK 19.1 · generated 2026-10-29
# Before running: install all Elastic prebuilt rules in Kibana (Rules > Add Elastic rules). They install disabled.
# Each response lists the rules Kibana would tag. Compare the counts with the comments below.
# Rules with an ignored tag (disabled-*) are skipped, so Kibana can report fewer than expected.

# Tag "apt2rule:2026-10-29" on selected rules: expect 1 rule
# Profile "Test profile" · Elastic 9.5.9 · ATT&CK 19.1
POST ${BULK}?dry_run=true
{
  "action": "edit",
  "query": "alert.attributes.params.ruleId: (\\"r-dos\\") AND NOT alert.attributes.tags: (disabled-*)",
  "edit": [
    {
      "type": "add_tags",
      "value": [
        "apt2rule:2026-10-29"
      ]
    }
  ]
}
`);
  });

  it("renders a production snippet that only adds tags", () => {
    const result = run(fixtureDataset(), fixtureProfile({ groups: ["G0003"], ignoreTags: ["disabled-*"] }), DATE);
    expect(result.snippets.apply).toBe(`# apt2rule PRODUCTION: adds tags
# Profile "Test profile" · Elastic prebuilt rules 9.5.9 (stack 9.5) · ATT&CK 19.1 · generated 2026-10-29
# Before running: install all Elastic prebuilt rules in Kibana (Rules > Add Elastic rules) and run the dry run first.
# These requests only add tags. They do not change, enable or disable any rule.
# Rules with an ignored tag (disabled-*) are skipped, so Kibana can report fewer than expected.

# Tag "apt2rule:2026-10-29" on selected rules: expect 1 rule
# Profile "Test profile" · Elastic 9.5.9 · ATT&CK 19.1
POST ${BULK}
{
  "action": "edit",
  "query": "alert.attributes.params.ruleId: (\\"r-dos\\") AND NOT alert.attributes.tags: (disabled-*)",
  "edit": [
    {
      "type": "add_tags",
      "value": [
        "apt2rule:2026-10-29"
      ]
    }
  ]
}
`);
  });
});

describe("report", () => {
  const profile = () => fixtureProfile({ groups: ["G0001", "G0002"], tagFilters: ["Data Source: Elastic Defend"] });

  it("lists the selected rule_ids one per line", () => {
    const result = run(fixtureDataset(), profile(), DATE);
    expect(result.ruleIdList).toBe("r-lsass\nr-ps\n");
  });

  it("exports one CSV row per included technique with its coverage status", () => {
    const result = run(fixtureDataset(), profile(), DATE);
    expect(result.report.csv).toBe(
      [
        "technique_id,technique_name,group_count,groups,status,selected_rule_ids,filtered_rule_ids",
        "T1059.001,PowerShell,2,APT1 (G0001); APT2 (G0002),covered,r-ps,",
        "T1003,OS Credential Dumping,1,APT1 (G0001),covered,r-lsass,r-ml",
        "T1027,Obfuscated Files or Information,1,APT2 (G0002),filtered out,,r-obf",
        "T1566.001,Spearphishing Attachment,1,APT1 (G0001),filtered out,,r-phish",
        "",
      ].join("\r\n"),
    );
  });

  it("quotes CSV fields that contain commas or quotes", () => {
    const dataset = fixtureDataset();
    dataset.techniques = dataset.techniques.map((t) => (t.id === "T1003" ? { ...t, name: 'Dumping, "LSASS"' } : t));
    const result = run(dataset, fixtureProfile(), DATE);
    expect(result.report.csv).toContain('\r\nT1003,"Dumping, ""LSASS""",1,');
  });

  it("marks techniques without any rule as gaps", () => {
    const dataset = fixtureDataset();
    dataset.rules = dataset.rules.filter((r) => r.ruleId !== "r-obf");
    const result = run(dataset, profile(), DATE);
    expect(result.report.csv).toContain("\r\nT1027,Obfuscated Files or Information,1,APT2 (G0002),no rule,,\r\n");
  });

  it("summarises coverage, gaps and filtered rules in Markdown", () => {
    const result = run(fixtureDataset(), profile(), DATE);
    const md = result.report.markdown;
    expect(md).toContain("# apt2rule coverage report: Test profile");
    expect(md).toContain("Generated 2026-10-29 · Elastic prebuilt rules 9.5.9 (stack 9.5) · ATT&CK 19.1");
    expect(md).toContain("- Tag filter: Data Source: Elastic Defend");
    expect(md).toContain("| APT1 (G0001) | 3 | 2 | 1 |");
    expect(md).toContain("| APT2 (G0002) | 2 | 1 | 1 |");
    expect(md).toContain("| T1566.001 | Spearphishing Attachment | APT1 (campaign) | 0 | filtered out |");
    expect(md).toContain("| r-phish | Rule r-phish | T1566.001 | Data Source: Microsoft 365 |");
    expect(md).toContain("| r-lsass | Rule r-lsass | medium | T1003 | Data Source: Elastic Defend, OS: Windows |  |");
    expect(md).toContain("- Selected rules (tag `apt2rule:2026-10-29`): 2");
    expect(md).toContain("- Matching rules removed by the tag filter (no tag): 3");
    expect(md).toContain("- Ignored tags (skipped in Kibana): none");
  });

  it("notes machine learning rules in the selected rules table", () => {
    const result = run(fixtureDataset(), fixtureProfile(), DATE);
    expect(result.report.markdown).toContain("| r-ml | Rule r-ml | medium | T1003 | Rule Type: ML | requires ML job |");
  });
});
