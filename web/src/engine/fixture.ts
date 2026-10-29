import type { Dataset, Profile, Rule } from "./types";

/** Hand-built dataset used by the engine tests. Must satisfy schema/dataset.schema.json. */
export function fixtureDataset(): Dataset {
  const rule = (ruleId: string, techniques: string[], integrations: string[], extra: Partial<Rule> = {}): Rule => ({
    ruleId,
    name: `Rule ${ruleId}`,
    type: "eql",
    severity: "medium",
    buildingBlock: false,
    integrations,
    techniques,
    ...extra,
  });
  return {
    schemaVersion: 1,
    ruleset: { packageVersion: "9.5.9", stackMinor: "9.5" },
    attack: { version: "19.1" },
    builtAt: "2026-10-29T00:00:00Z",
    techniques: [
      { id: "T1003", name: "OS Credential Dumping" },
      { id: "T1027", name: "Obfuscated Files or Information" },
      { id: "T1059", name: "Command and Scripting Interpreter" },
      { id: "T1059.001", name: "PowerShell" },
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1499", name: "Endpoint Denial of Service" },
      { id: "T1566.001", name: "Spearphishing Attachment" },
    ],
    groups: [
      {
        id: "G0001",
        name: "APT1",
        aliases: ["APT1", "Comment Crew"],
        description: "First test group.",
        techniques: { direct: ["T1059.001", "T1003"], campaign: ["T1566.001"], software: ["T1105", "T1003"] },
      },
      {
        id: "G0002",
        name: "APT2",
        aliases: ["APT2", "Test Bear"],
        description: "Second test group.",
        techniques: { direct: ["T1059.001", "T1027"], campaign: [], software: [] },
      },
      {
        id: "G0003",
        name: "Lazarus Group",
        aliases: ["Lazarus Group", "HIDDEN COBRA"],
        description: "Third test group.",
        techniques: { direct: ["T1499"], campaign: [], software: [] },
      },
    ],
    rules: [
      rule("r-ps", ["T1059.001"], ["endpoint", "windows"]),
      rule("r-cmd-parent", ["T1059"], ["endpoint"]),
      rule("r-lsass", ["T1003"], ["endpoint"]),
      rule("r-phish", ["T1566.001"], ["o365"]),
      rule("r-ingress", ["T1105"], ["network_traffic"]),
      rule("r-obf", ["T1027"], []),
      rule("r-bb", ["T1059.001"], ["endpoint"], { buildingBlock: true }),
      rule("r-ml", ["T1003"], [], { type: "machine_learning" }),
      rule("r-dos", ["T1499"], ["aws/cloudtrail"]),
    ],
    integrations: ["aws/cloudtrail", "endpoint", "network_traffic", "o365", "windows"],
    groupRedirects: { G0099: "G0002" },
    techniqueRedirects: { T1086: "T1059.001" },
  };
}

export function fixtureProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    schemaVersion: 1,
    name: "Test profile",
    rulesetVersion: "9.5.9",
    groups: ["G0001"],
    includeSoftware: false,
    minGroups: 1,
    techniqueOverrides: {},
    integrations: ["aws/cloudtrail", "endpoint", "network_traffic", "o365", "windows"],
    includeBuildingBlocks: false,
    includeMl: true,
    ...overrides,
  };
}
