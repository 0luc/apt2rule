/** Compact dataset for one ruleset version. Contract: schema/dataset.schema.json */
export interface Dataset {
  schemaVersion: 1;
  ruleset: { packageVersion: string; stackMinor: string };
  attack: { version: string };
  builtAt: string;
  techniques: { id: string; name: string }[];
  groups: Group[];
  rules: Rule[];
  integrations: string[];
  groupRedirects: Record<string, string>;
  techniqueRedirects: Record<string, string>;
}

export interface Group {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  techniques: Record<Provenance, string[]>;
}

export type Provenance = "direct" | "campaign" | "software";

export interface Rule {
  ruleId: string;
  name: string;
  type: string;
  severity: string;
  buildingBlock: boolean;
  integrations: string[];
  techniques: string[];
}

/** A saved threat profile: everything the user chose. */
export interface Profile {
  schemaVersion: 1;
  name: string;
  rulesetVersion: string;
  groups: string[];
  includeSoftware: boolean;
  minGroups: number;
  techniqueOverrides: Record<string, "include" | "exclude">;
  integrations: string[];
  includeBuildingBlocks: boolean;
  includeMl: boolean;
}

export interface TechniqueRow {
  id: string;
  name: string;
  /** Selected groups using this technique, with the provenances that brought it in. */
  groups: { id: string; via: Provenance[] }[];
  count: number;
  included: boolean;
  selectedRuleIds: string[];
  noDataRuleIds: string[];
}

export interface Result {
  warnings: string[];
  techniques: TechniqueRow[];
  /** Matched rules that will get the apt2rule:<date> tag. */
  selected: Rule[];
  /** Matched rules dropped because none of their integrations is ticked. No tag. */
  noData: Rule[];
  /** All other rules: they get the apt2rule(no-APT):<date> tag. */
  noApt: Rule[];
  tags: { selected: string; noApt: string };
  /** Kibana Dev Tools requests: every dry run first, then every apply. */
  requests: BulkTagRequest[];
  /** The requests rendered as text to paste into Kibana Dev Tools. */
  snippet: string;
  report: { markdown: string; csv: string };
  ruleIdList: string;
}

export interface BulkTagRequest {
  kind: "selected" | "noApt";
  dryRun: boolean;
  part: number;
  parts: number;
  /** Number of rules apt2rule expects Kibana to tag. */
  expected: number;
  method: "POST";
  path: string;
  body: {
    action: "edit";
    query: string;
    edit: { type: "add_tags"; value: string[] }[];
  };
}

export interface RunOptions {
  /** Maximum rule_ids per selected-rules request. */
  chunkSize?: number;
}
