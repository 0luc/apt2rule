/** threat2apt dataset. Contract: schema/threat2apt.schema.json */
export interface T2aDataset {
  schemaVersion: 1;
  attack: { version: string };
  builtAt: string;
  countries: Country[];
  groups: T2aGroup[];
}

export interface Country {
  code: string;
  name: string;
  /** Name first, then adjectives and abbreviations. Capitalised terms match case-sensitively. */
  terms: string[];
}

export interface T2aGroup {
  id: string;
  name: string;
  /** Aliases other than the name. */
  aliases: string[];
  /** Attributed countries in order of first evidence; empty when unknown. */
  attribution: Attribution[];
  /** Latest campaign last_seen, YYYY-MM-DD; null without campaigns. */
  lastSeen: string | null;
  /** The group's description first, then its campaigns'. */
  texts: { source: string; name: string; text: string }[];
}

export interface Attribution {
  country: string;
  /** The sentence that names the attribution, or an override's reason. */
  evidence: string;
  /** Group or campaign ID, or "override". */
  source: string;
}

/** A curated list of synonyms for one region, sector or country that threat2apt searches for. */
export interface TargetGroup {
  id: string;
  kind: "region" | "sector" | "country";
  label: string;
  terms: string[];
  /** Set for country target groups: hits inside another country's name don't count. */
  country?: string;
}

export type Tier = 1 | 2 | 3;

/** Saved threat2apt settings. Separate from apt2rule's profiles. */
export interface T2aProfile {
  schemaVersion: 1;
  name: string;
  /** Ticked country codes: groups attributed to one of them match on country. */
  countries: string[];
  /** Ticked target group IDs, e.g. "region:west", "sector:government", "country:DE". */
  targets: string[];
  /** Extra terms, matched like target group terms. */
  customTerms: string[];
  /** Hide groups last seen before this year. */
  seenSince: number | null;
  /** With seenSince: also hide groups whose last seen is unknown. */
  hideUnknownSeen: boolean;
  /** Tiers shown in the results. */
  tiers: Tier[];
  /** Ticks that differ from the default (tier 1 ticked, others not), by group ID. */
  picks: Record<string, boolean>;
}

/** One place a term was found. */
export interface Hit {
  /** Target group ID, or "custom". */
  target: string;
  term: string;
  /** Group or campaign ID of the text. */
  source: string;
  sourceName: string;
  /** Index into the group's texts. */
  text: number;
  start: number;
  end: number;
}

export interface TargetMatch {
  target: string;
  label: string;
  /** Distinct terms found, in order of first hit. */
  terms: string[];
  hits: Hit[];
}

export interface Suggestion {
  group: T2aGroup;
  tier: Tier;
  /** Attributions whose country is ticked. */
  countryMatches: Attribution[];
  /** One entry per ticked target group (or custom term) that matched. */
  targetMatches: TargetMatch[];
  picked: boolean;
}

/** Why a group was picked: travels with the group into apt2rule. */
export interface GroupReason {
  source: "threat2apt";
  /** Date of the handoff, YYYY-MM-DD. */
  date: string;
  profile: string;
  attackVersion: string;
  tier: Tier;
  countries: { code: string; name: string; evidence: string; source: string }[];
  matched: { target: string; terms: string[] }[];
  lastSeen: string | null;
}
