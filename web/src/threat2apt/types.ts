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
  kind: "region" | "sector" | "country" | "threat";
  label: string;
  terms: string[];
  /** Set for country target groups: hits inside another country's name don't count. */
  country?: string;
  /** Set for regions: codes of the countries whose terms also match it. */
  countries?: string[];
}

export type Tier = 1 | 2 | 3;

/** Saved threat2apt settings. Separate from apt2rule's profiles. */
export interface T2aProfile {
  schemaVersion: 1;
  name: string;
  /** Ticked country codes: groups attributed to one of them match on country. */
  countries: string[];
  /** Ransomware as a threat: groups whose texts name ransomware or extortion match too, whatever their country. */
  ransomware: boolean;
  /** Your area: ticked region and country target group IDs, e.g. "region:europe", "country:DE". */
  area: string[];
  /** Your sector: ticked sector target group IDs, e.g. "sector:government". */
  targets: string[];
  /** Extra terms, matched like sector terms. */
  customTerms: string[];
  /** Per threat (country code, or "ransomware"): target group IDs that drop its groups, e.g. { KP: ["sector:crypto"] }. */
  exclusions: Record<string, string[]>;
  /** With an area: hide groups whose texts only name places outside it. */
  hideElsewhere: boolean;
  /** Hide groups last seen before this year. */
  seenSince: number | null;
  /** With seenSince: also hide groups whose last seen is unknown. */
  hideUnknownSeen: boolean;
  /** Tiers shown in the results. */
  tiers: Tier[];
  /** Ticks that differ from the default (see Suggestion.defaultPicked), by group ID. */
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

/**
 * Where a group operates, judged from the places its texts name (its own attributed countries aside):
 * your area, only elsewhere, or no place at all. Null when no area is ticked.
 */
export type Location = "area" | "elsewhere" | "unknown";

/** A threat country's exclusion rule that hit: the excluded target groups the group matched. */
export interface Exclusion {
  /** Country code, or "ransomware". */
  country: string;
  matches: TargetMatch[];
}

export interface Suggestion {
  group: T2aGroup;
  tier: Tier;
  /** Attributions whose country is ticked. */
  countryMatches: Attribution[];
  /** With ransomware ticked: the ransomware and extortion terms its texts use. */
  ransomwareMatch: TargetMatch | null;
  /** One entry per ticked sector (or custom term) that matched. */
  targetMatches: TargetMatch[];
  location: Location | null;
  /** The places in your area it names; with "elsewhere", the places it names instead. */
  locationMatches: TargetMatch[];
  /** Empty unless an exclusion rule drops the group. */
  excludedBy: Exclusion[];
  /**
   * Not excluded, and: without an area, tier 1; with one, in your area (unless attributed only to countries you
   * didn't tick), or a ransomware match naming no place (ransomware strikes anywhere).
   */
  defaultPicked: boolean;
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
  /** Ransomware terms found, when ransomware was a threat. Absent in older reasons. */
  ransomware?: string[];
  matched: { target: string; terms: string[] }[];
  /** Absent in reasons from before areas, and when no area was ticked. */
  location?: { status: Location; places: string[] };
  lastSeen: string | null;
}
