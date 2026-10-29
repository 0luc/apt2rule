import type { Dataset, Profile } from "./engine";

const PROFILES_KEY = "apt2rule.profiles";
const CURRENT_KEY = "apt2rule.current";

export function newProfile(dataset: Dataset, name: string): Profile {
  return {
    schemaVersion: 1,
    name,
    rulesetVersion: dataset.ruleset.packageVersion,
    groups: [],
    includeSoftware: false,
    minGroups: 1,
    techniqueOverrides: {},
    integrations: [...dataset.integrations],
    includeBuildingBlocks: false,
    includeMl: true,
  };
}

/** Profiles live in this browser only; storage can be unavailable (private mode, blocked site data). */
export function loadProfiles(): { profiles: Record<string, Profile>; current: string | null } {
  try {
    const raw = JSON.parse(localStorage.getItem(PROFILES_KEY) ?? "{}") as Record<string, unknown>;
    const profiles: Record<string, Profile> = {};
    for (const value of Object.values(raw)) {
      try {
        const p = parseProfile(JSON.stringify(value));
        profiles[p.name] = p;
      } catch {
        // skip a corrupt entry rather than losing the rest
      }
    }
    return { profiles, current: localStorage.getItem(CURRENT_KEY) };
  } catch {
    return { profiles: {}, current: null };
  }
}

export function saveProfiles(profiles: Record<string, Profile>, current: string) {
  try {
    localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles));
    localStorage.setItem(CURRENT_KEY, current);
  } catch {
    // not persisted; export still works
  }
}

/** Parses an exported profile, filling defaults and rejecting anything that isn't one. */
export function parseProfile(text: string): Profile {
  const v = JSON.parse(text) as Partial<Profile>;
  const strings = (x: unknown) => Array.isArray(x) && x.every((s) => typeof s === "string");
  if (!v || typeof v !== "object" || v.schemaVersion !== 1 || typeof v.name !== "string" || !strings(v.groups)) {
    throw new Error("not an apt2rule profile (schemaVersion 1)");
  }
  const overrides: Profile["techniqueOverrides"] = {};
  for (const [id, value] of Object.entries(v.techniqueOverrides ?? {})) {
    if (value === "include" || value === "exclude") overrides[id] = value;
  }
  return {
    schemaVersion: 1,
    name: v.name.trim() || "Imported profile",
    rulesetVersion: typeof v.rulesetVersion === "string" ? v.rulesetVersion : "",
    groups: v.groups!,
    includeSoftware: v.includeSoftware === true,
    minGroups: Number.isInteger(v.minGroups) && v.minGroups! >= 1 ? v.minGroups! : 1,
    techniqueOverrides: overrides,
    integrations: strings(v.integrations) ? v.integrations! : [],
    includeBuildingBlocks: v.includeBuildingBlocks === true,
    includeMl: v.includeMl !== false,
  };
}
