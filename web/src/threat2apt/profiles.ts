import type { T2aProfile, Tier } from "./types";

const PROFILES_KEY = "threat2apt.profiles";
const CURRENT_KEY = "threat2apt.current";

/** A new profile ticks nothing: the user chooses countries and targets from their own threat assessment. */
export function newProfile(name: string): T2aProfile {
  return {
    schemaVersion: 1,
    name,
    countries: [],
    targets: [],
    customTerms: [],
    seenSince: null,
    hideUnknownSeen: false,
    tiers: [1, 2, 3],
    picks: {},
  };
}

/** Profiles live in this browser only; storage can be unavailable (private mode, blocked site data). */
export function loadProfiles(): { profiles: Record<string, T2aProfile>; current: string | null } {
  try {
    const raw = JSON.parse(localStorage.getItem(PROFILES_KEY) ?? "{}") as Record<string, unknown>;
    const profiles: Record<string, T2aProfile> = {};
    for (const value of Object.values(raw)) {
      try {
        const p = parseProfile(JSON.stringify({ ...(value as object), kind: "threat2apt" }));
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

export function saveProfiles(profiles: Record<string, T2aProfile>, current: string) {
  try {
    localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles));
    localStorage.setItem(CURRENT_KEY, current);
  } catch {
    // not persisted; export still works
  }
}

/** Parses an exported profile, filling defaults and rejecting anything that isn't one. */
export function parseProfile(text: string): T2aProfile {
  const v = JSON.parse(text) as Partial<T2aProfile> & { kind?: string };
  const strings = (x: unknown): x is string[] => Array.isArray(x) && x.every((s) => typeof s === "string");
  if (!v || typeof v !== "object" || v.kind !== "threat2apt" || v.schemaVersion !== 1 || typeof v.name !== "string") {
    throw new Error("not a threat2apt profile (schemaVersion 1)");
  }
  const tiers = Array.isArray(v.tiers) ? v.tiers.filter((t): t is Tier => t === 1 || t === 2 || t === 3) : [1, 2, 3];
  const picks: Record<string, boolean> = {};
  for (const [id, value] of Object.entries(v.picks ?? {})) if (typeof value === "boolean") picks[id] = value;
  return {
    schemaVersion: 1,
    name: v.name.trim() || "Imported profile",
    countries: strings(v.countries) ? v.countries : [],
    targets: strings(v.targets) ? v.targets : [],
    customTerms: strings(v.customTerms) ? v.customTerms : [],
    seenSince: Number.isInteger(v.seenSince) ? v.seenSince! : null,
    hideUnknownSeen: v.hideUnknownSeen === true,
    tiers: [...new Set(tiers)].sort() as Tier[],
    picks,
  };
}

/** The JSON written by "Export": marked so apt2rule and threat2apt profiles can't be mixed up. */
export function exportProfile(p: T2aProfile): string {
  return JSON.stringify({ kind: "threat2apt", ...p }, null, 2);
}
