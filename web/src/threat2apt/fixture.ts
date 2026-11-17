import { newProfile } from "./profiles";
import type { T2aDataset, T2aGroup, T2aProfile } from "./types";

const group = (id: string, name: string, text: string, extra: Partial<T2aGroup> = {}): T2aGroup => ({
  id,
  name,
  aliases: [],
  attribution: [],
  lastSeen: null,
  texts: [{ source: id, name, text }],
  ...extra,
});

/** Hand-built dataset for the threat2apt tests. Must satisfy schema/threat2apt.schema.json. */
export function fixtureT2a(): T2aDataset {
  return {
    schemaVersion: 1,
    attack: { version: "19.1" },
    builtAt: "2026-11-17T00:00:00Z",
    countries: [
      { code: "RU", name: "Russia", terms: ["Russia", "Russian", "Russian Federation"] },
      { code: "CN", name: "China", terms: ["China", "Chinese", "PRC"] },
      { code: "DE", name: "Germany", terms: ["Germany", "German"] },
      { code: "GN", name: "Guinea", terms: ["Guinea", "Guinean"] },
      { code: "PG", name: "Papua New Guinea", terms: ["Papua New Guinea"] },
      { code: "US", name: "United States", terms: ["United States", "US", "U.S."] },
    ],
    groups: [
      group("G0001", "Bear One", "Bear One is attributed to Russia. It targets European government ministries.", {
        attribution: [{ country: "RU", evidence: "Bear One is attributed to Russia.", source: "G0001" }],
        lastSeen: "2024-05-01",
      }),
      group("G0002", "Bear Two", "Bear Two is a Russia-based group that targets energy companies in Asia.", {
        attribution: [{ country: "RU", evidence: "Bear Two is a Russia-based group that targets energy companies in Asia.", source: "G0002" }],
      }),
      group("G0003", "Panda", "Panda is a China-based group.", {
        attribution: [{ country: "CN", evidence: "Panda is a China-based group.", source: "G0003" }],
        lastSeen: "2019-01-01",
        texts: [
          { source: "G0003", name: "Panda", text: "Panda is a China-based group." },
          { source: "C0001", name: "Operation Lantern", text: "Operation Lantern hit NATO members and the U.S. defense sector." },
        ],
      }),
      group("G0004", "Nobody", "Nobody targeted Western governments and non-governmental organizations.", { lastSeen: "2025-02-02" }),
      group("G0005", "Islander", "Islander targeted Papua New Guinea and us in German banks."),
      group("G0006", "Quiet", "Quiet is a criminal group."),
    ],
  };
}

export function fixtureProfile(extra: Partial<T2aProfile> = {}): T2aProfile {
  return { ...newProfile("Test profile"), ...extra };
}
