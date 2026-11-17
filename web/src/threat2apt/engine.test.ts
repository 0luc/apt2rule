import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import schema from "../../../schema/threat2apt.schema.json";
import { buildTable, matchGroup, prepare, reasonFor, suggest, targetCounts } from "./engine";
import { fixtureProfile, fixtureT2a } from "./fixture";
import { exportProfile, newProfile, parseProfile } from "./profiles";

const ctx = prepare(fixtureT2a());
const groupById = (id: string) => ctx.dataset.groups.find((g) => g.id === id)!;
const ids = (profile = fixtureProfile()) => suggest(ctx, profile).map((s) => `${s.group.id}:${s.tier}`);

it("the fixture satisfies the shared threat2apt schema", () => {
  const validate = new Ajv({ allErrors: true }).compile(schema);
  expect(validate(fixtureT2a()), JSON.stringify(validate.errors)).toBe(true);
});

describe("tiers", () => {
  it("shows nothing for an empty profile", () => {
    expect(ids()).toEqual([]);
  });

  it("puts country + target in tier 1, target only in tier 2, country only in tier 3", () => {
    const profile = fixtureProfile({ countries: ["RU"], targets: ["region:west", "sector:government"] });
    expect(ids(profile)).toEqual(["G0001:1", "G0004:2", "G0003:2", "G0002:3"]);
  });

  it("hides tiers that are not ticked", () => {
    const profile = fixtureProfile({ countries: ["RU"], targets: ["region:west"], tiers: [1] });
    expect(ids(profile)).toEqual(["G0001:1"]);
  });

  it("ticks tier 1 by default and keeps the user's own ticks", () => {
    const profile = fixtureProfile({ countries: ["RU"], targets: ["region:west"], picks: { G0001: false, G0002: true } });
    expect(suggest(ctx, profile).map((s) => [s.group.id, s.picked])).toEqual([
      ["G0001", false],
      ["G0004", false],
      ["G0003", false],
      ["G0002", true],
    ]);
  });
});

describe("ordering within a tier", () => {
  it("ranks by number of target groups matched, then last seen (newest first, unknown last), then name", () => {
    const profile = fixtureProfile({ targets: ["region:west", "sector:government", "sector:defence", "sector:energy"] });
    // G0003 matches West + Defence (2); G0004 West + Government (2, newer); G0001 West + Government (2, older); G0002 Energy (1)
    expect(ids(profile)).toEqual(["G0004:2", "G0001:2", "G0003:2", "G0002:2"]);
  });
});

describe("matching", () => {
  it("matches whole words only, with explicit variants", () => {
    const [m] = matchGroup(ctx, groupById("G0001"), ["region:west"], []);
    expect(m!.terms).toEqual(["European"]);
  });

  it("searches campaign descriptions and labels the source", () => {
    const [m] = matchGroup(ctx, groupById("G0003"), ["region:west"], []);
    expect(m!.terms).toEqual(["NATO", "U.S."]);
    expect(m!.hits.map((h) => h.source)).toEqual(["C0001", "C0001"]);
    expect(m!.hits[0]!.sourceName).toBe("Operation Lantern");
  });

  it("matches capitalised abbreviations case-sensitively", () => {
    expect(matchGroup(ctx, groupById("G0005"), ["country:US"], [])).toEqual([]);
  });

  it("does not count a country inside another country's name", () => {
    expect(matchGroup(ctx, groupById("G0005"), ["country:GN"], [])).toEqual([]);
    expect(matchGroup(ctx, groupById("G0005"), ["country:PG"], [])[0]!.terms).toEqual(["Papua New Guinea"]);
  });

  it("does not count 'governmental' inside 'non-governmental'", () => {
    const [m] = matchGroup(ctx, groupById("G0004"), ["sector:government"], []);
    expect(m!.terms).toEqual(["governments"]);
  });

  it("matches custom terms as their own target", () => {
    const [m] = matchGroup(ctx, groupById("G0005"), [], ["german banks", " "]);
    expect(m!.label).toBe("“german banks”");
    expect(m!.target).toBe("custom:german banks");
  });

  it("counts the groups each target group matches", () => {
    const counts = targetCounts(ctx);
    expect(counts.get("region:west")).toBe(3);
    expect(counts.get("country:GN")).toBeUndefined();
  });
});

describe("last seen filter", () => {
  const base = { targets: ["region:west", "sector:government", "sector:energy"] };

  it("hides groups last seen before the year but keeps unknown ones", () => {
    expect(ids(fixtureProfile({ ...base, seenSince: 2024 }))).toEqual(["G0004:2", "G0001:2", "G0002:2"]);
  });

  it("hides unknown ones only when asked", () => {
    expect(ids(fixtureProfile({ ...base, seenSince: 2024, hideUnknownSeen: true }))).toEqual(["G0004:2", "G0001:2"]);
  });
});

describe("reasons and export", () => {
  const profile = fixtureProfile({ countries: ["RU"], targets: ["region:west", "sector:government"] });
  const [first] = suggest(ctx, profile);

  it("explains a pick for apt2rule", () => {
    expect(reasonFor(ctx, first!, profile, "2026-11-17")).toEqual({
      source: "threat2apt",
      date: "2026-11-17",
      profile: "Test profile",
      attackVersion: "19.1",
      tier: 1,
      countries: [{ code: "RU", name: "Russia", evidence: "Bear One is attributed to Russia.", source: "G0001" }],
      matched: [
        { target: "West", terms: ["European"] },
        { target: "Government", terms: ["government", "ministries"] },
      ],
      lastSeen: "2024-05-01",
    });
  });

  it("writes a Markdown table and CSV", () => {
    const { markdown, csv } = buildTable(ctx, [first!]);
    expect(markdown.split("\n")[2]).toBe(
      "| Bear One | G0001 | 1 | Russia | Bear One is attributed to Russia. (G0001) | West: European; Government: government, ministries | 2024-05-01 |",
    );
    expect(csv.split("\n")[1]).toBe(
      "Bear One,G0001,1,Russia,Bear One is attributed to Russia. (G0001),\"West: European; Government: government, ministries\",2024-05-01",
    );
  });
});

describe("profiles", () => {
  it("round-trips through export and import", () => {
    const p = { ...newProfile("Mine"), countries: ["RU"], targets: ["region:west"], customTerms: ["x"], seenSince: 2020, picks: { G0001: false } };
    expect(parseProfile(exportProfile(p))).toEqual(p);
  });

  it("rejects an apt2rule profile", () => {
    expect(() => parseProfile(JSON.stringify({ schemaVersion: 1, name: "x", groups: [] }))).toThrow(/threat2apt/);
  });
});
