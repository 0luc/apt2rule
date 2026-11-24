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
    expect(ids(profile)).toEqual(["G0001:1", "G0004:2", "G0003:2", "G0005:2", "G0002:3"]);
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
      ["G0005", false],
      ["G0002", true],
    ]);
  });
});

describe("your area", () => {
  const base = { countries: ["RU", "CN"], targets: ["sector:government", "sector:energy"], tiers: [1, 2, 3] as const };
  const rows = (extra: Partial<Parameters<typeof fixtureProfile>[0]> = {}) =>
    suggest(ctx, fixtureProfile({ ...base, tiers: [1, 2, 3], ...extra })).map((s) => [s.group.id, s.location, s.picked]);

  it("is off without an area: tier 1 is ticked", () => {
    expect(rows()).toEqual([
      ["G0001", null, true],
      ["G0002", null, true],
      ["G0004", null, false],
      ["G0003", null, false],
    ]);
  });

  it("ticks groups naming a place in your area, whatever their tier, and ranks elsewhere last", () => {
    // G0001 names Europe; G0002 only Asia; G0004 "Western" (West); G0003 NATO and the U.S. in a campaign
    expect(rows({ area: ["region:europe", "region:west"] })).toEqual([
      ["G0001", "area", true],
      ["G0002", "elsewhere", false],
      ["G0004", "area", true],
      ["G0003", "area", true],
    ]);
    expect(rows({ area: ["region:europe"] })).toEqual([
      ["G0001", "area", true],
      ["G0002", "elsewhere", false],
      ["G0004", "elsewhere", false],
      ["G0003", "elsewhere", false],
    ]);
  });

  it("calls a group naming no place (other than its own country) unknown, and leaves it unticked", () => {
    const [coin] = suggest(ctx, fixtureProfile({ countries: ["KP"], area: ["region:europe"] }));
    expect(coin?.group.id).toBe("G0007");
    expect(coin?.location).toBe("unknown");
    expect(coin?.picked).toBe(false);
  });

  it("hides groups that only target elsewhere when asked", () => {
    expect(rows({ area: ["region:europe"], hideElsewhere: true }).map((r) => r[0])).toEqual(["G0001"]);
  });

  it("names the places in the reason and the table", () => {
    const profile = fixtureProfile({ ...base, tiers: [1, 2, 3], area: ["region:europe"] });
    const [first, second] = suggest(ctx, profile);
    expect(reasonFor(ctx, first!, profile, "2026-11-24").location).toEqual({ status: "area", places: ["Europe"] });
    expect(buildTable(ctx, [second!]).csv.split("\n")[1]).toContain(",elsewhere: Asia-Pacific,");
  });
});

describe("exclusions", () => {
  const profile = (exclusions: Record<string, string[]>) => fixtureProfile({ countries: ["KP", "RU"], exclusions });

  it("drops a threat country's groups that match an excluded target, unticked and with the reason", () => {
    const coin = suggest(ctx, profile({ KP: ["sector:crypto"] })).find((s) => s.group.id === "G0007")!;
    expect(coin.excludedBy.map((x) => [x.country, x.matches.map((m) => m.label)])).toEqual([["KP", ["Cryptocurrency"]]]);
    expect(coin.picked).toBe(false);
  });

  it("only applies to the country the rule belongs to", () => {
    const all = suggest(ctx, profile({ RU: ["sector:crypto"] }));
    expect(all.every((s) => !s.excludedBy.length)).toBe(true);
  });

  it("keeps a group that doesn't match the excluded target", () => {
    const all = suggest(ctx, profile({ RU: ["sector:finance"] }));
    expect(all.filter((s) => s.excludedBy.length)).toEqual([]);
  });
});

describe("ordering within a tier", () => {
  it("ranks by number of target groups matched, then last seen (newest first, unknown last), then name", () => {
    const profile = fixtureProfile({ targets: ["region:west", "sector:government", "sector:defence", "sector:energy"] });
    // G0003 matches West + Defence (2); G0004 West + Government (2, newer); G0001 West + Government (2, older);
    // G0002 Energy (1, named Bear Two); G0005 West through "German" (1, named Islander)
    expect(ids(profile)).toEqual(["G0004:2", "G0001:2", "G0003:2", "G0002:2", "G0005:2"]);
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

  it("matches a region through the names of its countries", () => {
    const [m] = matchGroup(ctx, groupById("G0005"), ["region:europe"], []);
    expect(m!.terms).toEqual(["German"]);
  });

  it("doesn't count a group's own country towards a region of its location", () => {
    // Coin Thief's only place is North Korea, its own country; Bear One names Europe ("European")
    expect(ctx.places.get("G0007")).toEqual([]);
    expect(ctx.places.get("G0001")!.map((m) => m.target)).toEqual(["region:west", "region:europe"]);
  });

  it("matches custom terms as their own target", () => {
    const [m] = matchGroup(ctx, groupById("G0005"), [], ["german banks", " "]);
    expect(m!.label).toBe("“german banks”");
    expect(m!.target).toBe("custom:german banks");
  });

  it("counts the groups each target group matches", () => {
    const counts = targetCounts(ctx);
    expect(counts.get("region:west")).toBe(4);
    expect(counts.get("country:GN")).toBeUndefined();
  });
});

describe("last seen filter", () => {
  const base = { targets: ["region:west", "sector:government", "sector:energy"] };

  it("hides groups last seen before the year but keeps unknown ones", () => {
    expect(ids(fixtureProfile({ ...base, seenSince: 2024 }))).toEqual(["G0004:2", "G0001:2", "G0002:2", "G0005:2"]);
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
      "| Bear One | G0001 | 1 | Russia | Bear One is attributed to Russia. (G0001) | West: European; Government: government, ministries |  | 2024-05-01 |",
    );
    expect(csv.split("\n")[1]).toBe(
      "Bear One,G0001,1,Russia,Bear One is attributed to Russia. (G0001),\"West: European; Government: government, ministries\",,2024-05-01",
    );
  });
});

describe("profiles", () => {
  it("round-trips through export and import", () => {
    const p = {
      ...newProfile("Mine"),
      countries: ["RU"],
      area: ["region:europe"],
      targets: ["sector:government"],
      customTerms: ["x"],
      exclusions: { KP: ["sector:crypto"] },
      hideElsewhere: true,
      seenSince: 2020,
      picks: { G0001: false },
    };
    expect(parseProfile(exportProfile(p))).toEqual(p);
  });

  it("moves the regions and countries of a profile from before areas into its area", () => {
    const old = { kind: "threat2apt", schemaVersion: 1, name: "Old", countries: ["RU"], targets: ["region:west", "sector:energy", "country:DE"] };
    const p = parseProfile(JSON.stringify(old));
    expect(p.area).toEqual(["region:west", "country:DE"]);
    expect(p.targets).toEqual(["sector:energy"]);
  });

  it("rejects an apt2rule profile", () => {
    expect(() => parseProfile(JSON.stringify({ schemaVersion: 1, name: "x", groups: [] }))).toThrow(/threat2apt/);
  });
});
