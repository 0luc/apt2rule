# ADR 0002: threat2apt, your area and per-country exclusions

Status: accepted

## Context

When an analyst picks groups by hand from ATT&CK descriptions, two questions decide most picks: does the group target organisations like mine, and does it do so where I am? A group attributed to a relevant country that attacks governments is still dismissed when its description only names places far away ("shifted from targeting US victims to political organizations in Hong Kong"). And a threat country can be relevant for one kind of activity but not another: a country's groups that only chase cryptocurrency matter little to an organisation that holds none.

In ADR 0001 regions were one more kind of target, ORed with sectors, so "targets Europe" and "targets government" counted the same, and tier 1 filled up with groups an analyst would reject for where they operate.

## Decision

### Your area

- The settings split "Targets like you" into **Your area** (regions and countries: where the organisation is) and **Your sector** (sectors and extra terms: what it is). Tiers stay as they were, with sectors as the target: tier 1 country and sector, tier 2 sector only, tier 3 country only.
- Every group gets a **location** from the places its texts name, other than the countries it is attributed to: *your area* (it names a place in your area), *elsewhere* (it names places, none in your area) or *unknown* (it names none). Without an area the location is off.
- With an area, a group is ticked by default when it is in your area, whatever its tier; without one, tier 1 is ticked as before. Within a tier, your area comes first and elsewhere last. An option hides the elsewhere groups.
- A region also covers its countries: naming "Germany" names Europe. The membership lists live with the regions in `targets.ts`. Russia, Belarus, Turkey and the Caucasus are not in Europe: naming them says little about Europe.
- Profiles from before this change keep working: their region and country targets move into the area.

### Per-country exclusions

- Each ticked threat country can carry exclusions: target groups (sectors, regions or countries) that drop its groups, for example North Korea + Finance + Cryptocurrency. The rule only applies to groups attributed to that country, so Chinese groups that also hit banks are untouched.
- An excluded group is unticked and moves to an "Excluded" section with the rule and the matching sentences. It can still be ticked by hand.
- Cryptocurrency is its own sector, split from Finance, so it can be excluded without banks.

## Consequences

- The default ticks follow where a group operates, not only what it targets. Groups whose descriptions name no place (Turla, Axiom) land under *unknown* and need the analyst's judgement; well-known groups that only name places elsewhere stay visible at the bottom for deliberate exceptions.
- Location is read from text like everything else. A description that mentions Europe in passing ("later Central Europe") counts as your area, and one that names no place is unknown even when the group is known to work everywhere. The evidence panel shows the sentences, so the analyst can judge.
