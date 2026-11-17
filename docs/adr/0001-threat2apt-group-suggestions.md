# ADR 0001: threat2apt, a page that suggests ATT&CK groups

Status: accepted

## Context

apt2rule starts from a list of ATT&CK groups that the user already chose. Choosing them is a yearly manual step: an organisation reads its threat assessment, picks the countries whose state actors are likely to target it, and then searches the ATT&CK group descriptions for those countries and for its kind of target (a region, a sector). That search is slow, easy to do inconsistently, and the reasons behind each pick get lost.

apt2rule's own page is already full, so this step does not fit inside its group selection.

## Decision

Add **threat2apt**: a second page in this repo and on the same site (`…/apt2rule/threat2apt/`), linked from apt2rule. It suggests a ranked, explained shortlist of ATT&CK groups. The user makes the final choice and sends it to apt2rule.

### Data

- ATT&CK only, the newest ATT&CK version the site builds (the one apt2rule's newest ruleset uses). No AI and no other intelligence sources in v1.
- Text searched per group: the group's description plus the descriptions of the campaigns attributed to it. Procedure examples and software descriptions are not searched.
- **Country attribution** is computed in the Python pipeline and stored in the dataset:
  - A dictionary per country: country name, adjectives, and state agencies (for example Russia: Russian, GRU, SVR, FSB).
  - A country word only counts **inside** an attribution phrase: `China-based`, `attributed to Russia's …`, `suspected Iranian threat group`, `operating out of China`, `with Chinese origins`, `North Korea–aligned`. Agency names count on their own. This keeps victims ("targeted Russian organisations", "located in the United States") and languages ("Russian-speaking") from being read as attribution. A first version that accepted any country word in a sentence with an attribution cue was too loose: "attributed to Russia's GRU … targets Ukrainian and Georgian organisations" also attributed Ukraine and Georgia.
  - The matching sentence is stored as evidence.
  - An override file in the repo corrects wrong or missing attributions.
  - A group can have several countries, or none (*unknown*).
- The country dictionary lives in `pipeline/src/apt2rule_pipeline/countries.py`, the phrases in `attribution.py`, the override file in `attribution_overrides.json`. An override for a group that no longer exists fails the build.
- **Last seen** is the latest `last_seen` across the group's attributed campaigns, otherwise *unknown*. The group's `modified` date is not used: it changes on any text edit.

- Output: `threat2apt.json` next to the ruleset datasets, contract in `schema/threat2apt.schema.json`. `index.json` points to it.

### Matching

Runs in the browser and updates live.

- The profile holds ticked countries, ticked target groups and custom terms.
- **Target groups** are curated synonym lists in a data file in the repo:
  - regions (for example *West*: Western, NATO, Europe, European, EU, North America, United States, U.S., US, United Kingdom, UK, Canada, Australia),
  - one group per country (name and adjective), generated from a standard country list,
  - sectors (government, energy, finance, defence, healthcare, telecom, education, and so on).
- Every variant is listed explicitly; no stemming or fuzzy matching. Matches are whole-word and case-insensitive, except terms written in capitals (EU, US, UK, NATO, IT), which are case-sensitive.
- A country's term inside another country's name does not count ("Guinea" in "Papua New Guinea", "Sudan" in "South Sudan"), and no term counts inside "non-governmental".
- **Tiers**:
  - Tier 1: an attributed country is ticked **and** a target term matches. Ticked by default.
  - Tier 2: a target term matches, the country is not ticked or unknown.
  - Tier 3: an attributed country is ticked, no target term matches.
- **Order within a tier**: number of distinct target groups matched, then last seen (newest first, unknown last), then name. No weighted score.
- Optional filter: hide groups not seen since a given year. Groups with an unknown last seen are only hidden when the user asks for it.

### Page

- Left: the profile settings (countries with group counts, target groups expandable to their terms, custom terms, seen-since year, tier checkboxes). Collapses above the results on small screens.
- Main: the results table grouped by tier, one checkbox per group. A row expands to its evidence: the attribution sentence and the matched snippets, highlighted and labelled with their source (group or campaign ID).
- Bottom bar: number selected, **Send to apt2rule**, **Copy as table** (Markdown and CSV).
- Profiles are named, stored in the browser's local storage, and exported and imported as JSON. They are separate from apt2rule's profiles. No profile ships preset: the page starts with nothing ticked.

### Handoff to apt2rule

- threat2apt writes the selected groups and their reasons to local storage (same origin) and opens apt2rule.
- apt2rule shows a banner: add the groups to the current profile or to a new one. It only adds, never removes.
- Each received group shows its reason (tier, countries with evidence, matched terms, last seen) in apt2rule and keeps it in the profile JSON. Groups added by hand get the reason *manual*.
- If a group does not exist in the ATT&CK version of the chosen ruleset, apt2rule says so instead of dropping it silently.

### Testing

- Pipeline tests on known groups: APT28 → Russia, APT41 → China, and a group that targets Russia is not attributed to Russia.
- Acceptance test: compare a real profile's tier 1 to an earlier manual selection. That selection and profile stay outside the repo.

## Alternatives considered

- **Output a prompt for an AI chat instead of a list.** Rejected: the result changes per run, the model can invent or misname groups, and nobody can trace why a group was picked.
- **A panel inside apt2rule's group step.** Rejected: that page is already crowded.
- **A separate repo and site.** Rejected: it would duplicate the ATT&CK pipeline and deployment, and the handoff would need copy-paste.
- **AI-tagged targets or countries in the pipeline.** Deferred: API cost, results that drift between runs, and a key in the nightly build. Could be added later as an extra signal.
- **MISP threat-actor galaxy as a source.** Deferred: it has structured country, victim and sector fields, and is the first candidate for enrichment after v1.
- **A separate sector field.** Rejected: sectors are target groups like regions; one mechanism is simpler.
- **A weighted relevance score.** Rejected in favour of a plain sort that anyone can explain.

## Consequences

- apt2rule gets a link to threat2apt, a handoff banner and per-group reasons; its flow is otherwise unchanged.
- The pipeline adds attribution, evidence and last seen to the dataset; the schema in `schema/` grows accordingly.
- The country dictionary and the override file need maintenance when ATT&CK adds groups.
