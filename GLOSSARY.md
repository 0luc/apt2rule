# Glossary

- **Group**: an ATT&CK intrusion set (`G0007` and so on).
- **Campaign**: an ATT&CK campaign (`C0027` and so on), attributed to a group.
- **Attribution**: the country (or countries) a group is linked to, derived in the pipeline from description sentences that contain an attribution cue. *Unknown* when there is none.
- **Attribution cue**: a phrase such as `attributed to` or `state-sponsored`, or a state agency name, that makes a country word in the same sentence count as attribution rather than as a victim.
- **Evidence**: the sentence or snippet, with its source (group or campaign), that shows why a group got an attribution or a target match.
- **Target group**: a curated list of synonyms for one region, country or sector (for example *West*, *Government*) that threat2apt searches for.
- **Target match**: a term from a ticked target group or a custom term found in a group's or its campaigns' descriptions.
- **Tier**: threat2apt's ranking bucket. Tier 1: ticked country and target match. Tier 2: target match only. Tier 3: ticked country only.
- **Last seen**: the latest `last_seen` across a group's campaigns; *unknown* without campaigns.
- **Reason**: the tier, attribution, matched terms and last seen stored with a group when threat2apt sends it to apt2rule; *manual* for groups added by hand.
- **Profile**: the saved settings of one page (apt2rule or threat2apt), kept in the browser and exportable as JSON. The two pages keep separate profiles.
