# ADR 0003: threat2apt, ransomware as a threat and stricter tier 2 ticks

Status: accepted

## Context

Threat assessments often name only state actors, while for many organisations criminal ransomware is the most likely way to be disrupted. In threat2apt such groups only showed up by accident: when their description happened to say "Russia-based", or when they named a sector the user ticked. Most ransomware descriptions name neither a country nor a sector nor a place.

With an area (ADR 0002), tier 2 groups in the area were ticked by default even when they were attributed to a country the assessment deliberately left out.

## Decision

- **Ransomware and extortion** is a threat next to the countries in step 01. A group matches when its texts say *ransomware*, *ransomware-as-a-service*, *RaaS*, *extortion* or *double extortion*, whatever its country. It counts like a ticked country: tiers are threat and sector, sector only, threat only.
- "Financially motivated" and "cybercriminal" are not matched. Tried first, they also pulled in bank-fraud groups from a decade ago and North Korea's revenue groups (Lazarus: "financially motivated campaigns"), so an exclusion meant for one swept up the other.
- Ransomware strikes anywhere: a ransomware match that names no place is ticked by default. One that only names places elsewhere is not.
- Ransomware carries its own exclusions, like a country, and can itself be chosen as an exclusion for a country.
- With an area, a tier 2 group is ticked by default only when its attribution is unknown. A group attributed to countries the user didn't tick stays unticked; it can still be ticked by hand.

## Consequences

- The ransomware list follows ATT&CK's wording: groups described only as "financially motivated" (FIN7-style intrusion sets) are not caught, and state groups that deploy ransomware (Agrius, Cinnamon Tempest) are. The evidence panel shows which word matched.
