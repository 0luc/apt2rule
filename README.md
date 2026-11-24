# apt2rule

**https://0luc.github.io/apt2rule/**

Turn the APT groups from your threat analysis into tags on the matching Elastic prebuilt detection rules.

> **Disclaimer:** apt2rule is fully vibe coded (built with AI assistance) and comes with no guarantees. Always run the dry run and review the rules before enabling or disabling anything in your cluster.

1. Pick the Elastic prebuilt ruleset version that matches your stack.
2. Select the MITRE ATT&CK groups relevant to your organisation (search by name or alias, or paste a list).
3. Narrow the techniques: see how many of your groups use each one, set a minimum, tick techniques in or out.
4. Optionally filter the rules on their Kibana tags (`Data Source: Elastic Defend`, `OS: Linux`, …). Within a tag category any ticked tag matches; across categories all must match.
5. Optionally list tags that make Kibana skip a rule, e.g. `disabled-*` (the default; a trailing `*` matches a prefix) for rules you disabled on purpose. By default Kibana also skips rules that are disabled but have run before: someone switched them off, and unlike a tag that survives Elastic rule updates.
6. Copy the **Dry run** Kibana Dev Tools snippet and check the counts, then the **Production** snippet. It **only adds one tag**, `apt2rule:<date>`, to the rules that cover your groups' techniques. Rules removed by your tag filter get no tag; the coverage report lists them.
7. In Kibana, filter the rules table on that tag and bulk-enable after review.

Not sure which groups to pick? **[threat2apt](https://0luc.github.io/apt2rule/threat2apt/)** suggests them:

1. Tick the threats your assessment names (countries, and optionally ransomware and extortion), your area (for example Europe and your country) and your sector. Optionally exclude per threat what you rule out, for example North Korea + Cryptocurrency.
2. threat2apt reads every ATT&CK group and campaign description. Tier 1: a threat match (a ticked country, or ransomware) *and* your sector. Tier 2: sector match only. Tier 3: threat only. Groups that name a place in your area are ticked; groups that only name places elsewhere sink to the bottom. Each suggestion shows the sentences that prove it.
3. Tick the groups you agree with and **Send to apt2rule**: they arrive with their reasons, which also appear in the coverage report. Or copy them as a Markdown or CSV table for your threat analysis.

Attribution is read from description text (ATT&CK has no country field) and can be wrong or missing: check the evidence. See [ADR 0001](docs/adr/0001-threat2apt-group-suggestions.md) , [ADR 0002](docs/adr/0002-threat2apt-area-and-exclusions.md) and [ADR 0003](docs/adr/0003-threat2apt-ransomware-and-tier-2.md).

Everything runs in your browser. Profiles are stored in your browser's local storage and can be exported as JSON. apt2rule never connects to your cluster.

## Before you run the snippet

- **Install all Elastic prebuilt rules** in Kibana first (Rules > Add Elastic rules). They install disabled. Kibana can only tag rules that are installed.
- Choose the ruleset version that is installed in your cluster (Management → Integrations → Prebuilt Security Detection Rules → Settings, or `GET kbn:/api/fleet/epm/packages/security_detection_engine` in Dev Tools). Only rules in that version are tagged.
- Always run the **Dry run** snippet first and compare the counts with the comments in it.
- The snippet tags all selected rules in **one request**. Each `rule_id` is one clause in the query; if your cluster's `indices.query.bool.max_clause_count` is lower than the number of rules, the dry run fails with a "too many clauses" error. Narrow the selection (fewer groups, a higher minimum, tag filters) in that case.
- Tagging prebuilt rules needs Elastic's *prebuilt rule customization* (Kibana 8.18 / 9.0+, Enterprise licence). A tagged prebuilt rule counts as **customised**; when Elastic upgrades it, the upgrade may drop your tags. Re-run apt2rule after upgrading rules.

## How it works

```
pipeline/   Python. Downloads Elastic prebuilt rule packages (Elastic Package Registry) and
            MITRE ATT&CK STIX data, and writes one compact dataset per ruleset version,
            plus threat2apt.json (groups with country attribution and searchable text).
schema/     JSON Schemas of those datasets: the contract between pipeline and site.
web/        TypeScript static site with two pages. The engine (src/engine) is a pure function
            (dataset, profile, date) -> result; the UI is a thin layer on top. threat2apt
            (threat2apt/, src/threat2apt) has its own engine and hands groups to apt2rule
            through the browser's local storage.
```

- Ruleset versions: the latest GA patch of every stack minor from 8.19 up.
- ATT&CK version follows the ruleset, like Elastic's own mappings: v19.1 for stack 9.5+, v18.1 before.
- A group's techniques are its direct techniques plus those of campaigns attributed to it; techniques from its software are optional.
- Rules match on the exact technique or sub-technique ID. Elastic nests sub-techniques under their parent; such a parent entry does not count as a mapping of its own.
- Revoked ATT&CK IDs are followed to their replacements; revoked and deprecated objects and deprecated rules are dropped.

A GitHub Actions workflow rebuilds the datasets nightly and deploys the site to GitHub Pages.

## Development

```sh
# pipeline (needs uv)
cd pipeline
uv run pytest
uv run python -m apt2rule_pipeline --out ../web/public/data   # downloads ~25 MB per ruleset version

# site (needs Node 24+)
cd web
npm ci
npm test
npm run dev
```

Offline / air-gapped: run `npm run build` after building the data, copy `web/dist`, and serve it with any static web server (for example `python3 -m http.server`). Opening `index.html` from disk does not work because the browser blocks loading the data files.

## Verified on a real cluster

Checked against a real Kibana cluster (dry run and production):

- [x] `alert.attributes.params.ruleId` selects rules by `rule_id` in `_bulk_action` queries.
- [x] `_bulk_action` with `action: edit` / `add_tags` and a `query` works on prebuilt rules, in Dev Tools with the `kbn:` prefix.
- [x] `dry_run=true` reports the matched rules without changing anything.
- [x] Rules carrying an ignored tag are skipped, including the `*` prefix match (`NOT alert.attributes.tags: (disabled-*)`).

Still open:

- [ ] What happens to the `apt2rule:` tag when Elastic upgrades a tagged prebuilt rule.
- [ ] Rules that are disabled but have run before are skipped (`NOT (alert.attributes.enabled: false AND alert.attributes.lastRun.outcome: *)`), and an Elastic upgrade keeps a rule's last run.

## Attribution

Group and technique data: [MITRE ATT&CK®](https://attack.mitre.org/), © The MITRE Corporation, used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Rule metadata (not rule queries): [Elastic prebuilt detection rules](https://github.com/elastic/detection-rules), Elastic License 2.0. apt2rule is not affiliated with or endorsed by MITRE or Elastic.

Code: [MIT](LICENSE).
