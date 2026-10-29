# apt2rule

**https://0luc.github.io/apt2rule/**

Turn the APT groups from your threat analysis into tags on the matching Elastic prebuilt detection rules.

1. Pick the Elastic prebuilt ruleset version that matches your stack.
2. Select the MITRE ATT&CK groups relevant to your organisation (search by name or alias, or paste a list).
3. Narrow the techniques: see how many of your groups use each one, set a minimum, tick techniques in or out.
4. Tick the integrations (data sources) you ingest.
5. Copy the Kibana Dev Tools snippet. It **only adds tags**:
   - `apt2rule:<date>` on the rules that cover your groups' techniques
   - `apt2rule(no-APT):<date>` on every other rule in the ruleset
   - rules that match a technique but need an integration you don't have get no tag; the coverage report lists them.
6. In Kibana, filter the rules table by tag and bulk-enable or bulk-disable after review.

Everything runs in your browser. Profiles are stored in your browser's local storage and can be exported as JSON. apt2rule never connects to your cluster.

## Before you run the snippet

- **Install all Elastic prebuilt rules** in Kibana first (Rules > Add Elastic rules). They install disabled. Kibana can only tag rules that are installed.
- Choose the ruleset version that is installed in your cluster. Only rules in that version are tagged.
- Always run the **dry run** requests first and compare the counts with the comments in the snippet.
- Tagging prebuilt rules needs Elastic's *prebuilt rule customization* (Kibana 8.18 / 9.0+, Enterprise licence). A tagged prebuilt rule counts as **customised**; when Elastic upgrades it, the upgrade may drop your tags. Re-run apt2rule after upgrading rules.

## How it works

```
pipeline/   Python. Downloads Elastic prebuilt rule packages (Elastic Package Registry) and
            MITRE ATT&CK STIX data, and writes one compact dataset per ruleset version.
schema/     JSON Schema of that dataset: the contract between pipeline and site.
web/        TypeScript static site. The engine (src/engine) is a pure function
            (dataset, profile, date) -> result; the UI is a thin layer on top.
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

## Still to verify on a real cluster

These Kibana behaviours are assumptions until checked against a Kibana 9.x Enterprise cluster:

- [ ] `alert.attributes.params.ruleId` is the KQL field that selects rules by `rule_id` in `_bulk_action` queries.
- [ ] `_bulk_action` with `action: edit` / `add_tags` and a `query` works on prebuilt rules, in Dev Tools with the `kbn:` prefix.
- [ ] `dry_run=true` reports the matched count without changing anything.
- [ ] 500 `rule_id`s per request stays within Kibana's and Elasticsearch's query limits.
- [ ] Adding a tag marks a prebuilt rule as customised; what happens to the tag on a rule upgrade.

## Attribution

Group and technique data: [MITRE ATT&CK®](https://attack.mitre.org/), © The MITRE Corporation, used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Rule metadata (not rule queries): [Elastic prebuilt detection rules](https://github.com/elastic/detection-rules), Elastic License 2.0. apt2rule is not affiliated with or endorsed by MITRE or Elastic.

Code: [MIT](LICENSE).
