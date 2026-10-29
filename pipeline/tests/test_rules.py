from apt2rule_pipeline.dataset import build_dataset
from conftest import rule


def build(make_package, make_bundle, rules):
    return build_dataset(make_package(rules), make_bundle([]), built_at="2026-10-29T00:00:00Z")


def test_keeps_only_the_highest_version_of_each_rule(make_package, make_bundle):
    dataset = build(make_package, make_bundle, [
        rule("r1", 1, {"T1003": []}),
        rule("r1", 3, {"T1059": []}),
        rule("r1", 2, {"T1027": []}),
    ])
    assert [(r["ruleId"], r["techniques"]) for r in dataset["rules"]] == [("r1", ["T1059"])]


def test_flattens_techniques_and_subtechniques(make_package, make_bundle):
    dataset = build(make_package, make_bundle, [rule("r1", 1, {"T1059": ["T1059.001", "T1059.003"], "T1003": []})])
    assert dataset["rules"][0]["techniques"] == ["T1003", "T1059.001", "T1059.003"]


def test_a_parent_only_counts_when_it_has_no_subtechniques_listed(make_package, make_bundle):
    # Elastic nests sub-techniques under their parent; that parent entry is structural, not a claim.
    dataset = build(make_package, make_bundle, [rule("r1", 1, {"T1059": ["T1059.001"]}), rule("r2", 1, {"T1059": []})])
    assert [r["techniques"] for r in dataset["rules"]] == [["T1059.001"], ["T1059"]]


def test_copies_the_rule_metadata_the_engine_needs(make_package, make_bundle):
    dataset = build(make_package, make_bundle, [
        rule("r1", 1, {"T1003": []}, [{"package": "endpoint", "version": "^9"}, {"package": "aws", "integration": "cloudtrail", "version": "^3"}],
             name="LSASS access", type="machine_learning", severity="high", building_block_type="default"),
    ])
    assert dataset["rules"] == [{
        "ruleId": "r1",
        "name": "LSASS access",
        "type": "machine_learning",
        "severity": "high",
        "buildingBlock": True,
        "integrations": ["aws/cloudtrail", "endpoint"],
        "techniques": ["T1003"],
    }]
    assert dataset["integrations"] == ["aws/cloudtrail", "endpoint"]


def test_drops_rules_whose_latest_version_is_deprecated(make_package, make_bundle):
    deprecated = {"id": "r1_2", "type": "security-rule",
                  "attributes": {"rule_id": "r1", "version": 2, "name": "Old", "deprecated": True, "deprecated_reason": "gone"}}
    dataset = build(make_package, make_bundle, [rule("r1", 1, {"T1003": []}), deprecated, rule("r2", 1)])
    assert [r["ruleId"] for r in dataset["rules"]] == ["r2"]


def test_ignores_threat_mappings_from_other_frameworks(make_package, make_bundle):
    r = rule("r1", 1, {"T1003": []})
    r["attributes"]["threat"][0]["framework"] = "MITRE ATLAS"
    dataset = build(make_package, make_bundle, [r])
    assert dataset["rules"][0]["techniques"] == []
