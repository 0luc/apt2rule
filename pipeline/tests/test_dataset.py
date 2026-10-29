import json
from pathlib import Path

import jsonschema
import pytest

from apt2rule_pipeline.dataset import PipelineError, build_dataset
from conftest import rule
from stix import group, rel, technique

SCHEMA = json.loads((Path(__file__).parents[2] / "schema" / "dataset.schema.json").read_text())


def test_builds_a_dataset_that_satisfies_the_shared_schema(make_package, make_bundle):
    apt1, t = group("G0001", "APT1"), technique("T1003", "OS Credential Dumping")
    dataset = build_dataset(
        make_package([rule("r1", 1, {"T1003": []}, tags=["OS: Windows"])], version="9.5.9"),
        make_bundle([apt1, t, rel(apt1, "uses", t)]),
        built_at="2026-10-29T00:00:00Z",
    )
    jsonschema.validate(dataset, SCHEMA)
    assert dataset["schemaVersion"] == 2
    assert dataset["ruleset"] == {"packageVersion": "9.5.9", "stackMinor": "9.5"}
    assert dataset["attack"] == {"version": "19.1"}
    assert dataset["builtAt"] == "2026-10-29T00:00:00Z"


def test_fails_loudly_when_a_rule_has_an_unexpected_shape(make_package, make_bundle):
    broken = rule("r1", 1)
    del broken["attributes"]["severity"]
    with pytest.raises(PipelineError, match="r1"):
        build_dataset(make_package([broken]), make_bundle([]), built_at="x")


def test_fails_loudly_when_the_bundle_has_no_attack_version(make_package, make_bundle):
    with pytest.raises(PipelineError, match="ATT&CK version"):
        build_dataset(make_package([]), make_bundle([], attack_version=None), built_at="x")


def test_rewrites_rule_techniques_that_attack_has_revoked(make_package, make_bundle):
    old, new = technique("T1086", "PowerShell (old)", revoked=True), technique("T1059.001", "PowerShell")
    dataset = build_dataset(
        make_package([rule("r1", 1, {"T1086": []})]),
        make_bundle([old, new, rel(old, "revoked-by", new)]),
        built_at="x",
    )
    assert dataset["rules"][0]["techniques"] == ["T1059.001"]
