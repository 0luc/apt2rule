import json
from pathlib import Path

import jsonschema
import pytest

from apt2rule_pipeline.dataset import PipelineError
from apt2rule_pipeline.threat2apt import build_threat2apt
from stix import campaign, group, rel

SCHEMA = json.loads((Path(__file__).parents[2] / "schema" / "threat2apt.schema.json").read_text())


@pytest.fixture
def no_overrides(tmp_path: Path) -> Path:
    path = tmp_path / "overrides.json"
    path.write_text("{}")
    return path


def dated_campaign(external_id, name, description="", last_seen=None):
    c = campaign(external_id, name)
    c["description"] = description
    if last_seen:
        c["last_seen"] = last_seen
    return c


def test_builds_groups_with_attribution_last_seen_and_texts(make_bundle, no_overrides):
    apt28 = group("G0007", "APT28", ["APT28", "Fancy Bear"],
                  description="[APT28](https://attack.mitre.org/groups/G0007) has been attributed to Russia's GRU.(Citation: X)"
                              "\n\nIt has targeted European governments.")
    c1 = dated_campaign("C0001", "Operation One", "Targeted NATO ministries.", "2023-05-01T00:00:00.000Z")
    c2 = dated_campaign("C0002", "Operation Two", "Hit German energy.", "2024-11-30T00:00:00.000Z")
    dataset = build_threat2apt(
        make_bundle([apt28, c2, c1, rel(c1, "attributed-to", apt28), rel(c2, "attributed-to", apt28)]),
        built_at="2026-11-17T00:00:00Z",
        overrides_path=no_overrides,
    )
    jsonschema.validate(dataset, SCHEMA)
    [g] = dataset["groups"]
    assert g["aliases"] == ["Fancy Bear"]
    assert g["attribution"] == [{"country": "RU", "evidence": "APT28 has been attributed to Russia's GRU.", "source": "G0007"}]
    assert g["lastSeen"] == "2024-11-30"
    assert g["texts"] == [
        {"source": "G0007", "name": "APT28", "text": "APT28 has been attributed to Russia's GRU.\n\nIt has targeted European governments."},
        {"source": "C0001", "name": "Operation One", "text": "Targeted NATO ministries."},
        {"source": "C0002", "name": "Operation Two", "text": "Hit German energy."},
    ]
    assert {"code": "DE", "name": "Germany", "terms": ["Germany", "German"]} in dataset["countries"]


def test_groups_without_campaigns_or_attribution_are_unknown(make_bundle, no_overrides):
    dataset = build_threat2apt(make_bundle([group("G0001", "Quiet", description="A threat group.")]), "x", no_overrides)
    [g] = dataset["groups"]
    assert g["attribution"] == []
    assert g["lastSeen"] is None


def test_an_override_replaces_the_attribution_and_keeps_agreeing_evidence(make_bundle, tmp_path):
    overrides = tmp_path / "overrides.json"
    overrides.write_text(json.dumps({"G1008": {"countries": ["PK", "AF"], "reason": "Checked by hand."}}))
    text = "SideCopy is a Pakistani threat group. It mimics Sidewinder, a suspected Indian threat group."
    dataset = build_threat2apt(make_bundle([group("G1008", "SideCopy", description=text)]), "x", overrides)
    assert dataset["groups"][0]["attribution"] == [
        {"country": "PK", "evidence": "SideCopy is a Pakistani threat group.", "source": "G1008"},
        {"country": "AF", "evidence": "Checked by hand.", "source": "override"},
    ]


def test_fails_loudly_on_an_override_for_a_group_that_does_not_exist(make_bundle, tmp_path):
    overrides = tmp_path / "overrides.json"
    overrides.write_text(json.dumps({"G0999": {"countries": ["RU"], "reason": "x"}}))
    with pytest.raises(PipelineError, match="G0999"):
        build_threat2apt(make_bundle([]), "x", overrides)


def test_the_shipped_overrides_file_is_valid(make_bundle):
    from apt2rule_pipeline.threat2apt import OVERRIDES, _read_overrides
    assert _read_overrides(OVERRIDES)
