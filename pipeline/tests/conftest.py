import json
import zipfile
from pathlib import Path

import pytest


def rule(rule_id, version, techniques=(), integrations=(), **extra):
    """A security-rule saved object as found in the Elastic package. techniques: {"T1059": ["T1059.001"]}."""
    threat = [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0002", "name": "Execution", "reference": ""},
            "technique": [
                {"id": t, "name": t, "reference": "", **({"subtechnique": [{"id": s, "name": s, "reference": ""} for s in subs]} if subs else {})}
                for t, subs in dict(techniques).items()
            ],
        }
    ] if techniques else []
    attributes = {
        "rule_id": rule_id,
        "version": version,
        "name": f"Rule {rule_id}",
        "type": "eql",
        "severity": "medium",
        "related_integrations": list(integrations),
        "threat": threat,
        **extra,
    }
    return {"id": f"{rule_id}_{version}", "type": "security-rule", "attributes": attributes}


@pytest.fixture
def make_package(tmp_path: Path):
    def make(rules, version="9.5.9"):
        path = tmp_path / f"security_detection_engine-{version}.zip"
        root = f"security_detection_engine-{version}"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(f"{root}/manifest.yml", f"name: security_detection_engine\nversion: {version}\n")
            z.writestr(f"{root}/kibana/security_rule/", "")
            for r in rules:
                a = r["attributes"]
                z.writestr(f"{root}/kibana/security_rule/{a['rule_id']}_{a['version']}.json", json.dumps(r))
        return path

    return make


@pytest.fixture
def make_bundle(tmp_path: Path):
    def make(objects, attack_version="19.1"):
        path = tmp_path / "enterprise-attack.json"
        collection = [{"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK",
                       "x_mitre_version": attack_version}] if attack_version else []
        path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": collection + objects}))
        return path

    return make
