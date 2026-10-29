from apt2rule_pipeline.dataset import build_dataset
from stix import campaign, group, rel, software, technique

T1003 = technique("T1003", "OS Credential Dumping")
T1059 = technique("T1059", "Command and Scripting Interpreter")
T1059_001 = technique("T1059.001", "PowerShell")
T1105 = technique("T1105", "Ingress Tool Transfer")
T1566_001 = technique("T1566.001", "Spearphishing Attachment")


def build(make_package, make_bundle, objects):
    return build_dataset(make_package([]), make_bundle(objects), built_at="2026-10-29T00:00:00Z")


def test_lists_techniques_with_their_ids_and_names(make_package, make_bundle):
    dataset = build(make_package, make_bundle, [T1059_001, T1003, T1059])
    assert dataset["techniques"] == [
        {"id": "T1003", "name": "OS Credential Dumping"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1059.001", "name": "PowerShell"},
    ]


def test_collects_group_techniques_per_provenance(make_package, make_bundle):
    apt1 = group("G0001", "APT1", ["APT1", "Comment Crew"])
    c0001 = campaign("C0001", "Operation Test")
    s0001 = software("S0001", "Mimikatz", kind="tool")
    dataset = build(make_package, make_bundle, [
        T1003, T1059_001, T1105, T1566_001, apt1, c0001, s0001,
        rel(apt1, "uses", T1059_001),
        rel(c0001, "attributed-to", apt1),
        rel(c0001, "uses", T1566_001),
        rel(apt1, "uses", s0001),
        rel(s0001, "uses", T1003),
        rel(s0001, "uses", T1105),
    ])
    [g] = dataset["groups"]
    assert g["id"] == "G0001"
    assert g["name"] == "APT1"
    assert g["aliases"] == ["APT1", "Comment Crew"]
    assert g["techniques"] == {"direct": ["T1059.001"], "campaign": ["T1566.001"], "software": ["T1003", "T1105"]}


def test_drops_revoked_and_deprecated_objects_and_relationships(make_package, make_bundle):
    apt1 = group("G0001", "APT1")
    old_group = group("G0099", "Old group", revoked=True)
    gone = group("G0098", "Gone group", x_mitre_deprecated=True)
    old_technique = technique("T1086", "PowerShell (old)", revoked=True)
    dataset = build(make_package, make_bundle, [
        T1003, old_technique, apt1, old_group, gone,
        rel(apt1, "uses", T1003),
        rel(apt1, "uses", old_technique),
        rel(apt1, "uses", T1059, revoked=True),
    ])
    assert [g["id"] for g in dataset["groups"]] == ["G0001"]
    assert dataset["groups"][0]["techniques"]["direct"] == ["T1003"]
    assert [t["id"] for t in dataset["techniques"]] == ["T1003"]


def test_maps_revoked_ids_to_their_replacements(make_package, make_bundle):
    apt2 = group("G0002", "APT2")
    old_group = group("G0099", "Old group", revoked=True)
    old_technique = technique("T1086", "PowerShell (old)", revoked=True)
    dataset = build(make_package, make_bundle, [
        T1059_001, old_technique, apt2, old_group,
        rel(old_group, "revoked-by", apt2),
        rel(old_technique, "revoked-by", T1059_001),
    ])
    assert dataset["groupRedirects"] == {"G0099": "G0002"}
    assert dataset["techniqueRedirects"] == {"T1086": "T1059.001"}


def test_shortens_group_descriptions_to_plain_text(make_package, make_bundle):
    description = (
        "[APT29](https://attack.mitre.org/groups/G0016) is a threat group attributed to a service.(Citation: Report 2020)"
        "(Citation: Other 2021) It has operated since 2008.\n\nSecond paragraph with more detail."
    )
    dataset = build(make_package, make_bundle, [group("G0016", "APT29", description=description)])
    assert dataset["groups"][0]["description"] == "APT29 is a threat group attributed to a service. It has operated since 2008."
