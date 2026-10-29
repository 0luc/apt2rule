"""Tiny STIX 2.1 object builders for pipeline tests."""


def _ref(kind, external_id):
    return [{"source_name": "mitre-attack", "external_id": external_id, "url": f"https://attack.mitre.org/{kind}/{external_id}"}]


def technique(external_id, name, **extra):
    return {"type": "attack-pattern", "id": f"attack-pattern--{external_id}", "name": name,
            "x_mitre_is_subtechnique": "." in external_id, "external_references": _ref("techniques", external_id), **extra}


def group(external_id, name, aliases=(), description="", **extra):
    return {"type": "intrusion-set", "id": f"intrusion-set--{external_id}", "name": name, "aliases": list(aliases),
            "description": description, "external_references": _ref("groups", external_id), **extra}


def campaign(external_id, name):
    return {"type": "campaign", "id": f"campaign--{external_id}", "name": name, "external_references": _ref("campaigns", external_id)}


def software(external_id, name, kind="malware"):
    return {"type": kind, "id": f"{kind}--{external_id}", "name": name, "external_references": _ref("software", external_id)}


def rel(source, kind, target, **extra):
    return {"type": "relationship", "id": f"relationship--{source['id']}-{kind}-{target['id']}", "relationship_type": kind,
            "source_ref": source["id"], "target_ref": target["id"], **extra}
