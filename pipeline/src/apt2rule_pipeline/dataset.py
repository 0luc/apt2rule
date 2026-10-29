"""Turns an Elastic prebuilt rule package and an ATT&CK STIX bundle into an apt2rule dataset."""

import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path


class PipelineError(Exception):
    """A source file does not look the way the pipeline expects. Never publish a dataset after this."""


def build_dataset(package_zip: Path, stix_bundle: Path, built_at: str) -> dict:
    package_version, rules = _read_package(package_zip)
    attack_version, attack = _read_attack(stix_bundle)
    redirects = attack["techniqueRedirects"]
    for rule in rules:
        rule["techniques"] = sorted({redirects.get(t, t) for t in rule["techniques"]})
    return {
        "schemaVersion": 2,
        "ruleset": {"packageVersion": package_version, "stackMinor": ".".join(package_version.split(".")[:2])},
        "attack": {"version": attack_version},
        "builtAt": built_at,
        **attack,
        "rules": rules,
        "tags": sorted({t for r in rules for t in r["tags"]}),
    }


def _read_package(package_zip: Path) -> tuple[str, list[dict]]:
    latest: dict[str, dict] = {}
    with zipfile.ZipFile(package_zip) as z:
        manifests = [n for n in z.namelist() if n.count("/") == 1 and n.endswith("/manifest.yml")]
        if len(manifests) != 1:
            raise PipelineError(f"{package_zip.name}: expected one manifest.yml, found {len(manifests)}")
        match = re.search(r"^version:\s*['\"]?(\d+\.\d+\.\d+)['\"]?\s*$", z.read(manifests[0]).decode(), re.MULTILINE)
        if not match:
            raise PipelineError(f"{package_zip.name}: manifest.yml has no version")
        for name in z.namelist():
            if "/kibana/security_rule/" not in name or not name.endswith(".json"):
                continue
            try:
                attributes = json.loads(z.read(name))["attributes"]
                attributes["rule_id"], attributes["version"]
            except (KeyError, TypeError, ValueError) as e:
                raise PipelineError(f"{name}: not a security rule saved object ({e!r})") from e
            current = latest.get(attributes["rule_id"])
            if current is None or attributes["version"] > current["version"]:
                latest[attributes["rule_id"]] = attributes
    return match.group(1), [_rule(a) for _, a in sorted(latest.items()) if not a.get("deprecated")]


def _rule(attributes: dict) -> dict:
    """Converts one security-rule saved object's attributes into a dataset rule."""
    try:
        return _rule_fields(attributes)
    except (KeyError, TypeError) as e:
        raise PipelineError(f"rule {attributes.get('rule_id')} v{attributes.get('version')}: unexpected shape, missing {e}") from e


def _rule_fields(a: dict) -> dict:
    techniques = set()
    for threat in a.get("threat", []):
        if threat.get("framework") != "MITRE ATT&CK":
            continue
        for technique in threat.get("technique", []):
            subtechniques = technique.get("subtechnique", [])
            techniques.update(s["id"] for s in subtechniques)
            if not subtechniques:
                techniques.add(technique["id"])
    return {
        "ruleId": a["rule_id"],
        "name": a["name"],
        "type": a["type"],
        "severity": a["severity"],
        "buildingBlock": bool(a.get("building_block_type")),
        "tags": sorted(set(a.get("tags", []))),
        "techniques": sorted(techniques),
    }


def _read_attack(stix_bundle: Path) -> tuple[str, dict]:
    objects = json.loads(stix_bundle.read_text())["objects"]
    versions = {o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"}
    if len(versions) != 1 or None in versions:
        raise PipelineError(f"{stix_bundle.name}: cannot determine the ATT&CK version from its x-mitre-collection")
    by_id = {o["id"]: o for o in objects}
    external_ids = {o["id"]: _external_id(o) for o in objects if _external_id(o)}

    def live(o: dict | None) -> bool:
        return o is not None and not o.get("revoked") and not o.get("x_mitre_deprecated")

    uses: dict[str, set[str]] = defaultdict(set)  # source STIX id -> target STIX ids
    campaigns_of: dict[str, set[str]] = defaultdict(set)  # group STIX id -> campaign STIX ids
    group_redirects: dict[str, str] = {}
    technique_redirects: dict[str, str] = {}
    for r in objects:
        if r["type"] != "relationship" or not live(r):
            continue
        source, target = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
        if source is None or target is None:
            continue
        kind = r["relationship_type"]
        if kind == "revoked-by" and live(target):
            redirects = {"intrusion-set": group_redirects, "attack-pattern": technique_redirects}.get(source["type"])
            if redirects is not None:
                redirects[external_ids[source["id"]]] = external_ids[target["id"]]
        elif not (live(source) and live(target)):
            continue
        elif kind == "uses":
            uses[source["id"]].add(target["id"])
        elif kind == "attributed-to" and source["type"] == "campaign" and target["type"] == "intrusion-set":
            campaigns_of[target["id"]].add(source["id"])

    def techniques_used_by(stix_ids) -> list[str]:
        return sorted({external_ids[t] for s in stix_ids for t in uses[s] if by_id[t]["type"] == "attack-pattern"})

    groups = []
    for o in objects:
        if o["type"] != "intrusion-set" or not live(o):
            continue
        software = [t for t in uses[o["id"]] if by_id[t]["type"] in ("malware", "tool")]
        groups.append({
            "id": external_ids[o["id"]],
            "name": o["name"],
            "aliases": o.get("aliases", []),
            "description": _short_description(o.get("description", "")),
            "techniques": {
                "direct": techniques_used_by([o["id"]]),
                "campaign": techniques_used_by(campaigns_of[o["id"]]),
                "software": techniques_used_by(software),
            },
        })
    techniques = [
        {"id": external_ids[o["id"]], "name": o["name"]}
        for o in objects
        if o["type"] == "attack-pattern" and live(o)
    ]
    return versions.pop(), {
        "techniques": sorted(techniques, key=lambda t: t["id"]),
        "groups": sorted(groups, key=lambda g: g["id"]),
        "groupRedirects": dict(sorted(group_redirects.items())),
        "techniqueRedirects": dict(sorted(technique_redirects.items())),
    }


def _external_id(o: dict) -> str | None:
    for ref in o.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _short_description(text: str) -> str:
    """First paragraph, without citations or markdown links."""
    first = text.strip().split("\n\n")[0]
    first = re.sub(r"\(Citation:[^)]*\)", "", first)
    first = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", first)
    return re.sub(r"\s+", " ", first).strip()
