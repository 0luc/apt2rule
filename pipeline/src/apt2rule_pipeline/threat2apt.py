"""Builds the threat2apt dataset: ATT&CK groups with their country attribution, last seen and searchable text."""

import json
import re
from collections import defaultdict
from pathlib import Path

from .attribution import attribute
from .countries import BY_CODE, COUNTRIES
from .dataset import PipelineError, _external_id

OVERRIDES = Path(__file__).with_name("attribution_overrides.json")


def build_threat2apt(stix_bundle: Path, built_at: str, overrides_path: Path = OVERRIDES) -> dict:
    objects = json.loads(stix_bundle.read_text())["objects"]
    versions = {o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"}
    if len(versions) != 1 or None in versions:
        raise PipelineError(f"{stix_bundle.name}: cannot determine the ATT&CK version from its x-mitre-collection")
    overrides = _read_overrides(overrides_path)

    def live(o: dict | None) -> bool:
        return o is not None and not o.get("revoked") and not o.get("x_mitre_deprecated")

    by_id = {o["id"]: o for o in objects}
    campaigns_of: dict[str, list[dict]] = defaultdict(list)
    for r in objects:
        if r["type"] != "relationship" or r["relationship_type"] != "attributed-to" or not live(r):
            continue
        source, target = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
        if live(source) and live(target) and source["type"] == "campaign" and target["type"] == "intrusion-set":
            campaigns_of[target["id"]].append(source)

    groups = []
    for o in objects:
        if o["type"] != "intrusion-set" or not live(o):
            continue
        group_id = _external_id(o)
        campaigns = sorted(campaigns_of[o["id"]], key=lambda c: _external_id(c) or "")
        texts = [{"source": group_id, "name": o["name"], "text": plain_text(o.get("description", ""))}]
        texts += [{"source": _external_id(c), "name": c["name"], "text": plain_text(c.get("description", ""))} for c in campaigns]
        attribution = attribute([(t["source"], t["text"]) for t in texts])
        if group_id in overrides:
            attribution = _apply_override(attribution, overrides.pop(group_id))
        seen = [c["last_seen"][:10] for c in campaigns if c.get("last_seen")]
        groups.append({
            "id": group_id,
            "name": o["name"],
            "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
            "attribution": attribution,
            "lastSeen": max(seen) if seen else None,
            "texts": texts,
        })
    if overrides:
        raise PipelineError(f"attribution overrides for groups not in ATT&CK {versions.pop()}: {', '.join(sorted(overrides))}")
    return {
        "schemaVersion": 1,
        "attack": {"version": versions.pop()},
        "builtAt": built_at,
        "countries": [{"code": c["code"], "name": c["name"], "terms": c["terms"]} for c in COUNTRIES],
        "groups": sorted(groups, key=lambda g: g["id"]),
    }


def plain_text(text: str) -> str:
    """Full description without citations or markdown links; paragraphs separated by a blank line."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    paragraphs = (re.sub(r"\s+", " ", p).strip() for p in text.split("\n\n"))
    return "\n\n".join(p for p in paragraphs if p)


def _read_overrides(path: Path) -> dict:
    overrides = json.loads(path.read_text())
    for group_id, entry in overrides.items():
        countries = entry.get("countries")
        if not re.fullmatch(r"G\d{4}", group_id) or not isinstance(countries, list) or not entry.get("reason"):
            raise PipelineError(f"{path.name}: {group_id} needs a G-ID key, a countries list and a reason")
        unknown = [c for c in countries if c not in BY_CODE]
        if unknown:
            raise PipelineError(f"{path.name}: {group_id} has unknown country codes {unknown}")
    return overrides


def _apply_override(found: list[dict], override: dict) -> list[dict]:
    """The override's countries replace what the text gave; text evidence is kept where it agrees."""
    evidence = {a["country"]: a for a in found}
    return [
        evidence.get(code) or {"country": code, "evidence": override["reason"], "source": "override"}
        for code in override["countries"]
    ]
