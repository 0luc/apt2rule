"""Downloads sources and writes the site's data folder.

    python -m apt2rule_pipeline --out ../web/public/data --cache .cache

Writes one ruleset-<version>.json per planned build plus index.json. Nothing is written
unless every build succeeds, so a broken source never replaces a good dataset.
"""

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .dataset import PipelineError, build_dataset
from .plan import plan_builds

EPR_SEARCH = "https://epr.elastic.co/search?package=security_detection_engine&all=true"
EPR_DOWNLOAD = "https://epr.elastic.co/epr/security_detection_engine/security_detection_engine-{version}.zip"
ATTACK_BUNDLE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{version}.json"
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apt2rule_pipeline", description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="data folder of the site")
    parser.add_argument("--cache", type=Path, default=Path(".cache"), help="download cache (sources are immutable)")
    parser.add_argument("--only", help="build just this package version, e.g. 9.5.9")
    args = parser.parse_args(argv)

    builds = plan_builds(json.loads(_fetch(EPR_SEARCH)))
    if args.only:
        builds = [b for b in builds if b["packageVersion"] == args.only]
    if not builds:
        raise PipelineError("no ruleset versions to build")

    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    outputs: dict[str, dict] = {}
    for build in builds:
        print(f"building {build['packageVersion']} with ATT&CK {build['attackVersion']}", file=sys.stderr)
        package = _cached(args.cache, EPR_DOWNLOAD.format(version=build["packageVersion"]))
        bundle = _cached(args.cache, ATTACK_BUNDLE.format(version=build["attackVersion"]))
        dataset = build_dataset(package, bundle, built_at=built_at)
        if dataset["attack"]["version"] != build["attackVersion"]:
            raise PipelineError(f"expected ATT&CK {build['attackVersion']}, bundle says {dataset['attack']['version']}")
        outputs[f"ruleset-{build['packageVersion']}.json"] = dataset

    index = {
        "builtAt": built_at,
        "versions": [{**b, "file": f"ruleset-{b['packageVersion']}.json"} for b in builds],
    }
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in {**outputs, "index.json": index}.items():
        tmp = args.out / f".{name}.tmp"
        tmp.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False))
        tmp.replace(args.out / name)
    print(f"wrote {len(outputs)} rulesets to {args.out}", file=sys.stderr)
    return 0


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "apt2rule-pipeline (+https://github.com/0luc/apt2rule)"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _cached(cache: Path, url: str) -> Path:
    path = cache / url.rsplit("/", 1)[1]
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".part")
        tmp.write_bytes(_fetch(url))
        tmp.replace(path)
    return path


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PipelineError as e:
        print(f"pipeline error: {e}", file=sys.stderr)
        sys.exit(1)
