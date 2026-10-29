"""Decides which ruleset versions to build, from the Elastic Package Registry search results."""

import re

# Oldest stack minor apt2rule offers (the oldest the elastic/detection-rules repo still builds for).
MIN_STACK = (8, 19)
# elastic/detection-rules maps rules to ATT&CK v19.1 from stack 9.5 on (MITRE_V19_MIN_STACK), v18.1 before.
ATTACK_V19_MIN_STACK = (9, 5)

_GA = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def plan_builds(search: list[dict]) -> list[dict]:
    latest: dict[tuple[int, int], tuple[int, int, int]] = {}
    for package in search:
        match = _GA.match(package["version"])
        if package.get("release", "ga") != "ga" or not match:
            continue
        version = tuple(int(x) for x in match.groups())
        minor = version[:2]
        if minor >= MIN_STACK and version > latest.get(minor, (0, 0, -1)):
            latest[minor] = version
    return [
        {
            "packageVersion": ".".join(map(str, version)),
            "stackMinor": f"{minor[0]}.{minor[1]}",
            "attackVersion": "19.1" if minor >= ATTACK_V19_MIN_STACK else "18.1",
        }
        for minor, version in sorted(latest.items(), reverse=True)
    ]
