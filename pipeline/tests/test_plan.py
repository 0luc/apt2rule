from apt2rule_pipeline.plan import plan_builds


def epr(version, release="ga"):
    return {"name": "security_detection_engine", "version": version, "release": release}


def test_picks_the_latest_ga_patch_of_each_supported_stack_minor_with_its_attack_version():
    search = [
        epr("8.18.40"), epr("8.19.35"), epr("8.19.36"), epr("9.4.2"), epr("9.4.10"),
        epr("9.5.9"), epr("9.6.0-beta.1", release="beta"), epr("9.6.1-beta.1"),
    ]
    assert plan_builds(search) == [
        {"packageVersion": "9.5.9", "stackMinor": "9.5", "attackVersion": "19.1"},
        {"packageVersion": "9.4.10", "stackMinor": "9.4", "attackVersion": "18.1"},
        {"packageVersion": "8.19.36", "stackMinor": "8.19", "attackVersion": "18.1"},
    ]
