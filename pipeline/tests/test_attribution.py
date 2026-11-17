import pytest

from apt2rule_pipeline.attribution import attribute


def countries(text: str) -> list[str]:
    return [a["country"] for a in attribute([("G0001", text)])]


@pytest.mark.parametrize("text, expected", [
    # phrasings taken from real ATT&CK descriptions
    ("APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU).", ["RU"]),
    ("APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group.", ["CN"]),
    ("APT16 is a China-based threat group that has launched spearphishing campaigns.", ["CN"]),
    ("APT33 is a suspected Iranian threat group that has carried out operations since at least 2013.", ["IR"]),
    ("APT37 is a North Korean state-sponsored cyber espionage group.", ["KP"]),
    ("Kimsuky is a Democratic People's Republic of Korea (DPRK)-based cyber espionage group.", ["KP"]),
    ("Volt Typhoon is a People's Republic of China (PRC) state-sponsored actor.", ["CN"]),
    ("Contagious Interview is a North Korea–aligned threat group active since 2023.", ["KP"]),
    ("TA459 is a threat group believed to operate out of China that has targeted Russia, Belarus, and Mongolia.", ["CN"]),
    ("Fox Kitten is threat actor with a suspected nexus to the Iranian government.", ["IR"]),
    ("Winnti Group is a threat group with Chinese origins that has been active since at least 2010.", ["CN"]),
    ("Malteiro is a financially motivated criminal group that is likely based in Brazil.", ["BR"]),
    ("MuddyWater is assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).", ["IR"]),
    # a state agency on its own is enough
    ("The group has been linked to the GRU.", ["RU"]),
])
def test_attributes_countries_named_in_attribution_phrases(text, expected):
    assert countries(text) == expected


@pytest.mark.parametrize("text", [
    "Silence is a financially motivated threat actor. Their main targets reside in Russia, Ukraine, Belarus and Poland.",
    "Inception has targeted governmental entities primarily in Russia, but has also been active in the United States.",
    "UNC3886 targets telecommunication organizations located in the United States.",
    "Nomadic Octopus is a Russian-speaking cyber espionage threat group.",
    "Machete is a suspected Spanish-speaking cyber espionage group.",
    "The operators recruited affiliates on Russian cybercrime forums.",
    "FIN7 has targeted the retail industry in the U.S. and the UK.",
])
def test_ignores_victims_and_languages(text):
    assert countries(text) == []


def test_a_victim_in_the_same_sentence_as_the_attribution_is_not_attributed():
    text = "Saint Bear is a Russian-nexus threat actor primarily targeting entities in Ukraine and Georgia."
    assert countries(text) == ["RU"]


def test_keeps_the_first_evidence_per_country_with_its_source():
    result = attribute([
        ("G0010", "Turla is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB)."),
        ("C0001", "The campaign was conducted by a Russia-based actor."),
    ])
    assert result == [{
        "country": "RU",
        "evidence": "Turla is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB).",
        "source": "G0010",
    }]


def test_capitalised_abbreviations_match_case_sensitively():
    assert countries("A group operating out of the US.") == ["US"]
    assert countries("Let us say a group operating out of us.") == []
