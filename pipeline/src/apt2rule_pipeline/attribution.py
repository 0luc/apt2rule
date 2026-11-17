"""Derives a group's country attribution from ATT&CK description text.

ATT&CK has no structured country field, so the pipeline reads the descriptions. A country word only
counts when it sits inside an attribution phrase: "China-based", "attributed to Russia's ...",
"suspected Iranian threat group", "operating out of China". A country named as a victim ("targeted
Russian banks") does not count. A state agency name (GRU, MSS, IRGC, ...) counts on its own.
"""

import re

from .countries import AGENCIES, COUNTRIES


def _alternation(words: list[str]) -> str:
    """Regex alternation: capitalised acronyms match case-sensitively, other words ignore case."""
    parts = []
    for w in sorted(words, key=len, reverse=True):
        escaped = re.escape(w).replace("'", "['’]")
        parts.append(f"(?-i:{escaped})" if w.replace(".", "").isupper() else escaped)
    return "(?:" + "|".join(parts) + ")"


# Word boundaries that also work for terms ending in a dot (U.S.).
_WORD = r"(?<!\w){}(?!\w)"
_HYPHEN = "[-\u2010\u2011\u2013 ]"


def _country(terms: list[str]) -> str:
    """A country term, optionally followed by its abbreviation in brackets: "People's Republic of China (PRC)".
    Never followed by "-speaking": a language is not an attribution."""
    return _WORD.format(_alternation(terms)) + r"(?: \([A-Z.]{2,6}\))?(?!" + _HYPHEN + "speaking)"


# {P} is replaced by a country's terms, {H} by a hyphen, dash or space. The whole pattern ignores case (except acronyms, see above).
_PHRASES = [
    r"{P}{H}(?:based|nexus|linked|affiliated|sponsored|backed|aligned|attributed|directed)\b",
    r"{P} (?:state|government){H}(?:sponsored|backed|affiliated|linked|aligned|directed)\b",
    r"\b(?:state|government){H}(?:sponsored|backed) {P}",
    r"\b(?:based|operate|operating|operates|operated|headquartered|originating) (?:in|out of|from) (?:the )?{P}",
    r"\battributed (?:to|with) (?:the )?{P}",
    r"\b(?:suspected|believed|assessed|likely|probably|reportedly|possibly|presumed|alleged)(?: to be)?(?: (?:a|an|the))? {P}",
    r"\bon behalf of (?:the )?{P}",
    r"\balign\w*(?: closely)? with (?:the )?{P}",
    r"\b(?:nexus|linked) (?:to|with) (?:the )?{P}",
    r"\bassociated with (?:the )?{P} (?:government|state|military|intelligence)",
    r"\b{P} origins?\b",
    r"\b{P}(?: state)? (?:cyber[- ]?espionage|espionage|threat|APT|advanced persistent threat|hacking|hacker|"
    r"nation[- ]state|state actor|cyber ?criminal|ransomware|intrusion set|entity|actor|group|operators?)\b",
]

_COUNTRY_PATTERNS = [
    (c["code"], re.compile("(?i:" + "|".join(p.replace("{P}", _country(c["terms"])).replace("{H}", _HYPHEN) for p in _PHRASES) + ")"))
    for c in COUNTRIES
]
_AGENCY_PATTERNS = [(code, re.compile("(?i:" + _WORD.format(_alternation(names)) + ")")) for code, names in AGENCIES.items()]

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"“(])")


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_END.split(text) if s.strip()]


def attribute(texts: list[tuple[str, str]]) -> list[dict]:
    """texts: (source ATT&CK ID, plain text), most authoritative first.

    Returns one entry per attributed country, in order of first evidence:
    {"country": "RU", "evidence": <sentence>, "source": "G0007"}.
    """
    found: dict[str, dict] = {}
    for source, text in texts:
        for sentence in sentences(text):
            for code, pattern in _COUNTRY_PATTERNS + _AGENCY_PATTERNS:
                if code not in found and pattern.search(sentence):
                    found[code] = {"country": code, "evidence": sentence, "source": source}
    return list(found.values())
