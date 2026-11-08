"""Conservative brand and website identity analysis.

This module only compares strings and URL structure. It never treats similarity by
itself as proof of impersonation or maliciousness.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

BRANDS: tuple[dict[str, object], ...] = (
    {"id": "google", "name": "Google", "domains": ("google.com", "google.co.uk")},
    {"id": "microsoft", "name": "Microsoft", "domains": ("microsoft.com", "microsoftonline.com")},
    {"id": "apple", "name": "Apple", "domains": ("apple.com",)},
    {"id": "paypal", "name": "PayPal", "domains": ("paypal.com",)},
    {"id": "amazon", "name": "Amazon", "domains": ("amazon.com", "amazon.in")},
    {"id": "meta", "name": "Meta", "domains": ("meta.com", "facebook.com")},
)

_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SUSPICIOUS_PATH = re.compile(r"(?:login|signin|verify|verification|secure|account|password|wallet|payment|update)", re.I)
_KNOWN_TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "com.br", "co.jp"}


@dataclass(frozen=True)
class IdentityAnalysis:
    claimed_brand: str | None
    actual_domain: str
    similarity_score: float
    suspicious_characters: list[str]
    detection_category: str
    evidence: list[str]
    confidence: float
    explanation: str
    brand_domain: str | None

    def as_evidence(self) -> dict[str, object]:
        return {
            "claimed_brand": self.claimed_brand,
            "actual_domain": self.actual_domain,
            "similarity_score": self.similarity_score,
            "suspicious_characters": self.suspicious_characters,
            "detection_category": self.detection_category,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "brand_domain": self.brand_domain,
        }


def _registered_domain(hostname: str) -> str:
    labels = hostname.rstrip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _KNOWN_TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()


def _ascii_domain(hostname: str) -> str:
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return hostname.lower()


def _best_brand(domain: str, requested: str | None) -> tuple[dict[str, object] | None, float, str | None]:
    wanted = requested.strip().casefold() if requested else ""
    candidates = [b for b in BRANDS if not wanted or str(b["name"]).casefold() == wanted or str(b["id"]) == wanted]
    if not candidates:
        candidates = list(BRANDS)
    best: tuple[dict[str, object] | None, float, str | None] = (None, 0.0, None)
    for brand in candidates:
        for reference in brand["domains"]:  # type: ignore[index]
            reference = str(reference)
            score = difflib.SequenceMatcher(None, domain.casefold(), reference.casefold()).ratio()
            if score > best[1]:
                best = (brand, score, reference)
    return best


def analyze_identity(url: str, claimed_brand: str | None = None) -> IdentityAnalysis:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    actual = _ascii_domain(hostname)
    registered = _registered_domain(actual)
    inferred_brand = claimed_brand
    if not inferred_brand:
        hostname_folded = hostname.casefold()
        for reference in BRANDS:
            brand_tokens = {str(reference["id"]).casefold(), str(reference["name"]).casefold().replace(" ", "")}
            hostname_labels = set(re.split(r"[.\-]", hostname_folded))
            if brand_tokens & hostname_labels:
                inferred_brand = str(reference["name"])
                break
    brand, similarity, brand_domain = _best_brand(registered, inferred_brand)
    if not claimed_brand and not inferred_brand and similarity < 0.72:
        brand, similarity, brand_domain = None, 0.0, None
    brand_name = str(brand["name"]) if brand else (claimed_brand.strip() if claimed_brand else None)
    suspicious: list[str] = []
    evidence: list[str] = []
    category = "NO_IDENTITY_MISMATCH"
    confidence = 0.35

    if hostname != hostname.encode("ascii", "ignore").decode("ascii") or "xn--" in hostname.casefold():
        suspicious.append("unicode_or_punycode")
        if "xn--" in hostname.casefold():
            suspicious.append("xn--")
        suspicious.extend(sorted({character for character in hostname if ord(character) > 127}))
        evidence.append("The hostname contains Unicode characters or an IDN punycode label.")
        category = "HOMOGRAPH_OR_PUNYCODE"
        confidence = max(confidence, 0.78)
    normalized = registered.casefold().translate(_SUBSTITUTIONS)
    if brand and normalized != registered.casefold() and str(brand["id"]).casefold() in normalized and registered.casefold() not in {str(x).casefold() for x in brand["domains"]}:  # type: ignore[index]
        suspicious.append("character_substitution")
        suspicious.extend(sorted({character for character in registered if character in "013457@$"}))
        evidence.append("The registrable domain contains a common lookalike character substitution for the reference brand.")
        category = "TYPOSQUATTING_OR_SUBSTITUTION"
        confidence = max(confidence, 0.82)
    subdomain = actual[:-len(registered)].rstrip(".") if actual.casefold().endswith(registered.casefold()) else ""
    subdomain_labels = set(re.split(r"[.\-]", subdomain.casefold()))
    if brand and str(brand["id"]).casefold() in subdomain_labels and registered not in {str(x).casefold() for x in brand["domains"]}:  # type: ignore[index]
        suspicious.append("brand_in_unrelated_subdomain")
        evidence.append("The brand name appears in a subdomain while the registrable domain is different.")
        category = "SUSPICIOUS_SUBDOMAIN"
        confidence = max(confidence, 0.86)
    if parsed.path and _SUSPICIOUS_PATH.search(parsed.path):
        suspicious.append("sensitive_path")
        evidence.append("The URL path contains a sign-in, verification, account, or payment term.")
        if category == "NO_IDENTITY_MISMATCH":
            category = "SUSPICIOUS_PATH"
        confidence = max(confidence, 0.55)
    if brand and similarity >= 0.72 and registered.casefold() not in {str(x).casefold() for x in brand["domains"]}:  # type: ignore[index]
        suspicious.append("brand_domain_mismatch")
        evidence.append(f"The actual registrable domain resembles {brand_name}, but it is not a configured reference domain.")
        if similarity >= 0.85 and category in {"NO_IDENTITY_MISMATCH", "SUSPICIOUS_PATH"}:
            suspicious.append("close_spelling_variant")
            category = "TYPOSQUATTING_OR_SUBSTITUTION"
        elif category == "NO_IDENTITY_MISMATCH":
            category = "BRAND_DOMAIN_MISMATCH"
        confidence = max(confidence, min(0.89, similarity))
    if not evidence:
        evidence.append("No configured brand mismatch signal was found from hostname and path comparison.")
    explanation = (
        f"Claimed brand: {brand_name or 'none supplied'}. Actual registrable domain: {registered}. "
        "Similarity is a lead for review, not proof of impersonation; verify ownership and independent evidence."
    )
    return IdentityAnalysis(brand_name, actual, round(similarity, 4), suspicious, category, evidence, round(min(confidence, 0.89), 4), explanation, brand_domain)


def brand_catalog() -> list[dict[str, object]]:
    return [{"id": str(b["id"]), "name": str(b["name"]), "domains": list(b["domains"])} for b in BRANDS]  # type: ignore[index]
