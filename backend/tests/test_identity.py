from app.services.identity import analyze_identity, brand_catalog


def test_brand_catalog_contains_reference_domains() -> None:
    google = next(item for item in brand_catalog() if item["id"] == "google")
    assert "google.com" in google["domains"]


def test_identity_detects_brand_domain_mismatch_without_overclaiming() -> None:
    result = analyze_identity("https://secure-paypal.example.net/login")
    assert result.claimed_brand == "PayPal"
    assert "brand_in_unrelated_subdomain" in result.suspicious_characters
    assert result.confidence <= 0.89
    assert "not proof of impersonation" in result.explanation


def test_identity_detects_punycode_and_sensitive_path() -> None:
    result = analyze_identity("https://xn--pple-43d.example/login")
    assert "unicode_or_punycode" in result.suspicious_characters
    assert "sensitive_path" in result.suspicious_characters
    assert result.detection_category == "HOMOGRAPH_OR_PUNYCODE"


def test_identity_does_not_call_exact_reference_domain_suspicious() -> None:
    result = analyze_identity("https://paypal.com/login")
    assert result.claimed_brand == "PayPal"
    assert result.detection_category == "SUSPICIOUS_PATH"
    assert "brand_domain_mismatch" not in result.suspicious_characters


def test_identity_catches_missing_extra_and_swapped_letter_variants() -> None:
    for url in ("https://paypa.com", "https://paypall.com", "https://paaypal.com"):
        result = analyze_identity(url)
        assert result.claimed_brand == "PayPal"
        assert result.detection_category == "TYPOSQUATTING_OR_SUBSTITUTION"
        assert "brand_domain_mismatch" in result.suspicious_characters


def test_identity_does_not_infer_unsupported_brand_from_unrelated_word() -> None:
    result = analyze_identity("https://pineapple.example/login")
    assert result.claimed_brand is None
    assert result.actual_domain == "pineapple.example"


def test_identity_uses_registrable_domain_for_regional_suffixes() -> None:
    result = analyze_identity("https://apple.co.uk/login")
    assert result.actual_domain == "apple.co.uk"
    assert "brand_in_unrelated_subdomain" not in result.suspicious_characters
