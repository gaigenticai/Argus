"""Arabic phishing analyzer — unit tests (P1 #1.6).

Pure unit tests on each detector and the aggregate :func:`analyze_message`
entry point. No DB needed. Plus one HTTP smoke test for the
``POST /api/v1/intel/phishing/analyze`` route (uses the existing client
fixture against the live ASGI app).
"""

from __future__ import annotations

import pytest

from src.intel.arabic_phishing import (
    PHISHING_THRESHOLD,
    PhishingScore,
    analyze_message,
    detect_bidi_overrides,
    detect_brand_impersonation,
    detect_homoglyphs,
    detect_mixed_script_domains,
    detect_pretexts,
)


# ── Homoglyphs ────────────────────────────────────────────────────────


def test_cyrillic_a_in_aramco():
    """А (Cyrillic, U+0410) used in place of A inside ARAMCO."""
    text = "ARАMCO"  # second char is Cyrillic А
    hits = detect_homoglyphs(text)
    assert any(h.source_script == "Cyrillic" and h.real_char == "A"
               for h in hits)


def test_arabic_indic_digit_in_amount():
    """Arabic-Indic digit ٠ used to mimic Latin 0 in a fake total."""
    hits = detect_homoglyphs("Total: $1٠٠٠")  # zeroes are Arabic-Indic
    digit_hits = [h for h in hits if h.source_script == "Arabic"]
    assert len(digit_hits) == 3
    assert all(h.real_char == "0" for h in digit_hits)


def test_pure_ascii_has_no_homoglyphs():
    assert detect_homoglyphs("plain ascii text 12345") == []


# ── Bidi-control / RTL-override ──────────────────────────────────────


def test_rtl_override_in_filename():
    """Classic ``invoice‮gpj.exe`` trick — looks like ``invoiceexe.jpg``
    in some renderers but actually ``invoice.exe`` of course."""
    hits = detect_bidi_overrides("Open invoice‮gpj.exe")
    assert len(hits) == 1
    assert "RLO" in hits[0].name


def test_no_bidi_in_clean_text():
    assert detect_bidi_overrides("normal text with no controls") == []


def test_rtl_override_alone_crosses_threshold():
    score = analyze_message(body="Open this attachment: doc‮fdp.exe")
    assert score.is_phish, (
        f"RTL-override alone should fire; got confidence={score.confidence}"
    )


# ── Mixed-script IDN ─────────────────────────────────────────────────


def test_cyrillic_a_in_domain_label():
    """``аramco.com`` (а is Cyrillic) is mixed-script — Latin + Cyrillic
    in the same label."""
    hits = detect_mixed_script_domains(["https://аramco.com/login"])
    assert len(hits) == 1
    assert "Cyrillic" in hits[0].scripts and "Latin" in hits[0].scripts


def test_pure_latin_domain_is_not_mixed():
    assert detect_mixed_script_domains(["https://aramco.com/"]) == []


def test_short_labels_skipped():
    """Two-char labels ('co' in '.co.uk') don't trigger — too noisy."""
    assert detect_mixed_script_domains(["https://co.uk"]) == []


# ── Pretext catalog ──────────────────────────────────────────────────


@pytest.mark.parametrize("text,expected_id", [
    ("Hajj 2026 voucher claim", "hajj_umrah"),
    ("تسجيل الحج المباشر — اضغط هنا", "hajj_umrah"),
    ("Update your Absher account", "ksa_gov_services"),
    ("Verify Tawakkalna profile", "ksa_gov_services"),
    ("UAE Pass authentication required", "uae_gov_services"),
    ("ICA Smart Services payment due", "uae_gov_services"),
    ("Aramco Bonus 2026 — claim now", "energy_bonus"),
    ("Saudia refund pending — verify", "airline_refund"),
    ("ZATCA tax refund of 4500 SAR", "zatca_tax_refund"),
    ("GOSI subsidy update required", "gosi_tasi_subsidy"),
    ("Ramadan e-card from your bank", "ramadan_ecard"),
    ("Nafath OTP needed to continue", "uae_pass_otp"),
    ("DEWA bill overdue — pay immediately", "utility_bill"),
    ("Salik violation 250 AED — pay now", "toll_fine"),
    ("Saher fine 800 SAR pending", "traffic_fine"),
])
def test_pretext_catalog_each_family_fires(text, expected_id):
    hits = detect_pretexts(text)
    ids = [h.id for h in hits]
    assert expected_id in ids, (
        f"text={text!r} matched {ids}, expected {expected_id}"
    )


def test_innocent_text_no_pretext():
    assert detect_pretexts("Q1 financial results attached.") == []


# ── Brand impersonation ──────────────────────────────────────────────


def test_brand_keyword_match():
    assert "aramco" in detect_brand_impersonation("Aramco internal — Q1")


def test_brand_alone_is_not_impersonation():
    """A clean Aramco mention without homoglyph/bidi is just a brand
    mention; the analyzer's impersonated_brands list stays empty."""
    score = analyze_message(body="Saudi Aramco quarterly update")
    assert score.impersonated_brands == []
    assert not score.is_phish


def test_brand_with_homoglyph_is_impersonation():
    # Cyrillic а inside 'aramco' triggers homoglyph + brand → impersonation.
    score = analyze_message(
        body="Click here for аramco bonus: https://аramco.com.sa/",
    )
    assert score.is_phish
    assert "aramco" in score.impersonated_brands
    assert score.homoglyphs


# ── Aggregate scoring ────────────────────────────────────────────────


def test_full_saudi_phish_clears_threshold():
    score = analyze_message(
        subject="عاجل: قسيمة العمرة - Aramco Bonus 2026",
        body="Click https://аramco.com.sa/bonus to claim your Hajj voucher.",
        sender="hr@аramco.com.sa",
    )
    assert score.is_phish
    assert score.confidence >= PHISHING_THRESHOLD
    assert score.has_arabic
    assert {h.source_script for h in score.homoglyphs} >= {"Cyrillic"}
    assert {p.id for p in score.pretexts} >= {"hajj_umrah", "energy_bonus"}
    assert "aramco" in score.impersonated_brands


def test_innocent_message_does_not_trigger():
    score = analyze_message(
        subject="Q1 results",
        body="Quarterly results attached for review.",
    )
    assert not score.is_phish
    assert score.confidence == 0.0
    assert score.homoglyphs == []
    assert score.pretexts == []
    assert score.impersonated_brands == []


def test_to_dict_round_trip():
    score = analyze_message(body="DEWA bill overdue — pay now")
    d = score.to_dict()
    assert "confidence" in d
    assert "is_phish" in d
    assert "pretexts" in d and isinstance(d["pretexts"], list)
    assert "homoglyphs" in d and isinstance(d["homoglyphs"], list)


# ── HTTP route ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_route_happy_path(client, analyst_user):
    body = {
        "subject": "Aramco bonus reminder",
        "body": "Visit https://аramco.com.sa/claim — Hajj refund attached.",
        "sender": "hr@аramco.com.sa",
        "urls": [],
    }
    r = await client.post(
        "/api/v1/intel/phishing/analyze",
        json=body, headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_phish"] is True
    assert data["confidence"] > PHISHING_THRESHOLD
    assert data["has_arabic"] is False  # subject/body are Latin
    pretext_ids = [p["id"] for p in data["pretexts"]]
    assert "hajj_umrah" in pretext_ids
    assert "energy_bonus" in pretext_ids


@pytest.mark.asyncio
async def test_analyze_route_requires_auth(client):
    r = await client.post(
        "/api/v1/intel/phishing/analyze",
        json={"subject": "x", "body": "y"},
    )
    assert r.status_code in (401, 403)
