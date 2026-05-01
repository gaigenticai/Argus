"""GCC ransomware DLS filter — unit tests (P1 #1.5).

Pure unit tests on the scoring function — no DB needed since the
filter is a pure function. Verifies each signal independently and the
behaviour around the confidence threshold.
"""

from __future__ import annotations

import pytest

from src.intel.gcc_ransomware_filter import (
    GCC_CONFIDENCE_THRESHOLD,
    GccRelevanceScore,
    is_gcc_victim,
    score_gcc_relevance,
)


# ── Country-code signal (strongest single signal) ────────────────────


@pytest.mark.parametrize("cc", ["SA", "AE", "QA", "KW", "BH", "OM", "EG"])
def test_country_code_alone_clears_threshold(cc):
    s = score_gcc_relevance(
        victim_name="Acme Corp", country=cc, group="lockbit",
    )
    assert s.is_gcc
    assert s.confidence >= GCC_CONFIDENCE_THRESHOLD
    assert s.matched_country == cc


def test_non_gcc_country_does_not_match():
    s = score_gcc_relevance(victim_name="Acme Corp", country="US")
    assert not s.is_gcc
    assert s.confidence == 0.0
    assert s.signals == []


# ── ccTLD signal ─────────────────────────────────────────────────────


@pytest.mark.parametrize("url,expected", [
    ("https://example.com.sa/", ".com.sa"),
    ("http://x.gov.qa/", ".gov.qa"),
    ("example.ae", ".ae"),
    ("subdomain.uni.edu.sa/path", ".edu.sa"),
])
def test_cctld_extraction(url, expected):
    s = score_gcc_relevance(victim_name="X", url=url, group="play")
    assert s.matched_cctld == expected
    assert s.is_gcc, f"{url} should be GCC-relevant"


def test_cctld_in_victim_name_when_url_missing():
    s = score_gcc_relevance(victim_name="example.qa", url=None, group="akira")
    assert s.matched_cctld == ".qa"
    assert s.is_gcc


def test_non_gcc_cctld_does_not_match():
    s = score_gcc_relevance(victim_name="example.com", url="https://example.com")
    assert s.matched_cctld is None
    assert not s.is_gcc


# ── Arabic letter signal ─────────────────────────────────────────────


def test_arabic_letters_alone_below_threshold():
    """Arabic alone is too ambiguous (Iran/Pakistan/Morocco etc. also use it)."""
    s = score_gcc_relevance(victim_name="شركة عربية")
    assert s.has_arabic
    assert not s.is_gcc, "Arabic letters alone must not auto-tag as GCC"


def test_arabic_plus_country_clears_threshold():
    s = score_gcc_relevance(
        victim_name="شركة المياه", country="EG", group="qilin",
    )
    assert s.has_arabic
    assert s.is_gcc
    assert "arabic_letters" in s.signals


# ── Company keyword fuzzy match ──────────────────────────────────────


@pytest.mark.parametrize("name,expected_in_keywords", [
    ("Saudi Aramco Internal HR Database", {"aramco", "saudi aramco"}),
    ("ADNOC Distribution leak", {"adnoc"}),
    ("QatarEnergy partners docs", {"qatarenergy", "qatar energy"}),
    ("Al Rajhi Bank — customer dump", {"al rajhi", "rajhi bank"}),
    ("National Bank of Kuwait — backups", {"nbk", "national bank of kuwait"}),
])
def test_company_keyword_match(name, expected_in_keywords):
    """Match is one of several valid GCC keywords for that brand —
    multiple aliases ('aramco' vs 'saudi aramco') both legitimately fire,
    so accept any keyword in the expected set."""
    s = score_gcc_relevance(victim_name=name)
    assert s.matched_company_keyword in expected_in_keywords, (
        f"matched={s.matched_company_keyword!r} not in {expected_in_keywords}"
    )
    assert s.is_gcc


def test_company_keyword_no_substring_overmatch():
    """The word 'inc' in 'Education Inc' must not match the watchlist
    group 'inc ransom' — and 'du' in 'Saudi' must not match the UAE
    telco brand 'du'. Word-boundary matching prevents both."""
    s = score_gcc_relevance(victim_name="Education Inc", country="US")
    assert s.matched_company_keyword is None
    assert not s.is_gcc


# ── Watchlist group bump ─────────────────────────────────────────────


def test_watchlist_group_alone_does_not_trigger():
    """Watchlist group bump applies only when at least one other signal
    fired — so a US victim of a watchlisted group is not GCC."""
    s = score_gcc_relevance(victim_name="Acme", country="US", group="ransomhub")
    assert s.watchlisted_group
    assert not s.is_gcc


def test_watchlist_group_bumps_when_other_signal_fires():
    s_no = score_gcc_relevance(victim_name="example.ae", group=None)
    s_yes = score_gcc_relevance(victim_name="example.ae", group="lockbit3")
    assert s_yes.confidence > s_no.confidence
    assert s_yes.watchlisted_group


# ── Combined: stacking signals ───────────────────────────────────────


def test_signals_stack_to_confidence_one():
    s = score_gcc_relevance(
        victim_name="Aramco IT — Riyadh ops",
        country="SA",
        url="https://aramco.com.sa/",
        group="LockBit",
    )
    assert s.confidence == 1.0  # capped at 1.0
    assert s.is_gcc
    assert s.matched_country == "SA"
    assert s.matched_cctld == ".com.sa"
    assert s.matched_company_keyword == "aramco"


def test_to_dict_stable_shape():
    s = score_gcc_relevance(victim_name="ADNOC", country="AE")
    d = s.to_dict()
    assert set(d.keys()) == {
        "is_gcc", "confidence", "signals", "matched_country",
        "matched_cctld", "matched_company_keyword",
        "matched_city_keyword", "has_arabic", "watchlisted_group",
    }
    assert isinstance(d["confidence"], float)
    assert isinstance(d["signals"], list)


def test_is_gcc_victim_wrapper():
    assert is_gcc_victim(score_gcc_relevance(victim_name="X", country="SA"))
    assert not is_gcc_victim(score_gcc_relevance(victim_name="X", country="US"))


# ── Edge cases ───────────────────────────────────────────────────────


def test_empty_inputs_safe():
    s = score_gcc_relevance(victim_name=None, country=None, url=None)
    assert isinstance(s, GccRelevanceScore)
    assert not s.is_gcc
    assert s.confidence == 0.0


def test_malformed_url_does_not_crash():
    s = score_gcc_relevance(victim_name="X", url="not a url at all ::: //")
    # Either matches a ccTLD by string check or matches nothing — must not raise.
    assert isinstance(s, GccRelevanceScore)
