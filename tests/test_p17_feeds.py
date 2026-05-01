"""P1 #1.7 — five commercial-licensable feeds (smoke tests).

Each feed is exercised against a canned upstream response so the test
stays deterministic and offline-clean. We patch the feed's
``_fetch_json`` / ``_fetch_text`` so the BaseFeed circuit-breaker +
aiohttp plumbing is bypassed — tests assert on the parsed FeedEntry
shape, which is what the rest of the pipeline consumes.
"""

from __future__ import annotations

import pytest

from src.feeds.abusech_tls_feed import AbuseChTLSFeed
from src.feeds.certstream_feed import CertStreamFeed
from src.feeds.circl_misp_feed import CIRCLMispFeed
from src.feeds.ghsa_exploitdb_feed import GHSAExploitDBFeed
from src.feeds.phishtank_certpl_feed import PhishTankCertPLFeed

pytestmark = pytest.mark.asyncio


def _patch(feed, responses_json=None, responses_text=None):
    """Install canned ``_fetch_json`` / ``_fetch_text`` on the feed
    instance. ``responses_*`` are dicts keyed by URL; lookups use a
    substring match so the test doesn't have to keep the exact URL
    in sync with the feed's URL builders."""

    async def fake_json(url, **kwargs):  # noqa: ARG001
        if responses_json is None:
            return None
        for needle, payload in responses_json.items():
            if needle in url:
                return payload
        return None

    async def fake_text(url, **kwargs):  # noqa: ARG001
        if responses_text is None:
            return None
        for needle, payload in responses_text.items():
            if needle in url:
                return payload
        return None

    feed._fetch_json = fake_json  # type: ignore[assignment]
    feed._fetch_text = fake_text  # type: ignore[assignment]


# ── A. CertStream / crt.sh ──────────────────────────────────────────


async def test_certstream_yields_one_entry_per_san():
    crtsh_payload = [
        {
            "id": 99001,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "argusdemo-bank.com\nwww.argusdemo-bank.com",
            "not_before": "2026-04-30T08:00:00",
            "not_after": "2026-07-29T08:00:00",
            "serial_number": "0123456789abcdef",
        },
    ]
    feed = CertStreamFeed(keywords=("argusdemo",))
    _patch(feed, responses_json={"crt.sh": crtsh_payload})

    entries = [e async for e in feed.poll()]
    domains = {e.value for e in entries}
    assert "argusdemo-bank.com" in domains
    assert "www.argusdemo-bank.com" in domains
    assert all(e.layer == "ct_logs" for e in entries)
    md = entries[0].feed_metadata or {}
    assert md["source"] == "crt.sh"
    assert md["matched_keyword"] == "argusdemo"
    assert "Let's Encrypt" in (md.get("issuer") or "")


async def test_certstream_dedups_across_keywords():
    crtsh_payload = [{"id": 1, "name_value": "shared.com",
                      "issuer_name": "X", "not_before": "2026-04-01T00:00:00",
                      "not_after": "2026-07-01T00:00:00", "serial_number": ""}]
    feed = CertStreamFeed(keywords=("kw1", "kw2"))
    _patch(feed, responses_json={"crt.sh": crtsh_payload})
    entries = [e async for e in feed.poll()]
    assert len(entries) == 1


# ── B. CIRCL OSINT MISP ─────────────────────────────────────────────


async def test_circl_misp_pulls_event_attributes():
    manifest = {
        "ev-1234": {
            "info": "MuddyWater spearphishing wave",
            "date": "2026-04-30",
            "threat_level_id": "1",
            "timestamp": "1714435200",
        },
    }
    event = {
        "Event": {
            "info": "MuddyWater spearphishing wave",
            "date": "2026-04-30",
            "threat_level_id": "1",
            "Attribute": [
                {"type": "ip-dst", "value": "203.0.113.7", "comment": "C2"},
                {"type": "domain", "value": "evil.example",
                 "comment": "phish landing"},
                {"type": "sha256", "value": "a" * 64, "comment": "loader"},
                {"type": "filename", "value": "ignored.txt"},  # filtered
            ],
        },
    }
    feed = CIRCLMispFeed()
    _patch(feed, responses_json={
        "manifest.json": manifest,
        "ev-1234.json": event,
    })

    entries = [e async for e in feed.poll()]
    types = {e.entry_type for e in entries}
    assert types == {"ip", "domain", "hash"}, types
    assert all(e.severity == "critical" for e in entries)  # threat_level_id=1
    assert all((e.feed_metadata or {}).get("event_uuid") == "ev-1234"
               for e in entries)


async def test_circl_misp_unknown_attribute_types_skipped():
    feed = CIRCLMispFeed()
    _patch(feed, responses_json={
        "manifest.json": {"ev-9": {"timestamp": "1", "info": "x"}},
        "ev-9.json": {"Event": {"info": "x", "date": "2026-04-01",
                                 "threat_level_id": "3",
                                 "Attribute": [
                                     {"type": "btc", "value": "1A1zP1..."},
                                     {"type": "yara", "value": "rule X"},
                                 ]}},
    })
    assert [e async for e in feed.poll()] == []


# ── C. PhishTank + CERT.PL ──────────────────────────────────────────


async def test_phishtank_certpl_combined():
    phishtank_payload = [
        {
            "phish_id": 42,
            "url": "https://phish.example/login",
            "verified": "yes",
            "verification_time": "2026-04-30T12:00:00+00:00",
            "target": "Saudia",
        },
        {
            "phish_id": 43,
            "url": "https://phish2.example/",
            "verified": "no",
            "verification_time": "",
            "target": "",
        },
    ]
    certpl_payload = [
        {"DomainAddress": "evil-bank.pl",
         "InsertDate": "2026-04-29T10:00:00",
         "RegisterPositionId": 12345},
    ]
    feed = PhishTankCertPLFeed()
    _patch(feed, responses_json={
        "phishtank": phishtank_payload,
        "cert.pl": certpl_payload,
        "hole.cert.pl": certpl_payload,
    })

    entries = [e async for e in feed.poll()]
    sources = {(e.feed_metadata or {}).get("source") for e in entries}
    assert sources == {"phishtank", "cert.pl"}, sources

    pt = next(e for e in entries
              if (e.feed_metadata or {}).get("phish_id") == 42)
    assert pt.severity == "high"
    assert pt.feed_metadata["target"] == "Saudia"
    assert pt.feed_metadata["verified"] is True

    pt2 = next(e for e in entries
               if (e.feed_metadata or {}).get("phish_id") == 43)
    assert pt2.severity == "medium"
    assert pt2.confidence == 0.6

    cp = next(e for e in entries if e.value == "evil-bank.pl")
    assert cp.feed_metadata["register_position_id"] == 12345


# ── D. GHSA + ExploitDB ─────────────────────────────────────────────


async def test_ghsa_exploitdb_combined():
    ghsa_payload = [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2026-12345",
            "summary": "Authentication bypass in widget-lib",
            "severity": "critical",
            "published_at": "2026-04-30T12:00:00Z",
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "widget-lib"}},
            ],
        },
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "",  # GHSA-only advisories with no CVE assigned
            "summary": "Prototype pollution in tiny-lib",
            "severity": "moderate",
            "published_at": "",
            "vulnerabilities": [],
        },
    ]
    exploitdb_csv = (
        "id,file,description,date_published,author,type,platform,port,"
        "date_added,date_updated,verified,codes,tags,aliases,"
        "screenshot_url,application_url,source_url\n"
        "51234,exploits/x.py,Acme Router RCE,2026-04-29,foo,remote,"
        "linux,80,2026-04-29,2026-04-29,1,CVE-2026-99999,,,,,\n"
        "51235,exploits/y.py,Generic LFI,2026-04-28,bar,webapps,"
        "php,80,2026-04-28,2026-04-28,0,,,,,,,\n"
    )
    feed = GHSAExploitDBFeed()
    _patch(
        feed,
        responses_json={"github.com/advisories": ghsa_payload},
        responses_text={"exploit-database": exploitdb_csv,
                        "files_exploits.csv": exploitdb_csv},
    )

    entries = [e async for e in feed.poll()]
    by_source = {(e.feed_metadata or {}).get("source"): e for e in entries
                 if (e.feed_metadata or {}).get("source")}
    assert {"ghsa", "exploitdb"} <= by_source.keys()

    cve_entry = next(e for e in entries if e.value == "CVE-2026-12345")
    assert cve_entry.severity == "critical"
    assert "widget-lib" in (cve_entry.feed_metadata or {}).get("packages", [])[0]

    # Verified PoC mapped to CVE → severity high.
    edb_entry = next(e for e in entries if e.value == "CVE-2026-99999")
    assert edb_entry.severity == "high"
    assert edb_entry.feed_metadata["verified"] is True
    assert edb_entry.feed_metadata["edb_id"] == "51234"

    # Unverified ExploitDB row without CVE falls back to EDB-id.
    edb2 = next(e for e in entries if e.value == "EDB-51235")
    assert edb2.severity == "medium"
    assert edb2.confidence == 0.7

    # GHSA entry without a CVE falls back to ghsa_id.
    ghsa2 = next(e for e in entries if e.value == "GHSA-aaaa-bbbb-cccc")
    assert ghsa2.severity == "medium"  # unrecognised severity normalised


# ── E. abuse.ch SSLBL / JA3 ────────────────────────────────────────


async def test_abusech_sslbl_ja3():
    sslbl_csv = (
        "# abuse.ch SSL Blacklist — header line ignored\n"
        "Listingdate,SHA1,Listingreason\n"
        "2026-04-29 12:00:00,deadbeef" + "00" * 16 + ",Cobalt Strike C2\n"
        "2026-04-30 09:30:00,cafebabe" + "11" * 16 + ",Sliver C2\n"
    )
    ja3_csv = (
        "# abuse.ch JA3 fingerprints — header line ignored\n"
        "ja3_md5,Firstseen,Lastseen,Listingreason\n"
        "abcd1234abcd1234abcd1234abcd1234,2026-04-01,2026-04-30,Emotet\n"
    )
    feed = AbuseChTLSFeed()
    _patch(
        feed,
        responses_text={
            "sslblacklist.csv": sslbl_csv,
            "ja3_fingerprints.csv": ja3_csv,
        },
    )

    entries = [e async for e in feed.poll()]
    sslbl = [e for e in entries
             if (e.feed_metadata or {}).get("source") == "sslbl"]
    ja3 = [e for e in entries
           if (e.feed_metadata or {}).get("source") == "abusech_ja3"]
    assert len(sslbl) == 2 and len(ja3) == 1

    cs = next(e for e in sslbl if "Cobalt" in (e.feed_metadata or {})
              .get("listing_reason", ""))
    assert cs.entry_type == "hash"
    assert cs.severity == "high"

    emotet = ja3[0]
    assert emotet.entry_type == "ja3"
    assert emotet.value == "abcd1234abcd1234abcd1234abcd1234"
    assert emotet.feed_metadata["listing_reason"] == "Emotet"


async def test_abusech_handles_empty_responses():
    feed = AbuseChTLSFeed()
    _patch(feed, responses_text={
        "sslblacklist.csv": "",
        "ja3_fingerprints.csv": "",
    })
    assert [e async for e in feed.poll()] == []
