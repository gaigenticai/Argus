"""CISA Decider — auto-map free-text alert content to MITRE ATT&CK
technique IDs (P2 #2.2).

Keyword + phrase classifier producing ranked (technique_id, confidence,
matched_keyword) triples. The corpus below is hand-curated against the
common phishing / credential-theft / ransomware / discovery patterns
analysts see in dark-web and feed-derived alerts; it is *inspired by*
the open-source CISA Decider project (github.com/cisagov/decider) but
built from scratch under MIT-compatible attribution rather than
vendoring Decider's TLP:CLEAR YAML directly. Refresh the corpus when
ATT&CK ships a content release; the version stamp below tracks it.

Three integration points:

  * :func:`classify_text` — pure scorer, takes text → ranked triples
  * :func:`apply_decider_to_alert` — runs the scorer on an alert's
    title + summary + agent_reasoning, materialises top-N results as
    ``AttackTechniqueAttachment`` rows tagged
    ``source=triage_agent``. Idempotent on (alert, technique) pairs
  * ``POST /api/v1/intel/decider/classify`` — analyst-facing tool
    surface (route lives in :mod:`src.api.routes.intel`)
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


_CORPUS_VERSION = "2026-05-01"


# ── Curated keyword → technique mapping ──────────────────────────────


@dataclass
class _Rule:
    technique_id: str
    technique_name: str
    keywords: tuple[str, ...]
    confidence_per_match: float = 0.6


# Curated rule corpus (~70 rules) covering the highest-leverage
# techniques for the alert categories Argus sees. Keywords are matched
# word-boundary so a substring "rdp" inside "FRDP" doesn't false-positive.
# Refresh / count exposed via :func:`rule_count` and
# :func:`corpus_version` (the API surface tests both).
_RULES: list[_Rule] = [
    # ── Initial Access — Phishing (T1566.x) ──────────────────────────
    _Rule("T1566.001", "Spearphishing Attachment",
          ("malicious attachment", "weaponised document", "weaponized doc",
           "weaponised pdf", "weaponized pdf", "weaponised attachment",
           "malicious docx", "malicious xlsx", "malicious pdf attachment",
           "macro-enabled attachment", "spearphishing attachment"), 0.85),
    _Rule("T1566.002", "Spearphishing Link",
          ("phishing link", "phish url", "credential harvester url",
           "lookalike login page", "fake login portal",
           "spoofed login page", "smishing link", "spearphishing link"), 0.85),
    _Rule("T1566.003", "Spearphishing via Service",
          ("spearphishing via linkedin", "spearphishing via whatsapp",
           "spearphishing via telegram", "social engineering via dm"), 0.8),
    _Rule("T1566", "Phishing",
          ("phishing", "phish", "phishing campaign", "phishing email",
           "phishing wave", "spearphishing", "spear-phishing",
           "spearphishing wave", "phishing-as-a-service",
           "homoglyph domain", "punycode lookalike"), 0.7),

    # ── Initial Access — Public-facing exploit ───────────────────────
    _Rule("T1190", "Exploit Public-Facing Application",
          ("public-facing exploit", "internet-facing exploit",
           "unauthenticated rce", "n-day exploit", "0-day exploit",
           "0day", "zero-day", "log4shell", "proxyshell", "proxylogon",
           "rce in", "remote code execution", "internet-exposed"), 0.85),

    # ── Initial Access — Drive-by ────────────────────────────────────
    _Rule("T1189", "Drive-by Compromise",
          ("drive-by download", "watering hole", "watering-hole attack",
           "compromised site delivers", "malvertising"), 0.8),

    # ── Initial Access — Valid Accounts ──────────────────────────────
    _Rule("T1078", "Valid Accounts",
          ("valid credentials", "stolen credentials", "credential stuffing",
           "default credentials", "weak password", "password spraying",
           "compromised account", "stolen vpn credentials"), 0.8),
    _Rule("T1078.004", "Cloud Accounts",
          ("compromised cloud account", "stolen aws keys",
           "aws access key leaked", "azure ad takeover", "iam takeover",
           "stolen oauth token", "leaked github token"), 0.85),

    # ── Execution ────────────────────────────────────────────────────
    _Rule("T1059.001", "PowerShell",
          ("powershell loader", "powershell payload",
           "powershell empire", "encoded powershell command",
           "powershell -enc", "obfuscated powershell"), 0.85),
    _Rule("T1059.003", "Windows Command Shell",
          ("cmd.exe payload", "batch script dropper"), 0.7),
    _Rule("T1059.005", "Visual Basic",
          ("vba macro", "vbs dropper", "vbscript loader",
           "office macro malware"), 0.85),
    _Rule("T1059.006", "Python",
          ("python loader", "python payload",
           "py2exe trojan"), 0.7),
    _Rule("T1204.002", "Malicious File",
          ("user opens malicious", "victim runs", "user-double-click"), 0.7),

    # ── Persistence ──────────────────────────────────────────────────
    _Rule("T1547.001", "Registry Run Keys / Startup Folder",
          ("registry run key", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
           "startup folder persistence"), 0.85),
    _Rule("T1053.005", "Scheduled Task/Job: Scheduled Task",
          ("scheduled task persistence", "schtasks /create",
           "creates scheduled task"), 0.85),
    _Rule("T1505.003", "Web Shell",
          ("web shell", "webshell", "asp web shell", "china chopper",
           "antsword", "behinder"), 0.9),
    _Rule("T1136", "Create Account",
          ("creates new account", "rogue admin account",
           "backdoor account"), 0.8),
    _Rule("T1098", "Account Manipulation",
          ("modifies account", "adds permissions to account",
           "promotes user to admin"), 0.7),

    # ── Privilege Escalation ─────────────────────────────────────────
    _Rule("T1068", "Exploitation for Privilege Escalation",
          ("local privilege escalation", "lpe exploit",
           "kernel exploit"), 0.85),
    _Rule("T1055", "Process Injection",
          ("process injection", "dll injection",
           "process hollowing"), 0.85),

    # ── Defense Evasion ──────────────────────────────────────────────
    _Rule("T1027", "Obfuscated Files or Information",
          ("obfuscated", "packed binary", "xor-encrypted payload",
           "string encryption"), 0.6),
    _Rule("T1140", "Deobfuscate/Decode Files or Information",
          ("decodes payload at runtime", "in-memory decryption",
           "base64-decoded shellcode"), 0.7),
    _Rule("T1070.004", "File Deletion",
          ("deletes evidence", "wipes logs", "removes traces",
           "cleartime", "anti-forensics"), 0.7),
    _Rule("T1218", "System Binary Proxy Execution",
          ("lolbas", "living off the land binary",
           "regsvr32 abuse", "rundll32 abuse"), 0.8),
    _Rule("T1218.005", "Mshta",
          ("mshta abuse", "mshta payload"), 0.85),
    _Rule("T1562.001", "Disable or Modify Tools",
          ("disables defender", "tampers with edr", "disables av",
           "kills security service"), 0.85),

    # ── Credential Access ────────────────────────────────────────────
    _Rule("T1003.001", "OS Credential Dumping: LSASS Memory",
          ("lsass dump", "mimikatz", "procdump lsass",
           "comsvcs.dll lsass", "lsass.exe memory"), 0.95),
    _Rule("T1003.003", "OS Credential Dumping: NTDS",
          ("ntds.dit dump", "ntds extraction",
           "domain controller credential dump"), 0.95),
    _Rule("T1056", "Input Capture",
          ("keylogger", "keystroke logger"), 0.85),
    _Rule("T1056.004", "Input Capture: Credential API Hooking",
          ("credential api hook"), 0.8),
    _Rule("T1110", "Brute Force",
          ("brute force", "brute-force", "bruteforce"), 0.7),
    _Rule("T1110.003", "Brute Force: Password Spraying",
          ("password spraying", "password-spray"), 0.85),
    _Rule("T1555", "Credentials from Password Stores",
          ("credential store dump", "browser credential theft"), 0.75),
    _Rule("T1555.003", "Credentials from Web Browsers",
          ("steals browser passwords", "redline stealer",
           "stealer log", "browser cookie theft"), 0.9),

    # ── Discovery ────────────────────────────────────────────────────
    _Rule("T1057", "Process Discovery",
          ("process enumeration", "tasklist", "ps -ef survey"), 0.6),
    _Rule("T1083", "File and Directory Discovery",
          ("file enumeration", "directory listing", "tree /f"), 0.55),
    _Rule("T1018", "Remote System Discovery",
          ("network discovery", "lan enumeration",
           "lateral target enumeration"), 0.65),
    _Rule("T1087", "Account Discovery",
          ("account enumeration", "net user", "ldap user enumeration"), 0.65),
    _Rule("T1082", "System Information Discovery",
          ("systeminfo.exe", "host fingerprinting", "os fingerprint"), 0.55),

    # ── Lateral Movement ─────────────────────────────────────────────
    _Rule("T1021.001", "Remote Services: Remote Desktop Protocol",
          ("rdp lateral movement", "rdp credentials sold",
           "exposed rdp", "rdp brute force"), 0.85),
    _Rule("T1021.002", "Remote Services: SMB/Windows Admin Shares",
          ("smb lateral movement", "smb admin shares",
           "psexec lateral", "admin$ pivot"), 0.85),
    _Rule("T1021.004", "Remote Services: SSH",
          ("ssh lateral movement", "ssh key theft",
           "stolen ssh keys"), 0.8),

    # ── Collection ───────────────────────────────────────────────────
    _Rule("T1005", "Data from Local System",
          ("collects local files", "harvests user files",
           "exfil from desktop"), 0.7),
    _Rule("T1114", "Email Collection",
          ("email harvesting", "mailbox dump",
           "exchange ews abuse"), 0.85),
    _Rule("T1119", "Automated Collection",
          ("automated collection", "scheduled exfil"), 0.7),
    _Rule("T1056.001", "Input Capture: Keylogging",
          ("keylogging payload",), 0.85),

    # ── Command and Control ──────────────────────────────────────────
    _Rule("T1071.001", "Application Layer Protocol: Web Protocols",
          ("http c2", "https c2", "web-based c2", "tls beacon",
           "c2 over https"), 0.85),
    _Rule("T1071.004", "Application Layer Protocol: DNS",
          ("dns tunneling", "dns c2", "dns exfiltration"), 0.9),
    _Rule("T1090", "Proxy",
          ("c2 proxy", "rotating proxy infrastructure",
           "fronting domain"), 0.7),
    _Rule("T1102", "Web Service",
          ("c2 over slack", "c2 over discord",
           "c2 over twitter", "abuses google docs"), 0.85),
    _Rule("T1573.001", "Encrypted Channel: Symmetric Cryptography",
          ("xor-encrypted c2", "rc4 c2 traffic"), 0.7),
    _Rule("T1132.001", "Data Encoding: Standard Encoding",
          ("base64 c2 traffic", "hex-encoded c2"), 0.65),

    # ── Exfiltration ─────────────────────────────────────────────────
    _Rule("T1041", "Exfiltration Over C2 Channel",
          ("exfil over c2", "data egress to c2"), 0.8),
    _Rule("T1567", "Exfiltration Over Web Service",
          ("exfil to mega.nz", "exfil to dropbox", "exfil to gdrive",
           "exfil to onedrive", "data uploaded to file-share"), 0.85),
    _Rule("T1567.002", "Exfiltration to Cloud Storage",
          ("aws s3 exfil", "azure blob exfil"), 0.85),
    _Rule("T1048", "Exfiltration Over Alternative Protocol",
          ("ftp exfil", "exfil over ftp", "smb exfil"), 0.7),

    # ── Impact ───────────────────────────────────────────────────────
    _Rule("T1486", "Data Encrypted for Impact",
          ("ransomware encryption", "files encrypted by",
           "ransom note dropped", "lockbit encrypts", "ryuk encrypts",
           "blackcat encrypts", "akira encrypts"), 0.95),
    _Rule("T1485", "Data Destruction",
          ("data wiper", "shamoon", "destructive malware",
           "wipes disks"), 0.9),
    _Rule("T1490", "Inhibit System Recovery",
          ("vssadmin delete shadows", "deletes shadow copies",
           "wbadmin delete catalog"), 0.9),
    _Rule("T1491", "Defacement",
          ("website defacement", "defaced homepage"), 0.8),
    _Rule("T1499", "Endpoint Denial of Service",
          ("denial of service", "dos attack",
           "ddos campaign"), 0.7),

    # ── Resource Development (campaign-prep signals in dark-web feeds) ──
    _Rule("T1583.001", "Acquire Infrastructure: Domains",
          ("typosquat domain", "lookalike domain registered",
           "newly-registered domain"), 0.7),
    _Rule("T1583.006", "Acquire Infrastructure: Web Services",
          ("free web hosting abuse", "github pages abuse"), 0.7),
    _Rule("T1585.001", "Establish Accounts: Social Media Accounts",
          ("fake linkedin profile", "impersonating linkedin",
           "fake twitter account"), 0.8),
    _Rule("T1587.001", "Develop Capabilities: Malware",
          ("custom backdoor", "in-house malware"), 0.7),
    _Rule("T1588.001", "Obtain Capabilities: Malware",
          ("malware-as-a-service", "purchases stealer",
           "purchases loader", "buys backdoor"), 0.8),
    _Rule("T1588.002", "Obtain Capabilities: Tool",
          ("cobalt strike", "sliver c2", "metasploit",
           "havoc framework", "brute ratel"), 0.85),
]


# ── Result types ─────────────────────────────────────────────────────


@dataclass
class DeciderHit:
    technique_id: str
    technique_name: str
    confidence: float
    matched_keywords: list[str]

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "confidence": round(self.confidence, 3),
            "matched_keywords": self.matched_keywords,
        }


# ── Scorer ───────────────────────────────────────────────────────────


_WORD_BOUNDARY_RE = re.compile(r"[A-Za-z0-9_]+")


def _normalise(text: str) -> str:
    """Lowercase + collapse whitespace. Word-boundary matching is done
    in :func:`_keyword_matches` rather than here because some Decider
    keywords are multi-word phrases ('lateral target enumeration')."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _keyword_matches(haystack_norm: str, keyword: str) -> bool:
    kn = _normalise(keyword)
    if not kn:
        return False
    # Pad with spaces so substring search respects word boundaries on
    # both ends without requiring a regex per keyword.
    padded = f" {haystack_norm} "
    return f" {kn} " in padded or f" {kn}." in padded \
        or f" {kn}," in padded or f" {kn}'" in padded


def classify_text(text: str, *, top_n: int = 5) -> list[DeciderHit]:
    """Score the input text against the corpus and return the top-N
    technique hits, ranked by confidence DESC.

    Confidence accumulates per matched keyword within a rule (capped at
    1.0) so a rule that hit on three different keywords scores higher
    than one that hit on a single weak keyword. Different rules
    contribute independent hits.
    """
    if not text:
        return []
    haystack = _normalise(text)
    by_technique: dict[str, DeciderHit] = {}
    for rule in _RULES:
        matched: list[str] = []
        for kw in rule.keywords:
            if _keyword_matches(haystack, kw):
                matched.append(kw)
        if not matched:
            continue
        confidence = min(rule.confidence_per_match * (1 + 0.15 * (len(matched) - 1)), 1.0)
        existing = by_technique.get(rule.technique_id)
        if existing and existing.confidence >= confidence:
            existing.matched_keywords.extend(matched)
            continue
        by_technique[rule.technique_id] = DeciderHit(
            technique_id=rule.technique_id,
            technique_name=rule.technique_name,
            confidence=confidence,
            matched_keywords=matched,
        )

    ranked = sorted(by_technique.values(), key=lambda h: h.confidence, reverse=True)
    return ranked[:top_n]


# ── DB integration ───────────────────────────────────────────────────


async def apply_decider_to_alert(
    session: AsyncSession,
    *,
    alert_id: uuid.UUID,
    top_n: int = 3,
) -> int:
    """Run the classifier on an alert's title + summary + agent_reasoning
    and materialise the top-N hits as ``AttackTechniqueAttachment`` rows.

    Idempotent on (entity_type, entity_id, matrix, technique_external_id)
    — re-running on the same alert never inserts duplicate attachments,
    just refreshes nothing. Returns the number of newly-inserted rows.
    """
    from src.models.mitre import AttachmentSource, AttackTechniqueAttachment
    from src.models.threat import Alert

    alert = await session.get(Alert, alert_id)
    if alert is None:
        return 0

    text = " ".join(filter(None, [
        alert.title, alert.summary, alert.agent_reasoning,
    ]))
    hits = classify_text(text, top_n=top_n)
    if not hits:
        return 0

    existing_keys: set[tuple[str, str]] = set(
        (await session.execute(
            select(
                AttackTechniqueAttachment.matrix,
                AttackTechniqueAttachment.technique_external_id,
            ).where(
                AttackTechniqueAttachment.organization_id == alert.organization_id,
                AttackTechniqueAttachment.entity_type == "alert",
                AttackTechniqueAttachment.entity_id == alert_id,
            )
        )).all()
    )

    inserted = 0
    for hit in hits:
        # Decider only emits enterprise-matrix techniques.
        key = ("enterprise", hit.technique_id)
        if key in existing_keys:
            continue
        session.add(AttackTechniqueAttachment(
            organization_id=alert.organization_id,
            entity_type="alert",
            entity_id=alert_id,
            matrix="enterprise",
            technique_external_id=hit.technique_id,
            confidence=hit.confidence,
            source=AttachmentSource.TRIAGE_AGENT.value,
            note=(
                f"Decider auto-tag (corpus={_CORPUS_VERSION}); "
                f"matched on: {', '.join(hit.matched_keywords[:5])}"
            ),
        ))
        existing_keys.add(key)
        inserted += 1
    return inserted


def corpus_version() -> str:
    return _CORPUS_VERSION


def rule_count() -> int:
    return len(_RULES)
