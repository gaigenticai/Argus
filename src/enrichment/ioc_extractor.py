"""Production-grade IOC (Indicator of Compromise) extraction engine.

Extracts IPv4, IPv6, CIDR, domains, URLs, hashes (MD5/SHA1/SHA256),
email addresses, CVE IDs, cryptocurrency addresses, JA3 fingerprints,
and file paths from arbitrary text.  Handles defanged notation.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum


class IOCTypeEnum(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BTC_ADDRESS = "btc_address"
    XMR_ADDRESS = "xmr_address"
    CVE = "cve"
    JA3 = "ja3"
    FILENAME = "filename"


@dataclass
class ExtractedIOC:
    ioc_type: IOCTypeEnum
    value: str
    confidence: float
    context_snippet: str = ""


# ---------------------------------------------------------------------------
# Allowlist — benign domains we never want to flag as IOCs
# ---------------------------------------------------------------------------

_DOMAIN_ALLOWLIST: set[str] = {
    # Major tech / cloud
    "google.com", "www.google.com", "googleapis.com", "gstatic.com",
    "google.co.uk", "google.de", "google.fr", "google.co.in",
    "microsoft.com", "www.microsoft.com", "windows.com", "live.com",
    "office.com", "office365.com", "outlook.com", "hotmail.com",
    "azure.com", "azure.microsoft.com", "windowsupdate.com",
    "apple.com", "www.apple.com", "icloud.com",
    "amazon.com", "www.amazon.com", "amazonaws.com", "aws.amazon.com",
    "cloudfront.net", "elasticbeanstalk.com",
    "facebook.com", "www.facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "t.co",
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com", "githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "youtube.com", "www.youtube.com", "youtu.be", "ytimg.com",
    "whatsapp.com", "web.whatsapp.com",
    "telegram.org", "t.me",
    "reddit.com", "www.reddit.com", "redd.it",
    "wikipedia.org", "en.wikipedia.org", "wikimedia.org",
    "stackexchange.com", "stackoverflow.com",
    # CDN / infra
    "cloudflare.com", "cloudflare-dns.com", "akamai.com", "akamaihd.net",
    "fastly.net", "edgecastcdn.net", "cdn77.org",
    "jquery.com", "bootstrapcdn.com", "unpkg.com", "cdnjs.cloudflare.com",
    # Email providers
    "gmail.com", "yahoo.com", "yahoo.co.jp", "aol.com", "protonmail.com",
    "proton.me", "zoho.com", "mail.com",
    # DNS / networking
    "cloudflare-dns.com", "opendns.com", "quad9.net",
    "in-addr.arpa", "ip6.arpa",
    # OS update / package repos
    "debian.org", "ubuntu.com", "fedoraproject.org", "centos.org",
    "archlinux.org", "npmjs.com", "pypi.org", "rubygems.org",
    "crates.io", "nuget.org", "maven.org",
    # Security vendors (avoid flagging their own domains)
    "virustotal.com", "hybrid-analysis.com", "malwarebytes.com",
    "kaspersky.com", "symantec.com", "mcafee.com", "eset.com",
    "trendmicro.com", "sophos.com", "crowdstrike.com", "paloaltonetworks.com",
    "fireeye.com", "mandiant.com", "anomali.com", "otx.alienvault.com",
    "alienvault.com", "threatconnect.com", "recordedfuture.com",
    "shodan.io", "censys.io", "zoomeye.org",
    # Misc safe
    "example.com", "example.org", "example.net", "localhost",
    "schema.org", "w3.org", "iana.org", "icann.org",
    "docker.com", "docker.io", "kubernetes.io",
    "nginx.com", "nginx.org", "apache.org",
    "letsencrypt.org", "digicert.com",
    "paypal.com", "stripe.com",
    "dropbox.com", "box.com",
    "slack.com", "zoom.us", "teams.microsoft.com",
}

# ---------------------------------------------------------------------------
# Context keywords that boost confidence
# ---------------------------------------------------------------------------

_HIGH_CONFIDENCE_KEYWORDS: set[str] = {
    "sell", "selling", "dump", "leak", "breach", "exploit", "malware",
    "ransomware", "c2", "c&c", "command and control", "botnet", "backdoor",
    "trojan", "rat", "keylogger", "stealer", "phishing", "dropper",
    "payload", "shellcode", "rootkit", "zero-day", "0day", "apt",
    "threat actor", "ioc", "indicator", "compromise", "exfil",
    "credential", "cred", "combolist", "fullz", "ssn", "cvv",
    "initial access", "rdp access", "vpn access", "shell access",
}


# ---------------------------------------------------------------------------
# Defanging helpers
# ---------------------------------------------------------------------------

def refang(text: str) -> str:
    """Convert defanged indicators back to their real form."""
    t = text
    t = t.replace("hxxp://", "http://")
    t = t.replace("hXXp://", "http://")
    t = t.replace("hxxps://", "https://")
    t = t.replace("hXXps://", "https://")
    t = t.replace("[.]", ".")
    t = t.replace("(dot)", ".")
    t = t.replace("[dot]", ".")
    t = t.replace("[:]", ":")
    t = t.replace("[at]", "@")
    t = t.replace("[@]", "@")
    t = t.replace("(at)", "@")
    t = re.sub(r"\[\.\]", ".", t)
    return t


def _snippet(text: str, match: re.Match, window: int = 80) -> str:
    """Return surrounding context for a match."""
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    return text[start:end].replace("\n", " ").strip()


def _context_confidence(snippet: str) -> float:
    """Compute a confidence boost based on context keywords."""
    lower = snippet.lower()
    hits = sum(1 for kw in _HIGH_CONFIDENCE_KEYWORDS if kw in lower)
    if hits >= 3:
        return 0.95
    if hits >= 2:
        return 0.85
    if hits >= 1:
        return 0.75
    return 0.5


# ---------------------------------------------------------------------------
# Private-range checks
# ---------------------------------------------------------------------------

_PRIVATE_IPV4_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "192.168.",
    "0.",
    "255.255.255.255",
)


def _is_private_ipv4(ip_str: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range."""
    if any(ip_str.startswith(p) for p in _PRIVATE_IPV4_PREFIXES):
        return True
    # 172.16.0.0 – 172.31.255.255
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False


def _is_private_ipv6(ip_str: str) -> bool:
    """Check if an IPv6 address is link-local, loopback, or private."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IPv4 — validated octets
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# CIDR notation
_RE_CIDR = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"/(?:3[0-2]|[12]?\d)\b"
)

# IPv6 — full, compressed, and mixed (::ffff:1.2.3.4) forms
_RE_IPV6 = re.compile(
    r"(?<![\w:.])"
    r"("
    # Full 8-group
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|"
    # Compressed with ::
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    # :: alone
    r"::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r")"
    r"(?![\w:.])",
    re.VERBOSE,
)

# Domain — 2+ labels, valid TLD (2-24 chars), allows subdomains
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,24}\b"
)

# URL — scheme required
_RE_URL = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}"
    r"(?::\d{1,5})?"
    r"(?:/[^\s\"'<>\]\)]*)?",
    re.IGNORECASE,
)

# Email
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b"
)

# Hashes — word-boundary constrained, hex only
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# CVE
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Bitcoin — legacy (1/3) and bech32 (bc1)
_RE_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_BTC_BECH32 = re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b")

# Monero
_RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# JA3 — 32 hex chars (same as MD5, differentiated by context keywords)
_JA3_CONTEXT_KEYWORDS = {"ja3", "ja3s", "fingerprint", "tls fingerprint", "ssl fingerprint"}

# File paths — Windows and Unix
_RE_WIN_PATH = re.compile(
    r"\b[A-Z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]+\b"
)
_RE_UNIX_PATH = re.compile(
    r"(?<!\w)/(?:etc|usr|var|tmp|opt|home|root|bin|sbin|dev|proc|sys|mnt|media|srv)"
    r"(?:/[^\s:;,\"'<>|(){}]+)+"
)


# ---------------------------------------------------------------------------
# Helper to validate hex strings are not just repeated chars / common words
# ---------------------------------------------------------------------------

def _is_valid_hex_hash(value: str) -> bool:
    """Reject hashes that are all-same-char, sequential, or too uniform."""
    v = value.lower()
    if len(set(v)) < 4:
        return False
    # Reject common hex-looking strings that aren't hashes
    if v == "0" * len(v) or v == "f" * len(v):
        return False
    return True


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def extract_iocs(text: str) -> list[ExtractedIOC]:
    """Extract all IOCs from raw text, returning deduplicated results."""
    # Refang for extraction, but keep original for context
    original_text = text
    text = refang(text)

    results: dict[tuple[str, str], ExtractedIOC] = {}  # (type, value) -> IOC
    url_values: set[str] = set()
    domain_from_urls: set[str] = set()

    def _add(ioc_type: IOCTypeEnum, value: str, match: re.Match, source_text: str) -> None:
        key = (ioc_type.value, value)
        if key in results:
            return
        snip = _snippet(source_text, match)
        conf = _context_confidence(snip)
        results[key] = ExtractedIOC(
            ioc_type=ioc_type,
            value=value,
            confidence=conf,
            context_snippet=snip,
        )

    # --- URLs first (so we can exclude their domains from standalone domain list) ---
    for m in _RE_URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        url_values.add(url)
        # Extract domain from URL for exclusion
        domain_match = re.match(r"https?://([^/:]+)", url)
        if domain_match:
            domain_from_urls.add(domain_match.group(1).lower())
        _add(IOCTypeEnum.URL, url, m, text)

    # --- CIDR before IPv4 (so we don't double-match the IP part) ---
    cidr_ips: set[str] = set()
    for m in _RE_CIDR.finditer(text):
        val = m.group(0)
        ip_part = val.split("/")[0]
        if not _is_private_ipv4(ip_part):
            cidr_ips.add(ip_part)
            _add(IOCTypeEnum.CIDR, val, m, text)

    # --- IPv4 ---
    for m in _RE_IPV4.finditer(text):
        ip = m.group(0)
        if _is_private_ipv4(ip):
            continue
        if ip in cidr_ips:
            continue
        _add(IOCTypeEnum.IPV4, ip, m, text)

    # --- IPv6 ---
    for m in _RE_IPV6.finditer(text):
        ip6 = m.group(1) if m.lastindex else m.group(0)
        if _is_private_ipv6(ip6):
            continue
        try:
            # Normalize to canonical form
            ip6_normalized = str(ipaddress.ip_address(ip6))
            _add(IOCTypeEnum.IPV6, ip6_normalized, m, text)
        except ValueError:
            _add(IOCTypeEnum.IPV6, ip6, m, text)

    # --- Domains (exclude URL-embedded domains and allowlisted) ---
    for m in _RE_DOMAIN.finditer(text):
        domain = m.group(0).lower()
        if domain in domain_from_urls:
            continue
        if domain in _DOMAIN_ALLOWLIST:
            continue
        # Also check if the parent domain is allowlisted
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            if parent in _DOMAIN_ALLOWLIST:
                continue
        # Skip if it's a pure TLD or single-label
        if len(parts) < 2:
            continue
        _add(IOCTypeEnum.DOMAIN, domain, m, text)

    # --- Email ---
    for m in _RE_EMAIL.finditer(text):
        email = m.group(0).lower()
        _add(IOCTypeEnum.EMAIL, email, m, text)

    # --- Hashes (SHA256 first → SHA1 → MD5, to avoid substring collisions) ---
    sha256_values: set[str] = set()
    for m in _RE_SHA256.finditer(text):
        val = m.group(0).lower()
        if _is_valid_hex_hash(val):
            sha256_values.add(val)
            _add(IOCTypeEnum.SHA256, val, m, text)

    sha1_values: set[str] = set()
    for m in _RE_SHA1.finditer(text):
        val = m.group(0).lower()
        # Skip if it's a substring of an already-matched SHA256
        if any(val in s for s in sha256_values):
            continue
        if _is_valid_hex_hash(val):
            sha1_values.add(val)
            _add(IOCTypeEnum.SHA1, val, m, text)

    for m in _RE_MD5.finditer(text):
        val = m.group(0).lower()
        # Skip if substring of SHA1 or SHA256
        if any(val in s for s in sha256_values) or any(val in s for s in sha1_values):
            continue
        if _is_valid_hex_hash(val):
            # Check for JA3 context
            snip = _snippet(text, m, window=120).lower()
            if any(kw in snip for kw in _JA3_CONTEXT_KEYWORDS):
                _add(IOCTypeEnum.JA3, val, m, text)
            else:
                _add(IOCTypeEnum.MD5, val, m, text)

    # --- CVE ---
    for m in _RE_CVE.finditer(text):
        cve = m.group(0).upper()
        _add(IOCTypeEnum.CVE, cve, m, text)

    # --- Bitcoin ---
    for m in _RE_BTC_LEGACY.finditer(text):
        _add(IOCTypeEnum.BTC_ADDRESS, m.group(0), m, text)
    for m in _RE_BTC_BECH32.finditer(text):
        _add(IOCTypeEnum.BTC_ADDRESS, m.group(0), m, text)

    # --- Monero ---
    for m in _RE_XMR.finditer(text):
        _add(IOCTypeEnum.XMR_ADDRESS, m.group(0), m, text)

    # --- File paths ---
    for m in _RE_WIN_PATH.finditer(text):
        _add(IOCTypeEnum.FILENAME, m.group(0), m, text)
    for m in _RE_UNIX_PATH.finditer(text):
        path = m.group(0)
        # Exclude overly short paths
        if len(path) > 4:
            _add(IOCTypeEnum.FILENAME, path, m, text)

    return list(results.values())
