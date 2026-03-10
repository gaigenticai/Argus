"""OPSEC hardening module — Tor circuit rotation, header randomization, fingerprint evasion."""

import asyncio
import random
import re
import socket

import aiohttp

from src.config.settings import settings


# --- Tor Circuit Rotation ---


async def rotate_tor_circuit(
    control_port: int | None = None,
    password: str | None = None,
) -> bool:
    """
    Send a NEWNYM signal to the Tor control port to rotate the circuit.
    Uses the raw Tor control protocol over a TCP socket.
    Returns True if circuit rotation was acknowledged.
    """
    port = control_port or settings.tor.control_port
    pwd = password or settings.tor.control_password
    host = settings.tor.socks_host

    loop = asyncio.get_running_loop()

    def _control_newnym() -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((host, port))

            # Authenticate
            sock.sendall(f'AUTHENTICATE "{pwd}"\r\n'.encode())
            auth_response = _recv_line(sock)
            if not auth_response.startswith("250"):
                raise ConnectionError(f"Tor auth failed: {auth_response}")

            # Send NEWNYM signal
            sock.sendall(b"SIGNAL NEWNYM\r\n")
            newnym_response = _recv_line(sock)
            if not newnym_response.startswith("250"):
                raise ConnectionError(f"NEWNYM failed: {newnym_response}")

            # Quit
            sock.sendall(b"QUIT\r\n")
            return True
        finally:
            sock.close()

    return await loop.run_in_executor(None, _control_newnym)


def _recv_line(sock: socket.socket, max_bytes: int = 1024) -> str:
    """Read a single response line from a socket."""
    data = b""
    while True:
        chunk = sock.recv(max_bytes)
        if not chunk:
            break
        data += chunk
        if b"\r\n" in data:
            break
    return data.decode("utf-8", errors="replace").strip()


# --- Header Randomization ---

# Real browser User-Agent distributions (weighted by market share approximation)
_USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", 35),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", 15),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", 12),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0", 10),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15", 8),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", 6),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0", 5),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", 4),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", 3),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", 2),
]

_ACCEPT_HEADERS = [
    ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 50),
    ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", 30),
    ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 20),
]

_ACCEPT_LANGUAGE = [
    ("en-US,en;q=0.9", 40),
    ("en-US,en;q=0.9,es;q=0.8", 15),
    ("en-GB,en;q=0.9,en-US;q=0.8", 10),
    ("en-US,en;q=0.8", 10),
    ("en-US,en;q=0.9,fr;q=0.8", 8),
    ("en-US,en;q=0.9,de;q=0.7", 7),
    ("en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7", 5),
    ("en-US,en;q=0.9,ja;q=0.8", 5),
]

_ACCEPT_ENCODING = [
    ("gzip, deflate, br", 60),
    ("gzip, deflate, br, zstd", 25),
    ("gzip, deflate", 15),
]


def _weighted_choice(options: list[tuple[str, int]]) -> str:
    """Pick an item from a weighted list."""
    values, weights = zip(*options)
    return random.choices(values, weights=weights, k=1)[0]


def randomize_headers() -> dict:
    """Generate randomized but realistic HTTP headers from real browser distributions."""
    ua = _weighted_choice(_USER_AGENTS)
    headers = {
        "User-Agent": ua,
        "Accept": _weighted_choice(_ACCEPT_HEADERS),
        "Accept-Language": _weighted_choice(_ACCEPT_LANGUAGE),
        "Accept-Encoding": _weighted_choice(_ACCEPT_ENCODING),
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Chrome-specific headers (only for Chrome UAs)
    if "Chrome" in ua and "Edg" not in ua:
        headers["Sec-Ch-Ua"] = '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        headers["Sec-Ch-Ua-Mobile"] = "?0"
        if "Windows" in ua:
            headers["Sec-Ch-Ua-Platform"] = '"Windows"'
        elif "Macintosh" in ua:
            headers["Sec-Ch-Ua-Platform"] = '"macOS"'
        elif "Linux" in ua:
            headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"

    return headers


# --- Request Jitter ---


def get_request_jitter() -> float:
    """
    Return a delay (in seconds) from a Pareto distribution.
    More realistic than uniform random — most delays are short, occasional long ones.
    Bounded between crawler settings min and max delays.
    """
    min_delay = settings.crawler.request_delay_min
    max_delay = settings.crawler.request_delay_max

    # Pareto distribution: shape parameter alpha=1.5 gives a good heavy tail
    # Scale so the minimum value is min_delay
    alpha = 1.5
    raw = (random.paretovariate(alpha) - 1) * min_delay + min_delay

    # Clamp to max
    return min(raw, max_delay)


# --- Blocking Detection ---

_BLOCKING_PATTERNS = [
    re.compile(r"access\s+denied", re.IGNORECASE),
    re.compile(r"403\s+forbidden", re.IGNORECASE),
    re.compile(r"captcha", re.IGNORECASE),
    re.compile(r"cf-browser-verification", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"ddos-guard", re.IGNORECASE),
    re.compile(r"please\s+enable\s+javascript", re.IGNORECASE),
    re.compile(r"just\s+a\s+moment", re.IGNORECASE),
    re.compile(r"checking\s+your\s+browser", re.IGNORECASE),
    re.compile(r"attention\s+required", re.IGNORECASE),
    re.compile(r"rate\s*limit", re.IGNORECASE),
    re.compile(r"too\s+many\s+requests", re.IGNORECASE),
    re.compile(r"<title>\s*blocked\s*</title>", re.IGNORECASE),
    re.compile(r"hcaptcha", re.IGNORECASE),
    re.compile(r"recaptcha", re.IGNORECASE),
    re.compile(r"challenge-platform", re.IGNORECASE),
    re.compile(r"_cf_chl_opt", re.IGNORECASE),
    re.compile(r"managed\s+challenge", re.IGNORECASE),
]


def check_source_blocking(response_text: str) -> bool:
    """Detect common blocking patterns in HTTP response text (CAPTCHA, WAF, rate limiting)."""
    if not response_text:
        return False
    for pattern in _BLOCKING_PATTERNS:
        if pattern.search(response_text):
            return True
    return False


# --- TLS Fingerprint Check ---


async def fingerprint_check(session: aiohttp.ClientSession, check_url: str) -> dict:
    """
    Check our TLS fingerprint against a known fingerprint checker service.
    Commonly used: https://tls.browserleaks.com/json or https://ja3er.com/json
    Returns the parsed JSON response from the checker.
    """
    timeout = aiohttp.ClientTimeout(total=15)
    try:
        async with session.get(check_url, timeout=timeout) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "status": "ok",
                    "fingerprint_data": data,
                    "status_code": resp.status,
                }
            else:
                body = await resp.text(errors="replace")
                return {
                    "status": "error",
                    "status_code": resp.status,
                    "response": body[:500],
                }
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
        }
