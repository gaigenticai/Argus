"""Industry → default tech-stack templates.

When a new organisation is loaded into Argus we don't know what
technology they actually run, so the triage agent's LLM has nothing
to correlate CISA KEV / vulnerability feed entries against and
correctly refuses to fire alerts ("plausibility alone does not
justify a threat flag without asset confirmation").

These templates seed each new org with the **canonical stack** for
its industry — the components a typical bank / hospital / SaaS
company is overwhelmingly likely to run. The operator can refine
this through ``PATCH /organizations/{id}`` (or, eventually, the
Settings → Tech Stack tab) — but starting from a sensible default
means triage produces actionable alerts on day one instead of zero.

The categories are intentionally broad and vendor-anchored: the
LLM uses them as keyword pivots when scanning advisories, so
"Apache ActiveMQ" in the message_broker bucket lets the agent
match a CVE on ActiveMQ even if the org never explicitly typed
it in.

Sources:
- CISA KEV technology-frequency analysis
- Banking & healthcare reference architectures (industry standards)
- Top vendors by enterprise market share per category
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Per-industry templates
# ---------------------------------------------------------------------------

_BANKING: dict[str, list[str]] = {
    "web_servers": ["Nginx", "Apache HTTP Server", "F5 BIG-IP"],
    "application_runtime": ["Java (OpenJDK)", "Node.js", ".NET"],
    "frameworks": ["Spring Boot", "Express.js", "ASP.NET Core"],
    "databases": ["Oracle Database", "Microsoft SQL Server", "PostgreSQL"],
    "message_broker": ["Apache ActiveMQ", "IBM MQ", "Apache Kafka"],
    "identity_sso": ["Microsoft Entra ID", "Okta", "Ping Identity"],
    "mdm": ["Ivanti EPMM", "Microsoft Intune", "VMware Workspace ONE"],
    "vpn_sdwan": [
        "Cisco Catalyst SD-WAN Manager",
        "Palo Alto GlobalProtect",
        "Fortinet FortiGate",
    ],
    "remote_support": ["SimpleHelp", "TeamViewer", "BeyondTrust"],
    "document_viewers": ["Adobe Acrobat", "Adobe Reader", "Foxit PDF Reader"],
    "endpoint_protection": [
        "CrowdStrike Falcon",
        "Microsoft Defender for Endpoint",
        "SentinelOne",
    ],
    "cloud": ["Microsoft Azure", "AWS", "Oracle Cloud Infrastructure"],
    "containers": ["Kubernetes", "Red Hat OpenShift", "Docker"],
    "core_banking": ["Temenos T24", "Infosys Finacle", "FIS Profile"],
    "payment_gateways": ["SWIFT Alliance", "Visa Direct", "Mastercard Send"],
    "atm_pos": ["NCR ATM", "Diebold Nixdorf"],
}

_HEALTHCARE: dict[str, list[str]] = {
    "web_servers": ["Nginx", "Apache HTTP Server"],
    "application_runtime": ["Java (OpenJDK)", ".NET"],
    "databases": ["Microsoft SQL Server", "Oracle Database"],
    "ehr": ["Epic", "Cerner (Oracle Health)", "Meditech"],
    "imaging_pacs": ["GE Centricity", "Philips IntelliSpace", "Sectra"],
    "identity_sso": ["Microsoft Entra ID", "Okta", "Imprivata"],
    "mdm": ["Microsoft Intune", "Ivanti EPMM", "VMware Workspace ONE"],
    "vpn_sdwan": ["Cisco AnyConnect", "Palo Alto GlobalProtect", "Fortinet FortiGate"],
    "remote_support": ["TeamViewer", "BeyondTrust"],
    "document_viewers": ["Adobe Acrobat", "Adobe Reader"],
    "endpoint_protection": [
        "CrowdStrike Falcon",
        "Microsoft Defender for Endpoint",
    ],
    "cloud": ["Microsoft Azure", "AWS"],
    "medical_devices": ["BD Infusion Pumps", "Philips Patient Monitors"],
}

_SAAS: dict[str, list[str]] = {
    "web_servers": ["Nginx", "Cloudflare", "AWS ALB"],
    "application_runtime": ["Node.js", "Python", "Go"],
    "frameworks": ["Express.js", "Next.js", "Django", "FastAPI"],
    "databases": ["PostgreSQL", "MySQL", "MongoDB", "Redis"],
    "message_broker": ["Apache Kafka", "RabbitMQ", "AWS SQS"],
    "identity_sso": ["Auth0", "Okta", "Microsoft Entra ID"],
    "mdm": ["Microsoft Intune", "Jamf", "Kandji"],
    "vpn_sdwan": ["Tailscale", "Cloudflare Access", "Twingate"],
    "endpoint_protection": [
        "CrowdStrike Falcon",
        "SentinelOne",
        "Microsoft Defender for Endpoint",
    ],
    "cloud": ["AWS", "Google Cloud Platform", "Microsoft Azure"],
    "containers": ["Kubernetes", "Docker", "AWS ECS"],
    "ci_cd": ["GitHub Actions", "GitLab CI", "CircleCI"],
    "observability": ["Datadog", "Sentry", "Grafana"],
}

# Generic fallback — every org runs *something* in these buckets so
# triage has at least minimal signal even when the industry is
# unknown / "Other".
_GENERIC: dict[str, list[str]] = {
    "web_servers": ["Nginx", "Apache HTTP Server"],
    "identity_sso": ["Microsoft Entra ID", "Okta"],
    "endpoint_protection": [
        "CrowdStrike Falcon",
        "Microsoft Defender for Endpoint",
    ],
    "vpn_sdwan": ["Palo Alto GlobalProtect", "Fortinet FortiGate"],
    "document_viewers": ["Adobe Acrobat", "Adobe Reader"],
    "cloud": ["Microsoft Azure", "AWS"],
    "mdm": ["Microsoft Intune"],
}


_REGISTRY: dict[str, dict[str, list[str]]] = {
    "banking": _BANKING,
    "finance": _BANKING,
    "fintech": _BANKING,
    "healthcare": _HEALTHCARE,
    "health": _HEALTHCARE,
    "saas": _SAAS,
    "software": _SAAS,
    "technology": _SAAS,
}


def default_tech_stack(industry: str | None) -> dict[str, list[str]]:
    """Return the canonical tech-stack template for ``industry``.

    Lookup is case-insensitive and falls back to a small generic
    template when the industry is unknown / empty. Every value is a
    fresh dict (not a reference into ``_REGISTRY``) so callers can
    mutate the result without poisoning future lookups.
    """
    key = (industry or "").strip().lower()
    template = _REGISTRY.get(key, _GENERIC)
    return {category: list(items) for category, items in template.items()}
