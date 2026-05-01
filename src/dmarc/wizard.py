"""DMARC implementation wizard.

Produces canonical SPF / DKIM / DMARC DNS records for a domain along
with the recommended progression path:

    1. Start at p=none (monitor only) — no mail flow disruption.
    2. After 30+ days of clean RUA reports, move to p=quarantine pct=25,
       then 50, 100.
    3. Finally move to p=reject. Recommended end-state for any domain
       that sends real mail.

Aligned with M3AAWG Sender BCP and DMARC.org policy guide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
)


@dataclass
class DmarcWizardOutput:
    """Wizard output for one domain.

    ``dkim_records`` carries one row per selector the operator
    declared. Each row is a fully-formed DNS record except for the
    ``p=`` (public key) value, which the operator's MTA / DKIM
    service must emit — the wizard cannot generate a real RSA key
    pair on the customer's behalf because the *private* key has to
    live with the sender, not in this database. The placeholder
    string ``<PUBLIC_KEY_BASE64>`` is replaced inline with the real
    value when the operator pastes it into the wizard's confirm
    step (``POST /dmarc/wizard/{domain}/dkim`` — see
    ``src/api/routes/dmarc.py``).
    """

    domain: str
    spf_record: str
    dkim_records: list[dict[str, str]]
    dmarc_records_progression: list[dict[str, str]]
    rua_endpoint: str
    ruf_endpoint: str | None
    rationale: str


def generate_records(
    domain: str,
    *,
    sending_ips: list[str] | None = None,
    sending_includes: list[str] | None = None,
    rua_endpoint: str = "rua@dmarc-report.argus.local",
    ruf_endpoint: str | None = None,
    dkim_selectors: list[str] | None = None,
) -> DmarcWizardOutput:
    if not _DOMAIN_RE.match(domain.lower()):
        raise ValueError(f"{domain!r} is not a valid domain")
    domain = domain.lower()

    spf_parts = ["v=spf1"]
    for ip in sending_ips or []:
        if ":" in ip:
            spf_parts.append(f"ip6:{ip}")
        else:
            spf_parts.append(f"ip4:{ip}")
    for inc in sending_includes or []:
        spf_parts.append(f"include:{inc}")
    # Default end-state: -all (hardfail). If no ips/includes were supplied,
    # we recommend ~all temporarily — but document that -all is the goal.
    if sending_ips or sending_includes:
        spf_parts.append("-all")
    else:
        spf_parts.append("~all  ; tighten to -all once sending sources confirmed")
    spf_record = " ".join(spf_parts)

    dkim_records: list[dict[str, str]] = []
    for sel in dkim_selectors or ["default"]:
        dkim_records.append(
            {
                "name": f"{sel}._domainkey.{domain}",
                "type": "TXT",
                "value": (
                    "v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64> "
                    "; replace <PUBLIC_KEY_BASE64> with the matching "
                    "DKIM key emitted by your sender."
                ),
            }
        )

    base = f"v=DMARC1; rua=mailto:{rua_endpoint};"
    if ruf_endpoint:
        base += f" ruf=mailto:{ruf_endpoint};"

    progression = [
        {
            "stage": "1. monitor",
            "name": f"_dmarc.{domain}",
            "type": "TXT",
            "value": base + " p=none; sp=none; aspf=r; adkim=r; pct=100",
            "duration": "≥ 30 days",
        },
        {
            "stage": "2. quarantine 25%",
            "name": f"_dmarc.{domain}",
            "type": "TXT",
            "value": base + " p=quarantine; sp=quarantine; aspf=r; adkim=r; pct=25",
            "duration": "1–2 weeks",
        },
        {
            "stage": "3. quarantine 100%",
            "name": f"_dmarc.{domain}",
            "type": "TXT",
            "value": base + " p=quarantine; sp=quarantine; aspf=r; adkim=r; pct=100",
            "duration": "1–2 weeks",
        },
        {
            "stage": "4. reject",
            "name": f"_dmarc.{domain}",
            "type": "TXT",
            "value": base + " p=reject; sp=reject; aspf=s; adkim=s; pct=100",
            "duration": "permanent",
        },
    ]

    rationale = (
        "Start at p=none to gather RUA reports without breaking mail flow. "
        "Once reports show all legitimate sources are SPF- or DKIM-aligned, "
        "advance to p=quarantine pct=25, then 100, then p=reject. Each "
        "stage should run for at least one full reporting cycle (24h) — "
        "bigger orgs typically take 30+ days at p=none. M3AAWG Sender BCP "
        "§4.2 and DMARC.org policy guide endorse this progression."
    )

    return DmarcWizardOutput(
        domain=domain,
        spf_record=spf_record,
        dkim_records=dkim_records,
        dmarc_records_progression=progression,
        rua_endpoint=rua_endpoint,
        ruf_endpoint=ruf_endpoint,
        rationale=rationale,
    )


__all__ = ["DmarcWizardOutput", "generate_records"]
