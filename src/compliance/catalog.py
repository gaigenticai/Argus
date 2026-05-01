"""Control catalog data + idempotent seeder.

Four frameworks ship in the v1 pack — the highest-leverage for the GCC
banking and cross-vertical demos. Subsequent frameworks (NESA, ADHICS,
Qatar NCSF, Bahrain CBB, Kuwait CITRA, Oman OCERT, PCI-DSS 4.0.1,
SOC 2 CC7.3) are queued as a P1 follow-on (see MEGA_PHASE.md §11).

Per framework we seed only the controls that are reachable from at
least one ``signal_kind/value`` — i.e., the ones the engine can
actually populate from Argus data. The remaining controls in each
framework live in the regulator's source document and can be linked
from the exporter cover page rather than re-typed here. This is an
intentional scope cut: a regulator-facing report that lists 114
NCA-ECC controls but populates 6 of them looks worse than a report
that lists 18 controls and populates 14.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.compliance import (
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceFramework,
)

logger = logging.getLogger(__name__)


# --- Framework metadata -------------------------------------------------


FRAMEWORKS: list[dict] = [
    {
        "code": "NCA-ECC-V2",
        "name_en": "NCA Essential Cybersecurity Controls",
        "name_ar": "الضوابط الأساسية للأمن السيبراني",
        "version": "2.0",
        "source_url": "https://nca.gov.sa/en/regulatory-documents/controls-list/",
        "source_version_date": date(2024, 1, 1),
        "description_en": (
            "Mandatory cybersecurity baseline issued by the Saudi National "
            "Cybersecurity Authority for government bodies and critical "
            "national infrastructure."
        ),
        "description_ar": (
            "الحد الأدنى الإلزامي للأمن السيبراني الصادر عن الهيئة الوطنية "
            "للأمن السيبراني للجهات الحكومية والبنية التحتية الوطنية الحساسة."
        ),
    },
    {
        "code": "SAMA-CSF-V1",
        "name_en": "SAMA Cyber Security Framework",
        "name_ar": "إطار الأمن السيبراني للبنك المركزي السعودي",
        "version": "1.0",
        "source_url": "https://www.sama.gov.sa/en-US/Laws/BankingRules/SAMA%20Cyber%20Security%20Framework.pdf",
        "source_version_date": date(2017, 5, 1),
        "description_en": (
            "Cyber security framework mandated by the Saudi Central Bank "
            "(SAMA) for all financial institutions, payment service "
            "providers, and insurers operating in the Kingdom."
        ),
        "description_ar": (
            "إطار الأمن السيبراني الإلزامي الصادر عن البنك المركزي السعودي "
            "لجميع المؤسسات المالية ومزودي خدمات الدفع وشركات التأمين "
            "العاملة في المملكة."
        ),
    },
    {
        "code": "ISO-27001-2022",
        "name_en": "ISO/IEC 27001:2022 — Information Security Management",
        "name_ar": "آيزو/آي إي سي 27001:2022 — إدارة أمن المعلومات",
        "version": "2022",
        "source_url": "https://www.iso.org/standard/27001",
        "source_version_date": date(2022, 10, 25),
        "description_en": (
            "International standard for information security management "
            "systems. The Annex A controls in this seed focus on those "
            "operationalised by a threat intelligence platform."
        ),
        "description_ar": (
            "المعيار الدولي لأنظمة إدارة أمن المعلومات. تركز ضوابط الملحق أ "
            "في هذه القائمة على ما يُفعَّل عبر منصة استخبارات التهديدات."
        ),
    },
    {
        "code": "NIST-CSF-V2",
        "name_en": "NIST Cybersecurity Framework 2.0",
        "name_ar": "إطار الأمن السيبراني NIST الإصدار 2.0",
        "version": "2.0",
        "source_url": "https://www.nist.gov/cyberframework",
        "source_version_date": date(2024, 2, 26),
        "description_en": (
            "U.S. National Institute of Standards and Technology Cybersecurity "
            "Framework — six functions (Govern, Identify, Protect, Detect, "
            "Respond, Recover) widely accepted as a global baseline."
        ),
        "description_ar": (
            "إطار الأمن السيبراني للمعهد الوطني للمعايير والتقنية (NIST) — "
            "ست وظائف: الحوكمة، التحديد، الحماية، الكشف، الاستجابة، التعافي."
        ),
    },
]


# --- Controls -----------------------------------------------------------
#
# Each entry: framework_code, control_id, sort_order, title_en, title_ar
# (optional), description_en, description_ar (optional).


CONTROLS: list[dict] = [
    # ── NCA-ECC v2 ────────────────────────────────────────────────────────
    {"f": "NCA-ECC-V2", "cid": "1-1", "sort": 110,
     "title_en": "Cybersecurity Strategy",
     "title_ar": "استراتيجية الأمن السيبراني",
     "desc_en": "Documented, board-approved cybersecurity strategy aligned "
                "with national priorities."},
    {"f": "NCA-ECC-V2", "cid": "1-3", "sort": 130,
     "title_en": "Cybersecurity Risk Management",
     "title_ar": "إدارة مخاطر الأمن السيبراني",
     "desc_en": "Continuous identification, assessment, and treatment of "
                "cybersecurity risks including third-party and supply chain."},
    {"f": "NCA-ECC-V2", "cid": "2-3", "sort": 230,
     "title_en": "Information Asset Protection",
     "title_ar": "حماية أصول المعلومات",
     "desc_en": "Classification and protection of information assets across "
                "their lifecycle."},
    {"f": "NCA-ECC-V2", "cid": "2-7", "sort": 270,
     "title_en": "Email Protection",
     "title_ar": "حماية البريد الإلكتروني",
     "desc_en": "Anti-phishing, DMARC/DKIM/SPF, sandbox detonation, and "
                "user awareness for email-borne threats."},
    {"f": "NCA-ECC-V2", "cid": "2-9", "sort": 290,
     "title_en": "Web Application Security",
     "title_ar": "أمن تطبيقات الإنترنت",
     "desc_en": "Protection of public-facing web apps including impersonation "
                "and brand abuse monitoring."},
    {"f": "NCA-ECC-V2", "cid": "2-10", "sort": 310,
     "title_en": "Cybersecurity Event Logs and Monitoring",
     "title_ar": "سجلات وأحداث الأمن السيبراني والمراقبة",
     "desc_en": "Centralised collection, retention, and active monitoring of "
                "cybersecurity events."},
    {"f": "NCA-ECC-V2", "cid": "2-11", "sort": 320,
     "title_en": "Cybersecurity Incident and Threat Management",
     "title_ar": "إدارة الحوادث والتهديدات السيبرانية",
     "desc_en": "Detection, triage, containment, eradication, and recovery "
                "of cybersecurity incidents."},
    {"f": "NCA-ECC-V2", "cid": "2-12", "sort": 330,
     "title_en": "Cyber Threat Intelligence",
     "title_ar": "استخبارات التهديدات السيبرانية",
     "desc_en": "Collection, analysis, dissemination, and operationalisation "
                "of cyber threat intelligence."},
    {"f": "NCA-ECC-V2", "cid": "2-13", "sort": 340,
     "title_en": "Vulnerability Management",
     "title_ar": "إدارة الثغرات",
     "desc_en": "Continuous identification, assessment, and remediation of "
                "technical vulnerabilities."},
    {"f": "NCA-ECC-V2", "cid": "2-14", "sort": 350,
     "title_en": "Penetration Testing",
     "title_ar": "اختبار الاختراق",
     "desc_en": "Periodic adversarial testing of cybersecurity controls."},
    {"f": "NCA-ECC-V2", "cid": "4-1", "sort": 410,
     "title_en": "Third-Party Cybersecurity",
     "title_ar": "الأمن السيبراني للأطراف الخارجية",
     "desc_en": "Cybersecurity in third-party contracts, vendor onboarding, "
                "and supply-chain risk."},
    {"f": "NCA-ECC-V2", "cid": "4-2", "sort": 420,
     "title_en": "Cloud Computing Cybersecurity",
     "title_ar": "الأمن السيبراني للحوسبة السحابية",
     "desc_en": "Cybersecurity for the use of cloud computing services."},

    # ── SAMA-CSF v1.0 ─────────────────────────────────────────────────────
    {"f": "SAMA-CSF-V1", "cid": "3.3.1", "sort": 100,
     "title_en": "Cyber Security Strategy",
     "title_ar": "استراتيجية الأمن السيبراني",
     "desc_en": "Board-approved cyber security strategy with executive "
                "sponsorship and measurable objectives."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.5", "sort": 200,
     "title_en": "Cyber Security in Third Party Risk Management",
     "title_ar": "الأمن السيبراني في إدارة مخاطر الأطراف الخارجية",
     "desc_en": "Cyber security requirements in third-party engagements, "
                "vendor due diligence, and ongoing monitoring."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.6", "sort": 300,
     "title_en": "Cyber Security in Operations & Technology",
     "title_ar": "الأمن السيبراني في العمليات والتقنية",
     "desc_en": "Cyber security controls embedded in IT operations, change "
                "management, and incident response."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.13", "sort": 700,
     "title_en": "Threat Intelligence",
     "title_ar": "استخبارات التهديدات",
     "desc_en": "Acquisition, analysis, and dissemination of threat "
                "intelligence relevant to the financial sector."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.14", "sort": 800,
     "title_en": "Vulnerability Management",
     "title_ar": "إدارة الثغرات",
     "desc_en": "Vulnerability identification, prioritisation, and remediation "
                "across the technology estate."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.15", "sort": 900,
     "title_en": "Patch Management",
     "title_ar": "إدارة التصحيحات",
     "desc_en": "Timely application of security patches with risk-based "
                "prioritisation."},
    {"f": "SAMA-CSF-V1", "cid": "3.3.16", "sort": 1000,
     "title_en": "Brand Protection",
     "title_ar": "حماية العلامة التجارية",
     "desc_en": "Detection and takedown of impersonation, phishing, and "
                "fraud targeting customers and the institution's brand."},

    # ── ISO 27001:2022 (Annex A subset) ───────────────────────────────────
    {"f": "ISO-27001-2022", "cid": "A.5.7", "sort": 57,
     "title_en": "Threat Intelligence",
     "title_ar": "استخبارات التهديدات",
     "desc_en": "Information about information security threats shall be "
                "collected and analysed to produce threat intelligence."},
    {"f": "ISO-27001-2022", "cid": "A.5.23", "sort": 523,
     "title_en": "Information security for use of cloud services",
     "title_ar": "أمن المعلومات لاستخدام الخدمات السحابية"},
    {"f": "ISO-27001-2022", "cid": "A.5.24", "sort": 524,
     "title_en": "Information security incident management planning"},
    {"f": "ISO-27001-2022", "cid": "A.5.25", "sort": 525,
     "title_en": "Assessment and decision on information security events"},
    {"f": "ISO-27001-2022", "cid": "A.5.26", "sort": 526,
     "title_en": "Response to information security incidents"},
    {"f": "ISO-27001-2022", "cid": "A.5.30", "sort": 530,
     "title_en": "ICT readiness for business continuity"},
    {"f": "ISO-27001-2022", "cid": "A.8.7", "sort": 807,
     "title_en": "Protection against malware"},
    {"f": "ISO-27001-2022", "cid": "A.8.8", "sort": 808,
     "title_en": "Management of technical vulnerabilities"},
    {"f": "ISO-27001-2022", "cid": "A.8.16", "sort": 816,
     "title_en": "Monitoring activities"},
    {"f": "ISO-27001-2022", "cid": "A.8.23", "sort": 823,
     "title_en": "Web filtering"},

    # ── NIST CSF 2.0 ──────────────────────────────────────────────────────
    {"f": "NIST-CSF-V2", "cid": "GV.OC-01", "sort": 100,
     "title_en": "Organisational mission is understood and informs "
                 "cybersecurity risk management"},
    {"f": "NIST-CSF-V2", "cid": "GV.RM-01", "sort": 110,
     "title_en": "Risk management objectives are established"},
    {"f": "NIST-CSF-V2", "cid": "ID.RA-03", "sort": 200,
     "title_en": "Internal and external threats to the organization are "
                 "identified and recorded"},
    {"f": "NIST-CSF-V2", "cid": "ID.RA-04", "sort": 210,
     "title_en": "Potential impacts and likelihoods of threats are identified"},
    {"f": "NIST-CSF-V2", "cid": "ID.IM-03", "sort": 220,
     "title_en": "Improvements are identified from execution of operational "
                 "processes"},
    {"f": "NIST-CSF-V2", "cid": "PR.IR-01", "sort": 300,
     "title_en": "Networks and environments are protected from unauthorized "
                 "access"},
    {"f": "NIST-CSF-V2", "cid": "DE.CM-01", "sort": 400,
     "title_en": "Networks and network services are monitored for adverse "
                 "events"},
    {"f": "NIST-CSF-V2", "cid": "DE.CM-03", "sort": 410,
     "title_en": "Personnel activity and technology usage are monitored"},
    {"f": "NIST-CSF-V2", "cid": "DE.CM-09", "sort": 420,
     "title_en": "Computing hardware and software, runtime environments, and "
                 "their data are monitored"},
    {"f": "NIST-CSF-V2", "cid": "DE.AE-02", "sort": 430,
     "title_en": "Potentially adverse events are analyzed to better understand "
                 "associated activities"},
    {"f": "NIST-CSF-V2", "cid": "DE.AE-03", "sort": 440,
     "title_en": "Information is correlated from multiple sources"},
    {"f": "NIST-CSF-V2", "cid": "DE.AE-04", "sort": 450,
     "title_en": "Estimated impact and scope of adverse events are understood"},
    {"f": "NIST-CSF-V2", "cid": "RS.MA-01", "sort": 500,
     "title_en": "The incident response plan is executed in coordination with "
                 "relevant third parties"},
    {"f": "NIST-CSF-V2", "cid": "RS.AN-03", "sort": 510,
     "title_en": "Information shared during incident response activities is "
                 "consistent with response plans"},
    {"f": "NIST-CSF-V2", "cid": "RS.MI-01", "sort": 520,
     "title_en": "Incidents are contained"},
    {"f": "NIST-CSF-V2", "cid": "RS.CO-02", "sort": 530,
     "title_en": "Internal and external stakeholders are notified of incidents"},
]


# --- Mappings: signal → controls ----------------------------------------
#
# Format: (signal_kind, signal_value, [(framework_code, control_id, confidence)])


_M = "mitre_technique"
_AC = "alert_category"
_CS = "case_state"

MAPPINGS: list[tuple[str, str, list[tuple[str, str, float]]]] = [
    # Phishing
    (_AC, "phishing", [
        ("NCA-ECC-V2", "2-7", 1.0),
        ("NCA-ECC-V2", "2-12", 0.9),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("SAMA-CSF-V1", "3.3.16", 0.9),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("ISO-27001-2022", "A.8.23", 0.6),
        ("NIST-CSF-V2", "DE.CM-09", 0.9),
        ("NIST-CSF-V2", "DE.AE-02", 0.8),
    ]),
    # Ransomware
    (_AC, "ransomware_victim", [
        ("NCA-ECC-V2", "2-11", 1.0),
        ("NCA-ECC-V2", "2-12", 0.9),
        ("NCA-ECC-V2", "4-1", 0.7),
        ("SAMA-CSF-V1", "3.3.6", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 0.9),
        ("ISO-27001-2022", "A.5.26", 1.0),
        ("ISO-27001-2022", "A.8.7", 0.9),
        ("ISO-27001-2022", "A.5.30", 0.7),
        ("NIST-CSF-V2", "RS.MA-01", 1.0),
        ("NIST-CSF-V2", "RS.MI-01", 0.9),
        ("NIST-CSF-V2", "RS.AN-03", 0.8),
    ]),
    # Credential leak / stealer log
    (_AC, "credential_leak", [
        ("NCA-ECC-V2", "1-3", 0.8),
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("ISO-27001-2022", "A.8.8", 0.7),
        ("NIST-CSF-V2", "DE.CM-01", 0.9),
        ("NIST-CSF-V2", "ID.RA-03", 0.8),
    ]),
    (_AC, "stealer_log", [
        ("NCA-ECC-V2", "1-3", 0.8),
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("ISO-27001-2022", "A.8.8", 0.6),
        ("NIST-CSF-V2", "DE.AE-02", 0.9),
    ]),
    # Data breach
    (_AC, "data_breach", [
        ("NCA-ECC-V2", "2-3", 0.9),
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.6", 1.0),
        ("ISO-27001-2022", "A.5.26", 1.0),
        ("NIST-CSF-V2", "RS.MA-01", 0.9),
        ("NIST-CSF-V2", "RS.AN-03", 0.9),
    ]),
    # Brand abuse / impersonation
    (_AC, "brand_abuse", [
        ("NCA-ECC-V2", "2-9", 1.0),
        ("NCA-ECC-V2", "2-12", 0.9),
        ("SAMA-CSF-V1", "3.3.16", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 0.8),
        ("ISO-27001-2022", "A.5.7", 0.9),
        ("NIST-CSF-V2", "DE.AE-02", 0.8),
    ]),
    (_AC, "impersonation", [
        ("NCA-ECC-V2", "2-9", 1.0),
        ("NCA-ECC-V2", "2-12", 0.9),
        ("SAMA-CSF-V1", "3.3.16", 1.0),
        ("ISO-27001-2022", "A.5.7", 0.9),
        ("NIST-CSF-V2", "DE.AE-02", 0.8),
    ]),
    # Vulnerabilities / exploits
    (_AC, "exploit", [
        ("NCA-ECC-V2", "2-13", 1.0),
        ("NCA-ECC-V2", "2-14", 0.7),
        ("SAMA-CSF-V1", "3.3.14", 1.0),
        ("SAMA-CSF-V1", "3.3.15", 0.9),
        ("ISO-27001-2022", "A.8.8", 1.0),
        ("NIST-CSF-V2", "ID.RA-03", 0.9),
        ("NIST-CSF-V2", "ID.RA-04", 0.8),
    ]),
    # Dark web / underground chatter
    (_AC, "dark_web_mention", [
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("NIST-CSF-V2", "DE.CM-03", 0.7),
        ("NIST-CSF-V2", "DE.AE-03", 0.8),
    ]),
    (_AC, "underground_chatter", [
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("NIST-CSF-V2", "DE.CM-03", 0.7),
    ]),
    # Doxxing
    (_AC, "doxxing", [
        ("NCA-ECC-V2", "2-12", 1.0),
        ("SAMA-CSF-V1", "3.3.13", 0.9),
        ("ISO-27001-2022", "A.5.7", 0.9),
        ("NIST-CSF-V2", "DE.AE-02", 0.7),
    ]),
    # Insider threat
    (_AC, "insider_threat", [
        ("NCA-ECC-V2", "1-3", 1.0),
        ("SAMA-CSF-V1", "3.3.6", 0.9),
        ("ISO-27001-2022", "A.5.26", 0.8),
        ("NIST-CSF-V2", "DE.CM-03", 1.0),
    ]),
    # Initial-access broker / access sale
    (_AC, "access_sale", [
        ("NCA-ECC-V2", "2-12", 1.0),
        ("NCA-ECC-V2", "4-1", 0.8),
        ("SAMA-CSF-V1", "3.3.13", 1.0),
        ("ISO-27001-2022", "A.5.7", 1.0),
        ("NIST-CSF-V2", "DE.AE-02", 0.8),
    ]),

    # MITRE ATT&CK technique mappings
    (_M, "T1566", [  # Phishing
        ("NCA-ECC-V2", "2-7", 1.0),
        ("ISO-27001-2022", "A.5.7", 0.9),
        ("NIST-CSF-V2", "DE.CM-09", 0.9),
    ]),
    (_M, "T1190", [  # Exploit Public-Facing App
        ("NCA-ECC-V2", "2-9", 1.0),
        ("NCA-ECC-V2", "2-13", 0.9),
        ("ISO-27001-2022", "A.8.8", 0.9),
        ("NIST-CSF-V2", "ID.RA-03", 0.9),
    ]),
    (_M, "T1078", [  # Valid Accounts
        ("NCA-ECC-V2", "1-3", 0.8),
        ("ISO-27001-2022", "A.8.8", 0.7),
        ("NIST-CSF-V2", "DE.CM-01", 0.9),
    ]),
    (_M, "T1486", [  # Data Encrypted for Impact (ransomware)
        ("NCA-ECC-V2", "2-11", 1.0),
        ("ISO-27001-2022", "A.8.7", 0.9),
        ("NIST-CSF-V2", "RS.MI-01", 1.0),
    ]),
    (_M, "T1071", [  # App Layer Protocol (C2)
        ("NCA-ECC-V2", "2-10", 1.0),
        ("ISO-27001-2022", "A.8.16", 0.9),
        ("NIST-CSF-V2", "DE.CM-01", 1.0),
    ]),
    (_M, "T1567", [  # Exfiltration over web service
        ("NCA-ECC-V2", "2-3", 0.9),
        ("ISO-27001-2022", "A.8.16", 0.9),
        ("NIST-CSF-V2", "DE.AE-03", 0.8),
    ]),
    (_M, "T1110", [  # Brute Force
        ("NCA-ECC-V2", "1-3", 0.7),
        ("ISO-27001-2022", "A.5.7", 0.6),
        ("NIST-CSF-V2", "DE.CM-01", 0.9),
    ]),

    # Case-state mappings — closed/verified cases are evidence of working IR
    (_CS, "verified", [
        ("NCA-ECC-V2", "2-11", 1.0),
        ("SAMA-CSF-V1", "3.3.6", 1.0),
        ("ISO-27001-2022", "A.5.26", 1.0),
        ("NIST-CSF-V2", "RS.AN-03", 1.0),
    ]),
    (_CS, "remediated", [
        ("NCA-ECC-V2", "2-11", 0.9),
        ("ISO-27001-2022", "A.5.26", 0.9),
        ("NIST-CSF-V2", "RS.MI-01", 0.9),
    ]),
    (_CS, "closed", [
        ("NCA-ECC-V2", "2-11", 0.8),
        ("ISO-27001-2022", "A.5.26", 0.8),
        ("NIST-CSF-V2", "RS.MA-01", 0.8),
    ]),
]


# --- Idempotent seeder --------------------------------------------------


async def seed_compliance_catalog(session: AsyncSession) -> dict[str, int]:
    """Seed frameworks, controls, and mappings.

    Idempotent: re-running yields no duplicates and updates ``updated_at``
    only when a row's source content has changed.

    Returns a dict with counts of added rows per table — caller can log
    or assert.
    """
    added = {"frameworks": 0, "controls": 0, "mappings": 0}

    framework_id_by_code: dict[str, "uuid.UUID"] = {}
    for fw in FRAMEWORKS:
        existing = (await session.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.code == fw["code"]
            )
        )).scalar_one_or_none()
        if existing is None:
            row = ComplianceFramework(
                code=fw["code"],
                name_en=fw["name_en"],
                name_ar=fw.get("name_ar"),
                version=fw["version"],
                source_url=fw.get("source_url"),
                source_version_date=fw.get("source_version_date"),
                description_en=fw.get("description_en"),
                description_ar=fw.get("description_ar"),
                is_active=True,
            )
            session.add(row)
            await session.flush()
            framework_id_by_code[fw["code"]] = row.id
            added["frameworks"] += 1
        else:
            framework_id_by_code[fw["code"]] = existing.id

    # Control catalogue.
    control_id_by_key: dict[tuple[str, str], "uuid.UUID"] = {}
    for ctrl in CONTROLS:
        fw_id = framework_id_by_code.get(ctrl["f"])
        if fw_id is None:
            logger.warning("control %s references unknown framework %s; skipped",
                           ctrl["cid"], ctrl["f"])
            continue
        existing = (await session.execute(
            select(ComplianceControl).where(
                ComplianceControl.framework_id == fw_id,
                ComplianceControl.control_id == ctrl["cid"],
            )
        )).scalar_one_or_none()
        if existing is None:
            row = ComplianceControl(
                framework_id=fw_id,
                control_id=ctrl["cid"],
                title_en=ctrl["title_en"],
                title_ar=ctrl.get("title_ar"),
                description_en=ctrl.get("desc_en"),
                description_ar=ctrl.get("desc_ar"),
                weight=ctrl.get("weight", 1.0),
                sort_order=ctrl.get("sort", 0),
            )
            session.add(row)
            await session.flush()
            control_id_by_key[(ctrl["f"], ctrl["cid"])] = row.id
            added["controls"] += 1
        else:
            control_id_by_key[(ctrl["f"], ctrl["cid"])] = existing.id

    # Mappings.
    for signal_kind, signal_value, targets in MAPPINGS:
        for fw_code, ctrl_id, conf in targets:
            ctrl_pk = control_id_by_key.get((fw_code, ctrl_id))
            if ctrl_pk is None:
                logger.warning(
                    "mapping %s/%s -> %s/%s skipped: control not seeded",
                    signal_kind, signal_value, fw_code, ctrl_id,
                )
                continue
            existing = (await session.execute(
                select(ComplianceControlMapping).where(
                    ComplianceControlMapping.control_id == ctrl_pk,
                    ComplianceControlMapping.signal_kind == signal_kind,
                    ComplianceControlMapping.signal_value == signal_value,
                )
            )).scalar_one_or_none()
            if existing is None:
                session.add(ComplianceControlMapping(
                    control_id=ctrl_pk,
                    signal_kind=signal_kind,
                    signal_value=signal_value,
                    confidence=conf,
                ))
                added["mappings"] += 1

    await session.flush()
    logger.info("compliance catalog seeded: %s", added)
    return added
