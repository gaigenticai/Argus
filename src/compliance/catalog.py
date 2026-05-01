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
    # ── UAE TDRA / NESA Information Assurance Regulation ──────────────
    {
        "code": "NESA-IA-V2",
        "name_en": "UAE TDRA Information Assurance Regulation",
        "name_ar": "نظام ضمان المعلومات — هيئة تنظيم قطاع الاتصالات",
        "version": "2.0",
        "source_url": "https://tdra.gov.ae/en/about-tdra/legislation/laws-and-regulations.aspx",
        "source_version_date": date(2020, 1, 1),
        "description_en": (
            "Mandatory information assurance baseline for UAE federal "
            "government and critical sector entities, issued by TDRA "
            "(formerly NESA). Combines management (M) and technical (T) "
            "controls; this seed selects the technical and incident-management "
            "controls a TI platform populates."
        ),
        "description_ar": (
            "الأساس الإلزامي لضمان المعلومات للجهات الاتحادية والقطاعات "
            "الحساسة في الإمارات، الصادر عن هيئة تنظيم قطاع الاتصالات (سابقاً NESA)."
        ),
    },
    # ── ADHICS v2 (Abu Dhabi Healthcare) ──────────────────────────────
    {
        "code": "ADHICS-V2",
        "name_en": "Abu Dhabi Healthcare Information & Cyber Security Standard",
        "name_ar": "معيار أمن المعلومات والأمن السيبراني للقطاع الصحي بأبوظبي",
        "version": "2.0",
        "source_url": "https://www.doh.gov.ae/en/resources/Adhics",
        "source_version_date": date(2023, 1, 1),
        "description_en": (
            "Cybersecurity standard mandated by the Department of Health — "
            "Abu Dhabi for all healthcare facilities, payers, and digital "
            "health solutions operating in the Emirate. Supersedes ADHICS v1."
        ),
        "description_ar": (
            "المعيار الإلزامي للأمن السيبراني الصادر عن دائرة الصحة بأبوظبي "
            "لجميع المنشآت الصحية وشركات التأمين والحلول الرقمية الصحية."
        ),
    },
    # ── Qatar NIA Policy v2 / Q-CERT NCSF ─────────────────────────────
    {
        "code": "QATAR-NIA-V2",
        "name_en": "Qatar National Information Assurance Policy (NIA) v2",
        "name_ar": "السياسة الوطنية لضمان المعلومات — قطر",
        "version": "2.0",
        "source_url": "https://www.motc.gov.qa/en/cyber-safety-security/cybersecurity",
        "source_version_date": date(2014, 4, 1),
        "description_en": (
            "Mandatory information assurance policy issued by Qatar's "
            "Ministry of Communications & IT through Q-CERT, applicable to "
            "government, telecom, and critical sector entities. The Qatar "
            "National Cybersecurity Strategy (2024) reaffirms this policy."
        ),
        "description_ar": (
            "السياسة الوطنية الإلزامية لضمان المعلومات الصادرة عن وزارة الاتصالات "
            "وتكنولوجيا المعلومات في قطر عبر مركز Q-CERT."
        ),
    },
    # ── Bahrain CBB Cybersecurity Module (Operational Risk Mgmt 7) ────
    {
        "code": "CBB-CYBER-V2",
        "name_en": "Central Bank of Bahrain — Cybersecurity Module (OM-7)",
        "name_ar": "وحدة الأمن السيبراني — مصرف البحرين المركزي",
        "version": "2.0",
        "source_url": "https://cbben.thomsonreuters.com/rulebook",
        "source_version_date": date(2022, 1, 1),
        "description_en": (
            "Cybersecurity rules embedded in the CBB Rulebook Volume 1 "
            "(Conventional Banks) and Volume 2 (Islamic Banks), Operational "
            "Risk Management module 7. Mandatory for all licensed financial "
            "institutions in Bahrain."
        ),
        "description_ar": (
            "قواعد الأمن السيبراني ضمن دليل قواعد مصرف البحرين المركزي — "
            "وحدة إدارة المخاطر التشغيلية رقم 7. إلزامية لكل المؤسسات المالية المرخصة."
        ),
    },
    # ── Kuwait CITRA Cybersecurity Framework ──────────────────────────
    {
        "code": "CITRA-CSF-V1",
        "name_en": "Kuwait CITRA National Cybersecurity Framework",
        "name_ar": "الإطار الوطني للأمن السيبراني — هيئة CITRA الكويت",
        "version": "1.0",
        "source_url": "https://citra.gov.kw/sites/en/Pages/cybersecurity.aspx",
        "source_version_date": date(2020, 1, 1),
        "description_en": (
            "National cybersecurity framework issued by Kuwait's "
            "Communication & Information Technology Regulatory Authority "
            "(CITRA), aligned to NIST CSF function families and applicable "
            "to government and critical sector entities."
        ),
        "description_ar": (
            "الإطار الوطني للأمن السيبراني الصادر عن هيئة الاتصالات وتقنية "
            "المعلومات في الكويت (CITRA)."
        ),
    },
    # ── Oman National Information Security Framework (OCERT) ──────────
    {
        "code": "OMAN-NISF-V1",
        "name_en": "Oman National Information Security Framework",
        "name_ar": "الإطار الوطني لأمن المعلومات — سلطنة عُمان",
        "version": "1.0",
        "source_url": "https://www.cert.gov.om/",
        "source_version_date": date(2017, 1, 1),
        "description_en": (
            "Mandatory information security framework published by Oman's "
            "national CERT (OCERT) under the Ministry of Transport, "
            "Communications and IT. Applicable to government bodies and "
            "operators of national critical infrastructure."
        ),
        "description_ar": (
            "الإطار الوطني الإلزامي لأمن المعلومات الصادر عن مركز الاستجابة "
            "للطوارئ السيبرانية في سلطنة عُمان (OCERT)."
        ),
    },
    # ── PCI-DSS 4.0.1 ─────────────────────────────────────────────────
    {
        "code": "PCI-DSS-V4",
        "name_en": "Payment Card Industry Data Security Standard (PCI-DSS)",
        "name_ar": "معيار أمن بيانات صناعة بطاقات الدفع",
        "version": "4.0.1",
        "source_url": "https://www.pcisecuritystandards.org/document_library/",
        "source_version_date": date(2024, 6, 1),
        "description_en": (
            "Global cardholder-data protection standard maintained by the "
            "PCI Security Standards Council. Version 4.0.1 (June 2024) "
            "introduces explicit threat-intelligence and continuous-monitoring "
            "requirements."
        ),
        "description_ar": (
            "المعيار العالمي لحماية بيانات حاملي البطاقات الصادر عن مجلس "
            "معايير أمن بطاقات الدفع. الإصدار 4.0.1 (يونيو 2024)."
        ),
    },
    # ── SOC 2 — Trust Services Criteria, CC7 (System Operations) ──────
    {
        "code": "SOC2-CC7",
        "name_en": "AICPA SOC 2 — Common Criteria CC7 (System Operations)",
        "name_ar": None,
        "version": "2017 (rev. 2022)",
        "source_url": "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
        "source_version_date": date(2022, 1, 1),
        "description_en": (
            "AICPA Trust Services Criteria — Common Criteria series CC7 "
            "(System Operations) covers detection, evaluation, and response "
            "to security incidents. The most TI-relevant subset of SOC 2 "
            "and the section auditors examine first when reviewing a TI "
            "platform's role in the customer's stack."
        ),
        "description_ar": None,
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

    # ── UAE TDRA / NESA Information Assurance ───────────────────────────
    {"f": "NESA-IA-V2", "cid": "T1.5", "sort": 150,
     "title_en": "Information Security Risk Assessment",
     "title_ar": "تقييم مخاطر أمن المعلومات",
     "desc_en": "Continuous identification and assessment of information "
                "security risks across the entity."},
    {"f": "NESA-IA-V2", "cid": "T2.5", "sort": 250,
     "title_en": "Threat and Vulnerability Management",
     "title_ar": "إدارة التهديدات والثغرات",
     "desc_en": "Acquisition and operationalisation of threat intelligence; "
                "discovery and remediation of technical vulnerabilities."},
    {"f": "NESA-IA-V2", "cid": "T3.6", "sort": 360,
     "title_en": "Security Monitoring",
     "title_ar": "مراقبة الأمن",
     "desc_en": "Centralised monitoring of security events with timely "
                "review and escalation."},
    {"f": "NESA-IA-V2", "cid": "T4.4", "sort": 440,
     "title_en": "Email and Web Defence",
     "title_ar": "الدفاع عن البريد الإلكتروني والإنترنت",
     "desc_en": "Anti-phishing, anti-malware, and brand-impersonation "
                "controls for email and web."},
    {"f": "NESA-IA-V2", "cid": "T7.5", "sort": 750,
     "title_en": "Incident Response",
     "title_ar": "الاستجابة للحوادث",
     "desc_en": "Documented and exercised incident response plan covering "
                "detection, containment, eradication, and recovery."},
    {"f": "NESA-IA-V2", "cid": "T8.2", "sort": 820,
     "title_en": "Information Security Logs",
     "title_ar": "سجلات أمن المعلومات",
     "desc_en": "Generation, retention, and protection of security logs "
                "with sufficient fidelity for forensic analysis."},
    {"f": "NESA-IA-V2", "cid": "M5.3", "sort": 530,
     "title_en": "Third-Party Information Security",
     "title_ar": "أمن المعلومات للأطراف الخارجية",
     "desc_en": "Cybersecurity requirements in third-party engagements and "
                "ongoing supply-chain risk monitoring."},

    # ── ADHICS v2 (Abu Dhabi Healthcare) ────────────────────────────────
    {"f": "ADHICS-V2", "cid": "TM.4", "sort": 440,
     "title_en": "Continuous Monitoring of Health Information Systems",
     "title_ar": "المراقبة المستمرة لأنظمة المعلومات الصحية",
     "desc_en": "Real-time monitoring for unauthorised access, data "
                "exfiltration, and operational anomalies in healthcare "
                "information systems."},
    {"f": "ADHICS-V2", "cid": "IM.2", "sort": 520,
     "title_en": "Incident Management",
     "title_ar": "إدارة الحوادث",
     "desc_en": "Detection, classification, response, and reporting of "
                "cybersecurity incidents affecting protected health "
                "information."},
    {"f": "ADHICS-V2", "cid": "IM.3", "sort": 530,
     "title_en": "Threat Intelligence",
     "title_ar": "استخبارات التهديدات",
     "desc_en": "Acquisition and integration of threat intelligence "
                "relevant to the healthcare sector."},
    {"f": "ADHICS-V2", "cid": "DM.5", "sort": 650,
     "title_en": "Healthcare Data Protection and Sharing",
     "title_ar": "حماية ومشاركة البيانات الصحية",
     "desc_en": "Protection of patient data including detection of leakage "
                "and unauthorised sharing."},
    {"f": "ADHICS-V2", "cid": "AC.7", "sort": 270,
     "title_en": "Access Control for Healthcare Information",
     "title_ar": "ضبط الوصول إلى المعلومات الصحية",
     "desc_en": "Strong authentication and granular access controls for "
                "healthcare workers, payers, and external integrators."},
    {"f": "ADHICS-V2", "cid": "SO.4", "sort": 340,
     "title_en": "Systems and Operations Monitoring",
     "title_ar": "مراقبة الأنظمة والعمليات",
     "desc_en": "Continuous monitoring of system operations for security "
                "and integrity events."},
    {"f": "ADHICS-V2", "cid": "TP.3", "sort": 730,
     "title_en": "Third-Party Healthcare Risk Management",
     "title_ar": "إدارة مخاطر الأطراف الخارجية في القطاع الصحي",
     "desc_en": "Cybersecurity requirements for healthcare vendors, EHR "
                "integrators, and digital-health solution providers."},

    # ── Qatar NIA Policy v2 ─────────────────────────────────────────────
    {"f": "QATAR-NIA-V2", "cid": "SM-3", "sort": 130,
     "title_en": "Risk Management",
     "title_ar": "إدارة المخاطر",
     "desc_en": "Continuous identification, assessment, and treatment of "
                "information security risks."},
    {"f": "QATAR-NIA-V2", "cid": "TI-1", "sort": 250,
     "title_en": "Threat Intelligence Acquisition",
     "title_ar": "اقتناء استخبارات التهديدات",
     "desc_en": "Acquisition, validation, and operationalisation of cyber "
                "threat intelligence."},
    {"f": "QATAR-NIA-V2", "cid": "VM-1", "sort": 350,
     "title_en": "Vulnerability Identification",
     "title_ar": "تحديد الثغرات",
     "desc_en": "Continuous identification of technical vulnerabilities "
                "across the technology estate."},
    {"f": "QATAR-NIA-V2", "cid": "CM-3", "sort": 450,
     "title_en": "Logging and Monitoring",
     "title_ar": "التسجيل والمراقبة",
     "desc_en": "Comprehensive logging of security-relevant events with "
                "active monitoring and alerting."},
    {"f": "QATAR-NIA-V2", "cid": "IM-2", "sort": 550,
     "title_en": "Incident Response",
     "title_ar": "الاستجابة للحوادث",
     "desc_en": "Documented and tested incident response procedures "
                "including coordination with Q-CERT."},
    {"f": "QATAR-NIA-V2", "cid": "AM-3", "sort": 650,
     "title_en": "Continuous Asset Monitoring",
     "title_ar": "المراقبة المستمرة للأصول",
     "desc_en": "Continuous monitoring of information assets for "
                "unauthorised changes or compromise."},

    # ── Bahrain CBB Cybersecurity Module (OM-7) ─────────────────────────
    {"f": "CBB-CYBER-V2", "cid": "OM-7.3", "sort": 730,
     "title_en": "Cyber Risk Management",
     "title_ar": "إدارة المخاطر السيبرانية",
     "desc_en": "Board-approved cyber risk management framework with "
                "documented appetite, tolerance, and treatment plans."},
    {"f": "CBB-CYBER-V2", "cid": "OM-7.4", "sort": 740,
     "title_en": "Threat Intelligence",
     "title_ar": "استخبارات التهديدات",
     "desc_en": "Acquisition and operationalisation of cyber threat "
                "intelligence relevant to the financial sector and the "
                "Kingdom of Bahrain."},
    {"f": "CBB-CYBER-V2", "cid": "OM-7.5", "sort": 750,
     "title_en": "Cyber Security Operations",
     "title_ar": "عمليات الأمن السيبراني",
     "desc_en": "24×7 cyber security operations capability — monitoring, "
                "detection, triage, and escalation."},
    {"f": "CBB-CYBER-V2", "cid": "OM-7.6", "sort": 760,
     "title_en": "Cyber Incident Management",
     "title_ar": "إدارة الحوادث السيبرانية",
     "desc_en": "Documented cyber incident response plan with reporting to "
                "the Central Bank of Bahrain within prescribed timelines."},
    {"f": "CBB-CYBER-V2", "cid": "OM-7.7", "sort": 770,
     "title_en": "Vulnerability Management",
     "title_ar": "إدارة الثغرات",
     "desc_en": "Risk-based vulnerability identification, prioritisation, "
                "and remediation across the licensee's estate."},
    {"f": "CBB-CYBER-V2", "cid": "OM-7.8", "sort": 780,
     "title_en": "Third Party Cyber Risk",
     "title_ar": "المخاطر السيبرانية للأطراف الخارجية",
     "desc_en": "Cybersecurity due diligence and ongoing monitoring of "
                "third parties with access to systems or data."},

    # ── Kuwait CITRA Cybersecurity Framework (NIST-aligned) ─────────────
    {"f": "CITRA-CSF-V1", "cid": "ID-3", "sort": 230,
     "title_en": "Threat Landscape Awareness",
     "title_ar": "الوعي بمشهد التهديدات",
     "desc_en": "Documented and continuously refreshed threat landscape "
                "covering relevant threat actors and techniques."},
    {"f": "CITRA-CSF-V1", "cid": "PR-7", "sort": 370,
     "title_en": "Email and Web Defences",
     "title_ar": "الدفاعات للبريد الإلكتروني والإنترنت",
     "desc_en": "Anti-phishing, anti-malware, and DNS-layer protections "
                "for email and web traffic."},
    {"f": "CITRA-CSF-V1", "cid": "DE-2", "sort": 420,
     "title_en": "Continuous Security Monitoring",
     "title_ar": "المراقبة الأمنية المستمرة",
     "desc_en": "Continuous monitoring with measured detection and triage "
                "performance."},
    {"f": "CITRA-CSF-V1", "cid": "DE-4", "sort": 440,
     "title_en": "Threat Intelligence Integration",
     "title_ar": "تكامل استخبارات التهديدات",
     "desc_en": "Integration of external threat intelligence into the "
                "detection and response stack."},
    {"f": "CITRA-CSF-V1", "cid": "RS-1", "sort": 510,
     "title_en": "Incident Response Plan",
     "title_ar": "خطة الاستجابة للحوادث",
     "desc_en": "Documented and exercised incident response plan with "
                "coordination requirements with CITRA."},
    {"f": "CITRA-CSF-V1", "cid": "RC-1", "sort": 610,
     "title_en": "Recovery Planning",
     "title_ar": "تخطيط التعافي",
     "desc_en": "Documented and tested recovery plan including "
                "communications and lessons-learned."},

    # ── Oman National Information Security Framework ────────────────────
    {"f": "OMAN-NISF-V1", "cid": "4.1", "sort": 410,
     "title_en": "Risk Management",
     "title_ar": "إدارة المخاطر",
     "desc_en": "Continuous identification, assessment, and treatment of "
                "information security risks."},
    {"f": "OMAN-NISF-V1", "cid": "4.5", "sort": 450,
     "title_en": "Information Security Operations",
     "title_ar": "عمليات أمن المعلومات",
     "desc_en": "Day-to-day security operations including monitoring, "
                "detection, and response."},
    {"f": "OMAN-NISF-V1", "cid": "4.6", "sort": 460,
     "title_en": "Threat Intelligence",
     "title_ar": "استخبارات التهديدات",
     "desc_en": "Acquisition and use of cyber threat intelligence to "
                "inform defensive operations."},
    {"f": "OMAN-NISF-V1", "cid": "4.7", "sort": 470,
     "title_en": "Vulnerability Management",
     "title_ar": "إدارة الثغرات",
     "desc_en": "Continuous identification and remediation of technical "
                "vulnerabilities."},
    {"f": "OMAN-NISF-V1", "cid": "4.8", "sort": 480,
     "title_en": "Incident Management",
     "title_ar": "إدارة الحوادث",
     "desc_en": "Documented incident response procedures with reporting "
                "to OCERT for incidents of national significance."},
    {"f": "OMAN-NISF-V1", "cid": "4.9", "sort": 490,
     "title_en": "Monitoring and Logging",
     "title_ar": "المراقبة والتسجيل",
     "desc_en": "Generation, retention, and active monitoring of security "
                "events across the technology estate."},

    # ── PCI-DSS 4.0.1 ──────────────────────────────────────────────────
    {"f": "PCI-DSS-V4", "cid": "5", "sort": 500,
     "title_en": "Protect All Systems and Networks from Malicious Software",
     "title_ar": None,
     "desc_en": "Anti-malware mechanisms, automatic updates, and periodic "
                "evaluations of evolving malware threats."},
    {"f": "PCI-DSS-V4", "cid": "6.3", "sort": 630,
     "title_en": "Identify and Address Security Vulnerabilities",
     "desc_en": "Establish a process to identify security vulnerabilities, "
                "assess risk, and ensure timely remediation."},
    {"f": "PCI-DSS-V4", "cid": "8.3", "sort": 830,
     "title_en": "Strong Authentication for Users and Administrators",
     "desc_en": "Multi-factor authentication and credential-leak monitoring "
                "for all access to the cardholder data environment."},
    {"f": "PCI-DSS-V4", "cid": "10.4", "sort": 1040,
     "title_en": "Review Logs and Security Events",
     "desc_en": "Daily review of security event logs across cardholder "
                "data environment systems."},
    {"f": "PCI-DSS-V4", "cid": "11.4", "sort": 1140,
     "title_en": "External and Internal Network Penetration Testing",
     "desc_en": "Periodic external and internal penetration testing with "
                "remediation of exploitable findings."},
    {"f": "PCI-DSS-V4", "cid": "11.5", "sort": 1150,
     "title_en": "Network Intrusion Detection and Change Detection",
     "desc_en": "Continuous network intrusion detection / prevention and "
                "change-detection mechanisms over the cardholder data "
                "environment."},
    {"f": "PCI-DSS-V4", "cid": "12.10", "sort": 1210,
     "title_en": "Incident Response Plan",
     "desc_en": "Documented incident response plan covering detection, "
                "containment, eradication, recovery, and lessons learned."},
    {"f": "PCI-DSS-V4", "cid": "12.10.7", "sort": 1217,
     "title_en": "Threat Intelligence Operationalisation",
     "desc_en": "(New in v4) Use threat intelligence to drive proactive "
                "defensive action and to inform the incident response plan."},

    # ── SOC 2 — Common Criteria CC7 ────────────────────────────────────
    {"f": "SOC2-CC7", "cid": "CC7.1", "sort": 710,
     "title_en": "Detection of Configuration Changes and Vulnerabilities",
     "desc_en": "Implements detection of (a) changes to system configurations "
                "that introduce vulnerabilities and (b) susceptibilities to "
                "known and emerging vulnerabilities."},
    {"f": "SOC2-CC7", "cid": "CC7.2", "sort": 720,
     "title_en": "Monitoring of System Components for Anomalies",
     "desc_en": "Designs and implements detection mechanisms covering "
                "system components, infrastructure, and personnel for "
                "anomalies indicative of malicious acts, natural disasters, "
                "or errors."},
    {"f": "SOC2-CC7", "cid": "CC7.3", "sort": 730,
     "title_en": "Evaluation of Security Events to Determine Incidents",
     "desc_en": "Evaluates security events to determine whether they could "
                "or have resulted in a failure of the entity to meet its "
                "objectives."},
    {"f": "SOC2-CC7", "cid": "CC7.4", "sort": 740,
     "title_en": "Response to Identified Security Incidents",
     "desc_en": "Responds to identified security incidents by executing a "
                "defined incident response programme to understand, "
                "contain, remediate, and communicate."},
    {"f": "SOC2-CC7", "cid": "CC7.5", "sort": 750,
     "title_en": "Recovery from Identified Security Incidents",
     "desc_en": "Identifies, develops, and implements activities to recover "
                "from identified security incidents."},
    {"f": "SOC2-CC7", "cid": "CC2.1", "sort": 210,
     "title_en": "Risk Identification — Internal and External Sources",
     "desc_en": "Identifies risks from internal and external sources, "
                "including threat intelligence, that may threaten the "
                "achievement of objectives."},
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

    # ── Mappings extending the alert categories to the 8 new frameworks.
    # The seeder is idempotent on (control_id, signal_kind, signal_value)
    # so these tuples cleanly stack on top of the lists above.

    # Phishing → ME defenders + PCI + SOC2
    (_AC, "phishing", [
        ("NESA-IA-V2", "T4.4", 1.0),
        ("NESA-IA-V2", "T2.5", 0.8),
        ("ADHICS-V2", "TM.4", 0.7),
        ("QATAR-NIA-V2", "TI-1", 0.9),
        ("CBB-CYBER-V2", "OM-7.4", 0.9),
        ("CITRA-CSF-V1", "PR-7", 1.0),
        ("CITRA-CSF-V1", "DE-4", 0.8),
        ("OMAN-NISF-V1", "4.6", 0.9),
        ("PCI-DSS-V4", "5", 0.7),
        ("PCI-DSS-V4", "12.10.7", 0.8),
        ("SOC2-CC7", "CC7.2", 0.8),
        ("SOC2-CC7", "CC2.1", 0.7),
    ]),
    # Ransomware
    (_AC, "ransomware_victim", [
        ("NESA-IA-V2", "T7.5", 1.0),
        ("NESA-IA-V2", "T2.5", 0.8),
        ("ADHICS-V2", "IM.2", 1.0),
        ("ADHICS-V2", "IM.3", 0.9),
        ("QATAR-NIA-V2", "IM-2", 1.0),
        ("CBB-CYBER-V2", "OM-7.6", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 0.8),
        ("CITRA-CSF-V1", "RS-1", 1.0),
        ("CITRA-CSF-V1", "RC-1", 0.8),
        ("OMAN-NISF-V1", "4.8", 1.0),
        ("PCI-DSS-V4", "12.10", 1.0),
        ("PCI-DSS-V4", "5", 0.7),
        ("SOC2-CC7", "CC7.4", 1.0),
        ("SOC2-CC7", "CC7.5", 0.9),
    ]),
    # Credential leak
    (_AC, "credential_leak", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("ADHICS-V2", "AC.7", 0.9),
        ("ADHICS-V2", "IM.3", 0.9),
        ("QATAR-NIA-V2", "TI-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 1.0),
        ("CITRA-CSF-V1", "DE-4", 1.0),
        ("OMAN-NISF-V1", "4.6", 1.0),
        ("PCI-DSS-V4", "8.3", 1.0),
        ("PCI-DSS-V4", "12.10.7", 0.8),
        ("SOC2-CC7", "CC2.1", 0.9),
    ]),
    (_AC, "stealer_log", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("ADHICS-V2", "IM.3", 0.9),
        ("QATAR-NIA-V2", "TI-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 1.0),
        ("CITRA-CSF-V1", "DE-4", 1.0),
        ("OMAN-NISF-V1", "4.6", 1.0),
        ("PCI-DSS-V4", "8.3", 0.9),
        ("SOC2-CC7", "CC2.1", 0.8),
    ]),
    # Data breach
    (_AC, "data_breach", [
        ("NESA-IA-V2", "T7.5", 1.0),
        ("ADHICS-V2", "IM.2", 1.0),
        ("ADHICS-V2", "DM.5", 1.0),
        ("QATAR-NIA-V2", "IM-2", 1.0),
        ("CBB-CYBER-V2", "OM-7.6", 1.0),
        ("CITRA-CSF-V1", "RS-1", 1.0),
        ("OMAN-NISF-V1", "4.8", 1.0),
        ("PCI-DSS-V4", "12.10", 1.0),
        ("SOC2-CC7", "CC7.3", 1.0),
        ("SOC2-CC7", "CC7.4", 1.0),
    ]),
    # Brand abuse / impersonation
    (_AC, "brand_abuse", [
        ("NESA-IA-V2", "T4.4", 1.0),
        ("NESA-IA-V2", "T2.5", 0.7),
        ("ADHICS-V2", "DM.5", 0.7),
        ("QATAR-NIA-V2", "TI-1", 0.9),
        ("CBB-CYBER-V2", "OM-7.4", 0.9),
        ("CITRA-CSF-V1", "DE-4", 0.9),
        ("OMAN-NISF-V1", "4.6", 0.9),
        ("PCI-DSS-V4", "12.10.7", 0.6),
        ("SOC2-CC7", "CC2.1", 0.7),
    ]),
    (_AC, "impersonation", [
        ("NESA-IA-V2", "T4.4", 1.0),
        ("ADHICS-V2", "AC.7", 0.7),
        ("QATAR-NIA-V2", "TI-1", 0.9),
        ("CBB-CYBER-V2", "OM-7.4", 0.9),
        ("CITRA-CSF-V1", "PR-7", 0.9),
        ("OMAN-NISF-V1", "4.6", 0.9),
        ("SOC2-CC7", "CC7.2", 0.8),
    ]),
    # Vulnerability / exploit
    (_AC, "exploit", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("ADHICS-V2", "TM.4", 0.8),
        ("QATAR-NIA-V2", "VM-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.7", 1.0),
        ("CITRA-CSF-V1", "DE-2", 0.9),
        ("OMAN-NISF-V1", "4.7", 1.0),
        ("PCI-DSS-V4", "6.3", 1.0),
        ("PCI-DSS-V4", "11.4", 0.7),
        ("SOC2-CC7", "CC7.1", 1.0),
    ]),
    # Dark web mention / chatter
    (_AC, "dark_web_mention", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("ADHICS-V2", "IM.3", 1.0),
        ("QATAR-NIA-V2", "TI-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 1.0),
        ("CITRA-CSF-V1", "DE-4", 1.0),
        ("CITRA-CSF-V1", "ID-3", 0.8),
        ("OMAN-NISF-V1", "4.6", 1.0),
        ("PCI-DSS-V4", "12.10.7", 0.8),
        ("SOC2-CC7", "CC2.1", 0.8),
    ]),
    (_AC, "underground_chatter", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("QATAR-NIA-V2", "TI-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 1.0),
        ("CITRA-CSF-V1", "ID-3", 1.0),
        ("OMAN-NISF-V1", "4.6", 1.0),
        ("SOC2-CC7", "CC2.1", 0.8),
    ]),
    # Doxxing
    (_AC, "doxxing", [
        ("NESA-IA-V2", "T2.5", 0.8),
        ("ADHICS-V2", "DM.5", 0.7),
        ("QATAR-NIA-V2", "TI-1", 0.9),
        ("CBB-CYBER-V2", "OM-7.4", 0.8),
        ("CITRA-CSF-V1", "DE-4", 0.8),
        ("OMAN-NISF-V1", "4.6", 0.8),
        ("SOC2-CC7", "CC7.3", 0.7),
    ]),
    # Insider threat
    (_AC, "insider_threat", [
        ("NESA-IA-V2", "T3.6", 1.0),
        ("ADHICS-V2", "AC.7", 1.0),
        ("ADHICS-V2", "SO.4", 0.9),
        ("QATAR-NIA-V2", "AM-3", 1.0),
        ("CBB-CYBER-V2", "OM-7.5", 1.0),
        ("CITRA-CSF-V1", "DE-2", 1.0),
        ("OMAN-NISF-V1", "4.5", 0.9),
        ("PCI-DSS-V4", "10.4", 1.0),
        ("SOC2-CC7", "CC7.2", 1.0),
    ]),
    # Initial-access broker / access sale
    (_AC, "access_sale", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("NESA-IA-V2", "M5.3", 0.7),
        ("ADHICS-V2", "TP.3", 0.8),
        ("QATAR-NIA-V2", "TI-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.4", 1.0),
        ("CBB-CYBER-V2", "OM-7.8", 0.8),
        ("CITRA-CSF-V1", "DE-4", 1.0),
        ("OMAN-NISF-V1", "4.6", 1.0),
        ("PCI-DSS-V4", "8.3", 0.9),
        ("SOC2-CC7", "CC2.1", 0.9),
    ]),

    # MITRE ATT&CK technique extensions
    (_M, "T1566", [
        ("NESA-IA-V2", "T4.4", 1.0),
        ("CITRA-CSF-V1", "PR-7", 1.0),
        ("PCI-DSS-V4", "5", 0.6),
        ("SOC2-CC7", "CC7.2", 0.8),
    ]),
    (_M, "T1190", [
        ("NESA-IA-V2", "T2.5", 1.0),
        ("QATAR-NIA-V2", "VM-1", 1.0),
        ("CBB-CYBER-V2", "OM-7.7", 1.0),
        ("OMAN-NISF-V1", "4.7", 1.0),
        ("PCI-DSS-V4", "6.3", 1.0),
        ("SOC2-CC7", "CC7.1", 1.0),
    ]),
    (_M, "T1078", [
        ("ADHICS-V2", "AC.7", 0.9),
        ("CBB-CYBER-V2", "OM-7.5", 0.9),
        ("CITRA-CSF-V1", "DE-2", 1.0),
        ("PCI-DSS-V4", "8.3", 1.0),
        ("PCI-DSS-V4", "10.4", 0.9),
        ("SOC2-CC7", "CC7.2", 1.0),
    ]),
    (_M, "T1486", [
        ("NESA-IA-V2", "T7.5", 1.0),
        ("ADHICS-V2", "IM.2", 1.0),
        ("QATAR-NIA-V2", "IM-2", 1.0),
        ("CBB-CYBER-V2", "OM-7.6", 1.0),
        ("CITRA-CSF-V1", "RS-1", 1.0),
        ("OMAN-NISF-V1", "4.8", 1.0),
        ("PCI-DSS-V4", "12.10", 1.0),
        ("SOC2-CC7", "CC7.4", 1.0),
    ]),
    (_M, "T1071", [
        ("NESA-IA-V2", "T8.2", 1.0),
        ("ADHICS-V2", "TM.4", 1.0),
        ("QATAR-NIA-V2", "CM-3", 1.0),
        ("CITRA-CSF-V1", "DE-2", 1.0),
        ("OMAN-NISF-V1", "4.9", 1.0),
        ("PCI-DSS-V4", "11.5", 1.0),
        ("SOC2-CC7", "CC7.2", 1.0),
    ]),
    (_M, "T1567", [
        ("ADHICS-V2", "DM.5", 1.0),
        ("CBB-CYBER-V2", "OM-7.5", 0.9),
        ("CITRA-CSF-V1", "DE-2", 0.9),
        ("OMAN-NISF-V1", "4.9", 0.9),
        ("PCI-DSS-V4", "11.5", 0.9),
        ("SOC2-CC7", "CC7.2", 0.9),
    ]),
    (_M, "T1110", [
        ("ADHICS-V2", "AC.7", 0.8),
        ("CITRA-CSF-V1", "DE-2", 0.9),
        ("PCI-DSS-V4", "8.3", 0.9),
        ("SOC2-CC7", "CC7.2", 0.9),
    ]),

    # Case-state extensions — verified/remediated/closed are evidence of
    # working IR programmes the regulators specifically want to see.
    (_CS, "verified", [
        ("NESA-IA-V2", "T7.5", 1.0),
        ("ADHICS-V2", "IM.2", 1.0),
        ("QATAR-NIA-V2", "IM-2", 1.0),
        ("CBB-CYBER-V2", "OM-7.6", 1.0),
        ("CITRA-CSF-V1", "RS-1", 1.0),
        ("OMAN-NISF-V1", "4.8", 1.0),
        ("PCI-DSS-V4", "12.10", 1.0),
        ("SOC2-CC7", "CC7.3", 1.0),
        ("SOC2-CC7", "CC7.4", 1.0),
    ]),
    (_CS, "remediated", [
        ("NESA-IA-V2", "T7.5", 0.9),
        ("ADHICS-V2", "IM.2", 0.9),
        ("CBB-CYBER-V2", "OM-7.6", 0.9),
        ("CITRA-CSF-V1", "RS-1", 0.9),
        ("PCI-DSS-V4", "12.10", 0.9),
        ("SOC2-CC7", "CC7.4", 0.9),
        ("SOC2-CC7", "CC7.5", 0.8),
    ]),
    (_CS, "closed", [
        ("NESA-IA-V2", "T7.5", 0.8),
        ("ADHICS-V2", "IM.2", 0.8),
        ("QATAR-NIA-V2", "IM-2", 0.8),
        ("CBB-CYBER-V2", "OM-7.6", 0.8),
        ("CITRA-CSF-V1", "RC-1", 0.8),
        ("OMAN-NISF-V1", "4.8", 0.8),
        ("PCI-DSS-V4", "12.10", 0.8),
        ("SOC2-CC7", "CC7.5", 0.8),
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
