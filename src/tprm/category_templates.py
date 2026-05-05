"""Category-specific question additions on top of the base SIG/CAIQ template.

We don't replace the base template — we add a few category-specific
required questions that the analyst can roll into their custom template.
The TPRM auto-fill agent uses these so the LLM knows which questions to
prioritise when building a draft from public posture.
"""
from __future__ import annotations

from src.models.tprm import VendorCategory


_PAYMENT_PROCESSOR = [
    {
        "id": "pci_dss_compliance_level",
        "text": "What is your PCI DSS compliance level (Level 1-4) and the date of your most recent ROC/SAQ?",
        "answer_kind": "free_text",
        "weight": 5,
        "required": True,
    },
    {
        "id": "tokenization_for_pan",
        "text": "Are PANs tokenised before storage and never returned in API responses?",
        "answer_kind": "yes_no_na",
        "weight": 5,
        "required": True,
    },
    {
        "id": "fraud_loss_reporting",
        "text": "What is your monthly fraud loss rate and how do you communicate it to merchants?",
        "answer_kind": "free_text",
        "weight": 3,
        "required": False,
    },
]

_CLOUD_PROVIDER = [
    {
        "id": "soc2_type2_current",
        "text": "Do you have a SOC 2 Type II report dated within the past 12 months?",
        "answer_kind": "evidence",
        "weight": 5,
        "required": True,
    },
    {
        "id": "data_residency_options",
        "text": "Which regions can customers pin data residency to?",
        "answer_kind": "free_text",
        "weight": 4,
        "required": True,
    },
    {
        "id": "shared_responsibility_doc",
        "text": "Provide a link to your shared-responsibility model documentation.",
        "answer_kind": "evidence",
        "weight": 3,
        "required": True,
    },
]

_SECURITY_VENDOR = [
    {
        "id": "third_party_pen_test",
        "text": "Date of your most recent independent penetration test and a summary of remediation status.",
        "answer_kind": "free_text",
        "weight": 5,
        "required": True,
    },
    {
        "id": "vuln_disclosure_program",
        "text": "Do you operate a public vulnerability disclosure / bug-bounty programme?",
        "answer_kind": "yes_no",
        "weight": 4,
        "required": True,
    },
]

_HR_PAYROLL = [
    {
        "id": "background_check_policy",
        "text": "Describe background-check controls for staff with access to client PII.",
        "answer_kind": "free_text",
        "weight": 4,
        "required": True,
    },
    {
        "id": "iso_27701_certified",
        "text": "Are you ISO 27701 / privacy-management certified?",
        "answer_kind": "yes_no",
        "weight": 3,
        "required": False,
    },
]

_TELECOM = [
    {
        "id": "lawful_intercept_disclosure",
        "text": "Disclose all jurisdictions in which you may receive lawful-intercept requests.",
        "answer_kind": "free_text",
        "weight": 4,
        "required": True,
    },
]

_LEGAL = [
    {
        "id": "data_protection_addendum",
        "text": "Provide your standard DPA / processing-agreement template.",
        "answer_kind": "evidence",
        "weight": 4,
        "required": True,
    },
]

_AUDITOR = [
    {
        "id": "audit_independence_statement",
        "text": "Confirm independence from any in-scope audit subject and provide your latest peer review.",
        "answer_kind": "evidence",
        "weight": 4,
        "required": True,
    },
]

_MARKETING_SAAS = [
    {
        "id": "data_minimisation_policy",
        "text": "What customer fields are stored beyond what's required for the marketing function?",
        "answer_kind": "free_text",
        "weight": 3,
        "required": False,
    },
]

_DATA_BROKER = [
    {
        "id": "consent_chain_proof",
        "text": "Provide proof of consent chain back to the original collector for any list you sell.",
        "answer_kind": "evidence",
        "weight": 5,
        "required": True,
    },
]


_ADDITIONS_BY_CATEGORY: dict[str, list[dict]] = {
    VendorCategory.PAYMENT_PROCESSOR.value: _PAYMENT_PROCESSOR,
    VendorCategory.CLOUD_PROVIDER.value: _CLOUD_PROVIDER,
    VendorCategory.SECURITY_VENDOR.value: _SECURITY_VENDOR,
    VendorCategory.HR_PAYROLL.value: _HR_PAYROLL,
    VendorCategory.TELECOM.value: _TELECOM,
    VendorCategory.LEGAL.value: _LEGAL,
    VendorCategory.AUDITOR.value: _AUDITOR,
    VendorCategory.MARKETING_SAAS.value: _MARKETING_SAAS,
    VendorCategory.DATA_BROKER.value: _DATA_BROKER,
}


def category_additions(category: str | None) -> list[dict]:
    if not category:
        return []
    return list(_ADDITIONS_BY_CATEGORY.get(category, []))


def merge_with_base(
    base_questions: list[dict], category: str | None
) -> list[dict]:
    additions = category_additions(category)
    if not additions:
        return list(base_questions)
    seen_ids = {q.get("id") for q in base_questions}
    merged = list(base_questions)
    for q in additions:
        if q["id"] not in seen_ids:
            merged.append(q)
    return merged


__all__ = ["category_additions", "merge_with_base"]
