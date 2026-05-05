"""Asset Registry — type-specific schemas, enums, and validation.

The Asset table stores polymorphic external entities monitored by Argus:
domains, IPs, executives, brands, mobile apps, social handles, vendors, etc.

Type-specific structured data lives in `Asset.details` (JSONB). This module
defines the Pydantic schemas that validate that JSONB per asset type, plus
the enums used for asset_type, criticality, and discovery_method.

Production-grade from day one — every schema is strict, every enum is closed,
every required field is validated.
"""

from __future__ import annotations

import enum
import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator


# --- Enums ---------------------------------------------------------------


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    SERVICE = "service"  # host:port
    EMAIL_DOMAIN = "email_domain"
    EXECUTIVE = "executive"
    BRAND = "brand"
    MOBILE_APP = "mobile_app"
    SOCIAL_HANDLE = "social_handle"
    VENDOR = "vendor"
    CODE_REPOSITORY = "code_repository"
    CLOUD_ACCOUNT = "cloud_account"


class AssetCriticality(str, enum.Enum):
    CROWN_JEWEL = "crown_jewel"  # losing this is existential
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DiscoveryMethod(str, enum.Enum):
    MANUAL = "manual"
    BULK_IMPORT = "bulk_import"
    ONBOARDING_WIZARD = "onboarding_wizard"
    EASM_DISCOVERY = "easm_discovery"
    DNS_ENUMERATION = "dns_enumeration"
    CERT_TRANSPARENCY = "cert_transparency"
    PORT_SCAN = "port_scan"
    HTTPX_PROBE = "httpx_probe"
    AGENT_DISCOVERY = "agent_discovery"
    API_IMPORT = "api_import"


# --- Monitoring profile (per-asset) --------------------------------------


class MonitoringProfile(BaseModel):
    """Per-asset monitoring configuration. Stored on Asset.monitoring_profile JSONB."""

    enabled: bool = True
    scan_cadence_hours: int = Field(default=24, ge=1, le=24 * 30)
    deep_scan_enabled: bool = False
    feeds_to_match: list[str] = Field(default_factory=list)
    alert_severity_floor: Literal["critical", "high", "medium", "low", "info"] = "low"
    notify_on_change: bool = True


# --- Type-specific Detail Schemas ----------------------------------------


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
)


class DomainDetails(BaseModel):
    """Apex/root domain. value field on Asset = the domain string."""

    registrar: str | None = None
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    name_servers: list[str] = Field(default_factory=list)
    whois_raw: str | None = None
    is_root: bool = True
    locked: bool | None = None
    dnssec_enabled: bool | None = None


class SubdomainDetails(BaseModel):
    parent_domain: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    cname: str | None = None
    discovered_via: str | None = None  # subfinder, amass, ct-log

    @field_validator("parent_domain")
    @classmethod
    def _check_parent(cls, v: str) -> str:
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"parent_domain {v!r} is not a valid domain")
        return v.lower()


class IPAddressDetails(BaseModel):
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None
    cloud_provider: str | None = None
    reverse_dns: str | None = None


class IPRangeDetails(BaseModel):
    cidr: str
    asn: int | None = None
    description: str | None = None

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"cidr {v!r} is not a valid CIDR network: {e}")
        return v


class ServiceDetails(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service_name: str | None = None  # http, https, ssh, ftp ...
    # Banner is structured: {product, version, service, extrainfo, raw}.
    # Stored as JSON; runners populate fields opportunistically.
    banner: dict[str, Any] | None = None
    tls_info: dict | None = None


class EmailDomainDetails(BaseModel):
    """Domain used for email sending. SPF/DKIM/DMARC monitoring target."""

    domain: str
    has_mx: bool = False
    spf_record: str | None = None
    dkim_selectors: list[str] = Field(default_factory=list)
    dmarc_policy: Literal["none", "quarantine", "reject"] | None = None
    dmarc_pct: int | None = Field(default=None, ge=0, le=100)
    dmarc_rua: list[str] = Field(default_factory=list)
    dmarc_ruf: list[str] = Field(default_factory=list)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"domain {v!r} is not a valid domain")
        return v.lower()


class ExecutiveDetails(BaseModel):
    """High-value individual whose impersonation must be detected."""

    full_name: str
    title: str | None = None
    aliases: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    photo_evidence_hashes: list[str] = Field(default_factory=list)
    social_profiles: dict[str, str] = Field(default_factory=dict)
    bio_keywords: list[str] = Field(default_factory=list)
    consent_recorded_at: datetime | None = None  # data-protection requirement


class BrandDetails(BaseModel):
    name: str
    aliases: list[str] = Field(default_factory=list)
    trademark_status: str | None = None
    logo_evidence_hashes: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    color_palette: list[str] = Field(default_factory=list)


class MobileAppDetails(BaseModel):
    app_name: str
    bundle_id: str | None = None
    apple_app_id: str | None = None
    google_package: str | None = None
    publisher: str | None = None


class SocialHandleDetails(BaseModel):
    platform: Literal[
        "twitter",
        "x",
        "facebook",
        "instagram",
        "linkedin",
        "tiktok",
        "youtube",
        "telegram",
        "discord",
        "github",
        "reddit",
        "mastodon",
    ]
    handle: str
    profile_url: str | None = None
    is_official: bool = True
    associated_executive_id: uuid.UUID | None = None


class VendorDetails(BaseModel):
    legal_name: str
    primary_domain: str
    contact_email: str | None = None
    relationship_type: Literal[
        "supplier", "saas", "infra", "consultant", "auditor", "other"
    ] = "saas"
    data_access_level: Literal[
        "none", "metadata", "pii", "financial", "crown_jewel"
    ] = "metadata"
    contract_start: datetime | None = None
    contract_end: datetime | None = None
    risk_owner_email: str | None = None

    @field_validator("primary_domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"primary_domain {v!r} is not a valid domain")
        return v.lower()


class CodeRepositoryDetails(BaseModel):
    provider: Literal["github", "gitlab", "bitbucket", "gitea"]
    org_or_user: str
    repo_name: str | None = None  # null => monitor whole org
    is_private: bool = True


class CloudAccountDetails(BaseModel):
    provider: Literal["aws", "azure", "gcp", "oci", "do"]
    account_id: str
    account_name: str | None = None
    region_default: str | None = None


# Map AssetType → Pydantic detail schema for routing validation.
ASSET_DETAIL_SCHEMAS: dict[AssetType, type[BaseModel]] = {
    AssetType.DOMAIN: DomainDetails,
    AssetType.SUBDOMAIN: SubdomainDetails,
    AssetType.IP_ADDRESS: IPAddressDetails,
    AssetType.IP_RANGE: IPRangeDetails,
    AssetType.SERVICE: ServiceDetails,
    AssetType.EMAIL_DOMAIN: EmailDomainDetails,
    AssetType.EXECUTIVE: ExecutiveDetails,
    AssetType.BRAND: BrandDetails,
    AssetType.MOBILE_APP: MobileAppDetails,
    AssetType.SOCIAL_HANDLE: SocialHandleDetails,
    AssetType.VENDOR: VendorDetails,
    AssetType.CODE_REPOSITORY: CodeRepositoryDetails,
    AssetType.CLOUD_ACCOUNT: CloudAccountDetails,
}


# --- Value validators per asset type -------------------------------------
# Asset.value is the canonical identifier string. Each type has its own
# canonicalization + validation rule.


def canonicalize_asset_value(asset_type: AssetType, value: str) -> str:
    """Normalize and validate the canonical `value` field for an asset.

    Raises ValueError on invalid input. Returns the canonical form to store.
    """
    v = (value or "").strip()
    if not v:
        raise ValueError("value must not be empty")

    if asset_type == AssetType.DOMAIN or asset_type == AssetType.EMAIL_DOMAIN:
        v = v.lower().rstrip(".")
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"value {v!r} is not a valid domain")
        return v

    if asset_type == AssetType.SUBDOMAIN:
        v = v.lower().rstrip(".")
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"value {v!r} is not a valid subdomain")
        return v

    if asset_type == AssetType.IP_ADDRESS:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"value {v!r} is not a valid IP: {e}")
        return str(ip)

    if asset_type == AssetType.IP_RANGE:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"value {v!r} is not a valid CIDR: {e}")
        return str(net)

    if asset_type == AssetType.SERVICE:
        # Form: host:port  (host can be domain or IP)
        if ":" not in v:
            raise ValueError(f"service value {v!r} must be host:port")
        host, port_str = v.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"service port {port_str!r} is not numeric")
        if not (1 <= port <= 65535):
            raise ValueError(f"service port {port} out of range")
        # host can be IP or domain
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _DOMAIN_RE.match(host.lower()):
                raise ValueError(f"service host {host!r} not a valid IP or domain")
        return f"{host.lower()}:{port}"

    if asset_type == AssetType.EXECUTIVE:
        # value = full name; canonicalize whitespace
        return " ".join(v.split())

    if asset_type == AssetType.BRAND:
        return " ".join(v.split())

    if asset_type == AssetType.MOBILE_APP:
        # value = bundle_id / package name
        if not re.match(r"^[A-Za-z0-9._-]+$", v):
            raise ValueError(f"mobile_app value {v!r} contains invalid chars")
        return v

    if asset_type == AssetType.SOCIAL_HANDLE:
        # value = platform:handle
        if ":" not in v:
            raise ValueError("social_handle value must be platform:handle")
        platform, handle = v.split(":", 1)
        platform = platform.lower().strip()
        handle = handle.strip().lstrip("@")
        if not handle:
            raise ValueError("social_handle handle empty")
        return f"{platform}:{handle}"

    if asset_type == AssetType.VENDOR:
        return " ".join(v.split())

    if asset_type == AssetType.CODE_REPOSITORY:
        # value = provider:org[/repo]
        if ":" not in v:
            raise ValueError("code_repository value must be provider:org[/repo]")
        return v.lower()

    if asset_type == AssetType.CLOUD_ACCOUNT:
        # value = provider:account_id
        if ":" not in v:
            raise ValueError("cloud_account value must be provider:account_id")
        return v.lower()

    raise ValueError(f"Unknown asset_type {asset_type}")


def _derive_details_from_value(
    asset_type: AssetType, value: str | None
) -> dict:
    """Synthesize the minimum `details` payload for an asset type when
    the operator only supplied the canonical ``value`` field.

    The onboarding wizard treats ``value`` as the primary input and
    keeps ``details`` behind an "Advanced (JSON)" accordion. Without
    this fallback, picking ``executive`` and typing a name produced a
    pydantic ``full_name Field required`` error at completion — the
    schema demands a structured detail field that the UI never
    surfaced. The mapping mirrors ``canonicalize_asset_value``: types
    whose value already encodes a structured payload (social_handle =
    ``platform:handle``, code_repository = ``provider:org/repo``,
    cloud_account = ``provider:account_id``) parse it back; types
    where value is plain text (executive, brand, mobile_app, vendor)
    copy it into the schema's required string field.

    Returns a partial dict to be merged INTO the operator-supplied
    details — operator values always win.
    """
    if not value:
        return {}
    v = value.strip()
    if not v:
        return {}
    if asset_type == AssetType.EXECUTIVE:
        return {"full_name": v}
    if asset_type == AssetType.BRAND:
        return {"name": v}
    if asset_type == AssetType.MOBILE_APP:
        # value canonicalizes to a bundle_id; app_name (the required
        # field) defaults to the same string until the operator
        # supplies a friendlier label via Advanced JSON.
        return {"app_name": v, "bundle_id": v}
    if asset_type == AssetType.VENDOR:
        return {"legal_name": v}
    if asset_type == AssetType.SOCIAL_HANDLE and ":" in v:
        platform, handle = v.split(":", 1)
        return {
            "platform": platform.lower().strip(),
            "handle": handle.strip().lstrip("@"),
        }
    if asset_type == AssetType.CODE_REPOSITORY and ":" in v:
        provider, rest = v.split(":", 1)
        if "/" in rest:
            org_or_user, repo_name = rest.split("/", 1)
            return {
                "provider": provider.lower().strip(),
                "org_or_user": org_or_user.strip(),
                "repo_name": repo_name.strip() or None,
            }
        return {
            "provider": provider.lower().strip(),
            "org_or_user": rest.strip(),
        }
    if asset_type == AssetType.CLOUD_ACCOUNT and ":" in v:
        provider, account_id = v.split(":", 1)
        return {
            "provider": provider.lower().strip(),
            "account_id": account_id.strip(),
        }
    return {}


def validate_asset_details(
    asset_type: AssetType,
    details: dict | None,
    value: str | None = None,
) -> dict:
    """Validate `details` JSONB against the schema for `asset_type`.

    When ``value`` is supplied, missing required fields are
    auto-filled from it via ``_derive_details_from_value`` — see that
    helper for the per-type mapping. Operator-supplied keys always
    win over the derivation.

    Returns the canonical (parsed + re-serialized) dict. Raises
    pydantic.ValidationError on failure.
    """
    schema = ASSET_DETAIL_SCHEMAS.get(asset_type)
    if schema is None:
        raise ValueError(f"No detail schema registered for {asset_type}")
    merged: dict = {}
    derived = _derive_details_from_value(asset_type, value)
    merged.update(derived)
    if details:
        merged.update(details)
    parsed = schema.model_validate(merged)
    return parsed.model_dump(mode="json", exclude_none=False)


def validate_monitoring_profile(profile: dict | None) -> dict:
    parsed = MonitoringProfile.model_validate(profile or {})
    return parsed.model_dump(mode="json")


__all__ = [
    "AssetType",
    "AssetCriticality",
    "DiscoveryMethod",
    "MonitoringProfile",
    "DomainDetails",
    "SubdomainDetails",
    "IPAddressDetails",
    "IPRangeDetails",
    "ServiceDetails",
    "EmailDomainDetails",
    "ExecutiveDetails",
    "BrandDetails",
    "MobileAppDetails",
    "SocialHandleDetails",
    "VendorDetails",
    "CodeRepositoryDetails",
    "CloudAccountDetails",
    "ASSET_DETAIL_SCHEMAS",
    "canonicalize_asset_value",
    "validate_asset_details",
    "validate_monitoring_profile",
]
