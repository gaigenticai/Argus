// Friendly labels + tooltip explanations for the Brand Protection
// surface. Mirror of the codes the backend emits in:
//   - SuspectDomainSource enum (src/models/brand.py)
//   - Brand Defender risk_signals (src/agents/brand_defender_agent.py)
//   - Brand Defender tool catalogue
//   - Live-probe verdicts
//
// Keep this file in sync — when backend adds a new code, the
// dashboard falls back to the raw string but loses the human
// explanation. Tooltips use the description field.

import type {
  SuspectSourceValue,
} from "@/lib/api";


// -- Suspect-domain source ---------------------------------------------

export const SOURCE_LABEL: Record<SuspectSourceValue | string, string> = {
  dnstwist: "dnstwist",
  certstream: "Cert Transparency",
  whoisds: "WhoisDS",
  phishtank: "PhishTank",
  openphish: "OpenPhish",
  urlhaus: "URLhaus",
  subdomain_fuzz: "Subdomain fuzz",
  manual: "Manual",
};

export const SOURCE_DESCRIPTION: Record<string, string> = {
  dnstwist: "Permutation-based scanner — generates plausible typosquats from your registered brand terms.",
  certstream: "Certificate Transparency live feed — every TLS cert issued anywhere on the internet streams in.",
  whoisds: "Bulk newly-registered domain list — daily ZIP from whoisds.com, scanned for brand-similar names.",
  phishtank: "Cisco/OpenDNS phishing URL feed — community-reported phish.",
  openphish: "OpenPhish phishing URL feed.",
  urlhaus: "abuse.ch malware URL list.",
  subdomain_fuzz: "Brand-term subdomain enumeration — `login.<brand>.com` style.",
  manual: "Manually entered by an analyst.",
};

export function sourceLabel(s: string | null | undefined): string {
  if (!s) return "—";
  return SOURCE_LABEL[s] ?? s;
}


// -- Brand Defender risk signals --------------------------------------
//
// Codes the agent emits in BrandAction.risk_signals — short tokens
// like `fresh<7d`, `name-sim>0.83`, `cn-nameservers`. These are the
// signals stats endpoint already counts as the top-N risk_signals.

export const RISK_SIGNAL_LABEL: Record<string, string> = {
  "fresh<1d": "Domain registered <1 day ago",
  "fresh<7d": "Domain registered <7 days ago",
  "fresh<30d": "Domain registered <30 days ago",
  "name-sim>0.83": "Brand-name similarity > 83%",
  "name-sim>0.90": "Brand-name similarity > 90%",
  "name-sim>0.95": "Brand-name similarity > 95% (near-identical)",
  "single-char-replacement": "Single-character substitution from the brand",
  "single-char-insertion": "Single-character insertion in the brand",
  "homoglyph": "Look-alike Unicode characters in the domain",
  "punycode": "IDN punycode-encoded — possible homograph attack",
  "cn-nameservers": "Nameservers in CN — common bulletproof hosting region",
  "ru-nameservers": "Nameservers in RU — common bulletproof hosting region",
  "cheap-tld": "Low-cost TLD (.tk / .ml / .ga / .cf) — typical for disposable phishing",
  "no-A-record": "Domain has no A record (DNS not yet pointed)",
  "no-MX": "No MX record — usually not used for legit email",
  "no-probe": "Live probe didn't run (or failed)",
  "probe:phishing": "Live probe rendered a confirmed phishing page",
  "probe:suspicious": "Live probe rendered a suspicious page",
  "probe:unreachable": "Live probe couldn't reach the host",
  "logo-match>0.85": "Logo similarity > 85% to your registered brand logo",
  "subsidiary-allowlisted": "Domain matches a registered subsidiary allowlist entry",
};

export function riskSignalLabel(code: string): string {
  return RISK_SIGNAL_LABEL[code] ?? code;
}


// -- Brand Defender tools ---------------------------------------------

export type BrandToolName =
  | "lookup_suspect"
  | "lookup_live_probe"
  | "lookup_logo_matches"
  | "check_subsidiary_allowlist"
  | "estimate_age";

export const BRAND_TOOL_META: Record<
  BrandToolName,
  { label: string; description: string }
> = {
  lookup_suspect: {
    label: "Inspect suspect",
    description: "Read the suspect-domain row — domain, similarity, source, DNS records.",
  },
  lookup_live_probe: {
    label: "Live probe",
    description: "Read the most recent live-probe result for this suspect (verdict, signals, screenshot).",
  },
  lookup_logo_matches: {
    label: "Logo matches",
    description: "Look up logo-similarity matches against the org's registered brand logos.",
  },
  check_subsidiary_allowlist: {
    label: "Subsidiary check",
    description: "Match the suspect against the org's editable subsidiary allowlist — auto-dismisses known-good domains.",
  },
  estimate_age: {
    label: "Domain age",
    description: "Estimate registration age via WHOIS — fresh domains (<7d) are higher-risk.",
  },
};

export function brandToolLabel(tool: string | null | undefined): string {
  if (!tool) return "Thinking";
  return (
    (BRAND_TOOL_META as Record<string, { label: string }>)[tool]?.label ?? tool
  );
}


// -- Brand-action recommendation tone ---------------------------------

export const RECOMMENDATION_LABEL: Record<string, string> = {
  takedown_now: "Take down NOW",
  takedown_after_review: "Takedown after review",
  dismiss_subsidiary: "Subsidiary — dismiss",
  monitor: "Monitor only",
  insufficient_data: "Insufficient data",
};

export const RECOMMENDATION_TONE: Record<string, string> = {
  takedown_now: "#B71D18",
  takedown_after_review: "#B76E00",
  dismiss_subsidiary: "var(--color-muted)",
  monitor: "#007B8A",
  insufficient_data: "var(--color-muted)",
};


// -- Live-probe verdict tone (mirror of overview-tab) -----------------

export const PROBE_VERDICT_LABEL: Record<string, string> = {
  phishing: "PHISHING",
  suspicious: "SUSPICIOUS",
  benign: "BENIGN",
  parked: "PARKED",
  unreachable: "UNREACHABLE",
  unknown: "UNKNOWN",
};
