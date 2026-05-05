"use client";

/**
 * <DomainVerificationBanner /> — surfaces the DNS-TXT ownership
 * challenge for any org whose primary domain hasn't been proven
 * owned yet.
 *
 * Why this exists: without an ownership challenge an operator can
 * register any apex (microsoft.com, etc.) and trigger crawlers +
 * brand monitors against infrastructure they don't control.
 *
 * Verification model (explained inline so the operator sees how
 * trustworthy "verified" actually is):
 *   - Marsad queries multiple independent public DNS-over-HTTPS
 *     resolvers (Cloudflare, Google, Quad9 by default).
 *   - At least 2 of them must independently see the matching TXT
 *     value before status flips to verified — a single compromised
 *     resolver cannot fake it.
 *   - The token expires 24h after issuance; expired challenges must
 *     be re-requested (bounds blast radius if a token leaks).
 *
 * Renders nothing when verified, when status fetch fails, or when
 * the parent forgot to pass orgId/domain. Banner color reflects
 * whether ARGUS_REQUIRE_DOMAIN_VERIFICATION is on (red = blocking)
 * or off (yellow = informational).
 */

import { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  Copy,
  Loader2,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { api, type DomainVerificationStatus } from "@/lib/api";
import { useToast } from "@/components/shared/toast";

type Props = {
  orgId: string;
  domain: string;
  onVerified?: () => void;
};

export function DomainVerificationBanner({ orgId, domain, onVerified }: Props) {
  const { toast } = useToast();
  const [status, setStatus] = useState<DomainVerificationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [requesting, setRequesting] = useState(false);
  const [checking, setChecking] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [showExplainer, setShowExplainer] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await api.domainVerification.status(orgId, domain);
      setStatus(s);
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, [orgId, domain]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleRequest = async () => {
    setRequesting(true);
    try {
      const s = await api.domainVerification.request(orgId, domain);
      setStatus(s);
      setShowInstructions(true);
    } catch (e) {
      toast("error", `Couldn't issue challenge: ${(e as Error).message}`);
    } finally {
      setRequesting(false);
    }
  };

  const handleCheck = async () => {
    setChecking(true);
    try {
      const r = await api.domainVerification.check(orgId, domain);
      if (r.verified) {
        toast(
          "success",
          `${domain} verified — ${r.matches} of ${r.resolvers_consulted} resolvers agreed.`,
        );
        onVerified?.();
      } else {
        toast(
          "warning",
          `Not yet — ${r.matches} of ${r.resolvers_consulted} resolvers saw the TXT record (need ${r.quorum_required}). DNS can take a few minutes to propagate.`,
        );
      }
      await load();
    } catch (e) {
      toast("error", `Check failed: ${(e as Error).message}`);
    } finally {
      setChecking(false);
    }
  };

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast("success", `${label} copied.`);
    } catch {
      toast("error", "Couldn't copy — select and ⌘C the value manually.");
    }
  };

  if (loading || !status) return null;
  if (status.status === "verified") return null;

  const tone = status.gate_required ? "blocking" : "advisory";
  const expired = status.status === "expired";
  const headline = expired
    ? `Verification token for ${domain} expired.`
    : tone === "blocking"
    ? `Verify ownership of ${domain} to enable monitoring.`
    : `Recommended: verify that you own ${domain}.`;
  const subhead = expired
    ? `Tokens are valid for ${status.ttl_hours}h after issuance. Generate a new challenge to continue.`
    : tone === "blocking"
    ? "Discovery and AI triage are paused for this org until at least 2 of 3 public DNS resolvers see your TXT record. (ARGUS_REQUIRE_DOMAIN_VERIFICATION is on.)"
    : "On this deployment verification is informational — but in production it gates EASM and triage from touching domains you can't prove you own.";

  return (
    <div
      className="px-5 py-4"
      style={{
        background: tone === "blocking" ? "rgba(239,68,68,0.05)" : "rgba(255,171,0,0.06)",
        border: `1px solid ${tone === "blocking" ? "rgba(239,68,68,0.25)" : "rgba(255,171,0,0.25)"}`,
        borderRadius: 5,
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-9 h-9 flex items-center justify-center shrink-0"
          style={{
            background: tone === "blocking" ? "var(--color-error)" : "var(--color-warning)",
            borderRadius: 4,
          }}
        >
          <ShieldAlert className="w-4 h-4" style={{ color: "var(--color-on-dark)" }} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
            {headline}
          </h3>
          <p className="text-[12.5px] mt-1" style={{ color: "var(--color-body)" }}>
            {subhead}
          </p>

          {(status.status === "unverified" || expired) && (
            <button
              onClick={handleRequest}
              disabled={requesting}
              className="inline-flex items-center gap-2 h-9 px-4 mt-3"
              style={{
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
                borderRadius: 4,
                fontSize: 13,
                fontWeight: 600,
                border: "none",
                cursor: requesting ? "not-allowed" : "pointer",
                opacity: requesting ? 0.6 : 1,
              }}
            >
              {requesting ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : expired ? (
                <RefreshCcw className="w-3.5 h-3.5" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5" />
              )}
              {expired ? "Issue a new challenge" : "Generate verification challenge"}
            </button>
          )}

          {status.status === "pending" && status.dns && (
            <div className="mt-3 space-y-3">
              {/* TXT record block */}
              <div
                className="p-3"
                style={{
                  background: "var(--color-canvas)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                }}
              >
                <div
                  className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-2"
                  style={{ color: "var(--color-muted)" }}
                >
                  Add this DNS TXT record
                  {status.expires_in_hours !== null && (
                    <span
                      className="ml-2 font-medium normal-case tracking-normal"
                      style={{ color: "var(--color-muted)" }}
                    >
                      · expires in {status.expires_in_hours}h
                    </span>
                  )}
                </div>
                <p className="text-[12px] mb-2" style={{ color: "var(--color-body)" }}>
                  In your DNS host (Route 53, Cloudflare, GoDaddy, etc.), create
                  a new <strong>TXT</strong> record with the values below. DNS
                  propagation usually takes &lt; 5 minutes. Then click{" "}
                  <strong>Check now</strong>.
                </p>
                <DnsRow
                  label="Record type"
                  value={status.dns.record_type}
                />
                <DnsRow
                  label="Record name"
                  value={status.dns.record_name}
                  onCopy={(v) => copy(v, "Record name")}
                />
                <DnsRow
                  label="Record value"
                  value={status.dns.record_value}
                  onCopy={(v) => copy(v, "Record value")}
                />
              </div>

              {/* Action row */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleCheck}
                  disabled={checking}
                  className="inline-flex items-center gap-2 h-9 px-4"
                  style={{
                    background: "var(--color-accent)",
                    color: "var(--color-on-dark)",
                    borderRadius: 4,
                    fontSize: 13,
                    fontWeight: 600,
                    border: "none",
                    cursor: checking ? "not-allowed" : "pointer",
                    opacity: checking ? 0.6 : 1,
                  }}
                >
                  {checking ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  )}
                  Check now
                </button>
                <button
                  onClick={() => setShowExplainer((x) => !x)}
                  className="inline-flex items-center gap-1 text-[12px] font-semibold"
                  style={{
                    color: "var(--color-muted)",
                    background: "transparent",
                    border: "none",
                    cursor: "pointer",
                    padding: 0,
                  }}
                >
                  <ChevronDown
                    className={`w-3.5 h-3.5 transition-transform ${showExplainer ? "rotate-0" : "-rotate-90"}`}
                  />
                  How does Marsad check this securely?
                </button>
              </div>

              {/* Per-resolver result from last check */}
              {status.last_check_report && (
                <ResolverReport report={status.last_check_report} />
              )}

              {/* Security explainer */}
              {showExplainer && (
                <div
                  className="p-3 text-[12px]"
                  style={{
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 4,
                    color: "var(--color-body)",
                  }}
                >
                  <p className="mb-2">
                    A naive lookup against your local resolver would trust
                    whoever runs it — your ISP, a hostile coffee-shop wifi,
                    a misconfigured corporate DNS. So instead Marsad queries{" "}
                    <strong>{status.resolvers.length} independent public
                    DNS-over-HTTPS resolvers</strong> ({status.resolvers.join(", ")})
                    in parallel, over HTTPS so the answers can&apos;t be spoofed
                    by a network-level attacker.
                  </p>
                  <p className="mb-2">
                    At least <strong>{status.quorum_required} of {status.resolvers.length}</strong>{" "}
                    must independently see your TXT value before
                    Marsad flips status to <em>verified</em>. A single
                    compromised resolver cannot fake the proof.
                  </p>
                  <p>
                    The token itself is {status.ttl_hours}h-lived random
                    entropy, scoped to <code>{domain}</code>. Air-gapped
                    deployments can override the resolver list via{" "}
                    <code>ARGUS_VERIFICATION_DOH_RESOLVERS</code> in <code>.env</code>.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DnsRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy?: (v: string) => void;
}) {
  return (
    <div className="flex items-start gap-2 mb-1.5">
      <div
        className="text-[10.5px] font-bold uppercase tracking-[0.6px] w-[110px] shrink-0 pt-1.5"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <code
        className="flex-1 px-2 py-1 text-[12px] font-mono break-all"
        style={{
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: 3,
          color: "var(--color-ink)",
        }}
      >
        {value}
      </code>
      {onCopy && (
        <button
          onClick={() => onCopy(value)}
          className="p-1.5 shrink-0"
          title="Copy"
          style={{
            background: "transparent",
            border: "1px solid var(--color-border)",
            borderRadius: 3,
            cursor: "pointer",
            color: "var(--color-body)",
          }}
        >
          <Copy className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}

function ResolverReport({
  report,
}: {
  report: NonNullable<DomainVerificationStatus["last_check_report"]>;
}) {
  return (
    <div
      className="p-3 text-[12px]"
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: 4,
      }}
    >
      <div
        className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-2"
        style={{ color: "var(--color-muted)" }}
      >
        Last check · {report.matches} of {report.resolvers_consulted} agreed (need {report.quorum_required})
      </div>
      <div className="space-y-1">
        {report.votes.map((v) => (
          <div key={v.resolver} className="flex items-center gap-2">
            {v.matched ? (
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-success)" }} />
            ) : (
              <XCircle className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-muted)" }} />
            )}
            <span className="font-semibold" style={{ color: "var(--color-ink)" }}>
              {v.resolver}
            </span>
            {!v.matched && v.error && (
              <span style={{ color: "var(--color-muted)" }}>· {v.error}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
