"use client";

/**
 * <ScopeVerificationGate /> — site-wide gate that:
 *
 *   1. Renders a persistent banner at the top of every page when the
 *      currently-scoped organisation (``argus_org_id`` localStorage)
 *      has at least one unverified primary domain.
 *   2. Blurs the page content underneath until verification clears
 *      so the operator sees the dashboard structure but cannot trust
 *      the values — scans still run, but UI signals "this data is
 *      against an unproven asset".
 *   3. Lets the operator manage the org's domain list inline — add
 *      a new one, swap which is primary, remove a typo'd domain,
 *      and run the DNS TXT challenge per domain.
 *
 * The component reads ``argus_org_id`` and listens to
 * ``argus:org-changed`` (dispatched by the header switcher) so a
 * scope change re-evaluates which domains to chase.
 *
 * Seed orgs and orgs without ``settings.created_via`` are exempt —
 * their domains aren't real.
 */

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Loader2,
  Plus,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Star,
  Trash2,
  XCircle,
} from "lucide-react";
import {
  api,
  type DomainVerificationStatus,
  type Org,
  type OrgDomainListItem,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";

const ORG_KEY = "argus_org_id";
const ORG_CHANGED_EVENT = "argus:org-changed";

type Props = {
  children: React.ReactNode;
};

export function ScopeVerificationGate({ children }: Props) {
  const [orgId, setOrgId] = useState<string>("");
  const [org, setOrg] = useState<Org | null>(null);
  const [domains, setDomains] = useState<OrgDomainListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);

  // Track scope. Reads localStorage on mount + listens for changes
  // dispatched by the header switcher.
  useEffect(() => {
    setOrgId(window.localStorage.getItem(ORG_KEY) || "");
    function handler(e: Event) {
      const detail = (e as CustomEvent<{ orgId: string }>).detail;
      setOrgId(detail?.orgId || "");
    }
    window.addEventListener(ORG_CHANGED_EVENT, handler as EventListener);
    return () => window.removeEventListener(ORG_CHANGED_EVENT, handler as EventListener);
  }, []);

  const refresh = useCallback(async () => {
    if (!orgId) {
      setOrg(null);
      setDomains([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [orgs, domainList] = await Promise.all([
        api.getOrgs(),
        api.orgDomains.list(orgId),
      ]);
      setOrg(orgs.find((o) => o.id === orgId) ?? null);
      setDomains(domainList);
      window.dispatchEvent(new CustomEvent("argus:domains-changed"));
    } catch {
      setOrg(null);
      setDomains([]);
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Seed orgs are detected by the absence of ``settings.created_via``
  // on the backend — but the org list endpoint doesn't return
  // settings. As a proxy, we treat an org as user-created when ANY
  // of its domains has an active verification record (pending /
  // verified / expired). Seed orgs never get one minted. That keeps
  // the gate from nagging operators on Argus Demo Bank.
  const hasVerificationRecord = domains.some(
    (d) => d.verification_status !== "unverified",
  );
  const primary = domains.find((d) => d.is_primary) ?? domains[0];
  const isUnverified =
    !!primary && primary.verification_status !== "verified";
  // Show gate when: we have a scope org, it looks user-created
  // (has a verification record), and the primary isn't verified.
  const shouldGate = !loading && !!org && hasVerificationRecord && isUnverified;

  // Stable wrapper styles. When gating, the children get a CSS
  // ``filter: blur`` and ``pointer-events: none`` plus a translucent
  // overlay so the operator can see the structure (cards, charts)
  // but can't read the values or click into them.
  const childWrapperStyle: React.CSSProperties = shouldGate
    ? {
        filter: "blur(6px)",
        pointerEvents: "none",
        userSelect: "none",
        position: "relative",
      }
    : {};

  return (
    <>
      {shouldGate && org && (
        <ScopeBanner
          org={org}
          domains={domains}
          expanded={expanded}
          onToggleExpand={() => setExpanded((x) => !x)}
          onRefresh={refresh}
        />
      )}
      <div style={childWrapperStyle} aria-hidden={shouldGate ? "true" : undefined}>
        {children}
      </div>
      {shouldGate && (
        <div
          // Sticky overlay block at the bottom that re-iterates the
          // gate so the operator who scrolled past the banner still
          // knows why content is blurred.
          className="fixed bottom-6 right-6 px-4 py-3 max-w-[360px] z-30 flex items-start gap-2"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 5,
            boxShadow: "var(--shadow-z16)",
          }}
        >
          <AlertTriangle
            className="w-4 h-4 mt-0.5 shrink-0"
            style={{ color: "var(--color-accent)" }}
          />
          <div className="text-[12px]" style={{ color: "var(--color-body)" }}>
            <strong>Results blurred</strong> — verify ownership of{" "}
            <code>{primary?.domain}</code> to view real values for{" "}
            <strong>{org?.name}</strong>.
          </div>
        </div>
      )}
    </>
  );
}

function ScopeBanner({
  org,
  domains,
  expanded,
  onToggleExpand,
  onRefresh,
}: {
  org: Org;
  domains: OrgDomainListItem[];
  expanded: boolean;
  onToggleExpand: () => void;
  onRefresh: () => Promise<void>;
}) {
  const primary = domains.find((d) => d.is_primary) ?? domains[0];
  return (
    <div
      className="mx-8 mt-4 px-5 py-4"
      style={{
        background: "rgba(239,68,68,0.04)",
        border: "1px solid rgba(239,68,68,0.25)",
        borderRadius: 5,
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-9 h-9 flex items-center justify-center shrink-0"
          style={{ background: "var(--color-accent)", borderRadius: 4 }}
        >
          <ShieldAlert className="w-4 h-4" style={{ color: "var(--color-on-dark)" }} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
            Verify ownership of{" "}
            <code style={{ fontFamily: "var(--font-mono, monospace)" }}>{primary?.domain}</code>{" "}
            to unblur {org.name}.
          </h3>
          <p className="text-[12.5px] mt-1" style={{ color: "var(--color-body)" }}>
            Marsad keeps running scans in the background, but values are
            hidden until you prove you control the domain via DNS TXT.
            DNS propagation usually takes &lt;5 minutes.
          </p>

          <button
            onClick={onToggleExpand}
            className="inline-flex items-center gap-1 text-[12.5px] font-semibold mt-2"
            style={{
              color: "var(--color-accent)",
              background: "transparent",
              border: "none",
              padding: 0,
              cursor: "pointer",
            }}
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            {expanded ? "Hide domain manager" : "Manage & verify domains"}
          </button>

          {expanded && (
            <div className="mt-3 space-y-3">
              {domains.map((d) => (
                <DomainRow
                  key={d.domain}
                  orgId={org.id}
                  domain={d}
                  canRemove={domains.length > 1}
                  onChanged={onRefresh}
                />
              ))}
              <AddDomainForm orgId={org.id} onAdded={onRefresh} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function DomainRow({
  orgId,
  domain,
  canRemove,
  onChanged,
}: {
  orgId: string;
  domain: OrgDomainListItem;
  canRemove: boolean;
  onChanged: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [acting, setActing] = useState(false);

  const handleSetPrimary = async () => {
    setActing(true);
    try {
      await api.orgDomains.add(orgId, domain.domain, true);
      toast("success", `${domain.domain} is now the primary domain.`);
      await onChanged();
    } catch (e) {
      toast("error", `Couldn't set primary: ${(e as Error).message}`);
    } finally {
      setActing(false);
    }
  };

  const handleRemove = async () => {
    if (!confirm(`Remove ${domain.domain} from this org?`)) return;
    setActing(true);
    try {
      await api.orgDomains.remove(orgId, domain.domain);
      toast("success", `${domain.domain} removed.`);
      await onChanged();
    } catch (e) {
      toast("error", `Couldn't remove: ${(e as Error).message}`);
    } finally {
      setActing(false);
    }
  };

  return (
    <div
      className="px-3 py-2.5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 4,
      }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        {domain.is_primary && (
          <Star className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-accent)" }} />
        )}
        <code className="text-[13px] font-mono flex-1 truncate" style={{ color: "var(--color-ink)" }}>
          {domain.domain}
        </code>
        <StatusPill status={domain.verification_status} />
        {!domain.is_primary && domain.verification_status !== "verified" && (
          <button
            onClick={handleSetPrimary}
            disabled={acting}
            className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold"
            title="Make this the primary domain (the one Marsad triages against)"
            style={{
              background: "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 3,
              cursor: "pointer",
              color: "var(--color-body)",
            }}
          >
            <Star className="w-3 h-3" />
            Make primary
          </button>
        )}
        {canRemove && (
          <button
            onClick={handleRemove}
            disabled={acting}
            className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold"
            title="Remove this domain"
            style={{
              background: "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 3,
              cursor: "pointer",
              color: "var(--color-error-dark)",
            }}
          >
            <Trash2 className="w-3 h-3" />
          </button>
        )}
        {domain.verification_status !== "verified" && (
          <button
            onClick={() => setOpen((x) => !x)}
            className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold"
            style={{
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
              border: "none",
              borderRadius: 3,
              cursor: "pointer",
            }}
          >
            {open ? "Hide" : "Verify"}
          </button>
        )}
      </div>
      {open && (
        <DomainChallengePanel
          orgId={orgId}
          domain={domain.domain}
          onChanged={onChanged}
        />
      )}
    </div>
  );
}

function StatusPill({ status }: { status: OrgDomainListItem["verification_status"] }) {
  const map: Record<typeof status, { bg: string; color: string; label: string }> = {
    verified: { bg: "rgba(34,197,94,0.12)", color: "var(--color-success-dark)", label: "Verified" },
    pending: { bg: "rgba(255,171,0,0.12)", color: "#B76E00", label: "Pending DNS" },
    unverified: { bg: "var(--color-surface-muted)", color: "var(--color-muted)", label: "Not started" },
    expired: { bg: "rgba(239,68,68,0.12)", color: "var(--color-error-dark)", label: "Expired" },
  };
  const s = map[status];
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px]"
      style={{ background: s.bg, color: s.color, borderRadius: 3 }}
    >
      {s.label}
    </span>
  );
}

export function DomainChallengePanel({
  orgId,
  domain,
  onChanged,
}: {
  orgId: string;
  domain: string;
  onChanged: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [status, setStatus] = useState<DomainVerificationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [requesting, setRequesting] = useState(false);
  const [checking, setChecking] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const s = await api.domainVerification.status(orgId, domain);
      setStatus(s);
      if (s.status === "unverified" || s.status === "expired") {
        // Auto-issue if there isn't a live token already.
        const fresh = await api.domainVerification.request(orgId, domain);
        setStatus(fresh);
      }
    } catch (e) {
      toast("error", `Couldn't load challenge: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [orgId, domain, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleNewToken = async () => {
    setRequesting(true);
    try {
      const fresh = await api.domainVerification.request(orgId, domain);
      setStatus(fresh);
    } catch (e) {
      toast("error", `Couldn't issue new token: ${(e as Error).message}`);
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
        await onChanged();
      } else if (r.status === "expired") {
        toast("warning", "Token expired — request a new one.");
        await load();
      } else {
        toast(
          "warning",
          `Not yet — ${r.matches} of ${r.resolvers_consulted} resolvers saw the TXT record (need ${r.quorum_required}). DNS may take a few minutes to propagate.`,
        );
        await load();
      }
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

  if (loading) {
    return (
      <div className="mt-3 flex items-center gap-2 text-[12px]" style={{ color: "var(--color-muted)" }}>
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        Loading challenge…
      </div>
    );
  }

  if (!status || !status.dns) return null;

  return (
    <div className="mt-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap text-[11px]" style={{ color: "var(--color-muted)" }}>
        <span>
          Token expires in <strong>{status.expires_in_hours ?? 0}h</strong> · checked
          via <strong>{status.resolvers.join(", ")}</strong> (need{" "}
          {status.quorum_required} of {status.resolvers.length} to agree)
        </span>
        <button
          onClick={handleNewToken}
          disabled={requesting}
          className="inline-flex items-center gap-1 ml-auto"
          style={{
            color: "var(--color-accent)",
            background: "transparent",
            border: "none",
            padding: 0,
            cursor: "pointer",
            fontWeight: 600,
          }}
          title="Mint a fresh token (e.g. if this one leaked)"
        >
          <RefreshCcw className="w-3 h-3" />
          New token
        </button>
      </div>
      <DnsRow label="Type" value={status.dns.record_type} />
      <DnsRow
        label="Name"
        value={status.dns.record_name}
        onCopy={() => copy(status.dns!.record_name, "Record name")}
      />
      <DnsRow
        label="Value"
        value={status.dns.record_value}
        onCopy={() => copy(status.dns!.record_value, "Record value")}
      />

      <div className="flex items-center gap-2">
        <button
          onClick={handleCheck}
          disabled={checking}
          className="inline-flex items-center gap-2 h-8 px-3"
          style={{
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            border: "none",
            borderRadius: 3,
            fontSize: 12,
            fontWeight: 600,
            cursor: checking ? "not-allowed" : "pointer",
            opacity: checking ? 0.6 : 1,
          }}
        >
          {checking ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
          Check now
        </button>
        {status.last_error && (
          <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
            {status.last_error}
          </span>
        )}
      </div>

      {status.last_check_report && status.last_check_report.votes.length > 0 && (
        <div className="grid grid-cols-3 gap-1 mt-1">
          {status.last_check_report.votes.map((v) => (
            <div
              key={v.resolver}
              className="flex items-center gap-1 px-2 py-1 text-[11px]"
              style={{
                background: "var(--color-surface)",
                border: "1px solid var(--color-border)",
                borderRadius: 3,
              }}
              title={v.error || "matched"}
            >
              {v.matched ? (
                <CheckCircle2 className="w-3 h-3 shrink-0" style={{ color: "var(--color-success)" }} />
              ) : (
                <XCircle className="w-3 h-3 shrink-0" style={{ color: "var(--color-muted)" }} />
              )}
              <span className="font-semibold" style={{ color: "var(--color-ink)" }}>
                {v.resolver}
              </span>
            </div>
          ))}
        </div>
      )}
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
  onCopy?: () => void;
}) {
  return (
    <div className="flex items-start gap-2">
      <div
        className="text-[10px] font-bold uppercase tracking-[0.6px] w-[55px] shrink-0 pt-1.5"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <code
        className="flex-1 px-2 py-1 text-[11.5px] font-mono break-all"
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
          onClick={onCopy}
          className="p-1 shrink-0"
          title="Copy"
          style={{
            background: "transparent",
            border: "1px solid var(--color-border)",
            borderRadius: 3,
            cursor: "pointer",
            color: "var(--color-body)",
          }}
        >
          <Copy className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}

export function AddDomainForm({
  orgId,
  onAdded,
}: {
  orgId: string;
  onAdded: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [makePrimary, setMakePrimary] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;
    setSubmitting(true);
    try {
      await api.orgDomains.add(orgId, domain.trim(), makePrimary);
      toast(
        "success",
        makePrimary
          ? `${domain} added as the new primary.`
          : `${domain} added — verify it from the row above.`,
      );
      setDomain("");
      setMakePrimary(false);
      await onAdded();
    } catch (e) {
      toast("error", `Couldn't add: ${(e as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="px-3 py-2.5 flex items-center gap-2 flex-wrap"
      style={{
        background: "var(--color-surface)",
        border: "1px dashed var(--color-border)",
        borderRadius: 4,
      }}
    >
      <Plus className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-muted)" }} />
      <input
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="another-domain.example"
        className="flex-1 min-w-[180px] h-8 px-2 text-[12.5px] font-mono"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 3,
          color: "var(--color-ink)",
          outline: "none",
        }}
      />
      <label
        className="flex items-center gap-1.5 text-[11.5px] cursor-pointer"
        style={{ color: "var(--color-body)" }}
      >
        <input
          type="checkbox"
          checked={makePrimary}
          onChange={(e) => setMakePrimary(e.target.checked)}
        />
        Make primary
      </label>
      <button
        type="submit"
        disabled={submitting || !domain.trim()}
        className="inline-flex items-center gap-1 h-8 px-3 text-[11.5px] font-semibold"
        style={{
          background: "var(--color-accent)",
          color: "var(--color-on-dark)",
          border: "none",
          borderRadius: 3,
          cursor: submitting ? "not-allowed" : "pointer",
          opacity: submitting ? 0.6 : 1,
        }}
      >
        {submitting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
        Add domain
      </button>
    </form>
  );
}
