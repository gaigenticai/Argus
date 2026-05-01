"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ClipboardList,
  PlayCircle,
  Plus,
  Trash2,
} from "lucide-react";
import {
  api,
  type Org,
  type RetentionCleanupResult,
  type RetentionPolicyResponse,
  type RetentionStats,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  StatePill,
  Th,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";

const RESOURCES = [
  { key: "raw_intel", label: "Raw intel" },
  { key: "alerts", label: "Alerts" },
  { key: "audit_logs", label: "Audit logs" },
  { key: "iocs", label: "IOCs" },
] as const;

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

export default function RetentionPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [policies, setPolicies] = useState<RetentionPolicyResponse[]>([]);
  const [stats, setStats] = useState<RetentionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] =
    useState<RetentionPolicyResponse | null>(null);
  const [cleanupRunning, setCleanupRunning] = useState(false);
  const [lastCleanup, setLastCleanup] = useState<RetentionCleanupResult[] | null>(
    null,
  );

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted = localStorage.getItem("argus_org_id");
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgIdState(initial);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load organizations",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    localStorage.setItem("argus_org_id", id);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, s] = await Promise.all([
        api.retention.listPolicies(),
        api.retention.stats(),
      ]);
      setPolicies(p);
      setStats(s);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load retention",
      );
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const runCleanup = async () => {
    if (
      !confirm(
        "Run cleanup now? This permanently deletes rows older than the configured windows (legal-hold rows are preserved).",
      )
    ) {
      return;
    }
    setCleanupRunning(true);
    try {
      const r = await api.retention.runCleanup();
      setLastCleanup(r);
      const total = r.reduce((s, x) => s + x.total_deleted, 0);
      toast(
        "success",
        `Cleanup complete — ${total.toLocaleString()} rows deleted`,
      );
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Cleanup failed");
    } finally {
      setCleanupRunning(false);
    }
  };

  const remove = async (p: RetentionPolicyResponse) => {
    if (!confirm("Delete this retention policy?")) return;
    try {
      await api.retention.deletePolicy(p.id);
      toast("success", "Policy deleted");
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: ClipboardList, label: "Governance" }}
        title="Retention"
        description="Per-tenant retention windows for raw intel, alerts, audit logs, IOCs, and Phase 1+ tables (news, probes, DLP, card leakage, DMARC, SLA). Legal-hold flag suppresses pruning. Worker auto-runs cleanup nightly when enabled."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={runCleanup}
              disabled={cleanupRunning}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold disabled:opacity-50"
              style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.6)", background: "#FF5630", color: "var(--color-on-dark)" }}
            >
              <PlayCircle
                className={`w-4 h-4 ${cleanupRunning ? "animate-pulse" : ""}`}
              />
              {cleanupRunning ? "Running…" : "Run cleanup now"}
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Plus className="w-4 h-4" />
              New policy
            </button>
          </>
        }
      />

      {/* Stats: what would be deleted */}
      {stats ? (
        <Section>
          <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Would-be-deleted on next run
            </h3>
            <p className="text-[11px]" style={{ color: "var(--color-muted)" }}>
              Computed against the current default policy windows.
            </p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4">
            {RESOURCES.map((r) => {
              const total = stats[
                `${r.key}_count` as keyof RetentionStats
              ] as number;
              const wouldDelete = stats[
                `${r.key}_would_delete` as keyof RetentionStats
              ] as number;
              const oldest = stats[
                `${r.key}_oldest` as keyof RetentionStats
              ] as string | null;
              const pct =
                total > 0 ? (wouldDelete / total) * 100 : 0;
              return (
                <div key={r.key} className="px-4 py-4" style={{ borderRight: "1px solid var(--color-border)" }}>
                  <div className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                    {r.label}
                  </div>
                  <div className="mt-1.5 flex items-baseline gap-2">
                    <span
                      className="font-mono tabular-nums text-[26px] leading-none font-extrabold tracking-[-0.01em]"
                      style={{ color: wouldDelete > 0 ? "#FF5630" : "var(--color-ink)" }}
                    >
                      {wouldDelete.toLocaleString()}
                    </span>
                    <span className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                      / {total.toLocaleString()}
                    </span>
                  </div>
                  <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
                    <div
                      className="h-full"
                      style={{ width: `${pct}%`, background: "rgba(255,86,48,0.7)" }}
                    />
                  </div>
                  <div className="text-[10.5px] font-mono tabular-nums mt-2" style={{ color: "var(--color-muted)" }}>
                    oldest:{" "}
                    {oldest ? formatDate(oldest).split(",")[0] : "—"}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      ) : null}

      {/* Last cleanup result */}
      {lastCleanup && lastCleanup.length > 0 ? (
        <Section>
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Last cleanup run
            </h3>
          </div>
          <div className="px-4 py-3 space-y-2">
            {lastCleanup.map((r) => (
              <div
                key={r.policy_id}
                className="flex items-center gap-3 text-[12.5px]"
              >
                <span className="font-mono tabular-nums w-[64px]" style={{ color: "var(--color-muted)" }}>
                  policy {r.policy_id.slice(-6).toUpperCase()}
                </span>
                <span className="font-mono tabular-nums font-bold w-[80px]" style={{ color: "var(--color-ink)" }}>
                  −{r.total_deleted.toLocaleString()}
                </span>
                <span className="font-mono text-[11px] truncate" style={{ color: "var(--color-body)" }}>
                  raw={r.raw_intel_deleted} · alerts={r.alerts_deleted} · audit=
                  {r.audit_logs_deleted} · ioc={r.iocs_deleted} · news=
                  {r.news_articles_deleted} · probe={r.live_probes_deleted} ·
                  dlp={r.dlp_findings_deleted} · cards=
                  {r.card_leakage_findings_deleted} · dmarc=
                  {r.dmarc_reports_deleted} · sla={r.sla_breach_events_deleted}
                </span>
              </div>
            ))}
          </div>
        </Section>
      ) : null}

      {/* Policies */}
      <Section>
        <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
            Retention policies
          </h3>
          <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Each row sets the max age (days) per resource type. Org-scoped
            policies override the default policy for that org.
          </p>
        </div>
        {loading ? (
          <SkeletonRows rows={3} columns={6} />
        ) : policies.length === 0 ? (
          <Empty
            icon={ClipboardList}
            title="No retention policies"
            description="Create at least one default policy to enable cleanup. Per-org policies override the defaults."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">
                    Scope
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Raw
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Alerts
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Audit
                  </Th>
                  <Th align="left" className="w-[80px]">
                    IOCs
                  </Th>
                  <Th align="left" className="w-[120px]">
                    Auto cleanup
                  </Th>
                  <Th align="left" className="w-[140px]">
                    Last run
                  </Th>
                  <Th align="right" className="pr-4 w-[140px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr
                    key={p.id}
                    className="h-12 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4">
                      {p.organization_id ? (
                        <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "rgba(255,79,0,0.1)", color: "var(--color-accent)" }}>
                          ORG-SCOPED
                        </span>
                      ) : (
                        <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "rgba(0,187,217,0.1)", color: "#007B8A" }}>
                          DEFAULT
                        </span>
                      )}
                    </td>
                    <DayCell value={p.raw_intel_days} />
                    <DayCell value={p.alerts_days} />
                    <DayCell value={p.audit_logs_days} />
                    <DayCell value={p.iocs_days} />
                    <td className="px-3">
                      {p.auto_cleanup_enabled ? (
                        <StatePill label="ON" tone="success" />
                      ) : (
                        <StatePill label="OFF" tone="muted" />
                      )}
                    </td>
                    <td className="px-3 font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {p.last_cleanup_at ? timeAgo(p.last_cleanup_at) : "never"}
                    </td>
                    <td className="pr-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setEditTarget(p)}
                          className="inline-flex items-center gap-1 h-7 px-2 text-[11px] font-bold transition-colors"
                          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
                        >
                          EDIT
                        </button>
                        <button
                          onClick={() => remove(p)}
                          className="p-1.5 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          onMouseEnter={e => { e.currentTarget.style.background = "rgba(255,86,48,0.1)"; e.currentTarget.style.color = "#B71D18"; }}
                          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--color-muted)"; }}
                          aria-label="Delete"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {showCreate && (
        <PolicyModal
          orgId={orgId || null}
          orgs={orgs}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}
      {editTarget && (
        <PolicyModal
          policy={editTarget}
          orgId={editTarget.organization_id || null}
          orgs={orgs}
          onClose={() => setEditTarget(null)}
          onSaved={() => {
            setEditTarget(null);
            load();
          }}
        />
      )}
    </div>
  );
}

function DayCell({ value }: { value: number }) {
  return (
    <td className="px-3 font-mono text-[12.5px] tabular-nums" style={{ color: "var(--color-body)" }}>
      {value}
      <span className="text-[10px] font-bold ml-1" style={{ color: "var(--color-muted)" }}>d</span>
    </td>
  );
}

function PolicyModal({
  policy,
  orgId,
  orgs,
  onClose,
  onSaved,
}: {
  policy?: RetentionPolicyResponse;
  orgId: string | null;
  orgs: Org[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [scope, setScope] = useState<"default" | "org">(
    policy?.organization_id ? "org" : "default",
  );
  const [scopedOrgId, setScopedOrgId] = useState(
    policy?.organization_id || orgId || "",
  );
  const [rawDays, setRawDays] = useState(policy?.raw_intel_days ?? 30);
  const [alertsDays, setAlertsDays] = useState(policy?.alerts_days ?? 90);
  const [auditDays, setAuditDays] = useState(policy?.audit_logs_days ?? 730);
  const [iocsDays, setIocsDays] = useState(policy?.iocs_days ?? 180);
  const [redactPii, setRedactPii] = useState(policy?.redact_pii ?? false);
  const [autoCleanup, setAutoCleanup] = useState(
    policy?.auto_cleanup_enabled ?? true,
  );
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (policy) {
        await api.retention.updatePolicy(policy.id, {
          raw_intel_days: rawDays,
          alerts_days: alertsDays,
          audit_logs_days: auditDays,
          iocs_days: iocsDays,
          redact_pii: redactPii,
          auto_cleanup_enabled: autoCleanup,
        });
        toast("success", "Policy updated");
      } else {
        await api.retention.createPolicy({
          organization_id: scope === "org" ? scopedOrgId : undefined,
          raw_intel_days: rawDays,
          alerts_days: alertsDays,
          audit_logs_days: auditDays,
          iocs_days: iocsDays,
          redact_pii: redactPii,
          auto_cleanup_enabled: autoCleanup,
        });
        toast("success", "Policy created");
      }
      onSaved();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title={policy ? "Edit retention policy" : "New retention policy"}
      onClose={onClose}
      width={620}
    >
      <div className="p-6 space-y-5">
        {!policy ? (
          <Field label="Scope" required>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                onClick={() => setScope("default")}
                className="h-10 flex items-center justify-center text-[12px] font-bold transition-all"
                style={scope === "default"
                  ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-canvas)", color: "var(--color-ink)", boxShadow: "0 0 0 2px rgba(32,21,21,0.08)" }
                  : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
                }
              >
                DEFAULT (all orgs)
              </button>
              <button
                onClick={() => setScope("org")}
                className="h-10 flex items-center justify-center text-[12px] font-bold transition-all"
                style={scope === "org"
                  ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-canvas)", color: "var(--color-ink)", boxShadow: "0 0 0 2px rgba(32,21,21,0.08)" }
                  : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
                }
              >
                ORG-SCOPED
              </button>
            </div>
            {scope === "org" ? (
              <div className="relative mt-2">
                <select
                  value={scopedOrgId}
                  onChange={(e) => setScopedOrgId(e.target.value)}
                  className="w-full h-10 px-3 text-[13px] appearance-none"
                  style={inputStyle}
                >
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}
          </Field>
        ) : null}
        <div className="grid grid-cols-2 gap-3">
          <DayField label="Raw intel" value={rawDays} onChange={setRawDays} />
          <DayField label="Alerts" value={alertsDays} onChange={setAlertsDays} />
          <DayField label="Audit logs" value={auditDays} onChange={setAuditDays} />
          <DayField label="IOCs" value={iocsDays} onChange={setIocsDays} />
        </div>
        <div className="space-y-2">
          <ToggleRow
            label="Redact PII before delete"
            hint="Anonymises PII columns rather than dropping the row entirely. Useful for GDPR Art.17 plus audit-trail preservation."
            value={redactPii}
            onChange={setRedactPii}
          />
          <ToggleRow
            label="Auto cleanup"
            hint="When enabled, the worker tick prunes nightly. Disable to require analyst-triggered cleanup."
            value={autoCleanup}
            onChange={setAutoCleanup}
          />
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Saving…" : "Save"}
        disabled={busy}
      />
    </ModalShell>
  );
}

function DayField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <Field label={label} hint="Max age in days. 0 disables retention.">
      <div className="relative">
        <input
          type="number"
          min={0}
          max={3650}
          value={value}
          onChange={(e) => onChange(Math.max(0, Number(e.target.value) || 0))}
          className="w-full h-10 pl-3 pr-10 font-mono tabular-nums"
          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)", outline: "none" }}
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] font-bold uppercase tracking-[0.06em]" style={{ color: "var(--color-muted)" }}>
          days
        </span>
      </div>
    </Field>
  );
}

function ToggleRow({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      onClick={() => onChange(!value)}
      className="w-full flex items-start gap-3 p-3 text-left transition-colors"
      style={{ borderRadius: "4px", border: "1px solid var(--color-border)" }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--color-border-strong)")}
      onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--color-border)")}
    >
      <span
        className="shrink-0 w-9 h-5 rounded-full transition-colors relative"
        style={{ background: value ? "#007B55" : "var(--color-surface-muted)" }}
      >
        <span
          className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
          style={{
            background: "var(--color-on-dark)",
            boxShadow: "0 1px 2px rgba(0,0,0,0.15)",
            left: value ? "18px" : "2px",
          }}
        />
      </span>
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>{label}</div>
        <div className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>{hint}</div>
      </div>
    </button>
  );
}
