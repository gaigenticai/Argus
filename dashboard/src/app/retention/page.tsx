"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ClipboardList,
  PlayCircle,
  Plus,
  Trash2,
  FileText,
  ShieldCheck,
  Languages,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import {
  api,
  type DsarCreatePayload,
  type DsarRequestResponse,
  type DsarRequestType,
  type Org,
  type RetentionAttestationResponse,
  type RetentionCleanupResult,
  type RetentionComplianceFramework,
  type RetentionDeletionMode,
  type RetentionPolicyResponse,
  type RetentionRegulationSuggestion,
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
import { Select as ThemedSelect } from "@/components/shared/select";

const RESOURCES = [
  { key: "raw_intel", label: "Raw intel" },
  { key: "alerts", label: "Alerts" },
  { key: "audit_logs", label: "Audit logs" },
  { key: "iocs", label: "IOCs" },
] as const;

const DELETION_MODE_LABEL: Record<RetentionDeletionMode, string> = {
  hard_delete: "Hard delete",
  soft_delete: "Soft delete",
  anonymise: "Anonymise",
};

type RetentionTab = "policies" | "dsar" | "attestation";

export default function RetentionPage() {
  const { toast } = useToast();
  const [tab, setTab] = useState<RetentionTab>("policies");
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [policies, setPolicies] = useState<RetentionPolicyResponse[]>([]);
  const [stats, setStats] = useState<RetentionStats | null>(null);
  const [frameworks, setFrameworks] = useState<RetentionComplianceFramework[]>(
    [],
  );
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] =
    useState<RetentionPolicyResponse | null>(null);
  const [showTranslate, setShowTranslate] = useState(false);
  const [cleanupRunning, setCleanupRunning] = useState(false);
  const [dryRunPreview, setDryRunPreview] = useState<RetentionCleanupResult[] | null>(
    null,
  );
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
      const [p, s, fw] = await Promise.all([
        api.retention.listPolicies(),
        api.retention.stats(),
        api.retention.listFrameworks(),
      ]);
      setPolicies(p);
      setStats(s);
      setFrameworks(fw);
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

  const startCleanup = async () => {
    setCleanupRunning(true);
    try {
      const r = await api.retention.runCleanup(true);
      setDryRunPreview(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Dry-run failed");
    } finally {
      setCleanupRunning(false);
    }
  };

  const confirmCleanup = async () => {
    setCleanupRunning(true);
    try {
      const r = await api.retention.runCleanup(false);
      setLastCleanup(r);
      setDryRunPreview(null);
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
        description="Per-tenant retention windows, DSAR pipeline, and compliance attestations. Bridge-LLM agents preserve institutional knowledge before purge, draft DSAR responses, and detect retention/regulation conflicts."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={load} refreshing={loading} />
            {tab === "policies" && (
              <>
                <button
                  onClick={() => setShowTranslate(true)}
                  className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    color: "var(--color-body)",
                  }}
                >
                  <Languages className="w-4 h-4" />
                  Translate regulation
                </button>
                <button
                  onClick={startCleanup}
                  disabled={cleanupRunning}
                  className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold disabled:opacity-50"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid rgba(255,86,48,0.6)",
                    background: "#FF5630",
                    color: "var(--color-on-dark)",
                  }}
                >
                  <PlayCircle
                    className={`w-4 h-4 ${cleanupRunning ? "animate-pulse" : ""}`}
                  />
                  {cleanupRunning ? "Running…" : "Run cleanup"}
                </button>
                <button
                  onClick={() => setShowCreate(true)}
                  className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-accent)",
                    background: "var(--color-accent)",
                    color: "var(--color-on-dark)",
                  }}
                >
                  <Plus className="w-4 h-4" />
                  New policy
                </button>
              </>
            )}
          </>
        }
      />

      {/* Tab switcher */}
      <div className="flex items-center gap-1">
        {(
          [
            { k: "policies", label: "Policies", icon: ClipboardList },
            { k: "dsar", label: "DSAR", icon: FileText },
            { k: "attestation", label: "Attestation", icon: ShieldCheck },
          ] as { k: RetentionTab; label: string; icon: typeof ClipboardList }[]
        ).map(({ k, label, icon: Icon }) => (
          <button
            key={k}
            onClick={() => setTab(k)}
            className="inline-flex items-center gap-1.5 h-9 px-3 text-[12.5px] font-bold transition-all"
            style={
              tab === k
                ? {
                    borderRadius: "4px",
                    border: "1px solid var(--color-ink)",
                    background: "var(--color-ink)",
                    color: "var(--color-on-dark)",
                  }
                : {
                    borderRadius: "4px",
                    border: "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    color: "var(--color-body)",
                  }
            }
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {tab === "policies" && (
        <>
          {stats ? (
            <Section>
              <div
                className="px-4 py-3 flex items-center justify-between"
                style={{ borderBottom: "1px solid var(--color-border)" }}
              >
                <h3
                  className="text-[13px] font-bold"
                  style={{ color: "var(--color-ink)" }}
                >
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
                  const pct = total > 0 ? (wouldDelete / total) * 100 : 0;
                  return (
                    <div
                      key={r.key}
                      className="px-4 py-4"
                      style={{ borderRight: "1px solid var(--color-border)" }}
                    >
                      <div
                        className="text-[10px] font-bold uppercase tracking-[0.12em]"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {r.label}
                      </div>
                      <div className="mt-1.5 flex items-baseline gap-2">
                        <span
                          className="font-mono tabular-nums text-[26px] leading-none font-extrabold tracking-[-0.01em]"
                          style={{
                            color:
                              wouldDelete > 0
                                ? "#FF5630"
                                : "var(--color-ink)",
                          }}
                        >
                          {wouldDelete.toLocaleString()}
                        </span>
                        <span
                          className="text-[12px] font-mono tabular-nums"
                          style={{ color: "var(--color-muted)" }}
                        >
                          / {total.toLocaleString()}
                        </span>
                      </div>
                      <div
                        className="mt-2 h-1 rounded-full overflow-hidden"
                        style={{ background: "var(--color-surface-muted)" }}
                      >
                        <div
                          className="h-full"
                          style={{
                            width: `${pct}%`,
                            background: "rgba(255,86,48,0.7)",
                          }}
                        />
                      </div>
                      <div
                        className="text-[10.5px] font-mono tabular-nums mt-2"
                        style={{ color: "var(--color-muted)" }}
                      >
                        oldest: {oldest ? formatDate(oldest).split(",")[0] : "—"}
                      </div>
                    </div>
                  );
                })}
              </div>
            </Section>
          ) : null}

          {lastCleanup && lastCleanup.length > 0 ? (
            <Section>
              <div
                className="px-4 py-3"
                style={{ borderBottom: "1px solid var(--color-border)" }}
              >
                <h3
                  className="text-[13px] font-bold"
                  style={{ color: "var(--color-ink)" }}
                >
                  Last cleanup run
                </h3>
              </div>
              <div className="px-4 py-3 space-y-2">
                {lastCleanup.map((r) => (
                  <div
                    key={r.policy_id}
                    className="flex items-center gap-3 text-[12.5px]"
                  >
                    <span
                      className="font-mono tabular-nums w-[64px]"
                      style={{ color: "var(--color-muted)" }}
                    >
                      policy {r.policy_id.slice(-6).toUpperCase()}
                    </span>
                    <span
                      className="font-mono tabular-nums font-bold w-[80px]"
                      style={{ color: "var(--color-ink)" }}
                    >
                      −{r.total_deleted.toLocaleString()}
                    </span>
                    <span
                      className="font-mono text-[11px] truncate"
                      style={{ color: "var(--color-body)" }}
                    >
                      raw={r.raw_intel_deleted} · alerts={r.alerts_deleted} ·
                      audit={r.audit_logs_deleted} · ioc={r.iocs_deleted} · news=
                      {r.news_articles_deleted} · probe={r.live_probes_deleted} ·
                      dlp={r.dlp_findings_deleted} · cards=
                      {r.card_leakage_findings_deleted} · dmarc=
                      {r.dmarc_reports_deleted} · sla=
                      {r.sla_breach_events_deleted}
                    </span>
                  </div>
                ))}
              </div>
            </Section>
          ) : null}

          <Section>
            <div
              className="px-4 py-3"
              style={{ borderBottom: "1px solid var(--color-border)" }}
            >
              <h3
                className="text-[13px] font-bold"
                style={{ color: "var(--color-ink)" }}
              >
                Retention policies
              </h3>
              <p
                className="text-[11.5px] mt-0.5"
                style={{ color: "var(--color-muted)" }}
              >
                Each row sets the max age (days) per resource type, deletion
                mode, and which compliance frameworks govern this scope.
              </p>
            </div>
            {loading ? (
              <SkeletonRows rows={3} columns={6} />
            ) : policies.length === 0 ? (
              <Empty
                icon={ClipboardList}
                title="No retention policies"
                description="Create at least one default policy to enable cleanup."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr
                      style={{
                        background: "var(--color-surface)",
                        borderBottom: "1px solid var(--color-border)",
                      }}
                    >
                      <Th align="left" className="pl-4">
                        Scope
                      </Th>
                      <Th align="left" className="w-[64px]">
                        Raw
                      </Th>
                      <Th align="left" className="w-[64px]">
                        Alerts
                      </Th>
                      <Th align="left" className="w-[64px]">
                        Audit
                      </Th>
                      <Th align="left" className="w-[64px]">
                        IOCs
                      </Th>
                      <Th align="left" className="w-[110px]">
                        Mode
                      </Th>
                      <Th align="left">Compliance</Th>
                      <Th align="left" className="w-[100px]">
                        Auto
                      </Th>
                      <Th align="left" className="w-[110px]">
                        Last run
                      </Th>
                      <Th align="right" className="pr-4 w-[120px]">
                        &nbsp;
                      </Th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p) => (
                      <tr
                        key={p.id}
                        className="h-12 transition-colors"
                        style={{
                          borderBottom: "1px solid var(--color-border)",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background =
                            "var(--color-surface)")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = "transparent")
                        }
                      >
                        <td className="pl-4">
                          {p.organization_id ? (
                            <span
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]"
                              style={{
                                borderRadius: "4px",
                                background: "rgba(255,79,0,0.1)",
                                color: "var(--color-accent)",
                              }}
                            >
                              ORG-SCOPED
                            </span>
                          ) : (
                            <span
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]"
                              style={{
                                borderRadius: "4px",
                                background: "rgba(0,187,217,0.1)",
                                color: "#007B8A",
                              }}
                            >
                              DEFAULT
                            </span>
                          )}
                        </td>
                        <DayCell value={p.raw_intel_days} />
                        <DayCell value={p.alerts_days} />
                        <DayCell value={p.audit_logs_days} />
                        <DayCell value={p.iocs_days} />
                        <td
                          className="px-3 text-[11.5px] font-bold"
                          style={{ color: "var(--color-body)" }}
                        >
                          {DELETION_MODE_LABEL[p.deletion_mode] ||
                            p.deletion_mode}
                        </td>
                        <td className="px-3">
                          <ComplianceChips
                            ids={p.compliance_mappings || []}
                            frameworks={frameworks}
                          />
                        </td>
                        <td className="px-3">
                          {p.auto_cleanup_enabled ? (
                            <StatePill label="ON" tone="success" />
                          ) : (
                            <StatePill label="OFF" tone="muted" />
                          )}
                        </td>
                        <td
                          className="px-3 font-mono text-[11.5px] tabular-nums"
                          style={{ color: "var(--color-muted)" }}
                        >
                          {p.last_cleanup_at
                            ? timeAgo(p.last_cleanup_at)
                            : "never"}
                        </td>
                        <td className="pr-4 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button
                              onClick={() => setEditTarget(p)}
                              className="inline-flex items-center gap-1 h-7 px-2 text-[11px] font-bold transition-colors"
                              style={{
                                borderRadius: "4px",
                                border: "1px solid var(--color-border)",
                                background: "var(--color-canvas)",
                                color: "var(--color-body)",
                              }}
                            >
                              EDIT
                            </button>
                            <button
                              onClick={() => remove(p)}
                              className="p-1.5 transition-colors"
                              style={{
                                borderRadius: "4px",
                                color: "var(--color-muted)",
                              }}
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
        </>
      )}

      {tab === "dsar" && (
        <DsarTab orgs={orgs} orgId={orgId} />
      )}

      {tab === "attestation" && (
        <AttestationTab orgs={orgs} orgId={orgId} />
      )}

      {showCreate && (
        <PolicyModal
          orgId={orgId || null}
          orgs={orgs}
          frameworks={frameworks}
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
          frameworks={frameworks}
          onClose={() => setEditTarget(null)}
          onSaved={() => {
            setEditTarget(null);
            load();
          }}
        />
      )}
      {dryRunPreview && (
        <DryRunModal
          preview={dryRunPreview}
          onClose={() => setDryRunPreview(null)}
          onConfirm={confirmCleanup}
          busy={cleanupRunning}
        />
      )}
      {showTranslate && (
        <TranslateModal
          frameworks={frameworks}
          onClose={() => setShowTranslate(false)}
        />
      )}
    </div>
  );
}

// ----------------------------------------------------------- chips & cells

function ComplianceChips({
  ids,
  frameworks,
}: {
  ids: string[];
  frameworks: RetentionComplianceFramework[];
}) {
  if (!ids || ids.length === 0) {
    return (
      <span
        className="text-[11px] font-mono"
        style={{ color: "var(--color-muted)" }}
      >
        —
      </span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {ids.slice(0, 4).map((id) => {
        const fw = frameworks.find((f) => f.id === id);
        const short = labelForFramework(id);
        return (
          <span
            key={id}
            title={fw?.name || id}
            className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.04em]"
            style={{
              borderRadius: "4px",
              background: chipColor(id).bg,
              color: chipColor(id).fg,
            }}
          >
            {short}
          </span>
        );
      })}
      {ids.length > 4 ? (
        <span
          className="text-[10.5px]"
          style={{ color: "var(--color-muted)" }}
        >
          +{ids.length - 4}
        </span>
      ) : null}
    </div>
  );
}

function labelForFramework(id: string): string {
  if (id.startsWith("gdpr")) return "GDPR";
  if (id.startsWith("ccpa")) return "CCPA";
  if (id.startsWith("hipaa")) return "HIPAA";
  if (id.startsWith("pci")) return "PCI";
  if (id.startsWith("sox")) return "SOX";
  if (id.startsWith("dora")) return "DORA";
  if (id.startsWith("iso")) return "ISO";
  if (id.startsWith("nist")) return "NIST";
  return id.slice(0, 8).toUpperCase();
}

function chipColor(id: string): { bg: string; fg: string } {
  if (id.startsWith("gdpr")) return { bg: "rgba(0,82,204,0.1)", fg: "#0747A6" };
  if (id.startsWith("ccpa")) return { bg: "rgba(0,135,90,0.1)", fg: "#006644" };
  if (id.startsWith("hipaa")) return { bg: "rgba(101,84,192,0.1)", fg: "#403294" };
  if (id.startsWith("pci")) return { bg: "rgba(255,86,48,0.1)", fg: "#B71D18" };
  if (id.startsWith("sox")) return { bg: "rgba(255,171,0,0.1)", fg: "#974F0C" };
  if (id.startsWith("dora")) return { bg: "rgba(0,184,217,0.1)", fg: "#006B7A" };
  return { bg: "rgba(94,108,132,0.1)", fg: "#42526E" };
}

function DayCell({ value }: { value: number }) {
  return (
    <td
      className="px-3 font-mono text-[12.5px] tabular-nums"
      style={{ color: "var(--color-body)" }}
    >
      {value}
      <span
        className="text-[10px] font-bold ml-1"
        style={{ color: "var(--color-muted)" }}
      >
        d
      </span>
    </td>
  );
}

// ----------------------------------------------------------- DryRun modal

function DryRunModal({
  preview,
  onClose,
  onConfirm,
  busy,
}: {
  preview: RetentionCleanupResult[];
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
}) {
  const totals = useMemo(() => {
    return preview.reduce(
      (acc, p) => {
        acc.total += p.total_deleted;
        acc.raw += p.raw_intel_deleted;
        acc.alerts += p.alerts_deleted;
        acc.audit += p.audit_logs_deleted;
        acc.iocs += p.iocs_deleted;
        acc.news += p.news_articles_deleted;
        acc.dlp += p.dlp_findings_deleted;
        acc.cards += p.card_leakage_findings_deleted;
        acc.dmarc += p.dmarc_reports_deleted;
        return acc;
      },
      {
        total: 0,
        raw: 0,
        alerts: 0,
        audit: 0,
        iocs: 0,
        news: 0,
        dlp: 0,
        cards: 0,
        dmarc: 0,
      },
    );
  }, [preview]);

  const breakdown = [
    { label: "Raw intel", value: totals.raw },
    { label: "Alerts", value: totals.alerts },
    { label: "Audit logs", value: totals.audit },
    { label: "IOCs", value: totals.iocs },
    { label: "News articles", value: totals.news },
    { label: "DLP findings", value: totals.dlp },
    { label: "Card leakage", value: totals.cards },
    { label: "DMARC reports", value: totals.dmarc },
  ];

  return (
    <ModalShell
      title="Confirm retention cleanup"
      onClose={onClose}
      width={620}
    >
      <div className="p-6 space-y-5">
        <div
          className="p-3 flex items-start gap-2 text-[12.5px]"
          style={{
            borderRadius: "4px",
            background: "rgba(255,86,48,0.08)",
            color: "#B71D18",
            border: "1px solid rgba(255,86,48,0.3)",
          }}
        >
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            This dry-run shows what <strong>would</strong> be deleted now. No
            rows have been removed yet. Confirm to proceed; legal-hold rows are
            always preserved.
          </div>
        </div>
        <div>
          <div
            className="text-[10.5px] font-bold tracking-[0.12em] uppercase mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Total deletions across {preview.length} polic
            {preview.length === 1 ? "y" : "ies"}
          </div>
          <div
            className="font-mono tabular-nums text-[40px] font-extrabold tracking-[-0.02em] leading-none"
            style={{ color: "#B71D18" }}
          >
            −{totals.total.toLocaleString()}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {breakdown.map((b) => (
            <div
              key={b.label}
              className="flex items-baseline justify-between px-3 py-2"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
              }}
            >
              <span
                className="text-[11.5px] font-bold"
                style={{ color: "var(--color-body)" }}
              >
                {b.label}
              </span>
              <span
                className="font-mono tabular-nums text-[14px] font-bold"
                style={{
                  color: b.value > 0 ? "#B71D18" : "var(--color-muted)",
                }}
              >
                −{b.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={onConfirm}
        submitLabel={busy ? "Running…" : "Confirm cleanup"}
        disabled={busy || totals.total === 0}
      />
    </ModalShell>
  );
}

// --------------------------------------------------------- Translate modal

function TranslateModal({
  frameworks,
  onClose,
}: {
  frameworks: RetentionComplianceFramework[];
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<RetentionRegulationSuggestion | null>(
    null,
  );

  const submit = async () => {
    if (text.trim().length < 20) {
      toast("error", "Paste at least a paragraph of regulation text");
      return;
    }
    setBusy(true);
    try {
      const r = await api.retention.translateRegulation({ regulation_text: text });
      setResult(r);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Translation failed",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Regulation → Policy translator" onClose={onClose} width={720}>
      <div className="p-6 space-y-4">
        <Field label="Regulation text" required hint="Paste the article or section.">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={8}
            className="w-full p-3 text-[12.5px] font-mono"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
              outline: "none",
            }}
            placeholder="Personal data shall be kept in a form which permits identification of data subjects for no longer than is necessary…"
          />
        </Field>
        {result ? (
          <div
            className="p-3 space-y-2 text-[12.5px]"
            style={{
              borderRadius: "4px",
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
            }}
          >
            <div className="font-bold" style={{ color: "var(--color-ink)" }}>
              Suggested policy
            </div>
            <div className="grid grid-cols-2 gap-2 font-mono tabular-nums">
              <div>raw_intel_days: {result.raw_intel_days}</div>
              <div>alerts_days: {result.alerts_days}</div>
              <div>audit_logs_days: {result.audit_logs_days}</div>
              <div>iocs_days: {result.iocs_days}</div>
              <div>deletion_mode: {result.deletion_mode}</div>
              <div>
                mappings:{" "}
                {result.compliance_mappings.length > 0
                  ? result.compliance_mappings.join(", ")
                  : "—"}
              </div>
            </div>
            {Object.keys(result.rationale_per_class || {}).length > 0 && (
              <div>
                <div
                  className="text-[10.5px] font-bold uppercase tracking-[0.12em] mt-2"
                  style={{ color: "var(--color-muted)" }}
                >
                  Rationale
                </div>
                <ul className="text-[11.5px] mt-1 space-y-0.5">
                  {Object.entries(result.rationale_per_class).map(([k, v]) => (
                    <li key={k}>
                      <strong>{k}:</strong> {v}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div
              className="text-[10.5px] mt-2"
              style={{ color: "var(--color-muted)" }}
            >
              model: {result.model_id || "—"} · frameworks catalog: {frameworks.length}
            </div>
          </div>
        ) : null}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Translating…" : "Translate"}
        disabled={busy}
      />
    </ModalShell>
  );
}

// ----------------------------------------------------------- DSAR tab

function DsarTab({ orgs, orgId }: { orgs: Org[]; orgId: string }) {
  const { toast } = useToast();
  const [items, setItems] = useState<DsarRequestResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [drawerId, setDrawerId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.retention.listDsar({
        organization_id: orgId || undefined,
        limit: 100,
      });
      setItems(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load DSARs");
    } finally {
      setLoading(false);
    }
  }, [toast, orgId]);

  useEffect(() => {
    if (orgId) load();
  }, [load, orgId]);

  return (
    <Section>
      <div
        className="px-4 py-3 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div>
          <h3
            className="text-[13px] font-bold"
            style={{ color: "var(--color-ink)" }}
          >
            Data Subject Access Requests
          </h3>
          <p
            className="text-[11.5px] mt-0.5"
            style={{ color: "var(--color-muted)" }}
          >
            GDPR Art.15/17, CCPA §1798.105, HIPAA §164.524 — intake, scan,
            draft, close. Bridge-LLM agent walks every PII-bearing table for
            matches.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            className="inline-flex items-center gap-1 h-9 px-3 text-[12px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="inline-flex items-center gap-1 h-9 px-3 text-[12px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            New DSAR
          </button>
        </div>
      </div>

      {loading ? (
        <SkeletonRows rows={4} columns={5} />
      ) : items.length === 0 ? (
        <Empty
          icon={FileText}
          title="No DSAR requests"
          description="Open one to record a subject's data access / erasure request."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr
                style={{
                  background: "var(--color-surface)",
                  borderBottom: "1px solid var(--color-border)",
                }}
              >
                <Th align="left" className="pl-4">Subject</Th>
                <Th align="left">Type</Th>
                <Th align="left">Regulation</Th>
                <Th align="left">Status</Th>
                <Th align="left">Matched</Th>
                <Th align="left">Deadline</Th>
                <Th align="right" className="pr-4">&nbsp;</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((d) => (
                <tr
                  key={d.id}
                  className="h-12 transition-colors cursor-pointer"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onClick={() => setDrawerId(d.id)}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background =
                      "var(--color-surface)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <td className="pl-4">
                    <div
                      className="text-[12.5px] font-bold"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {d.subject_email || d.subject_name || d.subject_phone || d.subject_id_other || "—"}
                    </div>
                    {d.subject_name && d.subject_email ? (
                      <div
                        className="text-[10.5px]"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {d.subject_name}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <span
                      className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em] uppercase"
                      style={{
                        borderRadius: "4px",
                        background: "rgba(94,108,132,0.1)",
                        color: "#42526E",
                      }}
                    >
                      {d.request_type}
                    </span>
                  </td>
                  <td
                    className="text-[11.5px] font-mono"
                    style={{ color: "var(--color-body)" }}
                  >
                    {d.regulation || "—"}
                  </td>
                  <td>
                    <DsarStatusPill status={d.status} />
                  </td>
                  <td
                    className="font-mono tabular-nums text-[12px]"
                    style={{ color: "var(--color-body)" }}
                  >
                    {d.matched_row_count} rows · {d.matched_tables.length} tables
                  </td>
                  <td
                    className="font-mono tabular-nums text-[11.5px]"
                    style={{
                      color:
                        d.deadline_at &&
                        new Date(d.deadline_at).getTime() < Date.now() &&
                        d.status !== "closed"
                          ? "#B71D18"
                          : "var(--color-muted)",
                    }}
                  >
                    {d.deadline_at ? deadlineCountdown(d.deadline_at) : "—"}
                  </td>
                  <td className="pr-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setDrawerId(d.id);
                      }}
                      className="inline-flex items-center h-7 px-2 text-[11px] font-bold"
                      style={{
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                        background: "var(--color-canvas)",
                        color: "var(--color-body)",
                      }}
                    >
                      OPEN
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <DsarCreateModal
          orgs={orgs}
          orgId={orgId}
          onClose={() => setShowCreate(false)}
          onSaved={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}
      {drawerId && (
        <DsarDrawer
          dsarId={drawerId}
          onClose={() => setDrawerId(null)}
          onChanged={() => load()}
        />
      )}
    </Section>
  );
}

function DsarStatusPill({ status }: { status: string }) {
  const map: Record<string, { tone: "success" | "muted" | "warning" | "info"; label: string }> = {
    received: { tone: "info", label: "RECEIVED" },
    scanning: { tone: "warning", label: "SCANNING" },
    ready_for_review: { tone: "warning", label: "REVIEW" },
    exported: { tone: "success", label: "EXPORTED" },
    closed: { tone: "muted", label: "CLOSED" },
    denied: { tone: "muted", label: "DENIED" },
  };
  const { tone, label } = map[status] || { tone: "muted", label: status };
  return <StatePill label={label} tone={tone} />;
}

function deadlineCountdown(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) {
    const overdue = Math.abs(Math.floor(ms / 86400000));
    return `${overdue}d overdue`;
  }
  const days = Math.floor(ms / 86400000);
  if (days >= 1) return `${days}d left`;
  const hrs = Math.floor(ms / 3600000);
  return `${hrs}h left`;
}

function DsarCreateModal({
  orgs,
  orgId,
  onClose,
  onSaved,
}: {
  orgs: Org[];
  orgId: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [body, setBody] = useState<DsarCreatePayload>({
    organization_id: orgId,
    subject_email: "",
    subject_name: "",
    subject_phone: "",
    request_type: "access",
    regulation: "gdpr",
    deadline_days: 30,
  });
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (
      !body.subject_email &&
      !body.subject_name &&
      !body.subject_phone &&
      !body.subject_id_other
    ) {
      toast("error", "At least one subject identifier is required");
      return;
    }
    setBusy(true);
    try {
      await api.retention.createDsar(body);
      toast("success", "DSAR opened");
      onSaved();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to create DSAR");
    } finally {
      setBusy(false);
    }
  };

  const update = <K extends keyof DsarCreatePayload>(
    k: K,
    v: DsarCreatePayload[K],
  ) => setBody((b) => ({ ...b, [k]: v }));

  return (
    <ModalShell title="Open DSAR" onClose={onClose} width={620}>
      <div className="p-6 space-y-4">
        <Field label="Organisation" required>
          <ThemedSelect
            value={body.organization_id}
            onChange={(v) => update("organization_id", v)}
            ariaLabel="organisation"
            options={orgs.map((o) => ({ value: o.id, label: o.name }))}
            style={{ width: "100%" }}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Subject email">
            <TextInput
              value={body.subject_email || ""}
              onChange={(v) => update("subject_email", v)}
              placeholder="alice@example.com"
            />
          </Field>
          <Field label="Subject name">
            <TextInput
              value={body.subject_name || ""}
              onChange={(v) => update("subject_name", v)}
              placeholder="Alice Smith"
            />
          </Field>
          <Field label="Subject phone">
            <TextInput
              value={body.subject_phone || ""}
              onChange={(v) => update("subject_phone", v)}
              placeholder="+44 …"
            />
          </Field>
          <Field label="Other identifier">
            <TextInput
              value={body.subject_id_other || ""}
              onChange={(v) => update("subject_id_other", v)}
              placeholder="customer-id, …"
            />
          </Field>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Request type" required>
            <ThemedSelect
              value={body.request_type}
              onChange={(v) => update("request_type", v as DsarRequestType)}
              ariaLabel="type"
              options={[
                { value: "access", label: "Access" },
                { value: "erasure", label: "Erasure" },
                { value: "portability", label: "Portability" },
                { value: "rectification", label: "Rectification" },
                { value: "restriction", label: "Restriction" },
              ]}
              style={{ width: "100%" }}
            />
          </Field>
          <Field label="Regulation">
            <ThemedSelect
              value={body.regulation || "gdpr"}
              onChange={(v) => update("regulation", v)}
              ariaLabel="regulation"
              options={[
                { value: "gdpr", label: "GDPR" },
                { value: "ccpa", label: "CCPA" },
                { value: "hipaa", label: "HIPAA" },
                { value: "lgpd", label: "LGPD" },
                { value: "pdpl", label: "PDPL" },
              ]}
              style={{ width: "100%" }}
            />
          </Field>
          <Field label="Deadline (days)">
            <TextInput
              value={String(body.deadline_days || 30)}
              onChange={(v) => update("deadline_days", Math.max(1, Number(v) || 30))}
              placeholder="30"
            />
          </Field>
        </div>
        <Field label="Notes" hint="Internal context. Not sent to the subject.">
          <textarea
            value={body.notes || ""}
            onChange={(e) => update("notes", e.target.value)}
            rows={3}
            className="w-full p-2.5 text-[12.5px]"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
              outline: "none",
            }}
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Opening…" : "Open DSAR"}
        disabled={busy}
      />
    </ModalShell>
  );
}

function DsarDrawer({
  dsarId,
  onClose,
  onChanged,
}: {
  dsarId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [item, setItem] = useState<DsarRequestResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<string>("");
  const [closing, setClosing] = useState(false);
  const [closeReason, setCloseReason] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.retention.getDsar(dsarId);
      setItem(r);
      setDraft(r.draft_response || "");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load DSAR");
    }
  }, [dsarId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  // Poll while scanning so the matched_tables populate.
  useEffect(() => {
    if (!item) return;
    if (item.status === "scanning") {
      const id = setInterval(() => load(), 4000);
      return () => clearInterval(id);
    }
  }, [item, load]);

  const scan = async () => {
    setBusy(true);
    try {
      const r = await api.retention.scanDsar(dsarId);
      setItem(r);
      toast("success", "Scan queued — refreshing automatically");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  };

  const draftResp = async () => {
    setBusy(true);
    try {
      await api.retention.draftDsarResponse(dsarId);
      toast("success", "Letter drafting queued");
      // Poll briefly; bridge usually replies within 30s.
      setTimeout(() => load(), 6000);
      setTimeout(() => load(), 15000);
      setTimeout(() => load(), 30000);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Draft failed");
    } finally {
      setBusy(false);
    }
  };

  const saveDraft = async () => {
    setBusy(true);
    try {
      const r = await api.retention.updateDsarDraft(dsarId, draft);
      setItem(r);
      toast("success", "Draft saved");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const submitClose = async () => {
    if (!closeReason.trim()) {
      toast("error", "Close reason is required");
      return;
    }
    setBusy(true);
    try {
      await api.retention.closeDsar(dsarId, {
        closed_reason: closeReason,
        final_response: draft || undefined,
      });
      toast("success", "DSAR closed");
      onChanged();
      onClose();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Close failed");
    } finally {
      setBusy(false);
    }
  };

  if (!item) {
    return (
      <ModalShell title="DSAR" onClose={onClose} width={780}>
        <div className="p-6">
          <SkeletonRows rows={4} columns={1} />
        </div>
      </ModalShell>
    );
  }

  return (
    <ModalShell
      title={`DSAR · ${item.request_type.toUpperCase()}`}
      onClose={onClose}
      width={780}
    >
      <div className="p-6 space-y-5">
        <div className="grid grid-cols-3 gap-3 text-[12px]">
          <KV label="Subject email" value={item.subject_email || "—"} />
          <KV label="Subject name" value={item.subject_name || "—"} />
          <KV label="Phone" value={item.subject_phone || "—"} />
          <KV label="Regulation" value={(item.regulation || "—").toUpperCase()} />
          <KV label="Status" value={item.status} />
          <KV
            label="Deadline"
            value={
              item.deadline_at
                ? `${formatDate(item.deadline_at).split(",")[0]} (${deadlineCountdown(item.deadline_at)})`
                : "—"
            }
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={scan}
            disabled={busy || item.status === "closed"}
            className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${item.status === "scanning" ? "animate-spin" : ""}`} />
            {item.status === "scanning" ? "Scanning…" : "Run scan"}
          </button>
          <button
            onClick={draftResp}
            disabled={
              busy ||
              item.status === "closed" ||
              (item.matched_tables.length === 0 && item.status !== "ready_for_review")
            }
            className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <FileText className="w-3.5 h-3.5" />
            Draft response
          </button>
        </div>

        {item.matched_tables.length > 0 ? (
          <div
            className="p-3"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-surface)",
            }}
          >
            <div
              className="text-[10.5px] font-bold uppercase tracking-[0.12em] mb-2"
              style={{ color: "var(--color-muted)" }}
            >
              Matched tables — {item.matched_row_count} total rows
            </div>
            <div className="space-y-1 text-[12px] font-mono tabular-nums">
              {Object.entries(item.match_summary || {}).map(([tbl, info]) => (
                <div key={tbl} className="flex items-baseline justify-between">
                  <span style={{ color: "var(--color-ink)" }}>{tbl}</span>
                  <span style={{ color: "var(--color-body)" }}>
                    {info.count} row{info.count === 1 ? "" : "s"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div
            className="p-3 text-[12px]"
            style={{
              borderRadius: "4px",
              border: "1px dashed var(--color-border)",
              color: "var(--color-muted)",
            }}
          >
            {item.status === "scanning"
              ? "Scanner agent running — this drawer auto-refreshes every 4s."
              : "No PII-bearing tables scanned yet. Run scan to populate."}
          </div>
        )}

        <div>
          <div
            className="text-[10.5px] font-bold uppercase tracking-[0.12em] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Draft response (markdown)
          </div>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={12}
            className="w-full p-3 text-[12.5px] font-mono"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
              outline: "none",
            }}
            placeholder="The Bridge agent will populate this when you click Draft response. Edit freely before close."
          />
          <div className="flex items-center gap-2 mt-2">
            <button
              onClick={saveDraft}
              disabled={busy}
              className="inline-flex items-center h-8 px-3 text-[11.5px] font-bold disabled:opacity-50"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              Save draft
            </button>
          </div>
        </div>

        {!closing ? (
          <button
            onClick={() => setClosing(true)}
            disabled={busy || item.status === "closed"}
            className="inline-flex items-center h-9 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Close DSAR
          </button>
        ) : (
          <div
            className="p-3 space-y-2"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-surface)",
            }}
          >
            <Field label="Close reason" required>
              <TextInput
                value={closeReason}
                onChange={setCloseReason}
                placeholder="Fulfilled / Refused — duplicate / Refused — identity not verified / …"
              />
            </Field>
            <div className="flex items-center gap-2">
              <button
                onClick={submitClose}
                disabled={busy}
                className="inline-flex items-center h-8 px-3 text-[11.5px] font-bold disabled:opacity-50"
                style={{
                  borderRadius: "4px",
                  background: "#B71D18",
                  color: "var(--color-on-dark)",
                }}
              >
                {busy ? "Closing…" : "Confirm close"}
              </button>
              <button
                onClick={() => setClosing(false)}
                className="inline-flex items-center h-8 px-3 text-[11.5px] font-bold"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-body)",
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </ModalShell>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div
        className="text-[10.5px] font-bold uppercase tracking-[0.12em]"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <div
        className="text-[12.5px] font-mono mt-0.5"
        style={{ color: "var(--color-ink)" }}
      >
        {value}
      </div>
    </div>
  );
}

// ----------------------------------------------------------- Attestation tab

function AttestationTab({ orgs, orgId }: { orgs: Org[]; orgId: string }) {
  const { toast } = useToast();
  const [items, setItems] = useState<RetentionAttestationResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState(90);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<RetentionAttestationResponse | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.retention.listAttestations({
        organization_id: orgId || undefined,
        limit: 50,
      });
      setItems(r);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load attestations",
      );
    } finally {
      setLoading(false);
    }
  }, [toast, orgId]);

  useEffect(() => {
    if (orgId) load();
  }, [load, orgId]);

  const generate = async () => {
    setBusy(true);
    try {
      await api.retention.generateAttestation({
        organization_id: orgId || undefined,
        period_days: period,
      });
      toast("success", `Generation queued — ${period} day window`);
      // Bridge takes ~30-60s.
      setTimeout(() => load(), 8000);
      setTimeout(() => load(), 25000);
      setTimeout(() => load(), 60000);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Generate failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section>
      <div
        className="px-4 py-3 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div>
          <h3
            className="text-[13px] font-bold"
            style={{ color: "var(--color-ink)" }}
          >
            Compliance attestations
          </h3>
          <p
            className="text-[11.5px] mt-0.5"
            style={{ color: "var(--color-muted)" }}
          >
            Bridge-LLM aggregates policies, cleanup runs, legal-hold counts,
            and DSAR activity into an audit-grade Markdown report.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            max={3650}
            value={period}
            onChange={(e) => setPeriod(Math.max(1, Number(e.target.value) || 90))}
            className="h-9 w-[80px] px-2 font-mono tabular-nums text-[12px]"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
              outline: "none",
            }}
          />
          <span
            className="text-[10.5px] font-bold"
            style={{ color: "var(--color-muted)" }}
          >
            DAYS
          </span>
          <button
            onClick={load}
            className="inline-flex items-center gap-1 h-9 px-3 text-[12px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
          <button
            onClick={generate}
            disabled={busy}
            className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            {busy ? "Queued…" : "Generate"}
          </button>
        </div>
      </div>

      {loading ? (
        <SkeletonRows rows={3} columns={3} />
      ) : items.length === 0 ? (
        <Empty
          icon={ShieldCheck}
          title="No attestations yet"
          description="Generate one to capture the current compliance posture."
        />
      ) : (
        <div className="px-4 py-3 space-y-2">
          {items.map((a) => (
            <button
              key={a.id}
              onClick={() => setOpen(a)}
              className="w-full text-left p-3 transition-colors"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "var(--color-surface)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background = "var(--color-canvas)")
              }
            >
              <div className="flex items-center justify-between">
                <div
                  className="text-[12.5px] font-bold"
                  style={{ color: "var(--color-ink)" }}
                >
                  Attestation · {formatDate(a.created_at).split(",")[0]}
                </div>
                <span
                  className="text-[10.5px] font-mono"
                  style={{ color: "var(--color-muted)" }}
                >
                  {a.window_start
                    ? formatDate(a.window_start).split(",")[0]
                    : "—"}{" "}
                  →{" "}
                  {a.window_end
                    ? formatDate(a.window_end).split(",")[0]
                    : "—"}
                </span>
              </div>
              <div
                className="text-[11.5px] mt-1 line-clamp-2"
                style={{ color: "var(--color-body)" }}
              >
                {a.summary_md.slice(0, 280)}…
              </div>
              <div
                className="text-[10.5px] font-mono mt-1"
                style={{ color: "var(--color-muted)" }}
              >
                model: {a.model_id || "—"} · policies: {a.rows_summarised}
              </div>
            </button>
          ))}
        </div>
      )}

      {open && (
        <AttestationViewer item={open} onClose={() => setOpen(null)} />
      )}
    </Section>
  );
}

function AttestationViewer({
  item,
  onClose,
}: {
  item: RetentionAttestationResponse;
  onClose: () => void;
}) {
  return (
    <ModalShell title="Compliance attestation" onClose={onClose} width={820}>
      <div className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <div
            className="text-[10.5px] font-bold uppercase tracking-[0.12em]"
            style={{ color: "var(--color-muted)" }}
          >
            Generated {formatDate(item.created_at)}
          </div>
          <button
            onClick={() => {
              navigator.clipboard.writeText(item.summary_md);
            }}
            className="inline-flex items-center h-7 px-2 text-[11px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Copy
          </button>
        </div>
        <pre
          className="text-[12.5px] whitespace-pre-wrap font-mono p-3"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
            maxHeight: "60vh",
            overflowY: "auto",
          }}
        >
          {item.summary_md}
        </pre>
      </div>
    </ModalShell>
  );
}

// ----------------------------------------------------------- Policy modal

function PolicyModal({
  policy,
  orgId,
  orgs,
  frameworks,
  onClose,
  onSaved,
}: {
  policy?: RetentionPolicyResponse;
  orgId: string | null;
  orgs: Org[];
  frameworks: RetentionComplianceFramework[];
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
  const [redactPii, setRedactPii] = useState(policy?.redact_pii ?? true);
  const [autoCleanup, setAutoCleanup] = useState(
    policy?.auto_cleanup_enabled ?? true,
  );
  const [deletionMode, setDeletionMode] = useState<RetentionDeletionMode>(
    policy?.deletion_mode || "hard_delete",
  );
  const [mappings, setMappings] = useState<string[]>(
    policy?.compliance_mappings || [],
  );
  const [description, setDescription] = useState(policy?.description || "");
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
          deletion_mode: deletionMode,
          compliance_mappings: mappings,
          description: description || null,
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
          deletion_mode: deletionMode,
          compliance_mappings: mappings,
          description: description || null,
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

  const toggleMapping = (id: string) => {
    setMappings((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));
  };

  return (
    <ModalShell
      title={policy ? "Edit retention policy" : "New retention policy"}
      onClose={onClose}
      width={720}
    >
      <div className="p-6 space-y-5">
        {!policy ? (
          <Field label="Scope" required>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                onClick={() => setScope("default")}
                className="h-10 flex items-center justify-center text-[12px] font-bold transition-all"
                style={
                  scope === "default"
                    ? {
                        borderRadius: "4px",
                        border: "1px solid var(--color-ink)",
                        background: "var(--color-canvas)",
                        color: "var(--color-ink)",
                        boxShadow: "0 0 0 2px rgba(32,21,21,0.08)",
                      }
                    : {
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                        background: "var(--color-canvas)",
                        color: "var(--color-body)",
                      }
                }
              >
                DEFAULT (all orgs)
              </button>
              <button
                onClick={() => setScope("org")}
                className="h-10 flex items-center justify-center text-[12px] font-bold transition-all"
                style={
                  scope === "org"
                    ? {
                        borderRadius: "4px",
                        border: "1px solid var(--color-ink)",
                        background: "var(--color-canvas)",
                        color: "var(--color-ink)",
                        boxShadow: "0 0 0 2px rgba(32,21,21,0.08)",
                      }
                    : {
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                        background: "var(--color-canvas)",
                        color: "var(--color-body)",
                      }
                }
              >
                ORG-SCOPED
              </button>
            </div>
            {scope === "org" ? (
              <div className="mt-2">
                <ThemedSelect
                  value={scopedOrgId}
                  onChange={setScopedOrgId}
                  ariaLabel="Scope organisation"
                  options={orgs.map((o) => ({ value: o.id, label: o.name }))}
                  style={{ width: "100%" }}
                />
              </div>
            ) : null}
          </Field>
        ) : null}

        <div className="grid grid-cols-4 gap-3">
          <DayField label="Raw intel" value={rawDays} onChange={setRawDays} />
          <DayField label="Alerts" value={alertsDays} onChange={setAlertsDays} />
          <DayField label="Audit logs" value={auditDays} onChange={setAuditDays} />
          <DayField label="IOCs" value={iocsDays} onChange={setIocsDays} />
        </div>

        <Field label="Deletion mode" required>
          <div className="grid grid-cols-3 gap-1.5">
            {(
              ["hard_delete", "soft_delete", "anonymise"] as RetentionDeletionMode[]
            ).map((m) => (
              <button
                key={m}
                onClick={() => setDeletionMode(m)}
                className="h-10 flex items-center justify-center text-[12px] font-bold transition-all"
                style={
                  deletionMode === m
                    ? {
                        borderRadius: "4px",
                        border: "1px solid var(--color-ink)",
                        background: "var(--color-canvas)",
                        color: "var(--color-ink)",
                        boxShadow: "0 0 0 2px rgba(32,21,21,0.08)",
                      }
                    : {
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                        background: "var(--color-canvas)",
                        color: "var(--color-body)",
                      }
                }
              >
                {DELETION_MODE_LABEL[m]}
              </button>
            ))}
          </div>
        </Field>

        <Field
          label="Compliance mappings"
          hint="Tag this policy with the regulations it satisfies. Conflict scanner enforces minimum windows."
        >
          <div
            className="grid grid-cols-2 gap-1.5 p-2"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-surface)",
              maxHeight: "200px",
              overflowY: "auto",
            }}
          >
            {frameworks.map((fw) => {
              const checked = mappings.includes(fw.id);
              return (
                <button
                  key={fw.id}
                  onClick={() => toggleMapping(fw.id)}
                  title={fw.full_text}
                  className="flex items-start gap-2 text-left p-2 transition-colors"
                  style={{
                    borderRadius: "4px",
                    border: checked
                      ? "1px solid var(--color-accent)"
                      : "1px solid var(--color-border)",
                    background: checked
                      ? "rgba(255,79,0,0.05)"
                      : "var(--color-canvas)",
                  }}
                >
                  <span
                    className="shrink-0 w-3.5 h-3.5 mt-0.5"
                    style={{
                      borderRadius: "3px",
                      border: "1.5px solid var(--color-border)",
                      background: checked ? "var(--color-accent)" : "transparent",
                    }}
                  />
                  <span className="flex-1 min-w-0">
                    <div
                      className="text-[11.5px] font-bold leading-tight"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {fw.name}
                    </div>
                    <div
                      className="text-[10.5px] font-mono mt-0.5"
                      style={{ color: "var(--color-muted)" }}
                    >
                      default {fw.default_retention_days}d
                    </div>
                  </span>
                </button>
              );
            })}
          </div>
        </Field>

        <Field label="Description" hint="Internal note for auditors.">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            className="w-full p-2.5 text-[12.5px]"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
              outline: "none",
            }}
          />
        </Field>

        <div className="space-y-2">
          <ToggleRow
            label="Redact PII before delete"
            hint="Anonymises PII columns rather than dropping the row entirely. Triggers the pre-purge knowledge preserver agent."
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

// ----------------------------------------------------------- shared inputs

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
    <Field label={label} hint="Max age in days. 0 disables.">
      <div className="relative">
        <input
          type="number"
          min={0}
          max={3650}
          value={value}
          onChange={(e) => onChange(Math.max(0, Number(e.target.value) || 0))}
          className="w-full h-10 pl-3 pr-10 font-mono tabular-nums"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
            outline: "none",
          }}
        />
        <span
          className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] font-bold uppercase tracking-[0.06em]"
          style={{ color: "var(--color-muted)" }}
        >
          d
        </span>
      </div>
    </Field>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full h-10 px-3 text-[12.5px]"
      style={{
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        color: "var(--color-ink)",
        outline: "none",
      }}
    />
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
        <div
          className="text-[13px] font-bold"
          style={{ color: "var(--color-ink)" }}
        >
          {label}
        </div>
        <div
          className="text-[11.5px] mt-0.5"
          style={{ color: "var(--color-muted)" }}
        >
          {hint}
        </div>
      </div>
    </button>
  );
}
