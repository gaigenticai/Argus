"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowUpRight,
  Briefcase,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleX,
  ExternalLink,
  Loader2,
  RefreshCw,
  Sparkles,
  Wrench,
} from "lucide-react";
import {
  api,
  type InvestigationDetail,
  type InvestigationListItem,
  type InvestigationStatus,
  type InvestigationTraceStep,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";


const STATUS_TONE: Record<InvestigationStatus, StateTone> = {
  queued: "neutral",
  running: "info",
  completed: "success",
  failed: "error",
};

const SEVERITY_TONE: Record<string, StateTone> = {
  critical: "error-strong",
  high: "error",
  medium: "warning",
  low: "info",
  informational: "muted",
};


export default function InvestigationsPage() {
  const { toast } = useToast();
  const [rows, setRows] = useState<InvestigationListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.investigations.list({ limit: 100 });
      setRows(data);
      // Auto-select the first row if nothing's picked yet.
      if (data.length > 0 && !selectedId) {
        setSelectedId(data[0].id);
      }
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load investigations",
      );
    } finally {
      setLoading(false);
    }
  }, [selectedId, toast]);

  const loadDetail = useCallback(
    async (id: string) => {
      setDetailLoading(true);
      try {
        const d = await api.investigations.get(id);
        setDetail(d);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load investigation",
        );
      } finally {
        setDetailLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    void loadList();
  }, [loadList]);

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
  }, [selectedId, loadDetail]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Investigations"
        description={
          "Agentic SOC analyst — runs a real observe → reason → act loop " +
          "against high-severity alerts. Five tools, max six iterations, " +
          "every step audited."
        }
        actions={<RefreshButton onClick={loadList} refreshing={loading} />}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left — list */}
        <Section className="lg:col-span-5">
          <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
              Recent investigations
            </h3>
            <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>{rows.length} total</span>
          </div>
          {loading ? (
            <SkeletonRows rows={6} columns={3} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Sparkles}
              title="No investigations yet"
              description={
                "Investigations are kicked off automatically on HIGH and " +
                "CRITICAL alerts. You can also trigger one manually from " +
                "any alert detail page."
              }
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">Status</Th>
                  <Th align="left" className="w-[110px]">Severity</Th>
                  <Th align="left">Alert</Th>
                  <Th align="right" className="pr-4 w-[100px]">Started</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <InvestigationRow
                    key={r.id}
                    r={r}
                    isActive={r.id === selectedId}
                    onClick={() => setSelectedId(r.id)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </Section>

        {/* Right — detail */}
        <div className="lg:col-span-7">
          {detail ? (
            <InvestigationDetailPanel
              detail={detail}
              loading={detailLoading}
              onAfterPromote={(caseId) => {
                // Optimistic update so the button flips to "View case"
                // even if the user navigates back before the next refetch.
                setDetail({ ...detail, case_id: caseId });
                setRows((prev) =>
                  prev.map((r) =>
                    r.id === detail.id ? { ...r, case_id: caseId } : r,
                  ),
                );
              }}
            />
          ) : (
            <Section>
              <Empty
                icon={Sparkles}
                title="Select an investigation"
                description="Click a row on the left to inspect the trace, IOCs, and recommended actions."
              />
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}


function InvestigationRow({
  r,
  isActive,
  onClick,
}: {
  r: InvestigationListItem;
  isActive: boolean;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: isActive ? "rgba(0,187,217,0.07)" : hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <StatusPill status={r.status} />
      </td>
      <td className="px-3">
        {r.severity_assessment ? (
          <StatePill
            label={r.severity_assessment}
            tone={SEVERITY_TONE[r.severity_assessment.toLowerCase()] || "neutral"}
          />
        ) : (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td style={{ padding: "0 12px", fontFamily: "monospace", fontSize: "12px", color: "var(--color-body)", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
          {r.alert_id.slice(0, 8)}…
          {r.case_id ? (
            <Briefcase style={{ width: "12px", height: "12px", color: "#007B55" }} aria-label="promoted to case" />
          ) : null}
        </span>
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.created_at)}
      </td>
    </tr>
  );
}

function StatusPill({ status }: { status: InvestigationStatus }) {
  const Icon = {
    queued: CircleDashed,
    running: Loader2,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<InvestigationStatus, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    queued: { background: "var(--color-surface-muted)", color: "var(--color-body)" },
    failed: { background: "rgba(255,86,48,0.08)", color: "#B71D18" },
  };

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "6px",
      height: "22px",
      padding: "0 8px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
      ...styleMap[status],
    }}>
      <Icon style={{ width: "12px", height: "12px" }} className={status === "running" ? "animate-spin" : undefined} />
      {status}
    </span>
  );
}


function InvestigationDetailPanel({
  detail,
  loading,
  onAfterPromote,
}: {
  detail: InvestigationDetail;
  loading: boolean;
  onAfterPromote: (caseId: string) => void;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [promoting, setPromoting] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set([1]));
  const toggle = (n: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });
  };

  const handlePromote = useCallback(async () => {
    setPromoting(true);
    try {
      const res = await api.investigations.promote(detail.id);
      if (res.already_promoted) {
        toast("info", "Already promoted — opening the linked case");
      } else {
        toast("success", `Case created — ${res.case_id.slice(0, 8)}…`);
      }
      onAfterPromote(res.case_id);
      router.push(`/cases/${res.case_id}`);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to promote investigation",
      );
    } finally {
      setPromoting(false);
    }
  }, [detail.id, onAfterPromote, router, toast]);

  return (
    <Section>
      <div className="px-4 py-3 flex items-center justify-between gap-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
        <div className="min-w-0">
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Investigation {detail.id.slice(0, 8)}…
          </h3>
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
            Alert{" "}
            <span style={{ fontFamily: "monospace" }}>{detail.alert_id.slice(0, 12)}…</span>
            {" · "}
            {detail.iterations} step{detail.iterations === 1 ? "" : "s"}
            {detail.model_id ? ` · ${detail.model_id}` : ""}
            {detail.duration_ms ? ` · ${(detail.duration_ms / 1000).toFixed(1)}s` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {detail.status === "completed" && detail.case_id ? (
            <ViewCaseButton onClick={() => router.push(`/cases/${detail.case_id!}`)}>
              <Briefcase style={{ width: "14px", height: "14px" }} />
              View case
              <ExternalLink style={{ width: "12px", height: "12px" }} />
            </ViewCaseButton>
          ) : detail.status === "completed" ? (
            <PromoteButton onClick={handlePromote} disabled={promoting}>
              {promoting ? (
                <Loader2 style={{ width: "14px", height: "14px" }} className="animate-spin" />
              ) : (
                <ArrowUpRight style={{ width: "14px", height: "14px" }} />
              )}
              Promote to case
            </PromoteButton>
          ) : null}
          <StatusPill status={detail.status} />
        </div>
      </div>

      {loading ? (
        <SkeletonRows rows={6} columns={2} />
      ) : (
        <div className="p-5 space-y-5">
          {detail.status === "failed" && detail.error_message ? (
            <div role="alert" style={{ display: "flex", alignItems: "flex-start", gap: "12px", borderRadius: "5px", border: "1px solid rgba(255,86,48,0.4)", background: "rgba(255,86,48,0.08)", padding: "12px 16px" }}>
              <AlertTriangle style={{ width: "20px", height: "20px", marginTop: "2px", color: "#B71D18", flexShrink: 0 }} />
              <div>
                <p style={{ fontSize: "13px", fontWeight: 700, color: "#B71D18" }}>Investigation failed</p>
                <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "2px", fontFamily: "monospace" }}>{detail.error_message}</p>
              </div>
            </div>
          ) : null}

          {detail.final_assessment ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>Final assessment</h4>
              <p style={{ fontSize: "14px", lineHeight: 1.55, color: "var(--color-ink)" }}>{detail.final_assessment}</p>
            </section>
          ) : null}

          {detail.correlated_actors.length > 0 || detail.correlated_iocs.length > 0 ? (
            <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {detail.correlated_actors.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>Suspected actors</h4>
                  <ul className="space-y-1">
                    {detail.correlated_actors.map((a) => (
                      <li key={a} style={{ fontSize: "13px", color: "var(--color-ink)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#B71D18", display: "inline-block" }} />
                        {a}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {detail.correlated_iocs.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>Correlated IOCs</h4>
                  <ul className="space-y-1">
                    {detail.correlated_iocs.map((ioc) => (
                      <li key={ioc} style={{ fontSize: "12px", fontFamily: "monospace", color: "var(--color-ink)" }} className="truncate">{ioc}</li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          ) : null}

          {detail.recommended_actions.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>Recommended actions</h4>
              <ul className="space-y-1.5">
                {detail.recommended_actions.map((a) => (
                  <li key={a} style={{ fontSize: "13px", color: "var(--color-ink)", display: "flex", alignItems: "flex-start", gap: "8px" }}>
                    <span style={{ marginTop: "4px", width: "14px", height: "14px", borderRadius: "3px", border: "1px solid var(--color-border)", flexShrink: 0 }} />
                    {a}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {detail.trace && detail.trace.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                Trace · {detail.trace.length} step{detail.trace.length === 1 ? "" : "s"}
              </h4>
              <ol className="space-y-2">
                {detail.trace.map((s) => (
                  <TraceStepCard key={s.iteration} step={s} isOpen={expanded.has(s.iteration)} onToggle={() => toggle(s.iteration)} />
                ))}
              </ol>
            </section>
          ) : null}
        </div>
      )}
    </Section>
  );
}


function ViewCaseButton({
  onClick,
  children,
}: {
  onClick: () => void;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "30px",
        padding: "0 12px",
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface-muted)" : "var(--color-canvas)",
        color: "var(--color-body)",
        fontSize: "12px",
        fontWeight: 700,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function PromoteButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled: boolean;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "30px",
        padding: "0 12px",
        borderRadius: "4px",
        border: "none",
        background: disabled ? "var(--color-surface-muted)" : hov ? "#e64600" : "var(--color-accent)",
        color: disabled ? "var(--color-muted)" : "var(--color-on-dark)",
        fontSize: "12px",
        fontWeight: 700,
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function TraceStepCard({
  step,
  isOpen,
  onToggle,
}: {
  step: InvestigationTraceStep;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <li style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-surface)", overflow: "hidden" }}>
      <button
        onClick={onToggle}
        onMouseEnter={() => setHov(true)}
        onMouseLeave={() => setHov(false)}
        style={{
          width: "100%",
          padding: "8px 12px",
          display: "flex",
          alignItems: "center",
          gap: "8px",
          textAlign: "left",
          background: hov ? "var(--color-surface-muted)" : "transparent",
          border: "none",
          cursor: "pointer",
          transition: "background 0.15s",
        }}
      >
        {isOpen ? (
          <ChevronDown style={{ width: "14px", height: "14px", color: "var(--color-muted)", flexShrink: 0 }} />
        ) : (
          <ChevronRight style={{ width: "14px", height: "14px", color: "var(--color-muted)", flexShrink: 0 }} />
        )}
        <span style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", width: "60px", flexShrink: 0 }}>
          Step {step.iteration}
        </span>
        {step.tool ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "12px", fontFamily: "monospace", color: "var(--color-accent)" }}>
            <Wrench style={{ width: "12px", height: "12px" }} />
            {step.tool}
          </span>
        ) : (
          <span style={{ fontSize: "12px", color: "var(--color-muted)", fontStyle: "italic" }}>(thinking only)</span>
        )}
      </button>
      {isOpen ? (
        <div style={{ padding: "0 12px 12px 12px", display: "flex", flexDirection: "column", gap: "8px" }}>
          <p style={{ fontSize: "12.5px", color: "var(--color-body)", fontStyle: "italic" }}>"{step.thought}"</p>
          {step.args ? (
            <pre style={{ fontSize: "11px", fontFamily: "monospace", background: "var(--color-border-strong)", color: "var(--color-on-dark)", padding: "8px 12px", borderRadius: "4px", overflowX: "auto" }}>
              {JSON.stringify(step.args, null, 2)}
            </pre>
          ) : null}
          {step.result !== null && step.result !== undefined ? (
            <pre style={{ fontSize: "11px", fontFamily: "monospace", background: "var(--color-border-strong)", color: "var(--color-on-dark)", padding: "8px 12px", borderRadius: "4px", overflowX: "auto", maxHeight: "300px", overflow: "auto" }}>
              {JSON.stringify(step.result, null, 2)}
            </pre>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
