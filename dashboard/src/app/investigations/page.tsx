"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  Briefcase,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleX,
  Clock,
  Diff,
  ExternalLink,
  GitCompare,
  Loader2,
  PauseCircle,
  Play,
  RefreshCw,
  RotateCw,
  Sparkles,
  Wrench,
} from "lucide-react";
import {
  api,
  SSE_BASE,  // eslint-disable-line @typescript-eslint/no-unused-vars
  type InvestigationDetail,
  type InvestigationListItem,
  type InvestigationPlanStep,
  type InvestigationStatus,
  type InvestigationStopReason,
  type InvestigationTraceStep,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";
import { estimateCostUsd, formatCostUsd } from "@/lib/llm-cost";

import { ToolResult } from "./_components/tool-renderers";
import { TOOL_META, toolLabel, type ToolName } from "./_components/tool-meta";
import { RunInvestigationModal } from "./_components/run-investigation-modal";


const STATUS_TONE: Record<InvestigationStatus, StateTone> = {
  queued: "neutral",
  running: "info",
  awaiting_plan_approval: "warning",
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

const STATUSES: Array<{ value: InvestigationStatus | "all"; label: string }> = [
  { value: "all", label: "Any status" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "awaiting_plan_approval", label: "Awaiting plan approval" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
];

// Friendly explanations for each stop reason — surfaced in the detail
// header so the analyst knows whether to trust the verdict.
const STOP_REASON_LABEL: Record<InvestigationStopReason, string> = {
  high_confidence: "High confidence",
  max_iterations: "Max iterations reached",
  no_new_evidence: "No new evidence",
  llm_error: "LLM error",
  user_aborted: "User aborted",
};
const STOP_REASON_TONE: Record<InvestigationStopReason, string> = {
  high_confidence: "#22C55E",
  max_iterations: "#FFAB00",
  no_new_evidence: "var(--color-muted)",
  llm_error: "#B71D18",
  user_aborted: "var(--color-muted)",
};


// Wrap the page so useSearchParams() is allowed in client component.
export default function InvestigationsPageWrapper() {
  return (
    <Suspense fallback={null}>
      <InvestigationsPage />
    </Suspense>
  );
}

function InvestigationsPage() {
  const { toast } = useToast();
  const router = useRouter();
  const searchParams = useSearchParams();

  const urlStatus = (searchParams.get("status") as InvestigationStatus | "all" | null) || "all";
  const urlSelectedId = searchParams.get("id");
  const urlAlertId = searchParams.get("alert");

  const [rows, setRows] = useState<InvestigationListItem[]>([]);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showRunModal, setShowRunModal] = useState(false);
  // Compare flow — operator picks two investigations against the same
  // alert and we open a diff modal.
  const [compareIds, setCompareIds] = useState<[string | null, string | null]>([null, null]);

  const setUrlParam = useCallback(
    (key: string, value: string | null) => {
      const next = new URLSearchParams(searchParams.toString());
      if (value === null || value === "" || value === "all") {
        next.delete(key);
      } else {
        next.set(key, value);
      }
      const qs = next.toString();
      router.replace(qs ? `/investigations?${qs}` : "/investigations");
    },
    [router, searchParams],
  );

  const setSelectedId = useCallback(
    (id: string | null) => setUrlParam("id", id),
    [setUrlParam],
  );

  // List loader — re-runs when the status filter / alert filter changes.
  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const params: { limit: number; status?: string; alert_id?: string } = { limit: 200 };
      if (urlStatus !== "all") params.status = urlStatus;
      if (urlAlertId) params.alert_id = urlAlertId;
      const data = await api.investigations.list(params);
      setRows(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load investigations",
      );
    } finally {
      setLoading(false);
    }
  }, [urlStatus, urlAlertId, toast]);

  // Auto-select the first row when no ?id is set. Re-runs whenever the
  // list changes (filter switch, refresh) so a stale selection doesn't
  // linger.
  useEffect(() => {
    if (urlSelectedId) return;
    if (rows.length > 0) {
      setSelectedId(rows[0].id);
    }
  }, [rows, urlSelectedId, setSelectedId]);

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
    if (urlSelectedId) void loadDetail(urlSelectedId);
    else setDetail(null);
  }, [urlSelectedId, loadDetail]);

  // Live SSE — when the selected investigation is running / queued /
  // awaiting plan approval, subscribe to /stream and append events
  // as they arrive. Closes on the "stopped" event or detail change.
  useEffect(() => {
    if (!detail) return;
    if (detail.status === "completed" || detail.status === "failed") return;
    const url = api.investigations.streamUrl(detail.id);
    const es = new EventSource(url, { withCredentials: true });
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data) as {
          kind?: string;
          iteration?: number;
          tool?: string | null;
          thought?: string;
          args?: Record<string, unknown> | null;
          result?: unknown;
          duration_ms?: number | null;
          status?: string;
          stop_reason?: string | null;
          final_confidence?: number | null;
          replay?: boolean;
        };
        if (data.kind === "step") {
          setDetail((prev) => {
            if (!prev || prev.id !== detail.id) return prev;
            const trace = prev.trace || [];
            // Skip duplicates from replay during reconnects.
            if (
              data.iteration !== undefined
              && trace.some((s) => s.iteration === data.iteration)
            ) {
              return prev;
            }
            const next: InvestigationTraceStep = {
              iteration: data.iteration ?? trace.length + 1,
              thought: data.thought ?? "",
              tool: data.tool ?? null,
              args: data.args ?? null,
              result: data.result ?? null,
              duration_ms: data.duration_ms ?? null,
            };
            return { ...prev, trace: [...trace, next], iterations: next.iteration };
          });
        } else if (data.kind === "stopped") {
          setDetail((prev) => {
            if (!prev || prev.id !== detail.id) return prev;
            return {
              ...prev,
              status: (data.status as InvestigationStatus) || prev.status,
              stop_reason: (data.stop_reason as InvestigationStopReason) || prev.stop_reason,
              final_confidence: data.final_confidence ?? prev.final_confidence,
            };
          });
          // Refresh from DB once after stop so we pick up any
          // server-side post-processing (auto-promote case_id etc.).
          void loadDetail(detail.id);
          void loadList();
          es.close();
        } else if (data.kind === "plan") {
          // Plan-then-act gate just emitted a plan — refresh detail to
          // pull the persisted ``plan`` array, status will flip to
          // awaiting_plan_approval.
          void loadDetail(detail.id);
          void loadList();
        }
      } catch {
        /* ignore malformed events */
      }
    };
    es.onerror = () => {
      // Browser auto-reconnects on transient failures; explicit close
      // happens on stopped event. No-op here.
    };
    return () => {
      es.close();
    };
  }, [detail?.id, detail?.status, loadDetail, loadList]);

  // Fallback polling — if SSE drops/misses (network blip, agent finishes
  // between initial detail load and stream open) we'd otherwise be stuck
  // on "Waiting for the agent to emit its first step…" forever. Poll the
  // DB every 4s while queued/running and refresh from the list every 8s
  // so newly-completed runs flip without manual reload.
  useEffect(() => {
    if (!detail) return;
    if (detail.status !== "queued" && detail.status !== "running") return;
    const detailTimer = setInterval(() => {
      void loadDetail(detail.id);
    }, 4000);
    const listTimer = setInterval(() => {
      void loadList();
    }, 8000);
    return () => {
      clearInterval(detailTimer);
      clearInterval(listTimer);
    };
  }, [detail?.id, detail?.status, loadDetail, loadList]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Investigations"
        description={
          "Agentic SOC analyst — runs a real observe → reason → act loop "
          + "against high-severity alerts. Five tools, max six iterations, "
          + "every step audited and streamable."
        }
        actions={
          <>
            <Link
              href="/investigations/stats"
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Investigation analytics — success rate, top tools, stop reasons"
            >
              <BarChart3 style={{ width: 13, height: 13 }} />
              Stats
            </Link>
            <RefreshButton onClick={loadList} refreshing={loading} />
            <button
              onClick={() => setShowRunModal(true)}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
            >
              <Play style={{ width: 13, height: 13 }} />
              Run new
            </button>
          </>
        }
      />

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="Status"
          value={urlStatus}
          onChange={(v) => setUrlParam("status", v)}
          options={STATUSES.map((s) => ({ value: s.value, label: s.label }))}
        />
        {urlAlertId ? (
          <span
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[11px] font-bold"
            style={{
              borderRadius: 4,
              background: "rgba(255,79,0,0.08)",
              color: "var(--color-accent)",
              border: "1px solid rgba(255,79,0,0.3)",
            }}
            title={`Filtered to investigations on alert ${urlAlertId}`}
          >
            alert={urlAlertId.slice(0, 8)}…
            <button
              onClick={() => setUrlParam("alert", null)}
              aria-label="Clear alert filter"
              style={{
                background: "transparent",
                border: "none",
                color: "var(--color-accent)",
                cursor: "pointer",
                padding: 0,
                fontSize: 14,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </span>
        ) : null}
        <span style={{ fontSize: 11, color: "var(--color-muted)" }}>
          {rows.length} {rows.length === 1 ? "result" : "results"}
        </span>
      </div>

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
              title="No investigations match"
              description={
                urlStatus !== "all" || urlAlertId
                  ? "Try removing a filter to see more."
                  : "Investigations are kicked off automatically on HIGH and CRITICAL alerts. You can also run one manually with the button above."
              }
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">Status</Th>
                  <Th align="left" className="w-[80px]">Sev</Th>
                  <Th align="left">Alert</Th>
                  <Th align="right" className="pr-4 w-[80px]">Started</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <InvestigationRow
                    key={r.id}
                    r={r}
                    isActive={r.id === urlSelectedId}
                    isCompareCandidate={compareIds.includes(r.id)}
                    compareDisabledFor={
                      // A row is compare-disabled when (a) we're already
                      // mid-pick on a different alert, or (b) the row
                      // would be the same id as the first pick.
                      compareIds[0] !== null
                      && compareIds[1] === null
                      && rows.find((x) => x.id === compareIds[0])?.alert_id !== r.alert_id
                    }
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
              compareIds={compareIds}
              setCompareIds={setCompareIds}
              onAfterPromote={(caseId) => {
                setDetail({ ...detail, case_id: caseId });
                setRows((prev) =>
                  prev.map((r) =>
                    r.id === detail.id ? { ...r, case_id: caseId } : r,
                  ),
                );
              }}
              onRefresh={() => {
                void loadList();
                void loadDetail(detail.id);
              }}
              onSelect={setSelectedId}
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

      {showRunModal && (
        <RunInvestigationModal
          onClose={() => setShowRunModal(false)}
          onCreated={(newId) => {
            setShowRunModal(false);
            setSelectedId(newId);
            void loadList();
          }}
        />
      )}

      {compareIds[0] !== null && compareIds[1] !== null && (
        <CompareModal
          aId={compareIds[0]}
          bId={compareIds[1]}
          onClose={() => setCompareIds([null, null])}
        />
      )}
    </div>
  );
}


// ---------------------------------------------------------------------
// List row
// ---------------------------------------------------------------------

function InvestigationRow({
  r,
  isActive,
  isCompareCandidate,
  compareDisabledFor,
  onClick,
}: {
  r: InvestigationListItem;
  isActive: boolean;
  isCompareCandidate: boolean;
  compareDisabledFor: boolean;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "56px",
        borderBottom: "1px solid var(--color-border)",
        background: isActive
          ? "rgba(0,187,217,0.07)"
          : isCompareCandidate
            ? "rgba(255,79,0,0.05)"
            : hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
        opacity: compareDisabledFor ? 0.4 : 1,
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
        ) : r.alert_severity ? (
          <span
            style={{
              padding: "1px 6px",
              borderRadius: 3,
              background: "var(--color-surface-muted)",
              color: "var(--color-body)",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
            title="Severity from the seed alert (agent has not yet emitted a verdict)"
          >
            {r.alert_severity}
          </span>
        ) : (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td style={{ padding: "0 12px", fontSize: 12, color: "var(--color-body)", maxWidth: "320px", overflow: "hidden" }}>
        <div
          style={{
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            color: "var(--color-ink)",
            fontWeight: 500,
            display: "flex",
            alignItems: "center",
            gap: 4,
          }}
          title={r.alert_title || r.alert_id}
        >
          {r.alert_title || r.alert_id.slice(0, 8) + "…"}
          {r.case_id ? (
            <Briefcase
              style={{ width: 11, height: 11, color: "#007B55", flexShrink: 0 }}
              aria-label="promoted to case"
            />
          ) : null}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 10.5,
            color: "var(--color-muted)",
            marginTop: 2,
          }}
        >
          {r.alert_category ? (
            <span style={{ fontFamily: "monospace", fontSize: 10 }}>{r.alert_category}</span>
          ) : null}
          {r.tools_used && r.tools_used.length > 0 ? (
            <>
              <span>·</span>
              <span>
                {r.tools_used.length} {r.tools_used.length === 1 ? "tool" : "tools"}
              </span>
            </>
          ) : null}
          {typeof r.final_confidence === "number" ? (
            <>
              <span>·</span>
              <span style={{ fontFamily: "monospace" }}>
                {Math.round(r.final_confidence * 100)}%
              </span>
            </>
          ) : null}
        </div>
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
    awaiting_plan_approval: PauseCircle,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<InvestigationStatus, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    awaiting_plan_approval: { background: "rgba(255,171,0,0.12)", color: "#B76E00" },
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
      fontSize: "10.5px",
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
      ...styleMap[status],
    }}>
      <Icon style={{ width: "12px", height: "12px" }} className={status === "running" ? "animate-spin" : undefined} />
      {status.replace(/_/g, " ")}
    </span>
  );
}


// ---------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------

function InvestigationDetailPanel({
  detail,
  loading,
  compareIds,
  setCompareIds,
  onAfterPromote,
  onRefresh,
  onSelect,
}: {
  detail: InvestigationDetail;
  loading: boolean;
  compareIds: [string | null, string | null];
  setCompareIds: (next: [string | null, string | null]) => void;
  onAfterPromote: (caseId: string) => void;
  onRefresh: () => void;
  onSelect: (id: string) => void;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [promoting, setPromoting] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set([1]));
  const traceEndRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll the trace as new live steps arrive.
  const isStreaming = detail.status === "running" || detail.status === "queued";
  useEffect(() => {
    if (isStreaming && traceEndRef.current) {
      traceEndRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [detail.iterations, isStreaming]);

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

  const handleRerun = useCallback(async (extra_context?: string) => {
    setRetrying(true);
    try {
      const res = await api.investigations.rerun(detail.id, extra_context);
      toast("success", "Rerun queued");
      onSelect(res.id);
      onRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to rerun investigation",
      );
    } finally {
      setRetrying(false);
    }
  }, [detail.id, onSelect, onRefresh, toast]);

  const handleApprovePlan = useCallback(async (plan?: InvestigationPlanStep[]) => {
    try {
      await api.investigations.approvePlan(detail.id, plan);
      toast("success", "Plan approved — agent resuming");
      onRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to approve plan",
      );
    }
  }, [detail.id, onRefresh, toast]);

  const totalDuration = useMemo(() => {
    if (detail.duration_ms) return detail.duration_ms;
    return (detail.trace || []).reduce((acc, s) => acc + (s.duration_ms || 0), 0);
  }, [detail.duration_ms, detail.trace]);

  // Estimated cost — rates externalised in src/lib/llm-cost.ts. The
  // helper returns null when any input is missing rather than guess.
  const estCostUsd = useMemo(
    () => estimateCostUsd(
      detail.model_id, detail.input_tokens, detail.output_tokens,
    ),
    [detail.input_tokens, detail.output_tokens, detail.model_id],
  );

  const compareToggle = () => {
    if (compareIds[0] === null) {
      setCompareIds([detail.id, null]);
    } else if (compareIds[0] === detail.id) {
      // Cancel the in-flight pick.
      setCompareIds([null, null]);
    } else {
      // Second pick — fire the diff.
      setCompareIds([compareIds[0], detail.id]);
    }
  };
  const compareLabel = compareIds[0] === null
    ? "Compare"
    : compareIds[0] === detail.id
      ? "Cancel compare"
      : "Compare with this";

  return (
    <Section>
      <header
        style={{
          padding: "10px 16px 12px",
          borderBottom: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0, flex: 1 }}>
          <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
            Investigation {detail.id.slice(0, 8)}…
          </h3>
          <div
            style={{
              fontSize: 11.5,
              color: "var(--color-muted)",
              marginTop: 4,
              display: "flex",
              alignItems: "center",
              gap: 6,
              flexWrap: "wrap",
            }}
          >
            <Link
              href={`/alerts/${detail.alert_id}`}
              style={{
                color: "var(--color-accent)",
                textDecoration: "none",
                display: "inline-flex",
                alignItems: "center",
                gap: 3,
                fontWeight: 600,
              }}
            >
              {detail.alert_title || `Alert ${detail.alert_id.slice(0, 8)}…`}
              <ExternalLink style={{ width: 11, height: 11 }} />
            </Link>
            <span>·</span>
            <span>
              {detail.iterations} step{detail.iterations === 1 ? "" : "s"}
            </span>
            {totalDuration ? (
              <>
                <span>·</span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 2 }}>
                  <Clock style={{ width: 11, height: 11 }} />
                  {(totalDuration / 1000).toFixed(1)}s
                </span>
              </>
            ) : null}
            {detail.model_id ? (
              <>
                <span>·</span>
                <span style={{ fontFamily: "monospace" }}>{detail.model_id}</span>
              </>
            ) : null}
            {estCostUsd !== null ? (
              <>
                <span>·</span>
                <span
                  style={{ fontFamily: "monospace" }}
                  title="Estimated cost using published model list price (see src/lib/llm-cost.ts)"
                >
                  ~{formatCostUsd(estCostUsd)}
                </span>
              </>
            ) : null}
          </div>
          {/* Stop reason + final confidence */}
          {detail.stop_reason || typeof detail.final_confidence === "number" ? (
            <div
              style={{
                marginTop: 6,
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                fontSize: 11,
              }}
            >
              {detail.stop_reason ? (
                <span
                  style={{
                    padding: "1px 6px",
                    borderRadius: 3,
                    background: "var(--color-surface-muted)",
                    color: STOP_REASON_TONE[detail.stop_reason] || "var(--color-body)",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    fontSize: 9.5,
                  }}
                >
                  {STOP_REASON_LABEL[detail.stop_reason] || detail.stop_reason}
                </span>
              ) : null}
              {typeof detail.final_confidence === "number" ? (
                <span style={{ color: "var(--color-body)", fontFamily: "monospace" }}>
                  {Math.round(detail.final_confidence * 100)}% confidence
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="flex items-center gap-2 flex-wrap" style={{ flexShrink: 0 }}>
          {detail.status === "failed" ? (
            <button
              onClick={() => handleRerun()}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Retry on the same alert with a fresh agent loop"
            >
              {retrying ? (
                <Loader2 style={{ width: 12, height: 12 }} className="animate-spin" />
              ) : (
                <RotateCw style={{ width: 12, height: 12 }} />
              )}
              Retry
            </button>
          ) : null}
          {detail.status === "completed" ? (
            <button
              onClick={() => {
                const note = window.prompt(
                  "Optional analyst note for the rerun (e.g. 'check IOCs a.com, b.com'). Leave blank to retry as-is.",
                ) || undefined;
                void handleRerun(note);
              }}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Run a new investigation on the same alert (e.g. after new IOCs landed)"
            >
              {retrying ? (
                <Loader2 style={{ width: 12, height: 12 }} className="animate-spin" />
              ) : (
                <RotateCw style={{ width: 12, height: 12 }} />
              )}
              Re-run
            </button>
          ) : null}
          {detail.status === "completed" ? (
            <button
              onClick={compareToggle}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: compareIds[0] === detail.id ? "1px solid var(--color-accent)" : "1px solid var(--color-border)",
                background: compareIds[0] === detail.id ? "rgba(255,79,0,0.08)" : "var(--color-canvas)",
                color: compareIds[0] === detail.id ? "var(--color-accent)" : "var(--color-body)",
              }}
              title={
                compareIds[0] === null
                  ? "Pick this run, then pick another on the same alert to diff"
                  : compareIds[0] === detail.id
                    ? "Cancel compare picking"
                    : "Diff with the previously picked run"
              }
            >
              <GitCompare style={{ width: 12, height: 12 }} />
              {compareLabel}
            </button>
          ) : null}
          {detail.status === "completed" && detail.case_id ? (
            <button
              onClick={() => router.push(`/cases/${detail.case_id!}`)}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              <Briefcase style={{ width: 13, height: 13 }} />
              View case
              <ExternalLink style={{ width: 11, height: 11 }} />
            </button>
          ) : detail.status === "completed" ? (
            <button
              onClick={handlePromote}
              disabled={promoting}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
            >
              {promoting ? (
                <Loader2 style={{ width: 12, height: 12 }} className="animate-spin" />
              ) : (
                <ArrowUpRight style={{ width: 13, height: 13 }} />
              )}
              Promote to case
            </button>
          ) : null}
          <StatusPill status={detail.status} />
        </div>
      </header>

      {loading ? (
        <SkeletonRows rows={6} columns={2} />
      ) : (
        <div className="p-5 space-y-5">
          {detail.status === "failed" && detail.error_message ? (
            <div
              role="alert"
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "12px",
                borderRadius: "5px",
                border: "1px solid rgba(255,86,48,0.4)",
                background: "rgba(255,86,48,0.08)",
                padding: "12px 16px",
              }}
            >
              <AlertTriangle style={{ width: "20px", height: "20px", marginTop: "2px", color: "#B71D18", flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: "13px", fontWeight: 700, color: "#B71D18" }}>Investigation failed</p>
                <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "2px", fontFamily: "monospace", wordBreak: "break-word" }}>
                  {detail.error_message}
                </p>
              </div>
            </div>
          ) : null}

          {detail.status === "awaiting_plan_approval" && detail.plan ? (
            <PlanApprovalGate
              plan={detail.plan}
              onApprove={handleApprovePlan}
            />
          ) : null}

          {/* Tools-used summary chips */}
          {detail.tools_used && detail.tools_used.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "6px" }}>
                Tools used
              </h4>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {detail.tools_used.map((t) => (
                  <span
                    key={t}
                    title={(TOOL_META as Record<string, { description: string }>)[t]?.description || t}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                      padding: "2px 8px",
                      borderRadius: 999,
                      background: "var(--color-surface-muted)",
                      color: "var(--color-body)",
                      fontSize: 11,
                      fontWeight: 600,
                    }}
                  >
                    <Wrench style={{ width: 10, height: 10, color: "var(--color-accent)" }} />
                    {toolLabel(t)}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {detail.final_assessment ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                Final assessment
              </h4>
              <p style={{ fontSize: "14px", lineHeight: 1.55, color: "var(--color-ink)" }}>
                {detail.final_assessment}
              </p>
            </section>
          ) : null}

          {detail.correlated_actors.length > 0 || detail.correlated_iocs.length > 0 ? (
            <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {detail.correlated_actors.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                    Suspected actors
                  </h4>
                  <ul className="space-y-1">
                    {detail.correlated_actors.map((a) => (
                      <li
                        key={a}
                        style={{
                          fontSize: "13px",
                          color: "var(--color-ink)",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                        }}
                      >
                        <span
                          style={{
                            width: "6px",
                            height: "6px",
                            borderRadius: "50%",
                            background: "#B71D18",
                            display: "inline-block",
                          }}
                        />
                        {a}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {detail.correlated_iocs.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                    Correlated IOCs
                  </h4>
                  <ul className="space-y-1">
                    {detail.correlated_iocs.map((ioc) => (
                      <li
                        key={ioc}
                        style={{
                          fontSize: "12px",
                          fontFamily: "monospace",
                          color: "var(--color-ink)",
                        }}
                        className="truncate"
                      >
                        {ioc}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          ) : null}

          {detail.recommended_actions.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                Recommended actions
              </h4>
              <ul className="space-y-1.5">
                {detail.recommended_actions.map((a) => (
                  <li
                    key={a}
                    style={{
                      fontSize: "13px",
                      color: "var(--color-ink)",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "8px",
                    }}
                  >
                    <CheckCircle2 style={{ width: 14, height: 14, marginTop: 3, color: "var(--color-accent)", flexShrink: 0 }} />
                    {a}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {detail.trace && detail.trace.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px", display: "flex", alignItems: "center", gap: 6 }}>
                Trace · {detail.trace.length} step{detail.trace.length === 1 ? "" : "s"}
                {isStreaming ? (
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 9.5, color: "#007B8A", fontWeight: 700 }}>
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        background: "#007B8A",
                        display: "inline-block",
                      }}
                      className="animate-pulse"
                    />
                    LIVE
                  </span>
                ) : null}
              </h4>
              <ol className="space-y-2">
                {detail.trace.map((s) => (
                  <TraceStepCard
                    key={s.iteration}
                    step={s}
                    isOpen={expanded.has(s.iteration)}
                    onToggle={() => toggle(s.iteration)}
                  />
                ))}
              </ol>
              <div ref={traceEndRef} />
            </section>
          ) : isStreaming ? (
            <div
              style={{
                fontSize: 12.5,
                color: "var(--color-muted)",
                textAlign: "center",
                padding: "24px",
                fontStyle: "italic",
              }}
            >
              Waiting for the agent to emit its first step…
            </div>
          ) : null}
        </div>
      )}
    </Section>
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
          <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "12px", color: "var(--color-accent)", fontWeight: 600 }}>
            <Wrench style={{ width: "12px", height: "12px" }} />
            {toolLabel(step.tool)}
          </span>
        ) : (
          <span style={{ fontSize: "12px", color: "var(--color-muted)", fontStyle: "italic" }}>
            (finalising)
          </span>
        )}
        <span style={{ flex: 1 }} />
        {step.duration_ms ? (
          <span
            style={{
              fontSize: 10.5,
              fontFamily: "monospace",
              color: "var(--color-muted)",
            }}
            title="Iteration duration"
          >
            {(step.duration_ms / 1000).toFixed(1)}s
          </span>
        ) : null}
      </button>
      {isOpen ? (
        <div style={{ padding: "0 12px 12px 12px", display: "flex", flexDirection: "column", gap: 8 }}>
          {step.thought ? (
            <p style={{ fontSize: 12.5, color: "var(--color-body)", fontStyle: "italic", margin: 0 }}>
              &quot;{step.thought}&quot;
            </p>
          ) : null}
          {step.tool && step.args && Object.keys(step.args).length > 0 ? (
            <div>
              <div
                style={{
                  fontSize: 9.5,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--color-muted)",
                  marginBottom: 4,
                }}
              >
                Args
              </div>
              <pre
                style={{
                  fontSize: 11,
                  fontFamily: "monospace",
                  background: "var(--color-canvas)",
                  border: "1px solid var(--color-border)",
                  color: "var(--color-ink)",
                  padding: "6px 10px",
                  borderRadius: 4,
                  margin: 0,
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {JSON.stringify(step.args, null, 2)}
              </pre>
            </div>
          ) : null}
          {step.tool && step.result !== null && step.result !== undefined ? (
            <div>
              <div
                style={{
                  fontSize: 9.5,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--color-muted)",
                  marginBottom: 4,
                }}
              >
                Result
              </div>
              <ToolResult tool={step.tool as ToolName} result={step.result} />
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}


// ---------------------------------------------------------------------
// Plan-then-act gate (T72)
// ---------------------------------------------------------------------

function PlanApprovalGate({
  plan,
  onApprove,
}: {
  plan: InvestigationPlanStep[];
  onApprove: (plan?: InvestigationPlanStep[]) => Promise<void> | void;
}) {
  const [editable, setEditable] = useState<InvestigationPlanStep[]>(plan);
  const [submitting, setSubmitting] = useState(false);
  const [editing, setEditing] = useState(false);

  const submit = async (next?: InvestigationPlanStep[]) => {
    setSubmitting(true);
    try {
      await onApprove(next);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section
      role="region"
      aria-label="Plan approval"
      style={{
        borderRadius: 5,
        border: "1px solid rgba(255,171,0,0.4)",
        background: "rgba(255,171,0,0.06)",
        padding: "12px 16px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <PauseCircle style={{ width: 16, height: 16, color: "#B76E00" }} />
        <h4 style={{ fontSize: 13, fontWeight: 700, color: "#B76E00", margin: 0 }}>
          Plan awaiting approval
        </h4>
      </div>
      <p style={{ fontSize: 12, color: "var(--color-body)", marginBottom: 8 }}>
        The agent has proposed a tool sequence below. Approve to let it execute, or
        edit if you want a different approach.
      </p>
      <ol style={{ margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 4 }}>
        {editable.map((step, idx) => (
          <li
            key={idx}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 8px",
              borderRadius: 4,
              border: "1px solid rgba(255,171,0,0.35)",
              background: "var(--color-canvas)",
            }}
          >
            <span
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                color: "var(--color-muted)",
                width: 16,
                flexShrink: 0,
              }}
            >
              {idx + 1}.
            </span>
            <Wrench style={{ width: 12, height: 12, color: "var(--color-accent)", flexShrink: 0 }} />
            <span style={{ fontFamily: "monospace", fontSize: 12, color: "var(--color-ink)", flexShrink: 0 }}>
              {step.tool || step.kind || "?"}
            </span>
            <span style={{ fontSize: 11.5, color: "var(--color-body)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {step.rationale || step.text || ""}
            </span>
            {editing ? (
              <button
                onClick={() => setEditable(editable.filter((_, i) => i !== idx))}
                aria-label="Remove step"
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--color-muted)",
                  cursor: "pointer",
                  fontSize: 14,
                  lineHeight: 1,
                  padding: 0,
                }}
              >
                ×
              </button>
            ) : null}
          </li>
        ))}
      </ol>
      <div style={{ display: "flex", gap: 8, marginTop: 10, justifyContent: "flex-end" }}>
        {!editing ? (
          <button
            onClick={() => setEditing(true)}
            disabled={submitting}
            className="h-8 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Edit
          </button>
        ) : (
          <button
            onClick={() => {
              setEditable(plan);
              setEditing(false);
            }}
            className="h-8 px-3 text-[12px] font-bold"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Reset
          </button>
        )}
        <button
          onClick={() => submit(editing ? editable : undefined)}
          disabled={submitting || (editing && editable.length === 0)}
          className="h-8 px-3 text-[12px] font-bold disabled:opacity-50"
          style={{
            borderRadius: 4,
            border: "1px solid #22C55E",
            background: "#22C55E",
            color: "#fff",
          }}
        >
          {submitting ? "Approving…" : (editing ? "Apply edited plan" : "Approve plan")}
        </button>
      </div>
    </section>
  );
}


// ---------------------------------------------------------------------
// Compare modal (T71)
// ---------------------------------------------------------------------

function CompareModal({
  aId,
  bId,
  onClose,
}: {
  aId: string;
  bId: string;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [diff, setDiff] = useState<Awaited<ReturnType<typeof api.investigations.compare>> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const d = await api.investigations.compare(aId, bId);
        if (!alive) return;
        setDiff(d);
      } catch (e) {
        if (!alive) return;
        const msg = e instanceof Error ? e.message : "Failed to compare investigations";
        setError(msg);
        toast("error", msg);
      }
    })();
    return () => {
      alive = false;
    };
  }, [aId, bId, toast]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.32)",
          zIndex: 70,
        }}
      />
      <div
        role="dialog"
        aria-label="Compare investigations"
        style={{
          position: "fixed",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          width: "min(720px, 95vw)",
          maxHeight: "90vh",
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 6,
          zIndex: 71,
          boxShadow: "0 16px 48px rgba(0,0,0,0.22)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <header
          style={{
            padding: "14px 18px",
            borderBottom: "1px solid var(--color-border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
          }}
        >
          <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)", display: "flex", alignItems: "center", gap: 8 }}>
            <Diff style={{ width: 14, height: 14 }} />
            Compare {aId.slice(0, 8)}… vs {bId.slice(0, 8)}…
          </h3>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-muted)",
              fontSize: 18,
              cursor: "pointer",
              padding: 0,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </header>
        <div style={{ flex: 1, overflowY: "auto", padding: "14px 18px" }}>
          {error ? (
            <div
              style={{
                fontSize: 12.5,
                color: "var(--color-error)",
                padding: 12,
                border: "1px solid rgba(255,86,48,0.4)",
                background: "rgba(255,86,48,0.06)",
                borderRadius: 4,
              }}
            >
              {error}
            </div>
          ) : !diff ? (
            <div style={{ fontSize: 12, color: "var(--color-muted)", textAlign: "center", padding: 24 }}>
              Loading diff…
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {/* Headline metrics */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                <Metric
                  label="Iteration delta"
                  value={(diff.iteration_delta > 0 ? "+" : "") + diff.iteration_delta}
                />
                <Metric
                  label="Duration delta"
                  value={
                    diff.duration_delta_ms !== null
                      ? `${diff.duration_delta_ms > 0 ? "+" : ""}${(diff.duration_delta_ms / 1000).toFixed(1)}s`
                      : "—"
                  }
                />
                <Metric
                  label="Confidence delta"
                  value={
                    diff.confidence_delta !== null
                      ? `${diff.confidence_delta > 0 ? "+" : ""}${Math.round(diff.confidence_delta * 100)}%`
                      : "—"
                  }
                />
              </div>

              {/* Severity / assessment side-by-side */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                <div style={{ border: "1px solid var(--color-border)", borderRadius: 4, padding: 10 }}>
                  <div style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", marginBottom: 6 }}>
                    Run A · {diff.severity_a || "—"}
                  </div>
                  <p style={{ fontSize: 12.5, color: "var(--color-ink)", margin: 0 }}>
                    {diff.assessment_a || <em style={{ color: "var(--color-muted)" }}>no assessment</em>}
                  </p>
                </div>
                <div style={{ border: "1px solid var(--color-border)", borderRadius: 4, padding: 10 }}>
                  <div style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", marginBottom: 6 }}>
                    Run B · {diff.severity_b || "—"}
                  </div>
                  <p style={{ fontSize: 12.5, color: "var(--color-ink)", margin: 0 }}>
                    {diff.assessment_b || <em style={{ color: "var(--color-muted)" }}>no assessment</em>}
                  </p>
                </div>
              </div>

              <DiffBlock label="IOCs" added={diff.iocs_added} removed={diff.iocs_removed} mono />
              <DiffBlock label="Actors" added={diff.actors_added} removed={diff.actors_removed} />
              <DiffBlock label="Recommended actions" added={diff.actions_added} removed={diff.actions_removed} />
              <DiffBlock label="Tools" added={diff.tools_added} removed={diff.tools_removed} mono />
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ border: "1px solid var(--color-border)", borderRadius: 4, padding: 10 }}>
      <div style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontFamily: "monospace", fontSize: 14, color: "var(--color-ink)", fontWeight: 700 }}>
        {value}
      </div>
    </div>
  );
}

function DiffBlock({
  label,
  added,
  removed,
  mono,
}: {
  label: string;
  added: string[];
  removed: string[];
  mono?: boolean;
}) {
  if (added.length === 0 && removed.length === 0) {
    return (
      <div>
        <h4 style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", marginBottom: 4 }}>
          {label}
        </h4>
        <div style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>No change</div>
      </div>
    );
  }
  return (
    <div>
      <h4 style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", marginBottom: 4 }}>
        {label}
      </h4>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        <ul style={{ margin: 0, padding: "6px 8px", listStyle: "none", border: "1px solid rgba(34,197,94,0.3)", borderRadius: 4, background: "rgba(34,197,94,0.06)", display: "flex", flexDirection: "column", gap: 2 }}>
          <li style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "#22C55E" }}>
            + Added ({added.length})
          </li>
          {added.map((x) => (
            <li
              key={"a" + x}
              style={{ fontSize: 11.5, color: "var(--color-ink)", fontFamily: mono ? "monospace" : undefined, wordBreak: "break-word" }}
            >
              {x}
            </li>
          ))}
        </ul>
        <ul style={{ margin: 0, padding: "6px 8px", listStyle: "none", border: "1px solid rgba(255,86,48,0.3)", borderRadius: 4, background: "rgba(255,86,48,0.06)", display: "flex", flexDirection: "column", gap: 2 }}>
          <li style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "#B71D18" }}>
            − Removed ({removed.length})
          </li>
          {removed.map((x) => (
            <li
              key={"r" + x}
              style={{ fontSize: 11.5, color: "var(--color-ink)", fontFamily: mono ? "monospace" : undefined, wordBreak: "break-word" }}
            >
              {x}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
