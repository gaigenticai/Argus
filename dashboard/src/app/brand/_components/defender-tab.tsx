"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ArrowUpRight,
  Briefcase,
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
  RotateCw,
  Sparkles,
  Wrench,
} from "lucide-react";

import {
  api,
  type BrandActionCompareDiff,
  type BrandActionDetail,
  type BrandActionListItem,
  type BrandActionRecommendation,
  type BrandActionStatus,
  type InvestigationPlanStep,
  type InvestigationTraceStep,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Section,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { estimateCostUsd, formatCostUsd } from "@/lib/llm-cost";

import { useBrandContext } from "./use-brand-context";
import { BrandToolResult } from "./brand-tool-renderers";
import {
  BRAND_TOOL_META,
  brandToolLabel,
  RECOMMENDATION_LABEL,
  RECOMMENDATION_TONE,
  riskSignalLabel,
} from "./labels";


const STATUS_TONE: Record<BrandActionStatus, StateTone> = {
  queued: "neutral",
  running: "info",
  awaiting_plan_approval: "warning",
  completed: "success",
  failed: "error",
};


export function DefenderTab() {
  const { orgId, refreshKey } = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<BrandActionListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<BrandActionDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  // Compare flow — pick two brand-actions on the same suspect.
  const [compareIds, setCompareIds] = useState<[string | null, string | null]>(
    [null, null],
  );

  const loadList = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      // The endpoint is org-scoped server-side; no org param needed.
      const data = await api.brandActions.list({ limit: 200 });
      setRows(data);
      if (!selectedId && data.length > 0) {
        setSelectedId(data[0].id);
      }
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load brand-actions",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, selectedId, toast]);

  useEffect(() => {
    void loadList();
  }, [loadList, refreshKey]);

  const loadDetail = useCallback(
    async (id: string) => {
      setDetailLoading(true);
      try {
        const d = await api.brandActions.get(id);
        setDetail(d);
      } catch (e) {
        toast("error", e instanceof Error ? e.message : "Failed to load detail");
      } finally {
        setDetailLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
    else setDetail(null);
  }, [selectedId, loadDetail]);

  // SSE live trace while the selected action is in flight.
  useEffect(() => {
    if (!detail) return;
    if (detail.status === "completed" || detail.status === "failed") return;
    const url = api.brandActions.streamUrl(detail.id);
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
          recommendation?: string | null;
          confidence?: number | null;
        };
        if (data.kind === "step") {
          setDetail((prev) => {
            if (!prev || prev.id !== detail.id) return prev;
            const trace = prev.trace || [];
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
              status: (data.status as BrandActionStatus) || prev.status,
              recommendation:
                (data.recommendation as BrandActionRecommendation) || prev.recommendation,
              confidence: data.confidence ?? prev.confidence,
            };
          });
          void loadDetail(detail.id);
          void loadList();
          es.close();
        } else if (data.kind === "plan") {
          void loadDetail(detail.id);
          void loadList();
        }
      } catch {
        /* malformed events ignored */
      }
    };
    es.onerror = () => {
      // Browser auto-reconnects; explicit close on stopped event.
    };
    return () => {
      es.close();
    };
  }, [detail?.id, detail?.status, loadDetail, loadList]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      {/* Left — list */}
      <Section className="lg:col-span-5">
        <div
          className="px-4 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Defender activity
          </h3>
          <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>
            {rows.length} runs
          </span>
        </div>
        {loading ? (
          <SkeletonRows rows={6} columns={3} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Sparkles}
            title="No defender runs yet"
            description="Brand Defender runs auto-queue on high-similarity suspect domains. You can also trigger a run manually from the Suspects tab."
          />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4 w-[110px]">Status</Th>
                <Th align="left" className="w-[140px]">Verdict</Th>
                <Th align="left">Suspect</Th>
                <Th align="right" className="pr-4 w-[90px]">Started</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <DefenderRow
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
          <DefenderDetailPanel
            detail={detail}
            loading={detailLoading}
            compareIds={compareIds}
            setCompareIds={setCompareIds}
            allActions={rows}
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
              title="Select a defender run"
              description="Click a row to inspect the agentic trace, recommendation, and risk signals."
            />
          </Section>
        )}
      </div>

      {compareIds[0] !== null && compareIds[1] !== null && (
        <CompareBrandActionsModal
          aId={compareIds[0]}
          bId={compareIds[1]}
          onClose={() => setCompareIds([null, null])}
        />
      )}
    </div>
  );
}


function DefenderRow({
  r,
  isActive,
  onClick,
}: {
  r: BrandActionListItem;
  isActive: boolean;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  const recTone = r.recommendation
    ? RECOMMENDATION_TONE[r.recommendation] || "var(--color-body)"
    : "var(--color-muted)";
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "56px",
        borderBottom: "1px solid var(--color-border)",
        background: isActive ? "rgba(0,187,217,0.07)" : hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <DefenderStatusPill status={r.status} />
      </td>
      <td className="px-3">
        {r.recommendation ? (
          <span
            style={{
              padding: "1px 6px",
              borderRadius: 3,
              background: "var(--color-surface-muted)",
              color: recTone,
              fontSize: 10,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            {RECOMMENDATION_LABEL[r.recommendation] || r.recommendation}
          </span>
        ) : (
          <span style={{ fontSize: 11, color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td style={{ padding: "0 12px", fontSize: 12 }}>
        <div
          style={{
            fontFamily: "monospace",
            color: "var(--color-ink)",
            fontWeight: 500,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            display: "flex",
            alignItems: "center",
            gap: 4,
          }}
          title={r.suspect_domain || r.suspect_domain_id}
        >
          {r.suspect_domain || r.suspect_domain_id.slice(0, 8) + "…"}
          {r.takedown_ticket_id ? (
            <Briefcase
              style={{ width: 11, height: 11, color: "#007B55", flexShrink: 0 }}
              aria-label="takedown filed"
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
          {typeof r.suspect_similarity === "number" ? (
            <span style={{ fontFamily: "monospace" }}>
              sim {Math.round(r.suspect_similarity * 100)}%
            </span>
          ) : null}
          {typeof r.confidence === "number" ? (
            <>
              <span>·</span>
              <span style={{ fontFamily: "monospace" }}>
                conf {Math.round(r.confidence * 100)}%
              </span>
            </>
          ) : null}
          {r.risk_signals.length > 0 ? (
            <>
              <span>·</span>
              <span>{r.risk_signals.length} signal{r.risk_signals.length === 1 ? "" : "s"}</span>
            </>
          ) : null}
        </div>
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: 11.5, color: "var(--color-muted)" }}>
        {timeAgo(r.created_at)}
      </td>
    </tr>
  );
}


function DefenderStatusPill({ status }: { status: BrandActionStatus }) {
  const Icon = {
    queued: CircleDashed,
    running: Loader2,
    awaiting_plan_approval: PauseCircle,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<BrandActionStatus, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    awaiting_plan_approval: { background: "rgba(255,171,0,0.12)", color: "#B76E00" },
    queued: { background: "var(--color-surface-muted)", color: "var(--color-body)" },
    failed: { background: "rgba(255,86,48,0.08)", color: "#B71D18" },
  };

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        height: 22,
        padding: "0 8px",
        borderRadius: 4,
        fontSize: 10.5,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        ...styleMap[status],
      }}
    >
      <Icon
        style={{ width: 12, height: 12 }}
        className={status === "running" ? "animate-spin" : undefined}
      />
      {status.replace(/_/g, " ")}
    </span>
  );
}


function DefenderDetailPanel({
  detail,
  loading,
  compareIds,
  setCompareIds,
  allActions,
  onRefresh,
  onSelect,
}: {
  detail: BrandActionDetail;
  loading: boolean;
  compareIds: [string | null, string | null];
  setCompareIds: (next: [string | null, string | null]) => void;
  allActions: BrandActionListItem[];
  onRefresh: () => void;
  onSelect: (id: string) => void;
}) {
  const { toast } = useToast();
  const [retrying, setRetrying] = useState(false);
  const [submittingTakedown, setSubmittingTakedown] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set([1]));
  const traceEndRef = useRef<HTMLDivElement | null>(null);
  const isStreaming = detail.status === "running" || detail.status === "queued";

  useEffect(() => {
    if (isStreaming && traceEndRef.current) {
      traceEndRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [detail.iterations, isStreaming]);

  const toggle = (n: number) =>
    setExpanded((p) => {
      const next = new Set(p);
      next.has(n) ? next.delete(n) : next.add(n);
      return next;
    });

  const totalDuration = useMemo(() => {
    if (detail.duration_ms) return detail.duration_ms;
    return (detail.trace || []).reduce((acc, s) => acc + (s.duration_ms || 0), 0);
  }, [detail.duration_ms, detail.trace]);

  // Tools used summary
  const toolsUsed = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of (detail.trace || [])) {
      if (s.tool) counts.set(s.tool, (counts.get(s.tool) || 0) + 1);
    }
    return Array.from(counts.entries());
  }, [detail.trace]);

  const handleRerun = async (extra?: string) => {
    setRetrying(true);
    try {
      const res = await api.brandActions.rerun(detail.id, extra);
      toast("success", "Re-run queued");
      onSelect(res.id);
      onRefresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to re-run");
    } finally {
      setRetrying(false);
    }
  };

  const handleApprovePlan = async (plan?: InvestigationPlanStep[]) => {
    try {
      await api.brandActions.approvePlan(detail.id, plan);
      toast("success", "Plan approved — agent resuming");
      onRefresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to approve plan");
    }
  };

  const handleSubmitTakedown = async () => {
    setSubmittingTakedown(true);
    try {
      const res = await api.brandActions.submitTakedown(detail.id);
      toast(
        "success",
        res.already_submitted
          ? "Takedown already filed — opening it"
          : "Takedown filed",
      );
      onRefresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to submit takedown");
    } finally {
      setSubmittingTakedown(false);
    }
  };

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
            Defender {detail.id.slice(0, 8)}…
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
            <span style={{ fontFamily: "monospace", color: "var(--color-ink)", fontWeight: 500 }}>
              {detail.suspect_domain || detail.suspect_domain_id.slice(0, 8)}
            </span>
            {typeof detail.suspect_similarity === "number" ? (
              <span>· sim {Math.round(detail.suspect_similarity * 100)}%</span>
            ) : null}
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
            {(() => {
              const cost = estimateCostUsd(
                detail.model_id,
                detail.input_tokens,
                detail.output_tokens,
              );
              return cost !== null ? (
                <>
                  <span>·</span>
                  <span
                    style={{ fontFamily: "monospace" }}
                    title="Estimated cost using published model list price (src/lib/llm-cost.ts)"
                  >
                    ~{formatCostUsd(cost)}
                  </span>
                </>
              ) : null;
            })()}
          </div>
          {detail.recommendation || typeof detail.confidence === "number" ? (
            <div
              style={{
                marginTop: 6,
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                fontSize: 11,
              }}
            >
              {detail.recommendation ? (
                <span
                  style={{
                    padding: "1px 6px",
                    borderRadius: 3,
                    background: "var(--color-surface-muted)",
                    color: RECOMMENDATION_TONE[detail.recommendation] || "var(--color-body)",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    fontSize: 9.5,
                  }}
                >
                  {RECOMMENDATION_LABEL[detail.recommendation] || detail.recommendation}
                </span>
              ) : null}
              {typeof detail.confidence === "number" ? (
                <span style={{ color: "var(--color-body)", fontFamily: "monospace" }}>
                  {Math.round(detail.confidence * 100)}% confidence
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="flex items-center gap-2 flex-wrap" style={{ flexShrink: 0 }}>
          {detail.takedown_ticket_id ? (
            <Link
              href={`/takedowns?id=${detail.takedown_ticket_id}`}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Open the takedown ticket filed for this action"
            >
              <Briefcase style={{ width: 13, height: 13 }} />
              View takedown
              <ExternalLink style={{ width: 11, height: 11 }} />
            </Link>
          ) : detail.status === "completed"
              && (detail.recommendation === "takedown_now"
                  || detail.recommendation === "takedown_after_review") ? (
            <button
              onClick={handleSubmitTakedown}
              disabled={submittingTakedown}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold disabled:opacity-50"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
              title="File the recommended takedown now"
            >
              {submittingTakedown ? (
                <Loader2 style={{ width: 12, height: 12 }} className="animate-spin" />
              ) : (
                <ArrowUpRight style={{ width: 13, height: 13 }} />
              )}
              File takedown
            </button>
          ) : null}
          {detail.status === "completed" || detail.status === "failed" ? (
            <button
              onClick={() => {
                const note = window.prompt(
                  "Optional analyst note for the re-run (e.g. 'check this freshly-probed evidence'). Leave blank to retry as-is.",
                ) || undefined;
                void handleRerun(note);
              }}
              disabled={retrying}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold disabled:opacity-50"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
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
              onClick={() => {
                if (compareIds[0] === null) {
                  setCompareIds([detail.id, null]);
                } else if (compareIds[0] === detail.id) {
                  setCompareIds([null, null]);
                } else {
                  setCompareIds([compareIds[0], detail.id]);
                }
              }}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border:
                  compareIds[0] === detail.id
                    ? "1px solid var(--color-accent)"
                    : "1px solid var(--color-border)",
                background:
                  compareIds[0] === detail.id
                    ? "rgba(255,79,0,0.08)"
                    : "var(--color-canvas)",
                color:
                  compareIds[0] === detail.id
                    ? "var(--color-accent)"
                    : "var(--color-body)",
              }}
              title={
                compareIds[0] === null
                  ? "Pick this run, then pick another on the same suspect to diff"
                  : compareIds[0] === detail.id
                    ? "Cancel compare picking"
                    : "Diff with the previously picked run"
              }
            >
              <GitCompare style={{ width: 12, height: 12 }} />
              {compareIds[0] === null
                ? "Compare"
                : compareIds[0] === detail.id
                  ? "Cancel compare"
                  : "Compare with this"}
            </button>
          ) : null}
          <DefenderStatusPill status={detail.status} />
        </div>
      </header>

      {loading ? (
        <SkeletonRows rows={6} columns={2} />
      ) : (
        <div className="p-5 space-y-5">
          {detail.status === "awaiting_plan_approval" && detail.plan ? (
            <PlanGate
              plan={detail.plan}
              onApprove={handleApprovePlan}
            />
          ) : null}

          {detail.status === "failed" && detail.error_message ? (
            <div
              role="alert"
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 12,
                borderRadius: 5,
                border: "1px solid rgba(255,86,48,0.4)",
                background: "rgba(255,86,48,0.08)",
                padding: "12px 16px",
              }}
            >
              <CircleX style={{ width: 18, height: 18, marginTop: 2, color: "#B71D18", flexShrink: 0 }} />
              <div>
                <p style={{ fontSize: 13, fontWeight: 700, color: "#B71D18" }}>Defender failed</p>
                <p style={{ fontSize: 12.5, color: "var(--color-body)", marginTop: 2, fontFamily: "monospace", wordBreak: "break-word" }}>
                  {detail.error_message}
                </p>
              </div>
            </div>
          ) : null}

          {/* Tools-used summary chips */}
          {toolsUsed.length > 0 ? (
            <section>
              <h4 style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: 6 }}>
                Tools used
              </h4>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {toolsUsed.map(([t, n]) => (
                  <span
                    key={t}
                    title={(BRAND_TOOL_META as Record<string, { description: string }>)[t]?.description || t}
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
                    {brandToolLabel(t)}
                    {n > 1 ? <span style={{ color: "var(--color-muted)" }}>×{n}</span> : null}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {/* Recommendation reason */}
          {detail.recommendation_reason ? (
            <section>
              <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: 8 }}>
                Recommendation reasoning
              </h4>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, color: "var(--color-ink)", margin: 0 }}>
                {detail.recommendation_reason}
              </p>
            </section>
          ) : null}

          {/* Risk signals */}
          {detail.risk_signals.length > 0 ? (
            <section>
              <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: 8 }}>
                Risk signals
              </h4>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {detail.risk_signals.map((s) => (
                  <span
                    key={s}
                    title={riskSignalLabel(s)}
                    style={{
                      padding: "2px 8px",
                      borderRadius: 3,
                      background: "rgba(255,86,48,0.08)",
                      color: "#B71D18",
                      fontSize: 10.5,
                      fontFamily: "monospace",
                      fontWeight: 700,
                    }}
                  >
                    {s}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {/* Trace */}
          {detail.trace && detail.trace.length > 0 ? (
            <section>
              <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
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
                  <BrandTraceStepCard
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
                padding: 24,
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


function BrandTraceStepCard({
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
    <li style={{ borderRadius: 5, border: "1px solid var(--color-border)", background: "var(--color-surface)", overflow: "hidden" }}>
      <button
        onClick={onToggle}
        onMouseEnter={() => setHov(true)}
        onMouseLeave={() => setHov(false)}
        style={{
          width: "100%",
          padding: "8px 12px",
          display: "flex",
          alignItems: "center",
          gap: 8,
          textAlign: "left",
          background: hov ? "var(--color-surface-muted)" : "transparent",
          border: "none",
          cursor: "pointer",
          transition: "background 0.15s",
        }}
      >
        {isOpen ? (
          <ChevronDown style={{ width: 14, height: 14, color: "var(--color-muted)", flexShrink: 0 }} />
        ) : (
          <ChevronRight style={{ width: 14, height: 14, color: "var(--color-muted)", flexShrink: 0 }} />
        )}
        <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", width: 60, flexShrink: 0 }}>
          Step {step.iteration}
        </span>
        {step.tool ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 12, color: "var(--color-accent)", fontWeight: 600 }}>
            <Wrench style={{ width: 12, height: 12 }} />
            {brandToolLabel(step.tool)}
          </span>
        ) : (
          <span style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
            (finalising)
          </span>
        )}
        <span style={{ flex: 1 }} />
        {step.duration_ms ? (
          <span style={{ fontSize: 10.5, fontFamily: "monospace", color: "var(--color-muted)" }}>
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
          ) : null}
          {step.tool && step.result !== null && step.result !== undefined ? (
            <BrandToolResult tool={step.tool} result={step.result} />
          ) : null}
        </div>
      ) : null}
    </li>
  );
}


// Plan-then-act gate UI for brand-actions.
function PlanGate({
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
        The Brand Defender has proposed a tool sequence below. Approve to let
        it execute, or edit if you want a different approach.
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
            <span style={{ fontSize: 10.5, fontWeight: 700, color: "var(--color-muted)", width: 16, flexShrink: 0 }}>
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
// Compare two brand-actions on the same suspect
// ---------------------------------------------------------------------

function CompareBrandActionsModal({
  aId,
  bId,
  onClose,
}: {
  aId: string;
  bId: string;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [diff, setDiff] = useState<BrandActionCompareDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const d = await api.brandActions.compare(aId, bId);
        if (!alive) return;
        setDiff(d);
      } catch (e) {
        if (!alive) return;
        const msg = e instanceof Error ? e.message : "Failed to compare";
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
        aria-label="Compare brand-actions"
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
          <h3
            className="text-[14px] font-semibold"
            style={{
              color: "var(--color-ink)",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
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
            <div
              style={{
                fontSize: 12,
                color: "var(--color-muted)",
                textAlign: "center",
                padding: 24,
              }}
            >
              Loading diff…
            </div>
          ) : (
            <div
              style={{ display: "flex", flexDirection: "column", gap: 14 }}
            >
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: 8,
                }}
              >
                <CompareMetric
                  label="Iteration delta"
                  value={
                    (diff.iteration_delta > 0 ? "+" : "") + diff.iteration_delta
                  }
                />
                <CompareMetric
                  label="Duration delta"
                  value={
                    diff.duration_delta_ms !== null
                      ? `${diff.duration_delta_ms > 0 ? "+" : ""}${(
                          diff.duration_delta_ms / 1000
                        ).toFixed(1)}s`
                      : "—"
                  }
                />
                <CompareMetric
                  label="Confidence delta"
                  value={
                    diff.confidence_delta !== null
                      ? `${diff.confidence_delta > 0 ? "+" : ""}${Math.round(
                          diff.confidence_delta * 100,
                        )}%`
                      : "—"
                  }
                />
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 8,
                }}
              >
                <div
                  style={{
                    border: "1px solid var(--color-border)",
                    borderRadius: 4,
                    padding: 10,
                  }}
                >
                  <div
                    style={{
                      fontSize: 9.5,
                      fontWeight: 700,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "var(--color-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Run A · {diff.recommendation_a || "—"}
                  </div>
                </div>
                <div
                  style={{
                    border: "1px solid var(--color-border)",
                    borderRadius: 4,
                    padding: 10,
                  }}
                >
                  <div
                    style={{
                      fontSize: 9.5,
                      fontWeight: 700,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "var(--color-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Run B · {diff.recommendation_b || "—"}
                  </div>
                </div>
              </div>
              <CompareDiffBlock
                label="Risk signals"
                added={diff.risk_signals_added}
                removed={diff.risk_signals_removed}
                mono
              />
              <CompareDiffBlock
                label="Tools"
                added={diff.tools_added}
                removed={diff.tools_removed}
                mono
              />
            </div>
          )}
        </div>
      </div>
    </>
  );
}


function CompareMetric({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: 4,
        padding: 10,
      }}
    >
      <div
        style={{
          fontSize: 9.5,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--color-muted)",
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: "monospace",
          fontSize: 14,
          color: "var(--color-ink)",
          fontWeight: 700,
        }}
      >
        {value}
      </div>
    </div>
  );
}


function CompareDiffBlock({
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
        <h4
          style={{
            fontSize: 10.5,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "var(--color-muted)",
            marginBottom: 4,
          }}
        >
          {label}
        </h4>
        <div
          style={{
            fontSize: 12,
            color: "var(--color-muted)",
            fontStyle: "italic",
          }}
        >
          No change
        </div>
      </div>
    );
  }
  return (
    <div>
      <h4
        style={{
          fontSize: 10.5,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--color-muted)",
          marginBottom: 4,
        }}
      >
        {label}
      </h4>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        <ul
          style={{
            margin: 0,
            padding: "6px 8px",
            listStyle: "none",
            border: "1px solid rgba(34,197,94,0.3)",
            borderRadius: 4,
            background: "rgba(34,197,94,0.06)",
            display: "flex",
            flexDirection: "column",
            gap: 2,
          }}
        >
          <li
            style={{
              fontSize: 9.5,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "#22C55E",
            }}
          >
            + Added ({added.length})
          </li>
          {added.map((x) => (
            <li
              key={"a" + x}
              style={{
                fontSize: 11.5,
                color: "var(--color-ink)",
                fontFamily: mono ? "monospace" : undefined,
                wordBreak: "break-word",
              }}
            >
              {x}
            </li>
          ))}
        </ul>
        <ul
          style={{
            margin: 0,
            padding: "6px 8px",
            listStyle: "none",
            border: "1px solid rgba(255,86,48,0.3)",
            borderRadius: 4,
            background: "rgba(255,86,48,0.06)",
            display: "flex",
            flexDirection: "column",
            gap: 2,
          }}
        >
          <li
            style={{
              fontSize: 9.5,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "#B71D18",
            }}
          >
            − Removed ({removed.length})
          </li>
          {removed.map((x) => (
            <li
              key={"r" + x}
              style={{
                fontSize: 11.5,
                color: "var(--color-ink)",
                fontFamily: mono ? "monospace" : undefined,
                wordBreak: "break-word",
              }}
            >
              {x}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
