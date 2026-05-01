"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Ban,
  Briefcase,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleX,
  ExternalLink,
  Eye,
  Loader2,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";
import {
  api,
  type BrandActionDetail,
  type BrandActionListItem,
  type BrandActionRecommendation,
  type BrandActionStatus,
  type InvestigationTraceStep,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";


const REC_PRESENTATION: Record<
  BrandActionRecommendation,
  { label: string; tone: StateTone; icon: typeof Sparkles; bg: string; color: string }
> = {
  takedown_now: {
    label: "Takedown now",
    tone: "error-strong",
    icon: AlertTriangle,
    bg: "rgba(255,86,48,0.08)",
    color: "#B71D18",
  },
  takedown_after_review: {
    label: "Review then takedown",
    tone: "warning",
    icon: Eye,
    bg: "rgba(255,171,0,0.1)",
    color: "#B76E00",
  },
  dismiss_subsidiary: {
    label: "Dismiss (subsidiary)",
    tone: "muted",
    icon: ShieldCheck,
    bg: "var(--color-surface-muted)",
    color: "var(--color-body)",
  },
  monitor: {
    label: "Monitor",
    tone: "info",
    icon: Eye,
    bg: "rgba(0,187,217,0.1)",
    color: "#007B8A",
  },
  insufficient_data: {
    label: "Insufficient data",
    tone: "muted",
    icon: Ban,
    bg: "var(--color-surface-muted)",
    color: "var(--color-muted)",
  },
};


export default function BrandDefenderPage() {
  const { toast } = useToast();
  const [rows, setRows] = useState<BrandActionListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<BrandActionDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.brandActions.list({ limit: 100 });
      setRows(data);
      if (data.length > 0 && !selectedId) {
        setSelectedId(data[0].id);
      }
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load brand actions",
      );
    } finally {
      setLoading(false);
    }
  }, [selectedId, toast]);

  const loadDetail = useCallback(
    async (id: string) => {
      setDetailLoading(true);
      try {
        const d = await api.brandActions.get(id);
        setDetail(d);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load action",
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
        title="Brand Defender"
        description={
          "Proactive phishing defence — when a look-alike domain lands, " +
          "the agent gathers signals (live probe, logo similarity, WHOIS " +
          "age, subsidiary allowlist) and recommends an action. The human " +
          "decides whether to file the takedown."
        }
        actions={<RefreshButton onClick={loadList} refreshing={loading} />}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Section className="lg:col-span-5">
          <div
            className="px-4 py-3 flex items-center justify-between"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
              Recent decisions
            </h3>
            <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>{rows.length} total</span>
          </div>
          {loading ? (
            <SkeletonRows rows={6} columns={3} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Sparkles}
              title="No brand-defender runs yet"
              description={
                "Runs are queued automatically when a SuspectDomain lands " +
                "with similarity ≥ 0.80. You can also trigger one manually " +
                "from a suspect's detail page."
              }
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">
                    Status
                  </Th>
                  <Th align="left">Recommendation</Th>
                  <Th align="left" className="w-[80px]">
                    Conf.
                  </Th>
                  <Th align="right" className="pr-4 w-[90px]">
                    Started
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <ActionRow
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

        <div className="lg:col-span-7">
          {detail ? (
            <BrandActionPanel
              detail={detail}
              loading={detailLoading}
              onAfterTakedown={(ticketId) => {
                setDetail({ ...detail, takedown_ticket_id: ticketId });
                setRows((prev) =>
                  prev.map((r) =>
                    r.id === detail.id
                      ? { ...r, takedown_ticket_id: ticketId }
                      : r,
                  ),
                );
              }}
            />
          ) : (
            <Section>
              <Empty
                icon={Sparkles}
                title="Select a decision"
                description="Click a row on the left to see the agent's reasoning, risk signals, and the trace of every tool it called."
              />
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}

function ActionRow({
  r,
  isActive,
  onClick,
}: {
  r: BrandActionListItem;
  isActive: boolean;
  onClick: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: isActive
          ? "rgba(0,187,217,0.07)"
          : hovered
          ? "var(--color-surface)"
          : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <StatusPill status={r.status} />
      </td>
      <td className="px-3">
        {r.recommendation ? (
          <RecommendationChip rec={r.recommendation} />
        ) : (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-body)" }}>
        {r.confidence !== null ? r.confidence.toFixed(2) : "—"}
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.created_at)}
      </td>
    </tr>
  );
}

function StatusPill({ status }: { status: BrandActionStatus }) {
  const Icon = {
    queued: CircleDashed,
    running: Loader2,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<BrandActionStatus, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    queued: { background: "var(--color-surface-muted)", color: "var(--color-body)" },
    failed: { background: "rgba(255,86,48,0.08)", color: "#B71D18" },
  };

  return (
    <span
      style={{
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
      }}
    >
      <Icon
        style={{ width: "12px", height: "12px" }}
        className={status === "running" ? "animate-spin" : undefined}
      />
      {status}
    </span>
  );
}

function RecommendationChip({ rec }: { rec: BrandActionRecommendation }) {
  const p = REC_PRESENTATION[rec];
  const Icon = p.icon;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "22px",
        padding: "0 8px",
        borderRadius: "4px",
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.04em",
        background: p.bg,
        color: p.color,
      }}
    >
      <Icon style={{ width: "12px", height: "12px" }} />
      {p.label}
    </span>
  );
}

function BrandActionPanel({
  detail,
  loading,
  onAfterTakedown,
}: {
  detail: BrandActionDetail;
  loading: boolean;
  onAfterTakedown: (ticketId: string) => void;
}) {
  const { toast } = useToast();
  const [submitting, setSubmitting] = useState(false);
  const [btnHov, setBtnHov] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set([1]));
  const toggle = (n: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });

  const showSubmit =
    detail.status === "completed" &&
    detail.takedown_ticket_id === null &&
    (detail.recommendation === "takedown_now" ||
      detail.recommendation === "takedown_after_review");

  const handleSubmit = useCallback(async () => {
    setSubmitting(true);
    try {
      const res = await api.brandActions.submitTakedown(detail.id, {
        partner: detail.suggested_partner ?? undefined,
      });
      if (res.already_submitted) {
        toast("info", "Already submitted — opening ticket");
      } else {
        toast(
          "success",
          `Takedown filed with ${res.partner} — ticket ${res.ticket_id.slice(0, 8)}…`,
        );
      }
      onAfterTakedown(res.ticket_id);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to submit takedown",
      );
    } finally {
      setSubmitting(false);
    }
  }, [detail.id, detail.suggested_partner, onAfterTakedown, toast]);

  return (
    <Section>
      <div
        className="px-4 py-3 flex items-center justify-between gap-3"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div className="min-w-0">
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Brand action {detail.id.slice(0, 8)}…
          </h3>
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
            Suspect{" "}
            <span style={{ fontFamily: "monospace" }}>
              {detail.suspect_domain_id.slice(0, 12)}…
            </span>
            {" · "}
            {detail.iterations} step{detail.iterations === 1 ? "" : "s"}
            {detail.model_id ? ` · ${detail.model_id}` : ""}
            {detail.duration_ms ? ` · ${(detail.duration_ms / 1000).toFixed(1)}s` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {detail.takedown_ticket_id ? (
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              height: "32px",
              padding: "0 12px",
              borderRadius: "4px",
              fontSize: "12px",
              fontWeight: 700,
              background: "rgba(0,167,111,0.1)",
              color: "#007B55",
            }}>
              <CheckCircle2 style={{ width: "14px", height: "14px" }} />
              Takedown filed
            </span>
          ) : showSubmit ? (
            <button
              type="button"
              onClick={handleSubmit}
              disabled={submitting}
              onMouseEnter={() => setBtnHov(true)}
              onMouseLeave={() => setBtnHov(false)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                height: "32px",
                padding: "0 12px",
                borderRadius: "4px",
                fontSize: "12px",
                fontWeight: 700,
                background: btnHov && !submitting ? "#e64600" : "var(--color-accent)",
                color: "var(--color-on-dark)",
                border: "none",
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.5 : 1,
                transition: "background 0.15s",
              }}
              title={`Submit takedown via ${detail.suggested_partner ?? "default partner"}`}
            >
              {submitting ? (
                <Loader2 style={{ width: "14px", height: "14px" }} className="animate-spin" />
              ) : (
                <Briefcase style={{ width: "14px", height: "14px" }} />
              )}
              Submit takedown
            </button>
          ) : null}
          <StatusPill status={detail.status} />
        </div>
      </div>

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
              <div>
                <p style={{ fontSize: "13px", fontWeight: 700, color: "#B71D18" }}>
                  Brand defender failed
                </p>
                <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "2px", fontFamily: "monospace" }}>
                  {detail.error_message}
                </p>
              </div>
            </div>
          ) : null}

          {detail.recommendation ? (
            <section className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <RecommendationChip rec={detail.recommendation} />
                {detail.confidence !== null ? (
                  <span style={{ fontSize: "11.5px", fontFamily: "monospace", color: "var(--color-body)" }}>
                    confidence {detail.confidence.toFixed(2)}
                  </span>
                ) : null}
                {detail.suggested_partner ? (
                  <span style={{ fontSize: "11.5px", color: "var(--color-body)" }}>
                    via{" "}
                    <span style={{ fontFamily: "monospace" }}>{detail.suggested_partner}</span>
                  </span>
                ) : null}
              </div>
              {detail.recommendation_reason ? (
                <p style={{ fontSize: "14px", lineHeight: 1.55, color: "var(--color-ink)" }}>
                  {detail.recommendation_reason}
                </p>
              ) : null}
              {detail.risk_signals.length > 0 ? (
                <div className="flex items-center gap-1.5 flex-wrap mt-1">
                  {detail.risk_signals.map((s) => (
                    <span
                      key={s}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        height: "20px",
                        padding: "0 6px",
                        borderRadius: "4px",
                        background: "rgba(255,171,0,0.1)",
                        color: "#B76E00",
                        fontSize: "10.5px",
                        fontFamily: "monospace",
                        fontWeight: 700,
                        letterSpacing: "0.04em",
                      }}
                    >
                      {s}
                    </span>
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}

          {detail.trace && detail.trace.length > 0 ? (
            <section>
              <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
                Trace · {detail.trace.length} step
                {detail.trace.length === 1 ? "" : "s"}
              </h4>
              <ol className="space-y-2">
                {detail.trace.map((s) => (
                  <TraceCard
                    key={s.iteration}
                    step={s}
                    isOpen={expanded.has(s.iteration)}
                    onToggle={() => toggle(s.iteration)}
                  />
                ))}
              </ol>
            </section>
          ) : null}
        </div>
      )}
    </Section>
  );
}

function TraceCard({
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
    <li style={{
      borderRadius: "5px",
      border: "1px solid var(--color-border)",
      background: "var(--color-surface)",
      overflow: "hidden",
    }}>
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
          <ChevronDown style={{ width: "14px", height: "14px", color: "var(--color-muted)" }} />
        ) : (
          <ChevronRight style={{ width: "14px", height: "14px", color: "var(--color-muted)" }} />
        )}
        <span style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", width: "60px" }}>
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
        <div className="px-3 pb-3 space-y-2">
          <p style={{ fontSize: "12.5px", color: "var(--color-body)", fontStyle: "italic" }}>"{step.thought}"</p>
          {step.args ? (
            <pre style={{
              fontSize: "11px",
              fontFamily: "monospace",
              background: "var(--color-border-strong)",
              color: "var(--color-on-dark)",
              padding: "8px 12px",
              borderRadius: "4px",
              overflowX: "auto",
            }}>
              {JSON.stringify(step.args, null, 2)}
            </pre>
          ) : null}
          {step.result !== null && step.result !== undefined ? (
            <pre style={{
              fontSize: "11px",
              fontFamily: "monospace",
              background: "var(--color-border-strong)",
              color: "var(--color-on-dark)",
              padding: "8px 12px",
              borderRadius: "4px",
              overflowX: "auto",
              maxHeight: "300px",
              opacity: 0.9,
            }}>
              {JSON.stringify(step.result, null, 2)}
            </pre>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

// Quiet the unused-import warning for a lucide icon we kept for future
// "view linked ticket" affordance.
void ExternalLink;
