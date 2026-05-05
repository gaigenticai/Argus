"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BarChart3, Sparkles } from "lucide-react";

import { api, type InvestigationStatsResponse } from "@/lib/api";
import { PageHeader, Section } from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";

import { toolLabel } from "../_components/tool-meta";


const STOP_REASON_LABEL: Record<string, string> = {
  high_confidence: "High confidence",
  max_iterations: "Max iterations",
  no_new_evidence: "No new evidence",
  llm_error: "LLM error",
  user_aborted: "User aborted",
};
const STOP_REASON_COLOR: Record<string, string> = {
  high_confidence: "#22C55E",
  max_iterations: "#FFAB00",
  no_new_evidence: "var(--color-muted)",
  llm_error: "#B71D18",
  user_aborted: "var(--color-muted)",
};

const RANGES: Array<{ value: number; label: string }> = [
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];


export default function InvestigationStatsPage() {
  const { toast } = useToast();
  const [days, setDays] = useState(30);
  const [stats, setStats] = useState<InvestigationStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.investigations.stats(days);
      setStats(res);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load stats",
      );
    } finally {
      setLoading(false);
    }
  }, [days, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-6">
      <Link
        href="/investigations"
        className="inline-flex items-center gap-1.5 text-[12.5px]"
        style={{ color: "var(--color-muted)" }}
      >
        <ArrowLeft style={{ width: 13, height: 13 }} />
        Back to investigations
      </Link>
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Investigation analytics"
        description={
          "Aggregate signal on the agent's behaviour. "
          + "Use this to spot regressions in success rate, drift in stop reasons, "
          + "or the agent over-relying on a single tool."
        }
        actions={
          <div style={{ display: "flex", gap: 4 }}>
            {RANGES.map((r) => (
              <button
                key={r.value}
                onClick={() => setDays(r.value)}
                className="h-8 px-3 text-[12px] font-bold transition-colors"
                style={{
                  borderRadius: 4,
                  border: r.value === days ? "1px solid var(--color-accent)" : "1px solid var(--color-border)",
                  background: r.value === days ? "rgba(255,79,0,0.06)" : "var(--color-canvas)",
                  color: r.value === days ? "var(--color-accent)" : "var(--color-body)",
                }}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      />

      {loading ? (
        <div style={{ padding: 32, textAlign: "center", color: "var(--color-muted)", fontSize: 12 }}>
          Loading…
        </div>
      ) : !stats ? null : (
        <>
          {/* Headline metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Tile label="Total runs" value={String(stats.total)} />
            <Tile
              label="Success rate"
              value={`${Math.round(stats.success_rate * 100)}%`}
              tone={stats.success_rate >= 0.9 ? "success" : stats.success_rate >= 0.6 ? "warning" : "error"}
            />
            <Tile
              label="Avg iterations"
              value={stats.avg_iterations.toFixed(1)}
              hint={`max=6 per run`}
            />
            <Tile
              label="Avg duration"
              value={
                stats.avg_duration_ms !== null
                  ? `${(stats.avg_duration_ms / 1000).toFixed(1)}s`
                  : "—"
              }
            />
          </div>

          {/* Stop reasons + status breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
                  Stop reasons
                </h3>
              </div>
              <div className="p-4">
                {stats.stop_reasons.length === 0 ? (
                  <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                    No completed runs in this window.
                  </p>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                    {stats.stop_reasons.map((s) => {
                      const total = stats.stop_reasons.reduce((a, b) => a + b.count, 0);
                      const pct = total > 0 ? (s.count / total) * 100 : 0;
                      return (
                        <li key={s.stop_reason}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 3 }}>
                            <span style={{ fontSize: 12, color: "var(--color-ink)" }}>
                              {STOP_REASON_LABEL[s.stop_reason] || s.stop_reason}
                            </span>
                            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--color-muted)" }}>
                              {s.count} · {pct.toFixed(0)}%
                            </span>
                          </div>
                          <div style={{ height: 6, borderRadius: 3, background: "var(--color-surface-muted)", overflow: "hidden" }}>
                            <div
                              style={{
                                height: "100%",
                                width: `${pct}%`,
                                background: STOP_REASON_COLOR[s.stop_reason] || "var(--color-accent)",
                              }}
                            />
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </Section>

            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
                  Status breakdown
                </h3>
              </div>
              <div className="p-4">
                <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
                  {Object.entries(stats.by_status).map(([status, count]) => (
                    <li
                      key={status}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: 12.5,
                        color: "var(--color-ink)",
                      }}
                    >
                      <span style={{ textTransform: "capitalize" }}>{status.replace(/_/g, " ")}</span>
                      <span style={{ fontFamily: "monospace", color: "var(--color-body)" }}>{count}</span>
                    </li>
                  ))}
                </ul>
                {typeof stats.avg_final_confidence === "number" ? (
                  <p style={{ fontSize: 11.5, color: "var(--color-muted)", marginTop: 12 }}>
                    Avg final confidence:{" "}
                    <span style={{ fontFamily: "monospace", color: "var(--color-ink)", fontWeight: 700 }}>
                      {Math.round(stats.avg_final_confidence * 100)}%
                    </span>
                  </p>
                ) : null}
              </div>
            </Section>
          </div>

          {/* Top tools + top actors */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
                  Top tools
                </h3>
              </div>
              <div className="p-4">
                {stats.top_tools.length === 0 ? (
                  <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                    No tool calls recorded yet.
                  </p>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 8 }}>
                    {stats.top_tools.map((t) => {
                      const max = stats.top_tools[0].count;
                      const pct = max > 0 ? (t.count / max) * 100 : 0;
                      return (
                        <li key={t.tool}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 3 }}>
                            <span style={{ fontSize: 12, color: "var(--color-ink)" }}>{toolLabel(t.tool)}</span>
                            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--color-muted)" }}>{t.count}</span>
                          </div>
                          <div style={{ height: 6, borderRadius: 3, background: "var(--color-surface-muted)", overflow: "hidden" }}>
                            <div
                              style={{
                                height: "100%",
                                width: `${pct}%`,
                                background: "var(--color-accent)",
                              }}
                            />
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </Section>

            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
                  Top actors found
                </h3>
              </div>
              <div className="p-4">
                {stats.top_actors.length === 0 ? (
                  <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                    No correlated actors yet.
                  </p>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
                    {stats.top_actors.map((a) => (
                      <li
                        key={a.actor}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          fontSize: 12.5,
                          color: "var(--color-ink)",
                          gap: 8,
                        }}
                      >
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                          {a.actor}
                        </span>
                        <span style={{ fontFamily: "monospace", color: "var(--color-body)" }}>{a.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </Section>
          </div>

          {/* Daily timeline — simple sparkline */}
          {stats.daily.length > 0 ? (
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)", display: "flex", alignItems: "center", gap: 6 }}>
                  <BarChart3 style={{ width: 13, height: 13 }} />
                  Daily timeline
                </h3>
              </div>
              <div className="p-4">
                <DailyBars daily={stats.daily} />
              </div>
            </Section>
          ) : null}
        </>
      )}
    </div>
  );
}


function Tile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "success" | "warning" | "error";
}) {
  const color =
    tone === "success"
      ? "#22C55E"
      : tone === "warning"
        ? "#FFAB00"
        : tone === "error"
          ? "#B71D18"
          : "var(--color-ink)";
  return (
    <div
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: 5,
        background: "var(--color-canvas)",
        padding: "12px 14px",
      }}
    >
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontFamily: "monospace", fontSize: 22, fontWeight: 700, color }}>
        {value}
      </div>
      {hint ? (
        <div style={{ fontSize: 10.5, color: "var(--color-muted)", marginTop: 2 }}>{hint}</div>
      ) : null}
    </div>
  );
}


function DailyBars({ daily }: { daily: Array<{ date: string; total: number; completed: number; failed: number }> }) {
  const max = Math.max(1, ...daily.map((d) => d.total));
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 100, overflowX: "auto" }}>
      {daily.map((d) => {
        const totalPct = (d.total / max) * 100;
        const failedPct = d.total > 0 ? (d.failed / d.total) * 100 : 0;
        return (
          <div
            key={d.date}
            title={`${d.date}: ${d.completed} completed, ${d.failed} failed, ${d.total} total`}
            style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, flex: 1, minWidth: 18 }}
          >
            <div
              style={{
                width: "100%",
                height: `${totalPct}%`,
                minHeight: 2,
                borderRadius: 3,
                background: failedPct > 50 ? "#B71D18" : failedPct > 0 ? "#FFAB00" : "#22C55E",
                opacity: 0.85,
              }}
            />
            <span
              style={{
                fontSize: 9,
                color: "var(--color-muted)",
                fontFamily: "monospace",
                whiteSpace: "nowrap",
              }}
            >
              {d.date.slice(5)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
