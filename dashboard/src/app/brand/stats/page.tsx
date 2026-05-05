"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BarChart3, ShieldCheck } from "lucide-react";

import { api, type BrandActionStatsResponse } from "@/lib/api";
import { PageHeader, Section } from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";

import {
  RECOMMENDATION_LABEL,
  RECOMMENDATION_TONE,
  riskSignalLabel,
} from "../_components/labels";


const RANGES: Array<{ value: number; label: string }> = [
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];


export default function BrandStatsPage() {
  const { toast } = useToast();
  const [days, setDays] = useState(30);
  const [stats, setStats] = useState<BrandActionStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.brandActions.stats(days);
      setStats(res);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load stats");
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
        href="/brand"
        className="inline-flex items-center gap-1.5 text-[12.5px]"
        style={{ color: "var(--color-muted)" }}
      >
        <ArrowLeft style={{ width: 13, height: 13 }} />
        Back to brand protection
      </Link>
      <PageHeader
        eyebrow={{ icon: ShieldCheck, label: "Brand Defender" }}
        title="Brand Defender analytics"
        description={
          "How the agent is behaving across your suspect-domain pipeline. "
          + "Use this to spot recommendation drift, find the most-cited "
          + "risk signals, and track defence→takedown conversion."
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
        <div className="text-center text-[12px] py-8" style={{ color: "var(--color-muted)" }}>
          Loading…
        </div>
      ) : !stats ? null : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Tile label="Total runs" value={String(stats.total)} />
            <Tile
              label="Defence→takedown"
              value={`${Math.round(stats.defence_to_takedown_rate * 100)}%`}
              tone={
                stats.defence_to_takedown_rate >= 0.5
                  ? "success"
                  : stats.defence_to_takedown_rate >= 0.2
                    ? "warning"
                    : "muted"
              }
              hint="of takedown_now / takedown_after_review actions that got a real ticket filed"
            />
            <Tile
              label="Avg confidence"
              value={
                stats.avg_confidence !== null
                  ? `${Math.round(stats.avg_confidence * 100)}%`
                  : "—"
              }
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

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
                  Recommendation breakdown
                </h3>
              </div>
              <div className="p-4">
                {Object.keys(stats.by_recommendation).length === 0 ? (
                  <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                    No completed runs in this window.
                  </p>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                    {Object.entries(stats.by_recommendation).map(([rec, count]) => {
                      const total = Object.values(stats.by_recommendation).reduce(
                        (a, b) => a + b,
                        0,
                      );
                      const pct = total > 0 ? (count / total) * 100 : 0;
                      return (
                        <li key={rec}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                            <span
                              style={{
                                fontSize: 12,
                                color: RECOMMENDATION_TONE[rec] || "var(--color-ink)",
                                fontWeight: 600,
                              }}
                            >
                              {RECOMMENDATION_LABEL[rec] || rec}
                            </span>
                            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--color-muted)" }}>
                              {count} · {pct.toFixed(0)}%
                            </span>
                          </div>
                          <div style={{ height: 6, borderRadius: 3, background: "var(--color-surface-muted)", overflow: "hidden" }}>
                            <div
                              style={{
                                height: "100%",
                                width: `${pct}%`,
                                background: RECOMMENDATION_TONE[rec] || "var(--color-accent)",
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
                  Top risk signals
                </h3>
              </div>
              <div className="p-4">
                {stats.top_risk_signals.length === 0 ? (
                  <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                    No risk signals recorded.
                  </p>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                    {stats.top_risk_signals.map((rs) => {
                      const max = stats.top_risk_signals[0]?.count || 1;
                      const pct = (rs.count / max) * 100;
                      return (
                        <li key={rs.risk_signal}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                            <span
                              style={{ fontSize: 12, color: "var(--color-ink)" }}
                              title={riskSignalLabel(rs.risk_signal)}
                            >
                              <span style={{ fontFamily: "monospace", color: "#B71D18", marginRight: 6 }}>
                                {rs.risk_signal}
                              </span>
                              <span style={{ color: "var(--color-muted)", fontSize: 11 }}>
                                {riskSignalLabel(rs.risk_signal)}
                              </span>
                            </span>
                            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--color-muted)" }}>
                              {rs.count}
                            </span>
                          </div>
                          <div style={{ height: 6, borderRadius: 3, background: "var(--color-surface-muted)", overflow: "hidden" }}>
                            <div
                              style={{
                                height: "100%",
                                width: `${pct}%`,
                                background: "#B71D18",
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
          </div>

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
  tone?: "success" | "warning" | "muted" | "error";
}) {
  const color =
    tone === "success" ? "#22C55E"
      : tone === "warning" ? "#FFAB00"
      : tone === "error" ? "#B71D18"
      : tone === "muted" ? "var(--color-muted)"
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
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          color: "var(--color-muted)",
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: "monospace",
          fontSize: 22,
          fontWeight: 700,
          color,
        }}
      >
        {value}
      </div>
      {hint ? (
        <div
          style={{
            fontSize: 10.5,
            color: "var(--color-muted)",
            marginTop: 4,
            lineHeight: 1.3,
          }}
        >
          {hint}
        </div>
      ) : null}
    </div>
  );
}


function DailyBars({
  daily,
}: {
  daily: Array<{
    date: string;
    total: number;
    completed: number;
    failed: number;
    takedown_now: number;
  }>;
}) {
  const max = Math.max(1, ...daily.map((d) => d.total));
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 110, overflowX: "auto" }}>
      {daily.map((d) => {
        const totalPct = (d.total / max) * 100;
        const failedPct = d.total > 0 ? (d.failed / d.total) * 100 : 0;
        const takedownPct = d.total > 0 ? (d.takedown_now / d.total) * 100 : 0;
        return (
          <div
            key={d.date}
            title={`${d.date}: ${d.total} total, ${d.completed} completed, ${d.failed} failed, ${d.takedown_now} takedown_now`}
            style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, flex: 1, minWidth: 18 }}
          >
            <div
              style={{
                width: "100%",
                height: `${totalPct}%`,
                minHeight: 2,
                borderRadius: 3,
                background: takedownPct > 0
                  ? "#B71D18"
                  : failedPct > 50
                    ? "#FF5630"
                    : "#22C55E",
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
