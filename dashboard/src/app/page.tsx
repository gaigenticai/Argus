"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Brain,
  Rss,
  Database,
  Zap,
  ArrowRight,
  Loader2,
} from "lucide-react";
import { api, type Alert, type AlertStats, type Crawler, type FeedSummary, type GlobalThreatStats } from "@/lib/api";
import { StatCard } from "@/components/shared/stat-card";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { CategoryChart } from "@/components/dashboard/category-chart";
import { RecentAlerts } from "@/components/dashboard/recent-alerts";
import { CrawlerStatus } from "@/components/dashboard/crawler-status";
import { useToast } from "@/components/shared/toast";

const INFOCON_STYLES: Record<string, { bg: string; dot: string; text: string }> = {
  green:  { bg: "rgba(34,197,94,0.10)",   dot: "var(--color-success)", text: "var(--color-success-dark)" },
  yellow: { bg: "rgba(245,158,11,0.10)",  dot: "var(--color-warning)", text: "var(--color-warning-dark)" },
  orange: { bg: "rgba(255,79,0,0.10)",    dot: "var(--color-accent)",  text: "var(--color-accent)" },
  red:    { bg: "rgba(239,68,68,0.10)",   dot: "var(--color-error)",   text: "var(--color-error-dark)" },
};

export default function DashboardPage() {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [feedData, setFeedData] = useState<FeedSummary | null>(null);
  const [threatStats, setThreatStats] = useState<GlobalThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [triageRunning, setTriageRunning] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    async function load() {
      try {
        const [s, a, c, f, ts] = await Promise.allSettled([
          api.getAlertStats(),
          api.getAlerts({ limit: 10 }),
          api.getCrawlers(),
          api.getFeeds(),
          api.getThreatMapStats(),
        ]);
        if (s.status === "fulfilled") setStats(s.value);
        if (a.status === "fulfilled") setAlerts(a.value);
        if (c.status === "fulfilled") setCrawlers(c.value);
        if (f.status === "fulfilled") setFeedData(f.value);
        if (ts.status === "fulfilled") setThreatStats(ts.value);
      } catch {
        toast("error", "Failed to connect to API server");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleTriggerCrawler = async (name: string) => {
    try {
      await api.triggerCrawler(name);
      toast("success", `Crawler ${name} triggered successfully`);
    } catch {
      toast("error", `Failed to trigger crawler ${name}`);
    }
  };

  const handleTriage = async () => {
    setTriageRunning(true);
    try {
      await api.triggerFeedTriage(24);
      toast("success", "AI triage dispatched — processing last 24h of entries");
    } catch {
      toast("error", "Failed to trigger AI triage");
    } finally {
      setTimeout(() => setTriageRunning(false), 3000);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div
            className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-border)", borderTopColor: "var(--color-accent)" }}
          />
          <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading…
          </p>
        </div>
      </div>
    );
  }

  const criticalCount = stats?.by_severity?.critical || 0;
  const newCount = stats?.by_status?.new || 0;
  const resolvedCount = stats?.by_status?.resolved || 0;
  const infoconLevel = threatStats?.infocon_level || "green";
  const infoconStyle = INFOCON_STYLES[infoconLevel] || INFOCON_STYLES.green;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <p
            className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            Overview
          </p>
          <h1
            className="text-[28px] font-medium leading-[1.1] tracking-[-0.02em]"
            style={{ color: "var(--color-ink)" }}
          >
            Dashboard
          </h1>
        </div>

        {/* INFOCON indicator */}
        <div
          className="flex items-center gap-2 px-3 py-1.5"
          style={{
            background: infoconStyle.bg,
            border: `1px solid ${infoconStyle.dot}30`,
            borderRadius: "20px",
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ background: infoconStyle.dot }}
          />
          <span
            className="text-[11px] font-semibold uppercase tracking-[0.8px]"
            style={{ color: infoconStyle.text }}
          >
            INFOCON {infoconLevel}
          </span>
        </div>
      </div>

      {/* Stat cards — border-forward, no saturated backgrounds */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          title="Total Alerts"
          value={stats?.total || 0}
          subtitle="All time"
          icon={AlertTriangle}
          color="var(--color-muted)"
        />
        <StatCard
          title="Critical"
          value={criticalCount}
          subtitle="Immediate action required"
          icon={ShieldAlert}
          color="var(--color-error)"
        />
        <StatCard
          title="New / Unreviewed"
          value={newCount}
          subtitle="Awaiting triage"
          icon={Eye}
          color="var(--color-accent)"
        />
        <StatCard
          title="Resolved"
          value={resolvedCount}
          subtitle="Successfully handled"
          icon={ShieldCheck}
          color="var(--color-success-dark)"
        />
      </div>

      {/* AI Triage Agent + Feed Health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* AI Triage Agent — dark reversed card */}
        <div
          className="p-6"
          style={{
            background: "var(--color-surface-dark)",
            borderRadius: "8px",
            border: "1px solid var(--color-border-strong)",
          }}
        >
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-3">
              <div
                className="w-9 h-9 flex items-center justify-center shrink-0"
                style={{
                  background: "rgba(255,79,0,0.15)",
                  borderRadius: "5px",
                  border: "1px solid rgba(255,79,0,0.2)",
                }}
              >
                <Brain className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
              </div>
              <div>
                <h3
                  className="text-[15px] font-semibold tracking-[-0.01em]"
                  style={{ color: "var(--color-on-dark)" }}
                >
                  AI Triage Agent
                </h3>
                <p className="text-[12px] mt-0.5" style={{ color: "var(--color-on-dark-muted)" }}>
                  Powered by your configured LLM
                </p>
              </div>
            </div>
            <button
              onClick={handleTriage}
              disabled={triageRunning}
              className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-opacity disabled:opacity-50"
              style={{
                background: "var(--color-accent)",
                color: "#fffefb",
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
              }}
            >
              {triageRunning ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5" />
              )}
              Run Triage
            </button>
          </div>

          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Feed Entries", value: threatStats?.total_entries?.toLocaleString() || "0" },
              { label: "C2 Servers", value: threatStats?.active_c2_servers || 0 },
              { label: "Exploited CVEs", value: threatStats?.exploited_cves_count || 0 },
            ].map((s) => (
              <div
                key={s.label}
                className="p-3"
                style={{
                  background: "rgba(255,254,251,0.05)",
                  borderRadius: "5px",
                  border: "1px solid rgba(255,254,251,0.08)",
                }}
              >
                <p
                  className="text-[24px] font-medium leading-none tracking-[-0.02em]"
                  style={{ color: "var(--color-on-dark)" }}
                >
                  {s.value}
                </p>
                <p
                  className="text-[10px] mt-2 font-semibold uppercase tracking-[0.7px]"
                  style={{ color: "var(--color-on-dark-muted)" }}
                >
                  {s.label}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Feed Health */}
        <div
          className="p-5"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "8px",
          }}
        >
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-3">
              <div
                className="w-9 h-9 flex items-center justify-center shrink-0"
                style={{
                  background: "var(--color-surface-muted)",
                  borderRadius: "5px",
                  border: "1px solid var(--color-border)",
                }}
              >
                <Rss className="w-4 h-4" style={{ color: "var(--color-body)" }} />
              </div>
              <div>
                <h3
                  className="text-[15px] font-semibold tracking-[-0.01em]"
                  style={{ color: "var(--color-ink)" }}
                >
                  Feed Health
                </h3>
                <p className="text-[12px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                  {feedData?.total_feeds || 0} feeds · {(feedData?.total_active_entries || 0).toLocaleString()} entries
                </p>
              </div>
            </div>
            <Link
              href="/feeds"
              className="flex items-center gap-1 text-[13px] font-semibold transition-colors"
              style={{ color: "var(--color-accent)" }}
            >
              Manage
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {feedData?.feeds && feedData.feeds.length > 0 ? (
            <div className="space-y-2.5">
              {feedData.feeds
                .sort((a, b) => b.active_entry_count - a.active_entry_count)
                .slice(0, 6)
                .map((feed) => {
                  const isHealthy =
                    feed.latest_entry_at &&
                    Date.now() - new Date(feed.latest_entry_at).getTime() < 86400000;
                  const pct =
                    feedData.total_active_entries > 0
                      ? (feed.active_entry_count / feedData.total_active_entries) * 100
                      : 0;

                  return (
                    <div key={feed.feed_name} className="flex items-center gap-3">
                      <div
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{
                          background: isHealthy
                            ? "var(--color-success)"
                            : "var(--color-border)",
                        }}
                      />
                      <span
                        className="text-[13px] w-[130px] truncate font-medium"
                        style={{ color: "var(--color-body)" }}
                      >
                        {feed.feed_name}
                      </span>
                      <div
                        className="flex-1 h-1 overflow-hidden"
                        style={{
                          background: "var(--color-surface-muted)",
                          borderRadius: "20px",
                        }}
                      >
                        <div
                          className="h-full"
                          style={{
                            width: `${Math.max(pct, 1)}%`,
                            background: feed.color || "var(--color-accent)",
                            borderRadius: "20px",
                          }}
                        />
                      </div>
                      <span
                        className="text-[12px] font-semibold w-[56px] text-right tabular-nums"
                        style={{ color: "var(--color-ink)", fontVariantNumeric: "tabular-nums" }}
                      >
                        {feed.active_entry_count.toLocaleString()}
                      </span>
                    </div>
                  );
                })}
            </div>
          ) : (
            <div
              className="flex items-center justify-center h-[100px] gap-2 text-[13px]"
              style={{ color: "var(--color-muted)" }}
            >
              <Database className="w-4 h-4" />
              No feed data available
            </div>
          )}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div
          className="p-5"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <h3
            className="text-[14px] font-semibold tracking-[-0.01em] mb-4"
            style={{ color: "var(--color-ink)" }}
          >
            Alerts by severity
          </h3>
          <SeverityChart data={stats?.by_severity || {}} />
        </div>
        <div
          className="p-5"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <h3
            className="text-[14px] font-semibold tracking-[-0.01em] mb-4"
            style={{ color: "var(--color-ink)" }}
          >
            Alerts by category
          </h3>
          <CategoryChart data={stats?.by_category || {}} />
        </div>
      </div>

      {/* Bottom row — recent alerts + crawler status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div
          className="lg:col-span-2 overflow-hidden"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div
            className="px-5 py-4"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3
              className="text-[14px] font-semibold tracking-[-0.01em]"
              style={{ color: "var(--color-ink)" }}
            >
              Recent alerts
            </h3>
          </div>
          <RecentAlerts alerts={alerts} />
        </div>
        <div
          className="overflow-hidden"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div
            className="px-5 py-4"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3
              className="text-[14px] font-semibold tracking-[-0.01em]"
              style={{ color: "var(--color-ink)" }}
            >
              Crawler status
            </h3>
          </div>
          <CrawlerStatus crawlers={crawlers} onTrigger={handleTriggerCrawler} />
        </div>
      </div>
    </div>
  );
}
