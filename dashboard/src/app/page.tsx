"use client";

import { useEffect, useRef, useState } from "react";
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
  Sparkles,
  Info,
} from "lucide-react";
import { api, type Alert, type AlertStats, type Crawler, type DashboardExposure, type FeedSummary, type GlobalThreatStats, type OnboardingState, type Org, type TriageRunSummary } from "@/lib/api";
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

// localStorage key for the one-time "this is demo data" banner shown
// to realistic-seed users on first dashboard hit. Stored as
// "<email>:<seedmode>" so a re-seed (which can flip a fresh deploy
// back into demo mode) re-shows the banner.
const DEMO_BANNER_DISMISSED_KEY = "marsad_demo_banner_dismissed";

export default function DashboardPage() {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [feedData, setFeedData] = useState<FeedSummary | null>(null);
  const [threatStats, setThreatStats] = useState<GlobalThreatStats | null>(null);
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [showDemoBanner, setShowDemoBanner] = useState(false);
  const [loading, setLoading] = useState(true);
  const [triageRunning, setTriageRunning] = useState(false);
  const [latestTriage, setLatestTriage] = useState<TriageRunSummary | null>(null);
  const [exposure, setExposure] = useState<DashboardExposure | null>(null);
  const triagePollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // The header's <OrgScopeSwitcher> writes to ``argus_org_id`` and
  // dispatches ``argus:org-changed``; we re-render scoped queries
  // when that fires. The string lives in state (not a ref) so the
  // load effect's dependency array picks it up.
  const [scopeOrgId, setScopeOrgId] = useState<string>("");
  const [scopeOrg, setScopeOrg] = useState<Org | null>(null);
  // Bumped after a triage finishes so the load effect re-fetches
  // alerts/stats without needing the org-scope to change.
  const [refreshKey, setRefreshKey] = useState(0);
  const { toast } = useToast();

  // Read initial org scope + subscribe to changes.
  useEffect(() => {
    setScopeOrgId(window.localStorage.getItem("argus_org_id") || "");
    function handler(e: Event) {
      const detail = (e as CustomEvent<{ orgId: string }>).detail;
      setScopeOrgId(detail?.orgId || "");
    }
    window.addEventListener("argus:org-changed", handler as EventListener);
    return () => window.removeEventListener("argus:org-changed", handler as EventListener);
  }, []);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const orgId = scopeOrgId || undefined;
        const [s, a, c, f, ts, ob, orgs, lt, ex] = await Promise.allSettled([
          api.getAlertStats(orgId),
          api.getAlerts({ limit: 10, org_id: orgId }),
          api.getCrawlers(),
          api.getFeeds(),
          api.getThreatMapStats(),
          api.getOnboardingState(),
          orgId ? api.getOrgs() : Promise.resolve([]),
          api.getLatestTriageRun(),
          api.getDashboardExposure(),
        ]);
        if (s.status === "fulfilled") setStats(s.value);
        if (a.status === "fulfilled") setAlerts(a.value);
        if (c.status === "fulfilled") setCrawlers(c.value);
        if (f.status === "fulfilled") setFeedData(f.value);
        if (ts.status === "fulfilled") setThreatStats(ts.value);
        if (lt.status === "fulfilled") setLatestTriage(lt.value);
        if (ex.status === "fulfilled") setExposure(ex.value);
        if (orgs.status === "fulfilled" && orgId) {
          setScopeOrg(orgs.value.find((o) => o.id === orgId) ?? null);
        } else {
          setScopeOrg(null);
        }
        if (ob.status === "fulfilled") {
          setOnboarding(ob.value);
          // Show demo banner once per (user, seed_mode) pair — if
          // the operator runs ``./start.sh wipe`` and re-seeds with
          // realistic data, they should see the banner again.
          if (ob.value.next_action === "welcome_demo") {
            const stored = window.localStorage.getItem(DEMO_BANNER_DISMISSED_KEY) || "";
            const fingerprint = `${ob.value.current_user_email}:${ob.value.seed_mode}`;
            if (!stored.split(",").includes(fingerprint)) {
              setShowDemoBanner(true);
            }
          }
        }
      } catch {
        toast("error", "Failed to connect to API server");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [scopeOrgId, refreshKey]);

  const dismissDemoBanner = () => {
    if (!onboarding) return;
    setShowDemoBanner(false);
    const stored = window.localStorage.getItem(DEMO_BANNER_DISMISSED_KEY) || "";
    const fp = `${onboarding.current_user_email}:${onboarding.seed_mode}`;
    const next = stored ? `${stored},${fp}` : fp;
    window.localStorage.setItem(DEMO_BANNER_DISMISSED_KEY, next);
  };

  const handleTriggerCrawler = async (name: string) => {
    try {
      await api.triggerCrawler(name);
      toast("success", `Crawler ${name} triggered successfully`);
    } catch {
      toast("error", `Failed to trigger crawler ${name}`);
    }
  };

  // Stop any in-flight poll on unmount so we don't leak intervals.
  useEffect(() => {
    return () => {
      if (triagePollRef.current) {
        clearInterval(triagePollRef.current);
        triagePollRef.current = null;
      }
    };
  }, []);

  const handleTriage = async () => {
    if (triageRunning) return;
    setTriageRunning(true);
    let previousId: string | null = null;
    try {
      const r = await api.triggerFeedTriage(24);
      previousId = r.previous_run_id;
      toast("success", "AI triage dispatched — processing last 24h of entries");
    } catch {
      toast("error", "Failed to trigger AI triage");
      setTriageRunning(false);
      return;
    }

    // Poll /feeds/triage/latest every 2s until a NEW run row appears
    // (id != previousId) AND its status is no longer "running". Cap at
    // 90s — manual triage normally finishes in <30s; if we time out
    // the row will eventually settle in the next page load.
    const start = Date.now();
    if (triagePollRef.current) clearInterval(triagePollRef.current);
    triagePollRef.current = setInterval(async () => {
      try {
        const latest = await api.getLatestTriageRun();
        if (!latest) return;
        const isNew = latest.id !== previousId;
        const isDone = latest.status !== "running";
        if (isNew && isDone) {
          if (triagePollRef.current) {
            clearInterval(triagePollRef.current);
            triagePollRef.current = null;
          }
          setLatestTriage(latest);
          setTriageRunning(false);
          if (latest.status === "error") {
            toast("error", `Triage failed: ${latest.error_message ?? "unknown error"}`);
          } else {
            toast(
              "success",
              `Triage complete — ${latest.iocs_created} IOCs, ${latest.alerts_generated} alerts in ${latest.duration_seconds.toFixed(1)}s`,
            );
            // Refresh dashboard counters so new alerts/IOCs appear.
            setRefreshKey((k) => k + 1);
          }
        }
      } catch {
        // transient — keep polling until timeout
      }
      if (Date.now() - start > 90_000) {
        if (triagePollRef.current) {
          clearInterval(triagePollRef.current);
          triagePollRef.current = null;
        }
        setTriageRunning(false);
        toast("error", "Triage poll timed out — refresh in a moment to see results");
      }
    }, 2000);
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
      {showDemoBanner && (
        <DemoSeedBanner
          orgCount={onboarding?.seed_org_count ?? 0}
          orgNames={onboarding?.seed_org_names ?? []}
          onDismiss={dismissDemoBanner}
        />
      )}
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

        {/* INFOCON indicator + info tooltip */}
        <InfoconBadge level={infoconLevel} style={infoconStyle} />
      </div>

      {/* Stat cards — border-forward, no saturated backgrounds */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          title="Total Alerts"
          value={stats?.total || 0}
          subtitle="All time"
          icon={AlertTriangle}
          color="var(--color-muted)"
          href="/alerts"
        />
        <StatCard
          title="Critical"
          value={criticalCount}
          subtitle="Immediate action required"
          icon={ShieldAlert}
          color="var(--color-error)"
          href="/alerts?severity=critical"
        />
        <StatCard
          title="New / Unreviewed"
          value={newCount}
          subtitle="Awaiting triage"
          icon={Eye}
          color="var(--color-accent)"
          href="/alerts?status=new"
        />
        <StatCard
          title="Resolved"
          value={resolvedCount}
          subtitle="Successfully handled"
          icon={ShieldCheck}
          color="var(--color-success-dark)"
          href="/alerts?status=resolved"
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
                <div className="flex items-center gap-1.5">
                  <h3
                    className="text-[15px] font-semibold tracking-[-0.01em]"
                    style={{ color: "var(--color-on-dark)" }}
                  >
                    AI Triage Agent
                  </h3>
                  <TriageInfoTooltip />
                </div>
                <p className="text-[12px] mt-0.5" style={{ color: "var(--color-on-dark-muted)" }}>
                  {triageRunning
                    ? "Running… analyzing recent feed entries"
                    : latestTriage
                      ? `Last run ${formatAgo(latestTriage.created_at)} · ${latestTriage.iocs_created} IOCs · ${latestTriage.alerts_generated} alerts${latestTriage.status === "error" ? " · failed" : ""}`
                      : "Powered by your configured LLM"}
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
              {triageRunning ? "Running…" : "Run Triage"}
            </button>
          </div>

          <div className="grid grid-cols-3 gap-2">
            {[
              {
                label: "CVEs Affecting You",
                value: exposure?.cves_affecting_you?.toLocaleString() ?? "—",
                href: "/intel",
                hint: exposure
                  ? `${exposure.declared_components} declared component${exposure.declared_components === 1 ? "" : "s"}`
                  : undefined,
              },
              {
                label: "Open Alerts",
                value: exposure?.open_alerts?.toLocaleString() ?? "—",
                href: "/alerts?status=new",
                hint: "Not resolved · not false-positive",
              },
              {
                label: "Tracked IOCs",
                value: exposure?.tracked_iocs?.toLocaleString() ?? "—",
                href: "/iocs",
                hint: "From your alerts",
              },
            ].map((s) => (
              <Link
                key={s.label}
                href={s.href}
                className="p-3 dark-stat-tile block"
                style={{
                  background: "rgba(255,254,251,0.05)",
                  borderRadius: "5px",
                  border: "1px solid rgba(255,254,251,0.08)",
                  transition: "background 0.15s ease, border-color 0.15s ease",
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
                {s.hint && (
                  <p
                    className="text-[10px] mt-1 leading-tight"
                    style={{ color: "var(--color-on-dark-muted)", opacity: 0.7 }}
                  >
                    {s.hint}
                  </p>
                )}
              </Link>
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
            className="px-5 py-4 flex items-center justify-between"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3
              className="text-[14px] font-semibold tracking-[-0.01em]"
              style={{ color: "var(--color-ink)" }}
            >
              Crawler status
            </h3>
            <Link
              href="/crawlers"
              className="text-[12px] font-semibold"
              style={{ color: "var(--color-accent)" }}
            >
              Manage →
            </Link>
          </div>
          <CrawlerStatus crawlers={crawlers} onTrigger={handleTriggerCrawler} />
        </div>
      </div>
    </div>
  );
}

function DemoSeedBanner({
  orgCount,
  orgNames,
  onDismiss,
}: {
  orgCount: number;
  orgNames: string[];
  onDismiss: () => void;
}) {
  const namePreview =
    orgNames.length === 0
      ? ""
      : orgNames.length <= 2
        ? ` (${orgNames.join(" + ")})`
        : ` (${orgNames.slice(0, 2).join(", ")} + ${orgNames.length - 2} more)`;
  return (
    <div
      className="px-5 py-4 flex items-start gap-3"
      style={{
        background: "linear-gradient(90deg, rgba(255,79,0,0.06), rgba(255,79,0,0.02))",
        border: "1px solid rgba(255,79,0,0.2)",
        borderRadius: 5,
      }}
    >
      <div
        className="w-8 h-8 flex items-center justify-center shrink-0"
        style={{ background: "var(--color-accent)", borderRadius: 4 }}
      >
        <Sparkles className="w-4 h-4" style={{ color: "var(--color-on-dark)" }} />
      </div>
      <div className="flex-1 min-w-0">
        <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
          You&apos;re looking at demo data.
        </h3>
        <p className="text-[12.5px] mt-0.5 leading-relaxed" style={{ color: "var(--color-body)" }}>
          Marsad seeded {orgCount} sample organization{orgCount === 1 ? "" : "s"}{namePreview} so
          every dashboard screen has representative IOCs, alerts, cases, and
          threat actors. To monitor your own organization,{" "}
          <Link
            href="/welcome"
            style={{ color: "var(--color-accent)", textDecoration: "underline", fontWeight: 600 }}
          >
            run the 2-minute quickstart
          </Link>
          {" "}or use the full{" "}
          <Link
            href="/onboarding"
            style={{ color: "var(--color-accent)", textDecoration: "underline", fontWeight: 600 }}
          >
            registration wizard
          </Link>
          .
        </p>
      </div>
      <button
        onClick={onDismiss}
        className="text-[12px] font-semibold shrink-0"
        style={{ color: "var(--color-muted)", background: "transparent", border: "none", cursor: "pointer" }}
      >
        Dismiss
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// INFOCON badge with click-to-toggle info tooltip.
//
// INFOCON is a global posture indicator computed by the feed-triage
// agent (``src/agents/feed_triage.py::_update_infocon``) from the
// volume of critical / high severity feed entries in the last 24h.
// Without an inline explanation operators see "INFOCON RED" and have
// no way to know what triggered it or whether it's actionable.
// ---------------------------------------------------------------------------
const INFOCON_INFO: { level: string; label: string; rule: string }[] = [
  { level: "green",  label: "Green",  rule: "Baseline — no surge in critical/high feed activity." },
  { level: "yellow", label: "Yellow", rule: "≥1 critical AND ≥5 high severity feed entries in last 24h." },
  { level: "orange", label: "Orange", rule: "≥2 critical AND ≥10 high severity feed entries in last 24h." },
  { level: "red",    label: "Red",    rule: "≥5 critical AND ≥20 high severity feed entries in last 24h." },
];

function InfoconBadge({
  level,
  style,
}: {
  level: string;
  style: { bg: string; dot: string; text: string };
}) {
  const [open, setOpen] = useState(false);

  // Close on outside click / Escape — minimal, no portal.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") setOpen(false); }
    function onClick(e: MouseEvent) {
      const tgt = e.target as HTMLElement;
      if (!tgt.closest("[data-infocon-pop]")) setOpen(false);
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open]);

  return (
    <div className="relative" data-infocon-pop>
      <div
        className="flex items-center gap-2 px-3 py-1.5"
        style={{
          background: style.bg,
          border: `1px solid ${style.dot}30`,
          borderRadius: "20px",
        }}
      >
        <span
          className="w-1.5 h-1.5 rounded-full animate-pulse"
          style={{ background: style.dot }}
        />
        <span
          className="text-[11px] font-semibold uppercase tracking-[0.8px]"
          style={{ color: style.text }}
        >
          INFOCON {level}
        </span>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
          aria-label="What does INFOCON mean?"
          aria-expanded={open}
          className="flex items-center justify-center w-4 h-4 rounded-full transition-opacity hover:opacity-70"
          style={{ color: style.text, background: "transparent", border: "none", cursor: "pointer" }}
        >
          <Info className="w-3.5 h-3.5" />
        </button>
      </div>
      {open && (
        <div
          role="dialog"
          className="absolute right-0 mt-2 z-20 w-[320px] p-4 shadow-lg"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
          }}
        >
          <p
            className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            INFOCON levels
          </p>
          <p className="text-[12.5px] mb-3 leading-relaxed" style={{ color: "var(--color-body)" }}>
            Global posture computed every triage run from the last 24h
            of feed entries. Higher level ⇒ more high/critical activity
            in upstream threat feeds (not your org's alerts).
          </p>
          <ul className="space-y-2">
            {INFOCON_INFO.map((entry) => {
              const s = INFOCON_STYLES[entry.level];
              const active = entry.level === level;
              return (
                <li key={entry.level} className="flex items-start gap-2">
                  <span
                    className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                    style={{ background: s.dot }}
                  />
                  <div className="text-[12px] leading-snug" style={{ color: "var(--color-ink)" }}>
                    <span style={{ fontWeight: active ? 700 : 600, color: active ? s.text : "var(--color-ink)" }}>
                      {entry.label}
                    </span>
                    {active && (
                      <span
                        className="ml-1 text-[10px] font-semibold uppercase tracking-[0.6px]"
                        style={{ color: s.text }}
                      >
                        · current
                      </span>
                    )}
                    <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-body)" }}>
                      {entry.rule}
                    </p>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}

// AI Triage Agent ⓘ — explains the agent's purpose, what it
// reads, what it writes, and the cadence. Sits next to the title
// inside the dark card so the operator can self-serve "what does
// this thing do?" without hunting in docs.
function TriageInfoTooltip() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") setOpen(false); }
    function onClick(e: MouseEvent) {
      const tgt = e.target as HTMLElement;
      if (!tgt.closest("[data-triage-info]")) setOpen(false);
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open]);

  return (
    <span className="relative inline-block" data-triage-info>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        aria-label="What does the AI Triage Agent do?"
        aria-expanded={open}
        className="flex items-center justify-center w-4 h-4 transition-opacity hover:opacity-70"
        style={{ color: "var(--color-on-dark-muted)", background: "transparent", border: "none", cursor: "pointer" }}
      >
        <Info className="w-3.5 h-3.5" />
      </button>
      {open && (
        <div
          role="dialog"
          className="absolute left-0 mt-2 z-20 w-[360px] p-4 shadow-lg"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
            // The card behind us is dark; the popover is light, so we
            // sit on top with a small offset for visual separation.
          }}
        >
          <p
            className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            What this is
          </p>
          <p className="text-[12.5px] mb-3 leading-relaxed" style={{ color: "var(--color-body)" }}>
            The agentic brain. Scans the last 24h of upstream threat
            feeds, correlates them against your declared{" "}
            <strong>tech stack</strong>, brand keywords, and domains,
            then asks the configured LLM whether each matching batch
            is a real threat to <em>you</em> specifically.
          </p>

          <p
            className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            What it produces
          </p>
          <ul className="text-[12.5px] mb-3 space-y-1 leading-relaxed" style={{ color: "var(--color-body)" }}>
            <li>
              <strong>IOCs</strong> — indicators (IPs, domains, hashes,
              CVEs) extracted from the batch and tagged as evidence
              for any alert that fires.
            </li>
            <li>
              <strong>Alerts</strong> — only when the LLM judges
              ``is_threat: true`` for your org, with title, summary,
              reasoning, and recommended actions.
            </li>
          </ul>

          <p
            className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            When it runs
          </p>
          <p className="text-[12.5px] mb-3 leading-relaxed" style={{ color: "var(--color-body)" }}>
            Click <strong>Run Triage</strong> for an on-demand sweep.
            Otherwise it&apos;s scheduled by the platform after each
            feed refresh. Manual runs are non-blocking — you can
            navigate away while it works.
          </p>

          <p
            className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Cost guard
          </p>
          <p className="text-[12.5px] leading-relaxed" style={{ color: "var(--color-body)" }}>
            A pre-filter drops feed batches that don&apos;t mention
            your stack/brand <em>before</em> any LLM call. Improve
            recall by completing your{" "}
            <Link href="/settings?tab=tech-stack" style={{ color: "var(--color-accent)", textDecoration: "underline", fontWeight: 600 }}>
              Tech Stack
            </Link>
            .
          </p>
        </div>
      )}
    </span>
  );
}

function formatAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "just now";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const d = Math.round(hr / 24);
  return `${d}d ago`;
}
