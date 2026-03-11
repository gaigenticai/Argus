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
import { timeAgo } from "@/lib/utils";

const INFOCON_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  green: { bg: "bg-success-lighter", text: "text-success-dark", dot: "bg-success" },
  yellow: { bg: "bg-warning-lighter", text: "text-warning-dark", dot: "bg-warning" },
  orange: { bg: "bg-[#FF8B00]/10", text: "text-[#B76E00]", dot: "bg-[#FF8B00]" },
  red: { bg: "bg-error-lighter", text: "text-error-dark", dot: "bg-error" },
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
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-[14px] text-grey-500">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const criticalCount = stats?.by_severity?.critical || 0;
  const newCount = stats?.by_status?.new || 0;
  const resolvedCount = stats?.by_status?.resolved || 0;
  const infoconLevel = threatStats?.infocon_level || "green";
  const infoconStyle = INFOCON_COLORS[infoconLevel] || INFOCON_COLORS.green;

  return (
    <div className="space-y-6">
      {/* Page title */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Dashboard</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Real-time threat intelligence overview
          </p>
        </div>
        {/* INFOCON Badge */}
        <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${infoconStyle.bg}`}>
          <div className={`w-2.5 h-2.5 rounded-full ${infoconStyle.dot} animate-pulse`} />
          <span className={`text-[13px] font-bold uppercase tracking-wider ${infoconStyle.text}`}>
            INFOCON {infoconLevel}
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats?.total || 0}
          subtitle="All time"
          icon={AlertTriangle}
          color="#8E33FF"
          bgColor="#EFD6FF"
        />
        <StatCard
          title="Critical"
          value={criticalCount}
          subtitle="Immediate action required"
          icon={ShieldAlert}
          color="#FF5630"
          bgColor="#FFE9D5"
        />
        <StatCard
          title="New / Unreviewed"
          value={newCount}
          subtitle="Awaiting triage"
          icon={Eye}
          color="#FFAB00"
          bgColor="#FFF5CC"
        />
        <StatCard
          title="Resolved"
          value={resolvedCount}
          subtitle="Successfully handled"
          icon={ShieldCheck}
          color="#22C55E"
          bgColor="#D3FCD2"
        />
      </div>

      {/* Agent + Feed Status Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Agent Intelligence Card */}
        <div className="bg-gradient-to-br from-[#1B1135] to-[#0F1B2D] rounded-xl border border-[#8E33FF]/20 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-[#8E33FF]/20 flex items-center justify-center">
                <Brain className="w-5 h-5 text-[#8E33FF]" />
              </div>
              <div>
                <h3 className="text-[15px] font-bold text-white">AI Triage Agent</h3>
                <p className="text-[12px] text-grey-500">z.ai GLM-5 powered analysis</p>
              </div>
            </div>
            <button
              onClick={handleTriage}
              disabled={triageRunning}
              className="flex items-center gap-2 h-9 px-4 rounded-lg text-[13px] font-bold bg-[#8E33FF] text-white hover:bg-[#6B21A8] transition-colors disabled:opacity-50"
            >
              {triageRunning ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5" />
              )}
              Run Triage
            </button>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="bg-white/[0.04] rounded-lg p-3 border border-white/[0.06]">
              <p className="text-[22px] font-extrabold text-white">
                {threatStats?.total_entries?.toLocaleString() || 0}
              </p>
              <p className="text-[11px] text-grey-500 mt-0.5">Feed Entries</p>
            </div>
            <div className="bg-white/[0.04] rounded-lg p-3 border border-white/[0.06]">
              <p className="text-[22px] font-extrabold text-[#00BBD9]">
                {threatStats?.active_c2_servers || 0}
              </p>
              <p className="text-[11px] text-grey-500 mt-0.5">C2 Servers</p>
            </div>
            <div className="bg-white/[0.04] rounded-lg p-3 border border-white/[0.06]">
              <p className="text-[22px] font-extrabold text-[#FF5630]">
                {threatStats?.exploited_cves_count || 0}
              </p>
              <p className="text-[11px] text-grey-500 mt-0.5">Exploited CVEs</p>
            </div>
          </div>
        </div>

        {/* Feed Health Card */}
        <div className="bg-white rounded-xl border border-grey-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-[#00A76F]/10 flex items-center justify-center">
                <Rss className="w-5 h-5 text-[#00A76F]" />
              </div>
              <div>
                <h3 className="text-[15px] font-bold text-grey-900">Feed Health</h3>
                <p className="text-[12px] text-grey-500">
                  {feedData?.total_feeds || 0} feeds, {(feedData?.total_active_entries || 0).toLocaleString()} entries
                </p>
              </div>
            </div>
            <Link
              href="/feeds"
              className="flex items-center gap-1 text-[13px] font-bold text-primary hover:text-primary-dark transition-colors"
            >
              Manage
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          {feedData?.feeds && feedData.feeds.length > 0 ? (
            <div className="space-y-2">
              {feedData.feeds
                .sort((a, b) => b.active_entry_count - a.active_entry_count)
                .slice(0, 6)
                .map((feed) => {
                  const isHealthy = feed.latest_entry_at && Date.now() - new Date(feed.latest_entry_at).getTime() < 86400000;
                  const pct = feedData.total_active_entries > 0
                    ? (feed.active_entry_count / feedData.total_active_entries) * 100
                    : 0;

                  return (
                    <div key={feed.feed_name} className="flex items-center gap-3">
                      <div
                        className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          isHealthy ? "bg-success" : "bg-grey-400"
                        }`}
                      />
                      <span className="text-[13px] text-grey-700 w-[120px] truncate">
                        {feed.feed_name}
                      </span>
                      <div className="flex-1 h-1.5 bg-grey-100 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.max(pct, 1)}%`,
                            backgroundColor: feed.color || "#637381",
                          }}
                        />
                      </div>
                      <span className="text-[12px] font-bold text-grey-600 w-[60px] text-right">
                        {feed.active_entry_count.toLocaleString()}
                      </span>
                    </div>
                  );
                })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-[120px] text-[13px] text-grey-500">
              <Database className="w-5 h-5 mr-2 text-grey-400" />
              No feed data available
            </div>
          )}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-xl border border-grey-200 p-6">
          <h3 className="text-[16px] font-bold text-grey-900 mb-4">
            Alerts by severity
          </h3>
          <SeverityChart data={stats?.by_severity || {}} />
        </div>
        <div className="bg-white rounded-xl border border-grey-200 p-6">
          <h3 className="text-[16px] font-bold text-grey-900 mb-4">
            Alerts by category
          </h3>
          <CategoryChart data={stats?.by_category || {}} />
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-white rounded-xl border border-grey-200">
          <div className="px-6 py-4 border-b border-grey-200">
            <h3 className="text-[16px] font-bold text-grey-900">
              Recent alerts
            </h3>
          </div>
          <RecentAlerts alerts={alerts} />
        </div>
        <div className="bg-white rounded-xl border border-grey-200">
          <div className="px-6 py-4 border-b border-grey-200">
            <h3 className="text-[16px] font-bold text-grey-900">
              Crawler status
            </h3>
          </div>
          <CrawlerStatus crawlers={crawlers} onTrigger={handleTriggerCrawler} />
        </div>
      </div>
    </div>
  );
}
