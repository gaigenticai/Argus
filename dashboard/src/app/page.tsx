"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Eye,
} from "lucide-react";
import { api, type Alert, type AlertStats, type Crawler } from "@/lib/api";
import { StatCard } from "@/components/shared/stat-card";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { CategoryChart } from "@/components/dashboard/category-chart";
import { RecentAlerts } from "@/components/dashboard/recent-alerts";
import { CrawlerStatus } from "@/components/dashboard/crawler-status";
import { useToast } from "@/components/shared/toast";

export default function DashboardPage() {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    async function load() {
      try {
        const [s, a, c] = await Promise.all([
          api.getAlertStats(),
          api.getAlerts({ limit: 10 }),
          api.getCrawlers(),
        ]);
        setStats(s);
        setAlerts(a);
        setCrawlers(c);
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

  return (
    <div className="space-y-6">
      {/* Page title */}
      <div>
        <h2 className="text-[22px] font-bold text-grey-900">Dashboard</h2>
        <p className="text-[14px] text-grey-500 mt-0.5">
          Real-time threat intelligence overview
        </p>
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
