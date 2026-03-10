"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Filter, RefreshCw } from "lucide-react";
import { api, type Alert } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";

const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"];
const STATUSES = ["all", "new", "triaged", "investigating", "confirmed", "false_positive", "resolved"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const { toast } = useToast();

  const load = async () => {
    setLoading(true);
    try {
      const data = await api.getAlerts({
        severity: severity === "all" ? undefined : severity,
        status: status === "all" ? undefined : status,
        limit: 100,
      });
      setAlerts(data);
    } catch {
      toast("error", "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [severity, status]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Alerts</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            {alerts.length} alerts found
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 text-grey-700 hover:bg-grey-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-grey-500" />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All statuses" : s.replace("_", " ").replace(/\b\w/g, (l) => l.toUpperCase())}
            </option>
          ))}
        </select>
      </div>

      {/* Alerts table */}
      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
            <p className="text-[14px]">No alerts match your filters</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-grey-100">
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Severity</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Title</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Category</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Status</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Confidence</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Date</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="h-[52px] border-b border-grey-200 last:border-b-0 hover:bg-grey-50 transition-colors"
                >
                  <td className="px-4">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4">
                    <Link
                      href={`/alerts/${alert.id}`}
                      className="text-[14px] font-semibold text-grey-800 hover:text-primary transition-colors line-clamp-1"
                    >
                      {alert.title}
                    </Link>
                  </td>
                  <td className="px-4 text-[13px] text-grey-600">
                    {categoryLabels[alert.category] || alert.category}
                  </td>
                  <td className="px-4">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-4 text-[13px] text-grey-600">
                    {Math.round(alert.confidence * 100)}%
                  </td>
                  <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                    {formatDate(alert.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
