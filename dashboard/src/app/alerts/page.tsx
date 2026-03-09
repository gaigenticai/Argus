"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Filter, RefreshCw } from "lucide-react";
import { api, type Alert } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";

const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"];
const STATUSES = ["all", "new", "triaged", "investigating", "confirmed", "false_positive", "resolved"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");

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
      // API not reachable
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
          <h2 className="text-[24px] font-bold text-[#1C252E]">Alerts</h2>
          <p className="text-[14px] text-[#637381] mt-0.5">
            {alerts.length} alerts found
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-white rounded-xl text-[13px] font-semibold text-[#1C252E] shadow-[0_0_2px_0_rgba(145,158,171,0.2)] hover:shadow-[0_0_2px_0_rgba(145,158,171,0.4)] transition-shadow"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex items-center gap-2 bg-white rounded-xl px-3 py-2 shadow-[0_0_2px_0_rgba(145,158,171,0.2)]">
          <Filter className="w-4 h-4 text-[#919EAB]" />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="text-[13px] text-[#1C252E] bg-transparent outline-none cursor-pointer"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2 bg-white rounded-xl px-3 py-2 shadow-[0_0_2px_0_rgba(145,158,171,0.2)]">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="text-[13px] text-[#1C252E] bg-transparent outline-none cursor-pointer"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s === "all" ? "All statuses" : s.replace("_", " ").replace(/\b\w/g, (l) => l.toUpperCase())}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Alerts table */}
      <div className="bg-white rounded-2xl shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-[#919EAB]">
            <p className="text-[14px]">No alerts match your filters</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#F4F6F8]">
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Severity</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Title</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Category</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Status</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Confidence</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Date</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, i) => (
                <tr
                  key={alert.id}
                  className={`border-b border-[#F4F6F8] last:border-b-0 hover:bg-[#F9FAFB] transition-colors ${
                    i % 2 === 0 ? "" : "bg-[#FCFDFD]"
                  }`}
                >
                  <td className="px-6 py-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-6 py-3">
                    <Link
                      href={`/alerts/${alert.id}`}
                      className="text-[14px] font-semibold text-[#1C252E] hover:text-[#00A76F] transition-colors line-clamp-1"
                    >
                      {alert.title}
                    </Link>
                  </td>
                  <td className="px-6 py-3 text-[13px] text-[#637381]">
                    {categoryLabels[alert.category] || alert.category}
                  </td>
                  <td className="px-6 py-3">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-6 py-3 text-[13px] text-[#637381]">
                    {Math.round(alert.confidence * 100)}%
                  </td>
                  <td className="px-6 py-3 text-[13px] text-[#919EAB] whitespace-nowrap">
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
