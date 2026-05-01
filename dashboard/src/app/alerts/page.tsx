"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Filter, RefreshCw, Brain, Loader2 } from "lucide-react";
import { api, type Alert } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";
import { Select } from "@/components/shared/select";

const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"];
const STATUSES = ["all", "new", "triaged", "investigating", "confirmed", "false_positive", "resolved"];

export default function AlertsPage() {
  const searchParams = useSearchParams();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  // Initialise filters from ``?severity=...&status=...`` so deep-links
  // from the dashboard KPI tiles arrive pre-filtered.
  const [severity, setSeverity] = useState(() => {
    const v = searchParams?.get("severity");
    return v && SEVERITIES.includes(v) ? v : "all";
  });
  const [status, setStatus] = useState(() => {
    const v = searchParams?.get("status");
    return v && STATUSES.includes(v) ? v : "all";
  });
  const [triageRunning, setTriageRunning] = useState(false);
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

  const handleTriage = async () => {
    setTriageRunning(true);
    try {
      await api.triggerFeedTriage(24);
      toast("success", "AI triage dispatched — analyzing last 24h of feed entries");
    } catch {
      toast("error", "Failed to trigger AI triage");
    } finally {
      setTimeout(() => setTriageRunning(false), 3000);
    }
  };

  const selectCls = "h-10 px-3 text-[13px] outline-none transition-colors cursor-pointer"

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Alerts
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {alerts.length} alerts found
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleTriage}
            disabled={triageRunning}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            {triageRunning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Brain className="w-4 h-4" />
            )}
            Run AI Triage
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
          <Select
            value={severity}
            onChange={setSeverity}
            ariaLabel="Severity filter"
            options={SEVERITIES.map((s) => ({
              value: s,
              label: s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1),
            }))}
          />
        </div>
        <Select
          value={status}
          onChange={setStatus}
          ariaLabel="Status filter"
          options={STATUSES.map((s) => ({
            value: s,
            label: s === "all" ? "All statuses" : s.replace("_", " ").replace(/\b\w/g, (l) => l.toUpperCase()),
          }))}
        />
      </div>

      {/* Alerts table */}
      <div
        className="overflow-hidden"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div
              className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
              style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
            />
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
            <Brain className="w-10 h-10 mb-3" style={{ color: "var(--color-border)" }} />
            <p className="text-[14px] font-semibold mb-1" style={{ color: "var(--color-body)" }}>No alerts yet</p>
            <p className="text-[13px] mb-4 max-w-sm text-center" style={{ color: "var(--color-muted)" }}>
              Alerts are generated by the AI triage agent when it analyzes threat feeds against your organizations.
            </p>
            <button
              onClick={handleTriage}
              disabled={triageRunning}
              className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
            >
              {triageRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Brain className="w-3.5 h-3.5" />}
              Run AI Triage Now
            </button>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface-muted)" }}>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Severity</th>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Title</th>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Category</th>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Status</th>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Confidence</th>
                <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="h-[52px] transition-colors"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4">
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/alerts/${alert.id}`}
                        className="text-[13px] font-semibold line-clamp-1 transition-colors"
                        style={{ color: "var(--color-ink)" }}
                        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-ink)")}
                      >
                        {alert.title}
                      </Link>
                      {alert.agent_reasoning && (
                        <span
                          className="shrink-0 flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5"
                          style={{
                            borderRadius: "4px",
                            background: "rgba(255,79,0,0.08)",
                            color: "var(--color-accent)",
                          }}
                        >
                          <Brain className="w-3 h-3" />
                          AI
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>
                    {categoryLabels[alert.category] || alert.category}
                  </td>
                  <td className="px-4">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>
                    {Math.round(alert.confidence * 100)}%
                  </td>
                  <td className="px-4 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
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
