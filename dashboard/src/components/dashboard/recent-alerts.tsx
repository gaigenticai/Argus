"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { type Alert } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, timeAgo } from "@/lib/utils";

interface RecentAlertsProps {
  alerts: Alert[];
}

export function RecentAlerts({ alerts }: RecentAlertsProps) {
  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
        <p className="text-[13px]">No alerts yet</p>
        <p className="text-[12px] mt-1">Alerts will appear here once crawlers detect threats</p>
      </div>
    );
  }

  return (
    <div>
      {alerts.map((alert) => (
        <Link
          key={alert.id}
          href={`/alerts/${alert.id}`}
          className="flex items-center gap-4 px-4 h-[52px] transition-colors"
          style={{ borderBottom: "1px solid var(--color-border)" }}
          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
          onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
        >
          <div className="flex-1 min-w-0 flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <p className="text-[13px] font-semibold truncate" style={{ color: "var(--color-body)" }}>
              {alert.title}
            </p>
            <span className="text-[12px] shrink-0 hidden sm:inline" style={{ color: "var(--color-muted)" }}>
              {categoryLabels[alert.category] || alert.category}
            </span>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <StatusBadge status={alert.status} />
            <span className="text-[11px] w-16 text-right" style={{ color: "var(--color-muted)" }}>
              {timeAgo(alert.created_at)}
            </span>
          </div>
        </Link>
      ))}

      <Link
        href="/alerts"
        className="flex items-center justify-center gap-1 h-[44px] text-[13px] font-semibold transition-colors"
        style={{ color: "var(--color-accent)" }}
        onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
        onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
      >
        View all alerts
        <ArrowRight className="w-4 h-4" />
      </Link>
    </div>
  );
}
