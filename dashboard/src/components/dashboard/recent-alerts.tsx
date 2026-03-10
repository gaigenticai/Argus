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
      <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
        <p className="text-sm">No alerts yet</p>
        <p className="text-xs mt-1">Alerts will appear here once crawlers detect threats</p>
      </div>
    );
  }

  return (
    <div>
      {alerts.map((alert) => (
        <Link
          key={alert.id}
          href={`/alerts/${alert.id}`}
          className="flex items-center gap-4 px-4 h-[52px] hover:bg-grey-100 transition-colors border-b border-grey-200 last:border-b-0"
        >
          <div className="flex-1 min-w-0 flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <p className="text-sm font-semibold text-grey-800 truncate">
              {alert.title}
            </p>
            <span className="text-xs text-grey-500 shrink-0 hidden sm:inline">
              {categoryLabels[alert.category] || alert.category}
            </span>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <StatusBadge status={alert.status} />
            <span className="text-[11px] text-grey-500 w-16 text-right">{timeAgo(alert.created_at)}</span>
          </div>
        </Link>
      ))}

      <Link
        href="/alerts"
        className="flex items-center justify-center gap-1 h-[44px] text-[13px] font-semibold text-primary hover:text-primary-dark transition-colors"
      >
        View all alerts
        <ArrowRight className="w-4 h-4" />
      </Link>
    </div>
  );
}
