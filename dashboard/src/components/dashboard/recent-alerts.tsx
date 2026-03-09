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
      <div className="flex flex-col items-center justify-center h-[300px] text-[#919EAB]">
        <p className="text-[14px]">No alerts yet</p>
        <p className="text-[12px] mt-1">Alerts will appear here once crawlers detect threats</p>
      </div>
    );
  }

  return (
    <div className="space-y-0">
      {alerts.map((alert) => (
        <Link
          key={alert.id}
          href={`/alerts/${alert.id}`}
          className="flex items-start gap-4 p-4 hover:bg-[#F9FAFB] transition-colors border-b border-[#F4F6F8] last:border-b-0"
        >
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={alert.severity} />
              <span className="text-[12px] text-[#919EAB]">
                {categoryLabels[alert.category] || alert.category}
              </span>
            </div>
            <p className="text-[14px] font-semibold text-[#1C252E] truncate">
              {alert.title}
            </p>
            <p className="text-[13px] text-[#637381] mt-0.5 line-clamp-1">
              {alert.summary}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <StatusBadge status={alert.status} />
            <span className="text-[11px] text-[#919EAB]">{timeAgo(alert.created_at)}</span>
          </div>
        </Link>
      ))}

      <Link
        href="/alerts"
        className="flex items-center justify-center gap-1 py-3 text-[13px] font-semibold text-[#00A76F] hover:text-[#007867] transition-colors"
      >
        View all alerts
        <ArrowRight className="w-4 h-4" />
      </Link>
    </div>
  );
}
