"use client";

import { Bot, Play, CheckCircle, Clock, AlertTriangle, CircleSlash } from "lucide-react";
import { type Crawler } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

// Map a crawler.last_status to (icon, color, label) so the
// dashboard widget tells the truth instead of just "Never run".
// Source values come from feed_health.status —
// ok / unconfigured / network_error / auth_error / rate_limited /
// parse_error / disabled.
const STATUS_PRESENTATION: Record<string, { color: string; icon: typeof CheckCircle; label?: string }> = {
  ok:             { color: "#22C55E", icon: CheckCircle },
  unconfigured:   { color: "#919EAB", icon: CircleSlash, label: "Unconfigured" },
  network_error:  { color: "#FF5630", icon: AlertTriangle, label: "Network error" },
  auth_error:     { color: "#FF8B00", icon: AlertTriangle, label: "Auth error" },
  rate_limited:   { color: "#FF8B00", icon: AlertTriangle, label: "Rate limited" },
  parse_error:    { color: "#FF5630", icon: AlertTriangle, label: "Parse error" },
  disabled:       { color: "#919EAB", icon: CircleSlash, label: "Disabled" },
};

interface CrawlerStatusProps {
  crawlers: Crawler[];
  onTrigger: (name: string) => void;
}

export function CrawlerStatus({ crawlers, onTrigger }: CrawlerStatusProps) {
  if (crawlers.length === 0) {
    return (
      <div className="flex items-center justify-center h-[200px] text-[13px]" style={{ color: "var(--color-muted)" }}>
        No crawlers registered
      </div>
    );
  }

  return (
    <div>
      {crawlers.map((crawler) => (
        <div
          key={crawler.name}
          className="flex items-center gap-3 px-4 h-[52px] transition-colors"
          style={{ borderBottom: "1px solid var(--color-border)" }}
          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
          onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
        >
          <Bot className="w-[18px] h-[18px] shrink-0" style={{ color: "var(--color-muted)" }} />
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>{crawler.name}</p>
            <div className="flex items-center gap-2">
              {(() => {
                const pres = crawler.last_status ? STATUS_PRESENTATION[crawler.last_status] : undefined;
                const Icon = pres?.icon ?? Clock;
                if (!crawler.last_run && !crawler.last_status) {
                  return (
                    <span className="flex items-center gap-1 text-[11px]" style={{ color: "var(--color-muted)" }}>
                      <Clock className="w-3 h-3" />
                      Never run
                    </span>
                  );
                }
                const color = pres?.color ?? "var(--color-muted)";
                const labelText = crawler.last_status === "ok"
                  ? (crawler.last_run ? timeAgo(crawler.last_run) : "ok")
                  : (pres?.label ?? crawler.last_status ?? "Unknown");
                return (
                  <span
                    className="flex items-center gap-1 text-[11px]"
                    style={{ color }}
                    title={crawler.last_detail ?? undefined}
                  >
                    <Icon className="w-3 h-3" />
                    {labelText}
                    {crawler.last_status === "ok" && crawler.last_rows_ingested > 0 && (
                      <span style={{ color: "var(--color-muted)" }}>
                        {" "}· {crawler.last_rows_ingested.toLocaleString()} rows
                      </span>
                    )}
                  </span>
                );
              })()}
              <span className="text-[10px]" style={{ color: "var(--color-border)" }}>|</span>
              <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                Every {Math.round(crawler.interval_seconds / 60)}m
              </span>
            </div>
          </div>
          <button
            onClick={() => onTrigger(crawler.name)}
            className="p-1.5 transition-colors"
            style={{ borderRadius: "4px" }}
            onMouseEnter={e => {
              e.currentTarget.style.background = "rgba(255,79,0,0.08)";
              e.currentTarget.style.color = "var(--color-accent)";
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.color = "var(--color-muted)";
            }}
            title="Run now"
          >
            <Play className="w-4 h-4" style={{ color: "inherit" }} />
          </button>
        </div>
      ))}
    </div>
  );
}
