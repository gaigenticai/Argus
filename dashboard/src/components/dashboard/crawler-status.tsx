"use client";

import { Bot, Play, CheckCircle, Clock } from "lucide-react";
import { type Crawler } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

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
              {crawler.last_run ? (
                <span className="flex items-center gap-1 text-[11px]" style={{ color: "#22C55E" }}>
                  <CheckCircle className="w-3 h-3" />
                  {timeAgo(crawler.last_run)}
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px]" style={{ color: "var(--color-muted)" }}>
                  <Clock className="w-3 h-3" />
                  Never run
                </span>
              )}
              <span className="text-[10px]" style={{ color: "var(--color-border)" }}>|</span>
              <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                Every {Math.round(crawler.interval_seconds / 60)}m
              </span>
            </div>
          </div>
          <button
            onClick={() => onTrigger(crawler.crawler_name)}
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
