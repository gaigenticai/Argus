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
      <div className="flex items-center justify-center h-[200px] text-sm text-grey-500">
        No crawlers registered
      </div>
    );
  }

  return (
    <div>
      {crawlers.map((crawler) => (
        <div
          key={crawler.name}
          className="flex items-center gap-3 px-4 h-[52px] border-b border-grey-200 last:border-b-0 hover:bg-grey-100 transition-colors"
        >
          <Bot className="w-[18px] h-[18px] text-grey-500 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold text-grey-800">{crawler.name}</p>
            <div className="flex items-center gap-2">
              {crawler.last_run ? (
                <span className="flex items-center gap-1 text-[11px] text-success">
                  <CheckCircle className="w-3 h-3" />
                  {timeAgo(crawler.last_run)}
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] text-grey-500">
                  <Clock className="w-3 h-3" />
                  Never run
                </span>
              )}
              <span className="text-[10px] text-grey-400">|</span>
              <span className="text-[11px] text-grey-500">
                Every {Math.round(crawler.interval_seconds / 60)}m
              </span>
            </div>
          </div>
          <button
            onClick={() => onTrigger(crawler.crawler_name)}
            className="p-1.5 rounded-lg hover:bg-primary-lighter text-primary transition-colors"
            title="Run now"
          >
            <Play className="w-4 h-4" />
          </button>
        </div>
      ))}
    </div>
  );
}
