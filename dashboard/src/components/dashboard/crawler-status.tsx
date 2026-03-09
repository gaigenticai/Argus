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
      <div className="flex items-center justify-center h-[200px] text-[14px] text-[#919EAB]">
        No crawlers registered
      </div>
    );
  }

  return (
    <div className="space-y-2 p-4">
      {crawlers.map((crawler) => (
        <div
          key={crawler.name}
          className="flex items-center gap-3 p-3 rounded-xl bg-[#F9FAFB] hover:bg-[#F4F6F8] transition-colors"
        >
          <div className="w-9 h-9 rounded-lg bg-[#EFD6FF] flex items-center justify-center">
            <Bot className="w-5 h-5 text-[#8E33FF]" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold text-[#1C252E]">{crawler.name}</p>
            <div className="flex items-center gap-2 mt-0.5">
              {crawler.last_run ? (
                <span className="flex items-center gap-1 text-[11px] text-[#22C55E]">
                  <CheckCircle className="w-3 h-3" />
                  {timeAgo(crawler.last_run)}
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] text-[#919EAB]">
                  <Clock className="w-3 h-3" />
                  Never run
                </span>
              )}
              <span className="text-[10px] text-[#C4CDD5]">|</span>
              <span className="text-[11px] text-[#919EAB]">
                Every {Math.round(crawler.interval_seconds / 60)}m
              </span>
            </div>
          </div>
          <button
            onClick={() => onTrigger(crawler.crawler_name)}
            className="p-2 rounded-lg hover:bg-[#C8FAD6] text-[#00A76F] transition-colors"
            title="Run now"
          >
            <Play className="w-4 h-4" />
          </button>
        </div>
      ))}
    </div>
  );
}
