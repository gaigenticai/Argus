"use client";

import { useEffect, useState } from "react";
import { Bot, Play, CheckCircle, Clock, RefreshCw, Zap } from "lucide-react";
import { api, type Crawler } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";

export default function CrawlersPage() {
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const data = await api.getCrawlers();
      setCrawlers(data);
    } catch {
      toast("error", "Failed to load crawlers");
    }
    setLoading(false);
  }

  async function handleTrigger(name: string) {
    setTriggering(name);
    try {
      await api.triggerCrawler(name);
      toast("success", `${name} triggered successfully`);
    } catch {
      toast("error", `Failed to trigger ${name}`);
    }
    setTimeout(() => setTriggering(null), 2000);
  }

  async function handleTriggerAll() {
    let count = 0;
    for (const c of crawlers) {
      try {
        await api.triggerCrawler(c.crawler_name);
        count++;
      } catch {
        // continue with others
      }
    }
    toast("success", `Triggered ${count}/${crawlers.length} crawlers`);
  }

  const crawlerColors: Record<string, string> = {
    TorForumCrawler: "text-secondary",
    TorMarketplaceCrawler: "text-secondary",
    TelegramCrawler: "text-info",
    I2PEepsiteCrawler: "text-error",
    LokinetCrawler: "text-error-dark",
    StealerLogCrawler: "text-warning",
    RansomwareLeakCrawler: "text-error",
    ForumCrawler: "text-warning-dark",
    MatrixCrawler: "text-info-dark",
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Crawlers</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Manage and monitor intelligence collection agents
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={handleTriggerAll}
            role="button"
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-grey-800 text-white hover:bg-grey-700 transition-colors"
          >
            <Zap className="w-4 h-4" />
            Run all
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {crawlers.map((crawler) => (
            <div
              key={crawler.name}
              className="bg-white rounded-xl border border-grey-200 p-6"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Bot className={`w-6 h-6 ${crawlerColors[crawler.name] || "text-grey-500"}`} />
                  <div>
                    <h3 role="heading" className="text-[14px] font-bold text-grey-900">{crawler.name}</h3>
                    <p className="text-[12px] text-grey-500">
                      Every {Math.round(crawler.interval_seconds / 60)} minutes
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  {crawler.last_run ? (
                    <>
                      <CheckCircle className="w-4 h-4 text-success" />
                      <span className="text-[12px] text-grey-600">
                        Last run: {timeAgo(crawler.last_run)}
                      </span>
                    </>
                  ) : (
                    <>
                      <Clock className="w-4 h-4 text-grey-500" />
                      <span className="text-[12px] text-grey-500">Never run</span>
                    </>
                  )}
                </div>
                <button
                  role="button"
                  onClick={() => handleTrigger(crawler.crawler_name)}
                  disabled={triggering === crawler.crawler_name}
                  className="flex items-center gap-1.5 px-3 h-8 rounded-lg text-[12px] font-bold bg-primary-lighter text-primary-dark hover:bg-primary hover:text-white transition-colors disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  {triggering === crawler.crawler_name ? "Running..." : "Run now"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
