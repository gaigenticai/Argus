"use client";

import { useEffect, useState } from "react";
import { Bot, Play, CheckCircle, Clock, RefreshCw, Zap } from "lucide-react";
import { api, type Crawler } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

export default function CrawlersPage() {
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const data = await api.getCrawlers();
      setCrawlers(data);
    } catch {}
    setLoading(false);
  }

  async function handleTrigger(name: string) {
    setTriggering(name);
    try {
      await api.triggerCrawler(name);
    } catch {}
    setTimeout(() => setTriggering(null), 2000);
  }

  async function handleTriggerAll() {
    for (const c of crawlers) {
      await api.triggerCrawler(c.crawler_name);
    }
  }

  const crawlerIcons: Record<string, string> = {
    CVECrawler: "#FF5630",
    PasteCrawler: "#FFAB00",
    GitHubCrawler: "#1C252E",
    TorForumCrawler: "#8E33FF",
    TorMarketplaceCrawler: "#8E33FF",
    TelegramCrawler: "#00BBD9",
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-bold text-[#1C252E]">Crawlers</h2>
          <p className="text-[14px] text-[#637381] mt-0.5">
            Manage and monitor intelligence collection agents
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-white rounded-xl text-[13px] font-semibold text-[#1C252E] shadow-[0_0_2px_0_rgba(145,158,171,0.2)] hover:shadow-[0_0_2px_0_rgba(145,158,171,0.4)] transition-shadow"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={handleTriggerAll}
            className="flex items-center gap-2 px-4 py-2 bg-[#1C252E] text-white rounded-xl text-[13px] font-bold hover:bg-[#454F5B] transition-colors"
          >
            <Zap className="w-4 h-4" />
            Run all
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {crawlers.map((crawler) => (
            <div
              key={crawler.name}
              className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div
                    className="w-11 h-11 rounded-xl flex items-center justify-center"
                    style={{ backgroundColor: (crawlerIcons[crawler.name] || "#919EAB") + "20" }}
                  >
                    <Bot className="w-6 h-6" style={{ color: crawlerIcons[crawler.name] || "#919EAB" }} />
                  </div>
                  <div>
                    <h3 className="text-[14px] font-bold text-[#1C252E]">{crawler.name}</h3>
                    <p className="text-[12px] text-[#919EAB]">
                      Every {Math.round(crawler.interval_seconds / 60)} minutes
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  {crawler.last_run ? (
                    <>
                      <CheckCircle className="w-4 h-4 text-[#22C55E]" />
                      <span className="text-[12px] text-[#637381]">
                        Last run: {timeAgo(crawler.last_run)}
                      </span>
                    </>
                  ) : (
                    <>
                      <Clock className="w-4 h-4 text-[#919EAB]" />
                      <span className="text-[12px] text-[#919EAB]">Never run</span>
                    </>
                  )}
                </div>
                <button
                  onClick={() => handleTrigger(crawler.crawler_name)}
                  disabled={triggering === crawler.crawler_name}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#C8FAD6] text-[#007867] rounded-lg text-[12px] font-bold hover:bg-[#5BE49B] transition-colors disabled:opacity-50"
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
