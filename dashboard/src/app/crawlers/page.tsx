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

  useEffect(() => { load(); }, []);

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
      } catch {}
    }
    toast("success", `Triggered ${count}/${crawlers.length} crawlers`);
  }

  // Map crawler names to accent colours for the icon
  const crawlerIconColor: Record<string, string> = {
    TorForumCrawler: "#8E33FF",
    TorMarketplaceCrawler: "#8E33FF",
    TelegramCrawler: "#00BBD9",
    I2PEepsiteCrawler: "#FF5630",
    LokinetCrawler: "#B71D18",
    StealerLogCrawler: "#FFAB00",
    RansomwareLeakCrawler: "#FF5630",
    ForumCrawler: "#B76E00",
    MatrixCrawler: "#007B8A",
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Crawlers</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Manage and monitor intelligence collection agents
          </p>
        </div>
        <div className="flex gap-2">
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
          <button
            onClick={handleTriggerAll}
            role="button"
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border-strong)",
              background: "var(--color-surface-dark)",
              color: "var(--color-on-dark)",
            }}
          >
            <Zap className="w-4 h-4" />
            Run all
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div
            className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {crawlers.map((crawler) => (
            <div
              key={crawler.name}
              className="p-6"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
              }}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Bot
                    className="w-6 h-6"
                    style={{ color: crawlerIconColor[crawler.name] || "var(--color-muted)" }}
                  />
                  <div>
                    <h3 role="heading" className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
                      {crawler.name}
                    </h3>
                    <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                      Every {Math.round(crawler.interval_seconds / 60)} minutes
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  {crawler.last_run ? (
                    <>
                      <CheckCircle className="w-4 h-4" style={{ color: "#22C55E" }} />
                      <span className="text-[12px]" style={{ color: "var(--color-body)" }}>
                        Last run: {timeAgo(crawler.last_run)}
                      </span>
                    </>
                  ) : (
                    <>
                      <Clock className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                      <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>Never run</span>
                    </>
                  )}
                </div>
                <button
                  role="button"
                  onClick={() => handleTrigger(crawler.crawler_name)}
                  disabled={triggering === crawler.crawler_name}
                  className="flex items-center gap-1.5 px-3 h-8 text-[12px] font-semibold transition-colors disabled:opacity-50"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-border)",
                    background: "var(--color-surface-muted)",
                    color: "var(--color-body)",
                  }}
                  onMouseEnter={e => {
                    if (triggering !== crawler.crawler_name) {
                      e.currentTarget.style.background = "var(--color-accent)";
                      e.currentTarget.style.border = "1px solid var(--color-accent)";
                      e.currentTarget.style.color = "var(--color-on-dark)";
                    }
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = "var(--color-surface-muted)";
                    e.currentTarget.style.border = "1px solid var(--color-border)";
                    e.currentTarget.style.color = "var(--color-body)";
                  }}
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
