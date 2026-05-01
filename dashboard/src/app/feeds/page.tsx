"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Rss,
  Play,
  Brain,
  MapPin,
  RefreshCw,
  CheckCircle,
  Clock,
  AlertTriangle,
  Zap,
  Database,
  Shield,
  Radio,
  Lock,
  Bug,
  Target,
  EyeOff,
  Ban,
  ShieldAlert,
  Network,
  MessageCircle,
  Fish,
  Skull,
  Loader2,
  BarChart3,
  TrendingUp,
} from "lucide-react";
import { api, type FeedInfo, type FeedSummary, type FeedbackStats } from "@/lib/api";
import { StatCard } from "@/components/shared/stat-card";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

const LAYER_ICONS: Record<string, typeof Rss> = {
  ransomware: Skull,
  botnet_c2: Radio,
  phishing: Fish,
  malware: Bug,
  honeypot: Target,
  tor_exit: EyeOff,
  ip_reputation: Ban,
  exploited_cve: ShieldAlert,
  ssl_abuse: Lock,
  bgp_hijack: Network,
  underground: MessageCircle,
};

const LAYER_LABELS: Record<string, string> = {
  ransomware: "Ransomware",
  botnet_c2: "Botnet C2",
  phishing: "Phishing",
  malware: "Malware",
  honeypot: "Honeypot",
  tor_exit: "Tor Exit",
  ip_reputation: "IP Reputation",
  exploited_cve: "Exploited CVEs",
  ssl_abuse: "SSL Abuse",
  bgp_hijack: "BGP Hijack",
  underground: "Underground",
};

export default function FeedsPage() {
  const [data, setData] = useState<FeedSummary | null>(null);
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [triggeringFeeds, setTriggeringFeeds] = useState<Set<string>>(new Set());
  const [triageRunning, setTriageRunning] = useState(false);
  const [backfillRunning, setBackfillRunning] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const [result, fbStats] = await Promise.all([
        api.getFeeds(),
        api.feedback.stats(),
      ]);
      setData(result);
      setFeedbackStats(fbStats);
    } catch {
      toast("error", "Failed to load feeds");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleTriggerFeed = async (feedName: string) => {
    setTriggeringFeeds((prev) => new Set([...prev, feedName]));
    try {
      await api.triggerFeed(feedName);
      toast("success", `Feed "${feedName}" poll dispatched`);
    } catch (err) {
      toast("error", `Failed to trigger ${feedName}: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setTriggeringFeeds((prev) => {
        const next = new Set(prev);
        next.delete(feedName);
        return next;
      });
    }
  };

  const handleTriage = async () => {
    setTriageRunning(true);
    try {
      await api.triggerFeedTriage(24);
      toast("success", "AI triage dispatched — processing last 24h of entries");
    } catch {
      toast("error", "Failed to trigger AI triage");
    } finally {
      setTimeout(() => setTriageRunning(false), 3000);
    }
  };

  const handleBackfill = async () => {
    setBackfillRunning(true);
    try {
      await api.backfillGeolocation();
      toast("success", "Geo backfill dispatched — resolving domains to IPs");
    } catch {
      toast("error", "Failed to trigger geo backfill");
    } finally {
      setTimeout(() => setBackfillRunning(false), 3000);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div
            className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
          <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>Loading feeds...</p>
        </div>
      </div>
    );
  }

  const feeds = data?.feeds || [];
  const grouped = feeds.reduce<Record<string, FeedInfo[]>>((acc, f) => {
    (acc[f.layer] = acc[f.layer] || []).push(f);
    return acc;
  }, {});

  const healthyCount = feeds.filter(
    (f) => f.latest_entry_at && Date.now() - new Date(f.latest_entry_at).getTime() < 86400000
  ).length;
  const staleCount = feeds.filter(
    (f) => !f.latest_entry_at || Date.now() - new Date(f.latest_entry_at).getTime() > 86400000
  ).length;

  const latestEntry = feeds
    .filter((f) => f.latest_entry_at)
    .sort((a, b) => new Date(b.latest_entry_at!).getTime() - new Date(a.latest_entry_at!).getTime())[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Feeds
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Manage threat intelligence feeds and run AI triage
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleBackfill}
            disabled={backfillRunning}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            {backfillRunning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <MapPin className="w-4 h-4" />
            )}
            Backfill Geo
          </button>
          <button
            onClick={handleTriage}
            disabled={triageRunning}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            {triageRunning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Brain className="w-4 h-4" />
            )}
            Run AI Triage
          </button>
          <button
            onClick={() => { setLoading(true); load(); }}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Feeds"
          value={data?.total_feeds || 0}
          subtitle={`${healthyCount} healthy, ${staleCount} stale`}
          icon={Rss}
          color="#00A76F"
          bgColor="#D3FCD2"
        />
        <StatCard
          title="Active Entries"
          value={(data?.total_active_entries || 0).toLocaleString()}
          subtitle="Non-expired entries across all feeds"
          icon={Database}
          color="#00BBD9"
          bgColor="#CAFDF5"
        />
        <StatCard
          title="Last Ingestion"
          value={latestEntry?.latest_entry_at ? timeAgo(latestEntry.latest_entry_at) : "Never"}
          subtitle={latestEntry ? `From ${latestEntry.feed_name}` : "No feeds polled yet"}
          icon={Clock}
          color="#FFAB00"
          bgColor="#FFF5CC"
        />
        <StatCard
          title="Threat Layers"
          value={Object.keys(grouped).length}
          subtitle="Active intelligence categories"
          icon={Shield}
          color="var(--color-accent)"
          bgColor="rgba(255,79,0,0.08)"
        />
      </div>

      {/* Triage Accuracy Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          title="Analyst Feedback"
          value={feedbackStats?.total_feedback ?? 0}
          subtitle="Total triage verdicts submitted"
          icon={MessageCircle}
          color="var(--color-accent)"
          bgColor="rgba(255,79,0,0.08)"
        />
        <StatCard
          title="True Positive Rate"
          value={feedbackStats ? `${Math.round((feedbackStats.true_positive_rate || 0) * 100)}%` : "—"}
          subtitle={`${feedbackStats?.true_positives ?? 0} TP / ${feedbackStats?.false_positives ?? 0} FP`}
          icon={TrendingUp}
          color="#00A76F"
          bgColor="#D3FCD2"
        />
        {(() => {
          const topCategory = feedbackStats?.category_accuracy?.sort((a, b) => b.accuracy - a.accuracy)[0];
          return (
            <StatCard
              title="Top Category Accuracy"
              value={topCategory ? topCategory.category : "—"}
              subtitle={topCategory ? `${Math.round(topCategory.accuracy)}% accuracy` : "No feedback yet"}
              icon={BarChart3}
              color="#00BBD9"
              bgColor="#CAFDF5"
            />
          );
        })()}
      </div>

      {/* Agent Actions Card */}
      <div
        className="p-6"
        style={{
          background: "var(--color-surface-dark)",
          border: "1px solid rgba(255,79,0,0.2)",
          borderRadius: "8px",
        }}
      >
        <div className="flex items-center gap-3 mb-3">
          <div
            className="w-10 h-10 flex items-center justify-center"
            style={{ borderRadius: "5px", background: "rgba(255,79,0,0.15)" }}
          >
            <Brain className="w-5 h-5" style={{ color: "var(--color-accent)" }} />
          </div>
          <div>
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-on-dark)" }}>Agentic Intelligence Pipeline</h3>
            <p className="text-[12px]" style={{ color: "rgba(255,254,251,0.5)" }}>
              AI-powered analysis of threat feeds — creates IOCs, generates alerts, correlates threats
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <div
            className="p-4"
            style={{
              background: "rgba(255,254,251,0.04)",
              borderRadius: "5px",
              border: "1px solid rgba(255,254,251,0.06)",
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4" style={{ color: "#FFAB00" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "rgba(255,254,251,0.4)" }}>Feed Triage</span>
            </div>
            <p className="text-[12px]" style={{ color: "rgba(255,254,251,0.6)" }}>
              LLM analyzes new feed entries, classifies threats, determines severity using z.ai GLM-5
            </p>
          </div>
          <div
            className="p-4"
            style={{
              background: "rgba(255,254,251,0.04)",
              borderRadius: "5px",
              border: "1px solid rgba(255,254,251,0.06)",
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-4 h-4" style={{ color: "#FF5630" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "rgba(255,254,251,0.4)" }}>IOC Extraction</span>
            </div>
            <p className="text-[12px]" style={{ color: "rgba(255,254,251,0.6)" }}>
              Auto-creates indicators of compromise from feeds — IPs, URLs, domains, hashes
            </p>
          </div>
          <div
            className="p-4"
            style={{
              background: "rgba(255,254,251,0.04)",
              borderRadius: "5px",
              border: "1px solid rgba(255,254,251,0.06)",
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4" style={{ color: "#00BBD9" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "rgba(255,254,251,0.4)" }}>Alert Generation</span>
            </div>
            <p className="text-[12px]" style={{ color: "rgba(255,254,251,0.6)" }}>
              Generates contextualized alerts with reasoning, recommended actions, and INFOCON updates
            </p>
          </div>
        </div>
      </div>

      {/* Empty state — no feeds configured */}
      {feeds.length === 0 ? (
        <div
          className="px-6 py-12"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex flex-col items-center justify-center text-center max-w-[520px] mx-auto">
            <div
              className="w-12 h-12 flex items-center justify-center mb-4"
              style={{ borderRadius: "5px", background: "rgba(255,171,0,0.12)" }}
            >
              <AlertTriangle className="w-5 h-5" style={{ color: "#B76E00" }} />
            </div>
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              No feeds configured
            </h3>
            <p className="text-[13px] mt-1.5" style={{ color: "var(--color-body)" }}>
              Argus has no threat-intelligence feeds enabled yet. Most feeds
              (OTX, KEV, GreyNoise, abuse.ch) require API keys set as
              environment variables; others (PhishTank, BinaryEdge,
              MalwareBazaar) work out of the box.
            </p>
            <div
              className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 text-[12px] font-mono"
              style={{
                borderRadius: "4px",
                background: "var(--color-surface-muted)",
                color: "var(--color-body)",
              }}
            >
              <code>ARGUS_OTX_API_KEY</code>
              <span style={{ color: "var(--color-muted)" }}>·</span>
              <code>ARGUS_GREYNOISE_API_KEY</code>
              <span style={{ color: "var(--color-muted)" }}>·</span>
              <code>...</code>
            </div>
            <p className="text-[11.5px] mt-3" style={{ color: "var(--color-muted)" }}>
              See <code className="font-mono" style={{ color: "var(--color-body)" }}>.env.example</code>{" "}
              for the full list, then restart the worker.
            </p>
          </div>
        </div>
      ) : null}

      {/* Feed Groups */}
      {Object.entries(grouped)
        .sort(([, a], [, b]) => {
          const aTotal = a.reduce((s, f) => s + f.active_entry_count, 0);
          const bTotal = b.reduce((s, f) => s + f.active_entry_count, 0);
          return bTotal - aTotal;
        })
        .map(([layer, layerFeeds]) => {
          const LayerIcon = LAYER_ICONS[layer] || Rss;
          const layerColor = layerFeeds[0]?.color || "var(--color-muted)";
          const totalEntries = layerFeeds.reduce((s, f) => s + f.active_entry_count, 0);

          return (
            <div
              key={layer}
              className="overflow-hidden"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
              }}
            >
              {/* Layer header */}
              <div
                className="flex items-center gap-3 px-6 py-4"
                style={{ borderBottom: "1px solid var(--color-border)" }}
              >
                <div
                  className="w-8 h-8 flex items-center justify-center"
                  style={{ borderRadius: "5px", backgroundColor: `${layerColor}18` }}
                >
                  <LayerIcon className="w-4 h-4" style={{ color: layerColor }} />
                </div>
                <div className="flex-1">
                  <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
                    {LAYER_LABELS[layer] || layer.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                  </h3>
                  <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                    {layerFeeds[0]?.description || `${layerFeeds.length} feed sources`}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-[18px] font-bold" style={{ color: layerColor }}>
                    {totalEntries.toLocaleString()}
                  </p>
                  <p className="text-[11px]" style={{ color: "var(--color-muted)" }}>active entries</p>
                </div>
              </div>

              {/* Feed rows */}
              <div>
                {layerFeeds.map((feed) => {
                  const isTriggering = triggeringFeeds.has(feed.feed_name);
                  const isHealthy = feed.latest_entry_at && Date.now() - new Date(feed.latest_entry_at).getTime() < 86400000;
                  const intervalLabel = feed.refresh_interval_seconds >= 3600
                    ? `${Math.round(feed.refresh_interval_seconds / 3600)}h`
                    : `${Math.round(feed.refresh_interval_seconds / 60)}m`;

                  return (
                    <div
                      key={feed.feed_name}
                      className="flex items-center gap-4 px-6 h-[60px] transition-colors"
                      style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      {/* Status indicator */}
                      <div
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{
                          backgroundColor: isHealthy ? "#22C55E" : feed.latest_entry_at ? "#FFAB00" : "var(--color-muted)",
                        }}
                      />

                      {/* Feed name */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                            {feed.feed_name}
                          </span>
                          {!feed.enabled && (
                            <span
                              className="text-[10px] font-semibold uppercase px-1.5 py-0.5"
                              style={{
                                borderRadius: "4px",
                                background: "var(--color-surface-muted)",
                                color: "var(--color-muted)",
                              }}
                            >
                              Disabled
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {feed.latest_entry_at ? (
                            <span className="flex items-center gap-1 text-[11px]" style={{ color: "#22C55E" }}>
                              <CheckCircle className="w-3 h-3" />
                              {timeAgo(feed.latest_entry_at)}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[11px]" style={{ color: "var(--color-muted)" }}>
                              <Clock className="w-3 h-3" />
                              Never polled
                            </span>
                          )}
                          <span className="text-[10px]" style={{ color: "var(--color-border)" }}>|</span>
                          <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                            Every {intervalLabel}
                          </span>
                        </div>
                      </div>

                      {/* Entry counts */}
                      <div className="text-right shrink-0 w-[120px]">
                        <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                          {feed.active_entry_count.toLocaleString()}
                        </span>
                        <span className="text-[12px] ml-1" style={{ color: "var(--color-muted)" }}>
                          / {feed.total_entry_count.toLocaleString()}
                        </span>
                      </div>

                      {/* Progress bar */}
                      <div className="w-[80px] shrink-0">
                        <div
                          className="h-1.5 rounded-full overflow-hidden"
                          style={{ background: "var(--color-surface-muted)" }}
                        >
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${feed.total_entry_count > 0 ? Math.min((feed.active_entry_count / feed.total_entry_count) * 100, 100) : 0}%`,
                              backgroundColor: layerColor,
                            }}
                          />
                        </div>
                      </div>

                      {/* Trigger button */}
                      <button
                        onClick={() => handleTriggerFeed(feed.feed_name)}
                        disabled={isTriggering || !feed.enabled}
                        className="p-2 transition-colors disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
                        style={{ borderRadius: "4px" }}
                        onMouseEnter={e => {
                          if (!isTriggering && feed.enabled) {
                            e.currentTarget.style.background = "var(--color-surface-muted)";
                            e.currentTarget.style.color = "var(--color-accent)";
                          }
                        }}
                        onMouseLeave={e => {
                          e.currentTarget.style.background = "transparent";
                          e.currentTarget.style.color = "var(--color-muted)";
                        }}
                        title="Poll now"
                      >
                        {isTriggering ? (
                          <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-accent)" }} />
                        ) : (
                          <Play className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                        )}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
    </div>
  );
}
