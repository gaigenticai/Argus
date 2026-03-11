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
} from "lucide-react";
import { api, type FeedInfo, type FeedSummary } from "@/lib/api";
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
  const [loading, setLoading] = useState(true);
  const [triggeringFeeds, setTriggeringFeeds] = useState<Set<string>>(new Set());
  const [triageRunning, setTriageRunning] = useState(false);
  const [backfillRunning, setBackfillRunning] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const result = await api.getFeeds();
      setData(result);
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
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-[14px] text-grey-500">Loading feeds...</p>
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
          <h2 className="text-[22px] font-bold text-grey-900">Feeds</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Manage threat intelligence feeds and run AI triage
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleBackfill}
            disabled={backfillRunning}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 text-grey-700 hover:bg-grey-100 transition-colors disabled:opacity-50"
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
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-[#8E33FF] text-white hover:bg-[#6B21A8] transition-colors disabled:opacity-50"
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
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 text-grey-700 hover:bg-grey-100 transition-colors"
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
          color="#8E33FF"
          bgColor="#EFD6FF"
        />
      </div>

      {/* Agent Actions Card */}
      <div className="bg-gradient-to-r from-[#1B1135] to-[#0F1B2D] rounded-xl border border-[#8E33FF]/20 p-6">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-xl bg-[#8E33FF]/20 flex items-center justify-center">
            <Brain className="w-5 h-5 text-[#8E33FF]" />
          </div>
          <div>
            <h3 className="text-[16px] font-bold text-white">Agentic Intelligence Pipeline</h3>
            <p className="text-[13px] text-grey-500">
              AI-powered analysis of threat feeds — creates IOCs, generates alerts, correlates threats
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <div className="bg-white/[0.04] rounded-lg p-4 border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4 text-[#FFAB00]" />
              <span className="text-[12px] font-bold text-grey-400 uppercase tracking-wider">Feed Triage</span>
            </div>
            <p className="text-[13px] text-grey-300">
              LLM analyzes new feed entries, classifies threats, determines severity using z.ai GLM-5
            </p>
          </div>
          <div className="bg-white/[0.04] rounded-lg p-4 border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-4 h-4 text-[#FF5630]" />
              <span className="text-[12px] font-bold text-grey-400 uppercase tracking-wider">IOC Extraction</span>
            </div>
            <p className="text-[13px] text-grey-300">
              Auto-creates indicators of compromise from feeds — IPs, URLs, domains, hashes
            </p>
          </div>
          <div className="bg-white/[0.04] rounded-lg p-4 border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4 text-[#00BBD9]" />
              <span className="text-[12px] font-bold text-grey-400 uppercase tracking-wider">Alert Generation</span>
            </div>
            <p className="text-[13px] text-grey-300">
              Generates contextualized alerts with reasoning, recommended actions, and INFOCON updates
            </p>
          </div>
        </div>
      </div>

      {/* Feed Groups */}
      {Object.entries(grouped)
        .sort(([, a], [, b]) => {
          const aTotal = a.reduce((s, f) => s + f.active_entry_count, 0);
          const bTotal = b.reduce((s, f) => s + f.active_entry_count, 0);
          return bTotal - aTotal;
        })
        .map(([layer, layerFeeds]) => {
          const LayerIcon = LAYER_ICONS[layer] || Rss;
          const layerColor = layerFeeds[0]?.color || "#637381";
          const totalEntries = layerFeeds.reduce((s, f) => s + f.active_entry_count, 0);

          return (
            <div key={layer} className="bg-white rounded-xl border border-grey-200 overflow-hidden">
              {/* Layer header */}
              <div className="flex items-center gap-3 px-6 py-4 border-b border-grey-200">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: `${layerColor}16` }}
                >
                  <LayerIcon className="w-4 h-4" style={{ color: layerColor }} />
                </div>
                <div className="flex-1">
                  <h3 className="text-[15px] font-bold text-grey-900">
                    {LAYER_LABELS[layer] || layer.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                  </h3>
                  <p className="text-[12px] text-grey-500">{layerFeeds[0]?.description || `${layerFeeds.length} feed sources`}</p>
                </div>
                <div className="text-right">
                  <p className="text-[18px] font-extrabold" style={{ color: layerColor }}>
                    {totalEntries.toLocaleString()}
                  </p>
                  <p className="text-[11px] text-grey-500">active entries</p>
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
                      className="flex items-center gap-4 px-6 h-[60px] border-b border-grey-100 last:border-b-0 hover:bg-grey-50 transition-colors"
                    >
                      {/* Status indicator */}
                      <div
                        className={`w-2 h-2 rounded-full shrink-0 ${
                          isHealthy ? "bg-success" : feed.latest_entry_at ? "bg-warning" : "bg-grey-400"
                        }`}
                      />

                      {/* Feed name */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[14px] font-semibold text-grey-800">
                            {feed.feed_name}
                          </span>
                          {!feed.enabled && (
                            <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-grey-200 text-grey-500">
                              Disabled
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {feed.latest_entry_at ? (
                            <span className="flex items-center gap-1 text-[11px] text-success">
                              <CheckCircle className="w-3 h-3" />
                              {timeAgo(feed.latest_entry_at)}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[11px] text-grey-500">
                              <Clock className="w-3 h-3" />
                              Never polled
                            </span>
                          )}
                          <span className="text-[10px] text-grey-400">|</span>
                          <span className="text-[11px] text-grey-500">
                            Every {intervalLabel}
                          </span>
                        </div>
                      </div>

                      {/* Entry counts */}
                      <div className="text-right shrink-0 w-[120px]">
                        <span className="text-[14px] font-bold text-grey-800">
                          {feed.active_entry_count.toLocaleString()}
                        </span>
                        <span className="text-[12px] text-grey-500 ml-1">
                          / {feed.total_entry_count.toLocaleString()}
                        </span>
                      </div>

                      {/* Progress bar */}
                      <div className="w-[80px] shrink-0">
                        <div className="h-1.5 bg-grey-200 rounded-full overflow-hidden">
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
                        className="p-2 rounded-lg hover:bg-primary-lighter text-primary transition-colors disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
                        title="Poll now"
                      >
                        {isTriggering ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <Play className="w-4 h-4" />
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
