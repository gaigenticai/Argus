"use client";

/**
 * Threat Layer detail page — drill-down for a single layer (e.g.
 * Honeypot, IP Reputation, Exploited CVE).
 *
 * Reached by clicking a layer header on /feeds. Aggregates all the
 * feeds within the layer and shows their per-source counts plus
 * cross-feed breakdowns by severity and country. Each feed row in
 * the table opens the same FeedDetailDrawer used on /feeds, so the
 * navigation pattern is consistent.
 */

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Database,
  Globe2,
  Layers,
  Loader2,
  Play,
  AlertCircle,
  CheckCircle,
} from "lucide-react";
import {
  api,
  type LayerSummaryResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { FeedDetailDrawer } from "@/components/feeds/feed-detail-drawer";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--color-error-dark)",
  high: "var(--color-error)",
  medium: "var(--color-warning-dark)",
  low: "var(--color-success-dark)",
  info: "var(--color-muted)",
};

export default function LayerDetailPage({
  params,
}: {
  params: Promise<{ layer: string }>;
}) {
  const { layer } = use(params);
  const { toast } = useToast();
  const [summary, setSummary] = useState<LayerSummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerFeed, setDrawerFeed] = useState<string | null>(null);
  const [triggering, setTriggering] = useState<Set<string>>(new Set());

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await api.getLayerSummary(layer);
      setSummary(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load layer");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layer]);

  const handleTrigger = async (feedName: string) => {
    setTriggering((s) => new Set(s).add(feedName));
    try {
      await api.triggerFeed(feedName);
      toast("success", `Triggered ${feedName}`);
    } catch (e) {
      toast("error", `Failed to trigger ${feedName}: ${e instanceof Error ? e.message : "unknown error"}`);
    } finally {
      setTriggering((s) => {
        const next = new Set(s);
        next.delete(feedName);
        return next;
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-5 h-5 animate-spin" style={{ color: "var(--color-muted)" }} />
      </div>
    );
  }

  if (error || !summary) {
    return (
      <div
        className="px-4 py-6 flex items-center gap-2 text-[13px]"
        style={{
          background: "rgba(239,68,68,0.08)",
          border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: 5,
          color: "var(--color-error-dark)",
        }}
      >
        <AlertCircle className="w-4 h-4" />
        {error ?? `Layer ${layer} not found`}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <Link
        href="/feeds"
        className="inline-flex items-center gap-1.5 text-[12.5px]"
        style={{ color: "var(--color-muted)" }}
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        Back to Feed Health
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p
            className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            Threat layer
          </p>
          <h1
            className="text-[28px] font-medium leading-[1.1] tracking-[-0.02em]"
            style={{ color: "var(--color-ink)" }}
          >
            {summary.display_name}
          </h1>
          {summary.description && (
            <p className="text-[13px] mt-1.5 max-w-[680px]" style={{ color: "var(--color-body)" }}>
              {summary.description}
            </p>
          )}
        </div>
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Tile icon={Database} label="Active entries" value={summary.active_entries} accent={summary.color} />
        <Tile icon={Layers} label="Total ever ingested" value={summary.total_entries} muted />
        <Tile icon={CheckCircle} label="Feeds in layer" value={summary.feeds.length} />
        <Tile
          icon={Globe2}
          label="Top country"
          value={summary.by_country[0]?.count ?? 0}
          subValue={summary.by_country[0]?.country_code}
        />
      </div>

      {/* Feed table */}
      <div
        className="overflow-hidden"
        style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: 5 }}
      >
        <div
          className="px-5 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3
            className="text-[12px] font-semibold uppercase tracking-[0.7px]"
            style={{ color: "var(--color-muted)" }}
          >
            Feeds in this layer ({summary.feeds.length})
          </h3>
          {summary.latest_entry_at && (
            <p className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>
              Latest entry: {new Date(summary.latest_entry_at).toLocaleString()}
            </p>
          )}
        </div>

        {summary.feeds.length === 0 ? (
          <div className="px-5 py-8 text-center text-[13px]" style={{ color: "var(--color-muted)" }}>
            No feeds configured for this layer.
          </div>
        ) : (
          <table className="w-full text-[13px]" style={{ borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--color-surface-muted)" }}>
                <Th>Feed</Th>
                <Th>Active</Th>
                <Th>Total</Th>
                <Th>Latest</Th>
                <th className="px-3 py-2 w-[1%]" />
              </tr>
            </thead>
            <tbody>
              {summary.feeds.map((f) => {
                const isTriggering = triggering.has(f.feed_name);
                return (
                  <tr
                    key={f.feed_name}
                    className="cursor-pointer transition-colors"
                    style={{ borderTop: "1px solid var(--color-surface-muted)" }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    onClick={() => setDrawerFeed(f.feed_name)}
                  >
                    <Td>
                      <span className="font-semibold" style={{ color: "var(--color-ink)" }}>
                        {f.feed_name}
                      </span>
                      {!f.enabled && (
                        <span
                          className="ml-2 text-[10px] font-semibold uppercase tracking-[0.6px] px-1.5 py-0.5"
                          style={{
                            background: "var(--color-surface-muted)",
                            color: "var(--color-muted)",
                            borderRadius: 3,
                          }}
                        >
                          Disabled
                        </span>
                      )}
                    </Td>
                    <Td>
                      <span style={{ color: "var(--color-ink)" }}>
                        {f.active_entry_count.toLocaleString()}
                      </span>
                    </Td>
                    <Td>
                      <span style={{ color: "var(--color-body)" }}>
                        {f.total_entry_count.toLocaleString()}
                      </span>
                    </Td>
                    <Td>
                      <span style={{ color: f.latest_entry_at ? "var(--color-body)" : "var(--color-muted)" }}>
                        {f.latest_entry_at ? formatAgo(f.latest_entry_at) : "Never polled"}
                      </span>
                    </Td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleTrigger(f.feed_name);
                        }}
                        disabled={isTriggering || !f.enabled}
                        className="flex items-center justify-center w-7 h-7 disabled:opacity-30"
                        style={{
                          background: "transparent",
                          border: "1px solid var(--color-border)",
                          borderRadius: 4,
                          color: "var(--color-muted)",
                          cursor: isTriggering ? "wait" : "pointer",
                        }}
                        title="Run this feed now"
                      >
                        {isTriggering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Breakdowns */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Breakdown
          title="By severity"
          rows={summary.by_severity.map((s) => ({
            label: s.entry_type,
            value: s.count,
            ink: SEVERITY_COLOR[s.entry_type],
          }))}
          emptyHint="No entries to bucket."
        />
        <Breakdown
          title="Top source countries"
          rows={summary.by_country.slice(0, 8).map((c) => ({ label: c.country_code, value: c.count }))}
          emptyHint="No geo data on entries in this layer."
        />
      </div>

      <FeedDetailDrawer
        feedName={drawerFeed}
        onClose={() => { setDrawerFeed(null); refresh(); }}
        onTrigger={handleTrigger}
        triggering={drawerFeed ? triggering.has(drawerFeed) : false}
      />
    </div>
  );
}

// --- helpers ---------------------------------------------------------------

function Tile({
  icon: Icon,
  label,
  value,
  subValue,
  accent,
  muted,
}: {
  icon: typeof Database;
  label: string;
  value: number;
  subValue?: string;
  accent?: string;
  muted?: boolean;
}) {
  return (
    <div
      className="px-4 py-3"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div className="flex items-center gap-1.5 mb-1.5">
        <Icon className="w-3.5 h-3.5" style={{ color: accent ?? "var(--color-muted)" }} />
        <span
          className="text-[10px] font-semibold uppercase tracking-[0.7px]"
          style={{ color: "var(--color-muted)" }}
        >
          {label}
        </span>
      </div>
      <p
        className="text-[22px] font-medium leading-none tracking-[-0.02em]"
        style={{ color: muted ? "var(--color-body)" : "var(--color-ink)" }}
      >
        {value.toLocaleString()}
      </p>
      {subValue && (
        <p className="text-[11px] mt-1" style={{ color: "var(--color-muted)" }}>
          {subValue}
        </p>
      )}
    </div>
  );
}

function Breakdown({
  title,
  rows,
  emptyHint,
}: {
  title: string;
  rows: { label: string; value: number; ink?: string }[];
  emptyHint: string;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.value), 0) || 1;
  return (
    <div
      className="p-3"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <h4
        className="text-[11px] font-semibold uppercase tracking-[0.7px] mb-2"
        style={{ color: "var(--color-muted)" }}
      >
        {title}
      </h4>
      {rows.length === 0 ? (
        <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {emptyHint}
        </p>
      ) : (
        <div className="space-y-1.5">
          {rows.map((r) => (
            <div key={r.label} className="flex items-center gap-2">
              <span
                className="text-[12px] font-medium w-20 shrink-0"
                style={{ color: r.ink ?? "var(--color-ink)" }}
              >
                {r.label}
              </span>
              <div
                className="flex-1 h-1.5 rounded-full overflow-hidden"
                style={{ background: "var(--color-surface-muted)" }}
              >
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(r.value / max) * 100}%`,
                    background: r.ink ?? "var(--color-accent)",
                  }}
                />
              </div>
              <span
                className="text-[12px] font-mono w-16 text-right shrink-0"
                style={{ color: "var(--color-body)" }}
              >
                {r.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th
      className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.7px]"
      style={{ color: "var(--color-muted)" }}
    >
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return <td className="px-3 py-2 align-middle">{children}</td>;
}

function formatAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.round(hr / 24)}d ago`;
}
