"use client";

/**
 * FeedDetailDrawer — slide-in drill-down for a single feed source.
 *
 * Replaces the "no drill-down anywhere" state of the Feed Health
 * card. Operators (and customers in a demo) click a feed name and
 * land here to see what's actually flowing through it: latest
 * entries with country/severity/value, type breakdown, top
 * countries, and how many IOCs/alerts the feed has produced.
 *
 * Read-only: no edits land here. The drawer also exposes the
 * existing manual-trigger button so the operator can re-run from
 * the same surface they used to inspect.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  X,
  Loader2,
  Play,
  AlertCircle,
  Globe2,
  Layers,
  Database,
  Shield,
} from "lucide-react";
import {
  api,
  type FeedEntriesResponse,
  type FeedStatsResponse,
} from "@/lib/api";

interface Props {
  feedName: string | null;
  onClose: () => void;
  onTrigger?: (feedName: string) => Promise<void> | void;
  triggering?: boolean;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--color-error-dark)",
  high: "var(--color-error)",
  medium: "var(--color-warning-dark)",
  low: "var(--color-success-dark)",
  info: "var(--color-muted)",
};

export function FeedDetailDrawer({ feedName, onClose, onTrigger, triggering }: Props) {
  const [stats, setStats] = useState<FeedStatsResponse | null>(null);
  const [entries, setEntries] = useState<FeedEntriesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Close on Escape — drawer is modal-ish.
  useEffect(() => {
    if (!feedName) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [feedName, onClose]);

  useEffect(() => {
    if (!feedName) {
      setStats(null);
      setEntries(null);
      setError(null);
      return;
    }
    let cancelled = false;
    async function load(name: string) {
      setLoading(true);
      setError(null);
      try {
        const [s, e] = await Promise.all([
          api.getFeedStats(name),
          api.getFeedEntries(name, { limit: 25 }),
        ]);
        if (!cancelled) {
          setStats(s);
          setEntries(e);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load feed details");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load(feedName);
    return () => { cancelled = true; };
  }, [feedName]);

  if (!feedName) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        aria-hidden
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.35)" }}
      />
      {/* Drawer */}
      <aside
        role="dialog"
        aria-label={`${feedName} feed details`}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
        style={{
          width: "min(720px, 92vw)",
          background: "var(--color-canvas)",
          borderLeft: "1px solid var(--color-border)",
          boxShadow: "-8px 0 24px rgba(0,0,0,0.12)",
        }}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between gap-3 px-6 py-5"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <div className="min-w-0">
            <p
              className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
              style={{ color: "var(--color-muted)" }}
            >
              Feed source
            </p>
            <h2
              className="text-[20px] font-medium tracking-[-0.01em] truncate"
              style={{ color: "var(--color-ink)" }}
            >
              {feedName}
            </h2>
            <p className="text-[12.5px] mt-1" style={{ color: "var(--color-muted)" }}>
              Layer:{" "}
              {stats?.layer ? (
                <Link
                  href={`/feeds/layers/${encodeURIComponent(stats.layer)}`}
                  className="underline decoration-dotted"
                  style={{ color: "var(--color-accent)" }}
                >
                  {prettyLayer(stats.layer)}
                </Link>
              ) : (
                "—"
              )}
              {stats?.latest_entry_at ? (
                <>
                  {" · "}
                  Latest: {new Date(stats.latest_entry_at).toLocaleString()}
                </>
              ) : null}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {onTrigger && (
              <button
                type="button"
                onClick={() => onTrigger(feedName)}
                disabled={triggering}
                className="flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
                style={{
                  background: "var(--color-accent)",
                  color: "#fffefb",
                  border: "1px solid var(--color-accent)",
                  borderRadius: 4,
                }}
                title="Force a manual fetch of this feed"
              >
                {triggering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Run now
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close feed details"
              className="flex items-center justify-center w-8 h-8"
              style={{
                background: "transparent",
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                color: "var(--color-muted)",
                cursor: "pointer",
              }}
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {error && (
            <div
              className="px-3 py-2 flex items-center gap-2 text-[12.5px]"
              style={{
                background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.25)",
                borderRadius: 4,
                color: "var(--color-error-dark)",
              }}
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {loading && !stats && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-5 h-5 animate-spin" style={{ color: "var(--color-muted)" }} />
            </div>
          )}

          {stats && (
            <>
              {/* Top stats strip */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <StatTile icon={Database} label="Active" value={stats.active_entries} />
                <StatTile icon={Layers} label="Total ingested" value={stats.total_entries} muted />
                <StatTile icon={Shield} label="IOCs promoted" value={stats.iocs_promoted} />
                <StatTile icon={AlertCircle} label="Alerts referencing" value={stats.alerts_referencing} />
              </div>

              {/* Fetch health — proof the upstream HTTP call landed.
                  Without this, "active entries: 107k" looks fine even
                  if the feed died 3 days ago. */}
              <FetchHealthBlock stats={stats} />

              {/* Type + country breakdowns */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Breakdown
                  title="Entry types"
                  rows={stats.by_type.map((t) => ({ label: t.entry_type, value: t.count }))}
                  emptyHint="No entries ingested yet."
                />
                <Breakdown
                  title="Top source countries"
                  rows={stats.by_country.slice(0, 8).map((c) => ({
                    label: c.country_code,
                    value: c.count,
                    leading: <Globe2 className="w-3 h-3" style={{ color: "var(--color-muted)" }} />,
                  }))}
                  emptyHint="No geographic data available for this feed."
                />
              </div>
            </>
          )}

          {/* Latest entries */}
          <div>
            <h3
              className="text-[11px] font-semibold uppercase tracking-[0.8px] mb-2"
              style={{ color: "var(--color-muted)" }}
            >
              Latest entries{" "}
              {entries ? <span style={{ color: "var(--color-muted)" }}>· {entries.total_returned} shown</span> : null}
            </h3>
            <div
              className="overflow-hidden"
              style={{ border: "1px solid var(--color-border)", borderRadius: 5 }}
            >
              <table className="w-full text-[12.5px]" style={{ borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--color-surface-muted)" }}>
                    <Th>Type</Th>
                    <Th>Value</Th>
                    <Th>Severity</Th>
                    <Th>Country</Th>
                    <Th>Last seen</Th>
                  </tr>
                </thead>
                <tbody>
                  {!entries && !loading && (
                    <tr>
                      <td colSpan={5} className="px-3 py-6 text-center" style={{ color: "var(--color-muted)" }}>
                        No data.
                      </td>
                    </tr>
                  )}
                  {entries && entries.entries.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-6 text-center" style={{ color: "var(--color-muted)" }}>
                        This feed has no entries yet.
                      </td>
                    </tr>
                  )}
                  {entries?.entries.map((e) => (
                    <tr key={e.id} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                      <Td>
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 text-[11px] font-mono"
                          style={{
                            background: "var(--color-surface-muted)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 3,
                            color: "var(--color-body)",
                          }}
                        >
                          {e.entry_type}
                        </span>
                      </Td>
                      <Td>
                        <div className="font-mono text-[12px] break-all" style={{ color: "var(--color-ink)" }}>
                          {e.value}
                        </div>
                        {e.label && (
                          <div className="text-[11px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                            {e.label}
                          </div>
                        )}
                      </Td>
                      <Td>
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.6px]"
                          style={{
                            background: "var(--color-surface-muted)",
                            borderRadius: 3,
                            color: SEVERITY_COLOR[e.severity] || "var(--color-body)",
                          }}
                        >
                          {e.severity}
                        </span>
                      </Td>
                      <Td>
                        <span style={{ color: e.country_code ? "var(--color-body)" : "var(--color-muted)" }}>
                          {e.country_code || "—"}
                        </span>
                      </Td>
                      <Td>
                        <span style={{ color: "var(--color-body)" }}>
                          {formatAgo(e.last_seen)}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}

// --- helpers ---------------------------------------------------------------

function StatTile({
  icon: Icon,
  label,
  value,
  muted,
}: {
  icon: typeof Database;
  label: string;
  value: number;
  muted?: boolean;
}) {
  return (
    <div
      className="px-3 py-2.5"
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div className="flex items-center gap-1.5 mb-1">
        <Icon className="w-3 h-3" style={{ color: "var(--color-muted)" }} />
        <span
          className="text-[10px] font-semibold uppercase tracking-[0.7px]"
          style={{ color: "var(--color-muted)" }}
        >
          {label}
        </span>
      </div>
      <p
        className="text-[18px] font-medium leading-none tracking-[-0.01em]"
        style={{ color: muted ? "var(--color-body)" : "var(--color-ink)" }}
      >
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function Breakdown({
  title,
  rows,
  emptyHint,
}: {
  title: string;
  rows: { label: string; value: number; leading?: React.ReactNode }[];
  emptyHint: string;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.value), 0) || 1;
  return (
    <div
      className="p-3"
      style={{
        background: "var(--color-surface)",
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
              {r.leading}
              <span
                className="text-[12px] font-medium w-16 shrink-0"
                style={{ color: "var(--color-ink)" }}
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
                    background: "var(--color-accent)",
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
  return <td className="px-3 py-2 align-top">{children}</td>;
}

// FetchHealthBlock — shows the last 10 poll attempts from
// ``feed_health`` so the operator can SEE the upstream HTTP call:
// status (ok / auth_error / network_error / unconfigured / etc.),
// rows ingested, duration, and detail. Missing this surface meant
// "Never polled" in the UI for c2_tracker / greynoise looked
// identical to "polled but returned 0 rows" or "polled but got 401".
function FetchHealthBlock({ stats }: { stats: FeedStatsResponse }) {
  const { last_fetch, recent_fetches } = stats;
  if (!last_fetch && (!recent_fetches || recent_fetches.length === 0)) {
    return (
      <div
        className="p-3 text-[12.5px]"
        style={{
          background: "var(--color-surface)",
          border: "1px dashed var(--color-border)",
          borderRadius: 5,
          color: "var(--color-muted)",
        }}
      >
        <strong style={{ color: "var(--color-body)" }}>Never polled.</strong>{" "}
        This feed has no recorded fetch attempts. Click <em>Run now</em> above
        to trigger a manual poll, then watch this section update with the
        upstream HTTP result.
      </div>
    );
  }
  const tone = healthTone(last_fetch?.status);
  return (
    <div
      className="p-3"
      style={{
        background: tone.bg,
        border: `1px solid ${tone.border}`,
        borderRadius: 5,
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <h4
          className="text-[11px] font-semibold uppercase tracking-[0.7px]"
          style={{ color: "var(--color-muted)" }}
        >
          Fetch health
        </h4>
        {last_fetch && (
          <span
            className="text-[10px] font-semibold uppercase tracking-[0.7px] px-2 py-0.5"
            style={{
              background: tone.badgeBg,
              color: tone.badgeInk,
              borderRadius: 3,
            }}
          >
            {last_fetch.status.replace(/_/g, " ")}
          </span>
        )}
      </div>
      {last_fetch && (
        <div className="text-[12.5px] mb-2" style={{ color: "var(--color-body)" }}>
          Last poll <strong>{formatAgo(last_fetch.observed_at)}</strong>
          {last_fetch.duration_ms != null && (
            <> · {(last_fetch.duration_ms / 1000).toFixed(1)}s</>
          )}{" "}
          · {last_fetch.rows_ingested.toLocaleString()} new row
          {last_fetch.rows_ingested === 1 ? "" : "s"} ingested.
          {last_fetch.detail && (
            <span style={{ color: "var(--color-muted)" }}> — {last_fetch.detail}</span>
          )}
        </div>
      )}
      {recent_fetches.length > 1 && (
        <details className="text-[12px]" style={{ color: "var(--color-body)" }}>
          <summary
            className="cursor-pointer"
            style={{ color: "var(--color-muted)" }}
          >
            Last {recent_fetches.length} attempts
          </summary>
          <table className="w-full mt-2" style={{ borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--color-surface-muted)" }}>
                <th className="px-2 py-1 text-left text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                  When
                </th>
                <th className="px-2 py-1 text-left text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                  Status
                </th>
                <th className="px-2 py-1 text-right text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                  Rows
                </th>
                <th className="px-2 py-1 text-right text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                  Duration
                </th>
              </tr>
            </thead>
            <tbody>
              {recent_fetches.map((f, i) => {
                const t = healthTone(f.status);
                return (
                  <tr key={`${f.observed_at}-${i}`} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                    <td className="px-2 py-1" style={{ color: "var(--color-body)" }}>
                      {formatAgo(f.observed_at)}
                    </td>
                    <td className="px-2 py-1">
                      <span
                        className="inline-flex px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.6px]"
                        style={{
                          background: t.badgeBg,
                          color: t.badgeInk,
                          borderRadius: 3,
                        }}
                      >
                        {f.status.replace(/_/g, " ")}
                      </span>
                      {f.detail && (
                        <span className="ml-1 text-[11px]" style={{ color: "var(--color-muted)" }}>
                          {f.detail}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1 text-right font-mono" style={{ color: "var(--color-body)" }}>
                      {f.rows_ingested.toLocaleString()}
                    </td>
                    <td className="px-2 py-1 text-right font-mono" style={{ color: "var(--color-body)" }}>
                      {f.duration_ms != null ? `${(f.duration_ms / 1000).toFixed(1)}s` : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}

function healthTone(status?: string): {
  bg: string;
  border: string;
  badgeBg: string;
  badgeInk: string;
} {
  switch (status) {
    case "ok":
      return {
        bg: "rgba(34,197,94,0.06)",
        border: "rgba(34,197,94,0.25)",
        badgeBg: "rgba(34,197,94,0.18)",
        badgeInk: "var(--color-success-dark)",
      };
    case "auth_error":
    case "rate_limited":
      return {
        bg: "rgba(245,158,11,0.06)",
        border: "rgba(245,158,11,0.30)",
        badgeBg: "rgba(245,158,11,0.20)",
        badgeInk: "var(--color-warning-dark)",
      };
    case "unconfigured":
    case "disabled":
      return {
        bg: "rgba(99,115,129,0.06)",
        border: "rgba(99,115,129,0.30)",
        badgeBg: "rgba(99,115,129,0.20)",
        badgeInk: "var(--color-muted)",
      };
    case "network_error":
    case "parse_error":
      return {
        bg: "rgba(239,68,68,0.06)",
        border: "rgba(239,68,68,0.30)",
        badgeBg: "rgba(239,68,68,0.20)",
        badgeInk: "var(--color-error-dark)",
      };
    default:
      return {
        bg: "var(--color-surface)",
        border: "var(--color-border)",
        badgeBg: "var(--color-surface-muted)",
        badgeInk: "var(--color-body)",
      };
  }
}

function prettyLayer(slug: string): string {
  return slug
    .replace(/[_-]+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
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
