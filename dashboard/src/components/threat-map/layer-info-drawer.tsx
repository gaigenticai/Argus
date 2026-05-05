"use client";

/**
 * LayerInfoDrawer — slide-in details panel for one threat layer on
 * the Threat Map. Same data the /feeds/layers/[layer] page surfaces,
 * but without losing the map context (the drawer overlays the map
 * instead of navigating away).
 *
 * Backed by ``GET /feeds/layers/{layer}/summary``.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  X,
  Loader2,
  Database,
  Globe2,
  AlertCircle,
  ExternalLink,
} from "lucide-react";
import { api, type LayerSummaryResponse } from "@/lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#FF5630",
  high: "#FF8B00",
  medium: "#FFAB00",
  low: "#22C55E",
  info: "#919EAB",
};

interface Props {
  layerName: string | null;
  onClose: () => void;
  onOpenFeed?: (feedName: string) => void;
}

export function LayerInfoDrawer({ layerName, onClose, onOpenFeed }: Props) {
  const [summary, setSummary] = useState<LayerSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!layerName) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [layerName, onClose]);

  useEffect(() => {
    if (!layerName) {
      setSummary(null);
      setError(null);
      return;
    }
    let cancelled = false;
    async function load(name: string) {
      setLoading(true);
      setError(null);
      try {
        const s = await api.getLayerSummary(name);
        if (!cancelled) setSummary(s);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load layer details");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load(layerName);
    return () => { cancelled = true; };
  }, [layerName]);

  if (!layerName) return null;

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.55)" }}
      />
      <aside
        role="dialog"
        aria-label={`${layerName} layer details`}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
        style={{
          width: "min(560px, 92vw)",
          background: "#161C24",
          borderLeft: "1px solid rgba(255,255,255,0.08)",
          boxShadow: "-8px 0 24px rgba(0,0,0,0.4)",
          color: "#DFE3E8",
        }}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between gap-3 px-5 py-4"
          style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}
        >
          <div className="min-w-0">
            <p
              className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
              style={{ color: "#919EAB" }}
            >
              Threat layer
            </p>
            <h2 className="text-[18px] font-medium tracking-[-0.01em] truncate">
              {summary?.display_name ?? layerName}
            </h2>
            {summary?.description && (
              <p className="text-[12px] mt-1.5 leading-relaxed" style={{ color: "#919EAB" }}>
                {summary.description}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link
              href={`/feeds/layers/${encodeURIComponent(layerName)}`}
              className="inline-flex items-center gap-1 h-7 px-2.5 text-[11px] font-semibold"
              style={{
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 4,
                color: "#DFE3E8",
              }}
              title="Open the full layer page"
            >
              <ExternalLink className="w-3 h-3" />
              Full page
            </Link>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="flex items-center justify-center w-7 h-7"
              style={{
                background: "transparent",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 4,
                color: "#919EAB",
                cursor: "pointer",
              }}
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {error && (
            <div
              className="px-3 py-2 flex items-center gap-2 text-[12px]"
              style={{
                background: "rgba(239,68,68,0.10)",
                border: "1px solid rgba(239,68,68,0.30)",
                borderRadius: 4,
                color: "#FF8C8C",
              }}
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}
          {loading && !summary && (
            <div className="flex items-center justify-center py-10">
              <Loader2 className="w-5 h-5 animate-spin" style={{ color: "#919EAB" }} />
            </div>
          )}
          {summary && (
            <>
              <div className="grid grid-cols-2 gap-2">
                <Tile label="Active" value={summary.active_entries} />
                <Tile label="Total ingested" value={summary.total_entries} muted />
              </div>

              <Section title={`Feeds in this layer (${summary.feeds.length})`}>
                {summary.feeds.length === 0 ? (
                  <p className="text-[12px]" style={{ color: "#919EAB" }}>
                    No feeds configured.
                  </p>
                ) : (
                  <div
                    className="overflow-hidden"
                    style={{ border: "1px solid rgba(255,255,255,0.08)", borderRadius: 4 }}
                  >
                    <table className="w-full text-[12px]" style={{ borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ background: "rgba(255,255,255,0.03)" }}>
                          <Th>Feed</Th>
                          <Th align="right">Active</Th>
                          <Th align="right">Latest</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.feeds.map((f) => (
                          <tr
                            key={f.feed_name}
                            className="cursor-pointer"
                            style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
                            onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.04)")}
                            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                            onClick={() => onOpenFeed?.(f.feed_name)}
                          >
                            <Td>
                              <span style={{ color: "#DFE3E8", fontWeight: 600 }}>
                                {f.feed_name}
                              </span>
                            </Td>
                            <Td align="right">
                              <span style={{ color: "#DFE3E8" }}>
                                {f.active_entry_count.toLocaleString()}
                              </span>
                            </Td>
                            <Td align="right">
                              <span style={{ color: f.latest_entry_at ? "#919EAB" : "#637381" }}>
                                {f.latest_entry_at ? formatAgo(f.latest_entry_at) : "Never"}
                              </span>
                            </Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Section>

              <Section title="By severity">
                <Bars
                  rows={summary.by_severity.map((s) => ({
                    label: s.entry_type,
                    value: s.count,
                    color: SEVERITY_COLOR[s.entry_type],
                  }))}
                  emptyHint="No entries to bucket."
                />
              </Section>

              <Section title="Top source countries">
                <Bars
                  rows={summary.by_country.slice(0, 8).map((c) => ({
                    label: c.country_code,
                    value: c.count,
                    leading: <Globe2 className="w-3 h-3" style={{ color: "#919EAB" }} />,
                  }))}
                  emptyHint="No geo data on entries in this layer."
                />
              </Section>
            </>
          )}
        </div>
      </aside>
    </>
  );
}

// --- helpers ---------------------------------------------------------------

function Tile({ label, value, muted }: { label: string; value: number; muted?: boolean }) {
  return (
    <div
      className="px-3 py-2"
      style={{
        background: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 4,
      }}
    >
      <div className="flex items-center gap-1.5 mb-1">
        <Database className="w-3 h-3" style={{ color: "#919EAB" }} />
        <span
          className="text-[10px] font-semibold uppercase tracking-[0.7px]"
          style={{ color: "#919EAB" }}
        >
          {label}
        </span>
      </div>
      <p
        className="text-[18px] font-medium leading-none tracking-[-0.01em]"
        style={{ color: muted ? "#919EAB" : "#DFE3E8" }}
      >
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3
        className="text-[10px] font-semibold uppercase tracking-[0.7px] mb-2"
        style={{ color: "#919EAB" }}
      >
        {title}
      </h3>
      {children}
    </div>
  );
}

function Bars({
  rows,
  emptyHint,
}: {
  rows: { label: string; value: number; color?: string; leading?: React.ReactNode }[];
  emptyHint: string;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.value), 0) || 1;
  if (rows.length === 0) {
    return <p className="text-[12px]" style={{ color: "#919EAB" }}>{emptyHint}</p>;
  }
  return (
    <div className="space-y-1.5">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-2">
          {r.leading}
          <span
            className="text-[12px] font-medium w-16 shrink-0"
            style={{ color: r.color ?? "#DFE3E8" }}
          >
            {r.label}
          </span>
          <div
            className="flex-1 h-1.5 rounded-full overflow-hidden"
            style={{ background: "rgba(255,255,255,0.05)" }}
          >
            <div
              className="h-full rounded-full"
              style={{
                width: `${(r.value / max) * 100}%`,
                background: r.color ?? "#FF8B00",
              }}
            />
          </div>
          <span
            className="text-[12px] font-mono w-16 text-right shrink-0"
            style={{ color: "#919EAB" }}
          >
            {r.value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

function Th({ children, align }: { children: React.ReactNode; align?: "right" | "left" }) {
  return (
    <th
      className="px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-[0.7px]"
      style={{
        color: "#919EAB",
        textAlign: align ?? "left",
      }}
    >
      {children}
    </th>
  );
}

function Td({ children, align }: { children: React.ReactNode; align?: "right" | "left" }) {
  return (
    <td className="px-2.5 py-1.5 align-middle" style={{ textAlign: align ?? "left" }}>
      {children}
    </td>
  );
}

function formatAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}
