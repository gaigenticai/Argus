"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import {
  RefreshCw,
  Filter,
  Download,
  Search,
  Crosshair,
  ChevronDown,
  ChevronUp,
  X,
} from "lucide-react";
import { api, type IOCItem, type IOCStats, type BulkSearchResult } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate } from "@/lib/utils";
import Link from "next/link";
import { Select } from "@/components/shared/select";

const IOC_TYPES = [
  "all", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
  "btc_address", "xmr_address", "cve", "filename", "registry_key", "mutex",
  "user_agent", "cidr", "asn", "ja3",
];

// Zapier-token badge colours keyed by IOC type
const TYPE_BADGE: Record<string, { bg: string; color: string }> = {
  ipv4: { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  ipv6: { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  domain: { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)" },
  url: { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)" },
  email: { bg: "rgba(255,171,0,0.12)", color: "#B76E00" },
  md5: { bg: "rgba(142,51,255,0.08)", color: "#6B21A8" },
  sha1: { bg: "rgba(142,51,255,0.08)", color: "#6B21A8" },
  sha256: { bg: "rgba(142,51,255,0.08)", color: "#6B21A8" },
  btc_address: { bg: "rgba(255,171,0,0.12)", color: "#B76E00" },
  xmr_address: { bg: "rgba(255,171,0,0.12)", color: "#B76E00" },
  cve: { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
  filename: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  registry_key: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  mutex: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  user_agent: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  cidr: { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  asn: { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  ja3: { bg: "rgba(142,51,255,0.08)", color: "#6B21A8" },
};

const defaultBadge = { bg: "var(--color-surface-muted)", color: "var(--color-body)" };

export default function IOCsPage() {
  const { toast } = useToast();
  const [iocs, setIOCs] = useState<IOCItem[]>([]);
  const [stats, setStats] = useState<IOCStats | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [searchText, setSearchText] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [showBulkSearch, setShowBulkSearch] = useState(false);
  const [bulkInput, setBulkInput] = useState("");
  const [bulkResults, setBulkResults] = useState<BulkSearchResult[] | null>(null);
  const [bulkSearching, setBulkSearching] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getIOCs({
        ioc_type: typeFilter === "all" ? undefined : typeFilter,
        min_confidence: minConfidence > 0 ? minConfidence : undefined,
        search: searchText || undefined,
        limit,
        offset,
      });
      setIOCs(data);
      setTotal(data.length === limit ? offset + limit + 1 : offset + data.length);
    } catch {
      toast("error", "Failed to load IOCs");
    }
    setLoading(false);
  }, [typeFilter, minConfidence, searchText, offset, toast]);

  const loadStats = useCallback(async () => {
    try {
      const data = await api.getIOCStats();
      setStats(data);
    } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadStats(); }, [loadStats]);

  async function handleExportSTIX() {
    try {
      const blob = await api.exportSTIX();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "argus-iocs.stix.json";
      a.click();
      URL.revokeObjectURL(url);
      toast("success", "STIX export downloaded");
    } catch {
      toast("error", "Failed to export STIX");
    }
  }

  async function handleExportCSV() {
    try {
      const blob = await api.exportCSV();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "argus-iocs.csv";
      a.click();
      URL.revokeObjectURL(url);
      toast("success", "CSV export downloaded");
    } catch {
      toast("error", "Failed to export CSV");
    }
  }

  async function handleBulkSearch(e: React.FormEvent) {
    e.preventDefault();
    const values = bulkInput.split("\n").map((s) => s.trim()).filter(Boolean);
    if (values.length === 0) return;
    setBulkSearching(true);
    try {
      const results = await api.searchIOCs(values);
      setBulkResults(results);
      const foundCount = results.filter((r) => r.found).length;
      toast("success", `Found ${foundCount} of ${values.length} IOCs`);
    } catch {
      toast("error", "Bulk search failed");
    }
    setBulkSearching(false);
  }

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const btnSecondary = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-body)",
  } as React.CSSProperties;

  const selectCls = "h-10 px-3 text-[13px] outline-none transition-colors cursor-pointer";
  const selectStyle = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-body)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Indicators of Compromise
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {total} IOCs tracked
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowBulkSearch(!showBulkSearch)}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={btnSecondary}
          >
            <Search className="w-4 h-4" />
            Bulk Search
          </button>
          <button onClick={handleExportSTIX} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <Download className="w-4 h-4" />
            STIX
          </button>
          <button onClick={handleExportCSV} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button onClick={() => { load(); loadStats(); }} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <div
            className="p-4"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
            }}
          >
            <div className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Total</div>
            <div className="text-[20px] font-bold mt-1" style={{ color: "var(--color-ink)" }}>{stats.total.toLocaleString()}</div>
          </div>
          {Object.entries(stats.by_type)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([type, count]) => {
              const badge = TYPE_BADGE[type] || defaultBadge;
              return (
                <div
                  key={type}
                  className="p-4"
                  style={{
                    background: "var(--color-canvas)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "5px",
                  }}
                >
                  <div className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: badge.color }}>{type}</div>
                  <div className="text-[20px] font-bold mt-1" style={{ color: "var(--color-ink)" }}>{count.toLocaleString()}</div>
                </div>
              );
            })}
        </div>
      )}

      {/* Bulk Search Panel */}
      {showBulkSearch && (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>Bulk IOC Search</h3>
            <button
              onClick={() => { setShowBulkSearch(false); setBulkResults(null); }}
              className="p-1 transition-colors"
              style={{ borderRadius: "4px" }}
              onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
              onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            >
              <X className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
            </button>
          </div>
          <form onSubmit={handleBulkSearch} className="space-y-3">
            <textarea
              value={bulkInput}
              onChange={(e) => setBulkInput(e.target.value)}
              rows={5}
              placeholder="Paste IOC values, one per line (IPs, domains, hashes, etc.)"
              className="w-full px-3 py-2 text-[13px] font-mono outline-none resize-none"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
              }}
            />
            <button
              type="submit"
              disabled={bulkSearching}
              className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
            >
              {bulkSearching ? "Searching..." : "Search"}
            </button>
          </form>

          {bulkResults !== null && (
            <div className="mt-4">
              {bulkResults.filter((r) => r.found).length === 0 ? (
                <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>No matches found in database</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full mt-2">
                    <thead>
                      <tr style={{ background: "var(--color-surface-muted)" }}>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Status</th>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Value</th>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Type</th>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Confidence</th>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Sightings</th>
                        <th className="text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bulkResults.map((result) => {
                        const ioc = result.ioc;
                        const badge = ioc ? (TYPE_BADGE[ioc.ioc_type] || defaultBadge) : defaultBadge;
                        return (
                          <tr key={result.value} className="h-[44px]" style={{ borderBottom: "1px solid var(--color-surface-muted)" }}>
                            <td className="px-3">
                              <span
                                className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                                style={{
                                  borderRadius: "4px",
                                  background: result.found ? "rgba(255,86,48,0.1)" : "var(--color-surface-muted)",
                                  color: result.found ? "#B71D18" : "var(--color-muted)",
                                }}
                              >
                                {result.found ? "Found" : "Clean"}
                              </span>
                            </td>
                            <td className="px-3 text-[13px] font-mono max-w-[300px] truncate" style={{ color: "var(--color-body)" }}>{result.value}</td>
                            <td className="px-3">
                              {ioc && (
                                <span
                                  className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                                  style={{ borderRadius: "4px", background: badge.bg, color: badge.color }}
                                >
                                  {ioc.ioc_type}
                                </span>
                              )}
                            </td>
                            <td className="px-3 text-[13px]" style={{ color: "var(--color-body)" }}>{ioc ? `${Math.round(ioc.confidence * 100)}%` : "-"}</td>
                            <td className="px-3 text-[13px]" style={{ color: "var(--color-body)" }}>{ioc?.sighting_count ?? "-"}</td>
                            <td className="px-3 text-[12px]" style={{ color: "var(--color-muted)" }}>{ioc ? formatDate(ioc.last_seen) : "-"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-end">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
          <Select
            value={typeFilter}
            onChange={(v) => { setTypeFilter(v); setOffset(0); }}
            ariaLabel="IOC type"
            options={IOC_TYPES.map((t) => ({
              value: t,
              label: t === "all" ? "All types" : t.toUpperCase(),
            }))}
          />
        </div>
        <div>
          <label
            className="block text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            Min Confidence
          </label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min={0}
              max={100}
              value={minConfidence}
              onChange={(e) => { setMinConfidence(Number(e.target.value)); setOffset(0); }}
              className="w-32"
            />
            <span className="text-[13px] font-semibold w-10" style={{ color: "var(--color-body)" }}>{minConfidence}%</span>
          </div>
        </div>
        <div>
          <input
            type="text"
            value={searchText}
            onChange={(e) => { setSearchText(e.target.value); setOffset(0); }}
            placeholder="Search IOC values..."
            className="h-10 px-3 text-[13px] outline-none w-[240px]"
            style={selectStyle}
          />
        </div>
      </div>

      {/* IOC Table */}
      <div
        className="overflow-hidden"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div
              className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
              style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
            />
          </div>
        ) : iocs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
            <Crosshair className="w-8 h-8 mb-2" style={{ color: "var(--color-border)" }} />
            <p className="text-[13px]">No IOCs match your filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface-muted)" }}>
                  <th className="w-8"></th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Type</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Value</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Confidence</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>First Seen</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Last Seen</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Sightings</th>
                  <th className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Actor</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => {
                  const badge = TYPE_BADGE[ioc.ioc_type] || defaultBadge;
                  const isExpanded = expandedId === ioc.id;
                  return (
                    <Fragment key={ioc.id}>
                      <tr
                        className="h-[52px] transition-colors cursor-pointer"
                        style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
                        onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                        onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                        onClick={() => setExpandedId(isExpanded ? null : ioc.id)}
                      >
                        <td className="pl-3">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                          ) : (
                            <ChevronDown className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                          )}
                        </td>
                        <td className="px-4">
                          <span
                            className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                            style={{ borderRadius: "4px", background: badge.bg, color: badge.color }}
                          >
                            {ioc.ioc_type}
                          </span>
                        </td>
                        <td className="px-4 text-[13px] font-mono max-w-[300px] truncate" style={{ color: "var(--color-body)" }}>
                          {ioc.value}
                        </td>
                        <td className="px-4">
                          <div className="flex items-center gap-2">
                            <div
                              className="w-16 h-1.5 rounded-full overflow-hidden"
                              style={{ background: "var(--color-surface-muted)" }}
                            >
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${ioc.confidence * 100}%`,
                                  background: "var(--color-accent)",
                                }}
                              />
                            </div>
                            <span className="text-[13px]" style={{ color: "var(--color-body)" }}>
                              {Math.round(ioc.confidence * 100)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-4 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                          {formatDate(ioc.first_seen)}
                        </td>
                        <td className="px-4 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                          {formatDate(ioc.last_seen)}
                        </td>
                        <td className="px-4 text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>
                          {ioc.sighting_count}
                        </td>
                        <td className="px-4 text-[13px]" style={{ color: "var(--color-muted)" }}>
                          {ioc.threat_actor_id ? (
                            <Link
                              href={`/actors/${ioc.threat_actor_id}`}
                              className="font-semibold transition-colors"
                              style={{ color: "var(--color-accent)" }}
                              onClick={(e) => e.stopPropagation()}
                            >
                              View
                            </Link>
                          ) : (
                            "-"
                          )}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${ioc.id}-detail`} style={{ borderBottom: "1px solid var(--color-surface-muted)" }}>
                          <td colSpan={8} className="px-8 py-4" style={{ background: "var(--color-surface)" }}>
                            <div className="grid grid-cols-2 gap-4 text-[13px]">
                              <div>
                                <span className="font-semibold" style={{ color: "var(--color-muted)" }}>Full Value:</span>
                                <p className="font-mono break-all mt-1" style={{ color: "var(--color-body)" }}>{ioc.value}</p>
                              </div>
                              {ioc.tags && ioc.tags.length > 0 && (
                                <div>
                                  <span className="font-semibold" style={{ color: "var(--color-muted)" }}>Tags:</span>
                                  <div className="flex gap-1 flex-wrap mt-1">
                                    {ioc.tags.map((tag) => (
                                      <span
                                        key={tag}
                                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold"
                                        style={{
                                          borderRadius: "4px",
                                          background: "var(--color-surface-muted)",
                                          color: "var(--color-body)",
                                        }}
                                      >
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {ioc.context && (
                                <div className="col-span-2">
                                  <span className="font-semibold" style={{ color: "var(--color-muted)" }}>Context:</span>
                                  <pre
                                    className="text-[12px] font-mono p-3 mt-1 overflow-x-auto"
                                    style={{
                                      borderRadius: "4px",
                                      border: "1px solid var(--color-border)",
                                      background: "var(--color-canvas)",
                                      color: "var(--color-body)",
                                    }}
                                  >
                                    {JSON.stringify(ioc.context, null, 2)}
                                  </pre>
                                </div>
                              )}
                              {ioc.source_alert_id && (
                                <div>
                                  <span className="font-semibold" style={{ color: "var(--color-muted)" }}>Source Alert:</span>
                                  <Link
                                    href={`/alerts/${ioc.source_alert_id}`}
                                    className="block font-semibold mt-1 transition-colors"
                                    style={{ color: "var(--color-accent)" }}
                                  >
                                    {ioc.source_alert_id.substring(0, 8)}...
                                  </Link>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Page {currentPage} of {totalPages}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
              style={btnSecondary}
            >
              Previous
            </button>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
              style={btnSecondary}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
