"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  RefreshCw,
  Filter,
  Download,
  Search,
  Crosshair,
  ChevronDown,
  ChevronUp,
  X,
  AlertTriangle,
} from "lucide-react";
import { api, type IOCItem, type IOCStats, type BulkSearchResult } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate } from "@/lib/utils";
import Link from "next/link";
import { Select } from "@/components/shared/select";

import { SourcesStrip } from "@/components/shared/sources-strip";
import { CoverageGate } from "@/components/shared/coverage-gate";
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
  const router = useRouter();
  const searchParams = useSearchParams();
  // Source-alert deep-link: ``/iocs?source_alert_id=<uuid>`` arrives
  // from an alert's "View in IOC explorer" link. We treat it as a
  // sticky pill the operator can dismiss to broaden back to the
  // full inventory; URL stays in sync so the filtered view is
  // shareable / refresh-safe.
  const [sourceAlertId, setSourceAlertId] = useState<string | null>(
    () => searchParams?.get("source_alert_id") || null,
  );
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
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [sightingsFor, setSightingsFor] = useState<string | null>(null);
  const [pivotFor, setPivotFor] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getIOCs({
        ioc_type: typeFilter === "all" ? undefined : typeFilter,
        min_confidence: minConfidence > 0 ? minConfidence : undefined,
        search: searchText || undefined,
        source_alert_id: sourceAlertId || undefined,
        limit,
        offset,
      });
      setIOCs(data);
      setTotal(data.length === limit ? offset + limit + 1 : offset + data.length);
    } catch {
      toast("error", "Failed to load IOCs");
    }
    setLoading(false);
  }, [typeFilter, minConfidence, searchText, sourceAlertId, offset, toast]);

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
      a.download = "marsad-iocs.stix.json";
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
      a.download = "marsad-iocs.csv";
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
    <CoverageGate pageSlug="iocs" pageLabel="IOCs">
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
      <SourcesStrip pageKey="iocs" />
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
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              background: "var(--color-accent)",
              color: "#fff",
            }}
          >
            + New IOC
          </button>
          <button
            onClick={() => setShowImport(true)}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={btnSecondary}
          >
            Import
          </button>
          <button onClick={() => { load(); loadStats(); }} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {showCreate && (
        <CreateIocModal
          onClose={() => setShowCreate(false)}
          onCreated={(item) => {
            setIOCs((prev) => [item, ...prev]);
            setShowCreate(false);
            toast("success", "IOC created");
          }}
        />
      )}
      {showImport && (
        <BulkImportModal
          onClose={() => setShowImport(false)}
          onDone={(r) => {
            setShowImport(false);
            load();
            toast(
              "success",
              `Bulk import — inserted ${r.inserted}, updated ${r.updated}${r.errors.length ? `, ${r.errors.length} errors` : ""}`,
            );
          }}
        />
      )}
      {sightingsFor && (
        <SightingsDrawer iocId={sightingsFor} onClose={() => setSightingsFor(null)} />
      )}
      {pivotFor && (
        <PivotDrawer iocId={pivotFor} onClose={() => setPivotFor(null)} />
      )}

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

      {/* Source-alert filter pill — visible only when arrived via
          deep-link from an alert. Click X to clear back to the
          full inventory. */}
      {sourceAlertId && (
        <div
          className="flex items-center gap-2 px-3 py-2 text-[12.5px]"
          style={{
            background: "rgba(255,79,0,0.06)",
            border: "1px solid rgba(255,79,0,0.25)",
            borderRadius: 5,
            color: "var(--color-body)",
          }}
        >
          <AlertTriangle className="w-3.5 h-3.5" style={{ color: "var(--color-accent)" }} />
          <span>
            Showing only indicators linked to alert{" "}
            <Link
              href={`/alerts/${sourceAlertId}`}
              className="font-mono font-semibold"
              style={{ color: "var(--color-accent)" }}
            >
              {sourceAlertId.slice(0, 8)}…
            </Link>
          </span>
          <button
            type="button"
            onClick={() => {
              setSourceAlertId(null);
              setOffset(0);
              router.replace("/iocs");
            }}
            aria-label="Clear alert filter"
            className="ml-auto inline-flex items-center gap-1 px-2 h-6 text-[11px] font-semibold"
            style={{
              background: "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 3,
              color: "var(--color-body)",
              cursor: "pointer",
            }}
          >
            <X className="w-3 h-3" />
            Clear
          </button>
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
                              {ioc.enrichment_data && Object.keys(ioc.enrichment_data).length > 0 && (
                                <div className="col-span-2">
                                  <span className="font-semibold" style={{ color: "var(--color-muted)" }}>Enrichment:</span>
                                  <div className="flex gap-2 flex-wrap mt-1">
                                    {Object.entries(ioc.enrichment_data)
                                      .filter(([k]) => k !== "fetched_at" && k !== "skipped")
                                      .map(([k, v]) => (
                                        <span
                                          key={k}
                                          className="inline-flex h-[22px] px-2 items-center text-[10px] font-semibold"
                                          style={{
                                            borderRadius: "4px",
                                            background: "rgba(0,124,90,0.10)",
                                            color: "#1B5E20",
                                            border: "1px solid rgba(0,124,90,0.25)",
                                          }}
                                          title={JSON.stringify(v)}
                                        >
                                          {k}
                                        </span>
                                      ))}
                                  </div>
                                </div>
                              )}
                              {ioc.is_allowlisted && (
                                <div className="col-span-2">
                                  <span
                                    className="inline-flex h-[22px] px-2 items-center text-[11px] font-semibold"
                                    style={{
                                      borderRadius: "4px",
                                      background: "rgba(40,167,69,0.10)",
                                      color: "#155724",
                                      border: "1px solid rgba(40,167,69,0.25)",
                                    }}
                                  >
                                    ALLOWLISTED{ioc.allowlist_reason ? ` — ${ioc.allowlist_reason}` : ""}
                                  </span>
                                </div>
                              )}
                              <div className="col-span-2 flex gap-2 flex-wrap mt-2 pt-3"
                                style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                                <button
                                  onClick={async () => {
                                    try {
                                      const updated = await api.enrichIOC(ioc.id);
                                      setIOCs((prev) => prev.map((x) => (x.id === ioc.id ? updated : x)));
                                      toast(
                                        "success",
                                        `Enrichment fetched — ${Object.keys(updated.enrichment_data || {}).length} sources hit`,
                                      );
                                    } catch (e) {
                                      toast("error", `Enrichment failed — ${String(e)}`);
                                    }
                                  }}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    background: "var(--color-accent)",
                                    color: "#fff",
                                  }}
                                >
                                  Enrich now
                                </button>
                                <button
                                  onClick={async () => {
                                    const reason = ioc.is_allowlisted
                                      ? undefined
                                      : window.prompt("Allowlist reason (optional):") || undefined;
                                    try {
                                      const updated = await api.toggleAllowlist(
                                        ioc.id,
                                        !ioc.is_allowlisted,
                                        reason,
                                      );
                                      setIOCs((prev) => prev.map((x) => (x.id === ioc.id ? updated : x)));
                                      toast("success", "");
                                    } catch (e) {
                                      toast("error", `Allowlist toggle failed — ${String(e)}`);
                                    }
                                  }}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    border: "1px solid var(--color-border)",
                                    background: "var(--color-canvas)",
                                    color: "var(--color-body)",
                                  }}
                                >
                                  {ioc.is_allowlisted ? "Remove allowlist" : "Allowlist"}
                                </button>
                                <button
                                  onClick={() => setSightingsFor(ioc.id)}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    border: "1px solid var(--color-border)",
                                    background: "var(--color-canvas)",
                                    color: "var(--color-body)",
                                  }}
                                >
                                  Sightings
                                </button>
                                <button
                                  onClick={() => setPivotFor(ioc.id)}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    border: "1px solid var(--color-border)",
                                    background: "var(--color-canvas)",
                                    color: "var(--color-body)",
                                  }}
                                >
                                  Pivot
                                </button>
                                <button
                                  onClick={async () => {
                                    try {
                                      const r = await api.getIOCDefanged(ioc.id);
                                      try {
                                        await navigator.clipboard.writeText(r.defanged);
                                        toast("success", `Defanged value copied — ${r.defanged}`);
                                      } catch {
                                        window.alert(`Defanged: ${r.defanged}`);
                                      }
                                    } catch (e) {
                                      toast("error", `Defang failed — ${String(e)}`);
                                    }
                                  }}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    border: "1px solid var(--color-border)",
                                    background: "var(--color-canvas)",
                                    color: "var(--color-body)",
                                  }}
                                >
                                  Defang →
                                </button>
                                <button
                                  onClick={async () => {
                                    if (!window.confirm("Delete this IOC permanently?")) return;
                                    try {
                                      await api.deleteIOC(ioc.id);
                                      setIOCs((prev) => prev.filter((x) => x.id !== ioc.id));
                                      toast("success", "IOC deleted");
                                    } catch (e) {
                                      toast("error", `Delete failed — ${String(e)}`);
                                    }
                                  }}
                                  className="h-8 px-3 text-[12px] font-semibold transition-colors"
                                  style={{
                                    borderRadius: "4px",
                                    border: "1px solid #B71D18",
                                    background: "rgba(183,29,24,0.05)",
                                    color: "#B71D18",
                                  }}
                                >
                                  Delete
                                </button>
                              </div>
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
      </CoverageGate>
  );
}


// --- Modals -----------------------------------------------------------

function CreateIocModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (item: IOCItem) => void;
}) {
  const [iocType, setIocType] = useState("ipv4");
  const [value, setValue] = useState("");
  const [confidence, setConfidence] = useState(0.5);
  const [tags, setTags] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-24"
      style={{ background: "rgba(0,0,0,0.4)" }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[480px] p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "8px",
        }}
      >
        <h3 className="text-[18px] font-semibold mb-4" style={{ color: "var(--color-ink)" }}>
          Add IOC
        </h3>
        <div className="space-y-3">
          <div>
            <label className="block text-[12px] font-semibold mb-1" style={{ color: "var(--color-muted)" }}>Type</label>
            <select
              value={iocType}
              onChange={(e) => setIocType(e.target.value)}
              className="w-full h-9 px-3 text-[13px]"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              {IOC_TYPES.filter((t) => t !== "all").map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[12px] font-semibold mb-1" style={{ color: "var(--color-muted)" }}>Value</label>
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="e.g. 198.51.100.42 or evil.example[.]com"
              className="w-full h-9 px-3 text-[13px] font-mono"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold mb-1" style={{ color: "var(--color-muted)" }}>
              Confidence: {Math.round(confidence * 100)}%
            </label>
            <input
              type="range"
              min={0}
              max={100}
              value={Math.round(confidence * 100)}
              onChange={(e) => setConfidence(Number(e.target.value) / 100)}
              className="w-full"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold mb-1" style={{ color: "var(--color-muted)" }}>Tags (comma separated)</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="e.g. ransomware, c2, apt29"
              className="w-full h-9 px-3 text-[13px]"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            />
          </div>
          {err && <p className="text-[12px]" style={{ color: "#B71D18" }}>{err}</p>}
        </div>
        <div className="flex justify-end gap-2 mt-5">
          <button
            onClick={onClose}
            className="h-9 px-4 text-[13px] font-semibold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Cancel
          </button>
          <button
            disabled={busy || !value.trim()}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                const item = await api.createIOC({
                  ioc_type: iocType,
                  value: value.trim(),
                  confidence,
                  tags: tags
                    .split(",")
                    .map((t) => t.trim())
                    .filter(Boolean),
                  source_feed: "manual",
                });
                onCreated(item);
              } catch (e) {
                setErr(String(e));
              } finally {
                setBusy(false);
              }
            }}
            className="h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              background: "var(--color-accent)",
              color: "#fff",
            }}
          >
            {busy ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}


function BulkImportModal({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: (r: { inserted: number; updated: number; errors: string[] }) => void;
}) {
  const [text, setText] = useState("");
  const [defaultType, setDefaultType] = useState("ipv4");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-16"
      style={{ background: "rgba(0,0,0,0.4)" }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[640px] p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "8px",
        }}
      >
        <h3 className="text-[18px] font-semibold mb-2" style={{ color: "var(--color-ink)" }}>
          Bulk import IOCs
        </h3>
        <p className="text-[12px] mb-3" style={{ color: "var(--color-muted)" }}>
          One value per line. Lines starting with <code>type:value</code> override the default type
          (e.g. <code>domain:evil.example.com</code>). Defanged values are auto-refanged.
        </p>
        <div className="space-y-3">
          <div>
            <label className="block text-[12px] font-semibold mb-1" style={{ color: "var(--color-muted)" }}>Default type</label>
            <select
              value={defaultType}
              onChange={(e) => setDefaultType(e.target.value)}
              className="h-9 px-3 text-[13px]"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              {IOC_TYPES.filter((t) => t !== "all").map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"198.51.100.42\ndomain:evil.example.com\nsha256:abc123..."}
            rows={12}
            className="w-full p-3 text-[12px] font-mono"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          />
          {err && <p className="text-[12px]" style={{ color: "#B71D18" }}>{err}</p>}
        </div>
        <div className="flex justify-end gap-2 mt-5">
          <button
            onClick={onClose}
            className="h-9 px-4 text-[13px] font-semibold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Cancel
          </button>
          <button
            disabled={busy || !text.trim()}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                const refangRe = (s: string) =>
                  s
                    .replace(/hxxps?:\/\//gi, "http://")
                    .replace(/\[\.\]/g, ".")
                    .replace(/\(\.\)/g, ".")
                    .replace(/\[at\]/gi, "@");
                const rows = text
                  .split(/\r?\n/)
                  .map((l) => l.trim())
                  .filter((l) => l && !l.startsWith("#"))
                  .map((line) => {
                    const m = /^([a-z0-9_]+):(.+)$/i.exec(line);
                    if (m) {
                      return { ioc_type: m[1].toLowerCase(), value: refangRe(m[2].trim()) };
                    }
                    return { ioc_type: defaultType, value: refangRe(line) };
                  });
                const r = await api.bulkImportIOCs(rows);
                onDone(r);
              } catch (e) {
                setErr(String(e));
              } finally {
                setBusy(false);
              }
            }}
            className="h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              background: "var(--color-accent)",
              color: "#fff",
            }}
          >
            {busy ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </div>
  );
}


function SightingsDrawer({ iocId, onClose }: { iocId: string; onClose: () => void }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<Awaited<ReturnType<typeof api.getIOCSightings>>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getIOCSightings(iocId)
      .then(setRows)
      .catch((e) => toast("error", `Sightings fetch failed — ${String(e)}`))
      .finally(() => setLoading(false));
  }, [iocId, toast]);

  return (
    <div
      className="fixed inset-0 z-[300] flex items-stretch justify-end"
      style={{ background: "rgba(0,0,0,0.4)" }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[520px] h-full overflow-y-auto p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-bold" style={{ color: "var(--color-ink)" }}>
            Sightings
          </h3>
          <button onClick={onClose} className="text-[12px] font-semibold" style={{ color: "var(--color-muted)" }}>
            Close
          </button>
        </div>
        {loading ? (
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Loading…</p>
        ) : rows.length === 0 ? (
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
            No sightings yet — sightings populate when this IOC appears in an ingested news article, alert, or feed.
          </p>
        ) : (
          <ul className="space-y-2">
            {rows.map((s) => (
              <li
                key={s.id}
                className="p-3"
                style={{ borderRadius: 4, border: "1px solid var(--color-surface-muted)" }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span
                    className="inline-flex h-[18px] px-1.5 text-[10px] font-bold uppercase"
                    style={{ borderRadius: 3, background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                  >
                    {s.source}
                  </span>
                  <span className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
                    {new Date(s.seen_at).toISOString().replace("T", " ").slice(0, 19)}
                  </span>
                </div>
                {s.source_url && (
                  <a
                    href={s.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[12px] break-all inline-block"
                    style={{ color: "var(--color-accent)" }}
                  >
                    {s.source_url}
                  </a>
                )}
                {Object.keys(s.context || {}).length > 0 && (
                  <pre
                    className="text-[11px] font-mono mt-1 p-2"
                    style={{
                      borderRadius: 4,
                      background: "var(--color-canvas)",
                      border: "1px solid var(--color-surface-muted)",
                      color: "var(--color-body)",
                    }}
                  >
                    {JSON.stringify(s.context, null, 2)}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}


function PivotDrawer({ iocId, onClose }: { iocId: string; onClose: () => void }) {
  const { toast } = useToast();
  const [data, setData] = useState<Awaited<ReturnType<typeof api.getIOCPivot>> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getIOCPivot(iocId)
      .then(setData)
      .catch((e) => toast("error", `Pivot fetch failed — ${String(e)}`))
      .finally(() => setLoading(false));
  }, [iocId, toast]);

  return (
    <div
      className="fixed inset-0 z-[300] flex items-stretch justify-end"
      style={{ background: "rgba(0,0,0,0.4)" }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[640px] h-full overflow-y-auto p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-bold" style={{ color: "var(--color-ink)" }}>
            Pivot
          </h3>
          <button onClick={onClose} className="text-[12px] font-semibold" style={{ color: "var(--color-muted)" }}>
            Close
          </button>
        </div>
        {loading || !data ? (
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Loading…</p>
        ) : (
          <>
            <div className="grid grid-cols-3 gap-2 mb-4">
              {[
                { label: "Articles citing", value: data.articles.length, tone: "rgba(0,187,217,0.10)", color: "#007B8A" },
                { label: "Related via articles", value: data.related_via_articles.length, tone: "rgba(255,79,0,0.10)", color: "var(--color-accent)" },
                { label: "Related via actor", value: data.related_via_actor.length, tone: "rgba(142,51,255,0.10)", color: "#6B21A8" },
              ].map((s) => (
                <div
                  key={s.label}
                  className="p-3"
                  style={{ borderRadius: 4, background: s.tone }}
                >
                  <div className="text-[10px] font-bold uppercase tracking-wide" style={{ color: s.color }}>
                    {s.label}
                  </div>
                  <div className="text-[20px] font-bold mt-1" style={{ color: s.color }}>
                    {s.value}
                  </div>
                </div>
              ))}
            </div>

            {data.articles.length > 0 && (
              <section className="mb-4">
                <h4 className="text-[12px] font-bold uppercase mb-2 tracking-wide" style={{ color: "var(--color-muted)" }}>
                  Articles
                </h4>
                <ul className="space-y-2">
                  {data.articles.map((a) => (
                    <li key={a.id} className="p-2" style={{ borderRadius: 4, border: "1px solid var(--color-surface-muted)" }}>
                      <a href={a.url} target="_blank" rel="noopener noreferrer" className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                        {a.title}
                      </a>
                      <p className="text-[11px] break-all mt-0.5" style={{ color: "var(--color-muted)" }}>{a.url}</p>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {(data.related_via_articles.length > 0 || data.related_via_actor.length > 0) && (
              <section>
                <h4 className="text-[12px] font-bold uppercase mb-2 tracking-wide" style={{ color: "var(--color-muted)" }}>
                  Related IOCs
                </h4>
                <ul className="space-y-1">
                  {[...data.related_via_articles, ...data.related_via_actor].slice(0, 30).map((r) => (
                    <li key={r.id} className="flex items-center gap-2 text-[12px]" style={{ color: "var(--color-body)" }}>
                      <span
                        className="inline-flex h-[16px] px-1 text-[10px] font-bold uppercase"
                        style={{ borderRadius: 3, background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                      >
                        {r.ioc_type}
                      </span>
                      <span className="font-mono break-all">{r.value}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
