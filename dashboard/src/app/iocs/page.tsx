"use client";

import { useEffect, useState, useCallback } from "react";
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

const IOC_TYPES = [
  "all",
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "email",
  "md5",
  "sha1",
  "sha256",
  "btc_address",
  "xmr_address",
  "cve",
  "filename",
  "registry_key",
  "mutex",
  "user_agent",
  "cidr",
  "asn",
  "ja3",
];

const TYPE_COLORS: Record<string, { bg: string; text: string }> = {
  ipv4: { bg: "bg-info-lighter", text: "text-info-dark" },
  ipv6: { bg: "bg-info-lighter", text: "text-info-dark" },
  domain: { bg: "bg-primary-lighter", text: "text-primary-dark" },
  url: { bg: "bg-primary-lighter", text: "text-primary-dark" },
  email: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  md5: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  sha1: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  sha256: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  btc_address: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  xmr_address: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  cve: { bg: "bg-error-lighter", text: "text-error-dark" },
  filename: { bg: "bg-grey-200", text: "text-grey-700" },
  registry_key: { bg: "bg-grey-200", text: "text-grey-700" },
  mutex: { bg: "bg-grey-200", text: "text-grey-700" },
  user_agent: { bg: "bg-grey-200", text: "text-grey-700" },
  cidr: { bg: "bg-info-lighter", text: "text-info-dark" },
  asn: { bg: "bg-info-lighter", text: "text-info-dark" },
  ja3: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
};

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

  // Expanded row
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Bulk search
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
      // Backend returns a plain array — total is approximated from array length + offset
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
    } catch {
      // Stats are optional
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Indicators of Compromise</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            {total} IOCs tracked
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowBulkSearch(!showBulkSearch)}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <Search className="w-4 h-4" />
            Bulk Search
          </button>
          <button
            onClick={handleExportSTIX}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <Download className="w-4 h-4" />
            STIX
          </button>
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button
            onClick={() => { load(); loadStats(); }}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="bg-white rounded-xl border border-grey-200 p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-grey-500">Total</div>
            <div className="text-[20px] font-bold text-grey-900 mt-1">{stats.total.toLocaleString()}</div>
          </div>
          {Object.entries(stats.by_type)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([type, count]) => {
              const colors = TYPE_COLORS[type] || TYPE_COLORS.filename;
              return (
                <div key={type} className="bg-white rounded-xl border border-grey-200 p-4">
                  <div className={`text-[11px] font-bold uppercase tracking-wider ${colors.text}`}>{type}</div>
                  <div className="text-[20px] font-bold text-grey-900 mt-1">{count.toLocaleString()}</div>
                </div>
              );
            })}
        </div>
      )}

      {/* Bulk Search Panel */}
      {showBulkSearch && (
        <div className="bg-white rounded-xl border border-grey-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[16px] font-bold text-grey-900">Bulk IOC Search</h3>
            <button onClick={() => { setShowBulkSearch(false); setBulkResults(null); }} className="p-1 rounded hover:bg-grey-100">
              <X className="w-4 h-4 text-grey-500" />
            </button>
          </div>
          <form onSubmit={handleBulkSearch} className="space-y-3">
            <textarea
              value={bulkInput}
              onChange={(e) => setBulkInput(e.target.value)}
              rows={5}
              placeholder="Paste IOC values, one per line (IPs, domains, hashes, etc.)"
              className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[13px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
            />
            <button
              type="submit"
              disabled={bulkSearching}
              className="h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
            >
              {bulkSearching ? "Searching..." : "Search"}
            </button>
          </form>

          {bulkResults !== null && (
            <div className="mt-4">
              {bulkResults.filter((r) => r.found).length === 0 ? (
                <p className="text-[13px] text-grey-500">No matches found in database</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full mt-2">
                    <thead>
                      <tr className="bg-grey-100">
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Status</th>
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Value</th>
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Type</th>
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Confidence</th>
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Sightings</th>
                        <th className="text-left h-10 px-3 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bulkResults.map((result) => {
                        const ioc = result.ioc;
                        const colors = ioc ? (TYPE_COLORS[ioc.ioc_type] || TYPE_COLORS.filename) : { bg: "bg-grey-200", text: "text-grey-600" };
                        return (
                          <tr key={result.value} className="h-[44px] border-b border-grey-100">
                            <td className="px-3">
                              <span className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${result.found ? "bg-error-lighter text-error-dark" : "bg-grey-200 text-grey-600"}`}>
                                {result.found ? "Found" : "Clean"}
                              </span>
                            </td>
                            <td className="px-3 text-[13px] font-mono text-grey-800 max-w-[300px] truncate">{result.value}</td>
                            <td className="px-3">
                              {ioc && (
                                <span className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${colors.bg} ${colors.text}`}>
                                  {ioc.ioc_type}
                                </span>
                              )}
                            </td>
                            <td className="px-3 text-[13px] text-grey-600">{ioc ? `${Math.round(ioc.confidence * 100)}%` : "-"}</td>
                            <td className="px-3 text-[13px] text-grey-600">{ioc?.sighting_count ?? "-"}</td>
                            <td className="px-3 text-[13px] text-grey-500">{ioc ? formatDate(ioc.last_seen) : "-"}</td>
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
          <Filter className="w-4 h-4 text-grey-500" />
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setOffset(0); }}
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
          >
            {IOC_TYPES.map((t) => (
              <option key={t} value={t}>
                {t === "all" ? "All types" : t.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[11px] font-bold text-grey-500 uppercase tracking-wider mb-1">Min Confidence</label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min={0}
              max={100}
              value={minConfidence}
              onChange={(e) => { setMinConfidence(Number(e.target.value)); setOffset(0); }}
              className="w-32"
            />
            <span className="text-[13px] text-grey-600 font-semibold w-10">{minConfidence}%</span>
          </div>
        </div>
        <div>
          <input
            type="text"
            value={searchText}
            onChange={(e) => { setSearchText(e.target.value); setOffset(0); }}
            placeholder="Search IOC values..."
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white w-[240px]"
          />
        </div>
      </div>

      {/* IOC Table */}
      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : iocs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
            <Crosshair className="w-8 h-8 mb-2 text-grey-400" />
            <p className="text-[14px]">No IOCs match your filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-grey-100">
                  <th className="w-8"></th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Type</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Value</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Confidence</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">First Seen</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Seen</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Sightings</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Actor</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => {
                  const colors = TYPE_COLORS[ioc.ioc_type] || TYPE_COLORS.filename;
                  const isExpanded = expandedId === ioc.id;
                  return (
                    <>
                      <tr
                        key={ioc.id}
                        className="h-[52px] border-b border-grey-100 hover:bg-grey-50 transition-colors cursor-pointer"
                        onClick={() => setExpandedId(isExpanded ? null : ioc.id)}
                      >
                        <td className="pl-3">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-grey-400" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-grey-400" />
                          )}
                        </td>
                        <td className="px-4">
                          <span className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${colors.bg} ${colors.text}`}>
                            {ioc.ioc_type}
                          </span>
                        </td>
                        <td className="px-4 text-[13px] font-mono text-grey-800 max-w-[300px] truncate">
                          {ioc.value}
                        </td>
                        <td className="px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-grey-200 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary rounded-full"
                                style={{ width: `${ioc.confidence * 100}%` }}
                              />
                            </div>
                            <span className="text-[13px] text-grey-600">{Math.round(ioc.confidence * 100)}%</span>
                          </div>
                        </td>
                        <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                          {formatDate(ioc.first_seen)}
                        </td>
                        <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                          {formatDate(ioc.last_seen)}
                        </td>
                        <td className="px-4 text-[13px] text-grey-600 font-semibold">
                          {ioc.sighting_count}
                        </td>
                        <td className="px-4 text-[13px] text-grey-500">
                          {ioc.threat_actor_id ? (
                            <Link
                              href={`/actors/${ioc.threat_actor_id}`}
                              className="text-primary hover:text-primary-dark transition-colors font-semibold"
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
                        <tr key={`${ioc.id}-detail`} className="border-b border-grey-100">
                          <td colSpan={8} className="px-8 py-4 bg-grey-50">
                            <div className="grid grid-cols-2 gap-4 text-[13px]">
                              <div>
                                <span className="text-grey-500 font-semibold">Full Value:</span>
                                <p className="font-mono text-grey-800 break-all mt-1">{ioc.value}</p>
                              </div>
                              {ioc.tags && ioc.tags.length > 0 && (
                                <div>
                                  <span className="text-grey-500 font-semibold">Tags:</span>
                                  <div className="flex gap-1 flex-wrap mt-1">
                                    {ioc.tags.map((tag) => (
                                      <span key={tag} className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold bg-grey-200 text-grey-700">
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {ioc.context && (
                                <div className="col-span-2">
                                  <span className="text-grey-500 font-semibold">Context:</span>
                                  <pre className="text-[12px] font-mono text-grey-700 bg-white border border-grey-200 rounded-lg p-3 mt-1 overflow-x-auto">
                                    {JSON.stringify(ioc.context, null, 2)}
                                  </pre>
                                </div>
                              )}
                              {ioc.source_alert_id && (
                                <div>
                                  <span className="text-grey-500 font-semibold">Source Alert:</span>
                                  <Link
                                    href={`/alerts/${ioc.source_alert_id}`}
                                    className="block text-primary hover:text-primary-dark transition-colors font-semibold mt-1"
                                  >
                                    {ioc.source_alert_id.substring(0, 8)}...
                                  </Link>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
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
          <p className="text-[13px] text-grey-500">
            Page {currentPage} of {totalPages}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
