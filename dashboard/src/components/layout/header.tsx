"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, Search, X } from "lucide-react";
import { api, type Alert, type Org } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";

export function Header() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [alertResults, setAlertResults] = useState<Alert[]>([]);
  const [orgResults, setOrgResults] = useState<Org[]>([]);
  const [searching, setSearching] = useState(false);
  const [unreviewed, setUnreviewed] = useState(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function fetchCount() {
      try {
        const stats = await api.getAlertStats();
        setUnreviewed(stats.by_status?.new || 0);
      } catch {}
    }
    fetchCount();
    const interval = setInterval(fetchCount, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!query.trim()) {
      setAlertResults([]);
      setOrgResults([]);
      setOpen(false);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const [alerts, orgs] = await Promise.all([
          api.searchAlerts(query),
          api.searchOrgs(query),
        ]);
        setAlertResults(alerts);
        setOrgResults(orgs);
        setOpen(true);
      } catch {}
      setSearching(false);
    }, 300);
  }, [query]);

  const hasResults = alertResults.length > 0 || orgResults.length > 0;

  return (
    <header className="sticky top-0 z-30 h-16 bg-white/80 backdrop-blur-md border-b border-grey-200 flex items-center justify-between px-8">
      <div ref={wrapperRef} className="relative flex items-center flex-1 max-w-lg">
        <div className="relative w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-[18px] h-[18px] text-grey-400" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search alerts, organizations..."
            className="w-full h-10 pl-10 pr-9 bg-grey-100 rounded-lg text-[14px] text-grey-800 placeholder:text-grey-400 border border-transparent outline-none focus:border-grey-300 focus:bg-white transition-colors"
          />
          {query && (
            <button
              onClick={() => { setQuery(""); setOpen(false); }}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-grey-200"
            >
              <X className="w-4 h-4 text-grey-500" />
            </button>
          )}
        </div>

        {open && (
          <div className="absolute top-full left-0 right-0 mt-1 bg-white rounded-xl shadow-z16 border border-grey-200 overflow-hidden z-50 max-h-[400px] overflow-y-auto">
            {searching && (
              <div className="px-4 py-3 text-[13px] text-grey-500">Searching...</div>
            )}
            {!searching && !hasResults && (
              <div className="px-4 py-6 text-center text-[13px] text-grey-500">
                No results for &ldquo;{query}&rdquo;
              </div>
            )}

            {orgResults.length > 0 && (
              <div>
                <div className="px-4 py-2 text-[11px] font-bold text-grey-500 uppercase tracking-wider bg-grey-50">
                  Organizations
                </div>
                {orgResults.map((org) => (
                  <button
                    key={org.id}
                    onClick={() => { router.push(`/organizations`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left hover:bg-grey-50 transition-colors flex items-center gap-3"
                  >
                    <span className="w-7 h-7 rounded-md bg-grey-100 flex items-center justify-center text-grey-600 text-[11px] font-bold">
                      {org.name.charAt(0)}
                    </span>
                    <div>
                      <div className="text-[13px] font-semibold text-grey-800">{org.name}</div>
                      {org.industry && <div className="text-[11px] text-grey-500">{org.industry}</div>}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {alertResults.length > 0 && (
              <div>
                <div className="px-4 py-2 text-[11px] font-bold text-grey-500 uppercase tracking-wider bg-grey-50">
                  Alerts
                </div>
                {alertResults.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => { router.push(`/alerts/${alert.id}`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left hover:bg-grey-50 transition-colors flex items-center gap-3"
                  >
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] font-semibold text-grey-800 truncate">{alert.title}</div>
                      <div className="text-[11px] text-grey-500 truncate">{alert.summary}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => router.push("/alerts?status=new")}
          className="relative p-2 rounded-lg hover:bg-grey-100 transition-colors"
        >
          <Bell className="w-5 h-5 text-grey-600" />
          {unreviewed > 0 && (
            <span className="absolute top-0.5 right-0.5 min-w-[18px] h-[18px] bg-error rounded-full flex items-center justify-center text-white text-[10px] font-bold px-1">
              {unreviewed > 99 ? "99+" : unreviewed}
            </span>
          )}
        </button>
        <div className="w-8 h-8 rounded-full bg-grey-800 flex items-center justify-center text-white text-[12px] font-bold">
          A
        </div>
      </div>
    </header>
  );
}
