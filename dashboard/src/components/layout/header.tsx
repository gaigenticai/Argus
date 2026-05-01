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
    <header
      className="sticky top-0 z-30 h-14 flex items-center justify-between px-6"
      style={{
        background: "var(--color-canvas)",
        borderBottom: "1px solid var(--color-border)",
      }}
    >
      <div ref={wrapperRef} className="relative flex items-center flex-1 max-w-md">
        <div className="relative w-full">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
            style={{ color: "var(--color-muted)" }}
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search alerts, organizations…"
            className="w-full h-9 pl-9 pr-8 text-[13px] outline-none transition-colors"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
              color: "var(--color-ink)",
            }}
            onFocus={(e) => {
              (e.target as HTMLInputElement).style.borderColor = "var(--color-accent)";
            }}
            onBlur={(e) => {
              (e.target as HTMLInputElement).style.borderColor = "var(--color-border)";
            }}
          />
          {query && (
            <button
              onClick={() => { setQuery(""); setOpen(false); }}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 transition-colors"
              style={{ color: "var(--color-muted)", borderRadius: "3px" }}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {open && (
          <div
            className="absolute top-full left-0 right-0 mt-1 overflow-hidden z-50 max-h-[380px] overflow-y-auto"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
              boxShadow: "var(--shadow-z16)",
            }}
          >
            {searching && (
              <div
                className="px-4 py-3 text-[12px]"
                style={{ color: "var(--color-muted)" }}
              >
                Searching…
              </div>
            )}
            {!searching && !hasResults && (
              <div
                className="px-4 py-6 text-center text-[13px]"
                style={{ color: "var(--color-muted)" }}
              >
                No results for &ldquo;{query}&rdquo;
              </div>
            )}

            {orgResults.length > 0 && (
              <div>
                <div
                  className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.8px]"
                  style={{
                    color: "var(--color-muted)",
                    background: "var(--color-surface-muted)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  Organizations
                </div>
                {orgResults.map((org) => (
                  <button
                    key={org.id}
                    onClick={() => { router.push(`/organizations`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left flex items-center gap-3 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "";
                    }}
                  >
                    <span
                      className="w-7 h-7 flex items-center justify-center text-[11px] font-bold shrink-0"
                      style={{
                        background: "var(--color-surface-muted)",
                        color: "var(--color-body)",
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                      }}
                    >
                      {org.name.charAt(0)}
                    </span>
                    <div>
                      <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                        {org.name}
                      </div>
                      {org.industry && (
                        <div className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                          {org.industry}
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {alertResults.length > 0 && (
              <div>
                <div
                  className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.8px]"
                  style={{
                    color: "var(--color-muted)",
                    background: "var(--color-surface-muted)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  Alerts
                </div>
                {alertResults.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => { router.push(`/alerts/${alert.id}`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left flex items-center gap-3 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "";
                    }}
                  >
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0 flex-1">
                      <div
                        className="text-[13px] font-semibold truncate"
                        style={{ color: "var(--color-ink)" }}
                      >
                        {alert.title}
                      </div>
                      <div
                        className="text-[11px] truncate"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {alert.summary}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        <button
          onClick={() => router.push("/alerts?status=new")}
          className="relative p-2 transition-colors"
          style={{ borderRadius: "5px", color: "var(--color-body)" }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "";
          }}
        >
          <Bell className="w-4 h-4" />
          {unreviewed > 0 && (
            <span
              className="absolute top-0.5 right-0.5 min-w-[16px] h-[16px] flex items-center justify-center text-[9px] font-bold px-1"
              style={{
                background: "var(--color-accent)",
                color: "#fffefb",
                borderRadius: "20px",
              }}
            >
              {unreviewed > 99 ? "99+" : unreviewed}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
