"use client";

/**
 * <SourcesStrip pageKey="leakage" /> — compact "what's powering this
 * view?" header for any data page.
 *
 * Backed by ``GET /admin/service-inventory/page/<pageKey>`` which
 * returns the subset of the catalog whose ``produces_pages`` includes
 * the given page slug. Each service renders as a small status pill;
 * click to expand for evidence + remediation links.
 *
 * Refresh strategy:
 *   - on mount: fetch immediately (instant truth on landing)
 *   - 30s interval while page is open
 *   - on window focus (operator tabs back in)
 *   - manual refresh button
 *
 * Status pills use the same colour convention as Settings → Services
 * so operators learn one visual language.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Info,
  Loader2,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { api, type ServiceInventoryEntry } from "@/lib/api";

// 3-state taxonomy. See dashboard/src/lib/api.ts → ServiceStatusValue.
type StripStatusMeta = {
  label: string;
  color: string;
  bg: string;
  border: string;
  icon: typeof CheckCircle2;
};

const STATUS_META: Record<
  ServiceInventoryEntry["status"],
  StripStatusMeta
> = {
  ok:            { label: "OK",            color: "var(--color-success-dark)", bg: "rgba(34,197,94,0.1)",   border: "rgba(34,197,94,0.3)",  icon: CheckCircle2 },
  needs_key:     { label: "Needs key",     color: "#B76E00",                   bg: "rgba(255,171,0,0.1)",   border: "rgba(255,171,0,0.3)",  icon: Info },
  not_installed: { label: "Not installed", color: "var(--color-muted)",        bg: "var(--color-surface-muted)", border: "var(--color-border)", icon: CircleSlash },
};

// Defensive lookup — same rationale as Settings → Services. A stale API
// container (or any future status emitter) returning a value outside the
// 3-bucket taxonomy must not crash the page; render a neutral pill that
// surfaces the raw status string instead.
function stripStatusMeta(status: string): StripStatusMeta {
  const known = STATUS_META[status as keyof typeof STATUS_META];
  if (known) return known;
  return {
    label: status || "?",
    color: "var(--color-muted)",
    bg: "var(--color-surface-muted)",
    border: "var(--color-border)",
    icon: Info,
  };
}

const REFRESH_INTERVAL_MS = 30_000;

export function SourcesStrip({
  pageKey,
  defaultCollapsed = true,
}: {
  pageKey: string;
  defaultCollapsed?: boolean;
}) {
  const [services, setServices] = useState<ServiceInventoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [expandedName, setExpandedName] = useState<string | null>(null);
  const aliveRef = useRef(true);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const r = await api.admin.servicesForPage(pageKey);
      if (!aliveRef.current) return;
      setServices(r.services);
      setError(null);
    } catch (e) {
      if (!aliveRef.current) return;
      setError((e as Error).message);
    } finally {
      if (aliveRef.current) setRefreshing(false);
    }
  }, [pageKey]);

  useEffect(() => {
    aliveRef.current = true;
    void load();
    const interval = setInterval(load, REFRESH_INTERVAL_MS);
    const onFocus = () => void load();
    window.addEventListener("focus", onFocus);
    return () => {
      aliveRef.current = false;
      clearInterval(interval);
      window.removeEventListener("focus", onFocus);
    };
  }, [load]);

  if (services === null && error === null) {
    // Don't reserve a tall block while loading — keep the page header
    // tight; render a 1-line skeleton.
    return (
      <div
        className="px-3 py-1.5 text-[11.5px] flex items-center gap-2"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 5,
          color: "var(--color-muted)",
        }}
      >
        <Loader2 className="w-3 h-3 animate-spin" />
        loading sources…
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="px-3 py-1.5 text-[11.5px] flex items-center gap-2"
        style={{
          background: "rgba(239,68,68,0.04)",
          border: "1px solid rgba(239,68,68,0.2)",
          borderRadius: 5,
          color: "var(--color-error-dark)",
        }}
      >
        <AlertTriangle className="w-3 h-3" /> couldn&apos;t load sources: {error}
        <button
          onClick={() => void load()}
          className="ml-auto inline-flex items-center gap-1 px-2 py-0.5"
          style={{ background: "transparent", border: "1px solid currentColor", borderRadius: 3, cursor: "pointer", color: "inherit" }}
        >
          retry
        </button>
      </div>
    );
  }

  // The collapsed bar shows the active count + a muted "+N available
  // with config" so the page header stays tight. Expanding reveals
  // BOTH sections — active (green pills) and dark (amber/grey pills)
  // — so operators can see exactly which sources are dark and click
  // through to fix them without leaving the page. Earlier versions of
  // this component hid dark rows entirely, which left the operator
  // guessing what was missing.
  const allServices = services ?? [];
  const list = allServices.filter((s) => s.status === "ok");
  const dark = allServices.filter((s) => s.status !== "ok");
  if (allServices.length === 0) {
    return null;  // page didn't claim any services in the catalog
  }

  const ok = list.length;
  const hiddenCount = dark.length;

  const sortByCatName = (a: ServiceInventoryEntry, b: ServiceInventoryEntry) =>
    a.category.localeCompare(b.category) ||
    a.name.localeCompare(b.name);
  const sorted = [...list].sort(sortByCatName);
  const sortedDark = [...dark].sort(sortByCatName);

  const headerColor =
    ok === 0 ? "var(--color-muted)" :
    "var(--color-body)";

  return (
    <div
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-[11.5px] text-left"
        style={{
          background: "transparent",
          border: "none",
          cursor: "pointer",
          color: "var(--color-body)",
        }}
      >
        <span
          className="font-bold uppercase tracking-[0.6px] text-[10.5px]"
          style={{ color: "var(--color-muted)" }}
        >
          Powered by
        </span>
        <span style={{ color: headerColor, fontWeight: 600 }}>
          {ok === 0 ? "no active sources" : `${ok} active source${ok === 1 ? "" : "s"}`}
        </span>
        {hiddenCount > 0 && (
          <Link
            href="/settings?tab=services"
            className="ml-1 inline-flex items-center"
            style={{ color: "var(--color-muted)", textDecoration: "none" }}
            onClick={(e) => e.stopPropagation()}
            title="Configure additional sources from Settings → Services"
          >
            <span style={{ fontWeight: 500 }}>
              + {hiddenCount} available with config →
            </span>
          </Link>
        )}
        <span className="ml-auto inline-flex items-center gap-2">
          {refreshing && (
            <Loader2 className="w-3 h-3 animate-spin" style={{ color: "var(--color-muted)" }} />
          )}
          <span
            style={{
              color: "var(--color-muted)",
              transform: collapsed ? "rotate(0deg)" : "rotate(90deg)",
              transition: "transform 0.15s",
              fontSize: 12,
              lineHeight: 1,
            }}
          >
            ▶
          </span>
        </span>
      </button>

      {!collapsed && (
        <div style={{ borderTop: "1px solid var(--color-border)" }}>
          {sorted.length > 0 && (
            <div className="px-3 pt-2 text-[10.5px] font-bold uppercase tracking-[0.6px]" style={{ color: "var(--color-muted)" }}>
              Active ({sorted.length})
            </div>
          )}
          <div className="flex flex-wrap gap-1.5 px-3 py-2">
            {sorted.map((s) => {
              const meta = stripStatusMeta(s.status);
              const Icon = meta.icon;
              const isOpen = expandedName === s.name;
              return (
                <button
                  key={s.name}
                  type="button"
                  onClick={() => setExpandedName(isOpen ? null : s.name)}
                  title={`${s.category}: ${s.description}`}
                  className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold"
                  style={{
                    background: meta.bg,
                    color: meta.color,
                    border: `1px solid ${meta.border}`,
                    borderRadius: 3,
                    cursor: "pointer",
                  }}
                >
                  <Icon className="w-2.5 h-2.5" />
                  {s.name}
                </button>
              );
            })}
            <button
              onClick={() => void load()}
              className="ml-auto inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: 3,
                color: "var(--color-muted)",
                cursor: "pointer",
              }}
              title="Re-probe every source"
            >
              <RefreshCw className={`w-3 h-3 ${refreshing ? "animate-spin" : ""}`} />
              refresh
            </button>
          </div>

          {sortedDark.length > 0 && (
            <>
              <div
                className="px-3 pt-1 text-[10.5px] font-bold uppercase tracking-[0.6px]"
                style={{ color: "var(--color-muted)", borderTop: "1px solid var(--color-border)" }}
              >
                Inactive ({sortedDark.length}) — click any to configure
              </div>
              <div className="flex flex-wrap gap-1.5 px-3 py-2">
                {sortedDark.map((s) => {
                  const meta = stripStatusMeta(s.status);
                  const Icon = meta.icon;
                  const isOpen = expandedName === s.name;
                  return (
                    <button
                      key={s.name}
                      type="button"
                      onClick={() => setExpandedName(isOpen ? null : s.name)}
                      title={`${s.category}: ${s.description}`}
                      className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold"
                      style={{
                        background: meta.bg,
                        color: meta.color,
                        border: `1px solid ${meta.border}`,
                        borderRadius: 3,
                        cursor: "pointer",
                        opacity: 0.85,
                      }}
                    >
                      <Icon className="w-2.5 h-2.5" />
                      {s.name}
                      <span
                        className="ml-1 text-[9.5px] uppercase tracking-[0.5px]"
                        style={{ opacity: 0.85 }}
                      >
                        {meta.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </>
          )}

          {expandedName && (() => {
            const s =
              sorted.find((x) => x.name === expandedName) ??
              sortedDark.find((x) => x.name === expandedName);
            if (!s) return null;
            const meta = stripStatusMeta(s.status);
            return (
              <div
                className="px-3 py-2.5 text-[12px] space-y-1.5"
                style={{
                  background: "var(--color-surface)",
                  borderTop: "1px solid var(--color-border)",
                  color: "var(--color-body)",
                }}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <strong style={{ color: "var(--color-ink)" }}>{s.name}</strong>
                  <span
                    className="px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.6px]"
                    style={{
                      background: meta.bg,
                      color: meta.color,
                      borderRadius: 3,
                    }}
                  >
                    {meta.label}
                  </span>
                  <span style={{ color: "var(--color-muted)", fontSize: 11 }}>
                    {s.category}
                  </span>
                </div>
                <div className="font-mono text-[11.5px]" style={{ color: meta.color }}>
                  {s.evidence || "(no evidence available)"}
                </div>
                {s.last_rows_ingested != null && s.last_rows_ingested > 0 && (
                  <div style={{ color: "var(--color-muted)", fontSize: 11 }}>
                    last ingested {s.last_rows_ingested.toLocaleString()} rows
                    {s.last_observed_at && ` · ${new Date(s.last_observed_at).toLocaleString()}`}
                  </div>
                )}
                <div className="flex items-center gap-3 pt-1 text-[11px]">
                  <Link
                    href="/settings?tab=services"
                    className="inline-flex items-center gap-1"
                    style={{ color: "var(--color-accent)" }}
                  >
                    Service Inventory
                  </Link>
                  {s.status === "needs_key" && (
                    <Link
                      href="/settings?tab=services"
                      className="inline-flex items-center gap-1"
                      style={{ color: "var(--color-accent)" }}
                    >
                      Configure key
                    </Link>
                  )}
                  {s.status === "not_installed" && (
                    <Link
                      href="/settings?tab=services"
                      className="inline-flex items-center gap-1"
                      style={{ color: "var(--color-accent)" }}
                    >
                      Install
                    </Link>
                  )}
                  {s.docs_url && (
                    <a
                      href={s.docs_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: "var(--color-muted)" }}
                    >
                      upstream docs ↗
                    </a>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
