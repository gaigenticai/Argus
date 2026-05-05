"use client";

/**
 * <EmptyState pageKey="leakage" /> — context-aware empty state for
 * any data page. Reads the same /admin/service-inventory/page/<key>
 * the SourcesStrip uses, and chooses between three messages:
 *
 *   1. NO sources configured/active → "Configure a source to populate
 *      this view" + link to Settings → Services.
 *   2. Sources active but none producing yet → "Sources are running
 *      but nothing matched. Try widening brand terms or wait for the
 *      next worker tick."
 *   3. Sources producing data globally but nothing for the current
 *      org/filter → "No findings for this scope. N rows landed in
 *      the last 24h overall."
 *
 * Drop into any data page where a list/table can be empty.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Inbox,
  Settings as SettingsIcon,
} from "lucide-react";
import { api, type ServiceInventoryEntry } from "@/lib/api";

type Props = {
  pageKey: string;
  // Optional: app-specific tagline shown alongside the source-aware
  // detail (e.g. "no leaked credentials yet")
  title?: string;
  // Override which Settings tab the "configure" CTA jumps to. Default
  // is the Service Inventory, but pages whose sources are
  // crawler_targets-backed should point at /admin → Crawler Targets.
  configureHref?: string;
};

export function EmptyState({ pageKey, title, configureHref = "/settings?tab=services" }: Props) {
  const [services, setServices] = useState<ServiceInventoryEntry[] | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const r = await api.admin.servicesForPage(pageKey);
        if (!alive) return;
        // Drop infrastructure rows ("*") — they're noise here. We
        // care about category-specific sources for THIS page.
        setServices(r.services.filter((s) => !s.produces_pages.includes("*")));
      } catch {
        if (alive) setServices([]);
      }
    })();
    return () => { alive = false; };
  }, [pageKey]);

  if (services === null) {
    return null;  // wait for sources fetch; SourcesStrip already showed a loader
  }

  const counts: Record<string, number> = {};
  for (const s of services) counts[s.status] = (counts[s.status] || 0) + 1;
  const ok = counts.ok || 0;
  const needsKey = counts.needs_key || 0;
  const notInstalled = counts.not_installed || 0;
  const actionable = needsKey + notInstalled;

  // Two-mode empty-state picker (the retired "broken" bucket is gone:
  // every non-OK row is operator-actionable, either via a key or by
  // installing a tool).
  let mode: "no-sources" | "running-empty";
  if (services.length === 0 || (ok === 0 && actionable > 0)) {
    mode = "no-sources";
  } else {
    mode = "running-empty";
  }

  return (
    <div
      className="px-6 py-10 text-center"
      style={{
        background: "var(--color-canvas)",
        border: "1px dashed var(--color-border)",
        borderRadius: 8,
      }}
    >
      <div className="flex justify-center mb-3">
        {mode === "no-sources" && <CircleSlash className="w-8 h-8" style={{ color: "var(--color-muted)" }} />}
        {mode === "running-empty" && <Inbox className="w-8 h-8" style={{ color: "var(--color-muted)" }} />}
      </div>
      <h3 className="text-[16px] font-semibold" style={{ color: "var(--color-ink)" }}>
        {title ?? "No findings yet"}
      </h3>
      <p className="text-[12.5px] mt-1.5 max-w-[520px] mx-auto" style={{ color: "var(--color-muted)" }}>
        {mode === "no-sources" && (
          <>
            This view is powered by <strong>{services.length}</strong> source{services.length === 1 ? "" : "s"} —{" "}
            <strong>{ok}</strong> active, <strong>{needsKey}</strong> need a key,{" "}
            <strong>{notInstalled}</strong> not installed.{" "}
            Configure at least one provider for this category to start populating findings.
          </>
        )}
        {mode === "running-empty" && (
          <>
            <strong>{ok}</strong> source{ok === 1 ? "" : "s"} actively running,{" "}
            no matches yet. Either nothing relevant has surfaced upstream,
            or the matchers (brand terms, monitored emails, asset list)
            need widening.
          </>
        )}
      </p>
      <div className="flex items-center justify-center gap-2 mt-4">
        {mode === "no-sources" && (
          <Link
            href={configureHref}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold"
            style={{
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
              border: "none",
              borderRadius: 4,
            }}
          >
            <SettingsIcon className="w-3.5 h-3.5" />
            Configure a source
          </Link>
        )}
        <Link
          href="/settings?tab=services"
          className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-medium"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-ink)",
          }}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          Service Inventory
        </Link>
      </div>
    </div>
  );
}
