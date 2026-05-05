"use client";

/**
 * <CoverageGate pageSlug="leakage"> — page-level wrapper that shows a
 * full-page "configure a source" CTA when no source for the named
 * page is producing data, and renders its children otherwise.
 *
 * Behaviour:
 *   - While coverage is loading (first paint), render children — never
 *     flash an empty CTA over a working view.
 *   - If `pageSlug` is NOT in the coverage map at all (UI-only page,
 *     no inventory entry targets it), render children — the inventory
 *     doesn't claim this page, so we can't make a coverage call.
 *   - If `pageSlug` is in the map and the value is `false` (zero OK
 *     sources produce this page's data type), render the CTA. The
 *     CTA links to /settings?tab=services and surfaces which catalogued
 *     sources back this page so the operator can pick one.
 *   - Otherwise render children.
 *
 * The coverage map is shared across all consumers (sidebar + every
 * gated page) via `useCoverage()`, so wrapping every data page costs
 * one /admin/service-coverage call per 30s window.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { CircleSlash, ExternalLink, Settings as SettingsIcon } from "lucide-react";

import {
  api,
  type ServiceInventoryEntry,
} from "@/lib/api";
import { isPageCovered, useCoverage } from "@/lib/use-coverage";

type Props = {
  pageSlug: string;
  // Optional human-readable label for the CTA copy
  // ("This view is powered by N <pageLabel> sources..."). Falls back
  // to the slug if absent.
  pageLabel?: string;
  // Optional override for where the "Configure" button links.
  configureHref?: string;
  children: React.ReactNode;
};

export function CoverageGate({
  pageSlug,
  pageLabel,
  configureHref = "/settings?tab=services",
  children,
}: Props) {
  const coverage = useCoverage();

  if (isPageCovered(coverage, "/" + pageSlug)) {
    return <>{children}</>;
  }

  return <UnconfiguredCta pageSlug={pageSlug} pageLabel={pageLabel} configureHref={configureHref} />;
}

function UnconfiguredCta({
  pageSlug,
  pageLabel,
  configureHref,
}: {
  pageSlug: string;
  pageLabel?: string;
  configureHref: string;
}) {
  // Pull the per-page inventory subset so we can show the operator
  // *which* services back this view — e.g. "Powered by HudsonRock
  // Cavalier, Have I Been Pwned, Intelligence X — none configured."
  const [services, setServices] = useState<ServiceInventoryEntry[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const r = await api.admin.servicesForPage(pageSlug);
        if (!alive) return;
        // Strip infrastructure rows (the universal "*") — they
        // power every page; not actionable from here.
        setServices(r.services.filter((s) => !s.produces_pages.includes("*")));
      } catch (e) {
        if (alive) setLoadError((e as Error).message);
      }
    })();
    return () => { alive = false; };
  }, [pageSlug]);

  const label = pageLabel || pageSlug;
  const total = services?.length ?? 0;

  return (
    <div
      className="px-6 py-12"
      style={{
        background: "var(--color-canvas)",
        border: "1px dashed var(--color-border)",
        borderRadius: 10,
      }}
    >
      <div className="max-w-[640px] mx-auto text-center">
        <div className="flex justify-center mb-4">
          <CircleSlash className="w-9 h-9" style={{ color: "var(--color-muted)" }} />
        </div>
        <h2
          className="text-[18px] font-semibold tracking-[-0.01em]"
          style={{ color: "var(--color-ink)" }}
        >
          No source configured for {label}
        </h2>
        <p
          className="text-[13px] mt-2 max-w-[480px] mx-auto"
          style={{ color: "var(--color-muted)" }}
        >
          {total > 0
            ? `This view is powered by ${total} catalogued source${total === 1 ? "" : "s"}, none of them currently configured. Add at least one to start populating ${label}.`
            : `Configure a source for this view in Settings → Services.`
          }
        </p>

        {services && services.length > 0 && (
          <div
            className="mt-5 mx-auto inline-block text-left text-[12px]"
            style={{ color: "var(--color-body)" }}
          >
            <div
              className="text-[10.5px] font-bold uppercase tracking-[0.7px] mb-1.5"
              style={{ color: "var(--color-muted)" }}
            >
              Available sources
            </div>
            <ul className="space-y-1 max-h-[180px] overflow-auto pr-2">
              {services.map((s) => (
                <li key={s.name} className="flex items-center gap-2">
                  <span
                    className="inline-block w-1 h-1 rounded-full"
                    style={{ background: "var(--color-muted)" }}
                  />
                  <span style={{ color: "var(--color-ink)" }}>{s.name}</span>
                  <span style={{ color: "var(--color-muted)" }}>
                    — {s.category}
                    {s.no_oss_substitute ? " (paid)" : ""}
                    {s.self_hosted ? " (self-hosted OSS)" : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex items-center justify-center gap-2 mt-6">
          <Link
            href={configureHref}
            className="inline-flex items-center gap-1.5 h-9 px-4 text-[13px] font-semibold"
            style={{
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
              border: "none",
              borderRadius: 5,
            }}
          >
            <SettingsIcon className="w-3.5 h-3.5" />
            Configure a source
          </Link>
          <a
            href="https://github.com/anthropics"
            target="_blank"
            rel="noreferrer noopener"
            className="hidden"
          >
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        {loadError && (
          <p
            className="text-[11px] mt-3"
            style={{ color: "var(--color-error-dark)" }}
          >
            (Couldn’t load source list: {loadError})
          </p>
        )}
      </div>
    </div>
  );
}
