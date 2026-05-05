"use client";

import { useEffect, useState } from "react";

import { api, type ServiceCoverageResponse } from "@/lib/api";

// Module-level cache + subscribers so every consumer (sidebar, page
// components, inline panels) shares one in-flight request and one
// 30-second poll. Calling useCoverage() in N components causes ONE
// /admin/service-coverage hit per refresh window, not N.

const REFRESH_MS = 30_000;

let cached: ServiceCoverageResponse | null = null;
let inFlight: Promise<ServiceCoverageResponse> | null = null;
let lastFetchAt = 0;
let timer: ReturnType<typeof setInterval> | null = null;
const subscribers = new Set<(c: ServiceCoverageResponse | null) => void>();

function broadcast() {
  for (const fn of subscribers) fn(cached);
}

async function refresh(): Promise<ServiceCoverageResponse> {
  if (inFlight) return inFlight;
  inFlight = (async () => {
    try {
      const c = await api.admin.serviceCoverage();
      cached = c;
      lastFetchAt = Date.now();
      broadcast();
      return c;
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

function ensurePolling() {
  if (timer) return;
  timer = setInterval(() => {
    void refresh().catch(() => {/* swallow — sidebar shouldn't crash on a bad fetch */});
  }, REFRESH_MS);
}

/**
 * Subscribe to the live coverage map. Returns null until the first
 * fetch resolves; consumers should treat null as "don't filter yet"
 * to avoid flashing-empty sidebars during initial load.
 */
export function useCoverage(): ServiceCoverageResponse | null {
  const [value, setValue] = useState<ServiceCoverageResponse | null>(cached);

  useEffect(() => {
    subscribers.add(setValue);
    ensurePolling();
    if (!cached || Date.now() - lastFetchAt > REFRESH_MS) {
      void refresh().catch(() => {});
    }
    return () => {
      subscribers.delete(setValue);
    };
  }, []);

  return value;
}

/**
 * Slug helper — normalises an `href` (e.g. "/iocs", "/cases/123")
 * to the slug coverage map keys use ("iocs", "cases").
 */
export function slugForHref(href: string): string {
  const stripped = (href || "").replace(/^\/+/, "");
  return stripped.split(/[\/?#]/)[0]?.toLowerCase() || "";
}

/**
 * True if the named page should render. Returns true while coverage
 * is loading (avoids flicker) and for UI-only pages with no producing
 * services in the inventory (slug not present in the map at all).
 *
 * Pages explicitly mapped to `false` are hidden — at least one
 * configured source must produce them before they appear.
 */
export function isPageCovered(
  coverage: ServiceCoverageResponse | null,
  href: string,
): boolean {
  if (!coverage) return true;
  const slug = slugForHref(href);
  if (!slug) return true;
  if (!(slug in coverage.pages)) return true;
  return coverage.pages[slug] === true;
}
