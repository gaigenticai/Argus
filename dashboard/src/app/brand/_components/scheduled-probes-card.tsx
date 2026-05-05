"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Calendar, Clock, ExternalLink } from "lucide-react";

import { api, type BrandScheduledProbe } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Section } from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";

import { useBrandContext } from "./use-brand-context";


/** Re-probe scheduler queue (T80 / T88).
 *
 *  Read-only view of which open suspects are due for the next live
 *  probe and why. The cadence is computed server-side per suspect
 *  (never probed → immediately; suspicious/unreachable → weekly;
 *  benign/parked → 7d then 30d, then settle).
 *
 *  The actual re-probing happens in the worker tick — this card just
 *  surfaces the queue so analysts know what's coming.
 */
export function ScheduledProbesCard() {
  const { orgId, refreshKey } = useBrandContext();
  const { toast } = useToast();
  const [queue, setQueue] = useState<BrandScheduledProbe[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const q = await api.brand.listScheduledProbes(orgId, 50);
      setQueue(q);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load scheduled probes",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  return (
    <Section>
      <div
        className="px-4 py-3 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
          <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
            Re-probe queue
          </h3>
        </div>
        <span style={{ fontSize: 11, color: "var(--color-muted)" }}>
          {loading ? "—" : `${queue.length} due`}
        </span>
      </div>
      {loading ? (
        <div
          className="text-center py-6 text-[12px]"
          style={{ color: "var(--color-muted)" }}
        >
          Loading…
        </div>
      ) : queue.length === 0 ? (
        <div
          className="text-center py-6 text-[12px]"
          style={{ color: "var(--color-muted)" }}
        >
          No re-probes due. The worker re-checks open suspects on a 7d/30d
          cadence based on previous verdict.
        </div>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          {queue.map((p) => (
            <li
              key={p.suspect_id}
              className="flex items-center gap-3 px-3 py-2"
              style={{
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                background: "var(--color-canvas)",
              }}
            >
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 11,
                  color:
                    p.similarity >= 0.9
                      ? "#B71D18"
                      : p.similarity >= 0.75
                        ? "#B76E00"
                        : "var(--color-body)",
                  fontWeight: 700,
                  width: 44,
                  flexShrink: 0,
                }}
              >
                {Math.round(p.similarity * 100)}%
              </span>
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 12.5,
                  color: "var(--color-ink)",
                  fontWeight: 500,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  flex: 1,
                  minWidth: 0,
                }}
              >
                {p.domain}
              </span>
              <span
                style={{ fontSize: 11, color: "var(--color-muted)" }}
                title={`Last probed: ${
                  p.last_probed_at ? timeAgo(p.last_probed_at) : "never"
                } · Verdict: ${p.last_verdict || "—"}`}
              >
                <Clock className="inline-block w-3 h-3 mr-1" />
                {p.reason}
              </span>
              <Link
                href={`/brand?tab=suspects&id=${p.suspect_id}`}
                style={{
                  color: "var(--color-accent)",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 3,
                  fontSize: 11,
                }}
              >
                <ExternalLink className="w-3 h-3" />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
