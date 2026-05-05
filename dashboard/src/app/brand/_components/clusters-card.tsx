"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Network } from "lucide-react";

import { api, type BrandSuspectCluster } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Section } from "@/components/shared/page-primitives";

import { useBrandContext } from "./use-brand-context";


const SIGNAL_LABEL: Record<string, string> = {
  nameserver: "Shared nameserver",
  ip: "Shared IP",
  matched_term: "Same brand term",
};


/** Campaign-clustering view (T92 / T93).
 *
 *  Surfaces patterns where multiple suspects share a registrant
 *  signal — usually evidence of a single bad actor running a brand
 *  phishing campaign. Clicking a cluster filters the suspects list
 *  back down to its members.
 */
export function ClustersCard({
  onPickCluster,
}: {
  onPickCluster?: (cluster: BrandSuspectCluster) => void;
}) {
  const { orgId, refreshKey } = useBrandContext();
  const { toast } = useToast();
  const [clusters, setClusters] = useState<BrandSuspectCluster[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const res = await api.brand.listSuspectClusters(orgId, 2);
      setClusters(res.clusters);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load clusters",
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
          <Network className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
          <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
            Campaign clusters
          </h3>
        </div>
        <span style={{ fontSize: 11, color: "var(--color-muted)" }}>
          {loading ? "—" : `${clusters.length} cluster${clusters.length === 1 ? "" : "s"}`}
        </span>
      </div>
      {loading ? (
        <div
          className="text-center py-6 text-[12px]"
          style={{ color: "var(--color-muted)" }}
        >
          Loading…
        </div>
      ) : clusters.length === 0 ? (
        <div
          className="text-center py-6 text-[12px]"
          style={{ color: "var(--color-muted)" }}
        >
          No campaign clusters detected. Open suspects don&apos;t share
          nameservers, IPs, or matched-terms in groups of 2+ yet.
        </div>
      ) : (
        <ul
          style={{
            listStyle: "none",
            margin: 0,
            padding: 8,
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: 8,
          }}
        >
          {clusters.map((c) => (
            <li
              key={`${c.signal_kind}:${c.signal_value}`}
              style={{
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                background: "var(--color-canvas)",
                padding: "10px 12px",
                cursor: onPickCluster ? "pointer" : "default",
              }}
              onClick={() => onPickCluster?.(c)}
            >
              <div
                className="flex items-center justify-between"
                style={{ marginBottom: 4 }}
              >
                <span
                  style={{
                    fontSize: 9.5,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--color-muted)",
                  }}
                >
                  {SIGNAL_LABEL[c.signal_kind] || c.signal_kind}
                </span>
                <span
                  style={{
                    fontFamily: "monospace",
                    fontSize: 12,
                    fontWeight: 700,
                    color:
                      c.max_similarity >= 0.9
                        ? "#B71D18"
                        : c.max_similarity >= 0.75
                          ? "#B76E00"
                          : "var(--color-body)",
                  }}
                >
                  {Math.round(c.max_similarity * 100)}%
                </span>
              </div>
              <div
                style={{
                  fontFamily: "monospace",
                  fontSize: 12.5,
                  color: "var(--color-ink)",
                  wordBreak: "break-all",
                  marginBottom: 4,
                }}
              >
                {c.signal_value}
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: "var(--color-body)",
                  marginBottom: 4,
                }}
              >
                <strong style={{ color: "var(--color-ink)" }}>{c.count}</strong>{" "}
                suspect{c.count === 1 ? "" : "s"}
              </div>
              <div
                style={{
                  fontSize: 10.5,
                  color: "var(--color-muted)",
                  fontFamily: "monospace",
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 4,
                }}
              >
                {c.sample_domains.slice(0, 3).map((d, idx) => (
                  <Link
                    key={d + idx}
                    href={`/brand?tab=suspects&id=${c.sample_suspect_ids[idx]}`}
                    onClick={(e) => e.stopPropagation()}
                    style={{
                      color: "var(--color-accent)",
                      textDecoration: "none",
                    }}
                  >
                    {d}
                  </Link>
                ))}
                {c.count > 3 ? (
                  <span style={{ color: "var(--color-muted)" }}>
                    +{c.count - 3} more
                  </span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
