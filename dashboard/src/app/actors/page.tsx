"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { RefreshCw, Search, Shield } from "lucide-react";
import { api, type ThreatActor } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate, timeAgo } from "@/lib/utils";

function riskColor(score: number): { bar: string; text: string } {
  if (score >= 0.8) return { bar: "#FF5630", text: "#B71D18" };
  if (score >= 0.6) return { bar: "#FFAB00", text: "#B76E00" };
  if (score >= 0.4) return { bar: "#00BBD9", text: "#007B8A" };
  return { bar: "var(--color-muted)", text: "var(--color-muted)" };
}

export default function ActorsPage() {
  const { toast } = useToast();
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getActors({ search: search || undefined, limit, offset });
      setActors(data);
      setTotal(data.length === limit ? offset + limit + 1 : offset + data.length);
    } catch {
      toast("error", "Failed to load threat actors");
    }
    setLoading(false);
  }, [search, offset, toast]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const btnSecondary = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-body)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Threat Actors</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {total} tracked actors
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
          style={btnSecondary}
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Search */}
      <div className="relative w-full max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--color-muted)" }} />
        <input
          type="text"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
          placeholder="Search by alias, description..."
          className="w-full h-10 pl-10 pr-3 text-[13px] outline-none transition-colors"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        />
      </div>

      {/* Actor cards */}
      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div
            className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
        </div>
      ) : actors.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
          <Shield className="w-8 h-8 mb-2" style={{ color: "var(--color-border)" }} />
          <p className="text-[13px]">No threat actors found</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {actors.map((actor) => {
            const risk = riskColor(actor.risk_score);
            return (
              <Link
                key={actor.id}
                href={`/actors/${actor.id}`}
                className="p-6 transition-colors group"
                style={{
                  background: "var(--color-canvas)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "5px",
                  display: "block",
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--color-border-strong)")}
                onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--color-border)")}
              >
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3
                      className="text-[14px] font-semibold transition-colors"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {actor.primary_alias}
                    </h3>
                    {actor.aliases.length > 0 && (
                      <p className="text-[12px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                        aka {actor.aliases.slice(0, 3).join(", ")}
                        {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
                      </p>
                    )}
                  </div>
                  <div className="text-right">
                    <span className="text-[20px] font-bold" style={{ color: risk.text }}>
                      {Math.round(actor.risk_score * 100)}
                    </span>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Risk</p>
                  </div>
                </div>

                {/* Risk bar */}
                <div
                  className="w-full h-1.5 rounded-full overflow-hidden mb-4"
                  style={{ background: "var(--color-surface-muted)" }}
                >
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${actor.risk_score * 100}%`, backgroundColor: risk.bar }}
                  />
                </div>

                {/* Platforms */}
                {actor.forums_active.length > 0 && (
                  <div className="flex gap-1 flex-wrap mb-3">
                    {actor.forums_active.slice(0, 4).map((platform) => (
                      <span
                        key={platform}
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                        style={{ borderRadius: "4px", background: "rgba(0,187,217,0.08)", color: "#007B8A" }}
                      >
                        {platform}
                      </span>
                    ))}
                    {actor.forums_active.length > 4 && (
                      <span
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold items-center"
                        style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-muted)" }}
                      >
                        +{actor.forums_active.length - 4}
                      </span>
                    )}
                  </div>
                )}

                {/* Languages */}
                {actor.languages.length > 0 && (
                  <div className="flex gap-1 flex-wrap mb-3">
                    {actor.languages.map((lang) => (
                      <span
                        key={lang}
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                        style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                      >
                        {lang}
                      </span>
                    ))}
                  </div>
                )}

                {/* Footer stats */}
                <div
                  className="flex items-center justify-between pt-3"
                  style={{ borderTop: "1px solid var(--color-border)" }}
                >
                  <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                    {actor.total_sightings} sightings
                  </span>
                  <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                    Last seen {timeAgo(actor.last_seen)}
                  </span>
                </div>
              </Link>
            );
          })}
        </div>
      )}

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
  );
}
