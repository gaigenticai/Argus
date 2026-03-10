"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { RefreshCw, Search, Shield } from "lucide-react";
import { api, type ThreatActor } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate, timeAgo } from "@/lib/utils";

function riskColor(score: number): { bar: string; text: string } {
  if (score >= 0.8) return { bar: "bg-error", text: "text-error-dark" };
  if (score >= 0.6) return { bar: "bg-warning", text: "text-warning-dark" };
  if (score >= 0.4) return { bar: "bg-info", text: "text-info-dark" };
  return { bar: "bg-grey-400", text: "text-grey-600" };
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
      const data = await api.getActors({
        search: search || undefined,
        limit,
        offset,
      });
      // Backend returns a plain array
      setActors(data);
      setTotal(data.length === limit ? offset + limit + 1 : offset + data.length);
    } catch {
      toast("error", "Failed to load threat actors");
    }
    setLoading(false);
  }, [search, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Threat Actors</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            {total} tracked actors
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Search */}
      <div className="relative w-full max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-grey-400" />
        <input
          type="text"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
          placeholder="Search by alias, description..."
          className="w-full h-10 pl-10 pr-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
        />
      </div>

      {/* Actor cards */}
      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : actors.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
          <Shield className="w-8 h-8 mb-2 text-grey-400" />
          <p className="text-[14px]">No threat actors found</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {actors.map((actor) => {
            const risk = riskColor(actor.risk_score);
            return (
              <Link
                key={actor.id}
                href={`/actors/${actor.id}`}
                className="bg-white rounded-xl border border-grey-200 p-6 hover:shadow-z4 transition-shadow group"
              >
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="text-[15px] font-bold text-grey-900 group-hover:text-primary transition-colors">
                      {actor.primary_alias}
                    </h3>
                    {actor.aliases.length > 0 && (
                      <p className="text-[12px] text-grey-500 mt-0.5">
                        aka {actor.aliases.slice(0, 3).join(", ")}
                        {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
                      </p>
                    )}
                  </div>
                  <div className="text-right">
                    <span className={`text-[20px] font-bold ${risk.text}`}>
                      {Math.round(actor.risk_score * 100)}
                    </span>
                    <p className="text-[10px] font-bold text-grey-400 uppercase tracking-wider">Risk</p>
                  </div>
                </div>

                {/* Risk bar */}
                <div className="w-full h-1.5 bg-grey-200 rounded-full overflow-hidden mb-4">
                  <div
                    className={`h-full rounded-full ${risk.bar}`}
                    style={{ width: `${actor.risk_score * 100}%` }}
                  />
                </div>

                {/* Platforms */}
                {actor.forums_active.length > 0 && (
                  <div className="flex gap-1 flex-wrap mb-3">
                    {actor.forums_active.slice(0, 4).map((platform) => (
                      <span
                        key={platform}
                        className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-secondary-lighter text-secondary-dark"
                      >
                        {platform}
                      </span>
                    ))}
                    {actor.forums_active.length > 4 && (
                      <span className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold items-center bg-grey-200 text-grey-600">
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
                        className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-info-lighter text-info-dark"
                      >
                        {lang}
                      </span>
                    ))}
                  </div>
                )}

                {/* Footer stats */}
                <div className="flex items-center justify-between pt-3 border-t border-grey-100">
                  <span className="text-[12px] text-grey-500">
                    {actor.total_sightings} sightings
                  </span>
                  <span className="text-[12px] text-grey-500">
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
