"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { RefreshCw, Search, Shield, Download } from "lucide-react";
import { api, type ThreatActor } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

import { SourcesStrip } from "@/components/shared/sources-strip";
import { CoverageGate } from "@/components/shared/coverage-gate";
function riskColor(score: number): { bar: string; text: string } {
  if (score >= 0.8) return { bar: "#FF5630", text: "#B71D18" };
  if (score >= 0.6) return { bar: "#FFAB00", text: "#B76E00" };
  if (score >= 0.4) return { bar: "#00BBD9", text: "#007B8A" };
  return { bar: "var(--color-muted)", text: "var(--color-muted)" };
}

const COUNTRY_FLAGS: Record<string, string> = {
  IR: "🇮🇷", RU: "🇷🇺", CN: "🇨🇳", KP: "🇰🇵", KR: "🇰🇷", UA: "🇺🇦",
  BY: "🇧🇾", SY: "🇸🇾", LB: "🇱🇧", VN: "🇻🇳", PK: "🇵🇰", IN: "🇮🇳",
  TR: "🇹🇷", IL: "🇮🇱", US: "🇺🇸", BR: "🇧🇷",
};

export default function ActorsPage() {
  const { toast } = useToast();
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [country, setCountry] = useState("");
  const [sector, setSector] = useState("");
  const [region, setRegion] = useState("");
  const [technique, setTechnique] = useState("");
  const [hasMitre, setHasMitre] = useState<"any" | "yes" | "no">("any");
  const [offset, setOffset] = useState(0);
  const [importing, setImporting] = useState(false);
  const limit = 60;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getActors({
        search: search || undefined,
        country: country || undefined,
        sector: sector || undefined,
        region: region || undefined,
        technique: technique || undefined,
        has_mitre_id: hasMitre === "any" ? undefined : hasMitre === "yes",
        limit,
        offset,
      });
      setActors(data);
      setTotal(data.length === limit ? offset + limit + 1 : offset + data.length);
    } catch {
      toast("error", "Failed to load threat actors");
    }
    setLoading(false);
  }, [search, country, sector, region, technique, hasMitre, offset, toast]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const btnSecondary = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-body)",
  } as React.CSSProperties;

  const inputStyle = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
  } as React.CSSProperties;

  return (
    <CoverageGate pageSlug="actors" pageLabel="Threat Actors">
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Threat Actors</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {total} tracked actors
          </p>
        </div>
      <SourcesStrip pageKey="actors" />
        <div className="flex gap-2">
          <button
            onClick={async () => {
              setImporting(true);
              try {
                const r = await api.importActorsFromMitre();
                toast("success", `Imported/refreshed ${r.written} actors from MITRE`);
                await load();
              } catch (e) {
                toast("error", `Import failed — ${String(e)}`);
              } finally {
                setImporting(false);
              }
            }}
            disabled={importing}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={{
              borderRadius: "4px",
              background: "var(--color-accent)",
              color: "#fff",
            }}
          >
            {importing ? "Importing…" : "Import from MITRE"}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={btnSecondary}
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-2">
        <div className="relative md:col-span-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--color-muted)" }} />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
            placeholder="Search alias or description…"
            className="w-full h-10 pl-10 pr-3 text-[13px]"
            style={inputStyle}
          />
        </div>
        <input
          type="text"
          value={country}
          onChange={(e) => { setCountry(e.target.value); setOffset(0); }}
          placeholder="Country (e.g. IR)"
          maxLength={3}
          className="h-10 px-3 text-[13px]"
          style={inputStyle}
        />
        <input
          type="text"
          value={sector}
          onChange={(e) => { setSector(e.target.value); setOffset(0); }}
          placeholder="Sector (e.g. energy)"
          className="h-10 px-3 text-[13px]"
          style={inputStyle}
        />
        <input
          type="text"
          value={region}
          onChange={(e) => { setRegion(e.target.value); setOffset(0); }}
          placeholder="Region (e.g. MENA)"
          className="h-10 px-3 text-[13px]"
          style={inputStyle}
        />
        <input
          type="text"
          value={technique}
          onChange={(e) => { setTechnique(e.target.value); setOffset(0); }}
          placeholder="ATT&CK ID (T1059)"
          className="h-10 px-3 text-[13px] font-mono"
          style={inputStyle}
        />
      </div>
      <div className="flex gap-3 text-[12px]" style={{ color: "var(--color-muted)" }}>
        <span>Filter:</span>
        {(["any", "yes", "no"] as const).map((opt) => (
          <button
            key={opt}
            onClick={() => { setHasMitre(opt); setOffset(0); }}
            className="font-semibold"
            style={{ color: hasMitre === opt ? "var(--color-accent)" : "var(--color-muted)" }}
          >
            {opt === "any" ? "All actors" : opt === "yes" ? "MITRE-linked only" : "Org-discovered only"}
          </button>
        ))}
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
            const flags = (actor.country_codes || []).map(
              (c) => COUNTRY_FLAGS[c.toUpperCase()] || c.toUpperCase(),
            );
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
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3
                        className="text-[14px] font-semibold transition-colors"
                        style={{ color: "var(--color-ink)" }}
                      >
                        {actor.primary_alias}
                      </h3>
                      {actor.mitre_group_id && (
                        <span
                          className="text-[10px] font-bold px-1.5 h-[18px] inline-flex items-center"
                          style={{
                            borderRadius: "3px",
                            background: "rgba(0,124,90,0.10)",
                            color: "#1B5E20",
                            border: "1px solid rgba(0,124,90,0.25)",
                          }}
                        >
                          {actor.mitre_group_id}
                        </span>
                      )}
                      {flags.length > 0 && (
                        <span className="text-[14px]" title={(actor.country_codes || []).join(", ")}>
                          {flags.slice(0, 3).join(" ")}
                        </span>
                      )}
                    </div>
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
                  className="w-full h-1.5 rounded-full overflow-hidden mb-3"
                  style={{ background: "var(--color-surface-muted)" }}
                >
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${actor.risk_score * 100}%`, backgroundColor: risk.bar }}
                  />
                </div>

                {/* Sectors / regions */}
                {(actor.sectors_targeted || []).length > 0 && (
                  <div className="flex gap-1 flex-wrap mb-2">
                    {(actor.sectors_targeted || []).slice(0, 4).map((s) => (
                      <span
                        key={s}
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                        style={{ borderRadius: "4px", background: "rgba(255,79,0,0.08)", color: "var(--color-accent)" }}
                      >
                        {s}
                      </span>
                    ))}
                    {(actor.sectors_targeted || []).length > 4 && (
                      <span
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold items-center"
                        style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-muted)" }}
                      >
                        +{(actor.sectors_targeted || []).length - 4}
                      </span>
                    )}
                  </div>
                )}
                {(actor.malware_families || []).length > 0 && (
                  <div className="text-[11px] mb-2" style={{ color: "var(--color-muted)" }}>
                    <span className="font-semibold">Malware:</span>{" "}
                    {(actor.malware_families || []).slice(0, 3).join(", ")}
                    {(actor.malware_families || []).length > 3 && ` +${(actor.malware_families || []).length - 3}`}
                  </div>
                )}

                {/* Footer stats */}
                <div
                  className="flex items-center justify-between pt-3"
                  style={{ borderTop: "1px solid var(--color-border)" }}
                >
                  <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                    {actor.known_ttps.length} TTPs · {actor.total_sightings} sightings
                  </span>
                  <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                    {timeAgo(actor.last_seen)}
                  </span>
                </div>
                <div
                  className="flex justify-end mt-2"
                  onClick={(e) => { e.preventDefault(); }}
                >
                  <button
                    onClick={async (e) => {
                      e.preventDefault();
                      try {
                        const stix = await api.exportActorStix(actor.id);
                        const blob = new Blob([JSON.stringify(stix, null, 2)], { type: "application/json" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${actor.primary_alias.replace(/[^A-Za-z0-9]+/g, "_")}.stix.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                      } catch (err) {
                        toast("error", `STIX export failed — ${String(err)}`);
                      }
                    }}
                    className="inline-flex items-center gap-1 text-[11px] font-semibold"
                    style={{ color: "var(--color-accent)" }}
                  >
                    <Download className="w-3 h-3" />
                    STIX
                  </button>
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
      </CoverageGate>
  );
}
