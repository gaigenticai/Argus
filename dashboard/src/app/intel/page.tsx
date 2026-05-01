"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bug,
  Eye,
  Flame,
  RefreshCw,
  Shield,
} from "lucide-react";
import {
  api,
  type CveResponse,
  type IntelSyncRow,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";

export default function IntelPage() {
  const { toast } = useToast();
  const [cves, setCves] = useState<CveResponse[]>([]);
  const [syncs, setSyncs] = useState<IntelSyncRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [kevOnly, setKevOnly] = useState(false);
  const [severity, setSeverity] = useState("all");
  const [minEpss, setMinEpss] = useState(0);
  const [search, setSearch] = useState("");
  const [syncing, setSyncing] = useState<"nvd" | "epss" | "kev" | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, recent] = await Promise.all([
        api.intel.listCves({
          is_kev: kevOnly || undefined,
          severity: severity === "all" ? undefined : severity,
          min_epss: minEpss || undefined,
          limit: 200,
        }),
        api.intel.listSyncs(10),
      ]);
      setCves(list);
      setSyncs(recent);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load intel",
      );
    } finally {
      setLoading(false);
    }
  }, [kevOnly, severity, minEpss, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    if (!search) return cves;
    const q = search.toUpperCase();
    return cves.filter(
      (c) =>
        c.cve_id.includes(q) ||
        (c.title || "").toUpperCase().includes(q) ||
        (c.description || "").toUpperCase().includes(q),
    );
  }, [cves, search]);

  const stats = useMemo(() => {
    const kev = cves.filter((c) => c.is_kev).length;
    const high = cves.filter(
      (c) => c.cvss_severity === "critical" || c.cvss_severity === "high",
    ).length;
    const exploitable = cves.filter((c) => (c.epss_score || 0) >= 0.5).length;
    return { kev, high, exploitable };
  }, [cves]);

  const sync = async (kind: "nvd" | "epss" | "kev") => {
    setSyncing(kind);
    try {
      const fn =
        kind === "nvd"
          ? api.intel.syncNvd
          : kind === "epss"
          ? api.intel.syncEpss
          : api.intel.syncKev;
      const r = await fn();
      if (r.succeeded) {
        toast(
          "success",
          `${kind.toUpperCase()} sync — ingested ${r.rows_ingested}, updated ${r.rows_updated}`,
        );
      } else {
        toast(
          "error",
          `${kind.toUpperCase()} sync failed: ${r.error || "unknown"}`,
        );
      }
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Sync failed");
    } finally {
      setSyncing(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Eye, label: "Intelligence" }}
        title="CVE / EPSS / KEV"
        description="NVD vulnerability records joined with EPSS exploit-prediction scoring and CISA's KEV catalogue. Workers refresh daily; analyst can trigger a sync inline."
        actions={
          <>
            <button
              onClick={() => sync("nvd")}
              disabled={syncing !== null}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50 transition-colors"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${syncing === "nvd" ? "animate-spin" : ""}`}
              />
              Sync NVD
            </button>
            <button
              onClick={() => sync("epss")}
              disabled={syncing !== null}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50 transition-colors"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${syncing === "epss" ? "animate-spin" : ""}`}
              />
              Sync EPSS
            </button>
            <button
              onClick={() => sync("kev")}
              disabled={syncing !== null}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50 transition-colors"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${syncing === "kev" ? "animate-spin" : ""}`}
              />
              Sync KEV
            </button>
            <RefreshButton onClick={load} refreshing={loading} />
          </>
        }
      />

      {/* Stats */}
      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <div className="grid grid-cols-2 md:grid-cols-4" style={{ borderBottom: "none" }}>
          <Stat
            label="CVEs loaded"
            value={cves.length}
            icon={Bug}
            tone="neutral"
          />
          <Stat
            label="On KEV catalogue"
            value={stats.kev}
            icon={Flame}
            tone={stats.kev > 0 ? "error" : "neutral"}
          />
          <Stat
            label="High / critical"
            value={stats.high}
            icon={AlertTriangle}
            tone={stats.high > 0 ? "warning" : "neutral"}
          />
          <Stat
            label="EPSS ≥ 0.50"
            value={stats.exploitable}
            icon={Shield}
            tone={stats.exploitable > 0 ? "warning" : "neutral"}
          />
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="CVE-… or keyword"
          className="h-10 px-3 w-[260px] text-[12.5px] font-mono outline-none"
          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
        />
        <Select
          ariaLabel="Severity"
          value={severity}
          options={[
            { value: "all", label: "Any severity" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
          onChange={setSeverity}
        />
        <Select
          ariaLabel="EPSS"
          value={String(minEpss)}
          options={[
            { value: "0", label: "Any EPSS" },
            { value: "0.1", label: "EPSS ≥ 0.10" },
            { value: "0.5", label: "EPSS ≥ 0.50" },
            { value: "0.85", label: "EPSS ≥ 0.85" },
          ]}
          onChange={(v) => setMinEpss(Number(v))}
        />
        <button
          onClick={() => setKevOnly((v) => !v)}
          className="flex items-center gap-2 h-10 px-3 text-[12px] font-bold transition-colors"
          style={kevOnly
            ? { borderRadius: "4px", border: "1px solid rgba(255,86,48,0.4)", background: "rgba(255,86,48,0.1)", color: "#B71D18" }
            : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
          }
        >
          <Flame className="w-3.5 h-3.5" />
          KEV ONLY
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* CVE table */}
        <Section className="lg:col-span-2">
          {loading ? (
            <SkeletonRows rows={10} columns={6} />
          ) : filtered.length === 0 ? (
            <Empty
              icon={Bug}
              title="No CVEs match"
              description="Run a sync to load NVD / EPSS / KEV. The worker syncs daily; manual sync above forces an immediate refresh."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                    <Th align="left" className="pl-4 w-[140px]">
                      CVE
                    </Th>
                    <Th align="left">Title</Th>
                    <Th align="left" className="w-[80px]">
                      CVSS
                    </Th>
                    <Th align="left" className="w-[100px]">
                      EPSS
                    </Th>
                    <Th align="left" className="w-[80px]">
                      KEV
                    </Th>
                    <Th align="right" className="pr-4 w-[110px]">
                      Published
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((c) => (
                    <tr
                      key={c.id}
                      className="h-12 transition-colors"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="pl-4">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-[12px] tabular-nums tracking-wide transition-colors"
                          style={{ color: "var(--color-ink)" }}
                          onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                          onMouseLeave={e => (e.currentTarget.style.color = "var(--color-ink)")}
                        >
                          {c.cve_id}
                        </a>
                      </td>
                      <td className="px-3 text-[12.5px] max-w-[420px] truncate" style={{ color: "var(--color-body)" }}>
                        {c.title || c.description || (
                          <span className="italic" style={{ color: "var(--color-muted)" }}>no title</span>
                        )}
                      </td>
                      <td className="px-3">
                        <CvssCell
                          score={c.cvss3_score}
                          severity={c.cvss_severity}
                        />
                      </td>
                      <td className="px-3">
                        <EpssCell
                          score={c.epss_score}
                          percentile={c.epss_percentile}
                        />
                      </td>
                      <td className="px-3">
                        {c.is_kev ? (
                          <StatePill label="KEV" tone="error-strong" />
                        ) : (
                          <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>
                        )}
                      </td>
                      <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                        {c.published_at ? formatDate(c.published_at) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {/* Sync runs */}
        <Section className="lg:col-span-1">
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Recent intel syncs
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Worker tick history with row counts.
            </p>
          </div>
          {syncs.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <p className="text-[12.5px]" style={{ color: "var(--color-muted)" }}>No sync history yet</p>
            </div>
          ) : (
            <ul>
              {syncs.map((s) => (
                <li key={s.id} className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
                      {s.source.toUpperCase()}
                    </span>
                    {s.succeeded ? (
                      <StatePill label="OK" tone="success" />
                    ) : (
                      <StatePill label="FAILED" tone="error-strong" />
                    )}
                  </div>
                  <div className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-body)" }}>
                    +{s.rows_ingested} / Δ{s.rows_updated}
                  </div>
                  <div className="text-[11px] font-mono tabular-nums mt-0.5" style={{ color: "var(--color-muted)" }}>
                    {timeAgo(s.started_at)}
                    {s.error ? (
                      <span style={{ color: "#B71D18" }}> · {s.error}</span>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* NVD attribution — required by NIST API ToS. */}
        <p
          className="text-[11px] mt-2"
          style={{ color: "var(--color-muted)" }}
        >
          This product uses the NVD API but is not endorsed or certified by the NVD.
        </p>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  tone: "neutral" | "warning" | "error";
}) {
  const valueColor =
    tone === "error"
      ? "#FF5630"
      : tone === "warning"
      ? "#B76E00"
      : "var(--color-ink)";
  return (
    <div className="px-4 py-4" style={{ borderRight: "1px solid var(--color-border)" }}>
      <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
        <Icon className="w-3.5 h-3.5" />
        {label}
      </div>
      <div
        className="mt-1.5 font-mono tabular-nums text-[28px] leading-none font-extrabold tracking-[-0.01em]"
        style={{ color: valueColor }}
      >
        {value}
      </div>
    </div>
  );
}

function CvssCell({
  score,
  severity,
}: {
  score: number | null;
  severity: string | null;
}) {
  if (score === null) return <span className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>—</span>;
  const scoreColor =
    score >= 9
      ? "#FF5630"
      : score >= 7
      ? "#B71D18"
      : score >= 4
      ? "#B76E00"
      : "var(--color-body)";
  return (
    <span className="font-mono text-[12px] font-bold tabular-nums" style={{ color: scoreColor }}>
      {score.toFixed(1)}
      {severity ? (
        <span className="ml-1 text-[10px] font-bold tracking-[0.06em] uppercase" style={{ opacity: 0.7 }}>
          {severity.slice(0, 4)}
        </span>
      ) : null}
    </span>
  );
}

function EpssCell({
  score,
  percentile,
}: {
  score: number | null;
  percentile: number | null;
}) {
  if (score === null) {
    return <span className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>—</span>;
  }
  const fillColor =
    score >= 0.85
      ? "#FF5630"
      : score >= 0.5
      ? "#FFAB00"
      : score >= 0.1
      ? "#00BBD9"
      : "var(--color-border)";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
        <div
          className="h-full"
          style={{ width: `${Math.min(100, score * 100)}%`, background: fillColor }}
        />
      </div>
      <span className="font-mono text-[10.5px] tabular-nums" style={{ color: "var(--color-body)" }}>
        {score.toFixed(2)}
      </span>
      {percentile !== null ? (
        <span className="font-mono text-[10px] tabular-nums" style={{ color: "var(--color-muted)" }}>
          p{Math.round(percentile * 100)}
        </span>
      ) : null}
    </div>
  );
}
