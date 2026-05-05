"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronRight,
  Clock,
  Flame,
  Globe,
  Layers,
  Network,
  RefreshCw,
  Scan,
  Sparkles,
  Shield,
} from "lucide-react";
import {
  api,
  type Org,
  type SurfaceAsset,
  type SurfaceAssetDetail,
  type SurfaceAssetExposure,
  type SurfaceChange,
  type SurfaceStats,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Select } from "@/components/shared/select";
import { timeAgo } from "@/lib/utils";

interface SubdomainResult {
  subdomain: string;
  ip: string | null;
}

interface ScanResults {
  discovered: number;
  subdomains: SubdomainResult[];
  scan_status?: "ok" | "partial" | "failed";
  errors?: string[];
  domains_scanned?: string[];
}

type TabKey = "assets" | "changes";

const TLS_GRADE_COLOR: Record<string, string> = {
  A: "#1e8e3e",
  B: "#0091FF",
  C: "#B76E00",
  F: "#B71D18",
};

const RISK_TONE = (v: number | null): string => {
  if (v === null) return "var(--color-muted)";
  if (v >= 70) return "#FF5630";
  if (v >= 50) return "#B76E00";
  if (v >= 30) return "#0091FF";
  return "var(--color-body)";
};

const CRIT_TONE: Record<string, string> = {
  crown_jewel: "#B71D18",
  high: "#FF8A65",
  medium: "#0091FF",
  low: "var(--color-muted)",
};

export default function SurfacePage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>("");
  const [tab, setTab] = useState<TabKey>("assets");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [stats, setStats] = useState<SurfaceStats | null>(null);
  const [assets, setAssets] = useState<SurfaceAsset[]>([]);
  const [changes, setChanges] = useState<SurfaceChange[]>([]);
  const [loading, setLoading] = useState(true);
  const [recomputing, setRecomputing] = useState(false);
  const [classifying, setClassifying] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [parentFilter, setParentFilter] = useState<{
    id: string;
    label: string;
  } | null>(null);
  const [filters, setFilters] = useState({
    has_kev: false,
    has_open_exposures: false,
    accessible_only: false,
    weak_tls_only: false,
    q: "",
  });
  const [sort, setSort] = useState<"risk" | "last_seen" | "discovered" | "value">("risk");
  const { toast } = useToast();

  // Load orgs.
  useEffect(() => {
    (async () => {
      try {
        const o = await api.getOrgs();
        setOrgs(o);
        if (o.length > 0) setSelectedOrg(o[0].id);
      } catch {
        toast("error", "Failed to load organizations");
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadAll = useCallback(
    async (orgId: string) => {
      if (!orgId) return;
      try {
        const [s, a, c] = await Promise.all([
          api.surface.stats(orgId),
          api.surface.listAssets({
            organization_id: orgId,
            sort,
            has_kev: filters.has_kev || undefined,
            has_open_exposures: filters.has_open_exposures || undefined,
            accessible_only: filters.accessible_only || undefined,
            weak_tls_only: filters.weak_tls_only || undefined,
            q: filters.q || undefined,
            parent_asset_id: parentFilter?.id,
            limit: 200,
          }),
          api.surface.listChanges({
            organization_id: orgId,
            since_days: 30,
            limit: 200,
          }),
        ]);
        setStats(s);
        setAssets(a);
        setChanges(c);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load surface data",
        );
      }
    },
    [sort, filters, parentFilter, toast],
  );

  useEffect(() => {
    if (selectedOrg) {
      loadAll(selectedOrg);
      setScanResults(null);
    }
  }, [selectedOrg, loadAll]);

  const selectedOrgData = orgs.find((o) => o.id === selectedOrg);

  async function handleScanSubdomains() {
    if (!selectedOrg) return;
    setScanning(true);
    setScanResults(null);
    try {
      const res = (await api.scanSubdomains(selectedOrg)) as ScanResults;
      setScanResults(res);
      if (res.scan_status === "failed") {
        toast("error", "Subdomain scan failed");
      } else if (res.scan_status === "partial") {
        toast(
          "info",
          `Discovered ${res.discovered} — partial result, some sources failed`,
        );
      } else {
        toast("success", `Discovered ${res.discovered} subdomain(s)`);
      }
      await loadAll(selectedOrg);
    } catch {
      toast("error", "Subdomain scan failed");
    } finally {
      setScanning(false);
    }
  }

  async function handleRecomputeRisk() {
    if (!selectedOrg || recomputing) return;
    setRecomputing(true);
    try {
      const r = await api.surface.recomputeRisk(selectedOrg);
      toast("success", `Re-scored ${r.updated}/${r.total_assets} assets`);
      await loadAll(selectedOrg);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Risk recompute failed",
      );
    } finally {
      setRecomputing(false);
    }
  }

  async function handleClassify() {
    if (!selectedOrg || classifying) return;
    setClassifying(true);
    try {
      const r = await api.surface.classify(selectedOrg, { use_llm: true });
      toast(
        "success",
        `Classified ${r.classified} assets (${r.llm_used} via LLM, ${r.llm_failed} fallback)`,
      );
      await loadAll(selectedOrg);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Classifier failed",
      );
    } finally {
      setClassifying(false);
    }
  }

  const cardStyle = {
    background: "var(--color-canvas)",
    border: "1px solid var(--color-border)",
    borderRadius: "5px",
  } as React.CSSProperties;

  const filterCount = useMemo(
    () =>
      [
        filters.has_kev,
        filters.has_open_exposures,
        filters.accessible_only,
        filters.weak_tls_only,
        filters.q !== "",
      ].filter(Boolean).length,
    [filters],
  );

  return (
    <div className="space-y-6">
      <div>
        <h2
          className="text-[24px] font-medium tracking-[-0.02em]"
          style={{ color: "var(--color-ink)" }}
        >
          Attack surface
        </h2>
        <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          Discover, fingerprint and risk-score every public-facing asset
        </p>
      </div>

      {/* Org + actions */}
      <div className="flex gap-2 items-center flex-wrap">
        <Select
          value={selectedOrg}
          onChange={setSelectedOrg}
          ariaLabel="Organization"
          options={orgs.map((o) => ({ value: o.id, label: o.name }))}
        />
        <button
          onClick={handleScanSubdomains}
          disabled={scanning || !selectedOrg}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-accent)",
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
          }}
        >
          <Scan className="w-4 h-4" />
          {scanning ? "Scanning…" : "Discover subdomains"}
        </button>
        <button
          onClick={handleRecomputeRisk}
          disabled={recomputing || !selectedOrg}
          className="flex items-center gap-2 h-9 px-3 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
          title="Recompute risk_score for every asset"
        >
          <RefreshCw className={`w-4 h-4 ${recomputing ? "animate-spin" : ""}`} />
          {recomputing ? "Scoring…" : "Re-score risk"}
        </button>
        <button
          onClick={handleClassify}
          disabled={classifying || !selectedOrg}
          className="flex items-center gap-2 h-9 px-3 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
          title="Run AI classifier (env / role / tags)"
        >
          <Sparkles className="w-4 h-4" />
          {classifying ? "Classifying…" : "AI classify"}
        </button>
      </div>

      {/* KPI strip */}
      {stats ? <SurfaceStatsStrip stats={stats} cardStyle={cardStyle} /> : null}

      {/* Tabs */}
      <div
        className="flex gap-0 border-b"
        style={{ borderColor: "var(--color-border)" }}
        role="tablist"
      >
        {([
          ["assets", `Assets (${assets.length})`, Network],
          ["changes", `Changes (${changes.length})`, Clock],
        ] as const).map(([k, label, Icon]) => {
          const active = tab === k;
          return (
            <button
              key={k}
              role="tab"
              onClick={() => setTab(k)}
              className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors"
              style={{
                color: active ? "var(--color-ink)" : "var(--color-muted)",
                borderBottom: active
                  ? "2px solid var(--color-accent)"
                  : "2px solid transparent",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          );
        })}
      </div>

      {tab === "assets" && (
        <>
          {parentFilter ? (
            <div
              className="flex items-center gap-2 text-[12px]"
              style={{
                padding: "8px 12px",
                background: "var(--color-surface-muted)",
                borderRadius: "5px",
              }}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>
                Showing direct children of{" "}
                <strong style={{ fontFamily: "monospace" }}>
                  {parentFilter.label}
                </strong>
              </span>
              <button
                onClick={() => setParentFilter(null)}
                style={{
                  marginLeft: "auto",
                  fontSize: "11px",
                  fontWeight: 700,
                  color: "var(--color-accent)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                Clear parent filter
              </button>
            </div>
          ) : null}
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={filters.q}
              onChange={(e) =>
                setFilters((f) => ({ ...f, q: e.target.value }))
              }
              placeholder="Search hostname…"
              style={{
                width: "260px",
                height: "36px",
                padding: "0 12px",
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
                fontSize: "13px",
                outline: "none",
              }}
            />
            <FilterChip
              label="KEV-linked"
              icon={Flame}
              active={filters.has_kev}
              onClick={() =>
                setFilters((f) => ({ ...f, has_kev: !f.has_kev }))
              }
            />
            <FilterChip
              label="Has open exposures"
              icon={Shield}
              active={filters.has_open_exposures}
              onClick={() =>
                setFilters((f) => ({
                  ...f,
                  has_open_exposures: !f.has_open_exposures,
                }))
              }
            />
            <FilterChip
              label="Accessible (2xx)"
              icon={Globe}
              active={filters.accessible_only}
              onClick={() =>
                setFilters((f) => ({
                  ...f,
                  accessible_only: !f.accessible_only,
                }))
              }
            />
            <FilterChip
              label="Weak TLS"
              icon={AlertTriangle}
              active={filters.weak_tls_only}
              onClick={() =>
                setFilters((f) => ({
                  ...f,
                  weak_tls_only: !f.weak_tls_only,
                }))
              }
            />
            <Select
              value={sort}
              onChange={(v) => setSort(v as typeof sort)}
              ariaLabel="Sort"
              options={[
                { value: "risk", label: "Risk score" },
                { value: "last_seen", label: "Last scanned" },
                { value: "discovered", label: "Discovered" },
                { value: "value", label: "Hostname" },
              ]}
            />
            {filterCount > 0 ? (
              <button
                onClick={() =>
                  setFilters({
                    has_kev: false,
                    has_open_exposures: false,
                    accessible_only: false,
                    weak_tls_only: false,
                    q: "",
                  })
                }
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "var(--color-muted)",
                  padding: "0 8px",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                Clear ({filterCount})
              </button>
            ) : null}
          </div>

          {/* Assets table */}
          {loading ? (
            <div className="p-12 text-center text-[13px]" style={cardStyle}>
              Loading…
            </div>
          ) : assets.length === 0 ? (
            <div
              className="p-12 flex flex-col items-center justify-center text-center"
              style={cardStyle}
            >
              <Network
                className="w-10 h-10 mb-3"
                style={{ color: "var(--color-border)" }}
              />
              <h3
                className="text-[14px] font-semibold mb-1"
                style={{ color: "var(--color-ink)" }}
              >
                No assets match these filters
              </h3>
              <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>
                Run discover-subdomains or relax the filters.
              </p>
            </div>
          ) : (
            <div style={cardStyle} className="overflow-hidden">
              <AssetsTable
                rows={assets}
                onSelect={(id) => setSelected(id)}
                onDrillChildren={(a) =>
                  setParentFilter({ id: a.id, label: a.value })
                }
              />
            </div>
          )}
        </>
      )}

      {tab === "changes" && (
        <ChangesTimeline rows={changes} cardStyle={cardStyle} />
      )}

      {/* Scan-status banner */}
      {scanResults && scanResults.scan_status && scanResults.scan_status !== "ok" ? (
        <div
          role="alert"
          className="flex items-start gap-3 px-4 py-3"
          style={{
            borderRadius: "5px",
            border:
              scanResults.scan_status === "failed"
                ? "1px solid rgba(255,86,48,0.4)"
                : "1px solid rgba(255,171,0,0.4)",
            background:
              scanResults.scan_status === "failed"
                ? "rgba(255,86,48,0.06)"
                : "rgba(255,171,0,0.06)",
          }}
        >
          <AlertTriangle
            className="w-5 h-5 mt-0.5 shrink-0"
            style={{
              color:
                scanResults.scan_status === "failed" ? "#B71D18" : "#B76E00",
            }}
          />
          <div className="flex-1 min-w-0">
            <p
              className="text-[13px] font-semibold"
              style={{
                color:
                  scanResults.scan_status === "failed" ? "#B71D18" : "#B76E00",
              }}
            >
              {scanResults.scan_status === "failed"
                ? "Scan failed — passive sources unreachable"
                : "Partial result — some sources failed"}
            </p>
            {scanResults.errors && scanResults.errors.length > 0 ? (
              <ul className="mt-2 space-y-0.5">
                {scanResults.errors.slice(0, 6).map((e, i) => (
                  <li
                    key={i}
                    className="text-[11.5px] font-mono truncate"
                    style={{ color: "var(--color-muted)" }}
                  >
                    · {e}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </div>
      ) : null}

      {selectedOrgData ? (
        <p className="text-[10.5px]" style={{ color: "var(--color-muted)" }}>
          Org · {selectedOrgData.name} · domains {selectedOrgData.domains?.join(", ") || "—"}
        </p>
      ) : null}

      {selected ? (
        <SurfaceAssetDrawer
          assetId={selected}
          onClose={() => setSelected(null)}
        />
      ) : null}
    </div>
  );
}

// ----------------------------------------------------------------------

function FilterChip({
  label,
  icon: Icon,
  active,
  onClick,
}: {
  label: string;
  icon: typeof Flame;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "36px",
        padding: "0 10px",
        borderRadius: "4px",
        border: active
          ? "1px solid var(--color-accent)"
          : "1px solid var(--color-border)",
        background: active ? "rgba(255,86,48,0.06)" : "var(--color-canvas)",
        color: active ? "var(--color-accent)" : "var(--color-body)",
        fontSize: "12px",
        fontWeight: 700,
        cursor: "pointer",
      }}
    >
      <Icon style={{ width: "13px", height: "13px" }} />
      {label}
    </button>
  );
}

function SurfaceStatsStrip({
  stats,
  cardStyle,
}: {
  stats: SurfaceStats;
  cardStyle: React.CSSProperties;
}) {
  const cell = (label: string, value: React.ReactNode, hint?: string) => (
    <div className="p-4" style={cardStyle}>
      <div
        className="text-[10px] font-semibold uppercase tracking-[0.08em] mb-1"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <div
        className="text-[22px] font-bold"
        style={{ color: "var(--color-ink)" }}
      >
        {value}
      </div>
      {hint ? (
        <div
          className="text-[11px] mt-0.5"
          style={{ color: "var(--color-muted)" }}
        >
          {hint}
        </div>
      ) : null}
    </div>
  );
  const totalByType = Object.entries(stats.by_type)
    .map(([k, v]) => `${k}:${v}`)
    .join(" · ");
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {cell("Assets", stats.total_assets, totalByType || "—")}
      {cell(
        "Risk avg",
        stats.avg_risk_score !== null ? stats.avg_risk_score.toFixed(1) : "—",
        stats.top_risk_score !== null
          ? `top ${stats.top_risk_score.toFixed(1)}`
          : undefined,
      )}
      {cell(
        "Open exposures",
        stats.open_exposures,
        stats.kev_exposures > 0 ? `${stats.kev_exposures} on KEV` : undefined,
      )}
      {cell(
        "Accessible (2xx)",
        stats.accessible_count,
        stats.auth_gated_count > 0
          ? `${stats.auth_gated_count} auth-gated`
          : undefined,
      )}
      {cell("Weak TLS", stats.weak_tls_count)}
    </div>
  );
}

// ---- Assets table ----------------------------------------------------

function AssetsTable({
  rows,
  onSelect,
  onDrillChildren,
}: {
  rows: SurfaceAsset[];
  onSelect: (id: string) => void;
  onDrillChildren: (a: SurfaceAsset) => void;
}) {
  const th =
    "text-left h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.08em]";
  return (
    <table className="w-full">
      <thead>
        <tr
          style={{
            background: "var(--color-surface-muted)",
            borderBottom: "1px solid var(--color-border)",
          }}
        >
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Risk
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Asset
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Class
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            HTTP
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Ports
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            TLS
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Tech
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Exposures
          </th>
          <th className={th} style={{ color: "var(--color-muted)" }}>
            Last seen
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((a) => (
          <AssetRow
            key={a.id}
            a={a}
            onSelect={() => onSelect(a.id)}
            onDrillChildren={() => onDrillChildren(a)}
          />
        ))}
      </tbody>
    </table>
  );
}

function AssetRow({
  a,
  onSelect,
  onDrillChildren,
}: {
  a: SurfaceAsset;
  onSelect: () => void;
  onDrillChildren: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <tr
      onClick={onSelect}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "52px",
        borderBottom: "1px solid var(--color-surface-muted)",
        background: hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="px-3">
        <RiskCell value={a.risk_score} />
      </td>
      <td className="px-3">
        <div className="flex items-center gap-2">
          <span
            style={{
              fontFamily: "monospace",
              fontSize: "13px",
              fontWeight: 600,
              color: "var(--color-ink)",
            }}
            className="truncate max-w-[280px]"
          >
            {a.value}
          </span>
          {a.is_active ? null : (
            <span
              className="inline-flex items-center h-[16px] px-1.5"
              style={{
                fontSize: "9px",
                fontWeight: 700,
                background: "var(--color-surface-muted)",
                color: "var(--color-muted)",
                borderRadius: "3px",
              }}
            >
              INACTIVE
            </span>
          )}
        </div>
        <div
          className="text-[10.5px] mt-0.5"
          style={{ color: "var(--color-muted)" }}
        >
          {a.asset_type}
          {a.criticality ? (
            <>
              {" · "}
              <span
                style={{
                  color: CRIT_TONE[a.criticality] || "var(--color-muted)",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                }}
              >
                {a.criticality.replace("_", " ")}
              </span>
            </>
          ) : null}
        </div>
      </td>
      <td className="px-3">
        <ClassificationCell c={a.ai_classification} />
      </td>
      <td className="px-3">
        <HttpCell sc={a.http_status_code} title={a.http_title} />
      </td>
      <td className="px-3">
        <PortsCell ports={a.ports} />
      </td>
      <td className="px-3">
        <TlsCell grade={a.tls_grade} counts={a.tls_issue_counts} />
      </td>
      <td className="px-3">
        <TechCell tech={a.http_tech} />
      </td>
      <td className="px-3">
        <ExposureCell open={a.open_exposures} kev={a.kev_exposures} />
        {a.children_count > 0 ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDrillChildren();
            }}
            title={`Show ${a.children_count} direct children`}
            style={{
              fontSize: "10px",
              fontFamily: "monospace",
              color: "var(--color-accent)",
              fontWeight: 700,
              border: "none",
              background: "none",
              padding: 0,
              marginTop: "2px",
              cursor: "pointer",
              display: "block",
            }}
          >
            ↳ {a.children_count} children
          </button>
        ) : null}
      </td>
      <td
        className="px-3"
        style={{
          fontFamily: "monospace",
          fontSize: "11.5px",
          color: "var(--color-muted)",
        }}
      >
        {a.last_scanned_at ? timeAgo(a.last_scanned_at) : "never"}
      </td>
    </tr>
  );
}

function RiskCell({ value }: { value: number | null }) {
  if (value === null) {
    return (
      <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>
    );
  }
  const v = Math.round(value);
  const tone = RISK_TONE(value);
  return (
    <div className="flex items-center gap-2">
      <span
        style={{
          fontFamily: "monospace",
          fontSize: "13px",
          fontWeight: 700,
          color: tone,
          minWidth: "26px",
        }}
      >
        {v}
      </span>
      <div
        style={{
          flex: 1,
          height: "3px",
          minWidth: "26px",
          maxWidth: "44px",
          background: "var(--color-border)",
          borderRadius: "2px",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            bottom: 0,
            width: `${v}%`,
            background: tone,
          }}
        />
      </div>
    </div>
  );
}

function ClassificationCell({
  c,
}: {
  c: SurfaceAsset["ai_classification"];
}) {
  if (!c) return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  return (
    <div
      title={c.rationale}
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "2px",
      }}
    >
      <span
        style={{
          fontSize: "10.5px",
          fontWeight: 700,
          letterSpacing: "0.04em",
          textTransform: "uppercase",
          color:
            c.environment === "prod"
              ? "var(--color-ink)"
              : c.environment === "internal"
              ? "#B71D18"
              : "var(--color-body)",
        }}
      >
        {c.environment} · {c.role}
      </span>
      {c.tags.length > 0 ? (
        <span
          style={{
            fontSize: "10px",
            color: "var(--color-muted)",
            fontFamily: "monospace",
          }}
          className="truncate max-w-[160px]"
        >
          {c.tags.slice(0, 2).join(", ")}
          {c.tags.length > 2 ? ` +${c.tags.length - 2}` : ""}
        </span>
      ) : null}
    </div>
  );
}

function HttpCell({ sc, title }: { sc: number | null; title: string | null }) {
  if (!sc)
    return (
      <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>
    );
  const color =
    sc >= 200 && sc < 300
      ? "#1e8e3e"
      : sc >= 300 && sc < 400
      ? "#0091FF"
      : sc === 401 || sc === 403
      ? "#B76E00"
      : sc >= 400 && sc < 500
      ? "var(--color-muted)"
      : "#B71D18";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
      <span
        style={{
          fontFamily: "monospace",
          fontSize: "12px",
          fontWeight: 700,
          color,
        }}
      >
        {sc}
      </span>
      {title ? (
        <span
          style={{
            fontSize: "10px",
            color: "var(--color-muted)",
          }}
          className="truncate max-w-[140px]"
        >
          {title}
        </span>
      ) : null}
    </div>
  );
}

function PortsCell({
  ports,
}: {
  ports: SurfaceAsset["ports"];
}) {
  if (!ports || ports.length === 0)
    return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  const display = ports.slice(0, 4).map((p) => p.port).join(", ");
  return (
    <span
      title={ports.map((p) => `${p.port}/${p.protocol}`).join(", ")}
      style={{
        fontFamily: "monospace",
        fontSize: "11.5px",
        color: "var(--color-body)",
      }}
    >
      {display}
      {ports.length > 4 ? ` +${ports.length - 4}` : ""}
    </span>
  );
}

function TlsCell({
  grade,
  counts,
}: {
  grade: string | null;
  counts: SurfaceAsset["tls_issue_counts"];
}) {
  if (!grade)
    return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  const c = TLS_GRADE_COLOR[grade] || "var(--color-body)";
  const tip = counts
    ? Object.entries(counts)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" · ")
    : undefined;
  return (
    <span
      title={tip}
      style={{
        display: "inline-flex",
        alignItems: "center",
        height: "20px",
        padding: "0 6px",
        borderRadius: "4px",
        background: `${c}15`,
        color: c,
        fontSize: "11px",
        fontWeight: 700,
        fontFamily: "monospace",
      }}
    >
      {grade}
    </span>
  );
}

function TechCell({ tech }: { tech: string[] }) {
  if (!tech || tech.length === 0)
    return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  return (
    <span
      title={tech.join(", ")}
      className="truncate max-w-[180px] inline-block"
      style={{
        fontSize: "11px",
        color: "var(--color-body)",
      }}
    >
      {tech.slice(0, 3).join(", ")}
      {tech.length > 3 ? ` +${tech.length - 3}` : ""}
    </span>
  );
}

function ExposureCell({ open, kev }: { open: number; kev: number }) {
  if (open === 0)
    return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  return (
    <div className="flex items-center gap-1.5">
      <span
        style={{
          fontFamily: "monospace",
          fontSize: "12px",
          fontWeight: 700,
          color: "var(--color-ink)",
        }}
      >
        {open}
      </span>
      {kev > 0 ? (
        <span
          title={`${kev} KEV-listed`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "2px",
            height: "16px",
            padding: "0 4px",
            background: "rgba(255,86,48,0.12)",
            color: "#B71D18",
            fontSize: "9px",
            fontWeight: 800,
            borderRadius: "3px",
          }}
        >
          <Flame style={{ width: "8px", height: "8px" }} />
          {kev}
        </span>
      ) : null}
    </div>
  );
}

// ---- Changes timeline ------------------------------------------------

const CHANGE_KIND_LABEL: Record<string, string> = {
  asset_created: "New asset",
  asset_revived: "Asset revived",
  asset_inactive: "Asset went inactive",
  port_opened: "Port opened",
  port_closed: "Port closed",
  service_banner_changed: "Service banner changed",
  http_status_changed: "HTTP status changed",
  http_title_changed: "HTTP title changed",
  http_tech_changed: "Tech stack changed",
  tls_cert_changed: "TLS cert rotated",
  tls_expiry_near: "TLS expiry approaching",
  dns_a_changed: "DNS A changed",
  dns_mx_changed: "DNS MX changed",
  dns_ns_changed: "DNS NS changed",
  spf_changed: "SPF changed",
  dkim_changed: "DKIM changed",
  dmarc_changed: "DMARC changed",
  whois_registrar_changed: "Registrar changed",
  whois_expiry_near: "WHOIS expiry approaching",
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "#B71D18",
  high: "#FF5630",
  medium: "#B76E00",
  low: "#0091FF",
  info: "var(--color-muted)",
};

function ChangesTimeline({
  rows,
  cardStyle,
}: {
  rows: SurfaceChange[];
  cardStyle: React.CSSProperties;
}) {
  if (rows.length === 0) {
    return (
      <div
        className="p-12 flex flex-col items-center justify-center text-center"
        style={cardStyle}
      >
        <Clock
          className="w-10 h-10 mb-3"
          style={{ color: "var(--color-border)" }}
        />
        <h3
          className="text-[14px] font-semibold mb-1"
          style={{ color: "var(--color-ink)" }}
        >
          No changes detected in the last 30 days
        </h3>
        <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>
          Run a discovery sweep — we surface every drift the workers
          observe (port toggles, TLS rotations, DNS edits, tech changes…).
        </p>
      </div>
    );
  }
  return (
    <div style={cardStyle} className="overflow-hidden">
      <ul>
        {rows.map((c) => {
          const tone = SEVERITY_TONE[c.severity] || "var(--color-muted)";
          return (
            <li
              key={c.id}
              className="flex items-start gap-3 px-4 py-3"
              style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
            >
              <div
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: tone,
                  marginTop: "6px",
                  flexShrink: 0,
                }}
              />
              <div className="flex-1 min-w-0">
                <div
                  className="text-[12.5px] font-semibold"
                  style={{ color: "var(--color-ink)" }}
                >
                  {c.summary}
                </div>
                <div
                  className="text-[11px] mt-0.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  <span
                    style={{
                      color: tone,
                      fontWeight: 700,
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {c.severity}
                  </span>
                  {" · "}
                  <span style={{ fontFamily: "monospace" }}>
                    {CHANGE_KIND_LABEL[c.kind] || c.kind}
                  </span>
                  {c.asset_value ? (
                    <>
                      {" · "}
                      <span style={{ fontFamily: "monospace" }}>
                        {c.asset_value}
                      </span>
                    </>
                  ) : null}
                  {" · "}
                  {timeAgo(c.detected_at)}
                </div>
                {c.before || c.after ? (
                  <details className="mt-1">
                    <summary
                      className="text-[10.5px] cursor-pointer"
                      style={{ color: "var(--color-muted)" }}
                    >
                      diff
                    </summary>
                    <pre
                      className="text-[10.5px] mt-1 p-2"
                      style={{
                        background: "var(--color-surface-muted)",
                        color: "var(--color-body)",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                        borderRadius: "3px",
                        fontFamily: "monospace",
                      }}
                    >
                      {`before: ${JSON.stringify(c.before)}\nafter:  ${JSON.stringify(c.after)}`}
                    </pre>
                  </details>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ---- Detail drawer ---------------------------------------------------

function SurfaceAssetDrawer({
  assetId,
  onClose,
}: {
  assetId: string;
  onClose: () => void;
}) {
  const [data, setData] = useState<SurfaceAssetDetail | null>(null);
  const [exposures, setExposures] = useState<SurfaceAssetExposure[]>([]);
  const [changes, setChanges] = useState<SurfaceChange[]>([]);
  const [tab, setTab] = useState<
    "overview" | "exposures" | "changes" | "screenshot" | "raw"
  >("overview");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const [d, e] = await Promise.all([
          api.surface.getAsset(assetId),
          api.surface.listAssetExposures(assetId),
        ]);
        setData(d);
        setExposures(e);
        // Changes — fetch from the per-asset filter on /surface/changes.
        const c = await api.surface.listChanges({
          organization_id: d.organization_id,
          asset_id: d.id,
          since_days: 90,
          limit: 100,
        });
        setChanges(c);
      } finally {
        setLoading(false);
      }
    })();
  }, [assetId]);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{
        background: "rgba(32,21,21,0.4)",
        backdropFilter: "blur(2px)",
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--color-canvas)",
          width: "100%",
          maxWidth: "780px",
          height: "100%",
          overflowY: "auto",
        }}
        onClick={(ev) => ev.stopPropagation()}
        role="dialog"
      >
        {loading || !data ? (
          <div className="p-8 text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading asset…
          </div>
        ) : (
          <>
            <div
              className="px-6 py-5 sticky top-0 z-10 flex items-start justify-between gap-3"
              style={{
                borderBottom: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
              }}
            >
              <div className="min-w-0">
                <div
                  className="text-[10.5px] uppercase tracking-[0.08em] mb-0.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  {data.asset_type}
                  {data.parent_value ? (
                    <>
                      {" "}
                      <ChevronRight className="inline w-3 h-3" />
                      <span style={{ fontFamily: "monospace" }}>
                        {data.parent_value}
                      </span>
                    </>
                  ) : null}
                </div>
                <h2
                  style={{
                    fontSize: "18px",
                    fontWeight: 700,
                    color: "var(--color-ink)",
                    fontFamily: "monospace",
                    wordBreak: "break-all",
                  }}
                >
                  {data.value}
                </h2>
                <div className="flex items-center gap-2 mt-1">
                  <RiskCell value={data.risk_score} />
                  {data.ai_classification ? (
                    <span
                      title={data.ai_classification.rationale}
                      style={{
                        fontSize: "10.5px",
                        fontWeight: 700,
                        letterSpacing: "0.04em",
                        textTransform: "uppercase",
                        color: "var(--color-body)",
                        padding: "1px 6px",
                        background: "var(--color-surface-muted)",
                        borderRadius: "3px",
                      }}
                    >
                      {data.ai_classification.environment} ·{" "}
                      {data.ai_classification.role}
                    </span>
                  ) : null}
                </div>
              </div>
              <button
                onClick={onClose}
                style={{
                  height: "32px",
                  width: "32px",
                  borderRadius: "4px",
                  border: "none",
                  background: "none",
                  color: "var(--color-body)",
                  cursor: "pointer",
                  fontSize: "18px",
                }}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div
              className="flex border-b"
              style={{ borderColor: "var(--color-border)" }}
            >
              {([
                ["overview", "Overview"],
                ["exposures", `Exposures (${exposures.length})`],
                ["changes", `Changes (${changes.length})`],
                ["screenshot", "Screenshot"],
                ["raw", "Raw"],
              ] as const).map(([k, label]) => {
                const active = tab === k;
                return (
                  <button
                    key={k}
                    onClick={() => setTab(k)}
                    className="h-9 px-4 text-[12px] font-semibold"
                    style={{
                      color: active
                        ? "var(--color-ink)"
                        : "var(--color-muted)",
                      borderBottom: active
                        ? "2px solid var(--color-accent)"
                        : "2px solid transparent",
                    }}
                  >
                    {label}
                  </button>
                );
              })}
            </div>

            <div className="p-6 space-y-5">
              {tab === "overview" ? (
                <DrawerOverview data={data} />
              ) : tab === "exposures" ? (
                <DrawerExposures rows={exposures} />
              ) : tab === "changes" ? (
                <ChangesTimeline
                  rows={changes}
                  cardStyle={{
                    background: "var(--color-canvas)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "5px",
                  }}
                />
              ) : tab === "screenshot" ? (
                <DrawerScreenshot data={data} />
              ) : (
                <DrawerRaw data={data} />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function DrawerOverview({ data }: { data: SurfaceAssetDetail }) {
  const details = (data.details as Record<string, unknown>) || {};
  const http = (details.http as Record<string, unknown>) || {};
  const tls = (details.tls as Record<string, unknown>) || {};
  const dns =
    ((details.dns_detail as Record<string, unknown>) ||
      (details.dns as Record<string, unknown>)) ?? {};
  const ports = (details.ports as Array<{ port: number; protocol: string }>) || [];
  const screenshot = (details.screenshot as Record<string, unknown>) || {};

  const Field = ({
    label,
    children,
  }: {
    label: string;
    children: React.ReactNode;
  }) => (
    <div>
      <div
        style={{
          fontSize: "10px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "var(--color-muted)",
          marginBottom: "4px",
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
        {children}
      </div>
    </div>
  );

  return (
    <>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Discovered">
          {data.discovered_at ? timeAgo(data.discovered_at) : "—"}
          <span
            style={{
              marginLeft: "6px",
              fontSize: "10px",
              color: "var(--color-muted)",
            }}
          >
            via {data.discovery_method}
          </span>
        </Field>
        <Field label="Last scanned">
          {data.last_scanned_at ? timeAgo(data.last_scanned_at) : "—"}
        </Field>
        <Field label="Criticality">
          <span
            style={{
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color: CRIT_TONE[data.criticality] || "var(--color-body)",
            }}
          >
            {data.criticality.replace("_", " ")}
          </span>
        </Field>
        <Field label="Open exposures">
          <span style={{ fontFamily: "monospace", fontWeight: 700 }}>
            {data.open_exposures}
          </span>
          {data.kev_exposures > 0 ? (
            <span style={{ marginLeft: "6px", color: "#B71D18", fontWeight: 700 }}>
              · {data.kev_exposures} KEV
            </span>
          ) : null}
        </Field>
      </div>

      {data.ai_classification ? (
        <div
          style={{
            padding: "12px 14px",
            background: "var(--color-surface-muted)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div
            className="text-[10px] uppercase tracking-[0.08em] font-bold"
            style={{ color: "var(--color-muted)" }}
          >
            AI classification ({data.ai_classification.source})
          </div>
          <div
            className="text-[12.5px] mt-1"
            style={{ color: "var(--color-ink)" }}
          >
            <strong>{data.ai_classification.environment}</strong> ·{" "}
            <strong>{data.ai_classification.role}</strong>
            {data.ai_classification.tags.length > 0 ? (
              <span
                style={{
                  marginLeft: "8px",
                  color: "var(--color-muted)",
                  fontFamily: "monospace",
                  fontSize: "11.5px",
                }}
              >
                {data.ai_classification.tags.join(" · ")}
              </span>
            ) : null}
          </div>
          <div
            className="text-[11px] mt-1"
            style={{ color: "var(--color-muted)" }}
          >
            confidence {data.ai_classification.confidence.toFixed(2)} —{" "}
            {data.ai_classification.rationale}
          </div>
        </div>
      ) : null}

      {http && Object.keys(http).length > 0 ? (
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.08em] font-bold mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            HTTP probe
          </div>
          <div className="grid grid-cols-2 gap-3 text-[12px]">
            <div>
              status:{" "}
              <span style={{ fontFamily: "monospace", fontWeight: 700 }}>
                {String(http.status_code ?? "—")}
              </span>
            </div>
            <div>
              title:{" "}
              <span
                style={{
                  fontFamily: "monospace",
                  color: "var(--color-body)",
                }}
              >
                {String(http.title ?? "—")}
              </span>
            </div>
            <div className="col-span-2">
              tech:{" "}
              {Array.isArray(http.tech) && (http.tech as string[]).length > 0
                ? (http.tech as string[]).join(", ")
                : "—"}
            </div>
            <div className="col-span-2">
              IPs:{" "}
              {Array.isArray(http.ips) && (http.ips as string[]).length > 0
                ? (http.ips as string[]).join(", ")
                : "—"}
            </div>
          </div>
        </div>
      ) : null}

      {ports.length > 0 ? (
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.08em] font-bold mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Open ports ({ports.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {ports.map((p, i) => (
              <span
                key={`${p.port}-${i}`}
                style={{
                  fontSize: "11px",
                  fontFamily: "monospace",
                  padding: "2px 6px",
                  background: "var(--color-surface-muted)",
                  borderRadius: "3px",
                  color: "var(--color-body)",
                }}
              >
                {p.port}/{p.protocol}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {tls && Object.keys(tls).length > 0 ? (
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.08em] font-bold mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            TLS posture
          </div>
          <div className="text-[12px]" style={{ color: "var(--color-body)" }}>
            grade:{" "}
            <strong style={{ color: TLS_GRADE_COLOR[tls.grade as string] || "var(--color-body)" }}>
              {String(tls.grade ?? "—")}
            </strong>
            {tls.issue_counts ? (
              <span
                style={{
                  marginLeft: "8px",
                  color: "var(--color-muted)",
                  fontFamily: "monospace",
                  fontSize: "11px",
                }}
              >
                {Object.entries(tls.issue_counts as Record<string, number>)
                  .map(([k, v]) => `${k}:${v}`)
                  .join(" · ")}
              </span>
            ) : null}
          </div>
        </div>
      ) : null}

      {dns && Object.keys(dns).length > 0 ? (
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.08em] font-bold mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            DNS
          </div>
          <div
            className="text-[11.5px] font-mono"
            style={{ color: "var(--color-body)" }}
          >
            {Object.entries(dns)
              .filter(([_, v]) => v && (Array.isArray(v) ? v.length > 0 : true))
              .slice(0, 8)
              .map(([k, v]) => (
                <div key={k}>
                  <strong>{k}:</strong>{" "}
                  {Array.isArray(v) ? (v as string[]).join(", ") : String(v)}
                </div>
              ))}
          </div>
        </div>
      ) : null}

      {screenshot.captured_at ? (
        <div
          className="text-[11px]"
          style={{ color: "var(--color-muted)" }}
        >
          Screenshot captured {timeAgo(screenshot.captured_at as string)} —
          see "Screenshot" tab.
        </div>
      ) : null}
    </>
  );
}

function DrawerExposures({ rows }: { rows: SurfaceAssetExposure[] }) {
  if (rows.length === 0) {
    return (
      <p
        className="text-[12.5px]"
        style={{ color: "var(--color-muted)" }}
      >
        No exposures recorded for this asset yet.
      </p>
    );
  }
  return (
    <ul className="space-y-2">
      {rows.map((e) => (
        <li
          key={e.id}
          className="flex items-start gap-3 p-3"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div
            style={{
              width: "3px",
              alignSelf: "stretch",
              background: SEVERITY_TONE[e.severity] || "var(--color-border)",
              marginRight: "4px",
            }}
          />
          <div className="flex-1 min-w-0">
            <div
              className="text-[12.5px] font-semibold"
              style={{ color: "var(--color-ink)" }}
            >
              {e.title}
            </div>
            <div
              className="text-[10.5px] mt-1 flex flex-wrap gap-2"
              style={{ color: "var(--color-muted)" }}
            >
              <span
                style={{
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  fontWeight: 700,
                  color: SEVERITY_TONE[e.severity] || "var(--color-muted)",
                }}
              >
                {e.severity}
              </span>
              {e.is_kev ? (
                <span
                  style={{
                    color: "#B71D18",
                    fontWeight: 700,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "2px",
                  }}
                >
                  <Flame className="w-2.5 h-2.5" />
                  KEV
                </span>
              ) : null}
              {e.cvss_score !== null ? (
                <span style={{ fontFamily: "monospace" }}>
                  CVSS {e.cvss_score.toFixed(1)}
                </span>
              ) : null}
              {e.epss_score !== null ? (
                <span style={{ fontFamily: "monospace" }}>
                  EPSS {(e.epss_score * 100).toFixed(0)}%
                </span>
              ) : null}
              {e.ai_priority !== null ? (
                <span
                  style={{
                    fontFamily: "monospace",
                    color: "var(--color-accent)",
                    fontWeight: 700,
                  }}
                >
                  AI {Math.round(e.ai_priority)}/100
                </span>
              ) : null}
              {e.cve_ids.length > 0 ? (
                <span style={{ fontFamily: "monospace" }}>
                  {e.cve_ids.slice(0, 2).join(", ")}
                  {e.cve_ids.length > 2 ? ` +${e.cve_ids.length - 2}` : ""}
                </span>
              ) : null}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function DrawerScreenshot({ data }: { data: SurfaceAssetDetail }) {
  const screenshot = (data.details as Record<string, unknown>)?.screenshot as
    | Record<string, unknown>
    | undefined;
  if (!screenshot || !screenshot.data_url) {
    return (
      <p
        className="text-[12.5px]"
        style={{ color: "var(--color-muted)" }}
      >
        No screenshot captured yet — gowitness needs to be installed in the
        worker image. Trigger a SCREENSHOT discovery job manually if the binary
        is available.
      </p>
    );
  }
  return (
    <div>
      <img
        src={screenshot.data_url as string}
        alt={`Screenshot of ${data.value}`}
        style={{
          maxWidth: "100%",
          borderRadius: "5px",
          border: "1px solid var(--color-border)",
        }}
      />
      <p
        className="text-[10.5px] mt-2"
        style={{ color: "var(--color-muted)" }}
      >
        Captured {screenshot.captured_at ? timeAgo(screenshot.captured_at as string) : "—"}
        {" · "}
        {screenshot.size_bytes
          ? `${Math.round((screenshot.size_bytes as number) / 1024)} KB`
          : "size unknown"}
      </p>
    </div>
  );
}

function DrawerRaw({ data }: { data: SurfaceAssetDetail }) {
  return (
    <pre
      style={{
        fontSize: "11px",
        fontFamily: "monospace",
        color: "var(--color-body)",
        background: "var(--color-surface-muted)",
        padding: "12px",
        borderRadius: "5px",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
        maxHeight: "60vh",
        overflowY: "auto",
      }}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}
