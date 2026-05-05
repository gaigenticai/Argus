"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ClipboardList,
  Network,
  RefreshCw,
  Sparkles,
  TrendingUp,
  Workflow,
} from "lucide-react";
import {
  api,
  type AssetRecord,
  type Org,
  type TprmExecDashboard,
  type TprmOnboardingResponse,
  type TprmQuestion,
  type TprmScorecardResponse,
  type TprmTemplateCreatePayload,
  type TprmTemplateResponse,
  type VendorOnboardingStage,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { Select as ThemedSelect } from "@/components/shared/select";

interface TprmCtx {
  orgs: Org[];
  orgId: string;
  setOrgId: (id: string) => void;
  refresh: () => void;
}
const Ctx = createContext<TprmCtx | null>(null);

const TABS = [
  { id: "exec", label: "Executive", icon: TrendingUp },
  { id: "scorecards", label: "Scorecards", icon: TrendingUp },
  { id: "onboarding", label: "Vendor onboarding", icon: Workflow },
  { id: "templates", label: "Questionnaires", icon: BookOpen },
] as const;
type TabId = (typeof TABS)[number]["id"];

const STAGE_TONE: Record<VendorOnboardingStage, StateTone> = {
  invited: "neutral",
  questionnaire_sent: "info",
  questionnaire_received: "info",
  analyst_review: "warning",
  approved: "success",
  rejected: "error-strong",
  on_hold: "muted",
};
const STAGE_LABEL: Record<VendorOnboardingStage, string> = {
  invited: "INVITED",
  questionnaire_sent: "Q SENT",
  questionnaire_received: "Q RECEIVED",
  analyst_review: "REVIEW",
  approved: "APPROVED",
  rejected: "REJECTED",
  on_hold: "ON HOLD",
};

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

export default function TprmPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window === "undefined") return "scorecards";
    const h = window.location.hash.replace("#", "");
    return (TABS.find((t) => t.id === h)?.id || "scorecards") as TabId;
  });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted = localStorage.getItem("argus_org_id");
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgIdState(initial);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load organizations",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    localStorage.setItem("argus_org_id", id);
  }, []);

  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  const switchTab = (raw: string) => {
    const next = (TABS.find((t) => t.id === raw)?.id || "scorecards") as TabId;
    setTab(next);
    const url = new URL(window.location.href);
    url.hash = next === "scorecards" ? "" : next;
    window.history.replaceState(null, "", url.toString());
  };

  return (
    <Ctx.Provider value={{ orgs, orgId, setOrgId, refresh }}>
      <div className="space-y-6">
        <PageHeader
          eyebrow={{ icon: Network, label: "Brand & Surface" }}
          title="Third-Party Risk"
          description="Per-vendor security ratings, questionnaire workflows, and onboarding decisions. Scorecards mix the EASM exposure surface scoped to each vendor's primary domain with the questionnaire pillar."
          actions={
            <>
              <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
              <RefreshButton onClick={refresh} refreshing={false} />
            </>
          }
        />

        <div className="flex items-center gap-1 -mx-1 overflow-x-auto" style={{ borderBottom: "1px solid var(--color-border)" }}>
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => switchTab(t.id)}
                className="relative h-10 px-3.5 flex items-center gap-2 text-[13px] font-bold whitespace-nowrap transition-colors"
                style={{
                  color: active ? "var(--color-ink)" : "var(--color-muted)",
                  boxShadow: active ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
                }}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>

        <div key={`${orgId}-${tab}-${refreshKey}`}>
          {tab === "exec" && <ExecDashboardTab />}
          {tab === "scorecards" && <ScorecardsTab />}
          {tab === "onboarding" && <OnboardingTab />}
          {tab === "templates" && <TemplatesTab />}
        </div>
      </div>
    </Ctx.Provider>
  );
}

function useTprm() {
  const c = useContext(Ctx);
  if (!c) throw new Error("Tprm context missing");
  return c;
}

// ─── Executive dashboard tab ─────────────────────────────────────────

function ExecDashboardTab() {
  const { orgId } = useTprm();
  const { toast } = useToast();
  const [data, setData] = useState<TprmExecDashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const r = await api.tprm.execDashboard(orgId);
      setData(r);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load exec dashboard",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const handleQuarterly = async () => {
    if (!orgId || running) return;
    setRunning(true);
    try {
      const r = await api.tprm.quarterlyHealthCheck(orgId, 20);
      toast(
        "success",
        `Recomputed ${r.computed}/${r.vendors_total} · ${r.drops_detected.length} drops detected`,
      );
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Health check failed",
      );
    } finally {
      setRunning(false);
    }
  };

  if (loading || !data) {
    return (
      <div
        className="p-12 text-center text-[13px]"
        style={{
          color: "var(--color-muted)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
          background: "var(--color-canvas)",
        }}
      >
        Loading executive dashboard…
      </div>
    );
  }

  const cardStyle = {
    background: "var(--color-canvas)",
    border: "1px solid var(--color-border)",
    borderRadius: "5px",
  } as React.CSSProperties;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2
          className="text-[16px] font-semibold"
          style={{ color: "var(--color-ink)" }}
        >
          Vendor risk — executive view
        </h2>
        <button
          onClick={handleQuarterly}
          disabled={running}
          className="h-9 px-3 text-[12px] font-semibold disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        >
          {running ? "Running…" : "Run quarterly health check"}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <ExecKpi
          label="Vendors"
          value={data.vendors_total}
          hint={
            data.below_threshold_count > 0
              ? `${data.below_threshold_count} below threshold`
              : "all on or above 70"
          }
          cardStyle={cardStyle}
        />
        <ExecKpi
          label="Avg score"
          value={data.avg_score !== null ? data.avg_score.toFixed(1) : "—"}
          cardStyle={cardStyle}
        />
        <ExecKpi
          label="Compliant %"
          value={`${data.compliant_pct.toFixed(1)}%`}
          hint="≥70 score"
          cardStyle={cardStyle}
        />
        <ExecKpi
          label="By tier"
          value={
            Object.entries(data.by_tier)
              .map(([k, v]) => `${k.replace("tier_", "T")}:${v}`)
              .join(" ") || "—"
          }
          cardStyle={cardStyle}
        />
        <ExecKpi
          label="By grade"
          value={
            Object.entries(data.by_grade)
              .map(([k, v]) => `${k}:${v}`)
              .join(" ") || "—"
          }
          cardStyle={cardStyle}
        />
      </div>

      <div style={cardStyle}>
        <div
          className="px-4 h-11 flex items-center"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3
            className="text-[13px] font-semibold"
            style={{ color: "var(--color-ink)" }}
          >
            Top 10 risk vendors
          </h3>
          <span
            className="ml-2 text-[10.5px]"
            style={{ color: "var(--color-muted)" }}
          >
            sorted by composite score (lowest first)
          </span>
        </div>
        {data.top_risk.length === 0 ? (
          <div
            className="p-6 text-[12.5px]"
            style={{ color: "var(--color-muted)" }}
          >
            No scorecards computed yet — onboard a vendor or hit
            "Recompute" on an existing one.
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr
                style={{
                  background: "var(--color-surface-muted)",
                  borderBottom: "1px solid var(--color-border)",
                }}
              >
                <th className="text-left h-8 px-3 text-[10px] font-bold uppercase tracking-[0.07em]">
                  Vendor
                </th>
                <th className="text-left h-8 px-3 text-[10px] font-bold uppercase tracking-[0.07em]">
                  Tier
                </th>
                <th className="text-left h-8 px-3 text-[10px] font-bold uppercase tracking-[0.07em]">
                  Category
                </th>
                <th className="text-left h-8 px-3 text-[10px] font-bold uppercase tracking-[0.07em]">
                  Score
                </th>
                <th className="text-left h-8 px-3 text-[10px] font-bold uppercase tracking-[0.07em]">
                  Pillars
                </th>
              </tr>
            </thead>
            <tbody>
              {data.top_risk.map((v) => (
                <tr
                  key={v.vendor_id}
                  style={{
                    height: "44px",
                    borderBottom: "1px solid var(--color-surface-muted)",
                  }}
                >
                  <td
                    className="px-3 text-[13px] font-mono"
                    style={{ color: "var(--color-ink)" }}
                  >
                    {v.vendor_value}
                  </td>
                  <td
                    className="px-3 text-[11px] font-mono"
                    style={{ color: "var(--color-body)" }}
                  >
                    {v.tier.replace("tier_", "T")}
                  </td>
                  <td
                    className="px-3 text-[11px]"
                    style={{ color: "var(--color-body)" }}
                  >
                    {v.category.replace(/_/g, " ")}
                  </td>
                  <td className="px-3">
                    <span
                      style={{
                        fontFamily: "monospace",
                        fontSize: "13px",
                        fontWeight: 700,
                        color:
                          v.score >= 80
                            ? "#1e8e3e"
                            : v.score >= 60
                            ? "#B76E00"
                            : "#B71D18",
                      }}
                    >
                      {v.score.toFixed(1)}
                    </span>
                    <span
                      className="ml-2 text-[10px]"
                      style={{ color: "var(--color-muted)" }}
                    >
                      ({v.grade})
                    </span>
                  </td>
                  <td className="px-3">
                    <span
                      className="text-[10.5px] font-mono"
                      style={{ color: "var(--color-muted)" }}
                    >
                      {Object.entries(v.pillar_scores)
                        .map(
                          ([k, s]) =>
                            `${k.slice(0, 3)}:${(s as number).toFixed(0)}`,
                        )
                        .join(" · ")}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ExecKpi({
  label,
  value,
  hint,
  cardStyle,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  cardStyle: React.CSSProperties;
}) {
  return (
    <div className="p-4" style={cardStyle}>
      <div
        className="text-[10px] font-semibold uppercase tracking-[0.08em] mb-1"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <div
        className="text-[20px] font-bold truncate"
        style={{ color: "var(--color-ink)" }}
        title={typeof value === "string" ? value : undefined}
      >
        {value}
      </div>
      {hint ? (
        <div
          className="text-[10.5px] mt-0.5"
          style={{ color: "var(--color-muted)" }}
        >
          {hint}
        </div>
      ) : null}
    </div>
  );
}

// ─── Scorecards tab ─────────────────────────────────────────────────

function ScorecardsTab() {
  const { orgId, refresh } = useTprm();
  const { toast } = useToast();
  const [rows, setRows] = useState<TprmScorecardResponse[]>([]);
  const [vendors, setVendors] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [recomputingId, setRecomputingId] = useState<string | null>(null);
  const [currentOnly, setCurrentOnly] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [{ data }, vs] = await Promise.all([
        api.tprm.listScorecards({
          organization_id: orgId,
          is_current: currentOnly || undefined,
          limit: 200,
        }),
        api.listAssets({
          organization_id: orgId,
          asset_type: "vendor",
          limit: 500,
        }),
      ]);
      setRows(data);
      setVendors(vs);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load scorecards",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, currentOnly, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const recompute = async (vendorId: string) => {
    setRecomputingId(vendorId);
    try {
      await api.tprm.recomputeScorecard(vendorId);
      toast("success", "Scorecard recomputed");
      await load();
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Recompute failed");
    } finally {
      setRecomputingId(null);
    }
  };

  const vendorMap = useMemo(
    () => Object.fromEntries(vendors.map((v) => [v.id, v])),
    [vendors],
  );

  const stats = useMemo(() => {
    const grades: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    for (const r of rows) grades[r.grade] = (grades[r.grade] || 0) + 1;
    const avgScore =
      rows.length === 0
        ? null
        : rows.reduce((s, r) => s + r.score, 0) / rows.length;
    return { grades, avgScore };
  }, [rows]);

  const GRADE_ACCENT: Record<string, string> = {
    A: "#007B55",
    B: "#00BBD9",
    C: "#FFAB00",
    D: "#B76E00",
    F: "#FF5630",
  };

  return (
    <div className="space-y-5">
      {/* Stat strip */}
      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <div className="grid grid-cols-2 md:grid-cols-7">
          <Stat label="Vendors" value={rows.length} />
          <Stat
            label="Avg score"
            value={stats.avgScore !== null ? stats.avgScore.toFixed(0) : "—"}
          />
          {(["A", "B", "C", "D", "F"] as const).map((g) => (
            <Stat
              key={g}
              label={`Grade ${g}`}
              value={stats.grades[g] || 0}
              accentColor={GRADE_ACCENT[g]}
            />
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => setCurrentOnly((v) => !v)}
          className="flex items-center gap-2 h-9 px-3 text-[12px] font-bold transition-colors"
          style={currentOnly
            ? { borderRadius: "4px", border: "1px solid rgba(0,187,217,0.4)", background: "rgba(0,187,217,0.1)", color: "#007B8A" }
            : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
          }
        >
          CURRENT ONLY
          {currentOnly ? <CheckCircle2 className="w-3.5 h-3.5" /> : null}
        </button>
        <p className="text-[12px] ml-auto font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          {rows.length} card{rows.length === 1 ? "" : "s"}
        </p>
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Network}
            title="No vendor scorecards yet"
            description="Add vendor assets in Operations → Onboarding (or via the Asset Registry), then trigger 'Recompute' here. The score blends EASM exposure pressure with questionnaire pillar."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[64px]">
                    Grade
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Score
                  </Th>
                  <Th align="left">Vendor</Th>
                  <Th align="left">Pillar scores</Th>
                  <Th align="left" className="w-[110px]">
                    Computed
                  </Th>
                  <Th align="right" className="pr-4 w-[150px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((sc) => {
                  const v = vendorMap[sc.vendor_asset_id];
                  return (
                    <tr
                      key={sc.id}
                      className="h-14 transition-colors"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="pl-4">
                        <GradePill grade={sc.grade} accentColors={GRADE_ACCENT} />
                      </td>
                      <td className="px-3">
                        <ScoreBar score={sc.score} />
                      </td>
                      <td className="px-3">
                        <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                          {v?.value || (
                            <span className="italic" style={{ color: "var(--color-muted)" }}>
                              vendor missing
                            </span>
                          )}
                        </div>
                        {v?.criticality ? (
                          <div className="text-[10.5px] font-bold uppercase tracking-[0.06em] mt-0.5" style={{ color: "var(--color-muted)" }}>
                            {v.criticality.replace("_", " ")}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-3">
                        <PillarBars scores={sc.pillar_scores} />
                      </td>
                      <td className="px-3 font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                        {timeAgo(sc.computed_at)}
                      </td>
                      <td className="pr-4 text-right">
                        <button
                          onClick={() => recompute(sc.vendor_asset_id)}
                          disabled={recomputingId === sc.vendor_asset_id}
                          className="inline-flex items-center gap-1 h-7 px-2.5 text-[11px] font-bold disabled:opacity-50 transition-colors"
                          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
                        >
                          <RefreshCw
                            className={`w-3 h-3 ${recomputingId === sc.vendor_asset_id ? "animate-spin" : ""}`}
                          />
                          RECOMPUTE
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}

function Stat({
  label,
  value,
  accentColor,
}: {
  label: string;
  value: number | string;
  accentColor?: string;
}) {
  return (
    <div className="px-4 py-4 relative" style={{ borderRight: "1px solid var(--color-border)" }}>
      {accentColor ? (
        <span
          className="absolute left-0 top-3 bottom-3 w-[2px] rounded-r"
          style={{ background: accentColor }}
        />
      ) : null}
      <div className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
        {label}
      </div>
      <div className="mt-1.5 font-mono tabular-nums text-[26px] leading-none font-extrabold tracking-[-0.01em]" style={{ color: "var(--color-ink)" }}>
        {value}
      </div>
    </div>
  );
}

function GradePill({ grade, accentColors }: { grade: string; accentColors: Record<string, string> }) {
  const color = accentColors[grade] || "var(--color-muted)";
  return (
    <span
      className="inline-flex items-center justify-center w-8 h-8 text-[16px] font-extrabold tracking-tight"
      style={{ borderRadius: "6px", border: `2px solid ${color}`, background: `${color}18`, color }}
    >
      {grade}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const pct = Math.max(0, Math.min(100, score));
  const fillColor =
    pct >= 85 ? "#007B55" : pct >= 70 ? "#00BBD9" : pct >= 55 ? "#FFAB00" : pct >= 40 ? "#B76E00" : "#FF5630";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
        <div className="h-full" style={{ width: `${pct}%`, background: fillColor }} />
      </div>
      <span className="font-mono text-[13px] font-bold tabular-nums" style={{ color: "var(--color-ink)" }}>
        {Math.round(pct)}
      </span>
    </div>
  );
}

function PillarBars({ scores }: { scores: Record<string, number> }) {
  const entries = Object.entries(scores);
  if (entries.length === 0) {
    return <span className="text-[11.5px] italic" style={{ color: "var(--color-muted)" }}>empty</span>;
  }
  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-1">
      {entries.slice(0, 6).map(([k, v]) => (
        <div key={k} className="flex items-center gap-1.5" title={`${k}: ${v}`}>
          <span className="text-[10.5px] font-bold uppercase tracking-[0.04em] w-[60px] truncate" style={{ color: "var(--color-body)" }}>
            {k.replace("_", " ")}
          </span>
          <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
            <div
              className="h-full"
              style={{
                width: `${Math.max(0, Math.min(100, v))}%`,
                background: v >= 70 ? "#007B55" : v >= 50 ? "#FFAB00" : "#FF5630",
              }}
            />
          </div>
          <span className="font-mono text-[10.5px] tabular-nums w-[24px] text-right" style={{ color: "var(--color-body)" }}>
            {Math.round(v)}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── Onboarding tab ─────────────────────────────────────────────────

function OnboardingTab() {
  const { orgId, refresh } = useTprm();
  const { toast } = useToast();
  const [rows, setRows] = useState<TprmOnboardingResponse[]>([]);
  const [vendors, setVendors] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showAddVendor, setShowAddVendor] = useState(false);
  const [transitionTarget, setTransitionTarget] =
    useState<TprmOnboardingResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [list, vs] = await Promise.all([
        api.tprm.listOnboarding(orgId),
        api.listAssets({ organization_id: orgId, asset_type: "vendor", limit: 500 }),
      ]);
      setRows(list);
      setVendors(vs);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load workflows",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const vendorMap = useMemo(
    () => Object.fromEntries(vendors.map((v) => [v.id, v])),
    [vendors],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          {rows.length} workflow{rows.length === 1 ? "" : "s"} ·{" "}
          {vendors.length} vendor asset
          {vendors.length === 1 ? "" : "s"}
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddVendor(true)}
            className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
          >
            + Add vendor
          </button>
          <button
            onClick={() => setShowCreate(true)}
            disabled={vendors.length === 0}
            title={
              vendors.length === 0
                ? "Add a vendor first — use the '+ Add vendor' button"
                : "Begin onboarding for one of your vendor assets"
            }
            className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            Begin onboarding
          </button>
        </div>
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={5} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Workflow}
            title="No vendor onboarding in flight"
            description="Begin one for each new vendor. The workflow steps through invited → questionnaire → review → approved/rejected. Reasons are mandatory on terminal stages and feed the audit log."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">
                    Vendor
                  </Th>
                  <Th align="left" className="w-[140px]">
                    Stage
                  </Th>
                  <Th align="left">Notes</Th>
                  <Th align="left" className="w-[120px]">
                    Decided
                  </Th>
                  <Th align="right" className="pr-4 w-[140px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((w) => (
                  <tr
                    key={w.id}
                    className="h-12 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4 text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                      {vendorMap[w.vendor_asset_id]?.value || (
                        <span className="italic" style={{ color: "var(--color-muted)" }}>missing</span>
                      )}
                    </td>
                    <td className="px-3">
                      <StatePill
                        label={STAGE_LABEL[w.stage]}
                        tone={STAGE_TONE[w.stage]}
                      />
                    </td>
                    <td className="px-3 text-[12.5px] line-clamp-1 max-w-[420px]" style={{ color: "var(--color-body)" }}>
                      {w.notes || (
                        <span className="italic" style={{ color: "var(--color-muted)" }}>—</span>
                      )}
                    </td>
                    <td className="px-3 font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {w.decided_at ? timeAgo(w.decided_at) : "—"}
                    </td>
                    <td className="pr-4 text-right">
                      {w.stage !== "approved" && w.stage !== "rejected" ? (
                        <button
                          onClick={() => setTransitionTarget(w)}
                          className="inline-flex items-center gap-1 h-7 px-2.5 text-[11px] font-bold transition-colors"
                          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
                        >
                          ADVANCE
                        </button>
                      ) : (
                        <span className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
                          terminal
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {showAddVendor && orgId ? (
        <AddVendorModal
          orgId={orgId}
          onClose={() => setShowAddVendor(false)}
          onCreated={async () => {
            setShowAddVendor(false);
            await load();
          }}
        />
      ) : null}
      {showCreate && orgId && (
        <BeginOnboardingModal
          orgId={orgId}
          vendors={vendors}
          existingIds={new Set(rows.map((r) => r.vendor_asset_id))}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            refresh();
            load();
          }}
        />
      )}
      {transitionTarget && (
        <TransitionOnboardingModal
          target={transitionTarget}
          onClose={() => setTransitionTarget(null)}
          onDone={() => {
            setTransitionTarget(null);
            refresh();
            load();
          }}
        />
      )}
    </div>
  );
}

function BeginOnboardingModal({
  orgId,
  vendors,
  existingIds,
  onClose,
  onCreated,
}: {
  orgId: string;
  vendors: AssetRecord[];
  existingIds: Set<string>;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const eligible = vendors.filter((v) => !existingIds.has(v.id));
  const [vendorId, setVendorId] = useState<string>(eligible[0]?.id || "");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!vendorId || busy) return;
    setBusy(true);
    try {
      await api.tprm.createOnboarding({
        organization_id: orgId,
        vendor_asset_id: vendorId,
        notes: notes.trim() || undefined,
      });
      toast("success", "Onboarding begun");
      onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <ModalShell title="Begin vendor onboarding" onClose={onClose}>
      <div className="p-6 space-y-5">
        {eligible.length === 0 ? (
          <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
            Every vendor in the registry already has an onboarding workflow.
            Add a new vendor first.
          </p>
        ) : (
          <>
            <Field label="Vendor" required>
              <ThemedSelect
                value={vendorId}
                onChange={setVendorId}
                ariaLabel="Vendor"
                options={eligible.map((v) => ({ value: v.id, label: v.value }))}
                style={{ width: "100%" }}
              />
            </Field>
            <Field label="Notes" hint="Optional context for the workflow.">
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 text-[13px] resize-none"
                style={inputStyle}
                placeholder="e.g. Replacing legacy KYC vendor; target go-live Q3."
              />
            </Field>
          </>
        )}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Creating…" : "Begin"}
        disabled={!vendorId || busy || eligible.length === 0}
      />
    </ModalShell>
  );
}

function TransitionOnboardingModal({
  target,
  onClose,
  onDone,
}: {
  target: TprmOnboardingResponse;
  onClose: () => void;
  onDone: () => void;
}) {
  const { toast } = useToast();
  const stages: VendorOnboardingStage[] = [
    "invited",
    "questionnaire_sent",
    "questionnaire_received",
    "analyst_review",
    "approved",
    "rejected",
    "on_hold",
  ];
  const next = stages.filter((s) => s !== target.stage);
  const [to, setTo] = useState<VendorOnboardingStage>(next[0]);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const requiresReason = ["approved", "rejected", "on_hold"].includes(to);
  const submit = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.tprm.transitionOnboarding(target.id, {
        to_stage: to,
        reason: reason.trim() || undefined,
      });
      toast("success", `Workflow → ${STAGE_LABEL[to]}`);
      onDone();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Transition failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <ModalShell title="Advance workflow" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Next stage" required>
          <div className="grid grid-cols-2 gap-1.5">
            {next.map((s) => {
              const active = to === s;
              return (
                <button
                  key={s}
                  onClick={() => setTo(s)}
                  className="h-10 flex items-center justify-center gap-1.5 transition-all"
                  style={active
                    ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-canvas)", boxShadow: "0 0 0 2px rgba(32,21,21,0.08)" }
                    : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }
                  }
                >
                  <StatePill label={STAGE_LABEL[s]} tone={STAGE_TONE[s]} />
                </button>
              );
            })}
          </div>
        </Field>
        <Field
          label={requiresReason ? "Reason" : "Reason (optional)"}
          required={requiresReason}
          hint={
            requiresReason
              ? "Required for terminal stages — feeds the vendor onboarding audit trail."
              : "Captured on the vendor onboarding audit trail."
          }
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={inputStyle}
            placeholder={
              requiresReason
                ? "Decision rationale and supporting evidence references."
                : "Optional note."
            }
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Saving…" : "Advance"}
        disabled={busy || (requiresReason && !reason.trim())}
      />
    </ModalShell>
  );
}

// ─── Templates tab ──────────────────────────────────────────────────

function TemplatesTab() {
  const { orgId } = useTprm();
  const { toast } = useToast();
  const [rows, setRows] = useState<TprmTemplateResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await api.tprm.listTemplates(orgId));
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load templates",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const seed = async () => {
    if (!orgId) {
      toast("error", "Pick an organization first");
      return;
    }
    setSeeding(true);
    try {
      await api.tprm.seedTemplates(orgId);
      toast("success", "Built-in templates seeded");
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Seed failed");
    } finally {
      setSeeding(false);
    }
  };

  const [creating, setCreating] = useState(false);
  const [previewing, setPreviewing] = useState<TprmTemplateResponse | null>(null);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          {rows.length} template{rows.length === 1 ? "" : "s"}
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCreating(true)}
            className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
          >
            + Build custom questionnaire
          </button>
          {rows.length === 0 ? (
            <button
              onClick={seed}
              disabled={seeding}
              className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold disabled:opacity-50"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
            >
              <Sparkles className="w-3.5 h-3.5" />
              {seeding ? "Seeding…" : "Seed built-in templates"}
            </button>
          ) : null}
        </div>
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={3} columns={4} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ClipboardList}
            title="No questionnaire templates"
            description="Seed the built-ins (SIG-Lite, CAIQ v4) for instant coverage, or build your own from scratch with the question builder. Templates feed onboarding workflows + vendor scorecards."
            action={
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCreating(true)}
                  className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    color: "var(--color-ink)",
                  }}
                >
                  Build custom
                </button>
                <button
                  onClick={seed}
                  disabled={seeding}
                  className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold disabled:opacity-50"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-accent)",
                    background: "var(--color-accent)",
                    color: "var(--color-on-dark)",
                  }}
                >
                  <Sparkles className="w-4 h-4" />
                  Seed built-ins
                </button>
              </div>
            }
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 p-3">
            {rows.map((t) => (
              <TemplateCard
                key={t.id}
                template={t}
                onClick={() => setPreviewing(t)}
              />
            ))}
          </div>
        )}
      </Section>
      {creating ? (
        <CustomQuestionnaireModal
          orgId={orgId}
          onClose={() => setCreating(false)}
          onCreated={async (t) => {
            setCreating(false);
            await load();
            setPreviewing(t);
          }}
        />
      ) : null}
      {previewing ? (
        <TemplatePreviewModal
          template={previewing}
          onClose={() => setPreviewing(null)}
        />
      ) : null}
    </div>
  );
}

function TemplateCard({
  template,
  onClick,
}: {
  template: TprmTemplateResponse;
  onClick?: () => void;
}) {
  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === "Enter" || e.key === " ")) onClick();
      }}
      className="p-4 space-y-3 transition-colors"
      style={{
        borderRadius: "5px",
        border: "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        cursor: onClick ? "pointer" : "default",
      }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--color-border-strong)")}
      onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--color-border)")}
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <h4 className="text-[14px] font-bold leading-tight" style={{ color: "var(--color-ink)" }}>
            {template.name}
          </h4>
          <div className="flex items-center gap-2 mt-1">
            <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
              {template.kind.toUpperCase()}
            </span>
            {template.organization_id ? (
              <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "rgba(255,79,0,0.1)", color: "var(--color-accent)" }}>
                CUSTOM
              </span>
            ) : (
              <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "rgba(0,187,217,0.1)", color: "#007B8A" }}>
                BUILT-IN
              </span>
            )}
          </div>
        </div>
        {template.is_active ? (
          <CheckCircle2 className="w-4 h-4" style={{ color: "#007B55" }} />
        ) : (
          <AlertTriangle className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
        )}
      </div>
      {template.description ? (
        <p className="text-[12px] line-clamp-3" style={{ color: "var(--color-body)" }}>
          {template.description}
        </p>
      ) : null}
      <div className="flex items-center justify-between text-[11px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
        <span>
          {template.questions.length} question
          {template.questions.length === 1 ? "" : "s"}
        </span>
        <span>{timeAgo(template.updated_at)}</span>
      </div>
    </div>
  );
}

// ─── Template preview modal ─────────────────────────────────────────

function TemplatePreviewModal({
  template,
  onClose,
}: {
  template: TprmTemplateResponse;
  onClose: () => void;
}) {
  return (
    <ModalShell title={`Preview · ${template.name}`} onClose={onClose}>
      <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className="inline-flex items-center h-[20px] px-2 text-[10.5px] font-bold tracking-[0.06em]"
            style={{
              borderRadius: "4px",
              background: "var(--color-surface-muted)",
              color: "var(--color-body)",
            }}
          >
            {template.kind.toUpperCase()}
          </span>
          {template.organization_id ? (
            <span
              className="inline-flex items-center h-[20px] px-2 text-[10.5px] font-bold tracking-[0.06em]"
              style={{
                borderRadius: "4px",
                background: "rgba(255,79,0,0.1)",
                color: "var(--color-accent)",
              }}
            >
              CUSTOM
            </span>
          ) : (
            <span
              className="inline-flex items-center h-[20px] px-2 text-[10.5px] font-bold tracking-[0.06em]"
              style={{
                borderRadius: "4px",
                background: "rgba(0,187,217,0.1)",
                color: "#007B8A",
              }}
            >
              BUILT-IN
            </span>
          )}
          <span
            className="text-[11px] font-mono"
            style={{ color: "var(--color-muted)" }}
          >
            {template.questions.length} question
            {template.questions.length === 1 ? "" : "s"} · updated{" "}
            {timeAgo(template.updated_at)}
          </span>
        </div>
        {template.description ? (
          <p
            className="text-[12.5px]"
            style={{ color: "var(--color-body)", lineHeight: 1.6 }}
          >
            {template.description}
          </p>
        ) : null}
        <div className="space-y-2">
          {template.questions.map((q, i) => (
            <div
              key={q.id || i}
              className="p-3"
              style={{
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
                background: "var(--color-surface-muted)",
              }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div
                    className="text-[10.5px] font-mono"
                    style={{ color: "var(--color-muted)" }}
                  >
                    Q{i + 1} · {q.id}
                  </div>
                  <div
                    className="text-[13px] mt-0.5"
                    style={{ color: "var(--color-ink)" }}
                  >
                    {q.text}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span
                    className="inline-flex items-center h-[18px] px-1.5 text-[10px] font-bold tracking-[0.06em]"
                    style={{
                      borderRadius: "3px",
                      background: "var(--color-canvas)",
                      color: "var(--color-body)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    {q.answer_kind}
                  </span>
                  <span
                    className="text-[10.5px] font-mono"
                    style={{ color: "var(--color-muted)" }}
                  >
                    weight {q.weight}
                    {q.required ? " · required" : ""}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={onClose}
        submitLabel="Close"
      />
    </ModalShell>
  );
}

// ─── Custom questionnaire builder ───────────────────────────────────

const ANSWER_KINDS: TprmQuestion["answer_kind"][] = [
  "yes_no",
  "yes_no_na",
  "scale_1_5",
  "free_text",
  "evidence",
];

const ANSWER_KIND_HELP: Record<string, string> = {
  yes_no: "Yes / No",
  yes_no_na: "Yes / No / N/A",
  scale_1_5: "1–5 scale (Likert)",
  free_text: "Free text answer",
  evidence: "Expects an uploaded file (SOC2 PDF, etc.)",
};

function defaultQuestion(idx: number): TprmQuestion {
  return {
    id: `q_${idx}`,
    text: "",
    answer_kind: "yes_no",
    weight: 1,
    required: true,
  };
}

function CustomQuestionnaireModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string;
  onClose: () => void;
  onCreated: (t: TprmTemplateResponse) => void | Promise<void>;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"sig_lite" | "sig_core" | "caiq_v4" | "custom">("custom");
  const [description, setDescription] = useState("");
  const [questions, setQuestions] = useState<TprmQuestion[]>([defaultQuestion(1)]);
  const [busy, setBusy] = useState(false);

  const addQuestion = () => {
    setQuestions((qs) => [...qs, defaultQuestion(qs.length + 1)]);
  };
  const removeQuestion = (i: number) => {
    setQuestions((qs) => qs.filter((_, idx) => idx !== i));
  };
  const updateQuestion = (i: number, patch: Partial<TprmQuestion>) => {
    setQuestions((qs) =>
      qs.map((q, idx) => (idx === i ? { ...q, ...patch } : q)),
    );
  };

  const valid =
    name.trim().length > 0 &&
    questions.length > 0 &&
    questions.every((q) => q.id.trim() && q.text.trim());

  const submit = async () => {
    if (!valid || busy) return;
    if (!orgId) {
      toast("error", "Pick an organization first");
      return;
    }
    setBusy(true);
    try {
      const ids = new Set<string>();
      for (const q of questions) {
        if (ids.has(q.id)) {
          throw new Error(`Duplicate question id: ${q.id}`);
        }
        ids.add(q.id);
      }
      const body: TprmTemplateCreatePayload = {
        organization_id: orgId,
        name: name.trim(),
        kind,
        description: description.trim() || undefined,
        questions,
        is_active: true,
      };
      const tpl = await api.tprm.createTemplate(body);
      toast("success", `Created "${tpl.name}" with ${tpl.questions.length} question(s)`);
      await onCreated(tpl);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to create template",
      );
    } finally {
      setBusy(false);
    }
  };

  const inputCls = "w-full h-9 px-2.5 text-[13px]";
  const inputStyle: React.CSSProperties = {
    border: "1px solid var(--color-border)",
    borderRadius: "4px",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
    outline: "none",
  };

  return (
    <ModalShell title="Build custom questionnaire" onClose={onClose}>
      <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme custom risk questionnaire"
            className={inputCls}
            style={inputStyle}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Framework"
            hint="Just a tag for grouping — doesn't auto-add questions."
          >
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as typeof kind)}
              className={inputCls}
              style={inputStyle}
            >
              <option value="custom">Custom (your own questions)</option>
              <option value="sig_lite">SIG Lite — ~125 Q, 18 risk domains</option>
              <option value="sig_core">SIG Core — full ~800 Q, high-crit vendors</option>
              <option value="caiq_v4">CAIQ v4 — cloud-vendor focused</option>
            </select>
          </Field>
          <Field label="Description (optional)">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Short summary"
              className={inputCls}
              style={inputStyle}
            />
          </Field>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <label
              className="text-[11px] font-bold tracking-[0.08em] uppercase"
              style={{ color: "var(--color-muted)" }}
            >
              Questions ({questions.length})
            </label>
            <button
              onClick={addQuestion}
              type="button"
              className="text-[11.5px] font-bold"
              style={{
                color: "var(--color-accent)",
                background: "none",
                border: "none",
                cursor: "pointer",
              }}
            >
              + Add question
            </button>
          </div>
          <div className="space-y-2">
            {questions.map((q, i) => (
              <div
                key={i}
                className="p-3 space-y-2"
                style={{
                  border: "1px solid var(--color-border)",
                  borderRadius: "5px",
                  background: "var(--color-surface-muted)",
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span
                    className="text-[10.5px] font-bold tracking-[0.06em]"
                    style={{ color: "var(--color-muted)" }}
                  >
                    Q{i + 1}
                  </span>
                  {questions.length > 1 ? (
                    <button
                      onClick={() => removeQuestion(i)}
                      type="button"
                      className="text-[11px]"
                      style={{
                        color: "#B71D18",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                      }}
                    >
                      Remove
                    </button>
                  ) : null}
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <input
                    value={q.id}
                    onChange={(e) =>
                      updateQuestion(i, { id: e.target.value.replace(/\s+/g, "_") })
                    }
                    placeholder="question_id"
                    className={inputCls}
                    style={{ ...inputStyle, fontFamily: "monospace" }}
                  />
                  <select
                    value={q.answer_kind}
                    onChange={(e) =>
                      updateQuestion(i, { answer_kind: e.target.value })
                    }
                    className={inputCls}
                    style={inputStyle}
                  >
                    {ANSWER_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {ANSWER_KIND_HELP[k]}
                      </option>
                    ))}
                  </select>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min={1}
                      max={10}
                      value={q.weight}
                      onChange={(e) =>
                        updateQuestion(i, {
                          weight: Math.max(1, Math.min(10, Number(e.target.value) || 1)),
                        })
                      }
                      className={inputCls}
                      style={{ ...inputStyle, width: "70px" }}
                    />
                    <label
                      className="text-[11px] inline-flex items-center gap-1 cursor-pointer"
                      style={{ color: "var(--color-body)" }}
                    >
                      <input
                        type="checkbox"
                        checked={q.required}
                        onChange={(e) =>
                          updateQuestion(i, { required: e.target.checked })
                        }
                      />
                      required
                    </label>
                  </div>
                </div>
                <input
                  value={q.text}
                  onChange={(e) => updateQuestion(i, { text: e.target.value })}
                  placeholder="What's the question?"
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
            ))}
          </div>
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Creating…" : "Create template"}
        disabled={!valid || busy}
      />
    </ModalShell>
  );
}

// ─── Add vendor modal ────────────────────────────────────────────────

const VENDOR_CRITICALITIES: Array<{ value: "crown_jewel" | "high" | "medium" | "low"; label: string }> = [
  { value: "crown_jewel", label: "Crown jewel — handles your crown-jewel data" },
  { value: "high", label: "High — significant access / hard to replace" },
  { value: "medium", label: "Medium — meaningful access" },
  { value: "low", label: "Low — minimal access / easily swapped" },
];

const VENDOR_TIERS: Array<{ value: "tier_1" | "tier_2" | "tier_3"; label: string }> = [
  { value: "tier_1", label: "Tier 1 — annual review (critical)" },
  { value: "tier_2", label: "Tier 2 — biennial review (important)" },
  { value: "tier_3", label: "Tier 3 — on-demand (standard)" },
];

const VENDOR_CATEGORIES: Array<{ value: string; label: string }> = [
  { value: "payment_processor", label: "Payment processor" },
  { value: "cloud_provider", label: "Cloud / SaaS provider" },
  { value: "security_vendor", label: "Security vendor" },
  { value: "hr_payroll", label: "HR / Payroll" },
  { value: "telecom", label: "Telecom" },
  { value: "legal", label: "Legal" },
  { value: "auditor", label: "Auditor" },
  { value: "marketing_saas", label: "Marketing SaaS" },
  { value: "data_broker", label: "Data broker" },
  { value: "other", label: "Other" },
];

const VENDOR_DATA_ACCESS: Array<{ value: string; label: string }> = [
  { value: "none", label: "None — no customer data" },
  { value: "metadata", label: "Metadata only" },
  { value: "pii", label: "PII (names, emails, addresses)" },
  { value: "financial", label: "Financial / payment data" },
  { value: "crown_jewel", label: "Crown-jewel data (full access)" },
];

function AddVendorModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string;
  onClose: () => void;
  onCreated: () => void | Promise<void>;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [primaryDomain, setPrimaryDomain] = useState("");
  const [criticality, setCriticality] = useState<"crown_jewel" | "high" | "medium" | "low">("medium");
  const [tier, setTier] = useState<"tier_1" | "tier_2" | "tier_3">("tier_3");
  const [category, setCategory] = useState("other");
  const [dataAccess, setDataAccess] = useState("metadata");
  const [githubOrg, setGithubOrg] = useState("");
  const [busy, setBusy] = useState(false);

  const valid = name.trim().length >= 2;

  const submit = async () => {
    if (!valid || busy) return;
    setBusy(true);
    try {
      const cleanDomain = primaryDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      await api.createAsset({
        organization_id: orgId,
        asset_type: "vendor",
        value: name.trim(),
        criticality,
        details: {
          primary_domain: cleanDomain || undefined,
          tier,
          category,
          data_access_level: dataAccess,
          github_org: githubOrg.trim() || undefined,
        },
        tags: ["vendor", category],
        discovery_method: "manual",
      });
      toast("success", `Vendor "${name.trim()}" added`);
      await onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to add vendor");
    } finally {
      setBusy(false);
    }
  };

  const inputCls = "w-full h-9 px-2.5 text-[13px]";
  const inputStyleLocal: React.CSSProperties = {
    border: "1px solid var(--color-border)",
    borderRadius: "4px",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
    outline: "none",
  };

  return (
    <ModalShell title="Add vendor" onClose={onClose}>
      <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
        <Field label="Vendor name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme Cloud Backup Inc"
            className={inputCls}
            style={inputStyleLocal}
            autoFocus
          />
        </Field>
        <Field
          label="Primary domain"
          hint="Used by EASM scope, DMARC/SPF check, HIBP probe, sanctions screen, and brand-protection typosquat correlation."
        >
          <input
            value={primaryDomain}
            onChange={(e) => setPrimaryDomain(e.target.value)}
            placeholder="acme-cloud.com"
            className={inputCls}
            style={{ ...inputStyleLocal, fontFamily: "monospace" }}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Criticality">
            <select
              value={criticality}
              onChange={(e) => setCriticality(e.target.value as typeof criticality)}
              className={inputCls}
              style={inputStyleLocal}
            >
              {VENDOR_CRITICALITIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Review cadence (tier)">
            <select
              value={tier}
              onChange={(e) => setTier(e.target.value as typeof tier)}
              className={inputCls}
              style={inputStyleLocal}
            >
              {VENDOR_TIERS.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Category">
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className={inputCls}
              style={inputStyleLocal}
            >
              {VENDOR_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="Data access level"
            hint="Drives the operational pillar of the scorecard."
          >
            <select
              value={dataAccess}
              onChange={(e) => setDataAccess(e.target.value)}
              className={inputCls}
              style={inputStyleLocal}
            >
              {VENDOR_DATA_ACCESS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field
          label="GitHub org (optional)"
          hint="Enables free GitHub Search-API leak scanning for this vendor's public repos."
        >
          <input
            value={githubOrg}
            onChange={(e) => setGithubOrg(e.target.value)}
            placeholder="acme-cloud"
            className={inputCls}
            style={{ ...inputStyleLocal, fontFamily: "monospace" }}
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Adding…" : "Add vendor"}
        disabled={!valid || busy}
      />
    </ModalShell>
  );
}
