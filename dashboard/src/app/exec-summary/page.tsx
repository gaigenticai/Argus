"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Briefcase,
  Building2,
  ChevronDown,
  ChevronUp,
  Download,
  GanttChart,
  Globe2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  UserX,
} from "lucide-react";
import {
  api,
  type BrandOverviewResponse,
  type CaseCounts,
  type Org,
  type SecurityRatingDetail,
  type SecurityRatingResponse,
  type SlaBreachResponse,
  type TprmScorecardResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
  Select,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";

const PERIODS = [
  { value: 7, label: "Last 7 days" },
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
];

const SEVERITY_PALETTE: Record<
  string,
  { stripeColor: string; chipBg: string; chipBorder: string; chipColor: string; label: string }
> = {
  critical: { stripeColor: "#FF5630", chipBg: "rgba(255,86,48,0.1)", chipBorder: "rgba(255,86,48,0.4)", chipColor: "#B71D18", label: "CRIT" },
  high: { stripeColor: "#FF8863", chipBg: "rgba(255,136,99,0.1)", chipBorder: "rgba(255,136,99,0.4)", chipColor: "#B71D18", label: "HIGH" },
  medium: { stripeColor: "#FFAB00", chipBg: "rgba(255,171,0,0.1)", chipBorder: "rgba(255,171,0,0.4)", chipColor: "#B76E00", label: "MED" },
  low: { stripeColor: "#00BBD9", chipBg: "rgba(0,187,217,0.1)", chipBorder: "rgba(0,187,217,0.4)", chipColor: "#007B8A", label: "LOW" },
  info: { stripeColor: "#939084", chipBg: "rgba(147,144,132,0.1)", chipBorder: "rgba(147,144,132,0.4)", chipColor: "#36342e", label: "INFO" },
};

interface DashboardData {
  cases: CaseCounts;
  brand: BrandOverviewResponse;
  rating: SecurityRatingDetail | null;
  sla: { breaches: SlaBreachResponse[]; total: number };
  scorecards: TprmScorecardResponse[];
}

export default function ExecSummaryPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [days, setDays] = useState(30);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);

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

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [cases, brand, rating, breaches, scorecards] = await Promise.all([
        api.cases.count(orgId),
        api.brand.overview(orgId),
        api.ratings.current(orgId).catch(() => null),
        api.sla
          .listBreaches({ organization_id: orgId, limit: 200 })
          .then((r) => ({ breaches: r, total: r.length }))
          .catch(() => ({ breaches: [], total: 0 })),
        api.tprm
          .listScorecards({
            organization_id: orgId,
            is_current: true,
            limit: 100,
          })
          .then((r) => r.data)
          .catch(() => []),
      ]);
      setData({ cases, brand, rating, sla: breaches, scorecards });
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load executive summary",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const downloadPdf = async () => {
    if (!orgId) return;
    setDownloading(true);
    try {
      const blob = await api.exec.downloadPdf({ organization_id: orgId, days });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `argus-exec-summary-${days}d.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast("success", "PDF downloaded");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "PDF download failed");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: GanttChart, label: "Overview" }}
        title="Executive Summary"
        description="Board-level posture across cases, exposures, brand surface, vendor risk, and SLA. The PDF export is identical to the printable bundle the SOC delivers to the audit committee."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <Select
              ariaLabel="Period"
              value={String(days)}
              options={PERIODS.map((p) => ({
                value: String(p.value),
                label: p.label,
              }))}
              onChange={(v) => setDays(Number(v))}
            />
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={downloadPdf}
              disabled={downloading || !orgId}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold disabled:opacity-50"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Download style={{ width: "16px", height: "16px" }} className={downloading ? "animate-pulse" : undefined} />
              {downloading ? "Generating…" : "Download PDF"}
            </button>
          </>
        }
      />

      {loading || !data ? (
        <DashboardSkeleton />
      ) : (
        <Dashboard
          data={data}
          orgId={orgId}
          onRatingRecomputed={(r) => setData((d) => d ? { ...d, rating: r } : d)}
        />
      )}
    </div>
  );
}

function Dashboard({ data, orgId, onRatingRecomputed }: { data: DashboardData; orgId: string; onRatingRecomputed: (r: SecurityRatingDetail) => void }) {
  const exposureCells: Array<{
    severity: keyof typeof SEVERITY_PALETTE;
    n: number;
  }> = useMemo(() => {
    const sev = data.brand.suspects_by_state || {};
    void sev;
    // Use cases.by_severity as the proxy for the rollup since
    // brand_overview doesn't carry per-severity exposure counts and
    // the Exposures page itself filters those. The PDF backend uses
    // ExposureFinding directly; the dashboard view is a board-level
    // shorthand that matches the Cases by-severity breakdown.
    return (
      ["critical", "high", "medium", "low", "info"] as const
    ).map((s) => ({
      severity: s,
      n: data.cases.by_severity?.[s] ?? 0,
    }));
  }, [data]);

  const successfulTakedowns = (data.brand.suspects_by_state?.cleared ?? 0) +
    (data.brand.suspects_by_state?.takedown_requested ?? 0);
  void successfulTakedowns;

  const totalImpersonations = data.brand.impersonations_total;
  const totalMobileApps = data.brand.mobile_apps_total;
  const totalFraud = data.brand.fraud_findings_total;
  const totalSuspects = data.brand.suspects_total;

  const recentBreaches = data.sla.breaches.slice(0, 5);

  return (
    <>
      {/* Headline strip */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <KpiCard
          icon={Briefcase}
          label="Open cases"
          value={data.cases.total - (data.cases.by_state?.closed ?? 0)}
          delta={null}
          sub={`${data.cases.overdue} overdue`}
          tone={data.cases.overdue > 0 ? "warning" : "neutral"}
        />
        <KpiCard
          icon={ShieldAlert}
          label="Active exposures"
          value={
            (data.cases.by_severity?.critical ?? 0) +
            (data.cases.by_severity?.high ?? 0) +
            (data.cases.by_severity?.medium ?? 0)
          }
          sub={`${data.cases.by_severity?.critical ?? 0} crit · ${
            data.cases.by_severity?.high ?? 0
          } high`}
          tone={(data.cases.by_severity?.critical ?? 0) > 0 ? "error" : "neutral"}
        />
        <KpiCard
          icon={Globe2}
          label="Brand suspects"
          value={totalSuspects}
          sub="open + investigation"
          tone="neutral"
        />
        <KpiCard
          icon={UserX}
          label="Impersonations"
          value={totalImpersonations}
          sub="across 11 platforms"
          tone="neutral"
        />
        <KpiCard
          icon={Smartphone}
          label="Rogue apps"
          value={totalMobileApps}
          sub="Google Play + iOS"
          tone="neutral"
        />
        <KpiCard
          icon={AlertTriangle}
          label="Fraud findings"
          value={totalFraud}
          sub="crypto / scam / shill"
          tone={totalFraud > 0 ? "warning" : "neutral"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Security rating card */}
        <Section className="lg:col-span-1">
          <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Security rating
            </h3>
            <ShieldCheck className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
          </div>
          <RatingPanel rating={data.rating} orgId={orgId} onRecomputed={onRatingRecomputed} />
        </Section>

        {/* Exposure severity bars */}
        <Section className="lg:col-span-2">
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Cases by severity
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              All-time — a leading indicator that maps 1:1 to detector
              auto-promotion (HIGH+ → Case).
            </p>
          </div>
          <div className="p-5">
            <SeverityBars cells={exposureCells} />
          </div>
        </Section>
      </div>

      {/* Detection mix + SLA */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Section className="lg:col-span-2">
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Detection mix — brand surface
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Where the active findings came from. Shows which feeds
              earn their cost.
            </p>
          </div>
          <div className="p-5">
            <SourceMix data={data.brand.suspects_by_source} />
          </div>
        </Section>

        <Section className="lg:col-span-1">
          <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              SLA breaches
            </h3>
            <span
              className="font-mono text-[14px] font-extrabold tabular-nums"
              style={{ color: data.sla.total > 0 ? "#FF5630" : "#007B55" }}
            >
              {data.sla.total}
            </span>
          </div>
          <SlaList breaches={recentBreaches} totalRemaining={data.sla.total} />
        </Section>
      </div>

      {/* Vendor risk */}
      <Section>
        <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <div>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Vendor risk distribution
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Current scorecards across {data.scorecards.length} vendor
              {data.scorecards.length === 1 ? "" : "s"}. Lower grade ⇒ more
              exposure pressure scoped to the vendor&apos;s primary domain.
            </p>
          </div>
          <Building2 className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
        </div>
        <VendorGradeMatrix scorecards={data.scorecards} />
      </Section>
    </>
  );
}

function KpiCard({
  icon: Icon,
  label,
  value,
  delta,
  sub,
  tone = "neutral",
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  delta?: number | null;
  sub?: string;
  tone?: "neutral" | "warning" | "error";
}) {
  const valueColor = tone === "error" ? "#FF5630" : tone === "warning" ? "#B76E00" : "var(--color-ink)";
  return (
    <div className="p-4" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
      <div className="flex items-center justify-between" style={{ color: "var(--color-muted)" }}>
        <div className="flex items-center gap-1.5 text-[10.5px] font-bold uppercase tracking-[0.12em]">
          <Icon className="w-3.5 h-3.5" />
          {label}
        </div>
        {delta !== null && delta !== undefined ? (
          <span
            className="inline-flex items-center gap-0.5 text-[10.5px] font-bold tabular-nums"
            style={{ color: delta < 0 ? "#007B55" : delta > 0 ? "#B71D18" : "var(--color-muted)" }}
          >
            {delta < 0 ? <ArrowDown className="w-3 h-3" /> : delta > 0 ? <ArrowUp className="w-3 h-3" /> : null}
            {Math.abs(delta)}
          </span>
        ) : null}
      </div>
      <div
        className="mt-2 font-mono tabular-nums text-[28px] leading-none font-extrabold tracking-[-0.02em]"
        style={{ color: valueColor }}
      >
        {value}
      </div>
      {sub ? (
        <div className="text-[11px] mt-1.5" style={{ color: "var(--color-muted)" }}>{sub}</div>
      ) : null}
    </div>
  );
}

function RatingPanel({
  rating,
  orgId,
  onRecomputed,
}: {
  rating: SecurityRatingDetail | null;
  orgId: string;
  onRecomputed: (r: SecurityRatingDetail) => void;
}) {
  const { toast } = useToast();
  const [recomputing, setRecomputing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory] = useState<SecurityRatingResponse[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [showRubric, setShowRubric] = useState(false);
  const [rubric, setRubric] = useState<{ pillar_weights: Record<string, number>; grade_thresholds: Record<string, number>; pillar_descriptions: Record<string, string>; version: string } | null>(null);

  const handleRecompute = async () => {
    if (!orgId) return;
    setRecomputing(true);
    try {
      const result = await api.ratings.recompute(orgId);
      onRecomputed(result);
      toast("success", `Rating recomputed: ${result.grade.toUpperCase()} (${Math.round(result.score)}/100)`);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Recompute failed");
    } finally {
      setRecomputing(false);
    }
  };

  const loadHistory = async () => {
    if (!orgId || historyLoading) return;
    setHistoryLoading(true);
    try {
      const rows = await api.ratings.history({ organization_id: orgId, limit: 10 });
      setHistory(Array.isArray(rows) ? rows : (rows as { data: SecurityRatingResponse[] }).data ?? []);
    } catch {
      toast("error", "Failed to load rating history");
    } finally {
      setHistoryLoading(false);
    }
  };

  const loadRubric = async () => {
    try {
      const r = await api.ratings.getRubric();
      setRubric(r as typeof rubric);
    } catch {
      toast("error", "Failed to load rubric");
    }
  };

  const handleToggleHistory = () => {
    const next = !showHistory;
    setShowHistory(next);
    if (next && history.length === 0) loadHistory();
  };

  const handleToggleRubric = () => {
    const next = !showRubric;
    setShowRubric(next);
    if (next && !rubric) loadRubric();
  };

  const gradeHexColor = (g: string) => {
    const u = g.toUpperCase();
    return u.startsWith("A") ? "#007B55"
      : u === "B" ? "var(--color-accent)"
      : u === "C" ? "#B76E00"
      : u === "D" ? "#7A4100"
      : "#B71D18";
  };

  const gradeStyle = (g: string): React.CSSProperties => {
    const u = g.toUpperCase();
    return u.startsWith("A")
      ? { background: "rgba(0,167,111,0.1)", borderColor: "rgba(0,167,111,0.5)", color: "#007B55" }
      : u === "B"
      ? { background: "rgba(255,79,0,0.1)", borderColor: "rgba(255,79,0,0.5)", color: "var(--color-accent)" }
      : u === "C"
      ? { background: "rgba(255,171,0,0.1)", borderColor: "rgba(255,171,0,0.5)", color: "#B76E00" }
      : u === "D"
      ? { background: "rgba(183,110,0,0.1)", borderColor: "rgba(183,110,0,0.5)", color: "#7A4100" }
      : { background: "rgba(255,86,48,0.1)", borderColor: "rgba(255,86,48,0.5)", color: "#B71D18" };
  };

  if (!rating) {
    return (
      <div className="p-5">
        <div className="text-center py-4">
          <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>No rating yet</p>
          <p className="text-[12px] mt-1 mb-4" style={{ color: "var(--color-muted)" }}>
            Run a recompute to generate the initial security score.
          </p>
        </div>
        <button
          onClick={handleRecompute}
          disabled={recomputing || !orgId}
          className="w-full flex items-center justify-center gap-2 h-9 text-[13px] font-bold disabled:opacity-50 transition-colors"
          style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${recomputing ? "animate-spin" : ""}`} />
          {recomputing ? "Computing…" : "Compute Rating"}
        </button>
      </div>
    );
  }

  const grade = rating.grade.toUpperCase();
  const gStyle = gradeStyle(grade);

  return (
    <div className="p-5">
      <div className="flex items-start gap-4">
        <div
          className="w-20 h-20 flex items-center justify-center text-[44px] font-extrabold leading-none tracking-tight shrink-0"
          style={{ borderRadius: "8px", border: "3px solid", ...gStyle }}
        >
          {grade}
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-mono tabular-nums text-[36px] font-extrabold leading-none" style={{ color: "var(--color-ink)" }}>
            {Math.round(rating.score)}
          </div>
          <div className="text-[11px] font-bold uppercase tracking-[0.08em] mt-1" style={{ color: "var(--color-muted)" }}>
            of 100
          </div>
          <button
            onClick={handleRecompute}
            disabled={recomputing || !orgId}
            className="mt-2 flex items-center gap-1.5 text-[11px] font-bold disabled:opacity-50 transition-colors"
            style={{ color: "var(--color-accent)" }}
          >
            <RefreshCw className={`w-3 h-3 ${recomputing ? "animate-spin" : ""}`} />
            {recomputing ? "Computing…" : "Recompute"}
          </button>
        </div>
      </div>

      {rating.summary?.pillars ? (
        <div className="mt-4 space-y-2">
          {Object.entries(rating.summary.pillars as Record<string, { score: number }>)
            .slice(0, 5)
            .map(([k, v]) => (
              <div key={k} className="flex items-center gap-2">
                <span className="text-[10.5px] font-bold uppercase tracking-[0.06em] w-[88px] truncate" style={{ color: "var(--color-body)" }}>
                  {k.replace(/_/g, " ")}
                </span>
                <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
                  <div
                    style={{
                      height: "100%",
                      width: `${Math.max(0, Math.min(100, v.score))}%`,
                      background: v.score >= 70 ? "#22C55E" : v.score >= 50 ? "#FFAB00" : "#FF5630",
                    }}
                  />
                </div>
                <span className="font-mono text-[10.5px] tabular-nums w-[24px] text-right" style={{ color: "var(--color-body)" }}>
                  {Math.round(v.score)}
                </span>
              </div>
            ))}
        </div>
      ) : null}

      <div className="mt-4 pt-3 flex items-center justify-between" style={{ borderTop: "1px solid var(--color-border)" }}>
        <span className="text-[11px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          {timeAgo(rating.computed_at)} · rubric {rating.rubric_version}
        </span>
        <div className="flex gap-2">
          <button
            onClick={handleToggleHistory}
            className="flex items-center gap-0.5 text-[11px] font-bold transition-colors"
            style={{ color: "var(--color-muted)" }}
          >
            History
            {showHistory ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          <button
            onClick={handleToggleRubric}
            className="flex items-center gap-0.5 text-[11px] font-bold transition-colors"
            style={{ color: "var(--color-muted)" }}
          >
            Rubric
            {showRubric ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {showHistory && (
        <div className="mt-3 overflow-hidden" style={{ borderRadius: "4px", border: "1px solid var(--color-border)" }}>
          <div className="px-3 py-1.5 text-[10.5px] font-bold uppercase tracking-[0.06em]" style={{ background: "var(--color-surface)", color: "var(--color-muted)", borderBottom: "1px solid var(--color-border)" }}>
            Rating History
          </div>
          {historyLoading ? (
            <div className="px-3 py-4 text-center text-[12px]" style={{ color: "var(--color-muted)" }}>Loading…</div>
          ) : history.length === 0 ? (
            <div className="px-3 py-4 text-center text-[12px]" style={{ color: "var(--color-muted)" }}>No history yet</div>
          ) : (
            <div>
              {history.map((r) => (
                <div key={r.id} className="px-3 py-2 flex items-center justify-between gap-2" style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <span className="text-[13px] font-extrabold tabular-nums" style={{ color: gradeHexColor(r.grade) }}>
                    {r.grade.toUpperCase()}
                  </span>
                  <span className="font-mono text-[12px] tabular-nums" style={{ color: "var(--color-body)" }}>
                    {Math.round(r.score)}/100
                  </span>
                  <span className="text-[11px] font-mono tabular-nums flex-1 text-right" style={{ color: "var(--color-muted)" }}>
                    {timeAgo(r.computed_at)}
                  </span>
                  {r.is_current && (
                    <span className="text-[9px] font-bold uppercase tracking-[0.08em] px-1.5 py-0.5" style={{ borderRadius: "4px", background: "rgba(255,79,0,0.1)", color: "var(--color-accent)" }}>
                      current
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {showRubric && (
        <div className="mt-3 overflow-hidden" style={{ borderRadius: "4px", border: "1px solid var(--color-border)" }}>
          <div className="px-3 py-1.5 text-[10.5px] font-bold uppercase tracking-[0.06em]" style={{ background: "var(--color-surface)", color: "var(--color-muted)", borderBottom: "1px solid var(--color-border)" }}>
            Scoring Rubric {rubric ? `· v${rubric.version}` : ""}
          </div>
          {!rubric ? (
            <div className="px-3 py-4 text-center text-[12px]" style={{ color: "var(--color-muted)" }}>Loading…</div>
          ) : (
            <div>
              {Object.entries(rubric.pillar_weights).map(([pillar, weight]) => (
                <div key={pillar} className="px-3 py-2" style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[11px] font-bold capitalize" style={{ color: "var(--color-body)" }}>
                      {pillar.replace(/_/g, " ")}
                    </span>
                    <span className="font-mono text-[11px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {Math.round(weight * 100)}%
                    </span>
                  </div>
                  {rubric.pillar_descriptions[pillar] && (
                    <p className="text-[10.5px] leading-snug" style={{ color: "var(--color-muted)" }}>
                      {rubric.pillar_descriptions[pillar]}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SeverityBars({
  cells,
}: {
  cells: Array<{ severity: keyof typeof SEVERITY_PALETTE; n: number }>;
}) {
  const max = Math.max(1, ...cells.map((c) => c.n));
  return (
    <div className="space-y-3">
      {cells.map((c) => {
        const p = SEVERITY_PALETTE[c.severity];
        const pct = (c.n / max) * 100;
        return (
          <div key={c.severity} className="flex items-center gap-3">
            <span
              className="inline-flex items-center justify-center w-12 h-[20px] px-1.5 text-[10px] font-bold tracking-[0.06em]"
              style={{ borderRadius: "4px", background: p.chipBg, border: `1px solid ${p.chipBorder}`, color: p.chipColor }}
            >
              {p.label}
            </span>
            <div className="flex-1 h-6 rounded overflow-hidden" style={{ background: "var(--color-surface)" }}>
              <div
                className="h-full transition-all duration-700"
                style={{ width: `${pct}%`, background: p.stripeColor }}
              />
            </div>
            <span className="font-mono text-[14px] font-extrabold tabular-nums w-[44px] text-right" style={{ color: "var(--color-ink)" }}>
              {c.n}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function SourceMix({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return (
      <p className="text-[12.5px] italic text-center py-6" style={{ color: "var(--color-muted)" }}>
        No suspects yet — feeds haven&apos;t produced matches.
      </p>
    );
  }
  const total = entries.reduce((s, [, n]) => s + n, 0);
  return (
    <div className="space-y-2.5">
      {entries.map(([source, n]) => {
        const pct = (n / total) * 100;
        return (
          <div key={source} className="flex items-center gap-3">
            <span className="inline-flex items-center w-[110px] text-[10.5px] font-bold uppercase tracking-[0.06em]" style={{ color: "var(--color-body)" }}>
              {source}
            </span>
            <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
              <div
                style={{ height: "100%", width: `${pct}%`, background: "var(--color-ink)" }}
              />
            </div>
            <span className="font-mono text-[12px] tabular-nums w-[40px] text-right" style={{ color: "var(--color-body)" }}>
              {n}
            </span>
            <span className="font-mono text-[10.5px] tabular-nums w-[42px] text-right" style={{ color: "var(--color-muted)" }}>
              {pct.toFixed(0)}%
            </span>
          </div>
        );
      })}
    </div>
  );
}

function SlaList({
  breaches,
  totalRemaining,
}: {
  breaches: SlaBreachResponse[];
  totalRemaining: number;
}) {
  if (breaches.length === 0) {
    return (
      <div className="px-4 py-8 text-center">
        <Activity className="w-7 h-7 mx-auto mb-2" style={{ color: "var(--color-border)" }} />
        <p className="text-[12.5px] font-bold" style={{ color: "var(--color-body)" }}>No breaches</p>
        <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          SLA evaluator did not flag any items in the window.
        </p>
      </div>
    );
  }
  return (
    <ul>
      {breaches.map((b) => (
        <li key={b.id} className="px-4 py-2.5" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <div className="flex items-center justify-between gap-2 mb-0.5">
            <span className="text-[10.5px] font-bold uppercase tracking-[0.06em]" style={{ color: "#B71D18" }}>
              {b.severity.toUpperCase()}
            </span>
            <span className="font-mono text-[10.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
              {timeAgo(b.detected_at)}
            </span>
          </div>
          <div className="text-[12px]" style={{ color: "var(--color-body)" }}>
            <span>
              Case{" "}
              <span className="font-mono tabular-nums">
                {b.case_id.slice(-6).toUpperCase()}
              </span>
            </span>
            {" "}· {b.kind === "first_response" ? "first response" : "remediation"} · {b.threshold_minutes}m budget
          </div>
        </li>
      ))}
      {totalRemaining > breaches.length ? (
        <li className="px-4 py-2 text-[11.5px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          + {totalRemaining - breaches.length} more
        </li>
      ) : null}
    </ul>
  );
}

const VENDOR_GRADE_STYLE: Record<string, { bg: string; color: string }> = {
  A: { bg: "rgba(0,167,111,0.1)", color: "#007B55" },
  B: { bg: "rgba(255,79,0,0.1)", color: "var(--color-accent)" },
  C: { bg: "rgba(255,171,0,0.1)", color: "#B76E00" },
  D: { bg: "rgba(183,110,0,0.1)", color: "#7A4100" },
  F: { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
};

function VendorGradeMatrix({
  scorecards,
}: {
  scorecards: TprmScorecardResponse[];
}) {
  if (scorecards.length === 0) {
    return (
      <div className="px-4 py-10 text-center">
        <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
          No vendor scorecards
        </p>
        <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
          Add vendors and recompute their scorecards under TPRM.
        </p>
      </div>
    );
  }
  const counts: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const sc of scorecards) counts[sc.grade] = (counts[sc.grade] || 0) + 1;
  return (
    <div className="grid grid-cols-5">
      {(["A", "B", "C", "D", "F"] as const).map((g) => {
        const gs = VENDOR_GRADE_STYLE[g];
        return (
          <div
            key={g}
            className="px-4 py-5 flex flex-col items-center text-center"
            style={{ borderRight: "1px solid var(--color-border)" }}
          >
            <div
              className="w-12 h-12 flex items-center justify-center text-[24px] font-extrabold tracking-tight"
              style={{ borderRadius: "4px", background: gs.bg, color: gs.color }}
            >
              {g}
            </div>
            <div className="font-mono text-[26px] tabular-nums font-extrabold mt-2" style={{ color: "var(--color-ink)" }}>
              {counts[g]}
            </div>
            <div className="text-[10.5px] font-bold uppercase tracking-[0.08em] mt-1" style={{ color: "var(--color-muted)" }}>
              vendor{counts[g] === 1 ? "" : "s"}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="h-[100px]"
            style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
          />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="h-[280px]" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }} />
        <div className="h-[280px] lg:col-span-2" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }} />
      </div>
    </div>
  );
}
