"use client";

import { useEffect, useState } from "react";
import {
  ArrowUpRight,
  Camera,
  Globe2,
  Image as ImageIcon,
  Sparkles,
  Smartphone,
  UserX,
  AlertOctagon,
  AlertTriangle,
} from "lucide-react";
import {
  api,
  type BrandOverviewResponse,
  type SuspectStateValue,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  MonoCell,
  Section,
  SkeletonRows,
  Th,
  StatePill,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

const SUSPECT_STATE_TONE: Record<SuspectStateValue, StateTone> = {
  open: "neutral",
  confirmed_phishing: "error-strong",
  takedown_requested: "warning",
  dismissed: "muted",
  cleared: "success",
};

const SUSPECT_STATE_LABEL: Record<SuspectStateValue, string> = {
  open: "OPEN",
  confirmed_phishing: "CONFIRMED",
  takedown_requested: "TAKEDOWN",
  dismissed: "DISMISSED",
  cleared: "CLEARED",
};

const PROBE_VERDICT_TONE: Record<string, StateTone> = {
  phishing: "error-strong",
  suspicious: "warning",
  clean: "success",
  unreachable: "muted",
};

// Tone → inline style for RollupCard breakdown badges
function toneToStyle(tone: StateTone): React.CSSProperties {
  switch (tone) {
    case "error-strong": return { background: "rgba(255,86,48,0.12)", color: "#B71D18" };
    case "error": return { background: "rgba(255,86,48,0.08)", color: "#B71D18" };
    case "warning": return { background: "rgba(255,171,0,0.1)", color: "#B76E00" };
    case "info": return { background: "rgba(0,187,217,0.1)", color: "#007B8A" };
    case "success": return { background: "rgba(0,167,111,0.1)", color: "#007B55" };
    case "muted": return { background: "var(--color-surface-muted)", color: "var(--color-muted)" };
    default: return { background: "var(--color-surface-muted)", color: "var(--color-body)" };
  }
}

export function OverviewTab({
  onJumpTab,
}: {
  onJumpTab: (id: string) => void;
}) {
  const { orgId } = useBrandContext();
  const { toast } = useToast();
  const [data, setData] = useState<BrandOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!orgId) return;
    let alive = true;
    setLoading(true);
    (async () => {
      try {
        const d = await api.brand.overview(orgId);
        if (alive) setData(d);
      } catch (e) {
        if (alive)
          toast(
            "error",
            e instanceof Error ? e.message : "Failed to load overview",
          );
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [orgId, toast]);

  if (loading || !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-[124px] animate-pulse"
              style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-surface)", animationDelay: `${i * 60}ms` }}
            />
          ))}
        </div>
        <Section>
          <SkeletonRows rows={5} columns={5} />
        </Section>
      </div>
    );
  }

  const cards: Array<{
    id: string;
    label: string;
    icon: React.ElementType;
    total: number;
    breakdown: Array<{ label: string; value: number; tone: StateTone }>;
    tabId: string;
  }> = [
    {
      id: "suspects",
      label: "Suspect domains",
      icon: Globe2,
      total: data.suspects_total,
      breakdown: Object.entries(data.suspects_by_state).map(([state, n]) => ({
        label: SUSPECT_STATE_LABEL[state as SuspectStateValue] || state.toUpperCase(),
        value: n,
        tone: SUSPECT_STATE_TONE[state as SuspectStateValue] || "neutral",
      })),
      tabId: "suspects",
    },
    {
      id: "probes",
      label: "Live probes",
      icon: Camera,
      total: data.live_probes_total,
      breakdown: Object.entries(data.live_probes_by_verdict).map(
        ([verdict, n]) => ({
          label: verdict.toUpperCase(),
          value: n,
          tone: PROBE_VERDICT_TONE[verdict] || "neutral",
        }),
      ),
      tabId: "probes",
    },
    {
      id: "logos",
      label: "Logos & matches",
      icon: ImageIcon,
      total: data.logos_count,
      breakdown: [
        { label: "MATCHES", value: data.logo_matches_total, tone: "warning" as StateTone },
        ...Object.entries(data.logo_matches_by_verdict).map(([v, n]) => ({
          label: v.toUpperCase(),
          value: n,
          tone:
            v === "phishing"
              ? ("error-strong" as StateTone)
              : v === "match"
              ? ("warning" as StateTone)
              : ("muted" as StateTone),
        })),
      ],
      tabId: "logos",
    },
    {
      id: "impersonations",
      label: "Impersonations",
      icon: UserX,
      total: data.impersonations_total,
      breakdown: Object.entries(data.impersonations_by_state).map(([s, n]) => ({
        label: s.toUpperCase(),
        value: n,
        tone:
          s === "confirmed"
            ? ("error-strong" as StateTone)
            : s === "open"
            ? ("neutral" as StateTone)
            : ("muted" as StateTone),
      })),
      tabId: "impersonations",
    },
    {
      id: "mobile-apps",
      label: "Mobile apps",
      icon: Smartphone,
      total: data.mobile_apps_total,
      breakdown: Object.entries(data.mobile_apps_by_state).map(([s, n]) => ({
        label: s.toUpperCase(),
        value: n,
        tone: s === "confirmed" ? ("error-strong" as StateTone) : ("neutral" as StateTone),
      })),
      tabId: "mobile-apps",
    },
    {
      id: "fraud",
      label: "Fraud",
      icon: AlertOctagon,
      total: data.fraud_findings_total,
      breakdown: Object.entries(data.fraud_findings_by_state).map(([s, n]) => ({
        label: s.toUpperCase(),
        value: n,
        tone:
          s === "confirmed"
            ? ("error-strong" as StateTone)
            : s === "reported_to_regulator"
            ? ("warning" as StateTone)
            : ("neutral" as StateTone),
      })),
      tabId: "fraud",
    },
  ];

  const grandTotal = cards.reduce((s, c) => s + c.total, 0);

  return (
    <div className="space-y-6">
      {data.logo_corpus_health?.status === "empty" ? (
        <div
          role="alert"
          className="flex items-start gap-3 px-4 py-3"
          style={{ borderRadius: "5px", border: "1px solid rgba(255,171,0,0.4)", background: "rgba(255,171,0,0.08)" }}
        >
          <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" style={{ color: "#B76E00" }} />
          <div className="flex-1">
            <p className="text-[13px] font-bold" style={{ color: "#B76E00" }}>
              Logo-abuse detection is inactive
            </p>
            <p className="text-[12.5px] mt-0.5" style={{ color: "var(--color-body)" }}>
              {data.logo_corpus_health.message}
            </p>
          </div>
          <button
            onClick={() => onJumpTab("logos")}
            className="shrink-0 inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid rgba(255,171,0,0.6)", background: "#FFAB00", color: "#201515" }}
          >
            Upload logos
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      ) : null}

      {grandTotal === 0 ? (
        <Section>
          <Empty
            icon={Sparkles}
            title="No brand-protection signal yet"
            description="Configure brand terms and run a scan to seed the surface. Live detectors (CertStream, mobile-app monitor, Telegram, Instagram, TikTok, Twitter, LinkedIn) start producing findings as the workers tick."
            action={
              <button
                onClick={() => onJumpTab("terms")}
                className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
                style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
              >
                Configure terms & feeds
              </button>
            }
          />
        </Section>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {cards.map((c) => (
          <RollupCard
            key={c.id}
            label={c.label}
            icon={c.icon}
            total={c.total}
            breakdown={c.breakdown}
            onClick={() => onJumpTab(c.tabId)}
          />
        ))}
      </div>

      {/* Top suspects */}
      <Section>
        <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <div>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Top similarity suspects
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Highest match score against your registered apex domains.
            </p>
          </div>
          <button
            onClick={() => onJumpTab("suspects")}
            className="inline-flex items-center gap-1 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
          >
            View all
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
        {data.suspects_top_similarity.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
              No suspects yet
            </p>
            <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
              The scanner has not surfaced any typosquats above the similarity
              threshold.
            </p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4 w-[80px]">
                  Sim
                </Th>
                <Th align="left">Domain</Th>
                <Th align="left">Matched term</Th>
                <Th align="left" className="w-[140px]">
                  Source
                </Th>
                <Th align="right" className="pr-4 w-[140px]">
                  State
                </Th>
              </tr>
            </thead>
            <tbody>
              {data.suspects_top_similarity.map((s) => (
                <tr
                  key={s.id}
                  className="h-11 transition-colors"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="pl-4">
                    <SimilarityBar value={s.similarity} />
                  </td>
                  <td className="px-3 font-mono text-[12.5px] tabular-nums" style={{ color: "var(--color-ink)" }}>
                    {s.domain}
                  </td>
                  <td className="px-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                    matches{" "}
                    <span className="font-mono" style={{ color: "var(--color-ink)" }}>
                      {s.matched_term}
                    </span>
                  </td>
                  <td className="px-3">
                    <SourceTag source={s.source} />
                  </td>
                  <td className="pr-4 text-right">
                    <StatePill
                      label={SUSPECT_STATE_LABEL[s.state as SuspectStateValue] || s.state}
                      tone={
                        SUSPECT_STATE_TONE[s.state as SuspectStateValue] || "neutral"
                      }
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* Recent phishing probes */}
      <Section>
        <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <div>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
              Recent phishing probes
            </h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Suspect domains where the live-probe rendered a cloned login or
              brand-impersonating page.
            </p>
          </div>
          <button
            onClick={() => onJumpTab("probes")}
            className="inline-flex items-center gap-1 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
          >
            View all
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
        {data.recent_phishing_probes.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
              No active phishing probes
            </p>
            <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
              The live probe has not landed on a confirmed phishing or
              suspicious page in the last batch.
            </p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4 w-[112px]">
                  Verdict
                </Th>
                <Th align="left">URL</Th>
                <Th align="left" className="w-[80px]">
                  Sim
                </Th>
                <Th align="right" className="pr-4 w-[120px]">
                  Probed
                </Th>
              </tr>
            </thead>
            <tbody>
              {data.recent_phishing_probes.map((p) => (
                <tr
                  key={p.id}
                  className="h-11 transition-colors"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="pl-4">
                    <StatePill
                      label={p.verdict}
                      tone={PROBE_VERDICT_TONE[p.verdict] || "neutral"}
                    />
                  </td>
                  <td className="px-3 font-mono text-[12px] truncate max-w-[420px]" style={{ color: "var(--color-body)" }}>
                    {p.url}
                  </td>
                  <td className="px-3">
                    {p.similarity_to_brand !== null ? (
                      <SimilarityBar value={p.similarity_to_brand} />
                    ) : (
                      <span className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>—</span>
                    )}
                  </td>
                  <td className="pr-4 text-right">
                    <MonoCell text={timeAgo(p.fetched_at)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}

function RollupCard({
  label,
  icon: Icon,
  total,
  breakdown,
  onClick,
}: {
  label: string;
  icon: React.ElementType;
  total: number;
  breakdown: Array<{ label: string; value: number; tone: StateTone }>;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="text-left p-4 transition-all"
      style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--color-border-strong)"; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--color-border)"; }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-[10.5px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
          <Icon className="w-3.5 h-3.5" />
          {label}
        </div>
        <ArrowUpRight className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
      </div>
      <div className="mt-2.5 font-mono tabular-nums text-[34px] leading-none font-extrabold tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
        {total}
      </div>
      {breakdown.length > 0 ? (
        <div className="mt-3 flex items-center gap-1.5 flex-wrap">
          {breakdown.slice(0, 5).map((b, i) => (
            <span
              key={`${b.label}-${i}`}
              className="inline-flex items-center gap-1 text-[10.5px] font-bold tracking-[0.04em]"
              style={{ color: "var(--color-body)" }}
            >
              <span className="font-mono tabular-nums">{b.value}</span>
              <span
                className="px-1 text-[9.5px]"
                style={{ borderRadius: "3px", ...toneToStyle(b.tone) }}
              >
                {b.label}
              </span>
            </span>
          ))}
        </div>
      ) : (
        <div className="mt-3 text-[11.5px]" style={{ color: "var(--color-muted)" }}>no activity</div>
      )}
    </button>
  );
}

function SimilarityBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor = pct >= 0.9 ? "#FF5630" : pct >= 0.75 ? "#FFAB00" : "#00BBD9";
  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
        <div
          className="h-full"
          style={{ width: `${pct * 100}%`, background: fillColor }}
        />
      </div>
      <span className="font-mono text-[11px] tabular-nums" style={{ color: "var(--color-body)" }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function SourceTag({ source }: { source: string }) {
  return (
    <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-semibold uppercase tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
      {source}
    </span>
  );
}
