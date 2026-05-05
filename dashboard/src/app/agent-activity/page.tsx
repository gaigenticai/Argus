"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  Briefcase,
  Compass,
  CircleCheck,
  CircleDashed,
  CircleX,
  Lock,
  Loader2,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import {
  api,
  type AgentActivityItem,
  type AgentKind,
  type AgentPosture,
  type FeedbackStats,
} from "@/lib/api";
import {
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  Th,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";


const KIND_PRESENTATION: Record<
  AgentKind,
  { label: string; icon: typeof Sparkles; bg: string; color: string }
> = {
  investigation: {
    label: "Investigation",
    icon: Search,
    bg: "rgba(0,187,217,0.1)",
    color: "#007B8A",
  },
  brand_defender: {
    label: "Brand Defender",
    icon: ShieldCheck,
    bg: "rgba(255,171,0,0.1)",
    color: "#B76E00",
  },
  case_copilot: {
    label: "Case Copilot",
    icon: Briefcase,
    bg: "rgba(0,167,111,0.1)",
    color: "#007B55",
  },
  threat_hunter: {
    label: "Threat Hunter",
    icon: Compass,
    bg: "var(--color-surface-muted)",
    color: "var(--color-body)",
  },
};


export default function AgentActivityPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [items, setItems] = useState<AgentActivityItem[]>([]);
  const [posture, setPosture] = useState<AgentPosture | null>(null);
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null);
  const [filter, setFilter] = useState<AgentKind | "all">("all");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [feed, p, fb] = await Promise.allSettled([
        api.agents.activity({ limit: 100 }),
        api.agents.posture(),
        api.feedback.stats(),
      ]);
      if (feed.status === "fulfilled") setItems(feed.value);
      if (p.status === "fulfilled") setPosture(p.value);
      if (fb.status === "fulfilled") setFeedbackStats(fb.value);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered =
    filter === "all" ? items : items.filter((i) => i.kind === filter);

  return (
    <CoverageGate pageSlug="agent-activity" pageLabel="Agent Activity">
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Agent Activity"
        description={
          "Unified feed of every recent run from the four agents. Click " +
          "any row to jump to the detail view that owns it."
        }
        actions={<RefreshButton onClick={load} refreshing={loading} />}
      />

      {/* HIL posture banner */}
      {posture ? <PostureBanner posture={posture} /> : null}

      {/* Triage Quality (moved from /feeds — quality of agent
          decisions belongs alongside the agent activity log, not
          mixed in with feed pipeline health). */}
      <TriageQualityCards stats={feedbackStats} />


      {/* Filter chips */}
      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
        <FilterChip
          active={filter === "all"}
          label="All"
          count={items.length}
          onClick={() => setFilter("all")}
        />
        {(Object.keys(KIND_PRESENTATION) as AgentKind[]).map((k) => (
          <FilterChip
            key={k}
            active={filter === k}
            label={KIND_PRESENTATION[k].label}
            count={items.filter((i) => i.kind === k).length}
            onClick={() => setFilter(k)}
          />
        ))}
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={8} columns={5} />
        ) : filtered.length === 0 ? (
          <div style={{ padding: "40px 24px", textAlign: "center" }}>
            <p style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-body)" }}>
              No agent runs yet
            </p>
            <p style={{ fontSize: "12px", color: "var(--color-muted)", marginTop: "4px" }}>
              Trigger one from the agent-specific pages, or wait for the
              scheduled ticks.
            </p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4 w-[140px]">
                  Agent
                </Th>
                <Th align="left" className="w-[110px]">
                  Status
                </Th>
                <Th align="left">Headline</Th>
                <Th align="left" className="w-[120px]">
                  Severity / focus
                </Th>
                <Th align="right" className="pr-4 w-[100px]">
                  Started
                </Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <ActivityRow
                  key={item.id}
                  item={item}
                  onClick={() => router.push(item.deep_link)}
                />
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
      </CoverageGate>
  );
}

function ActivityRow({
  item,
  onClick,
}: {
  item: AgentActivityItem;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  const k = KIND_PRESENTATION[item.kind];
  const Icon = k.icon;
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "6px",
          height: "22px",
          padding: "0 8px",
          borderRadius: "4px",
          fontSize: "11px",
          fontWeight: 700,
          background: k.bg,
          color: k.color,
        }}>
          <Icon style={{ width: "12px", height: "12px" }} />
          {k.label}
        </span>
      </td>
      <td className="px-3">
        <StatusPill status={item.status} />
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-body)", maxWidth: "420px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {item.headline}
      </td>
      <td className="px-3" style={{ fontSize: "12px", color: "var(--color-body)" }}>
        {item.severity ?? (
          <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>—</span>
        )}
        {item.confidence !== null ? (
          <span style={{ marginLeft: "4px", fontFamily: "monospace", fontSize: "11px", color: "var(--color-muted)" }}>
            ({item.confidence.toFixed(2)})
          </span>
        ) : null}
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(item.created_at)}
      </td>
    </tr>
  );
}

function StatusPill({ status }: { status: AgentActivityItem["status"] }) {
  const Icon = {
    queued: CircleDashed,
    running: Loader2,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<string, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    queued: { background: "var(--color-surface-muted)", color: "var(--color-body)" },
    failed: { background: "rgba(255,86,48,0.08)", color: "#B71D18" },
  };

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "6px",
      height: "22px",
      padding: "0 8px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
      ...styleMap[status],
    }}>
      <Icon style={{ width: "12px", height: "12px" }} className={status === "running" ? "animate-spin" : undefined} />
      {status}
    </span>
  );
}


function FilterChip({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean;
  label: string;
  count: number;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "32px",
        padding: "0 12px",
        borderRadius: "4px",
        border: "none",
        background: active ? "var(--color-border-strong)" : hov ? "var(--color-surface-muted)" : "var(--color-surface)",
        color: active ? "var(--color-on-dark)" : "var(--color-body)",
        fontSize: "12px",
        fontWeight: 700,
        cursor: "pointer",
        transition: "background 0.15s, color 0.15s",
      }}
    >
      {label}
      <span style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth: "18px",
        height: "18px",
        padding: "0 4px",
        borderRadius: "3px",
        fontSize: "10.5px",
        background: active ? "rgba(255,255,255,0.2)" : "var(--color-canvas)",
        color: active ? "var(--color-on-dark)" : "var(--color-body)",
      }}>
        {count}
      </span>
    </button>
  );
}


function PostureBanner({ posture }: { posture: AgentPosture }) {
  const hil = posture.human_in_loop_required;
  const enabledFeatures = Object.entries(posture.features)
    .filter(([, v]) => v)
    .map(([k]) => k);

  if (hil && enabledFeatures.length === 0) {
    return (
      <div
        role="status"
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
          borderRadius: "5px",
          border: "1px solid rgba(0,167,111,0.4)",
          background: "rgba(0,167,111,0.08)",
          padding: "12px 16px",
        }}
      >
        <Lock style={{ width: "20px", height: "20px", marginTop: "2px", color: "#007B55", flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <p style={{ fontSize: "13px", fontWeight: 700, color: "#007B55" }}>
            Human-in-the-loop guard ON
          </p>
          <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "4px" }}>
            No auto-actions will fire from this deployment. Agents propose;
            analysts dispose.{" "}
            <code style={{ fontFamily: "monospace", fontSize: "11.5px" }}>ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED=true</code>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      role="alert"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "12px",
        borderRadius: "5px",
        border: "1px solid rgba(255,86,48,0.4)",
        background: "rgba(255,86,48,0.08)",
        padding: "12px 16px",
      }}
    >
      <AlertTriangle style={{ width: "20px", height: "20px", marginTop: "2px", color: "#B71D18", flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <p style={{ fontSize: "13px", fontWeight: 700, color: "#B71D18" }}>
          {hil
            ? "Auto-action features green-lit but master guard is on (no effect)"
            : "Human-in-the-loop guard OFF"}
        </p>
        <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "4px" }}>
          {hil
            ? "These per-feature flags will activate only when the master guard is set to false: "
            : "The following auto-actions will fire without a human gate: "}
          {enabledFeatures.length > 0
            ? enabledFeatures.map((f) => (
                <code
                  key={f}
                  style={{ marginLeft: "4px", fontFamily: "monospace", fontSize: "11.5px", background: "rgba(255,255,255,0.5)", padding: "0 4px", borderRadius: "3px" }}
                >
                  {f}
                </code>
              ))
            : "(none)"}
        </p>
      </div>
    </div>
  );
}

// Triage Quality — three KPIs that describe how good the AI Triage
// Agent's decisions are, scored against operator-submitted verdicts
// (true positive / false positive / category re-classification). Was
// previously sitting on the Feed Health page where it didn't belong;
// agent quality lives with agent activity.
function TriageQualityCards({ stats }: { stats: FeedbackStats | null }) {
  const tpr = stats ? Math.round((stats.true_positive_rate || 0) * 100) : 0;
  const topCategory = stats?.category_accuracy
    ?.slice()
    .sort((a, b) => b.accuracy - a.accuracy)[0];
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
      <QualityCard
        label="Analyst Feedback"
        value={(stats?.total_feedback ?? 0).toLocaleString()}
        sub="Total triage verdicts submitted"
        emptyHint={!stats || stats.total_feedback === 0
          ? "No feedback yet — open an alert and rate the triage decision to start scoring the agent."
          : undefined}
      />
      <QualityCard
        label="True Positive Rate"
        value={stats ? `${tpr}%` : "—"}
        sub={stats
          ? `${stats.true_positives ?? 0} TP / ${stats.false_positives ?? 0} FP`
          : "Awaiting feedback"}
      />
      <QualityCard
        label="Top Category Accuracy"
        value={topCategory ? topCategory.category : "—"}
        sub={topCategory ? `${Math.round(topCategory.accuracy)}% accuracy` : "No feedback yet"}
      />
    </div>
  );
}

function QualityCard({
  label,
  value,
  sub,
  emptyHint,
}: {
  label: string;
  value: string;
  sub: string;
  emptyHint?: string;
}) {
  return (
    <div
      className="px-4 py-3"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <p
        className="text-[10px] font-semibold uppercase tracking-[0.7px] mb-1"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </p>
      <p
        className="text-[22px] font-medium leading-none tracking-[-0.02em]"
        style={{ color: "var(--color-ink)" }}
      >
        {value}
      </p>
      <p className="text-[11.5px] mt-1.5" style={{ color: "var(--color-muted)" }}>
        {sub}
      </p>
      {emptyHint && (
        <p className="text-[11px] mt-1.5 leading-relaxed" style={{ color: "var(--color-muted)" }}>
          {emptyHint}
        </p>
      )}
    </div>
  );
}
