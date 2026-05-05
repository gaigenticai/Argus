"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Brain,
  CreditCard,
  ExternalLink,
  FileText,
  Globe,
  Lock,
  Plus,
  ScanLine,
  ShieldAlert,
  Sparkles,
  TestTube,
  Trash2,
  Upload,
} from "lucide-react";
import {
  api,
  type AgentSummaryResponse,
  type BinResponse,
  type CardLeakageResponse,
  type DlpFindingResponse,
  type DlpPolicyResponse,
  type FindingClassification,
  type FindingCorrelation,
  type Org,
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
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";

const SEVERITY_TONE: Record<string, StateTone> = {
  critical: "error-strong",
  high: "error",
  medium: "warning",
  low: "info",
  info: "muted",
};

const STATE_TONE: Record<string, StateTone> = {
  open: "neutral",
  confirmed: "error-strong",
  notified: "info",
  reissued: "success",
  remediated: "success",
  false_positive: "muted",
  acknowledged: "info",
  dismissed: "muted",
};

const IMPACT_TONE: Record<string, StateTone> = {
  critical: "error-strong",
  high: "error",
  medium: "warning",
  low: "info",
};

const TABS = ["dlp", "cards", "policies", "bins"] as const;
type TabId = (typeof TABS)[number];

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

const SEVERITY_HIGH_OR_ABOVE = (s: string) =>
  s === "high" || s === "critical";

export default function LeakagePage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window === "undefined") return "dlp";
    const h = window.location.hash.replace("#", "");
    return ((TABS as readonly string[]).includes(h) ? h : "dlp") as TabId;
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const [showSampleScan, setShowSampleScan] = useState(false);
  const refresh = () => setRefreshKey((k) => k + 1);

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

  const switchTab = (next: TabId) => {
    setTab(next);
    const url = new URL(window.location.href);
    url.hash = next === "dlp" ? "" : next;
    window.history.replaceState(null, "", url.toString());
  };

  const tunePolicies = async () => {
    if (!orgId) return;
    try {
      const r = await api.leakage.runPolicyTune(orgId);
      toast(
        "success",
        `Policy tune queued (task ${r.queued_task_id.slice(0, 8)}); suggestions surface in Notifications.`,
      );
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to queue tune");
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Lock, label: "Governance" }}
        title="DLP & Card Leakage"
        description="Customer-supplied DLP regex policies plus a BIN-aware credit-card detector. Findings auto-classify, cross-org correlate, and (HIGH+) auto-promote to Cases."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <button
              onClick={() => setShowSampleScan(true)}
              className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold transition-colors"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Scan a chunk of arbitrary text"
            >
              <ScanLine className="w-3.5 h-3.5" />
              Scan sample
            </button>
            {tab === "policies" && orgId ? (
              <button
                onClick={tunePolicies}
                className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold transition-colors"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-body)",
                }}
                title="Run the regex hygiene agent against a benign corpus"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Tune policies
              </button>
            ) : null}
            <RefreshButton onClick={refresh} refreshing={false} />
          </>
        }
      />

      <div
        className="flex items-center gap-1 -mx-1"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        {(
          [
            ["dlp", "DLP findings", ShieldAlert],
            ["cards", "Card leakage", CreditCard],
            ["policies", "DLP policies", Lock],
            ["bins", "BIN registry", CreditCard],
          ] as const
        ).map(([id, label, Icon]) => {
          const active = tab === id;
          return (
            <button
              key={id}
              onClick={() => switchTab(id as TabId)}
              className="relative h-10 px-3.5 flex items-center gap-2 text-[13px] font-bold whitespace-nowrap transition-colors"
              style={{
                color: active ? "var(--color-ink)" : "var(--color-muted)",
                boxShadow: active
                  ? "rgb(255, 79, 0) 0px -3px 0px 0px inset"
                  : "none",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          );
        })}
      </div>

      <div key={`${orgId}-${tab}-${refreshKey}`}>
        {tab === "dlp" && <DlpFindingsTab orgId={orgId} />}
        {tab === "cards" && <CardLeakageTab orgId={orgId} />}
        {tab === "policies" && (
          <DlpPoliciesTab orgId={orgId} onChange={refresh} />
        )}
        {tab === "bins" && <BinRegistryTab orgId={orgId} onChange={refresh} />}
      </div>

      {showSampleScan && orgId ? (
        <ScanSampleModal
          orgId={orgId}
          onClose={() => setShowSampleScan(false)}
          onCompleted={() => {
            setShowSampleScan(false);
            refresh();
          }}
        />
      ) : null}
    </div>
  );
}

// -- Severity / impact / state chips ---------------------------------

function ImpactChip({
  classification,
}: {
  classification?: FindingClassification | null;
}) {
  if (!classification || !classification.impact_level) return null;
  const tone =
    IMPACT_TONE[classification.impact_level] || ("neutral" as StateTone);
  return (
    <span title={classification.rationale || classification.category}>
      <StatePill
        label={`AGENT · ${classification.impact_level.toUpperCase()}`}
        tone={tone}
      />
    </span>
  );
}

function CrossOrgBanner({
  rows,
  onOpen,
}: {
  rows: Array<{ correlated_findings?: FindingCorrelation | null }>;
  onOpen?: () => void;
}) {
  const correlated = rows.filter(
    (r) => (r.correlated_findings?.distinct_orgs ?? 0) >= 2,
  );
  if (correlated.length === 0) return null;
  const totalOrgs = correlated.reduce(
    (max, r) =>
      Math.max(max, r.correlated_findings?.distinct_orgs ?? 0),
    0,
  );
  return (
    <div
      role="alert"
      className="flex items-start gap-3 px-4 py-3"
      style={{
        borderRadius: "5px",
        border: "1px solid rgba(255,86,48,0.5)",
        background: "rgba(255,86,48,0.06)",
      }}
    >
      <Globe className="w-5 h-5 mt-0.5 shrink-0" style={{ color: "#B71D18" }} />
      <div className="flex-1">
        <p className="text-[13px] font-bold" style={{ color: "#B71D18" }}>
          Cross-org correlation: {correlated.length} finding
          {correlated.length === 1 ? "" : "s"} match leaks observed in other
          tenants
        </p>
        <p
          className="text-[12.5px] mt-0.5"
          style={{ color: "var(--color-body)" }}
        >
          The same secret fingerprint appears in up to {totalOrgs} distinct
          organisations — a probable supply-chain breach. The cross-org
          correlator agent has filed a triaged Alert per origin tenant.
          {onOpen ? (
            <>
              {" "}
              <button
                onClick={onOpen}
                className="underline font-bold"
                style={{ color: "#B71D18" }}
              >
                Open the most-correlated finding
              </button>
              .
            </>
          ) : null}
        </p>
      </div>
    </div>
  );
}

// -- DLP findings -----------------------------------------------------

function DlpFindingsTab({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DlpFindingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [stateFilter, setStateFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [active, setActive] = useState<DlpFindingResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await api.leakage.listDlpFindings({
        organization_id: orgId,
        state: stateFilter === "all" ? undefined : stateFilter,
        severity: severityFilter === "all" ? undefined : severityFilter,
        limit: 200,
      });
      setRows(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load DLP findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, severityFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const openMostCorrelated = () => {
    const target = [...rows].sort(
      (a, b) =>
        (b.correlated_findings?.distinct_orgs ?? 0) -
        (a.correlated_findings?.distinct_orgs ?? 0),
    )[0];
    if (target) setActive(target);
  };

  return (
    <div className="space-y-4">
      <CrossOrgBanner rows={rows} onOpen={openMostCorrelated} />
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            { value: "open", label: "Open" },
            { value: "confirmed", label: "Confirmed" },
            { value: "notified", label: "Notified" },
            { value: "dismissed", label: "Dismissed" },
          ]}
          onChange={setStateFilter}
        />
        <Select
          ariaLabel="Severity"
          value={severityFilter}
          options={[
            { value: "all", label: "Any severity" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
          onChange={setSeverityFilter}
        />
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ShieldAlert}
            title="No DLP findings"
            description="DLP findings are created when a regex policy fires against ingested content (Telegram, news articles, public-page snapshots, pastes)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr
                  style={{
                    background: "var(--color-surface)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  <Th align="left" className="pl-4 w-[110px]">
                    Severity
                  </Th>
                  <Th align="left">Policy</Th>
                  <Th align="left">Source</Th>
                  <Th align="left" className="w-[80px]">
                    Matches
                  </Th>
                  <Th align="left" className="w-[150px]">
                    Agent
                  </Th>
                  <Th align="left" className="w-[110px]">
                    State
                  </Th>
                  <Th align="right" className="pr-4 w-[100px]">
                    Detected
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className="h-12 transition-colors cursor-pointer"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onClick={() => setActive(r)}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background =
                        "var(--color-surface)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background = "transparent")
                    }
                  >
                    <td className="pl-4">
                      <StatePill
                        label={r.severity}
                        tone={SEVERITY_TONE[r.severity] || "neutral"}
                      />
                    </td>
                    <td className="px-3">
                      <div
                        className="text-[13px] font-semibold"
                        style={{ color: "var(--color-ink)" }}
                      >
                        {r.policy_name}
                      </div>
                      {r.matched_excerpts.length > 0 ? (
                        <div
                          className="text-[11px] font-mono line-clamp-1 mt-0.5"
                          style={{ color: "var(--color-muted)" }}
                        >
                          {r.matched_excerpts[0]}
                        </div>
                      ) : null}
                    </td>
                    <td
                      className="px-3 font-mono text-[12px] max-w-[280px] truncate"
                      style={{ color: "var(--color-body)" }}
                    >
                      {r.source_url ? (
                        <a
                          href={r.source_url}
                          target="_blank"
                          rel="noopener noreferrer nofollow"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 transition-colors"
                          style={{ color: "var(--color-body)" }}
                        >
                          {r.source_url}
                          <ExternalLink
                            className="w-3 h-3"
                            style={{ color: "var(--color-muted)" }}
                          />
                        </a>
                      ) : (
                        <span
                          className="italic"
                          style={{ color: "var(--color-muted)" }}
                        >
                          none
                        </span>
                      )}
                    </td>
                    <td
                      className="px-3 font-mono text-[13px] tabular-nums font-bold"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {r.matched_count}
                    </td>
                    <td className="px-3">
                      <ImpactChip classification={r.classification ?? null} />
                      {(r.correlated_findings?.distinct_orgs ?? 0) >= 2 ? (
                        <span className="ml-1.5">
                          <StatePill
                            label={`${r.correlated_findings?.distinct_orgs}× ORGS`}
                            tone="error"
                          />
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3">
                      <StatePill
                        label={r.state}
                        tone={STATE_TONE[r.state] || "neutral"}
                      />
                    </td>
                    <td
                      className="pr-4 text-right font-mono text-[11.5px] tabular-nums"
                      style={{ color: "var(--color-muted)" }}
                    >
                      {timeAgo(r.detected_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {active ? (
        <FindingDrawer
          finding={active}
          kind="dlp"
          onClose={() => setActive(null)}
          onChanged={() => {
            setActive(null);
            load();
          }}
        />
      ) : null}
    </div>
  );
}

// -- Card leakage -----------------------------------------------------

function CardLeakageTab({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<CardLeakageResponse[]>([]);
  const [binCount, setBinCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [active, setActive] = useState<CardLeakageResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [findings, bins] = await Promise.all([
        api.leakage.listCardFindings({
          organization_id: orgId,
          limit: 200,
        }),
        api.leakage.listBins(orgId),
      ]);
      setRows(findings);
      setBinCount(bins.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load card findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const binRegistryEmpty = binCount !== null && binCount === 0;

  return (
    <div className="space-y-4">
      <CrossOrgBanner rows={rows} />
      {binRegistryEmpty ? (
        <div
          role="alert"
          className="flex items-start gap-3 px-4 py-3"
          style={{
            borderRadius: "5px",
            border: "1px solid rgba(255,171,0,0.4)",
            background: "rgba(255,171,0,0.08)",
          }}
        >
          <AlertTriangle
            className="w-5 h-5 mt-0.5 shrink-0"
            style={{ color: "#B76E00" }}
          />
          <div className="flex-1">
            <p
              className="text-[13px] font-bold"
              style={{ color: "#B76E00" }}
            >
              BIN registry is empty — card-leakage detection is high-noise
            </p>
            <p
              className="text-[12.5px] mt-0.5"
              style={{ color: "var(--color-body)" }}
            >
              Without registered issuer prefixes the detector falls back to
              Luhn-only validation. Open the BIN registry tab to upload your
              bank&apos;s ranges as CSV.
            </p>
          </div>
        </div>
      ) : null}

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={CreditCard}
            title="No card leakage findings"
            description="Card findings are created when ingested content matches a registered BIN with a Luhn-valid PAN."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr
                  style={{
                    background: "var(--color-surface)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  <Th align="left" className="pl-4">
                    PAN
                  </Th>
                  <Th align="left">Issuer / scheme</Th>
                  <Th align="left">Source</Th>
                  <Th align="left" className="w-[150px]">
                    Agent
                  </Th>
                  <Th align="left" className="w-[110px]">
                    State
                  </Th>
                  <Th align="right" className="pr-4 w-[100px]">
                    Detected
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className="h-12 transition-colors cursor-pointer"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onClick={() => setActive(r)}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background =
                        "var(--color-surface)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background = "transparent")
                    }
                  >
                    <td
                      className="pl-4 font-mono text-[12.5px] tabular-nums"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {r.pan_first6}
                      <span style={{ color: "var(--color-muted)" }}>
                        ······
                      </span>
                      {r.pan_last4}
                    </td>
                    <td
                      className="px-3 text-[12.5px]"
                      style={{ color: "var(--color-body)" }}
                    >
                      {r.issuer || (
                        <span
                          className="italic"
                          style={{ color: "var(--color-muted)" }}
                        >
                          unknown
                        </span>
                      )}
                      <span
                        className="ml-1.5 text-[10.5px] font-bold uppercase tracking-[0.06em]"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {r.scheme}
                      </span>
                    </td>
                    <td
                      className="px-3 font-mono text-[12px] max-w-[280px] truncate"
                      style={{ color: "var(--color-body)" }}
                    >
                      {r.source_url ? (
                        <a
                          href={r.source_url}
                          target="_blank"
                          rel="noopener noreferrer nofollow"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 transition-colors"
                          style={{ color: "var(--color-body)" }}
                        >
                          {r.source_url}
                          <ExternalLink
                            className="w-3 h-3"
                            style={{ color: "var(--color-muted)" }}
                          />
                        </a>
                      ) : (
                        <span
                          className="italic"
                          style={{ color: "var(--color-muted)" }}
                        >
                          none
                        </span>
                      )}
                    </td>
                    <td className="px-3">
                      <ImpactChip classification={r.classification ?? null} />
                      {(r.correlated_findings?.distinct_orgs ?? 0) >= 2 ? (
                        <span className="ml-1.5">
                          <StatePill
                            label={`${r.correlated_findings?.distinct_orgs}× ORGS`}
                            tone="error"
                          />
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3">
                      <StatePill
                        label={r.state}
                        tone={STATE_TONE[r.state] || "neutral"}
                      />
                    </td>
                    <td
                      className="pr-4 text-right font-mono text-[11.5px] tabular-nums"
                      style={{ color: "var(--color-muted)" }}
                    >
                      {timeAgo(r.detected_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {active ? (
        <FindingDrawer
          finding={active}
          kind="card"
          onClose={() => setActive(null)}
          onChanged={() => {
            setActive(null);
            load();
          }}
        />
      ) : null}
    </div>
  );
}

// -- Finding drawer (state change + agent summary + takedown) --------

type AnyFinding = DlpFindingResponse | CardLeakageResponse;

function FindingDrawer({
  finding,
  kind,
  onClose,
  onChanged,
}: {
  finding: AnyFinding;
  kind: "dlp" | "card";
  onClose: () => void;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const [nextState, setNextState] = useState("notified");
  const [reason, setReason] = useState("");
  const [showTakedown, setShowTakedown] = useState(false);
  const [summary, setSummary] = useState<AgentSummaryResponse | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(true);

  const dlp = kind === "dlp" ? (finding as DlpFindingResponse) : null;
  const card = kind === "card" ? (finding as CardLeakageResponse) : null;

  useEffect(() => {
    let alive = true;
    setLoadingSummary(true);
    api.leakage
      .findingAgentSummary(finding.id, kind)
      .then((s) => {
        if (alive) setSummary(s);
      })
      .catch(() => {
        /* fall through to inline data */
      })
      .finally(() => {
        if (alive) setLoadingSummary(false);
      });
    return () => {
      alive = false;
    };
  }, [finding.id, kind]);

  const transition = async () => {
    if (busy) return;
    if (
      ["notified", "reissued", "dismissed"].includes(nextState) &&
      !reason.trim()
    ) {
      toast("error", "Reason is required for this state");
      return;
    }
    setBusy(true);
    try {
      if (kind === "dlp") {
        await api.leakage.transitionDlpFinding(finding.id, {
          state: nextState,
          reason: reason.trim() || undefined,
        });
      } else {
        await api.leakage.transitionCardFinding(finding.id, {
          state: nextState,
          reason: reason.trim() || undefined,
        });
      }
      toast("success", `Transitioned to ${nextState}`);
      onChanged();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "State change failed");
    } finally {
      setBusy(false);
    }
  };

  const cls = summary?.classification ?? finding.classification ?? null;
  const corr =
    summary?.correlated_findings ?? finding.correlated_findings ?? null;
  const breach =
    summary?.breach_correlations ?? finding.breach_correlations ?? null;
  // Card findings carry no severity field — fall back to medium so the
  // HIGH+ takedown gate still works on classifier verdicts.
  const findingSeverity =
    "severity" in finding && typeof finding.severity === "string"
      ? finding.severity
      : "medium";
  const isHighOrAbove =
    SEVERITY_HIGH_OR_ABOVE(findingSeverity) ||
    (cls && SEVERITY_HIGH_OR_ABOVE(cls.impact_level));

  return (
    <ModalShell
      title={
        dlp
          ? `DLP finding · ${dlp.policy_name}`
          : `Card leak · ${card!.pan_first6}··${card!.pan_last4}`
      }
      onClose={onClose}
      width={720}
    >
      <div className="p-6 space-y-5">
        {/* Top metadata */}
        <div className="grid grid-cols-2 gap-3 text-[12.5px]">
          <div>
            <div
              className="text-[10.5px] font-bold uppercase tracking-[0.08em]"
              style={{ color: "var(--color-muted)" }}
            >
              Severity
            </div>
            <StatePill
              label={findingSeverity}
              tone={SEVERITY_TONE[findingSeverity] || "neutral"}
            />
          </div>
          <div>
            <div
              className="text-[10.5px] font-bold uppercase tracking-[0.08em]"
              style={{ color: "var(--color-muted)" }}
            >
              State
            </div>
            <StatePill
              label={finding.state}
              tone={STATE_TONE[finding.state] || "neutral"}
            />
          </div>
          {finding.source_url ? (
            <div className="col-span-2">
              <div
                className="text-[10.5px] font-bold uppercase tracking-[0.08em]"
                style={{ color: "var(--color-muted)" }}
              >
                Source
              </div>
              <a
                href={finding.source_url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="font-mono text-[12px]"
                style={{ color: "var(--color-accent)" }}
              >
                {finding.source_url}
              </a>
            </div>
          ) : null}
        </div>

        {/* Classification */}
        <Section>
          <div
            className="px-4 py-2 flex items-center gap-2"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <Brain className="w-3.5 h-3.5" style={{ color: "#7B61FF" }} />
            <span
              className="text-[11px] font-bold uppercase tracking-[0.1em]"
              style={{ color: "var(--color-body)" }}
            >
              Agent classification
            </span>
          </div>
          <div className="p-4 text-[12.5px] space-y-2">
            {loadingSummary ? (
              <div style={{ color: "var(--color-muted)" }}>Loading…</div>
            ) : cls ? (
              <>
                <div>
                  <span
                    className="text-[10.5px] font-bold uppercase mr-2"
                    style={{ color: "var(--color-muted)" }}
                  >
                    Category
                  </span>
                  <code
                    className="font-mono text-[12px] px-1.5 py-0.5"
                    style={{
                      borderRadius: "3px",
                      background: "var(--color-surface)",
                      color: "var(--color-ink)",
                    }}
                  >
                    {cls.category}
                  </code>
                  <span className="mx-2" />
                  <span
                    className="text-[10.5px] font-bold uppercase mr-2"
                    style={{ color: "var(--color-muted)" }}
                  >
                    Impact
                  </span>
                  <StatePill
                    label={cls.impact_level}
                    tone={IMPACT_TONE[cls.impact_level] || "neutral"}
                  />
                  <span className="mx-2" />
                  <span
                    className="text-[10.5px] font-bold uppercase mr-2"
                    style={{ color: "var(--color-muted)" }}
                  >
                    Confidence
                  </span>
                  <span className="font-mono tabular-nums">
                    {(cls.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                {cls.compliance && cls.compliance.length > 0 ? (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span
                      className="text-[10.5px] font-bold uppercase"
                      style={{ color: "var(--color-muted)" }}
                    >
                      Compliance
                    </span>
                    {cls.compliance.map((c) => (
                      <code
                        key={c}
                        className="font-mono text-[10.5px] px-1.5 py-0.5"
                        style={{
                          borderRadius: "3px",
                          background: "rgba(123,97,255,0.1)",
                          color: "#5C40D6",
                        }}
                      >
                        {c.toUpperCase()}
                      </code>
                    ))}
                  </div>
                ) : null}
                {cls.rationale ? (
                  <p
                    className="text-[12px] leading-relaxed pt-1"
                    style={{ color: "var(--color-body)" }}
                  >
                    {cls.rationale}
                  </p>
                ) : null}
              </>
            ) : (
              <div style={{ color: "var(--color-muted)" }}>
                No classification yet — the agent will run within ~60s.
              </div>
            )}
          </div>
        </Section>

        {/* Cross-org correlation */}
        {corr && (corr.distinct_orgs ?? 0) >= 2 ? (
          <Section>
            <div
              className="px-4 py-2 flex items-center gap-2"
              style={{ borderBottom: "1px solid var(--color-border)" }}
            >
              <Globe className="w-3.5 h-3.5" style={{ color: "#B71D18" }} />
              <span
                className="text-[11px] font-bold uppercase tracking-[0.1em]"
                style={{ color: "#B71D18" }}
              >
                Cross-org correlation
              </span>
            </div>
            <div className="p-4 text-[12.5px] space-y-2">
              <div>
                Same secret observed in{" "}
                <strong>{corr.distinct_orgs}</strong> distinct organisations
                {corr.matches?.length ? (
                  <>
                    {" "}
                    across <strong>{corr.matches.length}</strong> related
                    findings
                  </>
                ) : null}
                .
              </div>
              {corr.actor_inference?.probable_source ? (
                <p style={{ color: "var(--color-body)" }}>
                  <strong>Probable source:</strong>{" "}
                  {corr.actor_inference.probable_source}
                </p>
              ) : null}
              {corr.actor_inference?.recommended_action ? (
                <p style={{ color: "var(--color-body)" }}>
                  <strong>Action:</strong>{" "}
                  {corr.actor_inference.recommended_action}
                </p>
              ) : null}
            </div>
          </Section>
        ) : null}

        {/* HIBP breach hits */}
        {breach && breach.emails && Object.keys(breach.emails).length > 0 ? (
          <Section>
            <div
              className="px-4 py-2 flex items-center gap-2"
              style={{ borderBottom: "1px solid var(--color-border)" }}
            >
              <ShieldAlert
                className="w-3.5 h-3.5"
                style={{ color: "#B76E00" }}
              />
              <span
                className="text-[11px] font-bold uppercase tracking-[0.1em]"
                style={{ color: "var(--color-body)" }}
              >
                HIBP correlation
              </span>
            </div>
            <div className="p-4 text-[12px] space-y-1.5">
              {Object.entries(breach.emails).map(([email, breaches]) => (
                <div key={email} className="font-mono">
                  <span style={{ color: "var(--color-ink)" }}>{email}</span>
                  <span style={{ color: "var(--color-muted)" }}>
                    {" "}
                    →{" "}
                    {breaches.length === 0
                      ? "no breach record"
                      : breaches.join(", ")}
                  </span>
                </div>
              ))}
            </div>
          </Section>
        ) : null}

        {/* Takedown */}
        {isHighOrAbove ? (
          <Section>
            <div
              className="px-4 py-2 flex items-center justify-between"
              style={{ borderBottom: "1px solid var(--color-border)" }}
            >
              <div className="flex items-center gap-2">
                <FileText
                  className="w-3.5 h-3.5"
                  style={{ color: "var(--color-accent)" }}
                />
                <span
                  className="text-[11px] font-bold uppercase tracking-[0.1em]"
                  style={{ color: "var(--color-body)" }}
                >
                  Takedown notice
                </span>
              </div>
              <button
                onClick={() => setShowTakedown(true)}
                className="inline-flex items-center gap-1 h-7 px-2.5 text-[11px] font-bold"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-accent)",
                  background: "var(--color-accent)",
                  color: "var(--color-on-dark)",
                }}
              >
                {finding.takedown_draft ? "View draft" : "Draft takedown"}
              </button>
            </div>
          </Section>
        ) : null}

        {/* State change */}
        <Section>
          <div
            className="px-4 py-2"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <span
              className="text-[11px] font-bold uppercase tracking-[0.1em]"
              style={{ color: "var(--color-body)" }}
            >
              Change state
            </span>
          </div>
          <div className="p-4 space-y-3">
            <Field label="New state" required>
              <Select
                ariaLabel="New state"
                value={nextState}
                options={[
                  { value: "open", label: "Open" },
                  { value: "confirmed", label: "Confirmed" },
                  { value: "notified", label: "Notified" },
                  { value: "reissued", label: "Reissued" },
                  { value: "dismissed", label: "Dismissed" },
                ]}
                onChange={setNextState}
              />
            </Field>
            <Field
              label="Reason"
              hint="Required when transitioning to notified, reissued, or dismissed"
            >
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 text-[13px] resize-none"
                style={inputStyle}
                placeholder="Notified Bank Y after card reissue request — ticket NOC-1234"
              />
            </Field>
          </div>
        </Section>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={transition}
        submitLabel={busy ? "Saving…" : `Transition to ${nextState}`}
        disabled={busy || nextState === finding.state}
      />
      {showTakedown ? (
        <TakedownDrawer
          findingId={finding.id}
          kind={kind}
          existing={finding.takedown_draft ?? summary?.takedown_draft ?? null}
          onClose={() => setShowTakedown(false)}
        />
      ) : null}
    </ModalShell>
  );
}

// -- Takedown drawer --------------------------------------------------

function TakedownDrawer({
  findingId,
  kind,
  existing,
  onClose,
}: {
  findingId: string;
  kind: "dlp" | "card";
  existing: string | null;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [draft, setDraft] = useState<string>(existing ?? "");
  const [busy, setBusy] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const generate = useCallback(async () => {
    setBusy(true);
    try {
      const r =
        kind === "dlp"
          ? await api.leakage.draftTakedownDlp(findingId)
          : await api.leakage.draftTakedownCard(findingId);
      if (r.status === "ready" && r.draft) {
        setDraft(r.draft);
        setBusy(false);
        return;
      }
      // Poll the agent-summary endpoint until the worker writes the draft.
      pollRef.current = setInterval(async () => {
        try {
          const s = await api.leakage.findingAgentSummary(findingId, kind);
          if (s.takedown_draft && s.takedown_draft.trim().length > 0) {
            setDraft(s.takedown_draft);
            setBusy(false);
            if (pollRef.current) {
              clearInterval(pollRef.current);
              pollRef.current = null;
            }
          }
        } catch {
          /* keep polling */
        }
      }, 4000);
    } catch (e) {
      setBusy(false);
      toast(
        "error",
        e instanceof Error ? e.message : "Takedown draft failed",
      );
    }
  }, [findingId, kind, toast]);

  useEffect(() => {
    if (!existing) {
      generate();
    }
  }, [existing, generate]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(draft);
      toast("success", "Copied to clipboard");
    } catch {
      toast("error", "Clipboard unavailable");
    }
  };

  return (
    <ModalShell title="Takedown notice (Markdown)" onClose={onClose} width={720}>
      <div className="p-6 space-y-4">
        {busy && !draft ? (
          <p
            className="text-[12.5px]"
            style={{ color: "var(--color-muted)" }}
          >
            Drafting via Bridge agent — this typically completes in 10-30
            seconds.
          </p>
        ) : null}
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={20}
          className="w-full px-3 py-2 text-[12px] font-mono resize-vertical"
          style={inputStyle}
          placeholder="The agent will populate this textarea with a DMCA / abuse takedown notice."
        />
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={copy}
        submitLabel="Copy to clipboard"
        disabled={!draft}
      />
    </ModalShell>
  );
}

// -- Sample-scan modal -----------------------------------------------

function ScanSampleModal({
  orgId,
  onClose,
  onCompleted,
}: {
  orgId: string;
  onClose: () => void;
  onCompleted: () => void;
}) {
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    dlp_policies: number;
    dlp_findings: number;
    dlp_matches: number;
    card_candidates: number;
    card_new: number;
    card_seen_again: number;
  } | null>(null);

  const run = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    setResult(null);
    try {
      const [dlp, cards] = await Promise.all([
        api.leakage.runDlpScan({
          organization_id: orgId,
          text,
          source_kind: "sample",
        }),
        api.leakage.runCardScan({
          organization_id: orgId,
          text,
          source_kind: "sample",
          require_bin_match: false,
        }),
      ]);
      setResult({
        dlp_policies: dlp.policies_evaluated,
        dlp_findings: dlp.findings_created,
        dlp_matches: dlp.matches_found,
        card_candidates: cards.candidates,
        card_new: cards.new_findings ?? 0,
        card_seen_again: cards.seen_again ?? cards.duplicates ?? 0,
      });
      if (dlp.findings_created > 0 || (cards.new_findings ?? 0) > 0) {
        toast("success", "New findings created — reload list to inspect");
      }
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Scan sample text" onClose={onClose} width={680}>
      <div className="p-6 space-y-4">
        <p
          className="text-[12.5px]"
          style={{ color: "var(--color-muted)" }}
        >
          Runs every enabled DLP policy and the BIN-aware card detector
          against the text below. New findings persist to this organisation
          and trigger the agentic classifier + cross-org correlator.
        </p>
        <Field label="Text" required>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={10}
            className="w-full px-3 py-2 text-[12px] font-mono resize-none"
            style={inputStyle}
            placeholder={
              "Paste a chunk of suspicious content. Include credit cards, emails, secrets — whatever you want to test against your policies."
            }
            autoFocus
          />
        </Field>
        {result ? (
          <Section>
            <div className="p-4 grid grid-cols-2 gap-3 text-[12.5px]">
              <div>
                <div
                  className="text-[10.5px] font-bold uppercase"
                  style={{ color: "var(--color-muted)" }}
                >
                  DLP
                </div>
                <div className="font-mono">
                  {result.dlp_policies} policies · {result.dlp_findings} new ·{" "}
                  {result.dlp_matches} matches
                </div>
              </div>
              <div>
                <div
                  className="text-[10.5px] font-bold uppercase"
                  style={{ color: "var(--color-muted)" }}
                >
                  Cards
                </div>
                <div className="font-mono">
                  {result.card_candidates} candidates · {result.card_new} new ·{" "}
                  {result.card_seen_again} dupes
                </div>
              </div>
            </div>
          </Section>
        ) : null}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={result ? onCompleted : run}
        submitLabel={busy ? "Scanning…" : result ? "Done" : "Scan"}
        disabled={(!result && !text.trim()) || busy}
      />
    </ModalShell>
  );
}

// -- DLP policies (unchanged behaviour, kept minimal) ----------------

function DlpPoliciesTab({
  orgId,
  onChange,
}: {
  orgId: string;
  onChange: () => void;
}) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DlpPolicyResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [testing, setTesting] = useState<DlpPolicyResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      setRows(await api.leakage.listDlpPolicies(orgId));
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load DLP policies",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const remove = async (p: DlpPolicyResponse) => {
    if (!confirm(`Delete DLP policy "${p.name}"?`)) return;
    try {
      await api.leakage.deleteDlpPolicy(p.id);
      toast("success", "Policy deleted");
      onChange();
      load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Delete failed");
    }
  };

  return (
    <CoverageGate pageSlug="leakage" pageLabel="DLP & Leakage">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <p
            className="text-[12px] font-mono tabular-nums"
            style={{ color: "var(--color-muted)" }}
          >
            {rows.length} polic{rows.length === 1 ? "y" : "ies"}
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            New policy
          </button>
        </div>

        <Section>
          {loading ? (
            <SkeletonRows rows={4} columns={5} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Lock}
              title="No DLP policies"
              description="Create regex policies to flag PII, secrets, source-code references in ingested content. Each policy is timeout-bounded by the ReDoS guard (Audit B8)."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr
                    style={{
                      background: "var(--color-surface)",
                      borderBottom: "1px solid var(--color-border)",
                    }}
                  >
                    <Th align="left" className="pl-4 w-[110px]">
                      Severity
                    </Th>
                    <Th align="left">Name</Th>
                    <Th align="left">Pattern</Th>
                    <Th align="left" className="w-[100px]">
                      Kind
                    </Th>
                    <Th align="left" className="w-[100px]">
                      Status
                    </Th>
                    <Th align="right" className="pr-4 w-[140px]">
                      &nbsp;
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((p) => (
                    <tr
                      key={p.id}
                      className="h-12 transition-colors"
                      style={{
                        borderBottom: "1px solid var(--color-border)",
                      }}
                    >
                      <td className="pl-4">
                        <StatePill
                          label={p.severity}
                          tone={SEVERITY_TONE[p.severity] || "neutral"}
                        />
                      </td>
                      <td className="px-3">
                        <div
                          className="text-[13px] font-semibold"
                          style={{ color: "var(--color-ink)" }}
                        >
                          {p.name}
                        </div>
                        {p.description ? (
                          <div
                            className="text-[11px] line-clamp-1 mt-0.5"
                            style={{ color: "var(--color-muted)" }}
                          >
                            {p.description}
                          </div>
                        ) : null}
                      </td>
                      <td
                        className="px-3 font-mono text-[11.5px] max-w-[300px] truncate"
                        style={{ color: "var(--color-body)" }}
                      >
                        {p.pattern}
                      </td>
                      <td className="px-3">
                        <span
                          className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]"
                          style={{
                            borderRadius: "4px",
                            background: "var(--color-surface-muted)",
                            color: "var(--color-body)",
                          }}
                        >
                          {p.kind.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-3">
                        {p.enabled ? (
                          <StatePill label="ENABLED" tone="success" />
                        ) : (
                          <StatePill label="DISABLED" tone="muted" />
                        )}
                      </td>
                      <td className="pr-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => setTesting(p)}
                            className="inline-flex items-center gap-1 h-7 px-2 text-[11px] font-bold"
                            style={{
                              borderRadius: "4px",
                              border: "1px solid var(--color-border)",
                              background: "var(--color-canvas)",
                              color: "var(--color-body)",
                            }}
                          >
                            <TestTube className="w-3 h-3" />
                            TEST
                          </button>
                          <button
                            onClick={() => remove(p)}
                            className="p-1.5"
                            style={{
                              borderRadius: "4px",
                              color: "var(--color-muted)",
                            }}
                            aria-label="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {showCreate && (
          <CreatePolicyModal
            orgId={orgId}
            onClose={() => setShowCreate(false)}
            onCreated={() => {
              setShowCreate(false);
              load();
              onChange();
            }}
          />
        )}
        {testing && (
          <TestPolicyModal
            policy={testing}
            onClose={() => setTesting(null)}
          />
        )}
      </div>
    </CoverageGate>
  );
}

function CreatePolicyModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [kind, setKind] = useState("regex");
  const [pattern, setPattern] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!name.trim() || !pattern.trim() || busy) return;
    setBusy(true);
    try {
      await api.leakage.createDlpPolicy({
        organization_id: orgId,
        name: name.trim(),
        kind,
        pattern,
        severity,
        description: description.trim() || undefined,
        enabled: true,
      });
      toast("success", `Policy "${name.trim()}" created`);
      onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Create DLP policy" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="customer-email-regex"
            autoFocus
          />
        </Field>
        <Field
          label="Pattern"
          required
          hint="Python re. ReDoS-bounded; nested quantifiers are statically rejected."
        >
          <textarea
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="\\b[A-Za-z0-9._%+-]+@argusbank\\.demo\\b"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Kind" required>
            <Select
              ariaLabel="Kind"
              value={kind}
              options={[
                { value: "regex", label: "Regex" },
                { value: "keyword", label: "Keyword" },
                { value: "yara", label: "YARA" },
              ]}
              onChange={setKind}
            />
          </Field>
          <Field label="Severity" required>
            <Select
              ariaLabel="Severity"
              value={severity}
              options={[
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ]}
              onChange={setSeverity}
            />
          </Field>
        </div>
        <Field label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="What this policy catches and why it matters."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Creating…" : "Create"}
        disabled={!name.trim() || !pattern.trim() || busy}
      />
    </ModalShell>
  );
}

function TestPolicyModal({
  policy,
  onClose,
}: {
  policy: DlpPolicyResponse;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [result, setResult] = useState<{
    matched: number;
    excerpts: string[];
    duration_ms: number;
  } | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    try {
      const r = await api.leakage.testDlpPolicy(policy.id, text);
      setResult(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title={`Test ${policy.name}`} onClose={onClose} width={600}>
      <div className="p-6 space-y-5">
        <Field label="Pattern" hint="Read-only. Edit the policy to change.">
          <pre
            className="px-3 py-2 text-[12px] font-mono overflow-x-auto"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-surface)",
              color: "var(--color-body)",
            }}
          >
            {policy.pattern}
          </pre>
        </Field>
        <Field label="Sample text" required>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={6}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="Paste content to evaluate against the regex…"
            autoFocus
          />
        </Field>
        {result ? (
          <Section>
            <div
              className="px-4 py-3 flex items-center justify-between"
              style={{ borderBottom: "1px solid var(--color-border)" }}
            >
              <span
                className="text-[12px] font-bold uppercase tracking-[0.1em]"
                style={{ color: "var(--color-body)" }}
              >
                Result
              </span>
              <span
                className="font-mono text-[11.5px] tabular-nums"
                style={{ color: "var(--color-muted)" }}
              >
                {Number(result.duration_ms).toFixed(1)}ms
              </span>
            </div>
            <div className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <span
                  className="font-mono text-[14px] font-extrabold tabular-nums"
                  style={{
                    color: result.matched > 0 ? "#FF5630" : "#007B55",
                  }}
                >
                  {result.matched}
                </span>
                <span
                  className="text-[12px]"
                  style={{ color: "var(--color-body)" }}
                >
                  match{result.matched === 1 ? "" : "es"}
                </span>
              </div>
              {result.excerpts.length > 0 ? (
                <ul className="space-y-1">
                  {result.excerpts.map((x, i) => (
                    <li
                      key={i}
                      className="font-mono text-[11.5px] px-2 py-1 truncate"
                      style={{
                        borderRadius: "4px",
                        border: "1px solid rgba(255,171,0,0.3)",
                        background: "rgba(255,171,0,0.06)",
                        color: "var(--color-body)",
                      }}
                    >
                      {x}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </Section>
        ) : null}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={run}
        submitLabel={busy ? "Running…" : "Test"}
        disabled={!text.trim() || busy}
      />
    </ModalShell>
  );
}

// -- BIN registry tab (with CSV import button) -----------------------

function BinRegistryTab({
  orgId,
  onChange,
}: {
  orgId: string;
  onChange: () => void;
}) {
  const { toast } = useToast();
  const [rows, setRows] = useState<BinResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await api.leakage.listBins(orgId || undefined));
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load BINs");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true);
    try {
      const r = await api.leakage.importBins(orgId || undefined, file);
      const errCount = r.errors?.length ?? 0;
      toast(
        errCount === 0 ? "success" : "warning",
        `Imported ${r.inserted} BIN${r.inserted === 1 ? "" : "s"}; ${r.skipped_duplicates} duplicate${r.skipped_duplicates === 1 ? "" : "s"} skipped${
          errCount > 0 ? `; ${errCount} row error${errCount === 1 ? "" : "s"}` : ""
        }`,
      );
      onChange();
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          BINs in the registry drive the card-leakage detector — only PANs
          whose prefix matches a registered BIN are flagged as issuer-confirmed.
          Required CSV columns:{" "}
          <code className="font-mono">
            bin_prefix,issuer,scheme,card_type,country_code
          </code>
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".csv,text/csv"
          onChange={onFile}
          className="hidden"
        />
        <button
          onClick={() => fileRef.current?.click()}
          disabled={importing}
          className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold whitespace-nowrap"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-accent)",
            background: importing ? "var(--color-surface)" : "var(--color-accent)",
            color: importing ? "var(--color-muted)" : "var(--color-on-dark)",
            opacity: importing ? 0.6 : 1,
          }}
        >
          <Upload className="w-3.5 h-3.5" />
          {importing ? "Importing…" : "Import CSV"}
        </button>
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={CreditCard}
            title="No BINs registered"
            description="Click 'Import CSV' to upload a comma-separated file with bin_prefix, issuer, scheme, card_type, country_code columns."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr
                  style={{
                    background: "var(--color-surface)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  <Th align="left" className="pl-4 w-[120px]">
                    Prefix
                  </Th>
                  <Th align="left">Issuer</Th>
                  <Th align="left" className="w-[100px]">
                    Scheme
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Type
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Country
                  </Th>
                  <Th align="right" className="pr-4 w-[120px]">
                    Added
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <tr
                    key={b.id}
                    className="h-11"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                  >
                    <td
                      className="pl-4 font-mono text-[12.5px] tabular-nums"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {b.bin_prefix}
                    </td>
                    <td
                      className="px-3 text-[12.5px]"
                      style={{ color: "var(--color-body)" }}
                    >
                      {b.issuer || (
                        <span
                          className="italic"
                          style={{ color: "var(--color-muted)" }}
                        >
                          unknown
                        </span>
                      )}
                    </td>
                    <td className="px-3">
                      <span
                        className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]"
                        style={{
                          borderRadius: "4px",
                          background: "var(--color-surface-muted)",
                          color: "var(--color-body)",
                        }}
                      >
                        {b.scheme.toUpperCase()}
                      </span>
                    </td>
                    <td
                      className="px-3 text-[12px]"
                      style={{ color: "var(--color-body)" }}
                    >
                      {b.card_type}
                    </td>
                    <td
                      className="px-3 font-mono text-[12px] tabular-nums"
                      style={{ color: "var(--color-body)" }}
                    >
                      {b.country_code || "—"}
                    </td>
                    <td
                      className="pr-4 text-right font-mono text-[11.5px] tabular-nums"
                      style={{ color: "var(--color-muted)" }}
                    >
                      {timeAgo(b.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
