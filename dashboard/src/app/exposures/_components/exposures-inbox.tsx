"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ExternalLink, ShieldAlert, Flame, Sparkles, Clock, Network } from "lucide-react";
import {
  api,
  type ExposureResponse,
  type ExposureSeverityValue,
  type ExposureStateValue,
  type RemediationAction,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  PaginationFooter,
  SearchInput,
  Section,
  Select,
  SkeletonRows,
  SevPill,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useExposuresContext } from "./use-exposures-context";

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: "40px",
  padding: "0 12px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  fontSize: "13px",
  outline: "none",
};

const STATES: ExposureStateValue[] = [
  "open",
  "acknowledged",
  "accepted_risk",
  "false_positive",
  "fixed",
  "reopened",
];
const STATE_LABEL: Record<ExposureStateValue, string> = {
  open: "OPEN",
  acknowledged: "ACKED",
  accepted_risk: "ACCEPTED",
  false_positive: "FALSE +VE",
  fixed: "FIXED",
  reopened: "REOPENED",
};
const STATE_TONE: Record<ExposureStateValue, StateTone> = {
  open: "neutral",
  acknowledged: "info",
  accepted_risk: "muted",
  false_positive: "muted",
  fixed: "success",
  reopened: "warning",
};

const SEV_STRIPE: Record<string, string> = {
  critical: "#FF5630",
  high: "#FF8A65",
  medium: "#FFAB00",
  low: "#00B8D9",
  info: "var(--color-border)",
};

const CVSS_COLOR = (score: number) =>
  score >= 9 ? "#FF5630" : score >= 7 ? "#B71D18" : score >= 4 ? "#B76E00" : "var(--color-body)";

const AGE_TONE = (days: number | null): { color: string; label: string } | null => {
  if (days === null) return null;
  if (days >= 180) return { color: "#B71D18", label: `${days}d open` };
  if (days >= 90) return { color: "#B76E00", label: `${days}d open` };
  return null;
};

const SORT_OPTIONS = [
  { value: "last_seen", label: "Last seen" },
  { value: "matched", label: "First matched" },
  { value: "age", label: "Oldest first" },
  { value: "severity", label: "Severity" },
  { value: "cvss", label: "CVSS" },
  { value: "epss", label: "EPSS exploit prob." },
  { value: "priority", label: "AI priority" },
] as const;
type SortKey = (typeof SORT_OPTIONS)[number]["value"];

const REMEDIATION_OPTIONS: { value: RemediationAction; label: string }[] = [
  { value: "patched", label: "Patched" },
  { value: "mitigated", label: "Mitigated (compensating control)" },
  { value: "waived", label: "Waived (risk accepted)" },
  { value: "blocked", label: "Blocked at WAF/firewall" },
  { value: "false_positive", label: "False positive" },
  { value: "other", label: "Other" },
];

const PAGE_LIMIT = 50;

export function ExposuresInbox() {
  const { orgId } = useExposuresContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<ExposureResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState<ExposureSeverityValue | "all">("all");
  const [state, setState] = useState<ExposureStateValue | "all">("all");
  const [search, setSearch] = useState("");
  const [cve, setCve] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("priority");
  const [triaging, setTriaging] = useState(false);
  const [loading, setLoading] = useState(true);
  const [transitionTarget, setTransitionTarget] =
    useState<ExposureResponse | null>(null);
  const [selected, setSelected] = useState<ExposureResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.easm.listExposures({
        organization_id: orgId,
        severity: severity === "all" ? undefined : severity,
        state: state === "all" ? undefined : state,
        q: search || undefined,
        cve: cve || undefined,
        is_kev: kevOnly ? true : undefined,
        sort,
        limit: PAGE_LIMIT,
        offset,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load exposures",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, severity, state, search, cve, kevOnly, sort, offset, toast]);

  const triageAll = async () => {
    if (!orgId || triaging) return;
    setTriaging(true);
    try {
      const r = await api.easm.triageExposures(orgId);
      toast("success", `AI triaged ${r.triaged_count} exposures`);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Triage failed",
      );
    } finally {
      setTriaging(false);
    }
  };

  useEffect(() => {
    load();
  }, [load]);

  const transition = async (
    target: ExposureResponse,
    to: ExposureStateValue,
    payload: {
      reason: string;
      remediation_action?: RemediationAction;
      remediation_patch_version?: string;
      remediation_owner?: string;
      remediation_notes?: string;
    },
  ) => {
    try {
      await api.easm.transitionExposure(target.id, {
        state: to,
        reason: payload.reason || undefined,
        remediation_action: payload.remediation_action,
        remediation_patch_version: payload.remediation_patch_version || undefined,
        remediation_owner: payload.remediation_owner || undefined,
        remediation_notes: payload.remediation_notes || undefined,
      });
      toast("success", `Exposure → ${STATE_LABEL[to]}`);
      setTransitionTarget(null);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to transition",
      );
    }
  };

  const filterCount = useMemo(
    () =>
      [
        severity !== "all",
        state !== "all",
        search !== "",
        cve !== "",
        kevOnly,
      ].filter(Boolean).length,
    [severity, state, search, cve, kevOnly],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput
          value={search}
          onChange={(v) => {
            setSearch(v);
            setOffset(0);
          }}
          placeholder="Search by title or target…"
          shortcut=""
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
            { value: "info", label: "Info" },
          ]}
          onChange={(v) => {
            setSeverity(v as ExposureSeverityValue | "all");
            setOffset(0);
          }}
        />
        <Select
          ariaLabel="State"
          value={state}
          options={[
            { value: "all", label: "Any state" },
            ...STATES.map((s) => ({ value: s, label: STATE_LABEL[s] })),
          ]}
          onChange={(v) => {
            setState(v as ExposureStateValue | "all");
            setOffset(0);
          }}
        />
        <input
          value={cve}
          onChange={(e) => {
            setCve(e.target.value);
            setOffset(0);
          }}
          placeholder="CVE-…"
          style={{ ...inputStyle, width: "140px", fontFamily: "monospace", fontSize: "12px" }}
        />
        <button
          onClick={() => {
            setKevOnly((v) => !v);
            setOffset(0);
          }}
          aria-pressed={kevOnly}
          title="CISA KEV catalog — actively exploited in the wild"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            height: "40px",
            padding: "0 12px",
            borderRadius: "4px",
            border: kevOnly
              ? "1px solid #B71D18"
              : "1px solid var(--color-border)",
            background: kevOnly ? "rgba(255,86,48,0.1)" : "var(--color-canvas)",
            color: kevOnly ? "#B71D18" : "var(--color-body)",
            fontSize: "12px",
            fontWeight: 700,
            cursor: "pointer",
          }}
        >
          <Flame style={{ width: "14px", height: "14px" }} />
          KEV
        </button>
        <Select
          ariaLabel="Sort"
          value={sort}
          options={SORT_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
          onChange={(v) => {
            setSort(v as SortKey);
            setOffset(0);
          }}
        />
        <button
          onClick={triageAll}
          disabled={triaging || rows.length === 0}
          title="Run AI triage agent — ranks open exposures by EPSS × CVSS × KEV × asset criticality"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            height: "40px",
            padding: "0 12px",
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
            fontSize: "12px",
            fontWeight: 700,
            cursor: triaging ? "wait" : "pointer",
            opacity: triaging || rows.length === 0 ? 0.6 : 1,
          }}
        >
          <Sparkles style={{ width: "14px", height: "14px" }} />
          {triaging ? "Triaging…" : "AI triage"}
        </button>
        {filterCount > 0 ? (
          <button
            onClick={() => {
              setSeverity("all");
              setState("all");
              setSearch("");
              setCve("");
              setKevOnly(false);
              setOffset(0);
            }}
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

      <Section>
        {loading ? (
          <SkeletonRows rows={10} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ShieldAlert}
            title={
              filterCount > 0
                ? "No exposures match these filters"
                : "No exposures recorded yet"
            }
            description={
              filterCount > 0
                ? "Widen the filters or clear them to see all open exposures."
                : "Run a discovery scan, then promote findings into Exposures. EASM workers tick automatically against the Asset Registry."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <th className="w-1 p-0" />
                  <Th align="left" className="pl-4 w-[88px]">
                    Sev
                  </Th>
                  <Th align="left">Title</Th>
                  <Th align="left">Target</Th>
                  <Th align="left" className="w-[88px]">
                    <span title="CVSS / EPSS exploit probability">Risk</span>
                  </Th>
                  <Th align="left" className="w-[110px]">
                    <span title="KEV / age / blast radius">Signals</span>
                  </Th>
                  <Th align="left" className="w-[140px]">
                    State
                  </Th>
                  <Th align="left" className="w-[110px]">
                    <span title="AI triage priority (0-100)">AI</span>
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Last seen
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <ExposureRow
                    key={e.id}
                    e={e}
                    onSelect={() => setSelected(e)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && rows.length > 0 ? (
          <PaginationFooter
            total={total}
            limit={PAGE_LIMIT}
            offset={offset}
            shown={rows.length}
            onPrev={() => setOffset((o) => Math.max(0, o - PAGE_LIMIT))}
            onNext={() => setOffset((o) => o + PAGE_LIMIT)}
          />
        ) : null}
      </Section>

      {selected && (
        <ExposureDrawer
          exposure={selected}
          onClose={() => setSelected(null)}
          onTransition={() => {
            setTransitionTarget(selected);
            setSelected(null);
          }}
        />
      )}
      {transitionTarget && (
        <ExposureStateModal
          target={transitionTarget}
          onClose={() => setTransitionTarget(null)}
          onSubmit={(to, payload) => transition(transitionTarget, to, payload)}
        />
      )}
    </div>
  );
}

function ExposureRow({
  e,
  onSelect,
}: {
  e: ExposureResponse;
  onSelect: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const stripeColor = SEV_STRIPE[e.severity] || "var(--color-border)";
  return (
    <tr
      onClick={onSelect}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="p-0">
        <div style={{ width: "3px", height: "48px", background: stripeColor }} />
      </td>
      <td className="px-3 pl-4">
        <SevPill severity={e.severity} />
      </td>
      <td className="px-3">
        <div style={{ fontSize: "13.5px", fontWeight: 600, color: "var(--color-ink)" }} className="line-clamp-1">
          {e.title}
        </div>
        <div style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
          {e.cve_ids.length > 0 ? (
            <span style={{ fontFamily: "monospace" }}>
              {e.cve_ids.slice(0, 2).join(", ")}
              {e.cve_ids.length > 2 ? ` +${e.cve_ids.length - 2}` : ""}
            </span>
          ) : (
            <span style={{ color: "var(--color-muted)" }}>no CVE</span>
          )}
        </div>
      </td>
      <td style={{ padding: "0 12px", fontFamily: "monospace", fontSize: "12px", color: "var(--color-body)", maxWidth: "280px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {e.target}
      </td>
      <td className="px-3">
        <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
          {e.cvss_score !== null ? (
            <span style={{
              fontFamily: "monospace",
              fontSize: "12px",
              fontWeight: 700,
              color: CVSS_COLOR(e.cvss_score),
            }}>
              CVSS {e.cvss_score.toFixed(1)}
            </span>
          ) : (
            <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>CVSS —</span>
          )}
          {e.epss_score !== null ? (
            <span
              style={{ fontSize: "10px", color: "var(--color-muted)", fontFamily: "monospace" }}
              title={`EPSS ${(e.epss_score * 100).toFixed(2)}% (${e.epss_percentile !== null ? `p${(e.epss_percentile * 100).toFixed(0)}` : "—"})`}
            >
              EPSS {(e.epss_score * 100).toFixed(0)}%
            </span>
          ) : null}
        </div>
      </td>
      <td className="px-3">
        <ExposureSignals e={e} />
      </td>
      <td className="px-3">
        <StatePill
          label={STATE_LABEL[e.state]}
          tone={STATE_TONE[e.state]}
        />
      </td>
      <td className="px-3">
        <AiPriorityCell e={e} />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(e.last_seen_at)}
      </td>
    </tr>
  );
}

function ExposureSignals({ e }: { e: ExposureResponse }) {
  const ageTone = AGE_TONE(e.age_days);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
      {e.is_kev ? (
        <span
          title={
            e.kev_added_at
              ? `CISA KEV — exploited since ${new Date(e.kev_added_at).toISOString().slice(0, 10)}`
              : "CISA KEV — exploited in the wild"
          }
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "3px",
            height: "18px",
            padding: "0 5px",
            borderRadius: "3px",
            background: "rgba(255,86,48,0.12)",
            color: "#B71D18",
            fontSize: "10px",
            fontWeight: 800,
            letterSpacing: "0.04em",
          }}
        >
          <Flame style={{ width: "10px", height: "10px" }} />
          KEV
        </span>
      ) : null}
      {ageTone ? (
        <span
          title={`First matched ${e.age_days} days ago — still open`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "3px",
            height: "18px",
            padding: "0 5px",
            borderRadius: "3px",
            background: `${ageTone.color}15`,
            color: ageTone.color,
            fontSize: "10px",
            fontWeight: 700,
            fontFamily: "monospace",
          }}
        >
          <Clock style={{ width: "10px", height: "10px" }} />
          {ageTone.label}
        </span>
      ) : null}
      {e.blast_radius && e.blast_radius > 0 ? (
        <span
          title={`${e.blast_radius} other open exposures share a CVE with this one`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "3px",
            height: "18px",
            padding: "0 5px",
            borderRadius: "3px",
            background: "var(--color-surface-muted)",
            color: "var(--color-body)",
            fontSize: "10px",
            fontWeight: 700,
            fontFamily: "monospace",
          }}
        >
          <Network style={{ width: "10px", height: "10px" }} />×{e.blast_radius}
        </span>
      ) : null}
      {e.ai_suggest_dismiss ? (
        <span
          title={e.ai_dismiss_reason || "AI suggests this is a false positive"}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "3px",
            height: "18px",
            padding: "0 5px",
            borderRadius: "3px",
            background: "rgba(0,184,217,0.1)",
            color: "#0066CC",
            fontSize: "10px",
            fontWeight: 700,
          }}
        >
          AI: dismiss?
        </span>
      ) : null}
    </div>
  );
}

function AiPriorityCell({ e }: { e: ExposureResponse }) {
  if (e.ai_priority === null || e.ai_priority === undefined) {
    return <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>—</span>;
  }
  const v = Math.round(e.ai_priority);
  const color = v >= 80 ? "#FF5630" : v >= 60 ? "#B76E00" : v >= 40 ? "#0091FF" : "var(--color-body)";
  return (
    <div
      title={e.ai_rationale || `AI priority score ${v}/100`}
      style={{ display: "flex", alignItems: "center", gap: "6px" }}
    >
      <Sparkles style={{ width: "11px", height: "11px", color }} />
      <span style={{ fontFamily: "monospace", fontSize: "12px", fontWeight: 700, color }}>
        {v}
      </span>
      <div
        style={{
          flex: 1,
          height: "3px",
          minWidth: "20px",
          maxWidth: "40px",
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
            background: color,
          }}
        />
      </div>
    </div>
  );
}

function ExposureDrawer({
  exposure,
  onClose,
  onTransition,
}: {
  exposure: ExposureResponse;
  onClose: () => void;
  onTransition: () => void;
}) {
  const [targetHov, setTargetHov] = useState(false);
  const [refHovIdx, setRefHovIdx] = useState<number | null>(null);
  const [transHov, setTransHov] = useState(false);
  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: "rgba(32,21,21,0.4)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--color-canvas)",
          width: "100%",
          maxWidth: "720px",
          height: "100%",
          overflowY: "auto",
        }}
        onClick={(ev) => ev.stopPropagation()}
        role="dialog"
      >
        <div
          className="px-6 py-5 sticky top-0 z-10 flex items-center justify-between gap-3"
          style={{ borderBottom: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
        >
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SevPill severity={exposure.severity} />
              <StatePill
                label={STATE_LABEL[exposure.state]}
                tone={STATE_TONE[exposure.state]}
              />
              <span style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-muted)" }}>
                {exposure.rule_id}
              </span>
            </div>
            <h2 style={{ fontSize: "17px", fontWeight: 700, color: "var(--color-ink)", lineHeight: 1.3 }} className="truncate">
              {exposure.title}
            </h2>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={onTransition}
              onMouseEnter={() => setTransHov(true)}
              onMouseLeave={() => setTransHov(false)}
              style={{
                height: "36px",
                padding: "0 12px",
                borderRadius: "4px",
                fontSize: "12px",
                fontWeight: 700,
                background: transHov ? "#e64600" : "var(--color-accent)",
                color: "var(--color-on-dark)",
                border: "none",
                cursor: "pointer",
                transition: "background 0.15s",
              }}
            >
              Transition state
            </button>
            <button
              onClick={onClose}
              style={{
                height: "36px",
                width: "36px",
                borderRadius: "4px",
                border: "none",
                background: "none",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--color-body)",
                cursor: "pointer",
                fontSize: "18px",
              }}
              aria-label="Close"
            >
              ×
            </button>
          </div>
        </div>

        <div className="p-6 space-y-5">
          {/* Top banner row — KEV / age danger / AI dismiss / orphan asset */}
          <DrawerBanners exposure={exposure} />

          <Detail label="Target">
            <a
              href={
                exposure.target.startsWith("http")
                  ? exposure.target
                  : `http://${exposure.target}`
              }
              target="_blank"
              rel="noopener noreferrer nofollow"
              onMouseEnter={() => setTargetHov(true)}
              onMouseLeave={() => setTargetHov(false)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                fontFamily: "monospace",
                fontSize: "13px",
                color: targetHov ? "var(--color-accent)" : "var(--color-ink)",
                wordBreak: "break-all",
                transition: "color 0.15s",
              }}
            >
              {exposure.target}
              <ExternalLink style={{ width: "12px", height: "12px", color: "var(--color-muted)", flexShrink: 0 }} />
            </a>
            {exposure.asset_value ? (
              <div style={{ marginTop: "4px", fontSize: "11.5px", color: "var(--color-muted)" }}>
                Linked asset:{" "}
                <span style={{ fontFamily: "monospace", color: "var(--color-body)" }}>
                  {exposure.asset_value}
                </span>
                {exposure.asset_criticality ? (
                  <span style={{ marginLeft: "6px", textTransform: "uppercase", fontSize: "10px" }}>
                    · {exposure.asset_criticality}
                  </span>
                ) : null}
              </div>
            ) : null}
          </Detail>
          {exposure.description ? (
            <Detail label="Description">
              <p style={{ fontSize: "13px", color: "var(--color-body)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                {exposure.description}
              </p>
            </Detail>
          ) : null}

          <div className="grid grid-cols-2 gap-x-6 gap-y-4">
            <Detail label="Category">
              <span style={{
                display: "inline-flex",
                alignItems: "center",
                height: "20px",
                padding: "0 6px",
                borderRadius: "4px",
                background: "var(--color-surface-muted)",
                fontSize: "10.5px",
                fontWeight: 700,
                letterSpacing: "0.06em",
                color: "var(--color-body)",
              }}>
                {exposure.category.replace(/_/g, " ").toUpperCase()}
              </span>
            </Detail>
            <Detail label="Source">
              <span style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-body)" }}>
                {exposure.source}
              </span>
            </Detail>
            <Detail label="CVSS">
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: "14px",
                  fontWeight: 700,
                  color:
                    exposure.cvss_score !== null
                      ? CVSS_COLOR(exposure.cvss_score)
                      : "var(--color-muted)",
                }}
              >
                {exposure.cvss_score?.toFixed(1) ?? "—"}
              </span>
            </Detail>
            <Detail label="EPSS exploit probability">
              {exposure.epss_score !== null ? (
                <span style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
                  {(exposure.epss_score * 100).toFixed(2)}%
                  {exposure.epss_percentile !== null ? (
                    <span style={{ marginLeft: "6px", color: "var(--color-muted)", fontWeight: 500 }}>
                      p{(exposure.epss_percentile * 100).toFixed(0)}
                    </span>
                  ) : null}
                </span>
              ) : (
                <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
              )}
            </Detail>
            <Detail label="Occurrences">
              <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 700, color: "var(--color-ink)" }}>
                {exposure.occurrence_count}
              </span>
            </Detail>
            <Detail label="Blast radius">
              <span
                style={{ fontFamily: "monospace", fontSize: "13px", color: "var(--color-body)" }}
                title="Other open exposures sharing a CVE with this one"
              >
                {exposure.blast_radius && exposure.blast_radius > 0
                  ? `${exposure.blast_radius} related open`
                  : "isolated"}
              </span>
            </Detail>
            <Detail label="First matched">
              <span style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
                {timeAgo(exposure.matched_at)}
                {exposure.age_days !== null ? (
                  <span style={{ marginLeft: "6px", color: "var(--color-muted)" }}>
                    · {exposure.age_days}d
                  </span>
                ) : null}
              </span>
            </Detail>
            <Detail label="Last seen">
              <span style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
                {timeAgo(exposure.last_seen_at)}
              </span>
            </Detail>
          </div>

          {exposure.cve_ids.length > 0 ? (
            <Detail label="CVEs">
              <div className="flex flex-wrap gap-1.5">
                {exposure.cve_ids.map((c) => (
                  <span
                    key={c}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      height: "20px",
                      padding: "0 6px",
                      borderRadius: "4px",
                      border: "1px solid rgba(255,86,48,0.3)",
                      background: "rgba(255,86,48,0.05)",
                      color: "#B71D18",
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {c}
                  </span>
                ))}
              </div>
            </Detail>
          ) : null}

          {exposure.cwe_ids.length > 0 ? (
            <Detail label="CWEs">
              <div className="flex flex-wrap gap-1.5">
                {exposure.cwe_ids.map((c) => (
                  <span
                    key={c}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      height: "20px",
                      padding: "0 6px",
                      borderRadius: "4px",
                      background: "var(--color-surface-muted)",
                      color: "var(--color-body)",
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                    }}
                  >
                    {c}
                  </span>
                ))}
              </div>
            </Detail>
          ) : null}

          {exposure.references.length > 0 ? (
            <Detail label="References">
              <ul className="space-y-1">
                {exposure.references.map((u, i) => (
                  <li key={`${u}-${i}`}>
                    <a
                      href={u}
                      target="_blank"
                      rel="noopener noreferrer"
                      onMouseEnter={() => setRefHovIdx(i)}
                      onMouseLeave={() => setRefHovIdx(null)}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px",
                        fontSize: "12px",
                        color: refHovIdx === i ? "var(--color-accent)" : "var(--color-body)",
                        wordBreak: "break-all",
                        transition: "color 0.15s",
                      }}
                    >
                      {u}
                      <ExternalLink style={{ width: "12px", height: "12px", flexShrink: 0 }} />
                    </a>
                  </li>
                ))}
              </ul>
            </Detail>
          ) : null}

          {exposure.state_reason ? (
            <Detail label="State reason">
              <p style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
                {exposure.state_reason}
              </p>
            </Detail>
          ) : null}

          {exposure.remediation_action ? (
            <Detail label="Remediation">
              <div style={{ fontSize: "12.5px", color: "var(--color-body)", lineHeight: 1.6 }}>
                <div>
                  <strong style={{ color: "var(--color-ink)" }}>Action:</strong>{" "}
                  {exposure.remediation_action.replace(/_/g, " ")}
                </div>
                {exposure.remediation_patch_version ? (
                  <div>
                    <strong style={{ color: "var(--color-ink)" }}>Patch version:</strong>{" "}
                    <span style={{ fontFamily: "monospace" }}>
                      {exposure.remediation_patch_version}
                    </span>
                  </div>
                ) : null}
                {exposure.remediation_owner ? (
                  <div>
                    <strong style={{ color: "var(--color-ink)" }}>Owner:</strong>{" "}
                    {exposure.remediation_owner}
                  </div>
                ) : null}
                {exposure.remediation_notes ? (
                  <div style={{ marginTop: "4px", whiteSpace: "pre-wrap" }}>
                    {exposure.remediation_notes}
                  </div>
                ) : null}
              </div>
            </Detail>
          ) : null}

          {exposure.ai_rationale || exposure.ai_priority !== null ? (
            <Detail label="AI triage">
              <div
                style={{
                  fontSize: "12.5px",
                  color: "var(--color-body)",
                  lineHeight: 1.6,
                  padding: "10px 12px",
                  background: "var(--color-surface-muted)",
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                }}
              >
                {exposure.ai_priority !== null ? (
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
                    <Sparkles style={{ width: "13px", height: "13px", color: "var(--color-accent)" }} />
                    <strong style={{ color: "var(--color-ink)" }}>Priority {Math.round(exposure.ai_priority)}/100</strong>
                    {exposure.ai_triaged_at ? (
                      <span style={{ marginLeft: "auto", fontSize: "10.5px", color: "var(--color-muted)" }}>
                        {timeAgo(exposure.ai_triaged_at)}
                      </span>
                    ) : null}
                  </div>
                ) : null}
                {exposure.ai_rationale ? (
                  <div style={{ whiteSpace: "pre-wrap" }}>{exposure.ai_rationale}</div>
                ) : null}
                {exposure.ai_suggest_dismiss ? (
                  <div
                    style={{
                      marginTop: "8px",
                      padding: "6px 8px",
                      background: "rgba(0,184,217,0.1)",
                      borderRadius: "3px",
                      color: "#0066CC",
                      fontWeight: 600,
                    }}
                  >
                    AI suggests dismissing as a likely false positive
                    {exposure.ai_dismiss_reason ? `: ${exposure.ai_dismiss_reason}` : "."}
                  </div>
                ) : null}
              </div>
            </Detail>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function DrawerBanners({ exposure }: { exposure: ExposureResponse }) {
  const banners: React.ReactNode[] = [];
  if (exposure.is_kev) {
    banners.push(
      <div
        key="kev"
        style={{
          padding: "10px 12px",
          background: "rgba(255,86,48,0.08)",
          borderLeft: "3px solid #B71D18",
          borderRadius: "3px",
          fontSize: "12px",
          color: "#B71D18",
          fontWeight: 600,
        }}
      >
        <Flame style={{ display: "inline-block", width: "13px", height: "13px", marginRight: "6px", verticalAlign: "-2px" }} />
        Listed on the CISA Known Exploited Vulnerabilities catalog
        {exposure.kev_added_at
          ? ` since ${new Date(exposure.kev_added_at).toISOString().slice(0, 10)}`
          : ""}.
      </div>,
    );
  }
  if (exposure.age_days !== null && exposure.age_days >= 90 && exposure.state === "open") {
    const tone = exposure.age_days >= 180 ? "#B71D18" : "#B76E00";
    banners.push(
      <div
        key="age"
        style={{
          padding: "10px 12px",
          background: `${tone}10`,
          borderLeft: `3px solid ${tone}`,
          borderRadius: "3px",
          fontSize: "12px",
          color: tone,
          fontWeight: 600,
        }}
      >
        <Clock style={{ display: "inline-block", width: "13px", height: "13px", marginRight: "6px", verticalAlign: "-2px" }} />
        Open for {exposure.age_days} days — {exposure.age_days >= 180 ? "well past SLA" : "approaching SLA"}.
      </div>,
    );
  }
  if (!exposure.asset_id) {
    banners.push(
      <div
        key="orphan"
        style={{
          padding: "10px 12px",
          background: "var(--color-surface-muted)",
          borderLeft: "3px solid var(--color-border-strong)",
          borderRadius: "3px",
          fontSize: "12px",
          color: "var(--color-body)",
        }}
      >
        Not linked to an asset in the registry. Use the row actions to link one.
      </div>,
    );
  }
  if (banners.length === 0) return null;
  return <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>{banners}</div>;
}

function ExposureStateModal({
  target,
  onClose,
  onSubmit,
}: {
  target: ExposureResponse;
  onClose: () => void;
  onSubmit: (
    to: ExposureStateValue,
    payload: {
      reason: string;
      remediation_action?: RemediationAction;
      remediation_patch_version?: string;
      remediation_owner?: string;
      remediation_notes?: string;
    },
  ) => void;
}) {
  const targets = STATES.filter((s) => s !== target.state);
  const [next, setNext] = useState<ExposureStateValue>(targets[0]);
  const [reason, setReason] = useState("");
  const [action, setAction] = useState<RemediationAction | "">("");
  const [patchVersion, setPatchVersion] = useState("");
  const [owner, setOwner] = useState("");
  const [notes, setNotes] = useState("");

  const isTerminal =
    next === "fixed" || next === "accepted_risk" || next === "false_positive";

  // When user picks false_positive state, default the remediation_action to
  // false_positive so the two stay aligned (analyst can override).
  useEffect(() => {
    if (next === "false_positive" && action !== "false_positive") {
      setAction("false_positive");
    } else if (next === "fixed" && !action) {
      setAction("patched");
    } else if (next === "accepted_risk" && !action) {
      setAction("waived");
    } else if (!isTerminal) {
      setAction("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [next]);

  return (
    <ModalShell title="Transition exposure" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Target state" required>
          <div className="grid grid-cols-2 gap-1.5">
            {targets.map((s) => {
              const active = next === s;
              return (
                <button
                  key={s}
                  onClick={() => setNext(s)}
                  style={{
                    height: "40px",
                    borderRadius: "4px",
                    border: active ? "1px solid var(--color-border-strong)" : "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    boxShadow: active ? "var(--color-border-strong) 0px 0px 0px 2px inset" : "none",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "6px",
                    cursor: "pointer",
                    transition: "all 0.15s",
                  }}
                >
                  <StatePill label={STATE_LABEL[s]} tone={STATE_TONE[s]} />
                </button>
              );
            })}
          </div>
        </Field>
        <Field label="Reason" required={isTerminal} hint="Captured on the exposure audit trail.">
          <textarea
            value={reason}
            onChange={(ev) => setReason(ev.target.value)}
            rows={3}
            style={{ ...inputStyle, height: "auto", padding: "8px 12px", resize: "none" }}
            placeholder="e.g. Patched with vendor advisory ABC-123, scanned post-deploy."
          />
        </Field>

        {isTerminal ? (
          <>
            <Field label="Remediation action" required>
              <Select
                ariaLabel="Remediation action"
                value={action}
                options={[
                  { value: "", label: "— select action —" },
                  ...REMEDIATION_OPTIONS.map((o) => ({
                    value: o.value,
                    label: o.label,
                  })),
                ]}
                onChange={(v) => setAction(v as RemediationAction | "")}
              />
            </Field>
            {action === "patched" || action === "mitigated" ? (
              <Field
                label="Patch / version"
                hint="The vendor advisory or version that resolves this exposure."
              >
                <input
                  value={patchVersion}
                  onChange={(ev) => setPatchVersion(ev.target.value)}
                  placeholder="e.g. log4j 2.17.1, KB5012170, 1.21.0"
                  style={{ ...inputStyle, fontFamily: "monospace", fontSize: "12px" }}
                />
              </Field>
            ) : null}
            <Field
              label="Owner"
              hint="Who validated the remediation? Defaults to your account."
            >
              <input
                value={owner}
                onChange={(ev) => setOwner(ev.target.value)}
                placeholder="ops@company.com"
                style={{ ...inputStyle, fontSize: "12.5px" }}
              />
            </Field>
            <Field
              label="Remediation notes"
              hint="Validation steps, screenshots, ticket links."
            >
              <textarea
                value={notes}
                onChange={(ev) => setNotes(ev.target.value)}
                rows={3}
                style={{ ...inputStyle, height: "auto", padding: "8px 12px", resize: "none" }}
                placeholder="e.g. Scanned post-deploy, no longer detected. Linked to JIRA-1234."
              />
            </Field>
          </>
        ) : null}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() =>
          onSubmit(next, {
            reason,
            remediation_action: action || undefined,
            remediation_patch_version: patchVersion || undefined,
            remediation_owner: owner || undefined,
            remediation_notes: notes || undefined,
          })
        }
        submitLabel="Transition"
        disabled={isTerminal && (!reason.trim() || !action)}
      />
    </ModalShell>
  );
}

function Detail({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--color-muted)", marginBottom: "6px" }}>
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}
