"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ExternalLink, ShieldAlert } from "lucide-react";
import {
  api,
  type ExposureResponse,
  type ExposureSeverityValue,
  type ExposureStateValue,
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
  }, [orgId, severity, state, search, cve, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const transition = async (
    target: ExposureResponse,
    to: ExposureStateValue,
    reason: string,
  ) => {
    try {
      await api.easm.transitionExposure(target.id, {
        state: to,
        reason: reason || undefined,
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
      [severity !== "all", state !== "all", search !== "", cve !== ""].filter(Boolean)
        .length,
    [severity, state, search, cve],
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
        {filterCount > 0 ? (
          <button
            onClick={() => {
              setSeverity("all");
              setState("all");
              setSearch("");
              setCve("");
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
                  <Th align="left" className="w-[110px]">
                    Category
                  </Th>
                  <Th align="left" className="w-[90px]">
                    CVSS
                  </Th>
                  <Th align="left" className="w-[140px]">
                    State
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
          onSubmit={(to, reason) => transition(transitionTarget, to, reason)}
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
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          height: "18px",
          padding: "0 6px",
          borderRadius: "4px",
          background: "var(--color-surface-muted)",
          fontSize: "10.5px",
          fontWeight: 700,
          color: "var(--color-body)",
          letterSpacing: "0.06em",
        }}>
          {e.category.replace(/_/g, " ").toUpperCase()}
        </span>
      </td>
      <td className="px-3">
        {e.cvss_score !== null ? (
          <span style={{
            fontFamily: "monospace",
            fontSize: "12px",
            fontWeight: 700,
            color: CVSS_COLOR(e.cvss_score),
          }}>
            {e.cvss_score.toFixed(1)}
          </span>
        ) : (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td className="px-3">
        <StatePill
          label={STATE_LABEL[e.state]}
          tone={STATE_TONE[e.state]}
        />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(e.last_seen_at)}
      </td>
    </tr>
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
              <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 700, color: "var(--color-ink)" }}>
                {exposure.cvss_score?.toFixed(1) ?? "—"}
              </span>
            </Detail>
            <Detail label="Occurrences">
              <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 700, color: "var(--color-ink)" }}>
                {exposure.occurrence_count}
              </span>
            </Detail>
            <Detail label="First matched">
              <span style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
                {timeAgo(exposure.matched_at)}
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
        </div>
      </div>
    </div>
  );
}

function ExposureStateModal({
  target,
  onClose,
  onSubmit,
}: {
  target: ExposureResponse;
  onClose: () => void;
  onSubmit: (to: ExposureStateValue, reason: string) => void;
}) {
  const targets = STATES.filter((s) => s !== target.state);
  const [next, setNext] = useState<ExposureStateValue>(targets[0]);
  const [reason, setReason] = useState("");
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
        <Field label="Reason" hint="Captured on the exposure audit trail.">
          <textarea
            value={reason}
            onChange={(ev) => setReason(ev.target.value)}
            rows={3}
            style={{ ...inputStyle, height: "auto", padding: "8px 12px", resize: "none" }}
            placeholder="e.g. Patched with vendor advisory ABC-123, scanned post-deploy."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(next, reason)}
        submitLabel="Transition"
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
