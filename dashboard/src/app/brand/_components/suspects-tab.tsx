"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Camera,
  Check,
  Globe2,
  Play,

} from "lucide-react";
import {
  api,
  type SuspectDomainResponse,
  type SuspectSourceValue,
  type SuspectStateValue,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  MonoCell,
  PaginationFooter,
  SearchInput,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

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

const SUSPECT_STATES: SuspectStateValue[] = [
  "open",
  "confirmed_phishing",
  "takedown_requested",
  "dismissed",
  "cleared",
];

const STATE_LABEL: Record<SuspectStateValue, string> = {
  open: "OPEN",
  confirmed_phishing: "CONFIRMED",
  takedown_requested: "TAKEDOWN",
  dismissed: "DISMISSED",
  cleared: "CLEARED",
};
const STATE_TONE: Record<SuspectStateValue, StateTone> = {
  open: "neutral",
  confirmed_phishing: "error-strong",
  takedown_requested: "warning",
  dismissed: "muted",
  cleared: "success",
};

const SOURCE_OPTIONS: Array<{ value: SuspectSourceValue | "all"; label: string }> = [
  { value: "all", label: "Any source" },
  { value: "dnstwist", label: "dnstwist" },
  { value: "certstream", label: "CertStream" },
  { value: "whoisds", label: "WhoisDS" },
  { value: "phishtank", label: "PhishTank" },
  { value: "openphish", label: "OpenPhish" },
  { value: "urlhaus", label: "URLhaus" },
  { value: "subdomain_fuzz", label: "Subdomain fuzz" },
  { value: "manual", label: "Manual" },
];

const PAGE_LIMIT = 50;

export function SuspectsTab() {
  const { orgId} = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<SuspectDomainResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [stateFilter, setStateFilter] = useState<SuspectStateValue | "all">(
    "all",
  );
  const [sourceFilter, setSourceFilter] = useState<SuspectSourceValue | "all">(
    "all",
  );
  const [resolvableOnly, setResolvableOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [transitionTarget, setTransitionTarget] =
    useState<SuspectDomainResponse | null>(null);
  const [probingId, setProbingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.brand.listSuspects({
        organization_id: orgId,
        state: stateFilter === "all" ? undefined : stateFilter,
        source: sourceFilter === "all" ? undefined : sourceFilter,
        is_resolvable: resolvableOnly || undefined,
        limit: PAGE_LIMIT,
        offset,
      });
      const filtered = search
        ? data.filter(
            (s) =>
              s.domain.includes(search.toLowerCase()) ||
              s.matched_term_value.includes(search.toLowerCase()),
          )
        : data;
      setRows(filtered);
      setTotal(page.total ?? filtered.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load suspect domains",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, sourceFilter, resolvableOnly, offset, search, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const transition = async (
    target: SuspectDomainResponse,
    to: SuspectStateValue,
    reason: string,
  ) => {
    try {
      await api.brand.transitionSuspect(target.id, {
        state: to,
        reason: reason || undefined,
      });
      toast("success", `${target.domain} → ${STATE_LABEL[to]}`);
      setTransitionTarget(null);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to transition",
      );
    }
  };

  const runProbe = async (s: SuspectDomainResponse) => {
    setProbingId(s.id);
    try {
      await api.brand.runProbe({
        organization_id: orgId,
        suspect_domain_id: s.id,
        follow_redirects: true,
      });
      toast("success", `Probe queued for ${s.domain}`);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Probe failed",
      );
    } finally {
      setProbingId(null);
    }
  };

  const filterCount = useMemo(
    () =>
      [
        stateFilter !== "all",
        sourceFilter !== "all",
        resolvableOnly,
        search !== "",
      ].filter(Boolean).length,
    [stateFilter, sourceFilter, resolvableOnly, search],
  );

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput
          value={search}
          onChange={(v) => {
            setSearch(v);
            setOffset(0);
          }}
          placeholder="Search by domain or matched term…"
          shortcut=""
        />
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            ...SUSPECT_STATES.map((s) => ({
              value: s,
              label: STATE_LABEL[s],
            })),
          ]}
          onChange={(v) => {
            setStateFilter(v as SuspectStateValue | "all");
            setOffset(0);
          }}
        />
        <Select
          ariaLabel="Source"
          value={sourceFilter}
          options={SOURCE_OPTIONS}
          onChange={(v) => {
            setSourceFilter(v as SuspectSourceValue | "all");
            setOffset(0);
          }}
        />
        <button
          onClick={() => {
            setResolvableOnly((v) => !v);
            setOffset(0);
          }}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            height: "40px",
            padding: "0 12px",
            borderRadius: "4px",
            fontSize: "12px",
            fontWeight: 700,
            border: resolvableOnly
              ? "1px solid rgba(0,187,217,0.4)"
              : "1px solid var(--color-border)",
            background: resolvableOnly
              ? "rgba(0,187,217,0.1)"
              : "var(--color-canvas)",
            color: resolvableOnly ? "#007B8A" : "var(--color-body)",
            cursor: "pointer",
          }}
        >
          RESOLVING DNS
          {resolvableOnly ? <Check className="w-3.5 h-3.5" /> : null}
        </button>
        {filterCount > 0 ? (
          <button
            onClick={() => {
              setStateFilter("all");
              setSourceFilter("all");
              setResolvableOnly(false);
              setSearch("");
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
            icon={Globe2}
            title={
              filterCount > 0
                ? "No suspects match these filters"
                : "No suspect domains yet"
            }
            description={
              filterCount > 0
                ? "Widen the filter set or clear it to see all suspects."
                : "Add brand terms under Terms & feeds, run a scan, or wait for the live feeds (CertStream, PhishTank, OpenPhish, URLhaus) to push matches."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[80px]">
                    Sim
                  </Th>
                  <Th align="left">Domain</Th>
                  <Th align="left">Matched term</Th>
                  <Th align="left" className="w-[120px]">
                    Source
                  </Th>
                  <Th align="left" className="w-[120px]">
                    Resolves
                  </Th>
                  <Th align="left" className="w-[120px]">
                    State
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Last seen
                  </Th>
                  <Th align="right" className="w-[160px] pr-4">
                    Actions
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <SuspectRow
                    key={s.id}
                    s={s}
                    probingId={probingId}
                    onProbe={runProbe}
                    onTransition={setTransitionTarget}
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

      {transitionTarget && (
        <SuspectStateModal
          target={transitionTarget}
          onClose={() => setTransitionTarget(null)}
          onSubmit={(to, reason) => transition(transitionTarget, to, reason)}
        />
      )}
    </div>
  );
}

function SuspectRow({
  s,
  probingId,
  onProbe,
  onTransition,
}: {
  s: SuspectDomainResponse;
  probingId: string | null;
  onProbe: (s: SuspectDomainResponse) => void;
  onTransition: (s: SuspectDomainResponse) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [linkHovered, setLinkHovered] = useState(false);
  return (
    <tr
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <td className="pl-4">
        <SimilarityBar value={s.similarity} />
      </td>
      <td className="px-3">
        <a
          href={`http://${s.domain}`}
          target="_blank"
          rel="noopener noreferrer nofollow"
          onMouseEnter={() => setLinkHovered(true)}
          onMouseLeave={() => setLinkHovered(false)}
          style={{
            fontFamily: "monospace",
            fontSize: "12.5px",
            color: linkHovered ? "var(--color-accent)" : "var(--color-ink)",
            tabularNums: true,
          } as React.CSSProperties}
        >
          {s.domain}
        </a>
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
        <span className="font-mono">{s.matched_term_value}</span>
        <span style={{ color: "var(--color-muted)", marginLeft: "6px" }}>
          / {s.permutation_kind}
        </span>
      </td>
      <td className="px-3">
        <SourceTag source={s.source} />
      </td>
      <td className="px-3">
        {s.is_resolvable === null ? (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>unknown</span>
        ) : s.is_resolvable ? (
          <span className="inline-flex items-center gap-1" style={{ fontSize: "11.5px", fontWeight: 700, color: "#B71D18" }}>
            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#FF5630", display: "inline-block" }} />
            {s.a_records[0] || "live"}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1" style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>
            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--color-border)", display: "inline-block" }} />
            dead
          </span>
        )}
      </td>
      <td className="px-3">
        <StatePill
          label={STATE_LABEL[s.state]}
          tone={STATE_TONE[s.state]}
        />
      </td>
      <td className="px-3">
        <MonoCell text={timeAgo(s.last_seen_at)} />
      </td>
      <td className="pr-4">
        <div className="flex items-center justify-end gap-1">
          <ActionButton
            onClick={() => onProbe(s)}
            disabled={probingId === s.id}
            title="Run live probe"
          >
            {probingId === s.id ? (
              <Camera className="w-3 h-3 animate-pulse" />
            ) : (
              <Play className="w-3 h-3" />
            )}
            PROBE
          </ActionButton>
          <ActionButton onClick={() => onTransition(s)}>
            STATE
          </ActionButton>
        </div>
      </td>
    </tr>
  );
}

function ActionButton({
  children,
  onClick,
  disabled,
  title,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  title?: string;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        height: "28px",
        padding: "0 8px",
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface-muted)" : "var(--color-canvas)",
        fontSize: "11px",
        fontWeight: 700,
        color: "var(--color-body)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function SuspectStateModal({
  target,
  onClose,
  onSubmit,
}: {
  target: SuspectDomainResponse;
  onClose: () => void;
  onSubmit: (to: SuspectStateValue, reason: string) => void;
}) {
  const targets = SUSPECT_STATES.filter((s) => s !== target.state);
  const [next, setNext] = useState<SuspectStateValue>(targets[0]);
  const [reason, setReason] = useState("");
  return (
    <ModalShell title={`Transition ${target.domain}`} onClose={onClose}>
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
                    fontSize: "11px",
                    fontWeight: 700,
                    letterSpacing: "0.06em",
                    color: active ? "var(--color-ink)" : "var(--color-body)",
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
        <Field
          label="Reason"
          hint="Captured on the suspect-domain audit trail."
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            style={{ ...inputStyle, height: "auto", padding: "8px 12px", resize: "none" }}
            placeholder="e.g. Live probe shows cloned login form, screenshot attached."
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

function SimilarityBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.9 ? "#FF5630" : pct >= 0.75 ? "#FFAB00" : "#00B8D9";
  return (
    <div className="flex items-center gap-2">
      <div style={{ width: "40px", height: "4px", borderRadius: "9999px", background: "var(--color-surface-muted)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct * 100}%`, background: fillColor }} />
      </div>
      <span style={{ fontFamily: "monospace", fontSize: "11px", tabularNums: true, color: "var(--color-body)" } as React.CSSProperties}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function SourceTag({ source }: { source: string }) {
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      height: "18px",
      padding: "0 6px",
      borderRadius: "4px",
      background: "var(--color-surface-muted)",
      fontSize: "10.5px",
      fontWeight: 600,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
      color: "var(--color-body)",
    }}>
      {source}
    </span>
  );
}
