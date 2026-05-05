"use client";

import {
  KeyboardEvent as ReactKeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  Briefcase,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Plus,
  RefreshCw,
  Search,
  Tag as TagIcon,
  X,
} from "lucide-react";
import { Select } from "@/components/shared/select";
import {
  api,
  type CaseCounts,
  type CaseResponse,
  type CaseSeverityValue,
  type CaseStateValue,
  type Org,
  type PageMeta,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";

const SEVERITIES: CaseSeverityValue[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const STATES: CaseStateValue[] = [
  "open",
  "triaged",
  "in_progress",
  "remediated",
  "verified",
  "closed",
];

const PAGE_LIMIT = 50;

// Severity → stripe color + chip colors (using Zapier inline tokens)
const SEVERITY_PRESENTATION: Record<
  CaseSeverityValue,
  { stripeColor: string; chipBg: string; chipBorder: string; chipColor: string; label: string; rank: number }
> = {
  critical: {
    stripeColor: "#FF5630",
    chipBg: "rgba(255,86,48,0.1)",
    chipBorder: "rgba(255,86,48,0.4)",
    chipColor: "#B71D18",
    label: "CRIT",
    rank: 4,
  },
  high: {
    stripeColor: "#FF5630",
    chipBg: "rgba(255,86,48,0.06)",
    chipBorder: "rgba(255,86,48,0.3)",
    chipColor: "#B71D18",
    label: "HIGH",
    rank: 3,
  },
  medium: {
    stripeColor: "#FFAB00",
    chipBg: "rgba(255,171,0,0.1)",
    chipBorder: "rgba(255,171,0,0.4)",
    chipColor: "#B76E00",
    label: "MED",
    rank: 2,
  },
  low: {
    stripeColor: "#00BBD9",
    chipBg: "rgba(0,187,217,0.08)",
    chipBorder: "rgba(0,187,217,0.4)",
    chipColor: "#007B8A",
    label: "LOW",
    rank: 1,
  },
  info: {
    stripeColor: "var(--color-muted)",
    chipBg: "var(--color-surface-muted)",
    chipBorder: "var(--color-border)",
    chipColor: "var(--color-muted)",
    label: "INFO",
    rank: 0,
  },
};

const STATE_PRESENTATION: Record<
  CaseStateValue,
  { chipBorder: string; chipColor: string; label: string }
> = {
  open: { chipBorder: "var(--color-border)", chipColor: "var(--color-body)", label: "OPEN" },
  triaged: { chipBorder: "rgba(0,187,217,0.6)", chipColor: "#007B8A", label: "TRIAGED" },
  in_progress: { chipBorder: "var(--color-border-strong)", chipColor: "var(--color-body)", label: "IN PROGRESS" },
  remediated: { chipBorder: "rgba(255,171,0,0.6)", chipColor: "#B76E00", label: "REMEDIATED" },
  verified: { chipBorder: "rgba(255,79,0,0.6)", chipColor: "var(--color-accent)", label: "VERIFIED" },
  closed: { chipBorder: "var(--color-border)", chipColor: "var(--color-muted)", label: "CLOSED" },
};

function _initials(input: string | null | undefined): string {
  if (!input) return "—";
  const parts = input.trim().split(/\s+/).slice(0, 2);
  return parts.map((p) => p[0]).join("").toUpperCase() || "—";
}

function _shortId(uuid: string): string {
  return uuid.slice(-6).toUpperCase();
}

function _slaState(
  due: string | null,
  closedAt: string | null,
): { tone: "ok" | "warn" | "breach" | "none"; label: string } {
  if (closedAt) return { tone: "none", label: "CLOSED" };
  if (!due) return { tone: "none", label: "—" };
  const now = Date.now();
  const dueAt = new Date(due).getTime();
  const ms = dueAt - now;
  if (ms <= 0) {
    const overdueBy = -ms;
    return { tone: "breach", label: `${_durationLabel(overdueBy)} OVERDUE` };
  }
  if (ms < 1000 * 60 * 60 * 4) {
    return { tone: "warn", label: `${_durationLabel(ms)} LEFT` };
  }
  return { tone: "ok", label: `${_durationLabel(ms)} LEFT` };
}

function _durationLabel(ms: number): string {
  const abs = Math.abs(ms);
  const minutes = Math.floor(abs / 60000);
  if (minutes < 60) return `${minutes}M`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}H`;
  const days = Math.floor(hours / 24);
  return `${days}D`;
}

interface NewCasePayload {
  title: string;
  summary: string;
  severity: CaseSeverityValue;
  tags: string[];
}

const FRESH_CASE: NewCasePayload = {
  title: "",
  summary: "",
  severity: "high",
  tags: [],
};

const btnSecondary: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-body)",
};

const btnPrimary: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-accent)",
  background: "var(--color-accent)",
  color: "var(--color-on-dark)",
};

export default function CasesPage() {
  const router = useRouter();
  const { toast } = useToast();

  // ---- Org selection -------------------------------------------------
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgId] = useState<string>("");
  const [orgLoading, setOrgLoading] = useState(true);

  // ---- Filters -------------------------------------------------------
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<CaseStateValue | "all">("all");
  const [sevFilter, setSevFilter] = useState<CaseSeverityValue | "all">("all");
  const [tagFilter, setTagFilter] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  // ---- Data ----------------------------------------------------------
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [page, setPage] = useState<PageMeta>({ total: null, limit: null, offset: null });
  const [counts, setCounts] = useState<CaseCounts | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // ---- Keyboard nav --------------------------------------------------
  const [cursor, setCursor] = useState(0);
  const searchRef = useRef<HTMLInputElement | null>(null);

  // ---- New-case modal ------------------------------------------------
  const [showNew, setShowNew] = useState(false);
  const [draft, setDraft] = useState<NewCasePayload>(FRESH_CASE);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted =
          typeof window !== "undefined"
            ? window.localStorage.getItem("argus_org_id")
            : null;
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgId(initial);
      } catch (e) {
        toast("error", e instanceof Error ? e.message : "Failed to load organizations");
      } finally {
        if (alive) setOrgLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [toast]);

  useEffect(() => {
    if (orgId && typeof window !== "undefined") {
      window.localStorage.setItem("argus_org_id", orgId);
    }
  }, [orgId]);

  const loadCases = useCallback(
    async (opts?: { signalRefresh?: boolean }) => {
      if (!orgId) return;
      if (opts?.signalRefresh) setRefreshing(true);
      else setLoading(true);
      try {
        const [{ data, page }, c] = await Promise.all([
          api.cases.list({
            organization_id: orgId,
            state: stateFilter === "all" ? undefined : stateFilter,
            severity: sevFilter === "all" ? undefined : sevFilter,
            tag: tagFilter || undefined,
            q: search || undefined,
            overdue: overdueOnly || undefined,
            limit: PAGE_LIMIT,
            offset,
          }),
          api.cases.count(orgId),
        ]);
        setCases(data);
        setPage(page);
        setCounts(c);
        setCursor((c) => Math.min(c, Math.max(data.length - 1, 0)));
      } catch (e) {
        toast("error", e instanceof Error ? e.message : "Failed to load cases");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [orgId, search, stateFilter, sevFilter, tagFilter, overdueOnly, offset, toast],
  );

  useEffect(() => {
    if (orgId) loadCases();
  }, [loadCases, orgId]);

  // ---- Keyboard handlers (j/k, /, c, enter) -------------------------
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName;
      const inField = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
      if (e.key === "Escape") {
        if (showNew) {
          e.preventDefault();
          setShowNew(false);
          return;
        }
        if (inField) (e.target as HTMLElement).blur();
        return;
      }
      if (inField) return;
      if (showNew) return;
      if (e.key === "j") {
        e.preventDefault();
        setCursor((c) => Math.min(cases.length - 1, c + 1));
      } else if (e.key === "k") {
        e.preventDefault();
        setCursor((c) => Math.max(0, c - 1));
      } else if (e.key === "Enter" && cases[cursor]) {
        e.preventDefault();
        router.push(`/cases/${cases[cursor].id}`);
      } else if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "c") {
        e.preventDefault();
        setDraft(FRESH_CASE);
        setShowNew(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [cases, cursor, router, showNew]);

  const total = page.total ?? cases.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_LIMIT));
  const currentPage = Math.floor(offset / PAGE_LIMIT) + 1;

  const sevBreakdown = useMemo(() => {
    const b = counts?.by_severity || ({} as Record<string, number>);
    return SEVERITIES.map((s) => ({ sev: s, n: b[s] ?? 0 }));
  }, [counts]);

  const handleCreate = async () => {
    if (!orgId || !draft.title.trim() || creating) return;
    setCreating(true);
    try {
      const res = await api.cases.create({
        organization_id: orgId,
        title: draft.title.trim(),
        summary: draft.summary.trim() || undefined,
        severity: draft.severity,
        tags: draft.tags,
      });
      toast("success", `Case ${_shortId(res.id)} created`);
      setShowNew(false);
      setDraft(FRESH_CASE);
      router.push(`/cases/${res.id}`);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to create case");
    } finally {
      setCreating(false);
    }
  };

  return (
    <CoverageGate pageSlug="cases" pageLabel="Cases">
    <div className="space-y-7">
      {/* ─── Header ──────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-6 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Briefcase className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
            <span className="text-[11px] font-bold uppercase tracking-[1.4px]" style={{ color: "var(--color-muted)" }}>Operations</span>
          </div>
          <h1 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Cases</h1>
          <p className="text-[13px] mt-1 max-w-[640px]" style={{ color: "var(--color-muted)" }}>
            Open investigations across your detection surface. Cases are
            auto-promoted by Argus when a finding lands at HIGH or
            CRITICAL severity, or created manually here.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {orgs.length > 1 ? (
            <Select
              value={orgId}
              onChange={(v) => { setOrgId(v); setOffset(0); }}
              ariaLabel="Organisation"
              options={orgs.map((o) => ({ value: o.id, label: o.name }))}
            />
          ) : null}
          <button
            onClick={() => loadCases({ signalRefresh: true })}
            disabled={refreshing || loading}
            className="flex items-center gap-2 h-10 px-3.5 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={btnSecondary}
            title="Refresh (R)"
          >
            <RefreshCw style={{ width: "16px", height: "16px" }} className={refreshing ? "animate-spin" : undefined} />
            Refresh
          </button>
          <button
            onClick={() => { setDraft(FRESH_CASE); setShowNew(true); }}
            className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors"
            style={btnPrimary}
            title="New case (C)"
          >
            <Plus className="w-4 h-4" />
            New case
            <kbd
              className="hidden md:inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-mono font-semibold"
              style={{ borderRadius: "4px", background: "rgba(255,255,255,0.2)" }}
            >
              C
            </kbd>
          </button>
        </div>
      </div>

      {/* ─── Editorial stat strip ───────────────────────────────── */}
      <div style={{ border: "1px solid var(--color-border)", background: "var(--color-canvas)", borderRadius: "5px" }}>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7" style={{ borderColor: "var(--color-border)" }}>
          <StatCell label="Total" value={counts ? counts.total : "—"} tone="neutral" />
          <StatCell
            label="Overdue"
            value={counts ? counts.overdue : "—"}
            tone={counts && counts.overdue > 0 ? "error" : "neutral"}
            highlightLabel={(counts?.overdue ?? 0) > 0}
          />
          {sevBreakdown.map(({ sev, n }) => (
            <StatCell
              key={sev}
              label={SEVERITY_PRESENTATION[sev].label}
              value={n}
              accentColor={SEVERITY_PRESENTATION[sev].stripeColor}
              tone="neutral"
            />
          ))}
        </div>
      </div>

      {/* ─── Filter bar ─────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[260px] max-w-[420px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "var(--color-muted)" }} />
          <input
            ref={searchRef}
            value={search}
            onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
            placeholder="Search by title…"
            className="w-full h-10 pl-9 pr-9 text-[13px] outline-none"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
          />
          <kbd
            className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center justify-center min-w-[20px] h-5 px-1 text-[10px] font-mono font-semibold"
            style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-muted)" }}
          >
            /
          </kbd>
        </div>

        <SegmentedFilter
          label="State"
          values={["all", ...STATES]}
          current={stateFilter}
          onChange={(v) => { setStateFilter(v as CaseStateValue | "all"); setOffset(0); }}
          renderLabel={(v) => v === "all" ? "Any state" : STATE_PRESENTATION[v as CaseStateValue].label}
        />

        <SegmentedFilter
          label="Severity"
          values={["all", ...SEVERITIES]}
          current={sevFilter}
          onChange={(v) => { setSevFilter(v as CaseSeverityValue | "all"); setOffset(0); }}
          renderLabel={(v) => v === "all" ? "Any severity" : SEVERITY_PRESENTATION[v as CaseSeverityValue].label}
        />

        <div className="relative">
          <TagIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "var(--color-muted)" }} />
          <input
            value={tagFilter}
            onChange={(e) => { setTagFilter(e.target.value); setOffset(0); }}
            placeholder="Tag…"
            className="h-10 pl-9 pr-3 w-[140px] text-[13px] outline-none"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
          />
        </div>

        <button
          onClick={() => { setOverdueOnly((v) => !v); setOffset(0); }}
          className="flex items-center gap-2 h-10 px-3 text-[12px] font-bold transition-colors"
          style={{
            borderRadius: "4px",
            border: overdueOnly ? "1px solid rgba(255,86,48,0.4)" : "1px solid var(--color-border)",
            background: overdueOnly ? "rgba(255,86,48,0.1)" : "var(--color-canvas)",
            color: overdueOnly ? "#B71D18" : "var(--color-body)",
          }}
          title="Filter to overdue cases only"
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          OVERDUE ONLY
          {overdueOnly ? <Check className="w-3.5 h-3.5" /> : null}
        </button>

        {(stateFilter !== "all" || sevFilter !== "all" || tagFilter || overdueOnly || search) && (
          <button
            onClick={() => { setStateFilter("all"); setSevFilter("all"); setTagFilter(""); setOverdueOnly(false); setSearch(""); setOffset(0); }}
            className="text-[12px] font-semibold px-2 transition-colors"
            style={{ color: "var(--color-muted)" }}
            onMouseEnter={e => (e.currentTarget.style.color = "var(--color-body)")}
            onMouseLeave={e => (e.currentTarget.style.color = "var(--color-muted)")}
          >
            Clear
          </button>
        )}
      </div>

      {/* ─── Table ─────────────────────────────────────────────── */}
      <div style={{ border: "1px solid var(--color-border)", background: "var(--color-canvas)", borderRadius: "5px", overflow: "hidden" }}>
        {orgLoading || loading ? (
          <CasesSkeleton rows={10} />
        ) : cases.length === 0 ? (
          <EmptyState
            hasFilters={stateFilter !== "all" || sevFilter !== "all" || tagFilter !== "" || overdueOnly || search !== ""}
            onCreate={() => { setDraft(FRESH_CASE); setShowNew(true); }}
            onReset={() => { setStateFilter("all"); setSevFilter("all"); setTagFilter(""); setOverdueOnly(false); setSearch(""); setOffset(0); }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <th className="w-1 p-0" />
                  <Th align="left" className="pl-4 w-[88px]">Sev</Th>
                  <Th align="left" className="w-[80px]">ID</Th>
                  <Th align="left">Title</Th>
                  <Th align="left" className="w-[124px]">State</Th>
                  <Th align="left" className="w-[120px]">SLA</Th>
                  <Th align="left" className="w-[140px]">Tags</Th>
                  <Th align="left" className="w-[80px]">Owner</Th>
                  <Th align="right" className="w-[112px] pr-4">Updated</Th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c, idx) => (
                  <CaseRow
                    key={c.id}
                    c={c}
                    active={idx === cursor}
                    onClick={() => router.push(`/cases/${c.id}`)}
                    onMouseEnter={() => setCursor(idx)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ─── Pagination footer ──────────────────────────────── */}
        {!loading && cases.length > 0 && (
          <div
            className="flex items-center justify-between px-4 py-3"
            style={{ borderTop: "1px solid var(--color-border)", background: "var(--color-surface)" }}
          >
            <div className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-body)" }}>
              {offset + 1}–{offset + cases.length} of {total}
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_LIMIT))}
                disabled={offset === 0}
                className="h-8 w-8 flex items-center justify-center disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                style={{ borderRadius: "4px", border: "1px solid var(--color-border)" }}
                onMouseEnter={e => { if (!e.currentTarget.disabled) e.currentTarget.style.background = "var(--color-surface-muted)"; }}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <ChevronLeft className="w-4 h-4" style={{ color: "var(--color-body)" }} />
              </button>
              <span className="text-[12px] font-mono tabular-nums px-2" style={{ color: "var(--color-body)" }}>
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setOffset((o) => Math.min((totalPages - 1) * PAGE_LIMIT, o + PAGE_LIMIT))}
                disabled={currentPage >= totalPages}
                className="h-8 w-8 flex items-center justify-center disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                style={{ borderRadius: "4px", border: "1px solid var(--color-border)" }}
                onMouseEnter={e => { if (!e.currentTarget.disabled) e.currentTarget.style.background = "var(--color-surface-muted)"; }}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <ChevronRight className="w-4 h-4" style={{ color: "var(--color-body)" }} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ─── Keyboard hint ────────────────────────────────────── */}
      {cases.length > 0 && (
        <p className="text-[11px] font-mono tracking-wide" style={{ color: "var(--color-muted)" }}>
          <kbd
            className="px-1.5 py-0.5 mr-1"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >J</kbd>
          <kbd
            className="px-1.5 py-0.5 mr-1"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >K</kbd>
          NAVIGATE
          <span className="mx-3" style={{ color: "var(--color-border)" }}>·</span>
          <kbd
            className="px-1.5 py-0.5 mr-1"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >⏎</kbd>
          OPEN
          <span className="mx-3" style={{ color: "var(--color-border)" }}>·</span>
          <kbd
            className="px-1.5 py-0.5 mr-1"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >/</kbd>
          SEARCH
          <span className="mx-3" style={{ color: "var(--color-border)" }}>·</span>
          <kbd
            className="px-1.5 py-0.5 mr-1"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >C</kbd>
          NEW CASE
        </p>
      )}

      {/* ─── New-case modal ──────────────────────────────────── */}
      {showNew && (
        <NewCaseModal
          draft={draft}
          setDraft={setDraft}
          onClose={() => setShowNew(false)}
          onSubmit={handleCreate}
          submitting={creating}
        />
      )}
    </div>
      </CoverageGate>
  );
}

// ─────────────────────────────────────────────────────────────────────
//  Sub-components
// ─────────────────────────────────────────────────────────────────────

function Th({
  children,
  align = "left",
  className,
}: {
  children: React.ReactNode;
  align?: "left" | "right";
  className?: string;
}) {
  return (
    <th
      className={className}
      style={{
        height: "36px",
        padding: "0 12px",
        fontSize: "10px",
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.07em",
        textAlign: align === "right" ? "right" : "left",
        color: "var(--color-muted)",
      }}
    >
      {children}
    </th>
  );
}

function CaseRow({
  c,
  active,
  onClick,
  onMouseEnter,
}: {
  c: CaseResponse;
  active: boolean;
  onClick: () => void;
  onMouseEnter: () => void;
}) {
  const sev = SEVERITY_PRESENTATION[c.severity];
  const stt = STATE_PRESENTATION[c.state];
  const sla = _slaState(c.sla_due_at, c.closed_at);
  return (
    <tr
      onClick={onClick}
      onMouseEnter={onMouseEnter}
      className="h-12 cursor-pointer transition-colors"
      style={{
        borderBottom: "1px solid var(--color-border)",
        background: active ? "var(--color-surface)" : "transparent",
      }}
    >
      <td className="p-0">
        {/* Severity stripe */}
        <div className="w-[3px] h-12" style={{ background: sev.stripeColor }} />
      </td>
      <td className="px-3 pl-4">
        <span
          className="inline-flex items-center justify-center h-[20px] px-1.5 text-[10px] font-bold tracking-[0.06em]"
          style={{ borderRadius: "4px", border: `1px solid ${sev.chipBorder}`, background: sev.chipBg, color: sev.chipColor }}
        >
          {sev.label}
        </span>
      </td>
      <td className="px-3 font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
        {_shortId(c.id)}
      </td>
      <td className="px-3">
        <div dir="auto" className="text-[13px] font-semibold line-clamp-1" style={{ color: "var(--color-ink)" }}>
          {c.title}
        </div>
        {c.summary ? (
          <div dir="auto" className="text-[12px] line-clamp-1 mt-0.5" style={{ color: "var(--color-muted)" }}>
            {c.summary}
          </div>
        ) : null}
      </td>
      <td className="px-3">
        <span
          className="inline-flex items-center h-[20px] px-1.5 text-[10px] font-bold tracking-[0.06em]"
          style={{
            borderRadius: "4px",
            border: `1px solid ${stt.chipBorder}`,
            background: "var(--color-canvas)",
            color: stt.chipColor,
          }}
        >
          {stt.label}
        </span>
      </td>
      <td className="px-3">
        <SlaCell tone={sla.tone} label={sla.label} />
      </td>
      <td className="px-3">
        {c.tags.length === 0 ? (
          <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>—</span>
        ) : (
          <div className="flex items-center gap-1 flex-wrap">
            {c.tags.slice(0, 2).map((t) => (
              <span
                key={t}
                className="inline-flex items-center h-[18px] px-1.5 text-[10px] font-semibold"
                style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
              >
                {t}
              </span>
            ))}
            {c.tags.length > 2 ? (
              <span className="text-[10px] font-semibold" style={{ color: "var(--color-muted)" }}>
                +{c.tags.length - 2}
              </span>
            ) : null}
          </div>
        )}
      </td>
      <td className="px-3">
        <Avatar id={c.assignee_user_id || c.owner_user_id} />
      </td>
      <td className="px-3 pr-4 text-right text-[12px] font-mono tabular-nums whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
        {timeAgo(c.updated_at)}
      </td>
    </tr>
  );
}

function SlaCell({ tone, label }: { tone: "ok" | "warn" | "breach" | "none"; label: string }) {
  const color =
    tone === "breach" ? "#B71D18"
    : tone === "warn" ? "#B76E00"
    : tone === "ok" ? "var(--color-body)"
    : "var(--color-muted)";
  return (
    <span className="font-mono text-[11.5px] font-semibold tabular-nums tracking-[0.04em]" style={{ color }}>
      {label}
    </span>
  );
}

function Avatar({ id }: { id: string | null }) {
  if (!id) return <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>—</span>;
  const hash = parseInt(id.replace(/[^0-9a-f]/g, "").slice(-2) || "0", 16);
  const tones = [
    { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
    { bg: "rgba(255,79,0,0.1)", color: "var(--color-accent)" },
    { bg: "rgba(255,171,0,0.1)", color: "#B76E00" },
    { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
    { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  ];
  const tone = tones[hash % tones.length];
  return (
    <span
      className="inline-flex items-center justify-center w-7 h-7 text-[10px] font-bold tracking-tight"
      style={{ borderRadius: "50%", background: tone.bg, color: tone.color }}
      title={id}
    >
      {_initials(id.slice(-4))}
    </span>
  );
}

function StatCell({
  label,
  value,
  tone,
  accentColor,
  highlightLabel,
}: {
  label: string;
  value: number | string;
  tone: "neutral" | "error";
  accentColor?: string;
  highlightLabel?: boolean;
}) {
  return (
    <div className="px-4 py-4 relative" style={{ borderRight: "1px solid var(--color-border)" }}>
      {accentColor ? (
        <span
          className="absolute left-0 top-3 bottom-3 w-[2px]"
          style={{ borderRadius: "0 2px 2px 0", background: accentColor }}
        />
      ) : null}
      <div
        className="text-[10px] font-bold uppercase tracking-[0.12em]"
        style={{ color: highlightLabel ? "#B71D18" : "var(--color-muted)" }}
      >
        {label}
      </div>
      <div
        className="mt-1.5 font-mono tabular-nums text-[28px] leading-none font-extrabold tracking-[-0.01em]"
        style={{ color: tone === "error" ? "#FF5630" : "var(--color-ink)" }}
      >
        {value}
      </div>
    </div>
  );
}

function SegmentedFilter<T extends string>({
  label,
  values,
  current,
  onChange,
  renderLabel,
}: {
  label: string;
  values: T[];
  current: T;
  onChange: (v: T) => void;
  renderLabel: (v: T) => string;
}) {
  return (
    <Select
      ariaLabel={label}
      value={current}
      onChange={onChange}
      options={values.map((v) => ({ value: v, label: renderLabel(v) }))}
    />
  );
}

function CasesSkeleton({ rows }: { rows: number }) {
  return (
    <div style={{ borderColor: "var(--color-border)" }} className="divide-y">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-12 px-4 flex items-center gap-4 animate-pulse"
          style={{ animationDelay: `${i * 60}ms` }}
        >
          <div className="w-[3px] h-8 -mx-4 ml-0" style={{ background: "var(--color-surface-muted)" }} />
          <div className="w-[52px] h-4 rounded" style={{ background: "var(--color-surface-muted)" }} />
          <div className="w-[60px] h-3 rounded" style={{ background: "var(--color-surface-muted)" }} />
          <div className="flex-1 h-4 rounded max-w-[480px]" style={{ background: "var(--color-surface-muted)" }} />
          <div className="w-[100px] h-4 rounded" style={{ background: "var(--color-surface-muted)" }} />
          <div className="w-[80px] h-4 rounded" style={{ background: "var(--color-surface-muted)" }} />
          <div className="w-7 h-7 rounded-full" style={{ background: "var(--color-surface-muted)" }} />
        </div>
      ))}
    </div>
  );
}

function EmptyState({
  hasFilters,
  onCreate,
  onReset,
}: {
  hasFilters: boolean;
  onCreate: () => void;
  onReset: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      <div
        className="w-12 h-12 flex items-center justify-center mb-4"
        style={{ borderRadius: "50%", background: "var(--color-surface-muted)", boxShadow: "0 0 0 8px var(--color-surface)" }}
      >
        <Briefcase className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
      </div>
      {hasFilters ? (
        <>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>No cases match these filters</h3>
          <p className="text-[13px] mt-1.5 max-w-[420px]" style={{ color: "var(--color-muted)" }}>
            Try widening the search or clearing the filter set.
          </p>
          <button
            onClick={onReset}
            className="mt-4 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >
            Clear filters
          </button>
        </>
      ) : (
        <>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>No cases yet for this organization</h3>
          <p className="text-[13px] mt-1.5 max-w-[460px]" style={{ color: "var(--color-muted)" }}>
            Cases auto-promote when an Argus detector emits a HIGH or
            CRITICAL finding (suspect domain, exposure, fraud signal,
            impersonation, DLP hit). Run a brand scan or wait for the
            next worker tick — or open one manually below.
          </p>
          <button
            onClick={onCreate}
            className="mt-5 inline-flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
          >
            <Plus className="w-4 h-4" />
            New case
          </button>
        </>
      )}
    </div>
  );
}

function NewCaseModal({
  draft,
  setDraft,
  onClose,
  onSubmit,
  submitting,
}: {
  draft: NewCasePayload;
  setDraft: (p: NewCasePayload | ((p: NewCasePayload) => NewCasePayload)) => void;
  onClose: () => void;
  onSubmit: () => void;
  submitting: boolean;
}) {
  const [tagInput, setTagInput] = useState("");
  const titleRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => { titleRef.current?.focus(); }, []);

  const onTagKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      const t = tagInput.trim().replace(/,$/, "");
      if (t && !draft.tags.includes(t)) {
        setDraft((d) => ({ ...d, tags: [...d.tags, t] }));
      }
      setTagInput("");
    } else if (e.key === "Backspace" && !tagInput && draft.tags.length) {
      setDraft((d) => ({ ...d, tags: d.tags.slice(0, -1) }));
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(32,21,21,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[560px] overflow-hidden"
        style={{ background: "var(--color-canvas)", borderRadius: "8px", border: "1px solid var(--color-border)", boxShadow: "var(--shadow-z24)" }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="new-case-title"
      >
        <div
          className="px-6 pt-5 pb-4 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h2 id="new-case-title" className="text-[16px] font-semibold tracking-tight" style={{ color: "var(--color-ink)" }}>
            New case
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 transition-colors"
            style={{ borderRadius: "4px" }}
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            aria-label="Close"
          >
            <X className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
          </button>
        </div>
        <div className="p-6 space-y-5">
          <Field label="Title" required hint="Plain summary, e.g. Suspect domain argus-secure.com confirmed phishing">
            <input
              ref={titleRef}
              value={draft.title}
              onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))}
              maxLength={500}
              className="w-full h-10 px-3 text-[13px] outline-none"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
              placeholder="What is this case about?"
            />
          </Field>

          <Field label="Summary" hint="Optional context or analyst notes.">
            <textarea
              value={draft.summary}
              onChange={(e) => setDraft((d) => ({ ...d, summary: e.target.value }))}
              rows={3}
              className="w-full px-3 py-2 text-[13px] outline-none resize-none"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
              placeholder="Background, hypothesis, links…"
            />
          </Field>

          <Field label="Severity" required>
            <div className="grid grid-cols-5 gap-1.5">
              {SEVERITIES.map((s) => {
                const p = SEVERITY_PRESENTATION[s];
                const active = draft.severity === s;
                return (
                  <button
                    key={s}
                    onClick={() => setDraft((d) => ({ ...d, severity: s }))}
                    className="h-10 text-[11px] font-bold tracking-[0.06em] transition-all"
                    style={{
                      borderRadius: "4px",
                      border: `1px solid ${active ? p.chipBorder : "var(--color-border)"}`,
                      background: active ? p.chipBg : "var(--color-canvas)",
                      color: active ? p.chipColor : "var(--color-muted)",
                    }}
                  >
                    {p.label}
                  </button>
                );
              })}
            </div>
          </Field>

          <Field label="Tags" hint="Press enter or comma to add. Tags surface in the list filter.">
            <div
              className="flex flex-wrap items-center gap-1.5 min-h-[40px] p-2"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
              onClick={() => {
                const el = document.getElementById("new-case-tag-input") as HTMLInputElement | null;
                el?.focus();
              }}
            >
              {draft.tags.map((t) => (
                <span
                  key={t}
                  className="inline-flex items-center gap-1 h-6 pl-2 pr-1 text-[11px] font-semibold"
                  style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                >
                  {t}
                  <button
                    onClick={() => setDraft((d) => ({ ...d, tags: d.tags.filter((x) => x !== t) }))}
                    className="p-0.5 transition-colors"
                    style={{ borderRadius: "3px" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-border)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <X className="w-3 h-3" style={{ color: "var(--color-muted)" }} />
                  </button>
                </span>
              ))}
              <input
                id="new-case-tag-input"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={onTagKeyDown}
                placeholder={draft.tags.length === 0 ? "phishing, kyc, vip…" : ""}
                className="flex-1 min-w-[80px] bg-transparent outline-none text-[13px]"
                style={{ color: "var(--color-ink)" }}
              />
            </div>
          </Field>
        </div>

        <div
          className="px-6 py-4 flex items-center justify-end gap-2"
          style={{ borderTop: "1px solid var(--color-border)", background: "var(--color-surface)" }}
        >
          <button
            onClick={onClose}
            className="h-9 px-3 text-[13px] font-semibold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          >
            Cancel
          </button>
          <button
            onClick={onSubmit}
            disabled={!draft.title.trim() || submitting}
            className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
          >
            {submitting ? "Creating…" : "Create case"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-1.5">
        <label className="text-[10px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-muted)" }}>
          {label}
        </label>
        {required ? (
          <span className="text-[10px] font-bold" style={{ color: "#FF5630" }}>*</span>
        ) : null}
      </div>
      {children}
      {hint ? (
        <p className="text-[11px] mt-1.5" style={{ color: "var(--color-muted)" }}>{hint}</p>
      ) : null}
    </div>
  );
}
