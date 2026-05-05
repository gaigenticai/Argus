"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  Plus,
  RefreshCw,
  Workflow,
  XCircle,
} from "lucide-react";
import {
  api,
  type Org,
  type TakedownListParams,
  type TakedownPartnerEntry,
  type TakedownPartnerValue,
  type TakedownStateValue,
  type TakedownTargetKindValue,
  type TakedownTicketHistoryEntry,
  type TakedownTicketResponse,
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
import { Select as ThemedSelect } from "@/components/shared/select";
import { CoverageGate } from "@/components/shared/coverage-gate";

const STATES: TakedownStateValue[] = [
  "submitted",
  "acknowledged",
  "in_progress",
  "succeeded",
  "rejected",
  "failed",
  "withdrawn",
];

const STATE_LABEL: Record<TakedownStateValue, string> = {
  submitted: "SUBMITTED",
  acknowledged: "ACKED",
  in_progress: "IN PROGRESS",
  succeeded: "SUCCEEDED",
  rejected: "REJECTED",
  failed: "FAILED",
  withdrawn: "WITHDRAWN",
};
const STATE_TONE: Record<TakedownStateValue, StateTone> = {
  submitted: "info",
  acknowledged: "info",
  in_progress: "warning",
  succeeded: "success",
  rejected: "error-strong",
  failed: "error-strong",
  withdrawn: "muted",
};

// Kanban column groupings
const COLUMNS: Array<{
  id: string;
  label: string;
  states: TakedownStateValue[];
}> = [
  { id: "queue", label: "Submitted", states: ["submitted"] },
  { id: "active", label: "In progress", states: ["acknowledged", "in_progress"] },
  { id: "won", label: "Succeeded", states: ["succeeded"] },
  { id: "lost", label: "Rejected / Failed", states: ["rejected", "failed", "withdrawn"] },
];

const PARTNER_LABEL: Record<TakedownPartnerValue, string> = {
  netcraft: "Netcraft",
  phishlabs: "PhishLabs",
  group_ib: "Group-IB",
  internal_legal: "Internal Legal",
  manual: "Manual",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  direct_registrar: "Direct Registrar",
};

const TARGET_LABEL: Record<TakedownTargetKindValue, string> = {
  suspect_domain: "DOMAIN",
  impersonation: "IMPERS",
  mobile_app: "MOBILE",
  fraud: "FRAUD",
  other: "OTHER",
};

const PAGE_LIMIT = 200;

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

const textareaStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  fontSize: "13px",
  outline: "none",
  resize: "none",
};

export default function TakedownsPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [rows, setRows] = useState<TakedownTicketResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<"kanban" | "table">("kanban");
  const [stateFilter, setStateFilter] = useState<TakedownStateValue | "all">(
    "all",
  );
  const [partnerFilter, setPartnerFilter] = useState<TakedownPartnerValue | "all">(
    "all",
  );
  const [showSubmit, setShowSubmit] = useState(false);
  const [transitionTarget, setTransitionTarget] =
    useState<TakedownTicketResponse | null>(null);
  // Click-to-open detail drawer. Holds the ticket id of the row the
  // analyst clicked; the drawer reads the live row from `rows` so it
  // stays in sync after sync/advance, then closes on ESC or backdrop.
  const [detailId, setDetailId] = useState<string | null>(null);
  // Bulk selection — Set<ticketId>. Drives the floating action bar
  // that appears when ≥1 row is selected. Cleared on org switch and
  // after every successful bulk run.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkAdvanceState, setBulkAdvanceState] = useState<TakedownStateValue | null>(null);
  const toggleSelected = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const clearSelection = useCallback(() => setSelectedIds(new Set()), []);

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
      const params: TakedownListParams = {
        organization_id: orgId,
        state: stateFilter === "all" ? undefined : stateFilter,
        partner: partnerFilter === "all" ? undefined : partnerFilter,
        limit: PAGE_LIMIT,
      };
      const { data } = await api.takedown.listTickets(params);
      setRows(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load takedown tickets",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, partnerFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const transition = async (
    target: TakedownTicketResponse,
    to: TakedownStateValue,
    reason: string,
  ) => {
    try {
      await api.takedown.transitionTicket(target.id, {
        to_state: to,
        reason: reason || undefined,
      });
      toast("success", `Ticket → ${STATE_LABEL[to]}`);
      setTransitionTarget(null);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Transition failed",
      );
    }
  };

  const sync = async (target: TakedownTicketResponse) => {
    try {
      await api.takedown.syncTicket(target.id);
      toast("success", "Synced from partner");
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Sync failed");
    }
  };

  // Org switch wipes any in-flight selection — selecting tickets in
  // ENBD then switching to Liv shouldn't carry the selection across.
  useEffect(() => {
    clearSelection();
  }, [orgId, clearSelection]);

  /**
   * Run an async task across N ticket ids with bounded concurrency.
   * Surfaces a single toast at the end with success / failure counts
   * so the operator sees one summary line instead of N toasts.
   *
   * The concurrency cap (5) keeps us inside the rate limits of every
   * partner adapter. Sync against Netcraft at ~10 RPS is fine; bulk
   * advance hits Postgres only.
   */
  const runBulk = useCallback(
    async (
      label: string,
      ids: string[],
      worker: (id: string) => Promise<void>,
    ) => {
      if (ids.length === 0) return;
      setBulkBusy(true);
      let ok = 0;
      let failed = 0;
      const queue = [...ids];
      const concurrency = 5;
      const runOne = async () => {
        while (queue.length) {
          const id = queue.shift()!;
          try {
            await worker(id);
            ok++;
          } catch {
            failed++;
          }
        }
      };
      try {
        await Promise.all(
          Array.from({ length: Math.min(concurrency, ids.length) }, () => runOne())
        );
        if (failed === 0) {
          toast("success", `${label}: ${ok} succeeded.`);
        } else if (ok === 0) {
          toast("error", `${label}: ${failed} failed.`);
        } else {
          toast("error", `${label}: ${ok} succeeded, ${failed} failed.`);
        }
      } finally {
        setBulkBusy(false);
        clearSelection();
        await load();
      }
    },
    [toast, clearSelection, load],
  );

  const bulkSync = useCallback(async () => {
    const ids = Array.from(selectedIds);
    await runBulk("Sync", ids, async (id) => {
      await api.takedown.syncTicket(id);
    });
  }, [selectedIds, runBulk]);

  const bulkAdvance = useCallback(
    async (to: TakedownStateValue, reason: string) => {
      const ids = Array.from(selectedIds);
      await runBulk(`Advance to ${STATE_LABEL[to]}`, ids, async (id) => {
        await api.takedown.transitionTicket(id, {
          to_state: to,
          reason: reason || undefined,
        });
      });
      setBulkAdvanceState(null);
    },
    [selectedIds, runBulk],
  );

  const grouped = useMemo(() => {
    const m: Record<string, TakedownTicketResponse[]> = {};
    for (const col of COLUMNS) m[col.id] = [];
    for (const r of rows) {
      const col = COLUMNS.find((c) => c.states.includes(r.state));
      if (col) m[col.id].push(r);
    }
    return m;
  }, [rows]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Workflow, label: "Operations" }}
        title="Takedowns"
        description="Outbound takedown tickets to registrars, hosting providers, app stores, and platform abuse desks. Each ticket tracks the partner reference, state machine, and proof of removal."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={load} refreshing={loading} />
            <SubmitButton onClick={() => setShowSubmit(true)} />
          </>
        }
      />

      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            ...STATES.map((s) => ({ value: s, label: STATE_LABEL[s] })),
          ]}
          onChange={(v) => setStateFilter(v as TakedownStateValue | "all")}
        />
        <Select
          ariaLabel="Partner"
          value={partnerFilter}
          options={[
            { value: "all", label: "Any partner" },
            ...(Object.keys(PARTNER_LABEL) as TakedownPartnerValue[]).map(
              (p) => ({ value: p, label: PARTNER_LABEL[p] }),
            ),
          ]}
          onChange={(v) => setPartnerFilter(v as TakedownPartnerValue | "all")}
        />
        <ViewToggle view={view} onChange={setView} />
      </div>

      {view === "kanban" ? (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {COLUMNS.map((col) => (
            <KanbanColumn
              key={col.id}
              label={col.label}
              tickets={grouped[col.id] || []}
              loading={loading}
              onAdvance={(t) => setTransitionTarget(t)}
              onSync={sync}
              onOpenDetail={(t) => setDetailId(t.id)}
              selectedIds={selectedIds}
              onToggleSelected={toggleSelected}
            />
          ))}
        </div>
      ) : (
        <Section>
          {loading ? (
            <SkeletonRows rows={6} columns={6} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Workflow}
              title="No takedown tickets yet"
              description="Submit one for any suspect domain, impersonation handle, fraudulent app, or scam channel. The partner adapter dispatches and tracks state."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                    <Th align="left" className="pl-4 w-[100px]">
                      Target
                    </Th>
                    <Th align="left">Identifier</Th>
                    <Th align="left" className="w-[120px]">
                      Partner
                    </Th>
                    <Th align="left" className="w-[120px]">
                      State
                    </Th>
                    <Th align="left" className="w-[110px]">
                      Submitted
                    </Th>
                    <Th align="left" className="w-[110px]">
                      Resolved
                    </Th>
                    <Th align="right" className="pr-4 w-[160px]">
                      &nbsp;
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((t) => (
                    <TableTicketRow
                      key={t.id}
                      t={t}
                      onSync={() => sync(t)}
                      onAdvance={() => setTransitionTarget(t)}
                      onOpenDetail={() => setDetailId(t.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {showSubmit && orgId && (
        <SubmitTakedownModal
          orgId={orgId}
          onClose={() => setShowSubmit(false)}
          onSubmitted={() => {
            setShowSubmit(false);
            load();
          }}
        />
      )}

      {transitionTarget && (
        <TransitionModal
          target={transitionTarget}
          onClose={() => setTransitionTarget(null)}
          onSubmit={(to, reason) => transition(transitionTarget, to, reason)}
        />
      )}

      {/* Click-to-open detail drawer. We resolve the ticket from the
          live `rows` array (not a captured snapshot) so SYNC / ADVANCE
          performed from inside the drawer reflect immediately after
          load() refreshes rows. If the ticket was filtered out (org
          switch, state filter), the drawer auto-closes. */}
      {detailId && (() => {
        const target = rows.find((r) => r.id === detailId);
        if (!target) return null;
        return (
          <TicketDetailDrawer
            ticket={target}
            onClose={() => setDetailId(null)}
            onSync={() => sync(target)}
            onAdvance={() => setTransitionTarget(target)}
          />
        );
      })()}
      {/* If the ticket disappears from `rows` while the drawer is open
          (filter/org switch), close it on the next render. */}
      {detailId && !rows.some((r) => r.id === detailId) && (
        <DrawerAutoClose onClose={() => setDetailId(null)} />
      )}

      {/* Bulk-action floating bar — appears whenever ≥1 row is selected.
          Positioned bottom-center so it doesn't shift the page on appearance.
          Concurrency is bounded inside runBulk(). */}
      {selectedIds.size > 0 && (
        <div
          role="region"
          aria-label="Bulk actions"
          style={{
            position: "fixed",
            bottom: 24,
            left: "50%",
            transform: "translateX(-50%)",
            zIndex: 60,
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border-strong)",
            borderRadius: 6,
            padding: "10px 14px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            boxShadow: "0 8px 24px rgba(0,0,0,0.16)",
          }}
        >
          <span className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
            {selectedIds.size} selected
          </span>
          <span style={{ color: "var(--color-border)" }}>·</span>
          <button
            type="button"
            disabled={bulkBusy}
            onClick={() => void bulkSync()}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-body)",
              cursor: bulkBusy ? "wait" : "pointer",
            }}
            title="Sync each selected ticket from its partner"
          >
            <RefreshCw className="w-3 h-3" /> Sync all
          </button>
          <button
            type="button"
            disabled={bulkBusy}
            onClick={() => setBulkAdvanceState("withdrawn")}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-body)",
              cursor: bulkBusy ? "wait" : "pointer",
            }}
            title="Withdraw all selected tickets (requires reason)"
          >
            Withdraw all
          </button>
          <button
            type="button"
            disabled={bulkBusy}
            onClick={() => setBulkAdvanceState("acknowledged")}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold disabled:opacity-50"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-body)",
              cursor: bulkBusy ? "wait" : "pointer",
            }}
            title="Mark all as acknowledged"
          >
            Acknowledge all
          </button>
          <span style={{ color: "var(--color-border)" }}>·</span>
          <button
            type="button"
            disabled={bulkBusy}
            onClick={clearSelection}
            className="inline-flex items-center h-8 px-2 text-[12px] disabled:opacity-50"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-muted)",
              cursor: bulkBusy ? "wait" : "pointer",
            }}
          >
            Clear
          </button>
        </div>
      )}

      {bulkAdvanceState && (
        <BulkAdvanceModal
          targetState={bulkAdvanceState}
          count={selectedIds.size}
          onClose={() => setBulkAdvanceState(null)}
          onSubmit={(reason) => bulkAdvance(bulkAdvanceState, reason)}
        />
      )}
    </div>
  );
}

function SubmitButton({ onClick }: { onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "40px",
        padding: "0 16px",
        borderRadius: "4px",
        border: "none",
        background: hov ? "#e64600" : "var(--color-accent)",
        color: "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 700,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <Plus style={{ width: "16px", height: "16px" }} />
      Submit takedown
    </button>
  );
}

function ViewToggle({
  view,
  onChange,
}: {
  view: "kanban" | "table";
  onChange: (v: "kanban" | "table") => void;
}) {
  const [hovKanban, setHovKanban] = useState(false);
  const [hovTable, setHovTable] = useState(false);
  return (
    <div
      style={{
        marginLeft: "auto",
        display: "inline-flex",
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        overflow: "hidden",
      }}
    >
      <button
        onClick={() => onChange("kanban")}
        onMouseEnter={() => setHovKanban(true)}
        onMouseLeave={() => setHovKanban(false)}
        style={{
          padding: "0 12px",
          height: "36px",
          fontSize: "12px",
          fontWeight: 700,
          border: "none",
          borderRight: "1px solid var(--color-border)",
          background: view === "kanban" ? "var(--color-border-strong)" : hovKanban ? "var(--color-surface-muted)" : "var(--color-canvas)",
          color: view === "kanban" ? "var(--color-on-dark)" : "var(--color-body)",
          cursor: "pointer",
          transition: "background 0.15s, color 0.15s",
        }}
      >
        Kanban
      </button>
      <button
        onClick={() => onChange("table")}
        onMouseEnter={() => setHovTable(true)}
        onMouseLeave={() => setHovTable(false)}
        style={{
          padding: "0 12px",
          height: "36px",
          fontSize: "12px",
          fontWeight: 700,
          border: "none",
          background: view === "table" ? "var(--color-border-strong)" : hovTable ? "var(--color-surface-muted)" : "var(--color-canvas)",
          color: view === "table" ? "var(--color-on-dark)" : "var(--color-body)",
          cursor: "pointer",
          transition: "background 0.15s, color 0.15s",
        }}
      >
        Table
      </button>
    </div>
  );
}

function TableTicketRow({
  t,
  onSync,
  onAdvance,
  onOpenDetail,
}: {
  t: TakedownTicketResponse;
  onSync: () => void;
  onAdvance: () => void;
  onOpenDetail: () => void;
}) {
  const [hov, setHov] = useState(false);
  const [syncHov, setSyncHov] = useState(false);
  const [advHov, setAdvHov] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
  const terminal = ["succeeded", "rejected", "withdrawn"].includes(t.state);
  return (
    <tr
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      onClick={onOpenDetail}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
        cursor: "pointer",
      }}
    >
      <td className="pl-4">
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
          {TARGET_LABEL[t.target_kind]}
        </span>
      </td>
      <td style={{ padding: "0 12px", fontFamily: "monospace", fontSize: "12px", color: "var(--color-ink)", maxWidth: "420px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {t.partner_url ? (
          <a
            href={t.partner_url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            onClick={(e) => e.stopPropagation()}
            onMouseEnter={() => setLinkHov(true)}
            onMouseLeave={() => setLinkHov(false)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              color: linkHov ? "var(--color-accent)" : "var(--color-ink)",
              textDecoration: "none",
              transition: "color 0.15s",
            }}
          >
            {t.target_identifier}
            <ExternalLink style={{ width: "12px", height: "12px", color: "var(--color-muted)" }} />
          </a>
        ) : (
          t.target_identifier
        )}
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
        {PARTNER_LABEL[t.partner]}
      </td>
      <td className="px-3">
        <StatePill
          label={STATE_LABEL[t.state]}
          tone={STATE_TONE[t.state]}
        />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(t.submitted_at)}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {t.succeeded_at
          ? timeAgo(t.succeeded_at)
          : t.failed_at
          ? timeAgo(t.failed_at)
          : "—"}
      </td>
      <td className="pr-4">
        <div className="flex items-center justify-end gap-1">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onSync();
            }}
            onMouseEnter={() => setSyncHov(true)}
            onMouseLeave={() => setSyncHov(false)}
            aria-label="Sync from partner"
            title="Sync from partner"
            style={{
              padding: "6px",
              borderRadius: "4px",
              border: "none",
              background: syncHov ? "var(--color-surface-muted)" : "transparent",
              color: syncHov ? "var(--color-ink)" : "var(--color-muted)",
              cursor: "pointer",
              transition: "background 0.15s, color 0.15s",
            }}
          >
            <RefreshCw style={{ width: "14px", height: "14px" }} />
          </button>
          {!terminal ? (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onAdvance();
              }}
              onMouseEnter={() => setAdvHov(true)}
              onMouseLeave={() => setAdvHov(false)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                height: "28px",
                padding: "0 10px",
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: advHov ? "var(--color-surface-muted)" : "transparent",
                color: "var(--color-body)",
                fontSize: "11px",
                fontWeight: 700,
                cursor: "pointer",
                transition: "background 0.15s",
              }}
            >
              ADVANCE
              <ArrowRight style={{ width: "12px", height: "12px" }} />
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

function KanbanColumn({
  label,
  tickets,
  loading,
  onAdvance,
  onSync,
  onOpenDetail,
  selectedIds,
  onToggleSelected,
}: {
  label: string;
  tickets: TakedownTicketResponse[];
  loading: boolean;
  onAdvance: (t: TakedownTicketResponse) => void;
  onSync: (t: TakedownTicketResponse) => void;
  onOpenDetail: (t: TakedownTicketResponse) => void;
  selectedIds: Set<string>;
  onToggleSelected: (id: string) => void;
}) {
  return (
    <div style={{
      borderRadius: "5px",
      border: "1px solid var(--color-border)",
      background: "var(--color-surface)",
      display: "flex",
      flexDirection: "column",
      minHeight: "400px",
    }}>
      <div style={{ padding: "10px 12px", borderBottom: "1px solid var(--color-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h3 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--color-body)" }}>
          {label}
        </h3>
        <span style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-muted)" }}>
          {tickets.length}
        </span>
      </div>
      <div style={{ flex: 1, padding: "8px", display: "flex", flexDirection: "column", gap: "8px", overflowY: "auto" }}>
        {loading ? (
          <>
            {Array.from({ length: 2 }).map((_, i) => (
              <div
                key={i}
                style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", height: "100px", opacity: 0.5 }}
              />
            ))}
          </>
        ) : tickets.length === 0 ? (
          <div style={{ padding: "32px 12px", textAlign: "center" }}>
            <p style={{ fontSize: "11.5px", color: "var(--color-muted)", fontStyle: "italic" }}>empty</p>
          </div>
        ) : (
          tickets.map((t) => (
            <KanbanCard
              key={t.id}
              ticket={t}
              onAdvance={() => onAdvance(t)}
              onSync={() => onSync(t)}
              onOpenDetail={() => onOpenDetail(t)}
              selected={selectedIds.has(t.id)}
              onToggleSelected={() => onToggleSelected(t.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

function KanbanCard({
  ticket,
  onAdvance,
  onSync,
  onOpenDetail,
  selected,
  onToggleSelected,
}: {
  ticket: TakedownTicketResponse;
  onAdvance: () => void;
  onSync: () => void;
  onOpenDetail: () => void;
  selected: boolean;
  onToggleSelected: () => void;
}) {
  const [hov, setHov] = useState(false);
  const [syncHov, setSyncHov] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
  const [advHov, setAdvHov] = useState(false);
  const terminal = ["succeeded", "rejected", "withdrawn"].includes(ticket.state);
  return (
    <CoverageGate pageSlug="takedowns" pageLabel="Takedowns">
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      onClick={onOpenDetail}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpenDetail();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={`Open ticket details for ${ticket.target_identifier}`}
      style={{
        borderRadius: "5px",
        border: selected
          ? "1px solid var(--color-accent)"
          : hov
            ? "1px solid var(--color-border-strong)"
            : "1px solid var(--color-border)",
        background: selected ? "rgba(255,79,0,0.04)" : "var(--color-canvas)",
        padding: "12px",
        transition: "border-color 0.15s, background 0.15s",
        position: "relative",
        cursor: "pointer",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", marginBottom: "6px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleSelected}
            onClick={(e) => e.stopPropagation()}
            aria-label="Select for bulk action"
            title="Select for bulk action"
            style={{
              cursor: "pointer",
              width: 14,
              height: 14,
              margin: 0,
              accentColor: "var(--color-accent)",
            }}
          />
          <StatePill
            label={STATE_LABEL[ticket.state]}
            tone={STATE_TONE[ticket.state]}
          />
          {ticket.needs_review ? (
            <span
              title={
                ticket.last_partner_state
                  ? `Partner returned "${ticket.last_partner_state}" — unrecognised state. Review in the partner UI.`
                  : "Partner returned an unrecognised state — review in the partner UI."
              }
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "3px",
                padding: "1px 6px",
                borderRadius: "3px",
                background: "rgba(245,158,11,0.12)",
                color: "var(--color-warning-dark)",
                fontSize: "9.5px",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.6px",
              }}
            >
              ⚠ NEEDS REVIEW
            </span>
          ) : null}
        </div>
        <span style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-muted)" }}>
          {timeAgo(ticket.submitted_at)}
        </span>
      </div>
      <div style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: "4px" }}>
        {ticket.target_identifier}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10.5px", color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em" }}>
        <span style={{ padding: "0 4px", borderRadius: "3px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
          {TARGET_LABEL[ticket.target_kind]}
        </span>
        <span>·</span>
        <span>{PARTNER_LABEL[ticket.partner]}</span>
      </div>
      {ticket.partner_reference ? (
        <div style={{ fontSize: "10.5px", color: "var(--color-muted)", fontFamily: "monospace", marginTop: "6px" }}>
          ref: {ticket.partner_reference}
        </div>
      ) : null}
      <div style={{ display: "flex", alignItems: "center", gap: "4px", marginTop: "10px", paddingTop: "8px", borderTop: "1px solid var(--color-border)" }}>
        {/* SYNC = poll the partner for the latest state. Only meaningful
            for non-Manual partners (the Manual adapter's fetch_status
            always returns "open" — it has no external state to read).
            Hidden for Manual to avoid suggesting an action that does
            nothing. */}
        {ticket.partner !== "manual" && ticket.partner_reference ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onSync();
            }}
            onMouseEnter={() => setSyncHov(true)}
            onMouseLeave={() => setSyncHov(false)}
            aria-label="Sync from partner"
            title="Pull the latest state from the partner. Use this first; only ADVANCE manually if the partner is unresponsive."
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              height: "24px",
              padding: "0 8px",
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: syncHov ? "var(--color-surface-muted)" : "transparent",
              color: "var(--color-body)",
              fontSize: "10.5px",
              fontWeight: 700,
              cursor: "pointer",
              transition: "background 0.15s",
            }}
          >
            <RefreshCw style={{ width: "10px", height: "10px" }} />
            SYNC
          </button>
        ) : null}
        {ticket.partner_url ? (
          <a
            href={ticket.partner_url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            onClick={(e) => e.stopPropagation()}
            onMouseEnter={() => setLinkHov(true)}
            onMouseLeave={() => setLinkHov(false)}
            style={{
              padding: "4px",
              borderRadius: "4px",
              color: linkHov ? "var(--color-accent)" : "var(--color-muted)",
              transition: "color 0.15s",
            }}
            aria-label="Open at partner"
            title="Open at partner UI"
          >
            <ExternalLink style={{ width: "12px", height: "12px" }} />
          </a>
        ) : null}
        {!terminal ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onAdvance();
            }}
            onMouseEnter={() => setAdvHov(true)}
            onMouseLeave={() => setAdvHov(false)}
            title={
              ticket.partner === "manual"
                ? "Move this ticket to its next state. The Manual partner has no external system to poll, so ADVANCE is the only mutator."
                : "Manually override state. Prefer SYNC first — only use ADVANCE when the partner is unresponsive or you've confirmed the outcome out-of-band."
            }
            style={{
              marginLeft: "auto",
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              height: "24px",
              padding: "0 8px",
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: advHov ? "var(--color-surface-muted)" : "transparent",
              color: "var(--color-body)",
              fontSize: "10.5px",
              fontWeight: 700,
              cursor: "pointer",
              transition: "background 0.15s",
            }}
          >
            ADVANCE
            <ArrowRight style={{ width: "10px", height: "10px" }} />
          </button>
        ) : ticket.state === "succeeded" ? (
          <CheckCircle2 style={{ width: "12px", height: "12px", color: "#007B55", marginLeft: "auto" }} />
        ) : (
          <XCircle style={{ width: "12px", height: "12px", color: "var(--color-muted)", marginLeft: "auto" }} />
        )}
      </div>
    </div>
      </CoverageGate>
  );
}

function SubmitTakedownModal({
  orgId,
  onClose,
  onSubmitted,
}: {
  orgId: string;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const { toast } = useToast();
  const [partner, setPartner] = useState<TakedownPartnerValue>("manual");
  const [targetKind, setTargetKind] = useState<TakedownTargetKindValue>(
    "suspect_domain",
  );
  const [identifier, setIdentifier] = useState("");
  const [reason, setReason] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false);

  // Per-partner readiness — drives the dropdown's "(not configured)"
  // suffix and the inline hint shown when the operator picks an
  // unwired partner. Without this UX, the operator clicks Submit and
  // gets a cryptic backend error like "PhishLabs adapter requires
  // ARGUS_TAKEDOWN_PHISHLABS_SMTP_RECIPIENT" — which doesn't tell
  // them that the right action is to either pick a different partner
  // or wire the env var.
  const [partners, setPartners] = useState<TakedownPartnerEntry[]>([]);
  useEffect(() => {
    let alive = true;
    api.takedown.listPartners()
      .then((r) => { if (alive) setPartners(r.partners); })
      .catch(() => {});
    return () => { alive = false; };
  }, []);
  const partnerEntry = partners.find((p) => p.name === partner);
  const partnerNotConfigured = partnerEntry && !partnerEntry.is_configured;

  const submit = async () => {
    if (!identifier.trim() || !reason.trim() || busy) return;
    setBusy(true);
    try {
      await api.takedown.createTicket({
        organization_id: orgId,
        partner,
        target_kind: targetKind,
        target_identifier: identifier.trim(),
        reason: reason.trim(),
        contact_email: contactEmail.trim() || undefined,
        evidence_urls: evidence
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
      });
      toast("success", "Takedown submitted");
      onSubmitted();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Submit failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Submit takedown" onClose={onClose}>
      <div className="p-6 space-y-5">
        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Partner"
            required
            hint={
              partnerNotConfigured && partnerEntry?.config_hint
                ? `⚠ ${partnerEntry.config_hint}`
                : undefined
            }
          >
            <ThemedSelect
              value={partner}
              onChange={(v) => setPartner(v as TakedownPartnerValue)}
              ariaLabel="Partner"
              options={
                partners.length > 0
                  // Server-driven options — labels carry the
                  // (not configured) suffix so an operator can't
                  // miss it before clicking.
                  ? partners.map((p) => ({
                      value: p.name,
                      label: p.is_configured
                        ? p.label
                        : `${p.label} — not configured`,
                    }))
                  // Fallback while /partners is in flight (or on a
                  // half-deployed environment that hasn't shipped
                  // the readiness endpoint yet).
                  : (Object.keys(PARTNER_LABEL) as TakedownPartnerValue[]).map((p) => ({
                      value: p,
                      label: PARTNER_LABEL[p],
                    }))
              }
              style={{ width: "100%" }}
            />
          </Field>
          <Field label="Target kind" required>
            <ThemedSelect
              value={targetKind}
              onChange={(v) => setTargetKind(v as TakedownTargetKindValue)}
              ariaLabel="Target kind"
              options={(Object.keys(TARGET_LABEL) as TakedownTargetKindValue[]).map((t) => ({
                value: t,
                label: TARGET_LABEL[t],
              }))}
              style={{ width: "100%" }}
            />
          </Field>
        </div>
        <Field
          label="Target identifier"
          required
          hint="The URL, domain, handle, or app id you want taken down."
        >
          <input
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            style={{ ...inputStyle, fontFamily: "monospace" }}
            placeholder="argus-secure-login.com"
            autoFocus
          />
        </Field>
        <Field
          label="Reason"
          required
          hint="Sent verbatim to the abuse desk; include trademark / phishing evidence."
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            style={textareaStyle}
            placeholder="Cloned login form impersonating Argus Banking, registered 2026-04-22; evidence URL below."
          />
        </Field>
        <Field
          label="Evidence URLs"
          hint="One per line — screenshots, archived copies, complaint references."
        >
          <textarea
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            rows={2}
            style={{ ...textareaStyle, fontFamily: "monospace" }}
            placeholder="https://argus.com/evidence/abc123"
          />
        </Field>
        <Field label="Contact email" hint="Where the partner replies.">
          <input
            type="email"
            value={contactEmail}
            onChange={(e) => setContactEmail(e.target.value)}
            style={inputStyle}
            placeholder="abuse-response@argus.demo"
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Submitting…" : "Submit"}
        // Block submit when the chosen partner has missing config —
        // the backend would reject and the analyst would lose their
        // form input. The "Manual" partner is always configured
        // (no external dependencies) so this never blocks the
        // happy path.
        disabled={
          busy ||
          !identifier.trim() ||
          !reason.trim() ||
          !!partnerNotConfigured
        }
      />
    </ModalShell>
  );
}

function TransitionModal({
  target,
  onClose,
  onSubmit,
}: {
  target: TakedownTicketResponse;
  onClose: () => void;
  onSubmit: (to: TakedownStateValue, reason: string) => void;
}) {
  // Filter to states the backend will actually accept. ``allowed_next``
  // is computed server-side from _ALLOWED_TRANSITIONS, so this list is
  // always in sync with the state-machine truth. Falling back to
  // STATES-minus-current keeps older API responses (pre-allowed_next)
  // working in case of a half-deployed environment.
  const candidates: TakedownStateValue[] =
    target.allowed_next && target.allowed_next.length > 0
      ? (target.allowed_next as TakedownStateValue[])
      : STATES.filter((s) => s !== target.state);
  const [to, setTo] = useState<TakedownStateValue>(candidates[0]);
  const [reason, setReason] = useState("");
  return (
    <ModalShell title="Advance takedown" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Target state" required>
          <div className="grid grid-cols-2 gap-1.5">
            {candidates.map((s) => {
              const active = to === s;
              return (
                <StateButton key={s} active={active} onClick={() => setTo(s)}>
                  <StatePill label={STATE_LABEL[s]} tone={STATE_TONE[s]} />
                </StateButton>
              );
            })}
          </div>
        </Field>
        <Field label="Reason" hint="Captured on the takedown audit trail.">
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            style={textareaStyle}
            placeholder="e.g. Partner ack received via email, ticket #ABC-123."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(to, reason)}
        submitLabel="Advance"
      />
    </ModalShell>
  );
}

/**
 * Bulk-advance reason prompt — required for ``rejected`` / ``failed`` /
 * ``withdrawn`` (backend rejects empty reason on those states with
 * 422). For other states reason is optional but still recorded on the
 * audit trail. The TransitionModal does the same for single tickets;
 * this is the bulk equivalent so the analyst supplies one reason that
 * applies to all selected rows (e.g. "false positives — closing in
 * bulk per L2 review").
 */
function BulkAdvanceModal({
  targetState,
  count,
  onClose,
  onSubmit,
}: {
  targetState: TakedownStateValue;
  count: number;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  const reasonRequired = ["rejected", "failed", "withdrawn"].includes(targetState);
  const canSubmit = !reasonRequired || reason.trim().length > 0;
  return (
    <ModalShell
      title={`${STATE_LABEL[targetState]} ${count} ticket${count === 1 ? "" : "s"}`}
      onClose={onClose}
    >
      <div className="p-6 space-y-4">
        <p className="text-[12.5px]" style={{ color: "var(--color-body)" }}>
          Each selected ticket will transition to{" "}
          <strong style={{ color: "var(--color-ink)" }}>
            {STATE_LABEL[targetState]}
          </strong>
          . Tickets whose current state doesn&apos;t allow this transition
          will fail and be reported in the summary toast.
        </p>
        <Field
          label="Reason"
          required={reasonRequired}
          hint={
            reasonRequired
              ? "Required for this state. Sent to every ticket's audit trail."
              : "Optional. Captured on every ticket's audit trail."
          }
        >
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            style={textareaStyle}
            placeholder="e.g. False positives — closing in bulk per L2 review."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(reason)}
        submitLabel={`Apply to ${count}`}
        disabled={!canSubmit}
      />
    </ModalShell>
  );
}


function StateButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "40px",
        borderRadius: "4px",
        border: active ? "1px solid var(--color-border-strong)" : "1px solid var(--color-border)",
        background: active ? "transparent" : hov ? "var(--color-surface-muted)" : "var(--color-canvas)",
        boxShadow: active ? "var(--color-border-strong) 0px 0px 0px 2px inset" : "none",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "6px",
        cursor: "pointer",
        transition: "background 0.15s, box-shadow 0.15s",
      }}
    >
      {children}
    </button>
  );
}


// ---------------------------------------------------------------------
// Detail drawer
// ---------------------------------------------------------------------

const ACTION_LABEL: Record<string, string> = {
  takedown_submit: "Submitted",
  takedown_state_change: "State change",
};

function fmtDate(s: string): string {
  try {
    const d = new Date(s);
    return d.toLocaleString();
  } catch {
    return s;
  }
}

function TicketDetailDrawer({
  ticket,
  onClose,
  onSync,
  onAdvance,
}: {
  ticket: TakedownTicketResponse;
  onClose: () => void;
  onSync: () => void;
  onAdvance: () => void;
}) {
  const [history, setHistory] = useState<TakedownTicketHistoryEntry[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const terminal = ["succeeded", "rejected", "withdrawn"].includes(ticket.state);

  // Fetch the per-ticket audit timeline. Re-runs whenever the ticket
  // updates (state change / sync) so the timeline shows the new entry
  // without a manual refresh.
  useEffect(() => {
    let alive = true;
    setHistory(null);
    setHistoryError(null);
    (async () => {
      try {
        const res = await api.takedown.getTicketHistory(ticket.id);
        if (!alive) return;
        setHistory(res.entries);
      } catch (e) {
        if (!alive) return;
        setHistoryError(
          e instanceof Error ? e.message : "Failed to load history",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [ticket.id, ticket.updated_at]);

  // ESC closes. Re-bind on every mount so closing then reopening works.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const rawJson = ticket.raw
    ? JSON.stringify(ticket.raw, null, 2)
    : null;

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.32)",
          zIndex: 70,
        }}
      />
      <aside
        role="dialog"
        aria-label="Takedown ticket details"
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: "min(520px, 100vw)",
          background: "var(--color-canvas)",
          borderLeft: "1px solid var(--color-border)",
          zIndex: 71,
          display: "flex",
          flexDirection: "column",
          boxShadow: "-12px 0 32px rgba(0,0,0,0.18)",
        }}
      >
        <header
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--color-border)",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
              <StatePill label={STATE_LABEL[ticket.state]} tone={STATE_TONE[ticket.state]} />
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  height: 18,
                  padding: "0 6px",
                  borderRadius: 4,
                  background: "var(--color-surface-muted)",
                  fontSize: 10.5,
                  fontWeight: 700,
                  color: "var(--color-body)",
                  letterSpacing: "0.06em",
                }}
              >
                {TARGET_LABEL[ticket.target_kind]}
              </span>
              <span style={{ fontSize: 11.5, fontWeight: 700, color: "var(--color-body)", letterSpacing: "0.06em" }}>
                {PARTNER_LABEL[ticket.partner]}
              </span>
              {ticket.needs_review ? (
                <span
                  title={
                    ticket.last_partner_state
                      ? `Partner returned "${ticket.last_partner_state}" — unrecognised state.`
                      : "Partner returned an unrecognised state."
                  }
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 3,
                    padding: "1px 6px",
                    borderRadius: 3,
                    background: "rgba(245,158,11,0.12)",
                    color: "var(--color-warning-dark)",
                    fontSize: 9.5,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.6px",
                  }}
                >
                  ⚠ NEEDS REVIEW
                </span>
              ) : null}
            </div>
            <div
              title={ticket.target_identifier}
              style={{
                fontFamily: "monospace",
                fontSize: 13,
                color: "var(--color-ink)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {ticket.target_identifier}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            title="Close (Esc)"
            style={{
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
              borderRadius: 4,
              width: 28,
              height: 28,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              fontSize: 14,
              flexShrink: 0,
            }}
          >
            ×
          </button>
        </header>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>
          {/* Field grid */}
          <dl
            style={{
              display: "grid",
              gridTemplateColumns: "120px 1fr",
              rowGap: 8,
              columnGap: 12,
              fontSize: 12.5,
              margin: 0,
            }}
          >
            <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
              Submitted
            </dt>
            <dd style={{ color: "var(--color-ink)", margin: 0 }}>
              {fmtDate(ticket.submitted_at)}
            </dd>

            {ticket.acknowledged_at ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  Acknowledged
                </dt>
                <dd style={{ color: "var(--color-ink)", margin: 0 }}>
                  {fmtDate(ticket.acknowledged_at)}
                </dd>
              </>
            ) : null}

            {ticket.succeeded_at ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  Succeeded
                </dt>
                <dd style={{ color: "var(--color-ink)", margin: 0 }}>
                  {fmtDate(ticket.succeeded_at)}
                </dd>
              </>
            ) : null}

            {ticket.failed_at ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  {ticket.state === "rejected" ? "Rejected" : "Failed"}
                </dt>
                <dd style={{ color: "var(--color-ink)", margin: 0 }}>
                  {fmtDate(ticket.failed_at)}
                </dd>
              </>
            ) : null}

            <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
              Partner ref
            </dt>
            <dd style={{ color: "var(--color-ink)", margin: 0, fontFamily: "monospace", wordBreak: "break-all" }}>
              {ticket.partner_reference || <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>}
            </dd>

            {ticket.partner_url ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  Partner URL
                </dt>
                <dd style={{ margin: 0, fontFamily: "monospace", wordBreak: "break-all" }}>
                  <a
                    href={ticket.partner_url}
                    target="_blank"
                    rel="noopener noreferrer nofollow"
                    style={{
                      color: "var(--color-accent)",
                      textDecoration: "none",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    Open at partner
                    <ExternalLink style={{ width: 12, height: 12 }} />
                  </a>
                </dd>
              </>
            ) : null}

            {ticket.last_partner_state ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  Last partner state
                </dt>
                <dd style={{ color: "var(--color-ink)", margin: 0, fontFamily: "monospace" }}>
                  {ticket.last_partner_state}
                </dd>
              </>
            ) : null}

            {ticket.proof_evidence_sha256 ? (
              <>
                <dt style={{ color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10.5 }}>
                  Proof SHA-256
                </dt>
                <dd style={{ color: "var(--color-ink)", margin: 0, fontFamily: "monospace", fontSize: 11.5, wordBreak: "break-all" }}>
                  {ticket.proof_evidence_sha256}
                </dd>
              </>
            ) : null}
          </dl>

          {ticket.notes ? (
            <section style={{ marginTop: 20 }}>
              <h4
                style={{
                  fontSize: 10.5,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.12em",
                  color: "var(--color-body)",
                  margin: "0 0 8px",
                }}
              >
                Notes
              </h4>
              <pre
                style={{
                  margin: 0,
                  padding: "10px 12px",
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                  fontSize: 11.5,
                  fontFamily: "monospace",
                  color: "var(--color-ink)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {ticket.notes}
              </pre>
            </section>
          ) : null}

          {/* Audit timeline */}
          <section style={{ marginTop: 20 }}>
            <h4
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.12em",
                color: "var(--color-body)",
                margin: "0 0 8px",
              }}
            >
              Timeline
            </h4>
            {history === null && historyError === null ? (
              <p style={{ fontSize: 11.5, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                Loading…
              </p>
            ) : historyError ? (
              <p style={{ fontSize: 11.5, color: "var(--color-error-strong)", margin: 0 }}>
                {historyError}
              </p>
            ) : history && history.length > 0 ? (
              <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                {history.map((h) => {
                  const d = (h.details || {}) as Record<string, unknown>;
                  const from = typeof d.from === "string" ? d.from : null;
                  const to = typeof d.to === "string" ? d.to : null;
                  const reason = typeof d.reason === "string" ? d.reason : null;
                  const partnerState = typeof d.partner_state === "string" ? d.partner_state : null;
                  const action = typeof d.action === "string" ? d.action : null;
                  return (
                    <li
                      key={h.id}
                      style={{
                        padding: "8px 10px",
                        border: "1px solid var(--color-border)",
                        borderRadius: 4,
                        background: "var(--color-surface)",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between" }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--color-ink)" }}>
                          {action === "sync"
                            ? "Sync"
                            : ACTION_LABEL[h.action] || h.action}
                          {from && to ? ` (${from} → ${to})` : null}
                          {action === "sync" && partnerState ? ` (partner: ${partnerState})` : null}
                        </span>
                        <span style={{ fontFamily: "monospace", fontSize: 10.5, color: "var(--color-muted)" }}>
                          {fmtDate(h.timestamp)}
                        </span>
                      </div>
                      {h.actor_email ? (
                        <div style={{ fontSize: 10.5, color: "var(--color-muted)", marginTop: 2 }}>
                          by {h.actor_email}
                        </div>
                      ) : null}
                      {reason ? (
                        <div
                          style={{
                            marginTop: 4,
                            padding: "4px 6px",
                            background: "var(--color-canvas)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 3,
                            fontSize: 11.5,
                            fontFamily: "monospace",
                            color: "var(--color-ink)",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-word",
                          }}
                        >
                          {reason}
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ol>
            ) : (
              <p style={{ fontSize: 11.5, color: "var(--color-muted)", fontStyle: "italic", margin: 0 }}>
                No history yet.
              </p>
            )}
          </section>

          {rawJson ? (
            <section style={{ marginTop: 20 }}>
              <button
                onClick={() => setShowRaw((v) => !v)}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: 0,
                  background: "transparent",
                  border: "none",
                  color: "var(--color-body)",
                  fontSize: 10.5,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.12em",
                  cursor: "pointer",
                }}
                aria-expanded={showRaw}
              >
                {showRaw ? "▾" : "▸"} Raw partner response
              </button>
              {showRaw ? (
                <pre
                  style={{
                    marginTop: 8,
                    padding: "10px 12px",
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 4,
                    fontSize: 11,
                    fontFamily: "monospace",
                    color: "var(--color-ink)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    maxHeight: 280,
                    overflow: "auto",
                  }}
                >
                  {rawJson}
                </pre>
              ) : null}
            </section>
          ) : null}
        </div>

        <footer
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--color-border)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "flex-end",
          }}
        >
          {ticket.partner !== "manual" && ticket.partner_reference ? (
            <button
              onClick={onSync}
              title="Pull the latest state from the partner."
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                height: 32,
                padding: "0 12px",
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "transparent",
                color: "var(--color-body)",
                fontSize: 11.5,
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              <RefreshCw style={{ width: 12, height: 12 }} />
              SYNC
            </button>
          ) : null}
          {!terminal ? (
            <button
              onClick={onAdvance}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                height: 32,
                padding: "0 14px",
                borderRadius: 4,
                border: "1px solid var(--color-border-strong)",
                background: "var(--color-ink)",
                color: "var(--color-canvas)",
                fontSize: 11.5,
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              ADVANCE
              <ArrowRight style={{ width: 12, height: 12 }} />
            </button>
          ) : null}
        </footer>
      </aside>
    </>
  );
}

function DrawerAutoClose({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    onClose();
  }, [onClose]);
  return null;
}
