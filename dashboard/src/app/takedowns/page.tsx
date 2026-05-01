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
  type TakedownPartnerValue,
  type TakedownStateValue,
  type TakedownTargetKindValue,
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
}: {
  t: TakedownTicketResponse;
  onSync: () => void;
  onAdvance: () => void;
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
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
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
            onClick={onSync}
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
              onClick={onAdvance}
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
}: {
  label: string;
  tickets: TakedownTicketResponse[];
  loading: boolean;
  onAdvance: (t: TakedownTicketResponse) => void;
  onSync: (t: TakedownTicketResponse) => void;
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
}: {
  ticket: TakedownTicketResponse;
  onAdvance: () => void;
  onSync: () => void;
}) {
  const [hov, setHov] = useState(false);
  const [syncHov, setSyncHov] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
  const [advHov, setAdvHov] = useState(false);
  const terminal = ["succeeded", "rejected", "withdrawn"].includes(ticket.state);
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        borderRadius: "5px",
        border: hov ? "1px solid var(--color-border-strong)" : "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        padding: "12px",
        transition: "border-color 0.15s",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", marginBottom: "6px" }}>
        <StatePill
          label={STATE_LABEL[ticket.state]}
          tone={STATE_TONE[ticket.state]}
        />
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
        <button
          onClick={onSync}
          onMouseEnter={() => setSyncHov(true)}
          onMouseLeave={() => setSyncHov(false)}
          aria-label="Sync"
          title="Sync from partner"
          style={{
            padding: "4px",
            borderRadius: "4px",
            border: "none",
            background: syncHov ? "var(--color-surface-muted)" : "transparent",
            color: syncHov ? "var(--color-ink)" : "var(--color-muted)",
            cursor: "pointer",
            transition: "background 0.15s, color 0.15s",
          }}
        >
          <RefreshCw style={{ width: "12px", height: "12px" }} />
        </button>
        {ticket.partner_url ? (
          <a
            href={ticket.partner_url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            onMouseEnter={() => setLinkHov(true)}
            onMouseLeave={() => setLinkHov(false)}
            style={{
              padding: "4px",
              borderRadius: "4px",
              color: linkHov ? "var(--color-accent)" : "var(--color-muted)",
              transition: "color 0.15s",
            }}
            aria-label="Open at partner"
            title="Open at partner"
          >
            <ExternalLink style={{ width: "12px", height: "12px" }} />
          </a>
        ) : null}
        {!terminal ? (
          <button
            onClick={onAdvance}
            onMouseEnter={() => setAdvHov(true)}
            onMouseLeave={() => setAdvHov(false)}
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
          <Field label="Partner" required>
            <ThemedSelect
              value={partner}
              onChange={(v) => setPartner(v as TakedownPartnerValue)}
              ariaLabel="Partner"
              options={(Object.keys(PARTNER_LABEL) as TakedownPartnerValue[]).map((p) => ({
                value: p,
                label: PARTNER_LABEL[p],
              }))}
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
        disabled={busy || !identifier.trim() || !reason.trim()}
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
  const candidates = STATES.filter((s) => s !== target.state);
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
