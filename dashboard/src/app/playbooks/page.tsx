"use client";

/**
 * /playbooks — Catalog · History · Approvals
 *
 * Three tabs in one page:
 *
 * 1. **Catalog** — every applicable playbook for the current org. Click
 *    a row to open the ActionDrawer and run it manually. Mirrors what
 *    the AI briefing surfaces, but always available.
 * 2. **History** — paginated execution log scoped to the org. Drill
 *    into any row to see step results, audit trail, and (for non-
 *    terminal runs) advance/cancel.
 * 3. **Approvals** — admin-only queue of pending_approval rows.
 *    Approve or deny inline; non-admins see an empty notice with
 *    a link to the relevant docs.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  CheckCircle2,
  ClipboardList,
  Clock,
  History as HistoryIcon,
  Layers,
  Loader2,
  Play,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import {
  api,
  type Org,
  type PlaybookCatalogResponse,
  type PlaybookDescriptor,
  type PlaybookExecutionResponse,
  type PlaybookHistoryResponse,
  type PlaybookStatus,
} from "@/lib/api";
import { useAuth } from "@/components/auth/auth-provider";
import {
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
} from "@/components/shared/page-primitives";
import { ActionDrawer } from "@/components/exec-summary/action-drawer";
import { useToast } from "@/components/shared/toast";

type Tab = "catalog" | "history" | "approvals";

const TAB_META: Record<Tab, { label: string; Icon: typeof Layers }> = {
  catalog: { label: "Catalog", Icon: Layers },
  history: { label: "History", Icon: HistoryIcon },
  approvals: { label: "Approvals", Icon: ShieldAlert },
};

export default function PlaybooksPage() {
  const { toast } = useToast();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const searchParams = useSearchParams();

  const initialTab: Tab = (() => {
    const t = searchParams?.get("tab");
    if (t === "history" || t === "approvals" || t === "catalog") return t;
    return "catalog";
  })();

  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [tab, setTab] = useState<Tab>(initialTab);
  const [refreshTick, setRefreshTick] = useState(0);

  // Keep the active tab in sync with the URL — header bell click navigates
  // to /playbooks?tab=approvals from anywhere; if the user is already
  // mounted on /playbooks the page won't remount, so we listen here.
  useEffect(() => {
    const t = searchParams?.get("tab");
    if (t === "history" || t === "approvals" || t === "catalog") {
      setTab(t);
    }
  }, [searchParams]);

  // Drawer state — shared across tabs.
  const [drawer, setDrawer] = useState<
    | { kind: "new"; playbookId: string }
    | { kind: "existing"; executionId: string }
    | null
  >(null);

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

  const refresh = () => setRefreshTick((n) => n + 1);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: ClipboardList, label: "Operations" }}
        title="Playbooks"
        description="Catalogued response actions wired to live data. Run them manually or approve briefing-driven runs from the queue. Every execution is audit-logged with per-step results."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={refresh} refreshing={false} />
          </>
        }
      />

      <div className="flex items-center gap-1">
        {(Object.keys(TAB_META) as Tab[]).map((t) => {
          const m = TAB_META[t];
          const active = t === tab;
          return (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold"
              style={{
                background: active ? "var(--color-canvas)" : "transparent",
                border: "1px solid var(--color-border)",
                borderBottom: active
                  ? "2px solid var(--color-accent)"
                  : "1px solid var(--color-border)",
                borderRadius: "4px 4px 0 0",
                color: active ? "var(--color-ink)" : "var(--color-muted)",
                cursor: "pointer",
              }}
            >
              <m.Icon className="w-3.5 h-3.5" />
              {m.label}
            </button>
          );
        })}
      </div>

      {tab === "catalog" && orgId && (
        <CatalogTab
          orgId={orgId}
          refreshTick={refreshTick}
          onOpenPlaybook={(playbookId) => setDrawer({ kind: "new", playbookId })}
        />
      )}
      {tab === "history" && orgId && (
        <HistoryTab
          orgId={orgId}
          refreshTick={refreshTick}
          onOpenExecution={(id) => setDrawer({ kind: "existing", executionId: id })}
        />
      )}
      {tab === "approvals" && orgId && (
        <ApprovalsTab
          orgId={orgId}
          isAdmin={isAdmin}
          refreshTick={refreshTick}
          onOpenExecution={(id) => setDrawer({ kind: "existing", executionId: id })}
        />
      )}

      {drawer && (
        <ActionDrawer
          executionId={drawer.kind === "existing" ? drawer.executionId : null}
          playbookId={drawer.kind === "new" ? drawer.playbookId : null}
          orgId={orgId}
          isAdmin={isAdmin}
          onClose={() => setDrawer(null)}
          onStateChanged={refresh}
        />
      )}
    </div>
  );
}

// ── Catalog tab ───────────────────────────────────────────────────


function CatalogTab({
  orgId,
  refreshTick,
  onOpenPlaybook,
}: {
  orgId: string;
  refreshTick: number;
  onOpenPlaybook: (playbookId: string) => void;
}) {
  const [data, setData] = useState<PlaybookCatalogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api.exec.playbookCatalog({ organization_id: orgId })
      .then((r) => { if (alive) { setData(r); setError(null); } })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : "Catalog load failed");
      })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [orgId, refreshTick]);

  return (
    <Section>
      {loading && (
        <div className="p-6 flex items-center justify-center">
          <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-muted)" }} />
        </div>
      )}
      {error && !loading && (
        <p className="p-6 text-[12.5px]" style={{ color: "var(--color-error-dark)" }}>
          {error}
        </p>
      )}
      {data && data.items.length === 0 && !loading && (
        <p className="p-6 text-[12.5px]" style={{ color: "var(--color-muted)" }}>
          No playbooks are currently applicable for this org. Run a few scans
          (typosquats, brand suspects, mobile apps) to surface actionable signals.
        </p>
      )}
      {data && data.items.length > 0 && (
        <div className="divide-y" style={{ borderColor: "var(--color-border)" }}>
          {data.items.map((pb) => (
            <CatalogRow key={pb.id} pb={pb} onClick={() => onOpenPlaybook(pb.id)} />
          ))}
        </div>
      )}
    </Section>
  );
}


function CatalogRow({
  pb,
  onClick,
}: {
  pb: PlaybookDescriptor;
  onClick: () => void;
}) {
  return (
    <div className="px-4 py-3 flex items-start gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <h4 className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
            {pb.title}
          </h4>
          <span
            className="text-[10px] font-bold uppercase tracking-[0.6px] px-1.5 py-0.5"
            style={{
              background: "var(--color-surface-muted)",
              color: "var(--color-muted)",
              borderRadius: 3,
            }}
          >
            {pb.category}
          </span>
          {pb.requires_approval && (
            <span
              className="text-[10px] font-bold uppercase tracking-[0.6px] px-1.5 py-0.5"
              style={{
                background: "rgba(245,158,11,0.15)",
                color: "var(--color-warning-dark)",
                borderRadius: 3,
              }}
            >
              Approval required
            </span>
          )}
          {pb.total_steps > 1 && (
            <span
              className="text-[10px] font-bold uppercase tracking-[0.6px] px-1.5 py-0.5"
              style={{
                background: "rgba(99,102,241,0.15)",
                color: "#3730A3",
                borderRadius: 3,
              }}
            >
              {pb.total_steps}-step
            </span>
          )}
        </div>
        <p className="text-[12px] mt-1" style={{ color: "var(--color-body)" }}>
          {pb.description}
        </p>
      </div>
      <button
        type="button"
        onClick={onClick}
        className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold shrink-0"
        style={{
          background: "var(--color-accent)",
          color: "#fffefb",
          border: "1px solid var(--color-accent)",
          borderRadius: 4,
        }}
      >
        <Play className="w-3.5 h-3.5" />
        {pb.cta_label || "Open"}
      </button>
    </div>
  );
}


// ── History tab ───────────────────────────────────────────────────


function HistoryTab({
  orgId,
  refreshTick,
  onOpenExecution,
}: {
  orgId: string;
  refreshTick: number;
  onOpenExecution: (id: string) => void;
}) {
  const [data, setData] = useState<PlaybookHistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<PlaybookStatus | "all">("all");

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api.exec.playbookHistory({
      organization_id: orgId,
      status: statusFilter === "all" ? undefined : statusFilter,
      limit: 100,
    })
      .then((r) => { if (alive) setData(r); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [orgId, statusFilter, refreshTick]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[11px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
          Status
        </span>
        {(["all", "pending_approval", "in_progress", "step_complete", "completed", "failed", "denied", "cancelled"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setStatusFilter(s)}
            className="text-[11px] font-semibold px-2 py-1"
            style={{
              background: statusFilter === s ? "var(--color-canvas)" : "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 3,
              color: statusFilter === s ? "var(--color-ink)" : "var(--color-muted)",
              cursor: "pointer",
            }}
          >
            {s.replace(/_/g, " ")}
          </button>
        ))}
      </div>
      <Section>
        {loading && (
          <div className="p-6 flex items-center justify-center">
            <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-muted)" }} />
          </div>
        )}
        {data && data.items.length === 0 && !loading && (
          <p className="p-6 text-[12.5px]" style={{ color: "var(--color-muted)" }}>
            No executions match this filter.
          </p>
        )}
        {data && data.items.length > 0 && (
          <table className="w-full text-[12.5px]" style={{ borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--color-surface-muted)" }}>
                <Th>Started</Th>
                <Th>Playbook</Th>
                <Th>Status</Th>
                <Th>Step</Th>
                <Th>Trigger</Th>
                <Th>Items</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr
                  key={e.id}
                  onClick={() => onOpenExecution(e.id)}
                  style={{
                    borderTop: "1px solid var(--color-surface-muted)",
                    cursor: "pointer",
                  }}
                >
                  <td className="px-3 py-2 align-top" style={{ color: "var(--color-body)" }}>
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <span className="font-mono text-[11.5px]" style={{ color: "var(--color-ink)" }}>
                      {e.playbook_id}
                    </span>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <SmallStatusPill status={e.status} />
                  </td>
                  <td className="px-3 py-2 align-top" style={{ color: "var(--color-muted)" }}>
                    {e.current_step_index + 1}/{e.total_steps}
                  </td>
                  <td className="px-3 py-2 align-top" style={{ color: "var(--color-muted)" }}>
                    {e.triggered_from === "exec_briefing" ? "Briefing" : "Manual"}
                  </td>
                  <td className="px-3 py-2 align-top text-right font-mono" style={{ color: "var(--color-body)" }}>
                    {countItems(e)}
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


// ── Approvals tab ─────────────────────────────────────────────────


function ApprovalsTab({
  orgId,
  isAdmin,
  refreshTick,
  onOpenExecution,
}: {
  orgId: string;
  isAdmin: boolean;
  refreshTick: number;
  onOpenExecution: (id: string) => void;
}) {
  const [data, setData] = useState<PlaybookHistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api.exec.playbookPendingApprovals({ organization_id: orgId, limit: 100 })
      .then((r) => { if (alive) setData(r); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [orgId, refreshTick]);

  return (
    <Section>
      {!isAdmin && (
        <div className="p-4 text-[12.5px]" style={{ color: "var(--color-muted)" }}>
          <ShieldAlert className="inline w-4 h-4 mr-1" />
          Only admins can approve or deny pending playbook runs. The list
          below is read-only for non-admins.
        </div>
      )}
      {loading && (
        <div className="p-6 flex items-center justify-center">
          <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-muted)" }} />
        </div>
      )}
      {data && data.items.length === 0 && !loading && (
        <div className="p-8 text-center" style={{ color: "var(--color-muted)" }}>
          <CheckCircle2 className="w-6 h-6 mx-auto mb-2" />
          <p className="text-[13px]">No pending approvals — queue is clear.</p>
        </div>
      )}
      {data && data.items.length > 0 && (
        <div className="divide-y" style={{ borderColor: "var(--color-border)" }}>
          {data.items.map((e) => (
            <ApprovalRow
              key={e.id}
              exec={e}
              onClick={() => onOpenExecution(e.id)}
            />
          ))}
        </div>
      )}
    </Section>
  );
}


function ApprovalRow({
  exec,
  onClick,
}: {
  exec: PlaybookExecutionResponse;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter") onClick(); }}
      className="px-4 py-3 flex items-start gap-3"
      style={{ cursor: "pointer" }}
    >
      <Clock className="w-4 h-4 mt-0.5 shrink-0" style={{ color: "var(--color-warning-dark)" }} />
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
          {exec.playbook_id}
        </div>
        <div className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          Requested {new Date(exec.created_at).toLocaleString()} · {exec.triggered_from === "exec_briefing" ? "AI Briefing" : "Manual"}
        </div>
      </div>
      <span
        className="inline-flex items-center text-[11.5px] font-semibold whitespace-nowrap shrink-0"
        style={{ color: "var(--color-accent)" }}
      >
        Review →
      </span>
    </div>
  );
}


function SmallStatusPill({ status }: { status: string }) {
  const meta: Record<string, { bg: string; color: string }> = {
    pending_approval: { bg: "rgba(245,158,11,0.15)", color: "var(--color-warning-dark)" },
    approved:         { bg: "rgba(99,102,241,0.15)", color: "#3730A3" },
    in_progress:      { bg: "rgba(99,102,241,0.15)", color: "#3730A3" },
    step_complete:    { bg: "rgba(34,197,94,0.15)", color: "var(--color-success-dark)" },
    completed:        { bg: "rgba(34,197,94,0.15)", color: "var(--color-success-dark)" },
    failed:           { bg: "rgba(239,68,68,0.15)", color: "var(--color-error-dark)" },
    denied:           { bg: "rgba(239,68,68,0.15)", color: "var(--color-error-dark)" },
    cancelled:        { bg: "rgba(99,115,129,0.15)", color: "var(--color-muted)" },
  };
  const m = meta[status] || { bg: "var(--color-surface-muted)", color: "var(--color-body)" };
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px]"
      style={{ background: m.bg, color: m.color, borderRadius: 3 }}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}


function Th({ children }: { children: React.ReactNode }) {
  return (
    <th
      className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.7px]"
      style={{ color: "var(--color-muted)" }}
    >
      {children}
    </th>
  );
}


function countItems(exec: PlaybookExecutionResponse): string {
  let total = 0;
  for (const sr of exec.step_results) total += sr.items.length;
  if (total === 0) return "—";
  const failed = exec.step_results.reduce(
    (n, sr) => n + sr.items.filter((it) => "error" in it).length,
    0,
  );
  return failed > 0 ? `${total} (${failed} fail)` : `${total}`;
}
