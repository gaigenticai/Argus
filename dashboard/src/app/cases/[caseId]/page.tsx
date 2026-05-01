"use client";

import {
  KeyboardEvent as ReactKeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Calendar,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Edit2,
  ExternalLink,
  Link2,
  Loader2,
  MessageSquare,
  Save,
  Sparkles,
  Trash2,
  User as UserIcon,
  X,
} from "lucide-react";
import {
  ApiError,
  api,
  type CaseDetailResponse,
  type CaseFindingResponse,
  type CaseSeverityValue,
  type CaseStateValue,
  type CopilotRunDetail,
  type InvestigationListItem,
  type InvestigationStatus,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate, timeAgo } from "@/lib/utils";

const SEVERITIES: CaseSeverityValue[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const STATES: CaseStateValue[] = [
  "open",
  "triaging",
  "investigating",
  "containing",
  "remediating",
  "monitoring",
  "closed",
];

const SEVERITY_PRESENTATION: Record<
  CaseSeverityValue,
  { stripeColor: string; chipBg: string; chipBorder: string; chipColor: string; label: string }
> = {
  critical: {
    stripeColor: "#FF5630",
    chipBg: "rgba(255,86,48,0.1)",
    chipBorder: "rgba(255,86,48,0.4)",
    chipColor: "#B71D18",
    label: "CRIT",
  },
  high: {
    stripeColor: "#FF8863",
    chipBg: "rgba(255,136,99,0.1)",
    chipBorder: "rgba(255,136,99,0.4)",
    chipColor: "#B71D18",
    label: "HIGH",
  },
  medium: {
    stripeColor: "#FFAB00",
    chipBg: "rgba(255,171,0,0.1)",
    chipBorder: "rgba(255,171,0,0.4)",
    chipColor: "#B76E00",
    label: "MED",
  },
  low: {
    stripeColor: "#00BBD9",
    chipBg: "rgba(0,187,217,0.1)",
    chipBorder: "rgba(0,187,217,0.4)",
    chipColor: "#007B8A",
    label: "LOW",
  },
  info: {
    stripeColor: "#939084",
    chipBg: "rgba(147,144,132,0.1)",
    chipBorder: "rgba(147,144,132,0.4)",
    chipColor: "#36342e",
    label: "INFO",
  },
};

const STATE_PRESENTATION: Record<
  CaseStateValue,
  { chipBorder: string; chipColor: string; label: string; rank: number }
> = {
  open: { chipBorder: "rgba(147,144,132,0.5)", chipColor: "#36342e", label: "OPEN", rank: 0 },
  triaging: { chipBorder: "rgba(0,187,217,0.5)", chipColor: "#007B8A", label: "TRIAGING", rank: 1 },
  investigating: { chipBorder: "rgba(255,79,0,0.5)", chipColor: "var(--color-accent)", label: "INVESTIGATING", rank: 2 },
  containing: { chipBorder: "rgba(255,171,0,0.5)", chipColor: "#B76E00", label: "CONTAINING", rank: 3 },
  remediating: { chipBorder: "rgba(183,110,0,0.5)", chipColor: "#7A4100", label: "REMEDIATING", rank: 4 },
  monitoring: { chipBorder: "rgba(0,167,111,0.5)", chipColor: "#007B55", label: "MONITORING", rank: 5 },
  closed: { chipBorder: "rgba(147,144,132,0.3)", chipColor: "#939084", label: "CLOSED", rank: 6 },
};

const INV_STATUS_TONE: Record<InvestigationStatus, { bg: string; color: string }> = {
  queued: { bg: "rgba(147,144,132,0.12)", color: "#36342e" },
  running: { bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  completed: { bg: "rgba(0,167,111,0.1)", color: "#007B55" },
  failed: { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
};

type Tab = "findings" | "comments" | "timeline" | "investigations" | "copilot";

function _shortId(uuid: string): string {
  return uuid.slice(-6).toUpperCase();
}

function _slaState(
  due: string | null,
  closedAt: string | null,
): { tone: "ok" | "warn" | "breach" | "none"; label: string } {
  if (closedAt) return { tone: "none", label: "Case closed" };
  if (!due) return { tone: "none", label: "No SLA" };
  const ms = new Date(due).getTime() - Date.now();
  if (ms <= 0) {
    return {
      tone: "breach",
      label: `Overdue by ${_dur(-ms)}`,
    };
  }
  if (ms < 1000 * 60 * 60 * 4) {
    return { tone: "warn", label: `${_dur(ms)} until breach` };
  }
  return { tone: "ok", label: `${_dur(ms)} remaining` };
}

function _dur(ms: number): string {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d`;
}

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

const btnPrimary: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-accent)",
  background: "var(--color-accent)",
  color: "var(--color-on-dark)",
};

const btnSecondary: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-body)",
};

export default function CaseDetailPage() {
  const router = useRouter();
  const { toast } = useToast();
  const params = useParams<{ caseId: string }>();
  const caseId = params.caseId;

  const [c, setC] = useState<CaseDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("findings");
  const [showTransition, setShowTransition] = useState(false);
  const [showLink, setShowLink] = useState(false);
  const [showClose, setShowClose] = useState(false);
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      const data = await api.cases.get(caseId);
      setC(data);
      setTitleDraft(data.title);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        toast("error", "Case not found");
        router.replace("/cases");
        return;
      }
      toast("error", e instanceof Error ? e.message : "Failed to load case");
    } finally {
      setLoading(false);
    }
  }, [caseId, router, toast]);

  useEffect(() => {
    load();
  }, [load]);

  // Esc to close any open modal
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (showTransition) setShowTransition(false);
        else if (showClose) setShowClose(false);
        else if (showLink) setShowLink(false);
        else if (editingTitle) setEditingTitle(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [showTransition, showClose, showLink, editingTitle]);

  const updateLocal = (patch: Partial<CaseDetailResponse>) => {
    setC((prev) => (prev ? { ...prev, ...patch } : prev));
  };

  const saveTitle = async () => {
    if (!c || titleDraft.trim() === c.title || !titleDraft.trim()) {
      setEditingTitle(false);
      setTitleDraft(c?.title || "");
      return;
    }
    try {
      const updated = await api.cases.update(c.id, {
        title: titleDraft.trim(),
      });
      updateLocal({ title: updated.title, updated_at: updated.updated_at });
      toast("success", "Title updated");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to save title");
    } finally {
      setEditingTitle(false);
    }
  };

  const updateSeverity = async (sev: CaseSeverityValue) => {
    if (!c || sev === c.severity || busy) return;
    setBusy(true);
    try {
      const updated = await api.cases.update(c.id, { severity: sev });
      updateLocal({
        severity: updated.severity,
        updated_at: updated.updated_at,
      });
      toast("success", `Severity set to ${sev.toUpperCase()}`);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to update severity",
      );
    } finally {
      setBusy(false);
    }
  };

  const updateTags = async (tags: string[]) => {
    if (!c) return;
    try {
      const updated = await api.cases.update(c.id, { tags });
      updateLocal({ tags: updated.tags, updated_at: updated.updated_at });
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to update tags");
    }
  };

  const updateSlaDue = async (due: string | null) => {
    if (!c) return;
    try {
      const updated = await api.cases.update(c.id, {
        sla_due_at: due,
      });
      updateLocal({
        sla_due_at: updated.sla_due_at,
        updated_at: updated.updated_at,
      });
      toast("success", due ? "SLA due date updated" : "SLA due date cleared");
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to update SLA due date",
      );
    }
  };

  const transition = async (toState: CaseStateValue, reason: string) => {
    if (!c || busy) return;
    setBusy(true);
    try {
      const updated = await api.cases.transition(c.id, {
        to_state: toState,
        reason: reason || undefined,
      });
      updateLocal({
        state: updated.state,
        updated_at: updated.updated_at,
        first_response_at: updated.first_response_at,
      });
      toast("success", `Moved to ${toState.toUpperCase()}`);
      setShowTransition(false);
      // Refetch to pick up the new transition row
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to transition state",
      );
    } finally {
      setBusy(false);
    }
  };

  const closeCase = async (reason: string, comment: string) => {
    if (!c || busy) return;
    setBusy(true);
    try {
      const updated = await api.cases.transition(c.id, {
        to_state: "closed",
        close_reason: reason,
        reason: reason,
      });
      updateLocal({
        state: updated.state,
        closed_at: updated.closed_at,
        close_reason: updated.close_reason,
        updated_at: updated.updated_at,
      });
      if (comment.trim()) {
        await api.cases.addComment(c.id, { body: comment.trim() });
      }
      toast("success", "Case closed");
      setShowClose(false);
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to close case");
    } finally {
      setBusy(false);
    }
  };

  const linkAlert = async (alertId: string, reason: string) => {
    if (!c) return;
    try {
      await api.cases.addFinding(c.id, {
        alert_id: alertId,
        link_reason: reason || undefined,
      });
      toast("success", "Finding linked");
      setShowLink(false);
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to link finding");
    }
  };

  const removeFinding = async (alertId: string) => {
    if (!c) return;
    if (!confirm("Remove this finding from the case?")) return;
    try {
      await api.cases.removeFinding(c.id, alertId);
      toast("success", "Finding removed");
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to remove finding");
    }
  };

  if (loading || !c) {
    return <DetailSkeleton />;
  }

  const sev = SEVERITY_PRESENTATION[c.severity];
  const stt = STATE_PRESENTATION[c.state];
  const sla = _slaState(c.sla_due_at, c.closed_at);

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <Link
        href="/cases"
        className="inline-flex items-center gap-1.5 text-[12px] font-semibold transition-colors"
        style={{ color: "var(--color-muted)" }}
        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-ink)")}
        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-muted)")}
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        All cases
      </Link>

      {/* Title block */}
      <div className="flex items-start gap-4">
        <div
          className="w-1 self-stretch rounded-full mt-1"
          style={{ background: sev.stripeColor }}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <span
              className="inline-flex items-center h-[20px] px-1.5 rounded border text-[10px] font-bold tracking-[0.06em]"
              style={{ background: sev.chipBg, borderColor: sev.chipBorder, color: sev.chipColor, borderRadius: "4px" }}
            >
              {sev.label}
            </span>
            <span
              className="inline-flex items-center h-[20px] px-1.5 rounded border text-[10px] font-bold tracking-[0.06em]"
              style={{ background: "var(--color-canvas)", borderColor: stt.chipBorder, color: stt.chipColor, borderRadius: "4px" }}
            >
              {stt.label}
            </span>
            <span className="font-mono text-[11px] tabular-nums tracking-wider" style={{ color: "var(--color-muted)" }}>
              CASE-{_shortId(c.id)}
            </span>
            {c.tags.length > 0 ? (
              <div className="flex items-center gap-1 ml-1">
                {c.tags.map((t) => (
                  <span
                    key={t}
                    className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-semibold"
                    style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                  >
                    {t}
                  </span>
                ))}
              </div>
            ) : null}
          </div>

          {editingTitle ? (
            <div className="flex items-center gap-2">
              <input
                autoFocus
                value={titleDraft}
                onChange={(e) => setTitleDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") saveTitle();
                  if (e.key === "Escape") {
                    setEditingTitle(false);
                    setTitleDraft(c.title);
                  }
                }}
                className="flex-1 text-[24px] font-extrabold tracking-[-0.01em] leading-[30px] px-3 py-1.5"
                style={{ ...inputStyle, color: "var(--color-ink)" }}
                maxLength={500}
              />
              <button
                onClick={saveTitle}
                className="h-9 w-9 flex items-center justify-center"
                style={btnPrimary}
                aria-label="Save title"
              >
                <Save className="w-4 h-4" />
              </button>
              <button
                onClick={() => {
                  setEditingTitle(false);
                  setTitleDraft(c.title);
                }}
                className="h-9 w-9 flex items-center justify-center"
                style={btnSecondary}
                aria-label="Cancel"
              >
                <X className="w-4 h-4" style={{ color: "var(--color-body)" }} />
              </button>
            </div>
          ) : (
            <div
              className="group flex items-baseline gap-2 cursor-text"
              onClick={() => setEditingTitle(true)}
            >
              <h1 className="text-[24px] leading-[30px] font-extrabold tracking-[-0.01em]" style={{ color: "var(--color-ink)" }}>
                {c.title}
              </h1>
              <Edit2 className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: "var(--color-muted)" }} />
            </div>
          )}

          {c.summary ? (
            <p className="text-[13.5px] mt-2 max-w-[760px]" style={{ color: "var(--color-body)" }}>
              {c.summary}
            </p>
          ) : null}

          <div className="flex items-center gap-5 mt-3 text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              opened {timeAgo(c.created_at)}
            </span>
            <span style={{ color: "var(--color-border)" }}>·</span>
            <span>updated {timeAgo(c.updated_at)}</span>
            {c.first_response_at ? (
              <>
                <span style={{ color: "var(--color-border)" }}>·</span>
                <span>first response {timeAgo(c.first_response_at)}</span>
              </>
            ) : null}
          </div>

          <div className="mt-3">
            <SlaBanner tone={sla.tone} label={sla.label} />
          </div>
        </div>
      </div>

      {/* Two column */}
      <div className="grid grid-cols-12 gap-6">
        {/* Main content */}
        <div className="col-span-12 lg:col-span-8 xl:col-span-9 min-w-0">
          {/* Tabs */}
          <div className="flex items-center gap-1" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <TabBtn
              label="Findings"
              count={c.findings.length}
              active={tab === "findings"}
              onClick={() => setTab("findings")}
            />
            <TabBtn
              label="Comments"
              count={c.comments.length}
              active={tab === "comments"}
              onClick={() => setTab("comments")}
            />
            <TabBtn
              label="Timeline"
              count={c.transitions.length}
              active={tab === "timeline"}
              onClick={() => setTab("timeline")}
            />
            <TabBtn
              label="Investigations"
              active={tab === "investigations"}
              onClick={() => setTab("investigations")}
            />
            <TabBtn
              label="Copilot"
              active={tab === "copilot"}
              onClick={() => setTab("copilot")}
            />
          </div>

          <div className="pt-5">
            {tab === "findings" && (
              <FindingsTab
                findings={c.findings}
                onLinkClick={() => setShowLink(true)}
                onRemove={removeFinding}
                disabled={c.state === "closed"}
              />
            )}
            {tab === "comments" && (
              <CommentsTab
                caseId={c.id}
                comments={c.comments}
                disabled={c.state === "closed"}
                onChange={load}
              />
            )}
            {tab === "timeline" && (
              <TimelineTab
                createdAt={c.created_at}
                transitions={c.transitions}
              />
            )}
            {tab === "investigations" && (
              <InvestigationsTab caseId={c.id} />
            )}
            {tab === "copilot" && (
              <CopilotTab caseId={c.id} onAppliedRefresh={load} />
            )}
          </div>
        </div>

        {/* Right rail — properties */}
        <aside className="col-span-12 lg:col-span-4 xl:col-span-3">
          <div
            className="sticky top-4"
            style={{
              borderRadius: "5px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
            }}
          >
            <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <span className="text-[10.5px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                Properties
              </span>
            </div>
            <PropRow label="Severity">
              <SeverityPicker
                value={c.severity}
                onChange={updateSeverity}
                disabled={busy || c.state === "closed"}
              />
            </PropRow>
            <PropRow label="State">
              <button
                onClick={() => setShowTransition(true)}
                disabled={c.state === "closed"}
                className="w-full flex items-center justify-between text-left h-9 px-2.5 transition-colors disabled:opacity-70 disabled:cursor-not-allowed"
                style={{ ...inputStyle, borderRadius: "4px" }}
              >
                <span
                  className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
                  style={{ borderRadius: "4px", background: "var(--color-canvas)", borderColor: stt.chipBorder, color: stt.chipColor }}
                >
                  {stt.label}
                </span>
                <ChevronRight className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              </button>
            </PropRow>
            <PropRow label="Owner">
              <UserPill id={c.owner_user_id} />
            </PropRow>
            <PropRow label="Assignee">
              <UserPill id={c.assignee_user_id} />
            </PropRow>
            <PropRow label="SLA due">
              <SlaDueEditor
                value={c.sla_due_at}
                onChange={updateSlaDue}
                disabled={c.state === "closed"}
              />
            </PropRow>
            <PropRow label="Tags">
              <TagsEditor
                tags={c.tags}
                onChange={updateTags}
                disabled={c.state === "closed"}
              />
            </PropRow>
            <PropRow label="Primary asset">
              {c.primary_asset_id ? (
                <span className="font-mono text-[11.5px] tabular-nums break-all" style={{ color: "var(--color-body)" }}>
                  {c.primary_asset_id.slice(-12)}
                </span>
              ) : (
                <span className="text-[12px] italic" style={{ color: "var(--color-muted)" }}>
                  unset
                </span>
              )}
            </PropRow>
            {c.state !== "closed" ? (
              <div className="px-4 py-3" style={{ borderTop: "1px solid var(--color-border)" }}>
                <button
                  onClick={() => setShowClose(true)}
                  className="w-full h-9 text-[12px] font-bold uppercase tracking-[0.06em] transition-colors"
                  style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                  onMouseEnter={e => {
                    e.currentTarget.style.borderColor = "rgba(255,86,48,0.5)";
                    e.currentTarget.style.color = "#B71D18";
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.borderColor = "var(--color-border)";
                    e.currentTarget.style.color = "var(--color-body)";
                  }}
                >
                  Close case
                </button>
              </div>
            ) : (
              <div className="px-4 py-3 text-[11.5px]" style={{ borderTop: "1px solid var(--color-border)", color: "var(--color-muted)" }}>
                <div className="font-bold uppercase tracking-[0.08em] mb-1" style={{ color: "var(--color-body)" }}>
                  Closed
                </div>
                <div className="font-mono tabular-nums">
                  {c.closed_at ? formatDate(c.closed_at) : "—"}
                </div>
                {c.close_reason ? (
                  <div className="mt-2 text-[12px]" style={{ color: "var(--color-body)" }}>
                    Reason:{" "}
                    <span className="font-semibold">{c.close_reason}</span>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </aside>
      </div>

      {/* Modals */}
      {showTransition && (
        <TransitionModal
          current={c.state}
          onClose={() => setShowTransition(false)}
          onSubmit={transition}
          submitting={busy}
        />
      )}
      {showLink && (
        <LinkAlertModal
          onClose={() => setShowLink(false)}
          onSubmit={linkAlert}
        />
      )}
      {showClose && (
        <CloseCaseModal
          onClose={() => setShowClose(false)}
          onSubmit={closeCase}
          submitting={busy}
        />
      )}
    </div>
  );
}

// Sub-components

function TabBtn({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="relative h-10 px-3 text-[13px] font-bold flex items-center gap-1.5 transition-colors"
      style={{
        color: active ? "var(--color-ink)" : "var(--color-muted)",
        boxShadow: active ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
      }}
    >
      {label}
      {typeof count === "number" ? (
        <span
          className="inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10.5px] font-bold tabular-nums"
          style={{
            borderRadius: "4px",
            background: active ? "var(--color-ink)" : "var(--color-surface-muted)",
            color: active ? "var(--color-on-dark)" : "var(--color-body)",
          }}
        >
          {count}
        </span>
      ) : null}
    </button>
  );
}

function FindingsTab({
  findings,
  onLinkClick,
  onRemove,
  disabled,
}: {
  findings: CaseFindingResponse[];
  onLinkClick: () => void;
  onRemove: (alertId: string) => void;
  disabled: boolean;
}) {
  return (
    <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", overflow: "hidden" }}>
      <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
        <div>
          <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
            Linked findings
          </h3>
          <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Findings auto-link from Argus detectors. Manually link an
            alert to keep this case as the source of truth.
          </p>
        </div>
        <button
          onClick={onLinkClick}
          disabled={disabled}
          className="flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          style={btnSecondary}
        >
          <Link2 className="w-3.5 h-3.5" />
          Link alert
        </button>
      </div>

      {findings.length === 0 ? (
        <div className="py-12 px-6 text-center">
          <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
            No findings linked yet
          </p>
          <p className="text-[12px] mt-1.5 max-w-[440px] mx-auto" style={{ color: "var(--color-muted)" }}>
            When a brand-protection detector fires, the matching
            finding lands here automatically. Until then you can link
            an alert manually.
          </p>
        </div>
      ) : (
        <table className="w-full">
          <thead>
            <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
              <th className="text-left h-9 px-4 text-[10.5px] font-bold uppercase tracking-[0.08em] w-[72px]" style={{ color: "var(--color-muted)" }}>
                Primary
              </th>
              <th className="text-left h-9 px-3 text-[10.5px] font-bold uppercase tracking-[0.08em]" style={{ color: "var(--color-muted)" }}>
                Finding ID
              </th>
              <th className="text-left h-9 px-3 text-[10.5px] font-bold uppercase tracking-[0.08em]" style={{ color: "var(--color-muted)" }}>
                Reason
              </th>
              <th className="text-left h-9 px-3 text-[10.5px] font-bold uppercase tracking-[0.08em] w-[120px]" style={{ color: "var(--color-muted)" }}>
                Linked
              </th>
              <th className="w-[40px] p-0" />
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr
                key={f.id}
                className="h-12 transition-colors"
                style={{ borderBottom: "1px solid var(--color-border)" }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <td className="px-4">
                  {f.is_primary ? (
                    <span
                      className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
                      style={{ borderRadius: "4px", borderColor: "rgba(255,79,0,0.4)", background: "rgba(255,79,0,0.08)", color: "var(--color-accent)" }}
                    >
                      PRIMARY
                    </span>
                  ) : (
                    <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>—</span>
                  )}
                </td>
                <td className="px-3">
                  <Link
                    href={`/alerts/${f.alert_id}`}
                    className="font-mono text-[12px] tabular-nums tracking-wide transition-colors"
                    style={{ color: "var(--color-body)" }}
                    onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                    onMouseLeave={e => (e.currentTarget.style.color = "var(--color-body)")}
                  >
                    {f.alert_id}
                  </Link>
                </td>
                <td className="px-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                  {f.link_reason || (
                    <span className="italic" style={{ color: "var(--color-muted)" }}>no reason</span>
                  )}
                </td>
                <td className="px-3 text-[11.5px] font-mono tabular-nums whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                  {timeAgo(f.created_at)}
                </td>
                <td className="px-2 text-right">
                  <button
                    onClick={() => onRemove(f.alert_id)}
                    disabled={disabled}
                    className="p-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                    aria-label="Remove finding"
                    onMouseEnter={e => {
                      e.currentTarget.style.background = "rgba(255,86,48,0.08)";
                      e.currentTarget.style.color = "#B71D18";
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.background = "transparent";
                      e.currentTarget.style.color = "var(--color-muted)";
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CommentsTab({
  caseId,
  comments,
  disabled,
  onChange,
}: {
  caseId: string;
  comments: CaseDetailResponse["comments"];
  disabled: boolean;
  onChange: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [draft, setDraft] = useState("");
  const [posting, setPosting] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingDraft, setEditingDraft] = useState("");

  const post = async () => {
    if (!draft.trim() || posting) return;
    setPosting(true);
    try {
      await api.cases.addComment(caseId, { body: draft.trim() });
      setDraft("");
      await onChange();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to post comment",
      );
    } finally {
      setPosting(false);
    }
  };

  const saveEdit = async (id: string) => {
    if (!editingDraft.trim()) return;
    try {
      await api.cases.updateComment(caseId, id, { body: editingDraft.trim() });
      setEditingId(null);
      setEditingDraft("");
      await onChange();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to edit comment",
      );
    }
  };

  const removeComment = async (id: string) => {
    if (!confirm("Delete this comment?")) return;
    try {
      await api.cases.deleteComment(caseId, id);
      await onChange();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to delete comment",
      );
    }
  };

  return (
    <div className="space-y-4">
      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        {comments.length === 0 ? (
          <div className="py-12 px-6 text-center">
            <MessageSquare className="w-7 h-7 mx-auto mb-3" style={{ color: "var(--color-border)" }} />
            <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
              No comments yet
            </p>
            <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
              Use comments to capture analyst notes, hypotheses, and
              cross-team handoffs.
            </p>
          </div>
        ) : (
          <ul className="divide-y" style={{ borderColor: "var(--color-border)" }}>
            {comments.map((cm) => (
              <li key={cm.id} className="px-5 py-4" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <div className="flex items-start gap-3">
                  <CommentAvatar />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[12.5px] font-bold" style={{ color: "var(--color-ink)" }}>
                        {cm.author_user_id ? "Analyst" : "System"}
                      </span>
                      <span className="text-[11.5px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                        · {timeAgo(cm.created_at)}
                      </span>
                      {cm.edited_at ? (
                        <span className="text-[11px] italic" style={{ color: "var(--color-muted)" }}>
                          (edited)
                        </span>
                      ) : null}
                      <span className="ml-auto flex items-center gap-1">
                        <button
                          onClick={() => {
                            setEditingId(cm.id);
                            setEditingDraft(cm.body);
                          }}
                          className="p-1 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          aria-label="Edit"
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                        >
                          <Edit2 className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => removeComment(cm.id)}
                          className="p-1 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          aria-label="Delete"
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </span>
                    </div>
                    {editingId === cm.id ? (
                      <div className="space-y-2">
                        <textarea
                          autoFocus
                          value={editingDraft}
                          onChange={(e) => setEditingDraft(e.target.value)}
                          rows={3}
                          className="w-full px-3 py-2 text-[13px] resize-none"
                          style={inputStyle}
                        />
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => saveEdit(cm.id)}
                            className="h-8 px-3 text-[12px] font-bold"
                            style={btnPrimary}
                          >
                            Save
                          </button>
                          <button
                            onClick={() => {
                              setEditingId(null);
                              setEditingDraft("");
                            }}
                            className="h-8 px-3 text-[12px] font-bold"
                            style={btnSecondary}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="text-[13px] whitespace-pre-wrap" style={{ color: "var(--color-body)" }}>
                        {cm.body}
                      </div>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Composer */}
      <div className="p-4" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          placeholder={
            disabled
              ? "Case is closed — re-open to comment."
              : "Add a note (markdown-friendly)…"
          }
          disabled={disabled}
          className="w-full px-3 py-2 text-[13px] resize-none disabled:cursor-not-allowed"
          style={{ ...inputStyle, opacity: disabled ? 0.6 : 1 }}
        />
        <div className="flex items-center justify-between mt-2.5">
          <p className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>
            <span className="font-mono">⌘⏎</span> to post · markdown preserved
          </p>
          <button
            onClick={post}
            disabled={!draft.trim() || posting || disabled}
            className="h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            style={btnPrimary}
          >
            {posting ? "Posting…" : "Post comment"}
          </button>
        </div>
      </div>
    </div>
  );
}

function TimelineTab({
  createdAt,
  transitions,
}: {
  createdAt: string;
  transitions: CaseDetailResponse["transitions"];
}) {
  const items = useMemo(() => {
    const base = transitions.map((t) => ({
      kind: "transition" as const,
      at: t.transitioned_at,
      from: t.from_state,
      to: t.to_state,
      reason: t.reason,
      who: t.transitioned_by_user_id,
      id: t.id,
    }));
    return base.sort(
      (a, b) => new Date(b.at).getTime() - new Date(a.at).getTime(),
    );
  }, [transitions]);

  return (
    <div className="p-6" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
      {items.length === 0 ? (
        <div className="text-center py-8">
          <Clock className="w-7 h-7 mx-auto mb-3" style={{ color: "var(--color-border)" }} />
          <p className="text-[13px] font-bold" style={{ color: "var(--color-body)" }}>
            No transitions yet
          </p>
          <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
            State changes will appear here in newest-first order.
          </p>
        </div>
      ) : (
        <ol className="relative pl-6 space-y-5" style={{ borderLeft: "2px solid var(--color-border)" }}>
          {items.map((it) => {
            const fromP = it.from
              ? STATE_PRESENTATION[it.from as CaseStateValue]
              : null;
            const toP = STATE_PRESENTATION[it.to as CaseStateValue];
            return (
              <li key={it.id} className="relative">
                <span
                  className="absolute -left-[31px] top-1 w-3 h-3 rounded-full"
                  style={{ background: "var(--color-canvas)", border: "2px solid var(--color-border)" }}
                />
                <div className="flex items-baseline gap-2 flex-wrap">
                  {fromP ? (
                    <span
                      className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
                      style={{ borderRadius: "4px", background: "var(--color-canvas)", borderColor: fromP.chipBorder, color: fromP.chipColor }}
                    >
                      {fromP.label}
                    </span>
                  ) : (
                    <span className="text-[11px] font-bold tracking-wide uppercase" style={{ color: "var(--color-muted)" }}>
                      Created
                    </span>
                  )}
                  <ChevronRight className="w-3 h-3" style={{ color: "var(--color-muted)" }} />
                  <span
                    className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
                    style={{ borderRadius: "4px", background: "var(--color-canvas)", borderColor: toP.chipBorder, color: toP.chipColor }}
                  >
                    {toP.label}
                  </span>
                  <span className="text-[11.5px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                    · {formatDate(it.at)}
                  </span>
                </div>
                {it.reason ? (
                  <p className="text-[12.5px] mt-1.5 max-w-[640px]" style={{ color: "var(--color-body)" }}>
                    {it.reason}
                  </p>
                ) : null}
              </li>
            );
          })}
          <li className="relative">
            <span
              className="absolute -left-[31px] top-1 w-3 h-3 rounded-full"
              style={{ background: "var(--color-canvas)", border: "2px solid var(--color-border)" }}
            />
            <div className="flex items-baseline gap-2 flex-wrap">
              <span className="text-[11px] font-bold tracking-wide uppercase" style={{ color: "var(--color-muted)" }}>
                Case opened
              </span>
              <span className="text-[11.5px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                · {formatDate(createdAt)}
              </span>
            </div>
          </li>
        </ol>
      )}
    </div>
  );
}


/* InvestigationsTab */

function InvestigationsTab({ caseId }: { caseId: string }) {
  const router = useRouter();
  const { toast } = useToast();
  const [rows, setRows] = useState<InvestigationListItem[] | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const data = await api.investigations.list({
          case_id: caseId,
          limit: 50,
        });
        if (alive) setRows(data);
      } catch (e) {
        if (alive)
          toast(
            "error",
            e instanceof Error ? e.message : "Failed to load investigations",
          );
      }
    })();
    return () => {
      alive = false;
    };
  }, [caseId, toast]);

  if (rows === null) {
    return (
      <div className="text-[13px] italic" style={{ color: "var(--color-muted)" }}>
        Loading investigations…
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div
        className="px-5 py-10 text-center"
        style={{ borderRadius: "5px", border: "1px dashed var(--color-border)", background: "var(--color-surface)" }}
      >
        <Sparkles className="w-6 h-6 mx-auto mb-2" style={{ color: "var(--color-muted)" }} />
        <p className="text-[14px] font-bold" style={{ color: "var(--color-ink)" }}>
          No agent investigation linked to this case
        </p>
        <p className="text-[12.5px] mt-1 max-w-[420px] mx-auto" style={{ color: "var(--color-muted)" }}>
          Cases promoted from the Investigations page show up here with the
          full trace, IOCs, and recommended actions the agent surfaced.
        </p>
      </div>
    );
  }
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li
          key={r.id}
          className="px-4 py-3 cursor-pointer transition-colors"
          style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
          onClick={() => router.push(`/investigations`)}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = "var(--color-border-strong)";
            e.currentTarget.style.background = "var(--color-surface)";
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = "var(--color-border)";
            e.currentTarget.style.background = "var(--color-canvas)";
          }}
        >
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="inline-flex items-center h-[20px] px-2 text-[10.5px] font-bold uppercase tracking-[0.06em]"
                  style={{ borderRadius: "4px", background: INV_STATUS_TONE[r.status].bg, color: INV_STATUS_TONE[r.status].color }}
                >
                  {r.status}
                </span>
                {r.severity_assessment ? (
                  <span className="text-[11px] font-bold uppercase tracking-[0.06em]" style={{ color: "var(--color-body)" }}>
                    {r.severity_assessment}
                  </span>
                ) : null}
                {r.iterations > 0 ? (
                  <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                    · {r.iterations} step{r.iterations === 1 ? "" : "s"}
                  </span>
                ) : null}
                {r.duration_ms ? (
                  <span className="text-[11px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                    · {(r.duration_ms / 1000).toFixed(1)}s
                  </span>
                ) : null}
              </div>
              <p className="text-[12px] font-mono truncate" style={{ color: "var(--color-muted)" }}>
                {r.id} · alert {r.alert_id.slice(0, 12)}…
                {r.model_id ? ` · ${r.model_id}` : ""}
              </p>
            </div>
            <ExternalLink className="w-4 h-4 shrink-0" style={{ color: "var(--color-muted)" }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function PropRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="px-4 py-3" style={{ borderTop: "1px solid var(--color-border)" }}>
      <div className="text-[10.5px] font-bold uppercase tracking-[0.12em] mb-1.5" style={{ color: "var(--color-muted)" }}>
        {label}
      </div>
      {children}
    </div>
  );
}

function SlaBanner({
  tone,
  label,
}: {
  tone: "ok" | "warn" | "breach" | "none";
  label: string;
}) {
  if (tone === "none") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: "var(--color-muted)" }}>
        <Clock className="w-3.5 h-3.5" />
        {label}
      </span>
    );
  }
  const toneStyles = {
    breach: { bg: "rgba(255,86,48,0.1)", border: "rgba(255,86,48,0.4)", color: "#B71D18" },
    warn:   { bg: "rgba(255,171,0,0.1)", border: "rgba(255,171,0,0.4)", color: "#B76E00" },
    ok:     { bg: "rgba(0,167,111,0.1)", border: "rgba(0,167,111,0.3)", color: "#007B55" },
  }[tone];
  return (
    <span
      className="inline-flex items-center gap-1.5 h-[24px] px-2 border text-[11.5px] font-bold tracking-[0.04em]"
      style={{ borderRadius: "4px", background: toneStyles.bg, borderColor: toneStyles.border, color: toneStyles.color }}
    >
      <Clock className="w-3 h-3" />
      {label.toUpperCase()}
    </span>
  );
}

function SeverityPicker({
  value,
  onChange,
  disabled,
}: {
  value: CaseSeverityValue;
  onChange: (v: CaseSeverityValue) => void;
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const cur = SEVERITY_PRESENTATION[value];
  return (
    <div className="relative" ref={ref}>
      <button
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        className="w-full h-9 px-2.5 flex items-center justify-between transition-colors disabled:opacity-70 disabled:cursor-not-allowed"
        style={inputStyle}
      >
        <span
          className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
          style={{ borderRadius: "4px", background: cur.chipBg, borderColor: cur.chipBorder, color: cur.chipColor }}
        >
          {cur.label}
        </span>
        <ChevronDown className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
      </button>
      {open && (
        <div
          className="absolute right-0 left-0 mt-1 overflow-hidden z-10"
          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", boxShadow: "var(--shadow-z16)" }}
        >
          {SEVERITIES.map((s) => {
            const p = SEVERITY_PRESENTATION[s];
            return (
              <button
                key={s}
                onClick={() => {
                  onChange(s);
                  setOpen(false);
                }}
                className="w-full px-2.5 h-9 flex items-center justify-between text-left transition-colors"
                style={{ background: s === value ? "var(--color-surface)" : "transparent" }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                onMouseLeave={e => (e.currentTarget.style.background = s === value ? "var(--color-surface)" : "transparent")}
              >
                <span
                  className="inline-flex items-center h-[20px] px-1.5 border text-[10px] font-bold tracking-[0.06em]"
                  style={{ borderRadius: "4px", background: p.chipBg, borderColor: p.chipBorder, color: p.chipColor }}
                >
                  {p.label}
                </span>
                {s === value ? (
                  <Check className="w-3.5 h-3.5" style={{ color: "var(--color-body)" }} />
                ) : null}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function UserPill({ id }: { id: string | null }) {
  if (!id) {
    return (
      <span className="text-[12.5px] italic" style={{ color: "var(--color-muted)" }}>unassigned</span>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <span
        className="inline-flex items-center justify-center w-6 h-6 rounded-full text-[10px] font-bold"
        style={{ background: "rgba(255,79,0,0.1)", color: "var(--color-accent)" }}
      >
        <UserIcon className="w-3 h-3" />
      </span>
      <span className="font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-body)" }}>
        {id.slice(-8)}
      </span>
    </div>
  );
}

function CommentAvatar() {
  return (
    <div
      className="shrink-0 w-8 h-8 rounded-full flex items-center justify-center"
      style={{ background: "var(--color-surface-muted)", border: "1px solid var(--color-border)" }}
    >
      <UserIcon className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
    </div>
  );
}

function SlaDueEditor({
  value,
  onChange,
  disabled,
}: {
  value: string | null;
  onChange: (v: string | null) => void;
  disabled: boolean;
}) {
  // Convert ISO → datetime-local string ('YYYY-MM-DDTHH:mm')
  const localValue = useMemo(() => {
    if (!value) return "";
    const d = new Date(value);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
      d.getHours(),
    )}:${pad(d.getMinutes())}`;
  }, [value]);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(localValue);
  // Snapshot the live value when entering edit mode, not on every change
  const beginEdit = () => {
    setDraft(localValue);
    setEditing(true);
  };

  if (editing) {
    return (
      <div className="flex items-center gap-1">
        <input
          type="datetime-local"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="flex-1 h-8 px-2 text-[12px]"
          style={inputStyle}
        />
        <button
          onClick={() => {
            const iso = draft ? new Date(draft).toISOString() : null;
            onChange(iso);
            setEditing(false);
          }}
          className="h-8 w-8 flex items-center justify-center"
          style={btnPrimary}
          aria-label="Save"
        >
          <Check className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => {
            setEditing(false);
            setDraft(localValue);
          }}
          className="h-8 w-8 flex items-center justify-center"
          style={btnSecondary}
          aria-label="Cancel"
        >
          <X className="w-3.5 h-3.5" style={{ color: "var(--color-body)" }} />
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => !disabled && beginEdit()}
      disabled={disabled}
      className="w-full h-9 px-2.5 flex items-center justify-between transition-colors text-left disabled:opacity-70 disabled:cursor-not-allowed"
      style={inputStyle}
    >
      {value ? (
        <span className="font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-body)" }}>
          {formatDate(value)}
        </span>
      ) : (
        <span className="text-[12.5px] italic" style={{ color: "var(--color-muted)" }}>no SLA</span>
      )}
      <Calendar className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
    </button>
  );
}

function TagsEditor({
  tags,
  onChange,
  disabled,
}: {
  tags: string[];
  onChange: (tags: string[]) => Promise<void>;
  disabled: boolean;
}) {
  const [draft, setDraft] = useState("");
  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      const t = draft.trim().replace(/,$/, "");
      if (t && !tags.includes(t)) onChange([...tags, t]);
      setDraft("");
    } else if (e.key === "Backspace" && !draft && tags.length) {
      onChange(tags.slice(0, -1));
    }
  };
  return (
    <div
      className="flex flex-wrap items-center gap-1 min-h-[36px] p-1.5"
      style={{
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        opacity: disabled ? 0.7 : 1,
        cursor: disabled ? "not-allowed" : "text",
      }}
    >
      {tags.map((t) => (
        <span
          key={t}
          className="inline-flex items-center gap-1 h-5 pl-1.5 pr-0.5 text-[11px] font-semibold"
          style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
        >
          {t}
          {!disabled && (
            <button
              onClick={() => onChange(tags.filter((x) => x !== t))}
              className="p-0.5 transition-colors"
              style={{ borderRadius: "3px", color: "var(--color-muted)" }}
              onMouseEnter={e => (e.currentTarget.style.background = "var(--color-border)")}
              onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            >
              <X className="w-2.5 h-2.5" />
            </button>
          )}
        </span>
      ))}
      {!disabled && (
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKey}
          placeholder={tags.length === 0 ? "add tag…" : ""}
          className="flex-1 min-w-[60px] bg-transparent outline-none text-[12px]"
          style={{ color: "var(--color-body)" }}
        />
      )}
    </div>
  );
}

function DetailSkeleton() {
  return (
    <div className="space-y-5 animate-pulse">
      <div className="h-3 w-20 rounded" style={{ background: "var(--color-surface-muted)" }} />
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <div className="h-5 w-16 rounded" style={{ background: "var(--color-surface-muted)" }} />
          <div className="h-5 w-24 rounded" style={{ background: "var(--color-surface-muted)" }} />
        </div>
        <div className="h-7 w-3/4 rounded" style={{ background: "var(--color-surface-muted)" }} />
        <div className="h-4 w-1/2 rounded" style={{ background: "var(--color-surface-muted)" }} />
      </div>
      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-9 h-[400px] rounded" style={{ background: "rgba(197,192,177,0.3)" }} />
        <div className="col-span-3 h-[400px] rounded" style={{ background: "rgba(197,192,177,0.3)" }} />
      </div>
    </div>
  );
}

// Modals

function TransitionModal({
  current,
  onClose,
  onSubmit,
  submitting,
}: {
  current: CaseStateValue;
  onClose: () => void;
  onSubmit: (toState: CaseStateValue, reason: string) => void;
  submitting: boolean;
}) {
  const [target, setTarget] = useState<CaseStateValue>(
    STATES.find((s) => STATE_PRESENTATION[s].rank > STATE_PRESENTATION[current].rank) ||
      "investigating",
  );
  const [reason, setReason] = useState("");
  return (
    <ModalShell title="Transition state" onClose={onClose}>
      <div className="p-6 space-y-5">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-body)" }}>
            Target state
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {STATES.filter((s) => s !== current).map((s) => {
              const p = STATE_PRESENTATION[s];
              const active = target === s;
              return (
                <button
                  key={s}
                  onClick={() => setTarget(s)}
                  className="h-10 flex items-center justify-center text-[11px] font-bold tracking-[0.06em] transition-all"
                  style={{
                    borderRadius: "4px",
                    border: active ? `1px solid ${p.chipBorder}` : "1px solid var(--color-border)",
                    background: active ? "var(--color-canvas)" : "var(--color-canvas)",
                    color: active ? p.chipColor : "var(--color-muted)",
                    boxShadow: active ? `0 0 0 2px ${p.chipBorder}` : "none",
                  }}
                >
                  {p.label}
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-1.5" style={{ color: "var(--color-body)" }}>
            Reason{" "}
            <span className="font-normal normal-case tracking-normal" style={{ color: "var(--color-muted)" }}>
              (optional)
            </span>
          </div>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder="Note for the timeline…"
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={inputStyle}
          />
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(target, reason)}
        submitLabel={submitting ? "Transitioning…" : "Transition"}
        disabled={submitting}
      />
    </ModalShell>
  );
}

function CloseCaseModal({
  onClose,
  onSubmit,
  submitting,
}: {
  onClose: () => void;
  onSubmit: (reason: string, comment: string) => void;
  submitting: boolean;
}) {
  const REASONS = [
    "Resolved",
    "False positive",
    "Duplicate",
    "Accepted risk",
    "Other",
  ];
  const [reason, setReason] = useState(REASONS[0]);
  const [comment, setComment] = useState("");
  return (
    <ModalShell title="Close case" onClose={onClose}>
      <div className="p-6 space-y-5">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Closing transitions the case to{" "}
          <span className="font-bold" style={{ color: "var(--color-ink)" }}>CLOSED</span>. Reopen
          by transitioning back to any earlier state.
        </p>
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-body)" }}>
            Close reason
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {REASONS.map((r) => {
              const active = reason === r;
              return (
                <button
                  key={r}
                  onClick={() => setReason(r)}
                  className="h-9 flex items-center justify-center text-[12px] font-semibold transition-all"
                  style={{
                    borderRadius: "4px",
                    border: active ? "1px solid var(--color-ink)" : "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    color: active ? "var(--color-ink)" : "var(--color-body)",
                  }}
                >
                  {r}
                </button>
              );
            })}
          </div>
        </div>
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-1.5" style={{ color: "var(--color-body)" }}>
            Closing note{" "}
            <span className="font-normal normal-case tracking-normal" style={{ color: "var(--color-muted)" }}>
              (optional)
            </span>
          </div>
          <textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            rows={3}
            placeholder="Outcome, references, lessons learned…"
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={inputStyle}
          />
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(reason, comment)}
        submitLabel={submitting ? "Closing…" : "Close case"}
        submitTone="error"
        disabled={submitting}
      />
    </ModalShell>
  );
}

function LinkAlertModal({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (alertId: string, reason: string) => void;
}) {
  const [alertId, setAlertId] = useState("");
  const [reason, setReason] = useState("");
  const valid = /^[0-9a-f-]{36}$/i.test(alertId.trim());
  return (
    <ModalShell title="Link alert" onClose={onClose}>
      <div className="p-6 space-y-5">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Manual linking is for analyst-driven cross-references. Findings
          from automated detectors land here on their own.
        </p>
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-1.5" style={{ color: "var(--color-body)" }}>
            Alert UUID
          </div>
          <input
            value={alertId}
            onChange={(e) => setAlertId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="w-full h-10 px-3 font-mono text-[13px]"
            style={inputStyle}
            autoFocus
          />
          {alertId && !valid ? (
            <p className="text-[11.5px] mt-1.5" style={{ color: "#B71D18" }}>
              Doesn&apos;t look like a UUID — paste the full alert id from{" "}
              <code className="font-mono">/alerts/&lt;id&gt;</code>.
            </p>
          ) : null}
        </div>
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.1em] mb-1.5" style={{ color: "var(--color-body)" }}>
            Reason{" "}
            <span className="font-normal normal-case tracking-normal" style={{ color: "var(--color-muted)" }}>
              (optional)
            </span>
          </div>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why is this alert relevant?"
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
          />
        </div>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(alertId.trim(), reason)}
        submitLabel="Link"
        disabled={!valid}
      />
    </ModalShell>
  );
}

function ModalShell({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(32,21,21,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[520px] overflow-hidden"
        style={{ background: "var(--color-canvas)", borderRadius: "8px", border: "1px solid var(--color-border)", boxShadow: "var(--shadow-z24)" }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
      >
        <div className="px-6 pt-5 pb-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <h2 className="text-[16px] font-bold tracking-tight" style={{ color: "var(--color-ink)" }}>
            {title}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 transition-colors"
            style={{ borderRadius: "4px", color: "var(--color-muted)" }}
            aria-label="Close"
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function ModalFooter({
  onCancel,
  onSubmit,
  submitLabel,
  submitTone,
  disabled,
}: {
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel: string;
  submitTone?: "error";
  disabled?: boolean;
}) {
  const submitStyle: React.CSSProperties = submitTone === "error"
    ? { borderRadius: "4px", border: "1px solid rgba(255,86,48,0.6)", background: "#FF5630", color: "var(--color-on-dark)" }
    : btnPrimary;

  return (
    <div className="px-6 py-4 flex items-center justify-end gap-2" style={{ background: "var(--color-surface)", borderTop: "1px solid var(--color-border)" }}>
      <button
        onClick={onCancel}
        className="h-9 px-3 text-[13px] font-bold transition-colors"
        style={btnSecondary}
      >
        Cancel
      </button>
      <button
        onClick={onSubmit}
        disabled={disabled}
        className="h-9 px-4 text-[13px] font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        style={submitStyle}
      >
        {submitLabel}
      </button>
    </div>
  );
}


/* CopilotTab */

function CopilotTab({
  caseId,
  onAppliedRefresh,
}: {
  caseId: string;
  onAppliedRefresh: () => void;
}) {
  const { toast } = useToast();
  const [run, setRun] = useState<CopilotRunDetail | null | undefined>(undefined);
  const [running, setRunning] = useState(false);
  const [applying, setApplying] = useState(false);

  const fetchLatest = useCallback(async () => {
    try {
      const r = await api.caseCopilot.latest(caseId);
      setRun(r);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load copilot run",
      );
    }
  }, [caseId, toast]);

  useEffect(() => {
    void fetchLatest();
  }, [fetchLatest]);

  // Poll while a run is queued/running so the analyst sees the result
  // land without manually refreshing.
  useEffect(() => {
    if (!run) return;
    if (run.status !== "queued" && run.status !== "running") return;
    const t = setInterval(fetchLatest, 4000);
    return () => clearInterval(t);
  }, [run, fetchLatest]);

  const handleRun = useCallback(async () => {
    setRunning(true);
    try {
      await api.caseCopilot.create(caseId);
      toast("info", "Copilot dispatched — give it a few seconds");
      await fetchLatest();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to start copilot",
      );
    } finally {
      setRunning(false);
    }
  }, [caseId, fetchLatest, toast]);

  const handleApply = useCallback(async () => {
    if (!run || run.status !== "completed") return;
    setApplying(true);
    try {
      const res = await api.caseCopilot.apply(run.id);
      if (res.already_applied) {
        toast("info", "Suggestions were already applied");
      } else {
        toast(
          "success",
          `Applied — ${res.mitre_attached} MITRE technique(s) attached, draft notes added`,
        );
      }
      await fetchLatest();
      onAppliedRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to apply suggestions",
      );
    } finally {
      setApplying(false);
    }
  }, [run, fetchLatest, onAppliedRefresh, toast]);

  if (run === undefined) {
    return (
      <div className="text-[13px] italic" style={{ color: "var(--color-muted)" }}>Loading copilot…</div>
    );
  }
  if (run === null) {
    return (
      <div
        className="px-5 py-10 text-center"
        style={{ borderRadius: "5px", border: "1px dashed var(--color-border)", background: "var(--color-surface)" }}
      >
        <Sparkles className="w-6 h-6 mx-auto mb-2" style={{ color: "var(--color-muted)" }} />
        <p className="text-[14px] font-bold" style={{ color: "var(--color-ink)" }}>
          No copilot run yet for this case
        </p>
        <p className="text-[12.5px] mt-1 max-w-[460px] mx-auto" style={{ color: "var(--color-muted)" }}>
          The Case Copilot drafts a starter timeline, MITRE attachments,
          and next-step checklist. You stay in control — nothing is
          attached to the case until you click <em>Apply</em>.
        </p>
        <button
          type="button"
          onClick={handleRun}
          disabled={running}
          className="mt-4 inline-flex items-center gap-1.5 h-9 px-4 text-[12.5px] font-bold transition-colors disabled:opacity-50"
          style={btnPrimary}
        >
          {running ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Sparkles className="w-4 h-4" />
          )}
          Run Copilot
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[12px] font-bold uppercase tracking-[0.08em]" style={{ color: "var(--color-muted)" }}>
            Run {run.id.slice(0, 8)}…
          </p>
          <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {run.status}
            {run.iterations > 0 ? ` · ${run.iterations} step${run.iterations === 1 ? "" : "s"}` : ""}
            {run.model_id ? ` · ${run.model_id}` : ""}
            {run.duration_ms ? ` · ${(run.duration_ms / 1000).toFixed(1)}s` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {run.applied_at ? (
            <span
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold"
              style={{ borderRadius: "4px", background: "rgba(0,167,111,0.1)", color: "#007B55" }}
            >
              <Check className="w-3.5 h-3.5" />
              Applied
            </span>
          ) : run.status === "completed" ? (
            <button
              type="button"
              onClick={handleApply}
              disabled={applying}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50"
              style={btnPrimary}
            >
              {applying ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Check className="w-3.5 h-3.5" />
              )}
              Apply suggestions
            </button>
          ) : null}
          <button
            type="button"
            onClick={handleRun}
            disabled={running || run.status === "running" || run.status === "queued"}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors disabled:opacity-50"
            style={btnSecondary}
            title="Run a fresh copilot pass"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Re-run
          </button>
        </div>
      </div>

      {run.status === "failed" && run.error_message ? (
        <div
          className="px-4 py-3 text-[12.5px] font-mono"
          style={{ borderRadius: "5px", border: "1px solid rgba(255,86,48,0.4)", background: "rgba(255,86,48,0.08)", color: "#B71D18" }}
        >
          {run.error_message}
        </div>
      ) : null}

      {(run.status === "queued" || run.status === "running") ? (
        <div
          className="px-4 py-3 flex items-center gap-3"
          style={{ borderRadius: "5px", border: "1px solid rgba(0,187,217,0.3)", background: "rgba(0,187,217,0.08)" }}
        >
          <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#007B8A" }} />
          <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
            Copilot is gathering context…
          </p>
        </div>
      ) : null}

      {run.summary ? (
        <section>
          <h4 className="text-[11px] font-bold uppercase tracking-[0.08em] mb-2" style={{ color: "var(--color-muted)" }}>
            Summary
          </h4>
          <p className="text-[13.5px] leading-[1.55]" style={{ color: "var(--color-body)" }}>
            {run.summary}
          </p>
        </section>
      ) : null}

      {run.suggested_mitre_ids && run.suggested_mitre_ids.length > 0 ? (
        <section>
          <h4 className="text-[11px] font-bold uppercase tracking-[0.08em] mb-2" style={{ color: "var(--color-muted)" }}>
            Suggested MITRE techniques
          </h4>
          <div className="flex items-center gap-1.5 flex-wrap">
            {run.suggested_mitre_ids.map((id) => (
              <span
                key={id}
                className="inline-flex items-center h-[22px] px-2 text-[11.5px] font-mono font-bold"
                style={{ borderRadius: "4px", background: "rgba(0,187,217,0.1)", color: "#007B8A" }}
              >
                {id}
              </span>
            ))}
          </div>
        </section>
      ) : null}

      {run.draft_next_steps && run.draft_next_steps.length > 0 ? (
        <section>
          <h4 className="text-[11px] font-bold uppercase tracking-[0.08em] mb-2" style={{ color: "var(--color-muted)" }}>
            Draft next steps
          </h4>
          <ul className="space-y-1.5">
            {run.draft_next_steps.map((s) => (
              <li
                key={s}
                className="text-[13px] flex items-start gap-2"
                style={{ color: "var(--color-body)" }}
              >
                <span className="mt-1 w-3.5 h-3.5 rounded shrink-0" style={{ border: "1px solid var(--color-border)" }} />
                {s}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {run.timeline_events && run.timeline_events.length > 0 ? (
        <section>
          <h4 className="text-[11px] font-bold uppercase tracking-[0.08em] mb-2" style={{ color: "var(--color-muted)" }}>
            Draft timeline
          </h4>
          <ol className="space-y-2 pl-4" style={{ borderLeft: "1px solid var(--color-border)" }}>
            {run.timeline_events.map((e, i) => (
              <li key={i} className="text-[13px] relative" style={{ color: "var(--color-body)" }}>
                <span
                  className="absolute -left-[20px] top-[7px] w-2 h-2 rounded-full"
                  style={{ background: "var(--color-border)" }}
                />
                {e.at ? (
                  <span className="text-[11.5px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                    {timeAgo(e.at)} ·{" "}
                  </span>
                ) : null}
                <span className="text-[10.5px] font-bold uppercase tracking-[0.08em]" style={{ color: "var(--color-muted)" }}>
                  {e.source}
                </span>{" "}
                — {e.text}
              </li>
            ))}
          </ol>
        </section>
      ) : null}
    </div>
  );
}
