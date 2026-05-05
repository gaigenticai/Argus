"use client";

/**
 * ActionDrawer — slide-in execution surface for one Playbook.
 *
 * Three modes the same drawer covers:
 *
 * 1. **New run** — opened from the AI Executive Briefing's "Open →"
 *    button. ``playbookId`` is set, ``executionId`` is null. Renders
 *    preview, optional input form (when ``requires_input``),
 *    Execute button. Server creates a PlaybookExecution row on
 *    Execute; we transition to mode 2.
 *
 * 2. **Existing run** — drawer is rehydrated against an existing
 *    execution. Shows step progress + per-step results + the right
 *    next-action button (Continue → step-advance, Cancel,
 *    Acknowledge-and-close on terminal states).
 *
 * 3. **Pending-approval review** — from the /playbooks/approvals
 *    queue. Same as mode 2 but with Approve / Deny buttons surfaced
 *    at the footer for admin users.
 *
 * Server is the source of truth for the execution row; the drawer
 * never mutates it locally. Every action POSTs and re-fetches the
 * full execution payload, so a refresh-mid-flow always shows the
 * authoritative state.
 */

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Loader2,
  Play,
  ShieldAlert,
  X,
} from "lucide-react";
import {
  api,
  type PlaybookCatalogResponse,
  type PlaybookDescriptor,
  type PlaybookExecutionResponse,
  type PlaybookPreviewResponse,
} from "@/lib/api";
import {
  toVipParams,
  VipRosterForm,
  type VipFormRow,
} from "./playbooks/vip-roster-form";

interface Props {
  /** Open mode: existing-run (executionId set) takes precedence. */
  executionId?: string | null;
  /** Open mode: new-run. Ignored when executionId is set. */
  playbookId?: string | null;
  /** Organization scope. Required for catalog and preview calls. */
  orgId: string;
  /** Briefing-driven runs pass the action index; manual runs leave null. */
  briefingActionIndex?: number | null;
  /** LLM-seeded params (when the briefing seeded an input_schema). */
  briefingParams?: Record<string, unknown> | null;
  /** Whether the current viewer can approve (admins only). */
  isAdmin?: boolean;
  /** Close handler. */
  onClose: () => void;
  /** Fired after a non-trivial state change (execute, approve, cancel, advance)
   *  so callers can re-fetch upstream data (e.g. the briefing card). */
  onStateChanged?: () => void;
}

type DrawerStage =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      playbook: PlaybookDescriptor;
      preview: PlaybookPreviewResponse | null;
      execution: PlaybookExecutionResponse | null;
      previewLoading: boolean;
      working: boolean;
    };


function makeIdempotencyKey(): string {
  // Browsers without crypto.randomUUID (older Safari, JSDOM) fall back
  // to a Math.random-based v4-shaped string. Server-side dedupe is
  // length-agnostic so the fallback is safe.
  const c = (typeof crypto !== "undefined" ? crypto : null) as
    | { randomUUID?: () => string }
    | null;
  if (c?.randomUUID) return c.randomUUID();
  return "k-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}


export function ActionDrawer({
  executionId,
  playbookId,
  orgId,
  briefingActionIndex,
  briefingParams,
  isAdmin = false,
  onClose,
  onStateChanged,
}: Props) {
  const [stage, setStage] = useState<DrawerStage>({ kind: "loading" });
  // Stable idempotency key per drawer-open. Re-clicking Execute on a
  // flaky network is therefore a no-op the second time.
  const [idempotencyKey] = useState(makeIdempotencyKey);

  // VIP roster form state — only used by add_vip_roster. Lifted here
  // so the form persists across preview re-fetches.
  const initialVipRows: VipFormRow[] = useMemo(() => {
    const seeded = briefingParams && Array.isArray((briefingParams as Record<string, unknown>).vips)
      ? ((briefingParams as Record<string, unknown>).vips as Array<Record<string, unknown>>)
      : [];
    if (seeded.length === 0) {
      return [{ name: "", title: "", emails: "", usernames: "" }];
    }
    return seeded.map((v) => ({
      name: typeof v.name === "string" ? v.name : "",
      title: typeof v.title === "string" ? v.title : "",
      emails: Array.isArray(v.emails) ? (v.emails as string[]).join(", ") : "",
      usernames: Array.isArray(v.usernames) ? (v.usernames as string[]).join(", ") : "",
    }));
  }, [briefingParams]);
  const [vipRows, setVipRows] = useState<VipFormRow[]>(initialVipRows);

  const [denyReason, setDenyReason] = useState("");
  const [showDenyForm, setShowDenyForm] = useState(false);

  // Close on Escape.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  // ── Compute current params from state ───────────────────────────
  // Keep this above the load effect so the load effect can read it.

  const currentParams = useMemo<Record<string, unknown>>(() => {
    if (stage.kind !== "ready") return briefingParams || {};
    if (stage.execution) return stage.execution.params || {};
    if (stage.playbook.id === "add_vip_roster") {
      return toVipParams(vipRows);
    }
    return briefingParams || {};
  }, [stage, vipRows, briefingParams]);

  const paramsKey = JSON.stringify(currentParams);

  // ── Load + preview as one flow ───────────────────────────────────
  // Earlier we split load and preview into two effects; React's
  // closure semantics for useCallback + useEffect made the preview
  // effect race against the just-set stage and silently no-op.
  // Combining them into one effect that reads current state via the
  // setStage updater removes the race entirely.

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setStage({ kind: "loading" });
      try {
        const catalog: PlaybookCatalogResponse = await api.exec.playbookCatalog({
          organization_id: orgId,
        });
        if (cancelled) return;
        let exec: PlaybookExecutionResponse | null = null;
        let resolvedPlaybookId = playbookId || null;
        if (executionId) {
          exec = await api.exec.playbookExecution(executionId);
          if (cancelled) return;
          resolvedPlaybookId = exec.playbook_id;
        }
        if (!resolvedPlaybookId) {
          setStage({ kind: "error", message: "No playbook selected." });
          return;
        }
        const playbook = catalog.items.find((p) => p.id === resolvedPlaybookId);
        if (!playbook) {
          setStage({
            kind: "error",
            message:
              `Playbook ${resolvedPlaybookId} is no longer in the applicable catalog. ` +
              `It may have been retired since the briefing was generated. Refresh the briefing.`,
          });
          return;
        }
        setStage({
          kind: "ready",
          playbook,
          preview: null,
          execution: exec,
          previewLoading: true,
          working: false,
        });

        // Skip preview when an existing execution is already terminal.
        const status = exec?.status;
        if (status === "completed" || status === "failed" || status === "denied" || status === "cancelled") {
          if (!cancelled) {
            setStage((s) => (s.kind === "ready" ? { ...s, previewLoading: false } : s));
          }
          return;
        }

        const params = exec?.params
          || (playbook.id === "add_vip_roster" ? toVipParams(vipRows) : (briefingParams || {}));
        const preview = await api.exec.playbookPreview({
          playbook_id: playbook.id,
          organization_id: orgId,
          params,
          execution_id: exec?.id,
          step_index: exec ? exec.current_step_index : 0,
        });
        if (cancelled) return;
        setStage((s) =>
          s.kind === "ready" ? { ...s, preview, previewLoading: false } : s,
        );
      } catch (err) {
        if (!cancelled) {
          setStage({
            kind: "error",
            message: err instanceof Error ? err.message : "Failed to load playbook",
          });
        }
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, playbookId, executionId]);

  // Re-fetch preview when params change (form input edits) or when a
  // step-advance moves us to the next step. Skips on terminal status.
  useEffect(() => {
    if (stage.kind !== "ready") return;
    const status = stage.execution?.status;
    if (status === "completed" || status === "failed" || status === "denied" || status === "cancelled") {
      return;
    }
    let cancelled = false;
    (async () => {
      setStage((s) => (s.kind === "ready" ? { ...s, previewLoading: true } : s));
      try {
        const preview = await api.exec.playbookPreview({
          playbook_id: stage.playbook.id,
          organization_id: orgId,
          params: currentParams,
          execution_id: stage.execution?.id,
          step_index: stage.execution ? stage.execution.current_step_index : 0,
        });
        if (cancelled) return;
        setStage((s) =>
          s.kind === "ready" ? { ...s, preview, previewLoading: false } : s,
        );
      } catch {
        if (!cancelled) {
          setStage((s) => (s.kind === "ready" ? { ...s, previewLoading: false } : s));
        }
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    paramsKey,
    stage.kind === "ready" ? stage.execution?.current_step_index : -1,
  ]);

  // ── Action handlers ──────────────────────────────────────────────

  async function handleExecute() {
    if (stage.kind !== "ready") return;
    setStage((s) => (s.kind === "ready" ? { ...s, working: true } : s));
    try {
      const exec = await api.exec.playbookExecute({
        playbook_id: stage.playbook.id,
        organization_id: orgId,
        params: currentParams,
        idempotency_key: idempotencyKey,
        briefing_action_index: briefingActionIndex,
        triggered_from: briefingActionIndex != null ? "exec_briefing" : "manual",
      });
      setStage((s) =>
        s.kind === "ready"
          ? { ...s, execution: exec, working: false }
          : s,
      );
      onStateChanged?.();
    } catch (err) {
      setStage((s) =>
        s.kind === "ready" ? { ...s, working: false } : s,
      );
      setStage({
        kind: "error",
        message: err instanceof Error ? err.message : "Execute failed",
      });
    }
  }

  async function handleStepAdvance() {
    if (stage.kind !== "ready" || !stage.execution) return;
    setStage((s) => (s.kind === "ready" ? { ...s, working: true } : s));
    try {
      const exec = await api.exec.playbookStepAdvance({
        execution_id: stage.execution.id,
      });
      setStage((s) =>
        s.kind === "ready"
          ? { ...s, execution: exec, working: false }
          : s,
      );
      onStateChanged?.();
    } catch (err) {
      setStage((s) =>
        s.kind === "ready" ? { ...s, working: false } : s,
      );
      setStage({
        kind: "error",
        message: err instanceof Error ? err.message : "Step advance failed",
      });
    }
  }

  async function handleCancel() {
    if (stage.kind !== "ready" || !stage.execution) return;
    setStage((s) => (s.kind === "ready" ? { ...s, working: true } : s));
    try {
      const exec = await api.exec.playbookCancel({
        execution_id: stage.execution.id,
      });
      setStage((s) =>
        s.kind === "ready"
          ? { ...s, execution: exec, working: false }
          : s,
      );
      onStateChanged?.();
    } catch (err) {
      setStage((s) =>
        s.kind === "ready" ? { ...s, working: false } : s,
      );
    }
  }

  async function handleApprove() {
    if (stage.kind !== "ready" || !stage.execution) return;
    setStage((s) => (s.kind === "ready" ? { ...s, working: true } : s));
    try {
      const exec = await api.exec.playbookApprove({
        execution_id: stage.execution.id,
      });
      setStage((s) =>
        s.kind === "ready"
          ? { ...s, execution: exec, working: false }
          : s,
      );
      onStateChanged?.();
    } catch (err) {
      setStage((s) =>
        s.kind === "ready" ? { ...s, working: false } : s,
      );
    }
  }

  async function handleDeny() {
    if (stage.kind !== "ready" || !stage.execution) return;
    if (!denyReason.trim()) return;
    setStage((s) => (s.kind === "ready" ? { ...s, working: true } : s));
    try {
      const exec = await api.exec.playbookDeny({
        execution_id: stage.execution.id,
        reason: denyReason.trim(),
      });
      setStage((s) =>
        s.kind === "ready"
          ? { ...s, execution: exec, working: false }
          : s,
      );
      setShowDenyForm(false);
      onStateChanged?.();
    } catch (err) {
      setStage((s) =>
        s.kind === "ready" ? { ...s, working: false } : s,
      );
    }
  }

  // ── Render ───────────────────────────────────────────────────────

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.35)" }}
      />
      <aside
        role="dialog"
        aria-label="Playbook drawer"
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
        style={{
          width: "min(720px, 92vw)",
          background: "var(--color-canvas)",
          borderLeft: "1px solid var(--color-border)",
          boxShadow: "-8px 0 24px rgba(0,0,0,0.12)",
        }}
      >
        {stage.kind === "loading" && (
          <div className="flex items-center justify-center flex-1">
            <Loader2 className="w-5 h-5 animate-spin" style={{ color: "var(--color-muted)" }} />
          </div>
        )}

        {stage.kind === "error" && (
          <div className="flex flex-col flex-1">
            <DrawerHeader title="Playbook unavailable" onClose={onClose} />
            <div className="p-6 text-[12.5px] flex-1" style={{ color: "var(--color-error-dark)" }}>
              <AlertTriangle className="inline w-4 h-4 mr-1" />
              {stage.message}
            </div>
          </div>
        )}

        {stage.kind === "ready" && (
          <>
            <DrawerHeader
              title={stage.playbook.title}
              subtitle={categoryLabel(stage.playbook.category)}
              onClose={onClose}
              statusBadge={
                stage.execution ? (
                  <StatusBadge status={stage.execution.status} />
                ) : null
              }
            />

            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
              {/* Description */}
              <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-body)" }}>
                {stage.playbook.description}
              </p>

              {/* Multi-step progress */}
              {stage.playbook.total_steps > 1 && (
                <StepProgress
                  steps={stage.playbook.steps}
                  current={stage.execution?.current_step_index ?? 0}
                  status={stage.execution?.status ?? "pending"}
                />
              )}

              {/* Pending-approval banner */}
              {stage.execution?.status === "pending_approval" && (
                <Banner tone="warning" icon={<ShieldAlert className="w-4 h-4" />}>
                  This playbook requires admin approval before execution.{" "}
                  {isAdmin
                    ? "Use Approve or Deny below."
                    : "An admin will be notified to review."}
                </Banner>
              )}

              {/* Input form (only for requires_input playbooks, only on new run) */}
              {!stage.execution && stage.playbook.requires_input && (
                <Section title="Input">
                  {stage.playbook.id === "add_vip_roster" ? (
                    <VipRosterForm rows={vipRows} onChange={setVipRows} />
                  ) : (
                    <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                      No custom form for this playbook yet — params are seeded from the briefing.
                    </p>
                  )}
                </Section>
              )}

              {/* Step results (history within this run) */}
              {stage.execution && stage.execution.step_results.length > 0 && (
                <Section title="Step results">
                  <div className="space-y-2">
                    {stage.execution.step_results.map((sr) => (
                      <div
                        key={sr.step}
                        className="p-3"
                        style={{
                          background: sr.ok
                            ? "rgba(34,197,94,0.06)"
                            : "rgba(239,68,68,0.06)",
                          border: `1px solid ${sr.ok ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`,
                          borderRadius: 4,
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          {sr.ok ? (
                            <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "var(--color-success-dark)" }} />
                          ) : (
                            <X className="w-3.5 h-3.5" style={{ color: "var(--color-error-dark)" }} />
                          )}
                          <span className="text-[12px] font-semibold" style={{ color: "var(--color-ink)" }}>
                            Step {sr.step + 1}: {sr.step_id}
                          </span>
                        </div>
                        <p className="text-[12px]" style={{ color: "var(--color-body)" }}>
                          {sr.summary}
                        </p>
                        {sr.error && (
                          <p className="text-[11.5px] mt-1 font-mono" style={{ color: "var(--color-error-dark)" }}>
                            {sr.error}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* Active preview block */}
              {stage.preview && !isTerminal(stage.execution?.status) && (
                <PreviewBlock
                  preview={stage.preview}
                  loading={stage.previewLoading}
                />
              )}
            </div>

            {/* Action footer */}
            <div
              className="px-6 py-4 flex flex-wrap items-center gap-2"
              style={{
                borderTop: "1px solid var(--color-border)",
                background: "var(--color-surface)",
              }}
            >
              <ActionFooter
                stage={stage}
                isAdmin={isAdmin}
                showDenyForm={showDenyForm}
                denyReason={denyReason}
                onDenyReasonChange={setDenyReason}
                onShowDenyForm={() => setShowDenyForm((v) => !v)}
                onExecute={handleExecute}
                onStepAdvance={handleStepAdvance}
                onCancel={handleCancel}
                onApprove={handleApprove}
                onDeny={handleDeny}
                onClose={onClose}
              />
            </div>
          </>
        )}
      </aside>
    </>
  );
}

// ── Subcomponents ─────────────────────────────────────────────────


function isTerminal(status: string | undefined): boolean {
  return status === "completed" || status === "failed" || status === "denied" || status === "cancelled";
}


function categoryLabel(c: string): string {
  switch (c) {
    case "brand": return "Brand protection";
    case "email": return "Email authentication";
    case "asset": return "Asset / VIP";
    case "intel": return "Intel";
    default: return c;
  }
}


function DrawerHeader({
  title,
  subtitle,
  onClose,
  statusBadge,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  statusBadge?: React.ReactNode;
}) {
  return (
    <div
      className="flex items-start justify-between gap-3 px-6 py-5"
      style={{ borderBottom: "1px solid var(--color-border)" }}
    >
      <div className="min-w-0">
        {subtitle && (
          <p
            className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            {subtitle}
          </p>
        )}
        <h2
          className="text-[18px] font-medium tracking-[-0.01em]"
          style={{ color: "var(--color-ink)" }}
        >
          {title}
        </h2>
        {statusBadge && <div className="mt-1.5">{statusBadge}</div>}
      </div>
      <button
        type="button"
        onClick={onClose}
        aria-label="Close"
        className="flex items-center justify-center w-8 h-8"
        style={{
          background: "transparent",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
          cursor: "pointer",
        }}
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}


function StatusBadge({ status }: { status: string }) {
  const meta: Record<string, { bg: string; color: string; label: string }> = {
    pending_approval: { bg: "rgba(245,158,11,0.15)", color: "var(--color-warning-dark)", label: "Pending approval" },
    approved:         { bg: "rgba(99,102,241,0.15)", color: "#3730A3", label: "Approved" },
    in_progress:      { bg: "rgba(99,102,241,0.15)", color: "#3730A3", label: "In progress" },
    step_complete:    { bg: "rgba(34,197,94,0.15)", color: "var(--color-success-dark)", label: "Step complete" },
    completed:        { bg: "rgba(34,197,94,0.15)", color: "var(--color-success-dark)", label: "Completed" },
    failed:           { bg: "rgba(239,68,68,0.15)", color: "var(--color-error-dark)", label: "Failed" },
    denied:           { bg: "rgba(239,68,68,0.15)", color: "var(--color-error-dark)", label: "Denied" },
    cancelled:        { bg: "rgba(99,115,129,0.15)", color: "var(--color-muted)", label: "Cancelled" },
  };
  const m = meta[status] || { bg: "var(--color-surface-muted)", color: "var(--color-body)", label: status };
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px]"
      style={{ background: m.bg, color: m.color, borderRadius: 3 }}
    >
      {m.label}
    </span>
  );
}


function StepProgress({
  steps,
  current,
  status,
}: {
  steps: { step_id: string; title: string }[];
  current: number;
  status: string;
}) {
  return (
    <div className="flex items-center gap-1">
      {steps.map((s, i) => {
        const completed = i < current || status === "completed";
        const active = i === current && status !== "completed";
        return (
          <div key={s.step_id} className="flex items-center gap-1 flex-1">
            <div
              className="flex items-center gap-1.5 px-2 py-1 flex-1"
              style={{
                background: active
                  ? "rgba(99,102,241,0.10)"
                  : completed
                    ? "rgba(34,197,94,0.10)"
                    : "var(--color-surface)",
                border: `1px solid ${active ? "rgba(99,102,241,0.40)" : completed ? "rgba(34,197,94,0.30)" : "var(--color-border)"}`,
                borderRadius: 3,
              }}
            >
              <span
                className="inline-flex items-center justify-center w-4 h-4 text-[9px] font-bold"
                style={{
                  background: completed
                    ? "var(--color-success-dark)"
                    : active
                      ? "var(--color-accent)"
                      : "var(--color-surface-muted)",
                  color: completed || active ? "#fff" : "var(--color-muted)",
                  borderRadius: "50%",
                }}
              >
                {completed ? <Check className="w-2.5 h-2.5" /> : i + 1}
              </span>
              <span className="text-[11.5px] font-semibold" style={{ color: "var(--color-ink)" }}>
                {s.title}
              </span>
            </div>
            {i < steps.length - 1 && (
              <ChevronRight className="w-3 h-3 shrink-0" style={{ color: "var(--color-muted)" }} />
            )}
          </div>
        );
      })}
    </div>
  );
}


function PreviewBlock({
  preview,
  loading,
}: {
  preview: PlaybookPreviewResponse;
  loading: boolean;
}) {
  return (
    <div className="space-y-3">
      <div
        className="p-3"
        style={{
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
        }}
      >
        <div className="flex items-center gap-2 mb-1.5">
          <h4
            className="text-[10.5px] font-bold uppercase tracking-[0.7px]"
            style={{ color: "var(--color-muted)" }}
          >
            Step {preview.step_index + 1} · {preview.step_title}
          </h4>
          {loading && <Loader2 className="w-3 h-3 animate-spin" style={{ color: "var(--color-muted)" }} />}
        </div>
        <p className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
          {preview.summary}
        </p>
        {preview.blocker_reason && (
          <p className="text-[12px] mt-1" style={{ color: "var(--color-error-dark)" }}>
            <Ban className="inline w-3.5 h-3.5 mr-1" />
            {preview.blocker_reason}
          </p>
        )}
      </div>

      {preview.warnings.length > 0 && (
        <div
          className="p-3 space-y-1"
          style={{
            background: "rgba(245,158,11,0.06)",
            border: "1px solid rgba(245,158,11,0.30)",
            borderRadius: 4,
          }}
        >
          {preview.warnings.map((w, i) => (
            <p key={i} className="text-[12px]" style={{ color: "var(--color-warning-dark)" }}>
              <AlertTriangle className="inline w-3.5 h-3.5 mr-1.5" />
              {w}
            </p>
          ))}
        </div>
      )}

      {preview.instructions.length > 0 && (
        <div>
          <h4
            className="text-[10.5px] font-bold uppercase tracking-[0.7px] mb-1.5"
            style={{ color: "var(--color-muted)" }}
          >
            Operator instructions
          </h4>
          <pre
            className="p-3 text-[11.5px] font-mono whitespace-pre-wrap break-all"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-ink)",
            }}
          >
            {preview.instructions.join("\n")}
          </pre>
        </div>
      )}

      {preview.affected_items.length > 0 && (
        <div>
          <h4
            className="text-[10.5px] font-bold uppercase tracking-[0.7px] mb-1.5"
            style={{ color: "var(--color-muted)" }}
          >
            Affected items ({preview.affected_items.length})
          </h4>
          <div
            className="overflow-y-auto"
            style={{
              maxHeight: 240,
              border: "1px solid var(--color-border)",
              borderRadius: 4,
            }}
          >
            <table className="w-full text-[12px]" style={{ borderCollapse: "collapse" }}>
              <tbody>
                {preview.affected_items.slice(0, 100).map((item) => (
                  <tr key={item.id} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                    <td className="px-3 py-2 align-top">
                      <div className="font-semibold" style={{ color: "var(--color-ink)" }}>
                        {item.label}
                      </div>
                      {item.sub_label && (
                        <div className="text-[11px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                          {item.sub_label}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {preview.affected_items.length > 100 && (
            <p className="text-[11px] mt-1" style={{ color: "var(--color-muted)" }}>
              Showing first 100 of {preview.affected_items.length}.
            </p>
          )}
        </div>
      )}
    </div>
  );
}


function ActionFooter({
  stage,
  isAdmin,
  showDenyForm,
  denyReason,
  onDenyReasonChange,
  onShowDenyForm,
  onExecute,
  onStepAdvance,
  onCancel,
  onApprove,
  onDeny,
  onClose,
}: {
  stage: Extract<DrawerStage, { kind: "ready" }>;
  isAdmin: boolean;
  showDenyForm: boolean;
  denyReason: string;
  onDenyReasonChange: (v: string) => void;
  onShowDenyForm: () => void;
  onExecute: () => void;
  onStepAdvance: () => void;
  onCancel: () => void;
  onApprove: () => void;
  onDeny: () => void;
  onClose: () => void;
}) {
  const exec = stage.execution;
  const canExecute = stage.preview?.can_execute ?? true;
  const working = stage.working;

  // Terminal: only Close.
  if (exec && isTerminal(exec.status)) {
    return (
      <button
        type="button"
        onClick={onClose}
        className="ml-auto h-8 px-4 text-[12px] font-semibold"
        style={{
          background: "var(--color-accent)",
          color: "#fffefb",
          border: "1px solid var(--color-accent)",
          borderRadius: 4,
        }}
      >
        Close
      </button>
    );
  }

  // Pending approval — admin gets Approve/Deny, others see notice.
  if (exec && exec.status === "pending_approval") {
    if (!isAdmin) {
      return (
        <>
          <Clock className="w-4 h-4" style={{ color: "var(--color-warning-dark)" }} />
          <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
            Awaiting admin review.
          </span>
          <div className="ml-auto flex gap-2">
            <button
              type="button"
              onClick={onCancel}
              disabled={working}
              className="h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                color: "var(--color-body)",
              }}
            >
              Withdraw request
            </button>
          </div>
        </>
      );
    }
    return (
      <>
        <button
          type="button"
          onClick={onShowDenyForm}
          disabled={working}
          className="h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-error-dark)",
          }}
        >
          {showDenyForm ? "Cancel deny" : "Deny"}
        </button>
        {showDenyForm ? (
          <>
            <input
              type="text"
              placeholder="Reason for denial (required)"
              value={denyReason}
              onChange={(e) => onDenyReasonChange(e.target.value)}
              className="flex-1 h-8 px-2 text-[12px]"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                color: "var(--color-ink)",
              }}
            />
            <button
              type="button"
              onClick={onDeny}
              disabled={working || !denyReason.trim()}
              className="h-8 px-4 text-[12px] font-semibold disabled:opacity-50"
              style={{
                background: "var(--color-error)",
                color: "#fff",
                border: "1px solid var(--color-error)",
                borderRadius: 4,
              }}
            >
              {working ? <Loader2 className="w-3 h-3 animate-spin inline" /> : "Confirm deny"}
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={onApprove}
            disabled={working}
            className="ml-auto h-8 px-4 text-[12px] font-semibold disabled:opacity-50"
            style={{
              background: "var(--color-success-dark)",
              color: "#fff",
              border: "1px solid var(--color-success-dark)",
              borderRadius: 4,
            }}
          >
            {working ? (
              <Loader2 className="w-3 h-3 animate-spin inline" />
            ) : (
              <>
                <Check className="w-3.5 h-3.5 inline mr-1" />
                Approve & execute
              </>
            )}
          </button>
        )}
      </>
    );
  }

  // Step-complete — Continue or Cancel.
  if (exec && exec.status === "step_complete") {
    return (
      <>
        <button
          type="button"
          onClick={onCancel}
          disabled={working}
          className="h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-body)",
          }}
        >
          Stop here
        </button>
        <button
          type="button"
          onClick={onStepAdvance}
          disabled={working}
          className="ml-auto h-8 px-4 text-[12px] font-semibold disabled:opacity-50"
          style={{
            background: "var(--color-accent)",
            color: "#fffefb",
            border: "1px solid var(--color-accent)",
            borderRadius: 4,
          }}
        >
          {working ? <Loader2 className="w-3 h-3 animate-spin inline" /> : `Continue to step ${exec.current_step_index + 2}`}
        </button>
      </>
    );
  }

  // No execution yet — Execute.
  if (!exec) {
    return (
      <>
        <button
          type="button"
          onClick={onClose}
          className="h-8 px-3 text-[12px] font-semibold"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-body)",
          }}
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onExecute}
          disabled={working || !canExecute}
          className="ml-auto h-8 px-4 text-[12px] font-semibold disabled:opacity-50 inline-flex items-center gap-1"
          style={{
            background: stage.playbook.requires_approval
              ? "var(--color-warning-dark)"
              : "var(--color-accent)",
            color: "#fffefb",
            border: "1px solid currentColor",
            borderRadius: 4,
          }}
        >
          {working ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Play className="w-3.5 h-3.5" />
          )}
          {stage.playbook.requires_approval ? "Request approval" : "Execute now"}
        </button>
      </>
    );
  }

  // In-progress (mid-execute). Just show working state.
  return (
    <>
      <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-muted)" }} />
      <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        Working…
      </span>
    </>
  );
}


function Banner({
  tone,
  icon,
  children,
}: {
  tone: "warning" | "info";
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  const colorMap = {
    warning: {
      bg: "rgba(245,158,11,0.08)",
      border: "rgba(245,158,11,0.35)",
      ink: "var(--color-warning-dark)",
    },
    info: {
      bg: "rgba(99,102,241,0.08)",
      border: "rgba(99,102,241,0.30)",
      ink: "#3730A3",
    },
  }[tone];
  return (
    <div
      className="p-3 flex items-start gap-2 text-[12.5px]"
      style={{
        background: colorMap.bg,
        border: `1px solid ${colorMap.border}`,
        borderRadius: 4,
        color: colorMap.ink,
      }}
    >
      {icon}
      <div className="flex-1">{children}</div>
    </div>
  );
}


function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h4
        className="text-[10.5px] font-bold uppercase tracking-[0.7px] mb-1.5"
        style={{ color: "var(--color-muted)" }}
      >
        {title}
      </h4>
      {children}
    </div>
  );
}
