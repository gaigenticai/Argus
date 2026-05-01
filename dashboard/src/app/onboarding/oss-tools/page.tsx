"use client";

/**
 * Admin first-login OSS-tools onboarding screen.
 *
 * Flow:
 *
 *   1. Admin lands here right after their first login (auth-provider
 *      redirects when `/oss-tools/onboarding` returns ``complete: false``).
 *   2. Page calls `/oss-tools/catalog` to render six selectable cards
 *      (MITRE Caldera, Shuffle, Velociraptor, MISP, OpenCTI, Wazuh)
 *      and `/oss-tools/preflight` to surface installer readiness.
 *   3. Admin checks tools they want, hits Install. Page POSTs the
 *      selection to `/oss-tools/install`, which kicks off
 *      ``docker compose --profile <X> up -d`` in a BackgroundTask and
 *      returns 202 immediately.
 *   4. Page polls `/oss-tools/` every 3s and renders per-tool state
 *      (pending → installing → installed | failed).
 *   5. Admin can also Skip — every tool goes to DISABLED + the wizard
 *      treats onboarding as complete so we don't re-prompt.
 */

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Box,
  CheckCircle2,
  Database,
  ExternalLink,
  HardDrive,
  Loader2,
  Lock,
  Package,
  Send,
  Shield,
  ShieldAlert,
  Workflow,
  XCircle,
} from "lucide-react";
import {
  api,
  type OssPreflight,
  type OssToolCatalogEntry,
  type OssToolState,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  Section,
  SkeletonRows,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";


const TOOL_ICON: Record<string, typeof Box> = {
  caldera: Shield,
  shuffle: Workflow,
  velociraptor: HardDrive,
  misp: Database,
  opencti: Send,
  wazuh: Package,
};


export default function OssOnboardingPage() {
  const [catalog, setCatalog] = useState<OssToolCatalogEntry[] | null>(null);
  const [preflight, setPreflight] = useState<OssPreflight | null>(null);
  const [states, setStates] = useState<OssToolState[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [polling, setPolling] = useState(false);
  const [done, setDone] = useState(false);
  const router = useRouter();
  const { toast } = useToast();

  // Initial fetch.
  useEffect(() => {
    let mounted = true;
    Promise.all([api.ossCatalog(), api.ossPreflight(), api.ossStates()])
      .then(([cat, pre, st]) => {
        if (!mounted) return;
        setCatalog(cat.tools);
        setPreflight(pre);
        setStates(st.tools);
      })
      .catch((err) => {
        toast("error", `Failed to load: ${(err as Error).message}`);
        setCatalog([]);
        setPreflight(null);
      });
    return () => {
      mounted = false;
    };
  }, [toast]);

  // Status polling while an install is running.
  useEffect(() => {
    if (!polling) return undefined;
    const t = setInterval(async () => {
      try {
        const r = await api.ossStates();
        setStates(r.tools);
        const settled = r.tools.every(
          (s) =>
            s.state === "installed" ||
            s.state === "failed" ||
            s.state === "disabled",
        );
        if (settled) setPolling(false);
      } catch {
        // ignore — keep polling
      }
    }, 3000);
    return () => clearInterval(t);
  }, [polling]);

  const stateByName = useMemo(() => {
    const m = new Map<string, OssToolState>();
    states.forEach((s) => m.set(s.tool_name, s));
    return m;
  }, [states]);

  const toggle = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const installSelected = async () => {
    if (selected.size === 0) {
      toast("info", "Pick at least one tool, or Skip below.");
      return;
    }
    setSubmitting(true);
    try {
      await api.ossInstall(Array.from(selected));
      toast(
        "success",
        `Install started for ${selected.size} tool${selected.size === 1 ? "" : "s"}.`,
      );
      setPolling(true);
      const r = await api.ossStates();
      setStates(r.tools);
    } catch (err) {
      toast("error", `Install failed: ${(err as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const skip = async () => {
    setSubmitting(true);
    try {
      await api.ossSkip();
      toast("info", "OSS onboarding skipped — you can install later from /connectors.");
      setDone(true);
      router.replace("/");
    } catch (err) {
      toast("error", `Skip failed: ${(err as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const finishIfDone = async () => {
    setSubmitting(true);
    try {
      // Mark every NON-selected tool DISABLED so the wizard completes.
      // Already-installed tools keep their state (the API does this
      // automatically via disable_unselected on the install path).
      // For users who installed everything they want, we just skip the
      // remaining tools and the page navigates home.
      await api.ossSkip();
      router.replace("/");
    } catch (err) {
      toast("error", `Finish failed: ${(err as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  if (done) return null;

  return (
    <div className="max-w-5xl mx-auto py-10 space-y-6">
      <PageHeader
        eyebrow={{ icon: Package, label: "Welcome to Argus" }}
        title="Install your open-source security stack"
        description="Argus runs end-to-end on its own — but you can co-host these well-known OSS tools alongside the platform. Each one wires into the matching Argus connector automatically. Pick what you need; you can always install the rest later."
      />

      {preflight && !preflight.ready && (
        <PreflightWarning preflight={preflight} />
      )}

      <Section>
        {catalog === null ? (
          <SkeletonRows rows={6} columns={2} />
        ) : catalog.length === 0 ? (
          <Empty
            icon={Package}
            title="Catalog unavailable"
            description="Could not load the OSS-tool catalog from the API. Try refreshing the page."
          />
        ) : (
          <div className="grid gap-px sm:grid-cols-2" style={{ background: "var(--color-border)" }}>
            {catalog.map((t) => (
              <ToolCard
                key={t.name}
                tool={t}
                state={stateByName.get(t.name)}
                selected={selected.has(t.name)}
                onToggle={() => toggle(t.name)}
                disabled={submitting || polling}
              />
            ))}
          </div>
        )}
      </Section>

      <div className="flex justify-between items-center gap-3 pt-2">
        <button
          type="button"
          onClick={skip}
          disabled={submitting || polling}
          className="inline-flex items-center gap-1 text-[13px] font-medium px-3 py-1.5"
          style={{
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            borderRadius: "5px",
            color: "var(--color-ink)",
          }}
        >
          Skip — install nothing
        </button>
        <div className="flex items-center gap-3">
          {polling && (
            <span
              className="inline-flex items-center gap-1.5 text-[12px]"
              style={{ color: "var(--color-muted)" }}
            >
              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
              Installing — docker pulls can take a few minutes…
            </span>
          )}
          {polling && allSettled(states, selected) ? (
            <button
              type="button"
              onClick={finishIfDone}
              className="inline-flex items-center gap-1 text-[13px] font-medium px-4 py-2"
              style={{
                background: "var(--color-accent)",
                color: "white",
                border: "1px solid var(--color-accent)",
                borderRadius: "5px",
              }}
            >
              Continue to dashboard
            </button>
          ) : (
            <button
              type="button"
              onClick={installSelected}
              disabled={submitting || polling || selected.size === 0}
              className="inline-flex items-center gap-1 text-[13px] font-medium px-4 py-2"
              style={{
                background: "var(--color-accent)",
                color: "white",
                border: "1px solid var(--color-accent)",
                borderRadius: "5px",
                opacity: submitting || polling || selected.size === 0 ? 0.5 : 1,
              }}
            >
              {submitting ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
              ) : null}
              Install {selected.size} tool{selected.size === 1 ? "" : "s"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}


function allSettled(
  states: OssToolState[],
  selected: Set<string>,
): boolean {
  if (selected.size === 0) return false;
  return Array.from(selected).every((name) => {
    const s = states.find((x) => x.tool_name === name);
    return s && (s.state === "installed" || s.state === "failed");
  });
}


function PreflightWarning({ preflight }: { preflight: OssPreflight }) {
  return (
    <div
      className="px-4 py-3 flex items-start gap-2"
      style={{
        border: "1px solid rgba(245,158,11,0.3)",
        background: "rgba(245,158,11,0.05)",
        borderRadius: "5px",
        color: "var(--color-warning-dark)",
      }}
    >
      <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
      <div className="text-[12px]">
        <strong>Installer not ready.</strong> Selecting a tool will record
        your choice but the docker compose subprocess will refuse to run
        until you fix:
        <ul className="list-disc pl-4 mt-1 space-y-0.5">
          {preflight.issues.map((i, idx) => (
            <li key={idx}>{i}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}


function ToolCard({
  tool,
  state,
  selected,
  onToggle,
  disabled,
}: {
  tool: OssToolCatalogEntry;
  state: OssToolState | undefined;
  selected: boolean;
  onToggle: () => void;
  disabled: boolean;
}) {
  const Icon = TOOL_ICON[tool.name] ?? Box;
  const installed = state?.state === "installed";
  const failed = state?.state === "failed";
  const installing =
    state?.state === "installing" || state?.state === "pending";

  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled || installed || installing}
      className="text-left p-5 transition-colors w-full"
      style={{
        background:
          selected || installed
            ? "rgba(255,79,0,0.04)"
            : "var(--color-canvas)",
        cursor: disabled || installed || installing ? "not-allowed" : "pointer",
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-9 h-9 flex items-center justify-center shrink-0 mt-0.5"
          style={{
            background: selected
              ? "rgba(255,79,0,0.1)"
              : "var(--color-surface-muted)",
            border: selected
              ? "1px solid var(--color-accent)"
              : "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <Icon
            className="w-4 h-4"
            style={{
              color: selected ? "var(--color-accent)" : "var(--color-muted)",
            }}
            aria-hidden
          />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <h3
              className="text-[14px] font-semibold leading-tight"
              style={{ color: "var(--color-ink)" }}
            >
              {tool.label}
            </h3>
            <StatusPill
              installed={installed}
              installing={installing}
              failed={failed}
              selected={selected}
              heavyweight={tool.is_heavyweight}
            />
          </div>
          <p
            className="text-[12px] mt-1"
            style={{ color: "var(--color-body)" }}
          >
            {tool.summary}
          </p>
          <p
            className="text-[11px] mt-2 italic"
            style={{ color: "var(--color-muted)" }}
          >
            {tool.capability}
          </p>
          <div
            className="text-[10px] mt-3 flex items-center gap-3 uppercase tracking-[0.6px]"
            style={{ color: "var(--color-muted)" }}
          >
            <span>{tool.ram_estimate_mb} MB RAM</span>
            <span>{tool.disk_estimate_gb} GB disk</span>
            {tool.docs_url && (
              <a
                href={tool.docs_url}
                target="_blank"
                rel="noreferrer noopener"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-0.5 underline"
              >
                Docs <ExternalLink className="w-2.5 h-2.5" aria-hidden />
              </a>
            )}
          </div>
          {failed && state?.error_message && (
            <div
              className="mt-3 px-2 py-1.5 text-[11px]"
              style={{
                border: "1px solid rgba(239,68,68,0.3)",
                background: "rgba(239,68,68,0.05)",
                borderRadius: "5px",
                color: "var(--color-error-dark)",
              }}
            >
              {state.error_message}
            </div>
          )}
          {installed && tool.post_install_action && (
            <div
              className="mt-3 px-2 py-1.5 text-[11px]"
              style={{
                border: "1px solid rgba(59,130,246,0.25)",
                background: "rgba(59,130,246,0.04)",
                borderRadius: "5px",
                color: "var(--color-info-dark)",
              }}
            >
              {tool.post_install_action}
            </div>
          )}
        </div>
      </div>
    </button>
  );
}


function StatusPill({
  installed,
  installing,
  failed,
  selected,
  heavyweight,
}: {
  installed: boolean;
  installing: boolean;
  failed: boolean;
  selected: boolean;
  heavyweight: boolean;
}) {
  const cls =
    "inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5";
  const radius = "999px";

  if (installed) {
    return (
      <span
        className={cls}
        style={{
          background: "rgba(16,185,129,0.08)",
          color: "var(--color-success-dark)",
          border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: radius,
        }}
      >
        <CheckCircle2 className="w-2.5 h-2.5" aria-hidden /> Installed
      </span>
    );
  }
  if (installing) {
    return (
      <span
        className={cls}
        style={{
          background: "rgba(255,79,0,0.06)",
          color: "var(--color-accent)",
          border: "1px solid rgba(255,79,0,0.25)",
          borderRadius: radius,
        }}
      >
        <Loader2 className="w-2.5 h-2.5 animate-spin" aria-hidden /> Installing
      </span>
    );
  }
  if (failed) {
    return (
      <span
        className={cls}
        style={{
          background: "rgba(239,68,68,0.06)",
          color: "var(--color-error-dark)",
          border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: radius,
        }}
      >
        <XCircle className="w-2.5 h-2.5" aria-hidden /> Failed
      </span>
    );
  }
  if (selected) {
    return (
      <span
        className={cls}
        style={{
          background: "rgba(255,79,0,0.08)",
          color: "var(--color-accent)",
          border: "1px solid var(--color-accent)",
          borderRadius: radius,
        }}
      >
        <CheckCircle2 className="w-2.5 h-2.5" aria-hidden /> Selected
      </span>
    );
  }
  if (heavyweight) {
    return (
      <span
        className={cls}
        style={{
          background: "rgba(245,158,11,0.06)",
          color: "var(--color-warning-dark)",
          border: "1px solid rgba(245,158,11,0.25)",
          borderRadius: radius,
        }}
      >
        <Lock className="w-2.5 h-2.5" aria-hidden /> Heavyweight
      </span>
    );
  }
  return null;
}
