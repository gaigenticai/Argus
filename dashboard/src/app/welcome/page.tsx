"use client";

/**
 * /welcome — first-run "see Marsad work" flow.
 *
 * Three inline steps, each ~30s:
 *   1. Tell us about your org (name, primary domain, brand keyword)
 *   2. Run your first AI triage (auto-dispatch + live progress)
 *   3. Review the findings (alerts that came back, links to drill in)
 *
 * The post-login route guard sends fresh operators here. Realistic-
 * seed users (admin@argus.demo) skip this and land on / with a
 * one-time demo banner; their state is ``next_action="welcome_demo"``.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Check,
  Loader2,
  Sparkles,
  ShieldAlert,
  Zap,
  Globe,
  Building2,
} from "lucide-react";
import { api, type OnboardingState, type Alert as AlertItem } from "@/lib/api";
import { Field } from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";

type Step = 1 | 2 | 3;

type WizardState = {
  step: Step;
  orgName: string;
  primaryDomain: string;
  brandKeyword: string;
  industry: string;
  orgId: string | null;
  triageStartedAt: number | null;
  triageProgress: string;
  triageAlertCount: number;
  alerts: AlertItem[];
};

const INITIAL: WizardState = {
  step: 1,
  orgName: "",
  primaryDomain: "",
  brandKeyword: "",
  industry: "",
  orgId: null,
  triageStartedAt: null,
  triageProgress: "",
  triageAlertCount: 0,
  alerts: [],
};

export default function WelcomePage() {
  const router = useRouter();
  const { toast } = useToast();
  const [state, setState] = useState<WizardState>(INITIAL);
  const [submitting, setSubmitting] = useState(false);
  const [bootState, setBootState] = useState<OnboardingState | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // On mount, fetch onboarding state. If the operator has already
  // completed setup (e.g. they hit /welcome by accident after
  // creating an org), bounce them back to the dashboard.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const s = await api.getOnboardingState();
        if (cancelled) return;
        setBootState(s);
        if (s.next_action === "ready" || s.next_action === "welcome_demo") {
          router.replace("/");
        }
      } catch {
        // If state can't load, let the operator proceed manually.
      }
    }
    void load();
    return () => {
      cancelled = true;
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [router]);

  const handleQuickstart = useCallback(async () => {
    if (!state.orgName.trim() || !state.primaryDomain.trim() || !state.brandKeyword.trim()) {
      toast("error", "Org name, primary domain, and brand keyword are all required.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.quickstart({
        org_name: state.orgName.trim(),
        primary_domain: state.primaryDomain.trim(),
        brand_keyword: state.brandKeyword.trim(),
        industry: state.industry.trim() || undefined,
      });
      setState((s) => ({ ...s, orgId: res.organization_id, step: 2 }));
    } catch (e) {
      toast("error", `Quickstart failed: ${(e as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  }, [state.orgName, state.primaryDomain, state.brandKeyword, state.industry, toast]);

  const handleRunTriage = useCallback(async () => {
    setSubmitting(true);
    try {
      await api.triggerFeedTriage(72);
      setState((s) => ({
        ...s,
        triageStartedAt: Date.now(),
        triageProgress: "Dispatching feed triage…",
      }));
      // Poll: every 5s, fetch alerts and the most recent triage run.
      // Stop when a TriageRun completes (status="completed" or "error").
      if (pollTimer.current) clearInterval(pollTimer.current);
      pollTimer.current = setInterval(async () => {
        try {
          const [runs, alerts] = await Promise.all([
            api.getTriageHistory(3),
            api.getAlerts({ limit: 10, org_id: state.orgId ?? undefined }),
          ]);
          const last = runs[0];
          if (last && last.status === "completed") {
            if (pollTimer.current) clearInterval(pollTimer.current);
            const orgScoped = alerts.filter((a) => a.organization_id === state.orgId);
            setState((s) => ({
              ...s,
              triageProgress: `Triage complete — ${last.alerts_generated} alert(s) across all orgs, ${orgScoped.length} for ${s.orgName}.`,
              triageAlertCount: orgScoped.length,
              alerts: orgScoped,
              step: 3,
            }));
          } else if (last && last.status === "error") {
            if (pollTimer.current) clearInterval(pollTimer.current);
            setState((s) => ({
              ...s,
              triageProgress: `Triage failed: ${last.error_message ?? "see API logs"}.`,
            }));
          } else {
            const elapsed = Math.floor((Date.now() - (state.triageStartedAt ?? Date.now())) / 1000);
            setState((s) => ({
              ...s,
              triageProgress: `Running… ${elapsed}s elapsed (Marsad analyzes feed entries against your org via the configured LLM)`,
            }));
          }
        } catch {
          /* keep polling — transient errors are fine */
        }
      }, 5000);
    } catch (e) {
      toast("error", `Triage trigger failed: ${(e as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  }, [state.orgId, state.triageStartedAt, toast]);

  return (
    <div
      className="max-w-3xl mx-auto py-10 space-y-8"
      style={{ paddingLeft: 24, paddingRight: 24 }}
    >
      {/* Hero */}
      <div>
        <div
          className="inline-flex items-center gap-2 px-2 py-1 mb-3"
          style={{
            borderRadius: 4,
            background: "rgba(255,79,0,0.08)",
            color: "var(--color-accent)",
          }}
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span className="text-[10px] font-bold uppercase tracking-[1.2px]">
            Welcome to Marsad
          </span>
        </div>
        <h1
          className="text-[32px] font-semibold tracking-[-0.02em]"
          style={{ color: "var(--color-ink)" }}
        >
          Catch your first threat in two minutes.
        </h1>
        <p
          className="mt-2 text-[14px] leading-relaxed max-w-[560px]"
          style={{ color: "var(--color-muted)" }}
        >
          Tell Marsad what to watch for — your organization, primary
          domain, and brand keyword. We&apos;ll wire up the asset
          registry, run an AI triage against the configured threat
          feeds, and surface anything the LLM thinks looks suspicious.
        </p>
      </div>

      {/* Step bar */}
      <StepBar current={state.step} />

      {/* Steps */}
      {state.step === 1 && (
        <Step1
          state={state}
          setState={setState}
          submitting={submitting}
          onSubmit={handleQuickstart}
        />
      )}
      {state.step === 2 && (
        <Step2
          state={state}
          submitting={submitting}
          onRunTriage={handleRunTriage}
        />
      )}
      {state.step === 3 && (
        <Step3
          state={state}
          onFinish={() => router.replace("/")}
        />
      )}

      {/* Escape hatch */}
      {bootState?.next_action === "quickstart" && state.step === 1 && (
        <div
          className="text-[12px] mt-4"
          style={{ color: "var(--color-muted)" }}
        >
          Need the full registration wizard (assets, vendors, infra,
          people)?{" "}
          <Link
            href="/onboarding"
            style={{ color: "var(--color-accent)", textDecoration: "underline" }}
          >
            Go to /onboarding
          </Link>
          {" "}— quickstart here is the express version.
        </div>
      )}
    </div>
  );
}

function StepBar({ current }: { current: Step }) {
  const steps: { num: Step; label: string; icon: typeof Building2 }[] = [
    { num: 1, label: "Your organization", icon: Building2 },
    { num: 2, label: "Run AI triage", icon: Zap },
    { num: 3, label: "Review findings", icon: ShieldAlert },
  ];
  return (
    <div className="flex items-center gap-2">
      {steps.map((s, i) => {
        const done = current > s.num;
        const active = current === s.num;
        const Icon = done ? Check : s.icon;
        return (
          <div key={s.num} className="flex items-center gap-2 flex-1">
            <div
              className="flex items-center gap-2 px-3 py-2 flex-1"
              style={{
                borderRadius: 4,
                border: `1px solid ${
                  active
                    ? "var(--color-accent)"
                    : done
                    ? "rgba(34,197,94,0.4)"
                    : "var(--color-border)"
                }`,
                background: active
                  ? "rgba(255,79,0,0.04)"
                  : done
                  ? "rgba(34,197,94,0.04)"
                  : "var(--color-canvas)",
              }}
            >
              <Icon
                className="w-4 h-4 shrink-0"
                style={{
                  color: done
                    ? "var(--color-success)"
                    : active
                    ? "var(--color-accent)"
                    : "var(--color-muted)",
                }}
              />
              <div className="leading-tight">
                <div
                  className="text-[10px] font-bold uppercase tracking-[0.8px]"
                  style={{ color: "var(--color-muted)" }}
                >
                  Step {s.num}
                </div>
                <div
                  className="text-[12px] font-semibold"
                  style={{ color: "var(--color-ink)" }}
                >
                  {s.label}
                </div>
              </div>
            </div>
            {i < steps.length - 1 && (
              <div
                className="h-px w-4 shrink-0"
                style={{ background: "var(--color-border)" }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: 40,
  padding: "0 12px",
  fontSize: 14,
  background: "var(--color-canvas)",
  border: "1px solid var(--color-border)",
  borderRadius: 4,
  outline: "none",
  color: "var(--color-ink)",
};

function Step1({
  state,
  setState,
  submitting,
  onSubmit,
}: {
  state: WizardState;
  setState: (s: (prev: WizardState) => WizardState) => void;
  submitting: boolean;
  onSubmit: () => void;
}) {
  return (
    <div
      className="p-6 space-y-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div>
        <h2 className="text-[18px] font-semibold" style={{ color: "var(--color-ink)" }}>
          Tell us about your organization
        </h2>
        <p className="text-[12.5px] mt-1" style={{ color: "var(--color-muted)" }}>
          Just the essentials — you can add assets, VIPs, and vendors
          later from the full onboarding wizard.
        </p>
      </div>

      <Field label="Organization name" required hint="Your company / brand entity. Shown on every alert.">
        <input
          value={state.orgName}
          onChange={(e) => setState((s) => ({ ...s, orgName: e.target.value }))}
          placeholder="e.g. Acme Corp"
          style={inputStyle}
          autoFocus
        />
      </Field>

      <Field label="Primary domain" required hint="Apex domain only (no scheme, no path). Marsad watches for typosquats and impersonations of this.">
        <input
          value={state.primaryDomain}
          onChange={(e) => setState((s) => ({ ...s, primaryDomain: e.target.value }))}
          placeholder="acme.example"
          style={{ ...inputStyle, fontFamily: "monospace" }}
        />
      </Field>

      <Field label="Brand keyword" required hint='What attackers might call you. Usually a short product/brand name (e.g. "Acme", "AcmePay").'>
        <input
          value={state.brandKeyword}
          onChange={(e) => setState((s) => ({ ...s, brandKeyword: e.target.value }))}
          placeholder="Acme"
          style={inputStyle}
        />
      </Field>

      <Field label="Industry" hint="Optional — helps the LLM weight industry-specific signals (banking → ransomware leak sites, healthcare → HIPAA-flavored phishing, etc.).">
        <input
          value={state.industry}
          onChange={(e) => setState((s) => ({ ...s, industry: e.target.value }))}
          placeholder="e.g. financial_services / healthcare / manufacturing"
          style={inputStyle}
        />
      </Field>

      <div className="flex justify-end pt-2">
        <button
          onClick={onSubmit}
          disabled={submitting}
          className="inline-flex items-center gap-2 h-10 px-5"
          style={{
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            borderRadius: 4,
            fontSize: 14,
            fontWeight: 600,
            border: "none",
            cursor: submitting ? "not-allowed" : "pointer",
            opacity: submitting ? 0.6 : 1,
          }}
        >
          {submitting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Creating…
            </>
          ) : (
            <>
              Create organization
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function Step2({
  state,
  submitting,
  onRunTriage,
}: {
  state: WizardState;
  submitting: boolean;
  onRunTriage: () => void;
}) {
  const running = state.triageStartedAt !== null;
  return (
    <div
      className="p-6 space-y-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div>
        <h2 className="text-[18px] font-semibold" style={{ color: "var(--color-ink)" }}>
          Run your first AI triage
        </h2>
        <p className="text-[12.5px] mt-1" style={{ color: "var(--color-muted)" }}>
          Marsad will analyze the last 72 hours of threat-feed entries
          against <strong>{state.orgName}</strong>, classify each as a
          potential threat or noise, and create alerts for anything
          that scores high. Typical run time: 30–90 seconds.
        </p>
      </div>

      <div
        className="p-4"
        style={{
          background: "var(--color-surface)",
          borderRadius: 4,
          border: "1px solid var(--color-border)",
        }}
      >
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 shrink-0" style={{ color: "var(--color-accent)" }} />
          <div className="flex-1">
            <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
              {state.orgName}
            </div>
            <div className="text-[12px] font-mono" style={{ color: "var(--color-muted)" }}>
              {state.primaryDomain} · brand: {state.brandKeyword}
            </div>
          </div>
        </div>
      </div>

      {running && (
        <div
          className="p-4 flex items-center gap-3"
          style={{
            borderRadius: 4,
            background: "rgba(255,79,0,0.04)",
            border: "1px solid rgba(255,79,0,0.2)",
          }}
        >
          <Loader2
            className="w-4 h-4 shrink-0 animate-spin"
            style={{ color: "var(--color-accent)" }}
          />
          <div className="text-[12.5px]" style={{ color: "var(--color-ink)" }}>
            {state.triageProgress}
          </div>
        </div>
      )}

      <div className="flex justify-end pt-2">
        <button
          onClick={onRunTriage}
          disabled={submitting || running}
          className="inline-flex items-center gap-2 h-10 px-5"
          style={{
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            borderRadius: 4,
            fontSize: 14,
            fontWeight: 600,
            border: "none",
            cursor: submitting || running ? "not-allowed" : "pointer",
            opacity: submitting || running ? 0.6 : 1,
          }}
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Running triage…
            </>
          ) : (
            <>
              <Zap className="w-4 h-4" />
              Run AI triage
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function Step3({
  state,
  onFinish,
}: {
  state: WizardState;
  onFinish: () => void;
}) {
  return (
    <div
      className="p-6 space-y-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div>
        <h2 className="text-[18px] font-semibold" style={{ color: "var(--color-ink)" }}>
          {state.alerts.length > 0
            ? `Marsad found ${state.alerts.length} alert${state.alerts.length === 1 ? "" : "s"} for ${state.orgName}`
            : `Triage complete — nothing flagged for ${state.orgName} yet`}
        </h2>
        <p className="text-[12.5px] mt-1" style={{ color: "var(--color-muted)" }}>
          {state.triageProgress}
        </p>
      </div>

      {state.alerts.length === 0 ? (
        <div
          className="p-4 text-[12.5px]"
          style={{
            background: "rgba(34,197,94,0.06)",
            borderRadius: 4,
            border: "1px solid rgba(34,197,94,0.2)",
            color: "var(--color-body)",
          }}
        >
          That&apos;s good news for now — no high-severity feed entries
          matched <strong>{state.orgName}</strong> in the last 72h.
          Marsad will keep polling feeds and re-running triage on a
          schedule. To boost signal, configure paid feed API keys
          (OTX, GreyNoise, abuse.ch) in <code>.env</code>; or wait
          for the next scheduled run.
        </div>
      ) : (
        <div className="space-y-2">
          {state.alerts.slice(0, 5).map((a) => (
            <div
              key={a.id}
              className="p-3 flex items-start gap-3"
              style={{
                background: "var(--color-surface)",
                borderRadius: 4,
                border: "1px solid var(--color-border)",
              }}
            >
              <SeverityDot severity={a.severity} />
              <div className="flex-1 min-w-0">
                <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                  {a.title}
                </div>
                <div
                  className="text-[12px] mt-0.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  {a.summary}
                </div>
              </div>
              <Link
                href={`/alerts/${a.id}`}
                className="text-[12px] font-semibold shrink-0"
                style={{ color: "var(--color-accent)" }}
              >
                Open →
              </Link>
            </div>
          ))}
          {state.alerts.length > 5 && (
            <div
              className="text-[12px] text-center pt-1"
              style={{ color: "var(--color-muted)" }}
            >
              + {state.alerts.length - 5} more on the alerts page.
            </div>
          )}
        </div>
      )}

      <div className="flex justify-between items-center pt-2">
        <Link
          href="/onboarding"
          className="text-[12px] underline"
          style={{ color: "var(--color-muted)" }}
        >
          Add more assets / vendors / VIPs →
        </Link>
        <button
          onClick={onFinish}
          className="inline-flex items-center gap-2 h-10 px-5"
          style={{
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            borderRadius: 4,
            fontSize: 14,
            fontWeight: 600,
            border: "none",
            cursor: "pointer",
          }}
        >
          Open dashboard
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "var(--color-error)",
    high: "var(--color-accent)",
    medium: "var(--color-warning)",
    low: "var(--color-muted)",
    info: "var(--color-muted)",
  };
  return (
    <div
      className="w-2 h-2 rounded-full mt-2 shrink-0"
      style={{ background: colors[severity] || colors.low }}
    />
  );
}
