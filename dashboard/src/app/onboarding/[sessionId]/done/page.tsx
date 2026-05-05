"use client";

/**
 * /onboarding/[sessionId]/done — landing screen after Complete.
 *
 * Answers the operator's "what now?" question by surfacing what
 * Marsad is doing for them in the background:
 *   - EASM discovery jobs (subdomain enum, HTTPS probe, DNS refresh)
 *   - AI triage running against threat feeds for the new org
 *   - Alerts as they land
 *
 * Plus three concrete next-step cards (feeds, notifications, agent
 * posture) and an "Open dashboard" CTA that scopes the dashboard
 * to the new org via the ``argus_org_id`` localStorage key.
 */

import { useCallback, useEffect, useRef, useState, use } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowRight,
  Bell,
  Brain,
  CheckCircle2,
  Globe,
  Loader2,
  Radio,
  Rss,
  ShieldAlert,
  Sparkles,
  Zap,
} from "lucide-react";
import { api, type Alert as AlertItem, type DiscoveryJobRecord } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { DomainVerificationBanner } from "@/components/shared/domain-verification-banner";

const ORG_LOCALSTORAGE_KEY = "argus_org_id";
const POLL_INTERVAL_MS = 5000;

export default function OnboardingDonePage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const sp = useSearchParams();
  const router = useRouter();
  const { toast } = useToast();

  const orgId = sp.get("org");
  const orgName = sp.get("orgName") || "your organization";
  const primaryDomain = sp.get("domain") || "";
  const assetsCreated = Number(sp.get("assets") || 0);
  const jobsEnqueued = Number(sp.get("jobs") || 0);

  const [discoveryJobs, setDiscoveryJobs] = useState<DiscoveryJobRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [triageRunning, setTriageRunning] = useState(false);
  const [triageDispatched, setTriageDispatched] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Set the new org as the operator's current scope so when they hit
  // "Open dashboard" the alerts/feeds pages are filtered to it.
  useEffect(() => {
    if (orgId) {
      window.localStorage.setItem(ORG_LOCALSTORAGE_KEY, orgId);
    }
  }, [orgId]);

  // Auto-dispatch the first feed triage on mount so the operator
  // sees real findings without having to click anything. Idempotent —
  // the running flag prevents double-dispatch on re-renders.
  useEffect(() => {
    if (triageDispatched || !orgId) return;
    let cancelled = false;
    (async () => {
      try {
        await api.triggerFeedTriage(72);
        if (cancelled) return;
        setTriageDispatched(true);
        setTriageRunning(true);
      } catch {
        // If triage trigger fails it's not fatal — the scheduled
        // worker will eventually run one. Surface a soft warning.
        toast(
          "warning",
          "Couldn't auto-dispatch the first triage — it will still run on schedule.",
        );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [orgId, triageDispatched, toast]);

  // Poll discovery jobs + recent alerts every 5s. Stop polling once
  // the queue has fully drained (no queued/running) AND triage has
  // completed at least once for this org.
  const refresh = useCallback(async () => {
    try {
      const [jobs, alertList, runs] = await Promise.all([
        orgId
          ? api.listDiscoveryJobs({ organization_id: orgId, limit: 50 })
          : Promise.resolve([] as DiscoveryJobRecord[]),
        api.getAlerts({ org_id: orgId ?? undefined, limit: 10 }),
        api.getTriageHistory(3),
      ]);
      setDiscoveryJobs(jobs);
      setAlerts(alertList);
      const lastRun = runs[0];
      if (lastRun && (lastRun.status === "completed" || lastRun.status === "error")) {
        setTriageRunning(false);
      }
    } catch {
      // Transient failures while polling are fine.
    }
  }, [orgId]);

  useEffect(() => {
    void refresh();
    pollTimer.current = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [refresh]);

  const queuedJobs = discoveryJobs.filter((j) => j.status === "queued").length;
  const runningJobs = discoveryJobs.filter((j) => j.status === "running").length;
  const completedJobs = discoveryJobs.filter((j) => j.status === "succeeded").length;
  const failedJobs = discoveryJobs.filter((j) => j.status === "failed").length;
  const allDiscoveryDone = discoveryJobs.length > 0 && queuedJobs === 0 && runningJobs === 0;

  return (
    <div className="max-w-3xl mx-auto py-10 space-y-7" style={{ paddingLeft: 24, paddingRight: 24 }}>
      {/* Hero */}
      <div>
        <div
          className="inline-flex items-center gap-2 px-2 py-1 mb-3"
          style={{
            borderRadius: 4,
            background: "rgba(34,197,94,0.1)",
            color: "var(--color-success-dark)",
          }}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span className="text-[10px] font-bold uppercase tracking-[1.2px]">
            Setup complete
          </span>
        </div>
        <h1
          className="text-[28px] font-semibold tracking-[-0.02em]"
          style={{ color: "var(--color-ink)" }}
        >
          Marsad is now monitoring {orgName}.
        </h1>
        <p
          className="mt-2 text-[14px] leading-relaxed max-w-[560px]"
          style={{ color: "var(--color-muted)" }}
        >
          {assetsCreated} asset{assetsCreated === 1 ? "" : "s"} registered ·{" "}
          {jobsEnqueued} discovery job{jobsEnqueued === 1 ? "" : "s"} queued.
          Below is what&apos;s running for you right now. You can leave
          this page open to watch results land, or jump straight to
          your dashboard.
        </p>
      </div>

      {/* Verify-your-domain banner — only renders when status != verified */}
      {orgId && primaryDomain && (
        <DomainVerificationBanner
          orgId={orgId}
          domain={primaryDomain}
          onVerified={() => void refresh()}
        />
      )}

      {/* Live status — discovery */}
      <StatusCard
        icon={Globe}
        title="EASM discovery"
        subtitle={
          allDiscoveryDone
            ? `Done — ${completedJobs} job(s) completed${failedJobs ? `, ${failedJobs} failed` : ""}.`
            : `${runningJobs} running · ${queuedJobs} queued · ${completedJobs} done${failedJobs ? ` · ${failedJobs} failed` : ""}`
        }
        spinning={!allDiscoveryDone && discoveryJobs.length > 0}
        helperLink={{ href: "/assets", label: "Watch assets land →" }}
        explainer="Subdomain enumeration (Amass + Subfinder), HTTP/S service probes, and DNS refresh against your primary domain. New subdomains and services become Asset records as they're discovered."
      />

      {/* Live status — triage */}
      <StatusCard
        icon={Brain}
        title="AI threat triage"
        subtitle={
          triageRunning
            ? "Running — Marsad is analyzing recent feed entries against your brand keywords via the configured LLM."
            : alerts.length > 0
            ? `Surfaced ${alerts.length} alert(s) so far for ${orgName}.`
            : "Triage idle. Re-run any time from the feeds page."
        }
        spinning={triageRunning}
        helperLink={{ href: "/alerts", label: "View all alerts →" }}
        explainer="Marsad triages new threat-feed entries against your org's domains, keywords, and VIPs. Anything the LLM scores as high-severity becomes an Alert."
      />

      {/* Most recent alerts */}
      {alerts.length > 0 && (
        <div
          className="p-5 space-y-3"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 5,
          }}
        >
          <div className="flex items-center justify-between">
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              Recent findings for {orgName}
            </h3>
            <Link
              href="/alerts"
              className="text-[12px] font-semibold"
              style={{ color: "var(--color-accent)" }}
            >
              See all →
            </Link>
          </div>
          {alerts.slice(0, 3).map((a) => (
            <Link
              key={a.id}
              href={`/alerts/${a.id}`}
              className="flex items-start gap-3 p-3"
              style={{
                background: "var(--color-surface)",
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                textDecoration: "none",
              }}
            >
              <SeverityDot severity={a.severity} />
              <div className="flex-1 min-w-0">
                <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                  {a.title}
                </div>
                <div className="text-[12px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                  {a.summary}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Next-step cards */}
      <div>
        <h3 className="text-[14px] font-semibold mb-3" style={{ color: "var(--color-ink)" }}>
          Strengthen your coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Pick this first — without channels + breach emails the
              Telegram crawler and HIBP checker have nothing to do. */}
          <NextStepCard
            icon={Radio}
            title="Pick monitoring scope"
            body="Choose Telegram channels + emails Marsad should watch on your behalf. Empty = silent workers."
            href="/settings?tab=monitoring"
          />
          <NextStepCard
            icon={Rss}
            title="Add paid feed keys"
            body="OTX, GreyNoise, abuse.ch — set the env vars in .env to multiply your feed volume."
            href="/feeds"
          />
          <NextStepCard
            icon={Bell}
            title="Wire up notifications"
            body="Slack / email / PagerDuty so you get pinged the moment a high-severity alert appears."
            href="/notifications"
          />
          <NextStepCard
            icon={ShieldAlert}
            title="Tune agent posture"
            body="Decide which actions agents can take autonomously vs. require you to approve."
            href="/agent-settings"
          />
        </div>
      </div>

      {/* CTA */}
      <div
        className="flex items-center justify-between pt-2"
        style={{ borderTop: "1px solid var(--color-border)", paddingTop: 24 }}
      >
        <Link
          href={`/onboarding/${sessionId}`}
          className="text-[12px] underline"
          style={{ color: "var(--color-muted)" }}
        >
          ← Review the wizard answers
        </Link>
        <button
          onClick={() => router.replace("/")}
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
          <Sparkles className="w-4 h-4" />
          Open my dashboard
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

function StatusCard({
  icon: Icon,
  title,
  subtitle,
  spinning,
  helperLink,
  explainer,
}: {
  icon: typeof Globe;
  title: string;
  subtitle: string;
  spinning: boolean;
  helperLink: { href: string; label: string };
  explainer: string;
}) {
  return (
    <div
      className="p-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-9 h-9 flex items-center justify-center shrink-0"
          style={{
            background: "var(--color-surface)",
            borderRadius: 4,
            border: "1px solid var(--color-border)",
          }}
        >
          {spinning ? (
            <Loader2 className="w-4 h-4 animate-spin" style={{ color: "var(--color-accent)" }} />
          ) : (
            <Icon className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              {title}
            </h3>
            <Link
              href={helperLink.href}
              className="text-[12px] font-semibold shrink-0"
              style={{ color: "var(--color-accent)" }}
            >
              {helperLink.label}
            </Link>
          </div>
          <div className="text-[12.5px] mt-1" style={{ color: "var(--color-body)" }}>
            {subtitle}
          </div>
          <div className="text-[11.5px] mt-2" style={{ color: "var(--color-muted)" }}>
            {explainer}
          </div>
        </div>
      </div>
    </div>
  );
}

function NextStepCard({
  icon: Icon,
  title,
  body,
  href,
}: {
  icon: typeof Globe;
  title: string;
  body: string;
  href: string;
}) {
  return (
    <Link
      href={href}
      className="p-4 block"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
        textDecoration: "none",
      }}
    >
      <Icon className="w-4 h-4 mb-2" style={{ color: "var(--color-accent)" }} />
      <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
        {title}
      </div>
      <div className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
        {body}
      </div>
      <div
        className="text-[11.5px] font-semibold mt-2 inline-flex items-center gap-1"
        style={{ color: "var(--color-accent)" }}
      >
        Configure
        <ArrowRight className="w-3 h-3" />
      </div>
    </Link>
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
