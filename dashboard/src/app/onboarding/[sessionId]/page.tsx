"use client";

import { use, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Sparkles,
  Building2,
  Globe,
  Users,
  Briefcase,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Plus,
  Trash2,
  Loader2,
  CircleAlert,
  ListChecks,
  Save,
  PartyPopper,
} from "lucide-react";
import {
  api,
  type AssetCriticalityLevel,
  type AssetTypeName,
  type DiscoveryJobKindName,
  type OnboardingSessionRecord,
  type OnboardingStepKey,
  type OnboardingValidationReport,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Select as ThemedSelect } from "@/components/shared/select";

// --- Types --------------------------------------------------------------

interface AssetEntry {
  asset_type: AssetTypeName;
  value: string;
  criticality: AssetCriticalityLevel;
  tags: string;
  details: string;
}

interface OrgStepData {
  name: string;
  industry: string;
  primary_domain: string;
  keywords: string;
  notes: string;
}

interface AssetStepData {
  assets: AssetEntry[];
}

interface ReviewStepData {
  enable_auto_discovery: boolean;
  discover_kinds: DiscoveryJobKindName[];
}

interface WizardState {
  organization: OrgStepData;
  infra: AssetStepData;
  people_and_brand: AssetStepData;
  vendors: AssetStepData;
  review: ReviewStepData;
}

const STEPS: { key: OnboardingStepKey; label: string; icon: typeof Building2; helper: string }[] = [
  { key: "organization", label: "Organization", icon: Building2, helper: "Identity, industry, primary domain." },
  { key: "infra", label: "Infra", icon: Globe, helper: "Domains, IPs, services, email-sending domains." },
  { key: "people_and_brand", label: "People & Brand", icon: Users, helper: "Executives, brands, social handles, mobile apps." },
  { key: "vendors", label: "Vendors", icon: Briefcase, helper: "Third parties for TPRM monitoring." },
  { key: "review", label: "Review", icon: CheckCircle2, helper: "Confirm counts and kick off auto-discovery." },
];

const INFRA_TYPES: AssetTypeName[] = [
  "domain",
  "subdomain",
  "ip_address",
  "ip_range",
  "service",
  "email_domain",
];

const PEOPLE_BRAND_TYPES: AssetTypeName[] = [
  "executive",
  "brand",
  "mobile_app",
  "social_handle",
];

const VENDOR_TYPES: AssetTypeName[] = ["vendor"];

const CRITICALITIES: AssetCriticalityLevel[] = ["crown_jewel", "high", "medium", "low"];

const DISCOVERY_KINDS: { kind: DiscoveryJobKindName; label: string; helper: string }[] = [
  { kind: "subdomain_enum", label: "Subdomain enumeration", helper: "Amass + Subfinder against your domains" },
  { kind: "httpx_probe", label: "HTTP/S probe", helper: "Detect live web services + tech stack" },
  { kind: "port_scan", label: "Port scan", helper: "naabu against IPs and ranges" },
  { kind: "ct_log_backfill", label: "Cert transparency backfill", helper: "Pull historical certs for your domains" },
  { kind: "whois_refresh", label: "WHOIS refresh", helper: "Snapshot registrar + expiry data" },
  { kind: "dns_refresh", label: "DNS refresh", helper: "MX/SPF/DKIM/DMARC + A/AAAA snapshots" },
];

// --- Utilities ----------------------------------------------------------

function emptyOrg(): OrgStepData {
  return { name: "", industry: "", primary_domain: "", keywords: "", notes: "" };
}
function emptyAssets(): AssetStepData {
  return { assets: [] };
}
function emptyReview(): ReviewStepData {
  return {
    enable_auto_discovery: true,
    discover_kinds: ["subdomain_enum", "httpx_probe", "dns_refresh"],
  };
}

function defaultEntry(asset_type: AssetTypeName): AssetEntry {
  return { asset_type, value: "", criticality: "medium", tags: "", details: "" };
}

function uiToServerOrg(o: OrgStepData) {
  return {
    name: o.name.trim(),
    industry: o.industry.trim() || undefined,
    primary_domain: o.primary_domain.trim() || undefined,
    keywords: o.keywords.split(",").map((s) => s.trim()).filter(Boolean),
    notes: o.notes.trim() || undefined,
  };
}

function uiToServerAssets(s: AssetStepData) {
  return {
    assets: s.assets.map((e) => {
      let detailsObj: Record<string, unknown> | undefined;
      const trimmed = e.details.trim();
      if (trimmed) {
        try {
          detailsObj = JSON.parse(trimmed) as Record<string, unknown>;
        } catch {
          detailsObj = undefined;
        }
      }
      return {
        asset_type: e.asset_type,
        value: e.value.trim(),
        criticality: e.criticality,
        tags: e.tags.split(",").map((t) => t.trim()).filter(Boolean),
        details: detailsObj,
      };
    }),
  };
}

function loadStateFromSession(sess: OnboardingSessionRecord): WizardState {
  const sd = (sess.step_data || {}) as Record<string, unknown>;

  const org = (sd.organization as Partial<OrgStepData> & { keywords?: string[] }) || {};
  const orgState: OrgStepData = {
    name: typeof org.name === "string" ? org.name : "",
    industry: typeof org.industry === "string" ? org.industry : "",
    primary_domain: typeof org.primary_domain === "string" ? org.primary_domain : "",
    keywords: Array.isArray(org.keywords) ? org.keywords.join(", ") : "",
    notes: typeof org.notes === "string" ? org.notes : "",
  };

  const decode = (key: string): AssetStepData => {
    const raw = sd[key] as { assets?: unknown[] } | undefined;
    if (!raw?.assets) return emptyAssets();
    return {
      assets: raw.assets.map((entry) => {
        const e = entry as Record<string, unknown>;
        return {
          asset_type: (e.asset_type as AssetTypeName) ?? "domain",
          value: typeof e.value === "string" ? e.value : "",
          criticality: (e.criticality as AssetCriticalityLevel) ?? "medium",
          tags: Array.isArray(e.tags) ? (e.tags as string[]).join(", ") : "",
          details: e.details ? JSON.stringify(e.details, null, 2) : "",
        };
      }),
    };
  };

  const review = (sd.review as Partial<ReviewStepData>) || {};
  const reviewState: ReviewStepData = {
    enable_auto_discovery:
      typeof review.enable_auto_discovery === "boolean"
        ? review.enable_auto_discovery
        : true,
    discover_kinds:
      Array.isArray(review.discover_kinds)
        ? (review.discover_kinds as DiscoveryJobKindName[])
        : ["subdomain_enum", "httpx_probe", "dns_refresh"],
  };

  return {
    organization: orgState,
    infra: decode("infra"),
    people_and_brand: decode("people_and_brand"),
    vendors: decode("vendors"),
    review: reviewState,
  };
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: "40px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  padding: "0 12px",
  fontSize: "14px",
  outline: "none",
};

const smallInputStyle: React.CSSProperties = {
  width: "100%",
  height: "36px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  padding: "0 8px",
  fontSize: "13px",
  outline: "none",
};

// --- Page ---------------------------------------------------------------

export default function WizardPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = use(params);
  const router = useRouter();
  const { toast } = useToast();

  const [session, setSession] = useState<OnboardingSessionRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [completing, setCompleting] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [reports, setReports] = useState<OnboardingValidationReport[]>([]);
  const [state, setState] = useState<WizardState>({
    organization: emptyOrg(),
    infra: emptyAssets(),
    people_and_brand: emptyAssets(),
    vendors: emptyAssets(),
    review: emptyReview(),
  });

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  async function load() {
    setLoading(true);
    try {
      const sess = await api.getOnboardingSession(sessionId);
      setSession(sess);
      setState(loadStateFromSession(sess));
      setStepIndex(Math.max(0, Math.min(STEPS.length - 1, sess.current_step - 1)));
    } catch (e) {
      toast("error", `Failed to load session: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }

  const currentStep = STEPS[stepIndex];
  const stepIsReadOnly = session?.state !== "draft";

  const persistStep = useCallback(
    async (advance: boolean) => {
      if (!session) return;
      if (stepIsReadOnly) return;
      setSaving(true);
      try {
        let payload: unknown;
        if (currentStep.key === "organization") payload = uiToServerOrg(state.organization);
        else if (currentStep.key === "review") payload = state.review;
        else payload = uiToServerAssets(state[currentStep.key]);

        const updated = await api.patchOnboardingSession(session.id, {
          step: currentStep.key,
          data: payload as object,
          advance,
        });
        setSession(updated);
        if (advance) {
          setStepIndex((idx) => Math.min(STEPS.length - 1, idx + 1));
        }
        toast("success", advance ? "Saved & advanced" : "Saved");
      } catch (e) {
        toast("error", `Save failed: ${(e as Error).message}`);
      } finally {
        setSaving(false);
      }
    },
    [session, stepIsReadOnly, currentStep, state, toast]
  );

  const runValidation = useCallback(async () => {
    if (!session) return;
    try {
      const r = await api.validateOnboardingSession(session.id);
      setReports(r);
      const allOk = r.every((rep) => rep.valid);
      toast(allOk ? "success" : "warning", allOk ? "All steps valid" : "Some steps need attention");
    } catch (e) {
      toast("error", `Validation failed: ${(e as Error).message}`);
    }
  }, [session, toast]);

  async function handleComplete() {
    if (!session) return;
    setCompleting(true);
    try {
      await persistStep(false);
      const result = await api.completeOnboardingSession(session.id);
      toast("success", `Complete — ${result.assets_created} assets, ${result.discovery_jobs_enqueued} discovery jobs queued.`);
      router.push(`/organizations`);
    } catch (e) {
      toast("error", `Complete failed: ${(e as Error).message}`);
    } finally {
      setCompleting(false);
    }
  }

  async function handleAbandon() {
    if (!session) return;
    if (!confirm("Abandon this session? You won't be able to edit it again.")) return;
    try {
      await api.abandonOnboardingSession(session.id);
      router.push("/onboarding");
    } catch (e) {
      toast("error", `Abandon failed: ${(e as Error).message}`);
    }
  }

  const stepReport = useMemo(
    () => reports.find((r) => r.step === currentStep.key),
    [reports, currentStep.key]
  );

  if (loading || !session) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "64px 0" }}>
        <Loader2 style={{ width: "24px", height: "24px", color: "var(--color-muted)" }} className="animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-ink)", display: "flex", alignItems: "center", gap: "8px" }}>
            <Sparkles style={{ width: "24px", height: "24px", color: "var(--color-accent)" }} />
            Onboarding wizard
          </h2>
          <p style={{ fontSize: "14px", color: "var(--color-muted)", marginTop: "2px" }}>
            Session <span style={{ fontFamily: "monospace" }}>{session.id.slice(0, 8)}…</span>
            {" · "}
            <span style={{ textTransform: "capitalize" }}>{session.state}</span>
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <WizardSecondaryButton onClick={runValidation}>
            <ListChecks style={{ width: "16px", height: "16px" }} />
            Validate
          </WizardSecondaryButton>
          {!stepIsReadOnly && (
            <WizardDangerButton onClick={handleAbandon}>
              Abandon
            </WizardDangerButton>
          )}
        </div>
      </div>

      {/* Stepper */}
      <div style={{ borderRadius: "5px", background: "var(--color-canvas)", border: "1px solid var(--color-border)", padding: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", overflowX: "auto" }}>
          {STEPS.map((s, i) => {
            const Icon = s.icon;
            const active = i === stepIndex;
            const done = i < stepIndex;
            return (
              <button
                key={s.key}
                onClick={() => setStepIndex(i)}
                style={{
                  flex: 1,
                  minWidth: "140px",
                  borderRadius: "5px",
                  padding: "8px 12px",
                  textAlign: "left",
                  border: active
                    ? "1px solid var(--color-accent)"
                    : done
                    ? "1px solid rgba(0,167,111,0.4)"
                    : "1px solid var(--color-border)",
                  background: active
                    ? "rgba(255,79,0,0.06)"
                    : done
                    ? "rgba(0,167,111,0.06)"
                    : "var(--color-surface)",
                  cursor: "pointer",
                  transition: "border-color 0.15s, background 0.15s",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <Icon style={{
                    width: "16px",
                    height: "16px",
                    color: active ? "var(--color-accent)" : done ? "#007B55" : "var(--color-muted)",
                  }} />
                  <span style={{
                    fontSize: "12px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: active ? "var(--color-accent)" : done ? "#007B55" : "var(--color-body)",
                  }}>
                    {i + 1}. {s.label}
                  </span>
                </div>
                <div style={{ fontSize: "11px", color: "var(--color-muted)", marginTop: "4px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {s.helper}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Validation banner */}
      {stepReport && !stepReport.valid && (
        <div style={{ borderRadius: "5px", background: "rgba(255,86,48,0.08)", border: "1px solid rgba(255,86,48,0.4)", padding: "16px", display: "flex", gap: "12px" }}>
          <CircleAlert style={{ width: "20px", height: "20px", color: "#B71D18", marginTop: "2px", flexShrink: 0 }} />
          <div style={{ flex: 1, fontSize: "13px", color: "#B71D18" }}>
            <div style={{ fontWeight: 700, marginBottom: "4px" }}>This step has validation issues</div>
            <ul style={{ listStyle: "disc", paddingLeft: "20px" }}>
              {stepReport.errors.slice(0, 6).map((err, i) => (
                <li key={i}>
                  <code style={{ fontSize: "12px" }}>{Array.isArray(err.loc) ? err.loc.join(".") : "?"}</code>
                  {": "}
                  {String(err.msg ?? JSON.stringify(err))}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Step body */}
      <div style={{ borderRadius: "5px", background: "var(--color-canvas)", border: "1px solid var(--color-border)", padding: "24px" }}>
        {currentStep.key === "organization" && (
          <OrganizationStep
            value={state.organization}
            onChange={(v) => setState((s) => ({ ...s, organization: v }))}
            readOnly={stepIsReadOnly}
          />
        )}
        {currentStep.key === "infra" && (
          <AssetTableStep
            title="Infrastructure"
            allowedTypes={INFRA_TYPES}
            value={state.infra}
            onChange={(v) => setState((s) => ({ ...s, infra: v }))}
            readOnly={stepIsReadOnly}
          />
        )}
        {currentStep.key === "people_and_brand" && (
          <AssetTableStep
            title="People & Brand"
            allowedTypes={PEOPLE_BRAND_TYPES}
            value={state.people_and_brand}
            onChange={(v) => setState((s) => ({ ...s, people_and_brand: v }))}
            readOnly={stepIsReadOnly}
          />
        )}
        {currentStep.key === "vendors" && (
          <AssetTableStep
            title="Vendors"
            allowedTypes={VENDOR_TYPES}
            value={state.vendors}
            onChange={(v) => setState((s) => ({ ...s, vendors: v }))}
            readOnly={stepIsReadOnly}
          />
        )}
        {currentStep.key === "review" && (
          <ReviewStepView
            wizard={state}
            onChange={(v) => setState((s) => ({ ...s, review: v }))}
            readOnly={stepIsReadOnly}
          />
        )}
      </div>

      {/* Footer nav */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <WizardSecondaryButton
          onClick={() => setStepIndex((i) => Math.max(0, i - 1))}
          disabled={stepIndex === 0}
        >
          <ChevronLeft style={{ width: "16px", height: "16px" }} />
          Back
        </WizardSecondaryButton>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {!stepIsReadOnly && (
            <WizardSecondaryButton onClick={() => persistStep(false)} disabled={saving}>
              {saving ? <Loader2 style={{ width: "16px", height: "16px" }} className="animate-spin" /> : <Save style={{ width: "16px", height: "16px" }} />}
              Save
            </WizardSecondaryButton>
          )}
          {stepIndex < STEPS.length - 1 ? (
            <WizardPrimaryButton onClick={() => persistStep(true)} disabled={saving || stepIsReadOnly}>
              Save & continue
              <ChevronRight style={{ width: "16px", height: "16px" }} />
            </WizardPrimaryButton>
          ) : (
            <WizardAccentButton onClick={handleComplete} disabled={completing || stepIsReadOnly}>
              {completing ? <Loader2 style={{ width: "16px", height: "16px" }} className="animate-spin" /> : <PartyPopper style={{ width: "16px", height: "16px" }} />}
              Complete onboarding
            </WizardAccentButton>
          )}
        </div>
      </div>
    </div>
  );
}

// --- Button helpers -----------------------------------------------------

function WizardSecondaryButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "40px",
        padding: "0 16px",
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface-muted)" : "var(--color-canvas)",
        color: "var(--color-body)",
        fontSize: "13px",
        fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function WizardPrimaryButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
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
        background: disabled ? "var(--color-surface-muted)" : hov ? "#444" : "var(--color-border-strong)",
        color: disabled ? "var(--color-muted)" : "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 700,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function WizardAccentButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "40px",
        padding: "0 20px",
        borderRadius: "4px",
        border: "none",
        background: disabled ? "var(--color-surface-muted)" : hov ? "#e64600" : "var(--color-accent)",
        color: disabled ? "var(--color-muted)" : "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 700,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function WizardDangerButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
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
        border: "1px solid rgba(255,86,48,0.4)",
        background: hov ? "rgba(255,86,48,0.08)" : "transparent",
        color: "#B71D18",
        fontSize: "13px",
        fontWeight: 600,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

// --- Step components ----------------------------------------------------

function OrganizationStep({
  value,
  onChange,
  readOnly,
}: {
  value: OrgStepData;
  onChange: (v: OrgStepData) => void;
  readOnly: boolean;
}) {
  return (
    <div className="space-y-4">
      <h3 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-ink)" }}>Organization</h3>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Legal name *">
          <input
            value={value.name}
            onChange={(e) => onChange({ ...value, name: e.target.value })}
            readOnly={readOnly}
            style={inputStyle}
            placeholder="e.g. Acme Bank Ltd"
          />
        </Field>
        <Field label="Industry">
          <input
            value={value.industry}
            onChange={(e) => onChange({ ...value, industry: e.target.value })}
            readOnly={readOnly}
            style={inputStyle}
            placeholder="e.g. finance, healthcare, retail"
          />
        </Field>
        <Field label="Primary domain">
          <input
            value={value.primary_domain}
            onChange={(e) => onChange({ ...value, primary_domain: e.target.value })}
            readOnly={readOnly}
            style={{ ...inputStyle, fontFamily: "monospace" }}
            placeholder="acme-bank.com"
          />
        </Field>
        <Field label="Keywords (comma separated)">
          <input
            value={value.keywords}
            onChange={(e) => onChange({ ...value, keywords: e.target.value })}
            readOnly={readOnly}
            style={inputStyle}
            placeholder="acme, retail-bank, mortgages"
          />
        </Field>
      </div>
      <Field label="Notes">
        <textarea
          value={value.notes}
          onChange={(e) => onChange({ ...value, notes: e.target.value })}
          readOnly={readOnly}
          rows={3}
          style={{
            width: "100%",
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
            padding: "8px 12px",
            fontSize: "14px",
            outline: "none",
            resize: "none",
          }}
        />
      </Field>
    </div>
  );
}

function AssetTableStep({
  title,
  allowedTypes,
  value,
  onChange,
  readOnly,
}: {
  title: string;
  allowedTypes: AssetTypeName[];
  value: AssetStepData;
  onChange: (v: AssetStepData) => void;
  readOnly: boolean;
}) {
  function update(idx: number, patch: Partial<AssetEntry>) {
    onChange({
      assets: value.assets.map((a, i) => (i === idx ? { ...a, ...patch } : a)),
    });
  }
  function remove(idx: number) {
    onChange({ assets: value.assets.filter((_, i) => i !== idx) });
  }
  function add() {
    onChange({ assets: [...value.assets, defaultEntry(allowedTypes[0])] });
  }

  return (
    <div className="space-y-4">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h3 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-ink)" }}>{title}</h3>
        {!readOnly && (
          <AddEntryButton onClick={add} />
        )}
      </div>

      {value.assets.length === 0 ? (
        <div style={{ borderRadius: "5px", border: "2px dashed var(--color-border)", padding: "32px 24px", textAlign: "center", fontSize: "13px", color: "var(--color-muted)" }}>
          No entries yet. Click <span style={{ fontWeight: 600 }}>Add entry</span> to start.
        </div>
      ) : (
        <div className="space-y-2">
          {value.assets.map((a, idx) => (
            <div
              key={idx}
              style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-surface)", padding: "12px", display: "grid", gridTemplateColumns: "repeat(12, 1fr)", gap: "12px", alignItems: "start" }}
            >
              <div style={{ gridColumn: "span 2" }}>
                <label style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)" }}>Type</label>
                <div style={{ marginTop: "4px" }}>
                  <ThemedSelect
                    value={a.asset_type}
                    onChange={(v) => update(idx, { asset_type: v as AssetTypeName })}
                    ariaLabel="Asset type"
                    disabled={readOnly}
                    options={allowedTypes.map((t) => ({ value: t, label: t }))}
                    style={{ width: "100%", height: "36px" }}
                  />
                </div>
              </div>
              <div style={{ gridColumn: "span 4" }}>
                <label style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)" }}>Value</label>
                <input
                  value={a.value}
                  onChange={(e) => update(idx, { value: e.target.value })}
                  readOnly={readOnly}
                  style={{ ...smallInputStyle, fontFamily: "monospace", marginTop: "4px" }}
                  placeholder={placeholderForType(a.asset_type)}
                />
              </div>
              <div style={{ gridColumn: "span 2" }}>
                <label style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)" }}>Criticality</label>
                <div style={{ marginTop: "4px" }}>
                  <ThemedSelect
                    value={a.criticality}
                    onChange={(v) => update(idx, { criticality: v as AssetCriticalityLevel })}
                    ariaLabel="Criticality"
                    disabled={readOnly}
                    options={CRITICALITIES.map((c) => ({ value: c, label: c }))}
                    style={{ width: "100%", height: "36px" }}
                  />
                </div>
              </div>
              <div style={{ gridColumn: "span 3" }}>
                <label style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)" }}>Tags (comma)</label>
                <input
                  value={a.tags}
                  onChange={(e) => update(idx, { tags: e.target.value })}
                  readOnly={readOnly}
                  style={{ ...smallInputStyle, marginTop: "4px" }}
                  placeholder="public, prod"
                />
              </div>
              <div style={{ gridColumn: "span 1", display: "flex", alignItems: "flex-end", justifyContent: "flex-end", height: "100%" }}>
                {!readOnly && (
                  <RemoveEntryButton onClick={() => remove(idx)} />
                )}
              </div>
              <div style={{ gridColumn: "span 12" }}>
                <details>
                  <summary style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-body)", cursor: "pointer" }}>
                    Advanced details (JSON)
                  </summary>
                  <textarea
                    value={a.details}
                    onChange={(e) => update(idx, { details: e.target.value })}
                    readOnly={readOnly}
                    rows={3}
                    style={{
                      marginTop: "8px",
                      width: "100%",
                      borderRadius: "4px",
                      border: "1px solid var(--color-border)",
                      background: "var(--color-canvas)",
                      color: "var(--color-ink)",
                      padding: "8px",
                      fontSize: "12px",
                      fontFamily: "monospace",
                      outline: "none",
                      resize: "none",
                    }}
                    placeholder={detailsPlaceholderForType(a.asset_type)}
                  />
                </details>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AddEntryButton({ onClick }: { onClick: () => void }) {
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
        height: "36px",
        padding: "0 12px",
        borderRadius: "4px",
        border: "none",
        background: hov ? "#444" : "var(--color-border-strong)",
        color: "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 600,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <Plus style={{ width: "16px", height: "16px" }} />
      Add entry
    </button>
  );
}

function RemoveEntryButton({ onClick }: { onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      aria-label="Remove"
      style={{
        width: "36px",
        height: "36px",
        borderRadius: "4px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        border: "none",
        background: hov ? "rgba(255,86,48,0.1)" : "transparent",
        color: hov ? "#FF5630" : "var(--color-muted)",
        cursor: "pointer",
        transition: "background 0.15s, color 0.15s",
      }}
    >
      <Trash2 style={{ width: "16px", height: "16px" }} />
    </button>
  );
}

function ReviewStepView({
  wizard,
  onChange,
  readOnly,
}: {
  wizard: WizardState;
  onChange: (v: ReviewStepData) => void;
  readOnly: boolean;
}) {
  const counts = {
    infra: wizard.infra.assets.length,
    people: wizard.people_and_brand.assets.length,
    vendors: wizard.vendors.assets.length,
  };
  const total = counts.infra + counts.people + counts.vendors;

  function toggleKind(kind: DiscoveryJobKindName) {
    const has = wizard.review.discover_kinds.includes(kind);
    const next = has
      ? wizard.review.discover_kinds.filter((k) => k !== kind)
      : [...wizard.review.discover_kinds, kind];
    onChange({ ...wizard.review, discover_kinds: next });
  }

  return (
    <div className="space-y-6">
      <h3 style={{ fontSize: "16px", fontWeight: 700, color: "var(--color-ink)" }}>Review</h3>

      <div className="grid grid-cols-4 gap-3">
        <Stat label="Organization" value={wizard.organization.name || "—"} mono />
        <Stat label="Infra assets" value={String(counts.infra)} />
        <Stat label="People / Brand" value={String(counts.people)} />
        <Stat label="Vendors" value={String(counts.vendors)} />
      </div>

      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-surface)", padding: "16px" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={wizard.review.enable_auto_discovery}
            onChange={(e) =>
              onChange({ ...wizard.review, enable_auto_discovery: e.target.checked })
            }
            disabled={readOnly}
            style={{ width: "16px", height: "16px", accentColor: "var(--color-accent)" }}
          />
          <div>
            <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--color-ink)" }}>Enable auto-discovery</div>
            <div style={{ fontSize: "12px", color: "var(--color-muted)" }}>
              Queues background jobs to expand the asset registry from your seed entries.
              Phase 1 EASM workers consume this queue.
            </div>
          </div>
        </label>

        {wizard.review.enable_auto_discovery && (
          <div style={{ marginTop: "16px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
            {DISCOVERY_KINDS.map((d) => {
              const checked = wizard.review.discover_kinds.includes(d.kind);
              return (
                <DiscoveryKindCard
                  key={d.kind}
                  d={d}
                  checked={checked}
                  readOnly={readOnly}
                  onToggle={() => toggleKind(d.kind)}
                />
              );
            })}
          </div>
        )}
      </div>

      {total === 0 && (
        <div style={{ borderRadius: "5px", border: "1px solid rgba(255,171,0,0.4)", background: "rgba(255,171,0,0.08)", padding: "12px 16px", fontSize: "13px", color: "#B76E00" }}>
          You haven&apos;t added any assets yet. Onboarding will create the organization but no
          monitoring targets — you can add them later.
        </div>
      )}
    </div>
  );
}

function DiscoveryKindCard({
  d,
  checked,
  readOnly,
  onToggle,
}: {
  d: { kind: DiscoveryJobKindName; label: string; helper: string };
  checked: boolean;
  readOnly: boolean;
  onToggle: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <label
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        borderRadius: "5px",
        border: checked ? "1px solid var(--color-accent)" : hov ? "1px solid var(--color-border-strong)" : "1px solid var(--color-border)",
        background: checked ? "rgba(255,79,0,0.05)" : "var(--color-canvas)",
        padding: "12px",
        cursor: "pointer",
        transition: "border-color 0.15s, background 0.15s",
        display: "block",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          disabled={readOnly}
          style={{ marginTop: "2px", width: "16px", height: "16px", accentColor: "var(--color-accent)" }}
        />
        <div>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>{d.label}</div>
          <div style={{ fontSize: "11px", color: "var(--color-muted)" }}>{d.helper}</div>
        </div>
      </div>
    </label>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)", display: "block", marginBottom: "4px" }}>
        {label}
      </label>
      <div style={{ marginTop: "4px" }}>{children}</div>
    </div>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-surface)", padding: "12px" }}>
      <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--color-muted)" }}>{label}</div>
      <div style={{ marginTop: "4px", fontSize: "16px", fontWeight: 700, color: "var(--color-ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: mono ? "monospace" : undefined }}>
        {value}
      </div>
    </div>
  );
}

function placeholderForType(t: AssetTypeName): string {
  switch (t) {
    case "domain":
    case "email_domain":
      return "example.com";
    case "subdomain":
      return "api.example.com";
    case "ip_address":
      return "203.0.113.42";
    case "ip_range":
      return "10.0.0.0/24";
    case "service":
      return "example.com:443";
    case "executive":
      return "Krishna Iyer";
    case "brand":
      return "Argus";
    case "mobile_app":
      return "com.gaigentic.argus";
    case "social_handle":
      return "twitter:argus_official";
    case "vendor":
      return "Acme Cloud Inc";
    case "code_repository":
      return "github:gaigenticai/argus";
    case "cloud_account":
      return "aws:123456789012";
    default:
      return "";
  }
}

function detailsPlaceholderForType(t: AssetTypeName): string {
  switch (t) {
    case "subdomain":
      return '{"parent_domain":"example.com"}';
    case "ip_range":
      return '{"cidr":"10.0.0.0/24","asn":12345}';
    case "service":
      return '{"host":"example.com","port":443,"service_name":"https"}';
    case "email_domain":
      return '{"domain":"example.com","dmarc_policy":"reject","dmarc_pct":100}';
    case "executive":
      return '{"full_name":"Krishna Iyer","title":"CEO","emails":["k@example.com"]}';
    case "brand":
      return '{"name":"Argus","keywords":["argus","gaigentic"]}';
    case "mobile_app":
      return '{"app_name":"Argus","bundle_id":"com.gaigentic.argus"}';
    case "social_handle":
      return '{"platform":"twitter","handle":"argus_official"}';
    case "vendor":
      return '{"legal_name":"Acme Cloud Inc","primary_domain":"acme-cloud.example","relationship_type":"saas"}';
    case "code_repository":
      return '{"provider":"github","org_or_user":"gaigenticai","is_private":false}';
    case "cloud_account":
      return '{"provider":"aws","account_id":"123456789012"}';
    default:
      return "";
  }
}
