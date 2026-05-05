"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import {
  User,
  Users,
  Key,
  ScrollText,
  RefreshCw,
  Plus,
  X,
  Copy,
  Check,
  Trash2,
  Globe,
  Globe2,
  Plug,
  ExternalLink,
  Loader2,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  Radio,
  AtSign,
  Lightbulb,
  Eye,
  EyeOff,
  KeyRound,
  Wrench,
  AlertTriangle,
  Info,
  CircleSlash,
  Search,
  Layers,
} from "lucide-react";
import { DomainRow, AddDomainForm } from "@/components/shared/scope-verification-gate";
import Link from "next/link";
import {
  api,
  type UserResponse,
  type APIKeyResponse,
  type APIKeyCreatedResponse,
  type AuditLogEntry,
  type OssToolState,
  type OssPreflight,
  type OrgDomainListItem,
  type MonitoredSourcesResponse,
  type TelegramChannelCatalogEntry,
  type ServiceInventoryEntry,
  type ServiceInventoryResponse,
  type Org,
  type TriageRunSummary,
  type P3ConnectorGroup,
  type ConnectorRow,
  type ConnectorHealth,
} from "@/lib/api";
import { useAuth } from "@/components/auth/auth-provider";
import { useLocale } from "@/components/locale-provider";
import { useToast } from "@/components/shared/toast";
import { formatDate } from "@/lib/utils";
import { Select as ThemedSelect } from "@/components/shared/select";

const TABS: { id: string; label: string; icon: typeof User; adminOnly?: boolean }[] = [
  { id: "profile", label: "Profile", icon: User },
  { id: "domains", label: "Domains", icon: Globe2, adminOnly: true },
  { id: "tech-stack", label: "Tech Stack", icon: Layers, adminOnly: true },
  { id: "monitoring", label: "Monitoring", icon: Radio, adminOnly: true },
  // Services is the single surface for both OSS install actions
  // (self-hosted rows) and SaaS API-key entry (paid rows). The old
  // OSS Stack and Integrations tabs were both folded in here.
  { id: "services", label: "Services", icon: Wrench, adminOnly: true },
  { id: "users", label: "Users", icon: Users, adminOnly: true },
  { id: "apikeys", label: "API Keys", icon: Key },
  { id: "locale", label: "Locale", icon: Globe, adminOnly: true },
  // OSS Stack tab merged into Services — self-hosted rows in the
  // Service Inventory now expose the same inline Install / preflight
  // actions that used to live on a separate tab.
  { id: "audit", label: "Audit Log", icon: ScrollText, adminOnly: true },
];

type TabId = "profile" | "domains" | "tech-stack" | "monitoring" | "services" | "users" | "apikeys" | "locale" | "audit";

const AUDIT_ACTIONS = [
  "all",
  "login",
  "logout",
  "login_failed",
  "user_create",
  "user_update",
  "user_delete",
  "alert_update",
  "crawler_trigger",
  "crawler_source_create",
  "crawler_source_update",
  "crawler_source_delete",
  "api_key_create",
  "api_key_revoke",
  "report_generate",
  "data_export",
  "settings_update",
];

const USER_ROLES = ["admin", "analyst", "viewer"];

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
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

export default function SettingsPage() {
  const { user } = useAuth();
  const search = useSearchParams();
  // Deep-linkable tab: ``/settings?tab=monitoring`` lands directly on
  // the Monitoring tab. Used by the onboarding done-page CTA.
  const initialTab: TabId = ((): TabId => {
    const requested = search?.get("tab");
    const allowed: TabId[] = [
      "profile", "domains", "tech-stack", "monitoring", "services", "users", "apikeys", "locale", "audit",
    ];
    if (requested && (allowed as string[]).includes(requested)) return requested as TabId;
    // Legacy ?tab=oss and ?tab=integrations deep-links land on Services
    // since both tabs were merged in; install actions and key entry
    // live inline on Service Inventory rows now.
    if (requested === "oss" || requested === "integrations") return "services";
    return "profile";
  })();
  const [tab, setTab] = useState<TabId>(initialTab);

  const isAdmin = user?.role === "admin";
  const availableTabs = TABS.filter((t) => !t.adminOnly || isAdmin);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Settings</h2>
        <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          Manage your account, users, API keys, and audit logs
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-0" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {availableTabs.map((t) => {
          const Icon = t.icon;
          const isActive = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id as TabId)}
              className="flex items-center gap-2 px-4 py-3 text-[13px] font-semibold transition-colors"
              style={{
                color: isActive ? "var(--color-accent)" : "var(--color-muted)",
                borderBottom: "none",
                boxShadow: isActive ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
                background: "transparent",
              }}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      {tab === "profile" && <ProfileTab />}
      {tab === "domains" && isAdmin && <DomainsTab />}
      {tab === "tech-stack" && isAdmin && <TechStackTab />}
      {tab === "monitoring" && isAdmin && <MonitoringTab />}
      {tab === "services" && isAdmin && <ServicesTab />}
      {tab === "users" && isAdmin && <UsersTab />}
      {tab === "apikeys" && <APIKeysTab />}
      {tab === "locale" && isAdmin && <LocaleTab />}
      {tab === "audit" && isAdmin && <AuditTab />}
    </div>
  );
}

/* ── Domains Tab (Admin) — extend monitoring scope by adding more domains.
 *    Reuses DomainRow + AddDomainForm primitives from the verification gate
 *    so the experience is identical whether the operator is gated or not. */

const ORG_KEY = "argus_org_id";

function DomainsTab() {
  const { toast } = useToast();
  const [orgId, setOrgId] = useState<string>("");
  const [domains, setDomains] = useState<OrgDomainListItem[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setOrgId(window.localStorage.getItem(ORG_KEY) || "");
    function handler(e: Event) {
      const detail = (e as CustomEvent<{ orgId: string }>).detail;
      setOrgId(detail?.orgId || "");
    }
    window.addEventListener("argus:org-changed", handler as EventListener);
    return () => window.removeEventListener("argus:org-changed", handler as EventListener);
  }, []);

  const refresh = useCallback(async () => {
    if (!orgId) {
      setDomains([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const list = await api.orgDomains.list(orgId);
      setDomains(list);
      window.dispatchEvent(new CustomEvent("argus:domains-changed"));
    } catch (err) {
      toast("error", `Couldn't load domains: ${(err as Error).message}`);
      setDomains([]);
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => { void refresh(); }, [refresh]);

  if (!orgId) {
    return (
      <div
        className="p-6 text-[13px]"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
          color: "var(--color-muted)",
        }}
      >
        No organisation selected. Pick one in the header to manage its domains.
      </div>
    );
  }

  const verifiedCount = (domains ?? []).filter((d) => d.verification_status === "verified").length;
  const totalCount = (domains ?? []).length;

  return (
    <div
      className="p-6 space-y-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 8,
      }}
    >
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-[16px] font-semibold" style={{ color: "var(--color-ink)" }}>
            Identity &amp; monitored domains
          </h2>
          <p className="text-[12px] mt-1 max-w-[680px]" style={{ color: "var(--color-muted)" }}>
            The <strong style={{ color: "var(--color-body)" }}>primary domain</strong>{" "}
            is your organisation&apos;s identity anchor — the only thing
            Marsad can cryptographically prove you control. Every alert,
            risk score, dark-web mention, and brand action is attributed
            to <em>this domain&apos;s owner</em>, not the org name (which
            is just a label). Add additional domains (subsidiaries,
            acquired brands, regional sites) to extend the same identity
            across more surface.
          </p>
        </div>
        <div
          className="inline-flex items-center gap-2 px-3 py-1.5 text-[12px]"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: 5,
            color: "var(--color-body)",
          }}
        >
          <ShieldCheck className="w-3.5 h-3.5" style={{ color: "var(--color-success)" }} />
          <strong>{verifiedCount}</strong> of <strong>{totalCount}</strong> proven
        </div>
      </div>

      {loading && domains === null ? (
        <div
          className="px-4 py-8 text-[13px] text-center"
          style={{ color: "var(--color-muted)" }}
        >
          <Loader2 className="w-4 h-4 animate-spin inline mr-1" aria-hidden /> Loading domains…
        </div>
      ) : (
        <div className="space-y-3">
          {(domains ?? []).map((d) => (
            <DomainRow
              key={d.domain}
              orgId={orgId}
              domain={d}
              canRemove={(domains ?? []).length > 1}
              onChanged={refresh}
            />
          ))}
          {(domains ?? []).length === 0 && (
            <div
              className="px-4 py-6 text-[13px] text-center"
              style={{
                background: "var(--color-surface)",
                border: "1px dashed var(--color-border)",
                borderRadius: 4,
                color: "var(--color-muted)",
              }}
            >
              No domains yet. Add the first one below to start monitoring.
            </div>
          )}
          <AddDomainForm orgId={orgId} onAdded={refresh} />
        </div>
      )}

      <div
        className="px-3 py-2.5 text-[11.5px] space-y-2"
        style={{
          background: "var(--color-surface-muted)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
        }}
      >
        <div>
          <strong style={{ color: "var(--color-body)" }}>Why a domain proves identity:</strong>{" "}
          Anyone can type &ldquo;Acme Bank&rdquo; into a sign-up form. Only the
          true owner of <code style={{ fontFamily: "var(--font-mono, monospace)" }}>acmebank.com</code>{" "}
          can publish a DNS TXT record on it. That&apos;s why every Marsad
          finding — IOC matches, leaked credentials, lookalike domains, dark-web
          chatter — is keyed to the verified domain, not the free-text name.
          Without a verified primary, we cannot safely show you results: a
          competitor could otherwise sign up as you and pull your intel.
        </div>
        <div>
          <strong style={{ color: "var(--color-body)" }}>How verification works:</strong>{" "}
          Marsad mints a 24h challenge token, you publish it as a TXT record at{" "}
          <code style={{ fontFamily: "var(--font-mono, monospace)" }}>
            _marsad-challenge.&lt;domain&gt;
          </code>
          , and three independent DoH resolvers (Cloudflare, Google, Quad9) must
          agree (2-of-3 quorum). Until verified, EASM scans skip the domain to
          prevent DDoS-amplification abuse and the dashboard blurs results.
        </div>
      </div>
    </div>
  );
}


/* ── OssInstallStrip — inline Install action for self-hosted rows ──
 *
 *  Replaces the standalone OSS Stack tab. Renders inside an expanded
 *  ServiceEntry row when ``oss_install_name`` is set, hitting
 *  /oss-tools/install for the named tool. Disabled when the installer
 *  preflight reports the docker.sock mount or admin gate isn't ready.
 */

function OssInstallStrip({
  toolName,
  state,
  busy,
  preflightReady,
  onInstall,
}: {
  toolName: string;
  state: OssToolState | undefined;
  busy: boolean;
  preflightReady: boolean;
  onInstall: () => void;
}) {
  const isInstalled = state?.state === "installed";
  const isInstalling = busy || state?.state === "installing" || state?.state === "pending";
  const isFailed = state?.state === "failed";
  return (
    <div
      className="px-3 py-2 flex items-center gap-3 flex-wrap"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <StateBadge state={state?.state ?? "disabled"} />
      <code className="text-[11px]" style={{ color: "var(--color-muted)" }}>
        oss-tools/{toolName}
      </code>
      {isFailed && state?.error_message && (
        <span
          className="text-[11px] truncate"
          style={{ color: "var(--color-error-dark)", maxWidth: 360 }}
          title={state.error_message ?? ""}
        >
          {state.error_message}
        </span>
      )}
      <button
        type="button"
        onClick={onInstall}
        disabled={isInstalling || !preflightReady}
        className="ml-auto inline-flex items-center gap-1.5 text-[12px] font-semibold px-3 py-1.5"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-ink)",
          cursor: isInstalling || !preflightReady ? "not-allowed" : "pointer",
          opacity: isInstalling || !preflightReady ? 0.55 : 1,
        }}
        title={!preflightReady ? "OSS installer preflight not ready — see banner above" : ""}
      >
        {isInstalling ? (
          <Loader2 className="w-3 h-3 animate-spin" aria-hidden />
        ) : (
          <RefreshCw className="w-3 h-3" aria-hidden />
        )}
        {isInstalled ? "Reinstall" : "Install"}
      </button>
    </div>
  );
}



function StateBadge({ state }: { state: string }) {
  const cls = "inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5";
  const radius = "999px";
  if (state === "installed") {
    return (
      <span className={cls} style={{
        background: "rgba(16,185,129,0.08)",
        color: "var(--color-success-dark)",
        border: "1px solid rgba(16,185,129,0.25)", borderRadius: radius,
      }}>
        <CheckCircle2 className="w-2.5 h-2.5" aria-hidden /> Installed
      </span>
    );
  }
  if (state === "installing" || state === "pending") {
    return (
      <span className={cls} style={{
        background: "rgba(255,79,0,0.06)",
        color: "var(--color-accent)",
        border: "1px solid rgba(255,79,0,0.25)", borderRadius: radius,
      }}>
        <Loader2 className="w-2.5 h-2.5 animate-spin" aria-hidden /> Installing
      </span>
    );
  }
  if (state === "failed") {
    return (
      <span className={cls} style={{
        background: "rgba(239,68,68,0.06)",
        color: "var(--color-error-dark)",
        border: "1px solid rgba(239,68,68,0.25)", borderRadius: radius,
      }}>
        <XCircle className="w-2.5 h-2.5" aria-hidden /> Failed
      </span>
    );
  }
  return (
    <span className={cls} style={{
      background: "var(--color-surface-muted)",
      color: "var(--color-muted)",
      border: "1px solid var(--color-border)", borderRadius: radius,
    }}>
      Not installed
    </span>
  );
}

/* ── Locale Tab (P1 #1.2 — Hijri / Asia/Riyadh) ─────────────────────── */

function LocaleTab() {
  const { locale, supported, setLocale } = useLocale();
  const { toast } = useToast();
  const [saving, setSaving] = useState(false);

  async function save(next: { timeZone?: string; calendar?: "gregorian" | "islamic-umalqura" }) {
    setSaving(true);
    try {
      await setLocale(next);
      toast("success", "Locale updated");
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to update locale");
    } finally {
      setSaving(false);
    }
  }

  // Live preview using a fixed reference date so analysts can compare formats.
  const preview = new Date("2026-05-01T15:30:00.000Z");
  const fmt = (cal: string, tz: string) => {
    try {
      return preview.toLocaleString(`en-u-ca-${cal}`, {
        month: "short", day: "numeric", year: "numeric",
        hour: "2-digit", minute: "2-digit", timeZone: tz,
      });
    } catch {
      return preview.toISOString();
    }
  };

  return (
    <div
      className="p-6 space-y-6"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: "8px",
      }}
    >
      <div>
        <h2 className="text-[16px] font-semibold" style={{ color: "var(--color-ink)" }}>
          Tenant locale
        </h2>
        <p className="text-[12px] mt-1" style={{ color: "var(--color-muted)" }}>
          Sets the timezone and calendar used across the dashboard, exports, and PDF reports.
          Defaults to <strong>Asia/Riyadh</strong> + Gregorian.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label
            className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
            style={{ color: "var(--color-muted)" }}
          >
            Timezone
          </label>
          <ThemedSelect
            value={locale.timeZone}
            onChange={(v) => save({ timeZone: v })}
            options={supported.timezones.map((tz) => ({
              value: tz,
              label: `${tz} — ${fmt(locale.calendar, tz)}`,
            }))}
            disabled={saving}
            ariaLabel="Timezone"
          />
        </div>
        <div>
          <label
            className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
            style={{ color: "var(--color-muted)" }}
          >
            Calendar
          </label>
          <ThemedSelect
            value={locale.calendar}
            onChange={(v) => save({ calendar: v as "gregorian" | "islamic-umalqura" })}
            options={supported.calendars.map((cal) => ({
              value: cal,
              label: `${cal === "islamic-umalqura" ? "Hijri (Umm al-Qura)" : "Gregorian"} — ${fmt(cal, locale.timeZone)}`,
            }))}
            disabled={saving}
            ariaLabel="Calendar"
          />
        </div>
      </div>

      <div
        className="p-3"
        style={{
          background: "var(--color-canvas-subtle)",
          border: "1px solid var(--color-border)",
          borderRadius: "6px",
        }}
      >
        <div
          className="text-[11px] font-semibold uppercase tracking-[0.07em] mb-1"
          style={{ color: "var(--color-muted)" }}
        >
          Reference timestamp (2026-05-01T15:30 UTC)
        </div>
        <div className="text-[13px] font-mono" style={{ color: "var(--color-ink)" }}>
          {fmt(locale.calendar, locale.timeZone)}
        </div>
      </div>
    </div>
  );
}

/* ── Profile Tab ─────────────────────────────────────── */

function ProfileTab() {
  const { user, refreshUser } = useAuth();
  const { toast } = useToast();
  const [displayName, setDisplayName] = useState(user?.display_name || "");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (user) setDisplayName(user.display_name);
  }, [user]);

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const data: Record<string, string> = {};
      if (displayName !== user?.display_name) data.display_name = displayName;
      if (newPassword) {
        data.current_password = currentPassword;
        data.new_password = newPassword;
      }
      if (Object.keys(data).length === 0) {
        toast("info", "No changes to save");
        setSaving(false);
        return;
      }
      await api.updateMe(data);
      await refreshUser();
      setCurrentPassword("");
      setNewPassword("");
      toast("success", "Profile updated");
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to update profile");
    }
    setSaving(false);
  }

  if (!user) return null;

  return (
    <div className="max-w-lg">
      <div
        className="p-6 space-y-6"
        style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}
      >
        <div>
          <h3 className="text-[15px] font-semibold mb-4" style={{ color: "var(--color-ink)" }}>Account Details</h3>
          <div className="space-y-3">
            {[
              { label: "Email", value: user.email },
              { label: "Username", value: user.username },
              { label: "Role", value: user.role },
              { label: "Member since", value: formatDate(user.created_at) },
              ...(user.last_login_at ? [{ label: "Last login", value: formatDate(user.last_login_at) }] : []),
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between text-[13px]">
                <span style={{ color: "var(--color-muted)" }}>{label}</span>
                <span className="font-medium capitalize" style={{ color: "var(--color-body)" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        <hr style={{ borderColor: "var(--color-border)" }} />

        <form onSubmit={handleUpdateProfile} className="space-y-4">
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>Update Profile</h3>
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>Display Name</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full h-10 px-3 text-[13px] outline-none"
              style={inputStyle}
            />
          </div>

          <hr style={{ borderColor: "var(--color-border)" }} />

          <h4 className="text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>Change Password</h4>
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full h-10 px-3 text-[13px] outline-none"
              style={inputStyle}
              autoComplete="current-password"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full h-10 px-3 text-[13px] outline-none"
              style={inputStyle}
              autoComplete="new-password"
            />
          </div>
          <button
            type="submit"
            disabled={saving}
            className="h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={btnPrimary}
          >
            {saving ? "Saving..." : "Save Changes"}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ── Monitoring Tab (Admin) — Telegram channels + breach-check emails.
 *
 *  The two operator-curated lists that drive scope-sensitive
 *  harvesters. Until this tab existed, the only way to seed them was
 *  by hand-editing JSONB on Organization.settings — which meant nobody
 *  did it, which meant the workers silently skipped the org. The whole
 *  point of this surface is "make it obvious what we're watching, and
 *  let the operator change it without touching SQL." */

function MonitoringTab() {
  const { toast } = useToast();
  const [data, setData] = useState<MonitoredSourcesResponse | null>(null);
  const [selectedChannels, setSelectedChannels] = useState<Set<string>>(new Set());
  const [emails, setEmails] = useState<string[]>([]);
  const [emailDraft, setEmailDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [filter, setFilter] = useState("");

  const load = useCallback(async () => {
    try {
      const result = await api.monitoredSources.get();
      setData(result);
      setSelectedChannels(new Set(result.telegram_channels));
      setEmails(result.breach_emails);
    } catch (err) {
      toast("error", `Couldn't load monitoring config: ${(err as Error).message}`);
    }
  }, [toast]);

  useEffect(() => { void load(); }, [load]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const next = await api.monitoredSources.update({
        telegram_channels: Array.from(selectedChannels),
        breach_emails: emails,
      });
      setData(next);
      setSelectedChannels(new Set(next.telegram_channels));
      setEmails(next.breach_emails);
      toast("success", "Monitoring scope saved");
    } catch (err) {
      toast("error", `Save failed: ${(err as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  if (!data) {
    return (
      <div
        className="p-6 text-[13px] flex items-center gap-2"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
          color: "var(--color-muted)",
        }}
      >
        <Loader2 className="w-4 h-4 animate-spin" /> Loading monitoring config…
      </div>
    );
  }

  const toggleChannel = (handle: string) => {
    setSelectedChannels((prev) => {
      const next = new Set(prev);
      if (next.has(handle)) next.delete(handle);
      else next.add(handle);
      return next;
    });
  };

  const filterLower = filter.trim().toLowerCase();
  const filteredCatalog = data.catalog.telegram_channels.filter((c) => {
    if (!filterLower) return true;
    return (
      c.handle.toLowerCase().includes(filterLower) ||
      c.cluster.toLowerCase().includes(filterLower) ||
      c.rationale.toLowerCase().includes(filterLower) ||
      (c.region_focus || []).some((r) => r.toLowerCase().includes(filterLower))
    );
  });

  const handleAddEmail = () => {
    const v = emailDraft.trim().toLowerCase();
    if (!v) return;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) {
      toast("error", `Not a valid email: ${v}`);
      return;
    }
    if (emails.includes(v)) {
      toast("info", "Already in the list");
      return;
    }
    setEmails([...emails, v]);
    setEmailDraft("");
  };

  const handleRemoveEmail = (e: string) => {
    setEmails(emails.filter((x) => x !== e));
  };

  const handleAddSuggested = () => {
    const missing = data.catalog.suggested_emails.filter((s) => !emails.includes(s));
    if (missing.length === 0) {
      toast("info", "All suggested emails are already in your list");
      return;
    }
    setEmails([...emails, ...missing]);
  };

  return (
    <div className="space-y-6">
      <div
        className="px-4 py-3 text-[12.5px]"
        style={{
          background: "rgba(255,79,0,0.04)",
          border: "1px solid rgba(255,79,0,0.2)",
          borderRadius: 5,
          color: "var(--color-body)",
        }}
      >
        <strong style={{ color: "var(--color-ink)" }}>Why this matters:</strong>{" "}
        Marsad&apos;s Telegram crawler and breach-credential checker are
        only as good as the channels and emails you point them at. Empty
        lists = silent workers. Save changes here and the next worker
        tick picks them up automatically.
      </div>

      {/* ── Telegram channels ───────────────────────────────────── */}
      <div
        className="p-6 space-y-4"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
        }}
      >
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2
              className="text-[16px] font-semibold flex items-center gap-2"
              style={{ color: "var(--color-ink)" }}
            >
              <Radio className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
              Telegram channels
            </h2>
            <p
              className="text-[12px] mt-1 max-w-[680px]"
              style={{ color: "var(--color-muted)" }}
            >
              Public channels Marsad scrapes via{" "}
              <code style={{ fontFamily: "var(--font-mono, monospace)" }}>t.me/s/</code>
              {" "}for fraud, hacktivist, and ransomware-leak signal. Catalog comes from{" "}
              <code style={{ fontFamily: "var(--font-mono, monospace)" }}>
                src/integrations/telegram_collector/channels.py
              </code>
              {" "}— every entry has been seen referenced in public security-vendor reporting.
            </p>
          </div>
          <div
            className="inline-flex items-center gap-2 px-3 py-1.5 text-[12px]"
            style={{
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              borderRadius: 5,
              color: "var(--color-body)",
            }}
          >
            <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "var(--color-success)" }} />
            <strong>{selectedChannels.size}</strong> of{" "}
            <strong>{data.catalog.telegram_channels.length}</strong> selected
          </div>
        </div>

        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by handle, cluster, region (e.g. GCC, IL, ransomware-leak)…"
          className="w-full h-9 px-3 text-[13px] outline-none"
          style={{
            borderRadius: 4,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        />

        <div
          className="overflow-hidden"
          style={{ border: "1px solid var(--color-border)", borderRadius: 5 }}
        >
          {filteredCatalog.length === 0 ? (
            <div
              className="px-4 py-8 text-[13px] text-center"
              style={{ color: "var(--color-muted)" }}
            >
              No channels match the filter.
            </div>
          ) : (
            filteredCatalog.map((c) => (
              <ChannelRow
                key={c.handle}
                entry={c}
                checked={selectedChannels.has(c.handle)}
                onToggle={() => toggleChannel(c.handle)}
              />
            ))
          )}
        </div>
      </div>

      {/* ── Breach-check emails ────────────────────────────────── */}
      <div
        className="p-6 space-y-4"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
        }}
      >
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2
              className="text-[16px] font-semibold flex items-center gap-2"
              style={{ color: "var(--color-ink)" }}
            >
              <AtSign className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
              Breach-check emails
            </h2>
            <p
              className="text-[12px] mt-1 max-w-[680px]"
              style={{ color: "var(--color-muted)" }}
            >
              Addresses to query against breach corpora (HIBP, IntelX, DeHashed —
              when configured). Role-based addresses at your verified domains catch the
              widest blast radius; named exec emails catch targeted leaks.
            </p>
          </div>
          {data.catalog.suggested_emails.length > 0 && (
            <button
              type="button"
              onClick={handleAddSuggested}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-medium"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: 5,
                color: "var(--color-ink)",
                cursor: "pointer",
              }}
            >
              <Lightbulb className="w-3.5 h-3.5" />
              Add suggested ({data.catalog.suggested_emails.length})
            </button>
          )}
        </div>

        <div
          className="flex items-center gap-2"
        >
          <input
            type="email"
            value={emailDraft}
            onChange={(e) => setEmailDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleAddEmail();
              }
            }}
            placeholder="ceo@yourdomain.com"
            className="flex-1 h-9 px-3 text-[13px] outline-none font-mono"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
          />
          <button
            type="button"
            onClick={handleAddEmail}
            disabled={!emailDraft.trim()}
            className="inline-flex items-center gap-1.5 h-9 px-4 text-[13px] font-semibold"
            style={{
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
              border: "none",
              borderRadius: 4,
              cursor: emailDraft.trim() ? "pointer" : "not-allowed",
              opacity: emailDraft.trim() ? 1 : 0.5,
            }}
          >
            <Plus className="w-3.5 h-3.5" />
            Add
          </button>
        </div>

        {emails.length === 0 ? (
          <div
            className="px-4 py-6 text-[13px] text-center"
            style={{
              background: "var(--color-surface)",
              border: "1px dashed var(--color-border)",
              borderRadius: 4,
              color: "var(--color-muted)",
            }}
          >
            No emails yet. Click <strong>Add suggested</strong> above to seed
            role-based addresses from your verified domains.
          </div>
        ) : (
          <div className="space-y-1">
            {emails.map((e) => (
              <div
                key={e}
                className="flex items-center gap-2 px-3 py-2"
                style={{
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                }}
              >
                <AtSign className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-muted)" }} />
                <code
                  className="flex-1 text-[12.5px] font-mono truncate"
                  style={{ color: "var(--color-ink)" }}
                >
                  {e}
                </code>
                <button
                  type="button"
                  onClick={() => handleRemoveEmail(e)}
                  className="p-1"
                  style={{
                    background: "transparent",
                    border: "1px solid var(--color-border)",
                    borderRadius: 3,
                    color: "var(--color-error-dark)",
                    cursor: "pointer",
                  }}
                  title="Remove"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Save bar ───────────────────────────────────────────── */}
      <div
        className="flex items-center justify-end gap-3 px-4 py-3"
        style={{
          background: "var(--color-surface-muted)",
          border: "1px solid var(--color-border)",
          borderRadius: 5,
          position: "sticky",
          bottom: 0,
        }}
      >
        <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {selectedChannels.size} channels · {emails.length} emails
        </span>
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 h-9 px-4 text-[13px] font-semibold"
          style={{
            ...btnPrimary,
            opacity: saving ? 0.5 : 1,
            cursor: saving ? "not-allowed" : "pointer",
          }}
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
          Save monitoring scope
        </button>
      </div>
    </div>
  );
}

function ChannelRow({
  entry,
  checked,
  onToggle,
}: {
  entry: TelegramChannelCatalogEntry;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <label
      className="flex items-start gap-3 px-4 py-3 cursor-pointer"
      style={{
        borderTop: "1px solid var(--color-border)",
        background: checked ? "rgba(255,79,0,0.03)" : "transparent",
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        className="mt-0.5"
        style={{ accentColor: "var(--color-accent)" }}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <code
            className="text-[12.5px] font-mono font-semibold"
            style={{ color: "var(--color-ink)" }}
          >
            @{entry.handle}
          </code>
          <ClusterPill cluster={entry.cluster} />
          <LangPill lang={entry.language} />
          {entry.region_focus.map((r) => (
            <RegionPill key={r} region={r} />
          ))}
          {entry.status !== "active" && (
            <span
              className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.6px]"
              style={{
                background: "rgba(120,120,120,0.1)",
                color: "var(--color-muted)",
                borderRadius: 3,
              }}
            >
              {entry.status}
            </span>
          )}
        </div>
        <p
          className="text-[11.5px] mt-1"
          style={{ color: "var(--color-muted)" }}
        >
          {entry.rationale}
        </p>
      </div>
    </label>
  );
}

function ClusterPill({ cluster }: { cluster: string }) {
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.6px]"
      style={{
        background: "var(--color-surface-muted)",
        color: "var(--color-body)",
        border: "1px solid var(--color-border)",
        borderRadius: 3,
      }}
    >
      {cluster}
    </span>
  );
}

function LangPill({ lang }: { lang: string }) {
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono"
      style={{
        background: "rgba(0,0,0,0.05)",
        color: "var(--color-muted)",
        borderRadius: 3,
      }}
    >
      {lang}
    </span>
  );
}

function RegionPill({ region }: { region: string }) {
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold"
      style={{
        background: "rgba(34,197,94,0.08)",
        color: "var(--color-success-dark)",
        borderRadius: 3,
      }}
    >
      {region}
    </span>
  );
}

/* ── Users Tab (Admin) ──────────────────────────────── */

function UsersTab() {
  const { toast } = useToast();
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  const [newEmail, setNewEmail] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getUsers({ limit: 100 });
      setUsers(data.users);
      setTotal(data.total);
    } catch {
      toast("error", "Failed to load users");
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      await api.register({
        email: newEmail,
        username: newUsername,
        display_name: newDisplayName,
        password: newPassword,
        role: newRole,
      });
      toast("success", `User ${newUsername} created`);
      setShowCreate(false);
      setNewEmail(""); setNewUsername(""); setNewDisplayName(""); setNewPassword(""); setNewRole("viewer");
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to create user");
    }
    setCreating(false);
  }

  async function handleToggleActive(u: UserResponse) {
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      toast("success", `${u.username} ${u.is_active ? "deactivated" : "activated"}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to update user");
    }
  }

  async function handleRoleChange(u: UserResponse, role: string) {
    try {
      await api.updateUser(u.id, { role });
      toast("success", `${u.username} role updated to ${role}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to update role");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>{total} users</p>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
          <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnPrimary}>
            <Plus className="w-4 h-4" /> Add User
          </button>
        </div>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["User", "Email", "Role", "Status", "Last Login", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr
                  key={u.id}
                  className="h-[52px]"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4">
                    <div className="flex items-center gap-3">
                      <div
                        className="w-8 h-8 flex items-center justify-center text-[12px] font-bold"
                        style={{ borderRadius: "50%", background: "rgba(255,79,0,0.1)", color: "var(--color-accent)" }}
                      >
                        {u.display_name?.charAt(0)?.toUpperCase() || "U"}
                      </div>
                      <div>
                        <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{u.display_name}</div>
                        <div className="text-[11px]" style={{ color: "var(--color-muted)" }}>@{u.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>{u.email}</td>
                  <td className="px-4">
                    <ThemedSelect
                      value={u.role}
                      onChange={(v) => handleRoleChange(u, v)}
                      ariaLabel="Role"
                      options={USER_ROLES.map((r) => ({ value: r, label: r }))}
                      style={{ height: "32px", minWidth: 110 }}
                    />
                  </td>
                  <td className="px-4">
                    <span
                      className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                      style={{
                        borderRadius: "4px",
                        background: u.is_active ? "rgba(0,167,111,0.1)" : "var(--color-surface-muted)",
                        color: u.is_active ? "#007B55" : "var(--color-muted)",
                      }}
                    >
                      {u.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                    {u.last_login_at ? formatDate(u.last_login_at) : "Never"}
                  </td>
                  <td className="px-4">
                    <button
                      onClick={() => handleToggleActive(u)}
                      className="text-[12px] font-semibold transition-colors"
                      style={{ color: "var(--color-muted)" }}
                      onMouseEnter={e => (e.currentTarget.style.color = "var(--color-body)")}
                      onMouseLeave={e => (e.currentTarget.style.color = "var(--color-muted)")}
                    >
                      {u.is_active ? "Deactivate" : "Activate"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Create User Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(32,21,21,0.5)" }} onClick={() => setShowCreate(false)}>
          <div className="p-8 w-full max-w-md" style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[17px] font-semibold" style={{ color: "var(--color-ink)" }}>Create User</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 transition-opacity hover:opacity-70">
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              {[
                { label: "Email", type: "email", value: newEmail, onChange: setNewEmail },
                { label: "Username", type: "text", value: newUsername, onChange: setNewUsername },
                { label: "Display Name", type: "text", value: newDisplayName, onChange: setNewDisplayName },
                { label: "Password", type: "password", value: newPassword, onChange: setNewPassword },
              ].map(({ label, type, value, onChange }) => (
                <div key={label}>
                  <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>{label}</label>
                  <input
                    type={type}
                    required
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    className="w-full h-10 px-3 text-[13px] outline-none"
                    style={inputStyle}
                    autoComplete={type === "password" ? "new-password" : undefined}
                  />
                </div>
              ))}
              <div>
                <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>Role</label>
                <ThemedSelect
                  value={newRole}
                  onChange={setNewRole}
                  ariaLabel="Role"
                  options={USER_ROLES.map((r) => ({ value: r, label: r }))}
                  style={{ width: "100%" }}
                />
              </div>
              <div className="flex gap-2 pt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>Cancel</button>
                <button type="submit" disabled={creating} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>{creating ? "Creating..." : "Create"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── API Keys Tab ───────────────────────────────────── */

function APIKeysTab() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [keys, setKeys] = useState<APIKeyResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createdKey, setCreatedKey] = useState<APIKeyCreatedResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const data = await api.getUserApiKeys(user.id);
      setKeys(data);
    } catch {
      toast("error", "Failed to load API keys");
    }
    setLoading(false);
  }, [user, toast]);

  useEffect(() => { load(); }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!user) return;
    setCreating(true);
    try {
      const result = await api.createApiKey(user.id, { name: newKeyName });
      setCreatedKey(result);
      setNewKeyName("");
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to create API key");
    }
    setCreating(false);
  }

  async function handleRevoke(keyId: string) {
    if (!user) return;
    try {
      await api.revokeApiKey(user.id, keyId);
      toast("success", "API key revoked");
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to revoke API key");
    }
  }

  function handleCopy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>{keys.length} API keys</p>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnPrimary}>
          <Plus className="w-4 h-4" /> Create API Key
        </button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? (
          <div className="flex items-center justify-center h-[200px]">
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
          </div>
        ) : keys.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[200px]" style={{ color: "var(--color-muted)" }}>
            <Key className="w-8 h-8 mb-2" style={{ color: "var(--color-border)" }} />
            <p className="text-[13px]">No API keys yet</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Name", "Prefix", "Status", "Last Used", "Created", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr
                  key={k.id}
                  className="h-[52px]"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{k.name}</td>
                  <td className="px-4 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>{k.key_prefix}...</td>
                  <td className="px-4">
                    <span
                      className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                      style={{
                        borderRadius: "4px",
                        background: k.is_active ? "rgba(0,167,111,0.1)" : "var(--color-surface-muted)",
                        color: k.is_active ? "#007B55" : "var(--color-muted)",
                      }}
                    >
                      {k.is_active ? "Active" : "Revoked"}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                    {k.last_used_at ? formatDate(k.last_used_at) : "Never"}
                  </td>
                  <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                    {formatDate(k.created_at)}
                  </td>
                  <td className="px-4">
                    {k.is_active && (
                      <button
                        onClick={() => handleRevoke(k.id)}
                        className="flex items-center gap-1 text-[12px] font-semibold transition-colors"
                        style={{ color: "#FF5630" }}
                        onMouseEnter={e => (e.currentTarget.style.color = "#B71D18")}
                        onMouseLeave={e => (e.currentTarget.style.color = "#FF5630")}
                      >
                        <Trash2 className="w-3.5 h-3.5" /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Create API Key Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(32,21,21,0.5)" }} onClick={() => { setShowCreate(false); setCreatedKey(null); }}>
          <div className="p-8 w-full max-w-md" style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[17px] font-semibold" style={{ color: "var(--color-ink)" }}>
                {createdKey ? "API Key Created" : "Create API Key"}
              </h3>
              <button onClick={() => { setShowCreate(false); setCreatedKey(null); }} className="p-1 transition-opacity hover:opacity-70">
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>

            {createdKey ? (
              <div className="space-y-4">
                <div
                  className="p-4"
                  style={{ background: "rgba(255,171,0,0.08)", border: "1px solid rgba(255,171,0,0.3)", borderRadius: "5px" }}
                >
                  <p className="text-[13px] font-semibold mb-2" style={{ color: "#B76E00" }}>
                    Copy this key now. It will not be shown again.
                  </p>
                  <div className="flex items-center gap-2">
                    <code
                      className="flex-1 text-[13px] font-mono px-3 py-2 break-all"
                      style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "4px", color: "var(--color-ink)" }}
                    >
                      {createdKey.raw_key}
                    </code>
                    <button
                      onClick={() => handleCopy(createdKey.raw_key)}
                      className="p-2 transition-colors shrink-0"
                      style={{ borderRadius: "4px" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      {copied ? (
                        <Check className="w-4 h-4" style={{ color: "#22C55E" }} />
                      ) : (
                        <Copy className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                      )}
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => { setShowCreate(false); setCreatedKey(null); }}
                  className="w-full h-10 text-[13px] font-semibold transition-colors"
                  style={btnPrimary}
                >
                  Done
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreate} className="space-y-4">
                <div>
                  <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>Key Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. CI/CD Pipeline"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    className="w-full h-10 px-3 text-[13px] outline-none"
                    style={inputStyle}
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <button type="button" onClick={() => setShowCreate(false)} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>Cancel</button>
                  <button type="submit" disabled={creating} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>{creating ? "Creating..." : "Create"}</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Audit Log Tab (Admin) ──────────────────────────── */

function AuditTab() {
  const { toast } = useToast();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState("all");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLogs({
        action: action === "all" ? undefined : action,
        since: since || undefined,
        until: until || undefined,
        limit,
        offset,
      });
      setLogs(data.logs);
      setTotal(data.total);
    } catch {
      toast("error", "Failed to load audit logs");
    }
    setLoading(false);
  }, [action, since, until, offset, toast]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-end">
        {[
          {
            label: "Action",
            element: (
              <ThemedSelect
                value={action}
                onChange={(v) => { setAction(v); setOffset(0); }}
                ariaLabel="Audit action"
                options={AUDIT_ACTIONS.map((a) => ({ value: a, label: a === "all" ? "All actions" : a.replace(/_/g, " ") }))}
              />
            ),
          },
          {
            label: "Since",
            element: (
              <input
                type="date"
                value={since}
                onChange={(e) => { setSince(e.target.value); setOffset(0); }}
                className="h-10 px-3 text-[13px] outline-none"
                style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
              />
            ),
          },
          {
            label: "Until",
            element: (
              <input
                type="date"
                value={until}
                onChange={(e) => { setUntil(e.target.value); setOffset(0); }}
                className="h-10 px-3 text-[13px] outline-none"
                style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
              />
            ),
          },
        ].map(({ label, element }) => (
          <div key={label}>
            <label className="block text-[10px] font-semibold uppercase tracking-[0.07em] mb-1" style={{ color: "var(--color-muted)" }}>{label}</label>
            {element}
          </div>
        ))}
        <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>{total} entries</p>

      {/* Table */}
      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
            <p className="text-[13px]">No audit logs found</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Time", "Action", "Resource", "IP", "Details"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className="h-[52px]"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-body)" }}>
                    {formatDate(log.timestamp)}
                  </td>
                  <td className="px-4">
                    <span
                      className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                      style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                    >
                      {log.action.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>
                    {log.resource_type && (
                      <span style={{ color: "var(--color-muted)" }}>
                        {log.resource_type}
                        {log.resource_id && (
                          <span className="font-mono text-[11px] ml-1" style={{ color: "var(--color-muted)" }}>
                            {log.resource_id.substring(0, 8)}...
                          </span>
                        )}
                      </span>
                    )}
                  </td>
                  <td className="px-4 text-[13px] font-mono" style={{ color: "var(--color-muted)" }}>
                    {log.ip_address || "-"}
                  </td>
                  <td className="px-4 text-[12px] max-w-[200px] truncate" style={{ color: "var(--color-muted)" }}>
                    {log.details ? JSON.stringify(log.details) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>Page {currentPage} of {totalPages}</p>
          <div className="flex gap-2">
            <button onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset === 0} className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnSecondary}>Previous</button>
            <button onClick={() => setOffset(offset + limit)} disabled={offset + limit >= total} className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnSecondary}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}


/* ── Services Tab (Admin) — live inventory of every external service.
 *
 *  This is the page that answers "what's actually working in my
 *  deployment?" without grepping the codebase. Backed by
 *  /admin/service-inventory, which resolves status from feed_health,
 *  crawler_targets, integration_keys cache, env presence, binary
 *  probes, and lightweight HTTP/TCP checks. The catalog lives in
 *  src/core/service_inventory.py — adding a new external dependency
 *  to the platform should ALWAYS include adding an entry there so it
 *  shows up here. No more silently-broken integrations.
 */

// 3-state taxonomy. Every row resolves to OK / Needs key / Not installed.
// The retired buckets (Broken / Unconfigured / Disabled / Missing /
// Incomplete / Unknown) collapsed into these three; engineering detail
// lives in the per-row evidence line via `sub_reason`.
type ServiceStatusMeta = {
  label: string;
  color: string;
  bg: string;
  icon: typeof CheckCircle2;
};

const SERVICE_STATUS_META: Record<
  ServiceInventoryEntry["status"],
  ServiceStatusMeta
> = {
  ok:            { label: "OK",            color: "var(--color-success-dark)", bg: "rgba(34,197,94,0.1)",   icon: CheckCircle2 },
  needs_key:     { label: "Needs key",     color: "#B76E00",                   bg: "rgba(255,171,0,0.1)",   icon: Info },
  not_installed: { label: "Not installed", color: "var(--color-muted)",        bg: "var(--color-surface-muted)", icon: CircleSlash },
};

// Tier classification — derived client-side from the service entry's
// ``self_hosted`` flag and the human text in ``requires``. Lets the
// row header tell the operator at a glance whether they're looking at
// a 5-min free signup, a freemium SaaS, a paid-only vendor, or an
// OSS tool they need to host themselves. The catalog isn't currently
// tagged explicitly so we keyword-sniff; if we add an explicit
// ``tier`` field to ServiceEntry later this function becomes a
// one-liner.
type ServiceTier = "free" | "freemium" | "paid" | "oss";

function serviceTier(s: ServiceInventoryEntry): ServiceTier {
  if (s.self_hosted) return "oss";
  const requiresText = s.requires.join(" ").toLowerCase();
  const fullText = (requiresText + " " + (s.description || "")).toLowerCase();

  // ``requires`` is the authoritative signal — it lists the env vars
  // the operator actually has to set, with the access tier in
  // parentheses. ``description`` may mention a paid tier in passing
  // (e.g. "free key for X; paid for bulk Y") but as long as the free
  // tier covers the documented integration the row should read FREE.
  // Description-only paid mentions are weaker evidence than what's
  // listed in ``requires``.
  if (/\b(free|gratis|community)\b/.test(requiresText)) return "free";
  if (s.no_oss_substitute) return "paid";
  if (/\b(no oss substitute|enterprise|paid|byok|license)\b/.test(requiresText)) {
    return "paid";
  }
  if (/\b(free|gratis|community)\b/.test(fullText)) return "free";
  if (/\b(enterprise|paid|byok|license)\b/.test(fullText)) return "paid";
  return "freemium";
}

const TIER_PRESENTATION: Record<ServiceTier, { label: string; bg: string; color: string; help: string }> = {
  free: {
    label: "Free",
    bg: "rgba(34,197,94,0.10)",
    color: "var(--color-success-dark)",
    help: "Free signup or no key required. Typically a 5-minute registration.",
  },
  freemium: {
    label: "Freemium",
    bg: "rgba(0,187,217,0.10)",
    color: "#007B8A",
    help: "Has a free tier with rate limits or feature caps; paid plans expand quotas.",
  },
  paid: {
    label: "Paid",
    bg: "rgba(255,86,48,0.10)",
    color: "#B71D18",
    help: "Requires a paid subscription / commercial license to use.",
  },
  oss: {
    label: "OSS",
    bg: "var(--color-surface-muted)",
    color: "var(--color-body)",
    help: "Open-source software — free, but you self-host. Set the URL + token after install.",
  },
};

// Defensive lookup — if the backend ever returns a status outside the
// canonical 3-bucket taxonomy (e.g. a stale container still emitting the
// retired ``disabled`` / ``unconfigured`` / ``broken`` / ``missing`` /
// ``incomplete`` / ``unknown`` values), render a generic pill that shows
// the raw status string so the operator can see exactly what came back
// instead of a hard React crash.
function statusMeta(status: string): ServiceStatusMeta {
  const known = SERVICE_STATUS_META[status as keyof typeof SERVICE_STATUS_META];
  if (known) return known;
  return {
    label: status || "?",
    color: "var(--color-muted)",
    bg: "var(--color-surface-muted)",
    icon: Info,
  };
}

function ServicesTab() {
  const { toast } = useToast();
  const [data, setData] = useState<ServiceInventoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  // OSS-stack install state — fetched alongside the inventory so the
  // self-hosted rows that have ``oss_install_name`` set can render an
  // inline Install / Reinstall button. Replaces the standalone
  // OSS Stack tab; one surface, one mental model.
  const [ossStates, setOssStates] = useState<OssToolState[]>([]);
  const [ossPreflight, setOssPreflight] = useState<OssPreflight | null>(null);
  const [ossBusy, setOssBusy] = useState<string | null>(null);

  // Connector index — maps Service Inventory row labels to their
  // (group, name) so the Probe button on EDR/email-gateway/sandbox/SOAR
  // rows can call the right /intel/<group>/<name>/health endpoint.
  // Replaces the standalone /connectors page (deleted).
  const [connectorIndex, setConnectorIndex] = useState<
    Map<string, { group: P3ConnectorGroup; name: string }>
  >(new Map());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const groups: P3ConnectorGroup[] = ["edr", "email-gateway", "sandbox", "soar"];
      const [inv, st, pre, ...connectorLists] = await Promise.all([
        api.admin.serviceInventory(),
        api.ossStates().catch(() => ({ tools: [] as OssToolState[] })),
        api.ossPreflight().catch(() => null),
        ...groups.map((g) =>
          api.listConnectors(g).catch(() => ({ connectors: [] as ConnectorRow[] }))
        ),
      ]);
      setData(inv);
      setOssStates(st.tools);
      setOssPreflight(pre);
      const idx = new Map<string, { group: P3ConnectorGroup; name: string }>();
      groups.forEach((group, i) => {
        const list = connectorLists[i] as {
          connectors?: ConnectorRow[];
          providers?: ConnectorRow[];
        };
        const rows: ConnectorRow[] = list.connectors ?? list.providers ?? [];
        rows.forEach((r: ConnectorRow) => {
          const key = (r.label ?? r.name).trim().toLowerCase();
          idx.set(key, { group, name: r.name });
        });
      });
      setConnectorIndex(idx);
    } catch (err) {
      toast("error", `Couldn't load service inventory: ${(err as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const installOssTool = useCallback(
    async (toolName: string) => {
      setOssBusy(toolName);
      try {
        await api.ossInstall([toolName]);
        toast("success", `${toolName} install queued — refreshing in a moment.`);
        setTimeout(() => void load(), 1500);
      } catch (err) {
        toast("error", `Install failed: ${(err as Error).message}`);
      } finally {
        setOssBusy(null);
      }
    },
    [load, toast],
  );

  const ossStateByName = useMemo(
    () => new Map(ossStates.map((s) => [s.tool_name, s])),
    [ossStates],
  );

  useEffect(() => { void load(); }, [load]);

  if (loading && !data) {
    return (
      <div
        className="p-6 text-[13px] flex items-center gap-2"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
          color: "var(--color-muted)",
        }}
      >
        <Loader2 className="w-4 h-4 animate-spin" /> Probing every service…
      </div>
    );
  }

  if (!data) return null;

  const filterLower = filter.trim().toLowerCase();
  const filtered = data.services.filter((s) => {
    if (statusFilter && s.status !== statusFilter) return false;
    if (categoryFilter && s.category !== categoryFilter) return false;
    if (!filterLower) return true;
    return (
      s.name.toLowerCase().includes(filterLower) ||
      s.description.toLowerCase().includes(filterLower) ||
      s.category.toLowerCase().includes(filterLower) ||
      s.requires.some((r) => r.toLowerCase().includes(filterLower)) ||
      s.produces.some((p) => p.toLowerCase().includes(filterLower)) ||
      s.evidence.toLowerCase().includes(filterLower)
    );
  });

  // Split self-hosted (OSS — operator runs it) from paid SaaS so the
  // operator sees the OSS-first surface up top with install hints,
  // distinct from "buy a license" SaaS connectors below.
  const selfHosted = filtered.filter((s) => s.self_hosted);
  const paidOrBundled = filtered.filter((s) => !s.self_hosted);

  const groupedSelfHosted = data.categories
    .map((cat) => ({
      category: cat,
      services: selfHosted.filter((s) => s.category === cat),
    }))
    .filter((g) => g.services.length > 0);

  const groupedByCat = data.categories
    .map((cat) => ({
      category: cat,
      services: paidOrBundled.filter((s) => s.category === cat),
    }))
    .filter((g) => g.services.length > 0);

  return (
    <div className="space-y-5">
      {/* ── Header + summary ─── */}
      <div
        className="px-4 py-3 text-[12.5px] flex items-start justify-between gap-3 flex-wrap"
        style={{
          background: "rgba(255,79,0,0.04)",
          border: "1px solid rgba(255,79,0,0.2)",
          borderRadius: 5,
          color: "var(--color-body)",
        }}
      >
        <div style={{ flex: 1, minWidth: 280 }}>
          <strong style={{ color: "var(--color-ink)" }}>Live service inventory.</strong>{" "}
          Every external service Argus uses, with required inputs, what
          it produces, and current status. Self-hosted OSS rows expose
          inline Install actions; paid SaaS rows expose inline key
          entry. Catalog lives at{" "}
          <code style={{ fontFamily: "var(--font-mono, monospace)" }}>
            src/core/service_inventory.py
          </code>
          .
        </div>
        <Link
          href="/onboarding/oss-tools"
          className="inline-flex items-center gap-1 text-[12px] font-medium px-3 py-1.5"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 5,
            color: "var(--color-ink)",
            whiteSpace: "nowrap",
          }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden />
          Re-run onboarding wizard
        </Link>
      </div>

      {ossPreflight && !ossPreflight.ready && (
        <div
          className="px-3 py-2 text-[12px]"
          style={{
            border: "1px solid rgba(245,158,11,0.3)",
            background: "rgba(245,158,11,0.05)",
            borderRadius: 5,
            color: "var(--color-warning-dark)",
          }}
        >
          <strong>OSS installer not ready</strong> — self-hosted Install
          buttons below will be disabled until these are resolved:
          <ul className="list-disc pl-4 mt-1 space-y-0.5">
            {ossPreflight.issues.map((i, idx) => <li key={idx}>{i}</li>)}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {(["ok", "needs_key", "not_installed"] as const).map(
          (s) => {
            const count = data.summary[s] ?? 0;
            if (count === 0 && statusFilter !== s) return null;
            const meta = statusMeta(s);
            const Icon = meta.icon;
            const active = statusFilter === s;
            return (
              <button
                key={s}
                onClick={() => setStatusFilter(active ? "" : s)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11.5px] font-semibold"
                style={{
                  background: active ? meta.bg : "var(--color-canvas)",
                  border: `1px solid ${active ? meta.color : "var(--color-border)"}`,
                  borderRadius: 4,
                  color: active ? meta.color : "var(--color-body)",
                  cursor: "pointer",
                }}
              >
                <Icon className="w-3 h-3" style={{ color: meta.color }} />
                {meta.label} <span style={{ color: meta.color }}>{count}</span>
              </button>
            );
          },
        )}
        <button
          onClick={load}
          className="inline-flex items-center gap-1.5 ml-auto h-8 px-3 text-[12px] font-medium"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-ink)",
            cursor: "pointer",
          }}
        >
          <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
          Re-probe
        </button>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5"
            style={{ color: "var(--color-muted)" }}
          />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name, requirement, output, evidence…"
            className="w-full h-9 pl-9 pr-3 text-[13px] outline-none"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
          />
        </div>
        <ThemedSelect
          value={categoryFilter}
          onChange={(v) => setCategoryFilter(v)}
          ariaLabel="Filter by category"
          options={[
            { value: "", label: "All categories" },
            ...data.categories.map((c) => ({ value: c, label: c })),
          ]}
          style={{ minWidth: 200 }}
        />
      </div>

      {/* ── OSS — self-hosted section (renders FIRST) ─── */}
      {groupedSelfHosted.length > 0 && (
        <div className="space-y-3">
          <div
            className="px-4 py-3 text-[12.5px]"
            style={{
              background: "rgba(34,197,94,0.05)",
              border: "1px solid rgba(34,197,94,0.25)",
              borderRadius: 5,
              color: "var(--color-body)",
            }}
          >
            <strong style={{ color: "var(--color-ink)" }}>
              OSS — self-hosted.
            </strong>{" "}
            Free, open-source services you run yourself. Drop the URL +
            token into the form on each card and Argus will start
            ingesting / forwarding without further code changes — every
            entry below has its install steps inline.
          </div>
          {groupedSelfHosted.map(({ category, services }) => (
            <div key={`oss-${category}`}>
              <h3
                className="text-[12px] font-bold uppercase tracking-[0.07em] mb-2"
                style={{ color: "var(--color-muted)" }}
              >
                {category} <span style={{ color: "var(--color-body)" }}>({services.length})</span>
              </h3>
              <div
                className="overflow-hidden"
                style={{
                  background: "var(--color-canvas)",
                  border: "1px solid rgba(34,197,94,0.35)",
                  borderRadius: 8,
                }}
              >
                {services.map((s, idx) => {
                  const meta = statusMeta(s.status);
                  const Icon = meta.icon;
                  const isOpen = expanded[`oss/${category}/${s.name}`];
                  return (
                    <div
                      key={s.name}
                      style={{
                        borderTop: idx === 0 ? "none" : "1px solid var(--color-border)",
                      }}
                    >
                      <button
                        type="button"
                        onClick={() =>
                          setExpanded((e) => ({ ...e, [`oss/${category}/${s.name}`]: !isOpen }))
                        }
                        className="w-full px-4 py-3 flex items-start gap-3 text-left"
                        style={{
                          background: "transparent",
                          border: "none",
                          cursor: "pointer",
                        }}
                      >
                        <span
                          className="inline-flex items-center gap-1 px-2 py-0.5 mt-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px] shrink-0"
                          style={{
                            background: meta.bg,
                            color: meta.color,
                            borderRadius: 3,
                            minWidth: 110,
                            justifyContent: "center",
                          }}
                        >
                          <Icon className="w-2.5 h-2.5" />
                          {meta.label}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <strong className="text-[13.5px]" style={{ color: "var(--color-ink)" }}>
                              {s.name}
                            </strong>
                            <span
                              className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.5px]"
                              style={{
                                background: "rgba(34,197,94,0.12)",
                                color: "#15803d",
                                borderRadius: 3,
                              }}
                            >
                              OSS
                            </span>
                          </div>
                          <p
                            className="text-[12px] mt-0.5"
                            style={{ color: "var(--color-muted)" }}
                          >
                            {s.description}
                          </p>
                          <p
                            className="text-[11.5px] mt-1 font-mono"
                            style={{ color: "var(--color-body)" }}
                          >
                            {s.evidence}
                          </p>
                        </div>
                        <ChevronRightIcon open={isOpen} />
                      </button>
                      {isOpen && (
                        <div
                          className="px-4 pb-4 pt-1 space-y-3 text-[12px]"
                          style={{ background: "var(--color-surface)", color: "var(--color-body)" }}
                        >
                          {s.oss_install_name && (
                            <OssInstallStrip
                              toolName={s.oss_install_name}
                              state={ossStateByName.get(s.oss_install_name)}
                              busy={ossBusy === s.oss_install_name}
                              preflightReady={ossPreflight?.ready ?? true}
                              onInstall={() => installOssTool(s.oss_install_name!)}
                            />
                          )}
                          {s.self_host_install_hint && (
                            <div
                              className="px-3 py-2.5 text-[12px]"
                              style={{
                                background: "var(--color-canvas)",
                                border: "1px solid var(--color-border)",
                                borderRadius: 5,
                                whiteSpace: "pre-wrap",
                                fontFamily: "var(--font-mono, monospace)",
                                lineHeight: 1.55,
                              }}
                            >
                              {s.self_host_install_hint}
                            </div>
                          )}
                          {s.docs_url && (
                            <a
                              href={s.docs_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-[12px] font-semibold"
                              style={{ color: "var(--color-accent, #FF4F00)" }}
                            >
                              Official install docs →
                            </a>
                          )}
                          {s.key_fields.length > 0 && (
                            <ServiceKeyEntryForm service={s} onSaved={load} />
                          )}
                          <ServiceProbeButton service={s} index={connectorIndex} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Paid SaaS / bundled (renders below the OSS section) ─── */}
      {groupedByCat.length === 0 && groupedSelfHosted.length === 0 ? (
        <div
          className="px-4 py-8 text-[13px] text-center"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 8,
            color: "var(--color-muted)",
          }}
        >
          No services match the current filters.
        </div>
      ) : groupedByCat.length === 0 ? null : (
        groupedByCat.map(({ category, services }) => (
          <div key={category}>
            <h3
              className="text-[12px] font-bold uppercase tracking-[0.07em] mb-2"
              style={{ color: "var(--color-muted)" }}
            >
              {category} <span style={{ color: "var(--color-body)" }}>({services.length})</span>
            </h3>
            <div
              className="overflow-hidden"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: 8,
              }}
            >
              {services.map((s, idx) => {
                const meta = statusMeta(s.status);
                const Icon = meta.icon;
                const isOpen = expanded[`${category}/${s.name}`];
                return (
                  <div
                    key={s.name}
                    style={{
                      borderTop: idx === 0 ? "none" : "1px solid var(--color-border)",
                    }}
                  >
                    <button
                      type="button"
                      onClick={() =>
                        setExpanded((e) => ({ ...e, [`${category}/${s.name}`]: !isOpen }))
                      }
                      className="w-full px-4 py-3 flex items-start gap-3 text-left"
                      style={{
                        background: "transparent",
                        border: "none",
                        cursor: "pointer",
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLElement).style.background = "var(--color-surface)";
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.background = "transparent";
                      }}
                    >
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 mt-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px] shrink-0"
                        style={{
                          background: meta.bg,
                          color: meta.color,
                          borderRadius: 3,
                          minWidth: 110,
                          justifyContent: "center",
                        }}
                      >
                        <Icon className="w-2.5 h-2.5" />
                        {meta.label}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <strong className="text-[13.5px]" style={{ color: "var(--color-ink)" }}>
                            {s.name}
                          </strong>
                          {/* Tier badge — derived client-side from
                              the ``requires`` strings + self_hosted
                              flag. Cuts through the page so the
                              operator can answer "is this a 5-min
                              free signup or a paid SaaS?" without
                              expanding the row. */}
                          {(() => {
                            const tier = serviceTier(s);
                            const t = TIER_PRESENTATION[tier];
                            return (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-[0.7px]"
                                style={{
                                  background: t.bg,
                                  color: t.color,
                                  borderRadius: 3,
                                }}
                                title={t.help}
                              >
                                {t.label}
                              </span>
                            );
                          })()}
                          {s.last_rows_ingested != null && s.last_rows_ingested > 0 && (
                            <span
                              className="text-[10.5px] font-semibold"
                              style={{ color: "var(--color-muted)" }}
                            >
                              {s.last_rows_ingested.toLocaleString()} rows
                            </span>
                          )}
                          {s.last_observed_at && (
                            <span
                              className="text-[10.5px]"
                              style={{ color: "var(--color-muted)" }}
                              title={new Date(s.last_observed_at).toLocaleString()}
                            >
                              · {timeAgo(s.last_observed_at)}
                            </span>
                          )}
                          {/* Inline "Get key" CTA — only rendered when
                              the service is needs_key AND has a docs
                              URL. Saves the operator from expanding
                              the row just to find the signup link. */}
                          {s.status === "needs_key" && s.docs_url && (
                            <a
                              href={s.docs_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 px-2 py-0.5 text-[10.5px] font-semibold ml-auto"
                              style={{
                                background: "var(--color-accent)",
                                color: "#fffefb",
                                borderRadius: 3,
                              }}
                            >
                              {serviceTier(s) === "free" ? "Get free key" : "Get key"}
                              <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          )}
                        </div>
                        <p
                          className="text-[12px] mt-0.5"
                          style={{ color: "var(--color-muted)" }}
                        >
                          {s.description}
                        </p>
                        <p
                          className="text-[11.5px] mt-1 font-mono"
                          style={{ color: "var(--color-body)" }}
                        >
                          {s.evidence}
                        </p>
                      </div>
                      <ChevronRightIcon open={isOpen} />
                    </button>
                    {isOpen && (
                      <div
                        className="px-4 pb-4 pt-1 space-y-3 text-[12px]"
                        style={{ background: "var(--color-surface)", color: "var(--color-body)" }}
                      >
                        {s.no_oss_substitute && (
                          <div
                            className="px-2.5 py-1.5 text-[11.5px]"
                            style={{
                              background: "rgba(255,171,0,0.08)",
                              border: "1px solid rgba(255,171,0,0.25)",
                              borderRadius: 4,
                              color: "#B76E00",
                            }}
                          >
                            <strong>No OSS substitute:</strong>{" "}
                            this category has no open-source equivalent that
                            covers the same data quality. BYOK enterprise
                            license required for full functionality.
                          </div>
                        )}
                        {s.legacy_only && (
                          <div
                            className="px-2.5 py-1.5 text-[11.5px]"
                            style={{
                              background: "rgba(239,68,68,0.06)",
                              border: "1px solid rgba(239,68,68,0.25)",
                              borderRadius: 4,
                              color: "var(--color-error-dark)",
                            }}
                          >
                            <strong>Registration closed by upstream:</strong>{" "}
                            new keys can&apos;t be obtained right now. Only
                            operators with a pre-existing legacy key can
                            configure this. The integration code stays
                            wired so legacy keys keep working.
                          </div>
                        )}
                        {s.key_fields.length > 0 && (
                          <ServiceKeyEntryForm
                            service={s}
                            onSaved={load}
                          />
                        )}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <div>
                            <div
                              className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-1"
                              style={{ color: "var(--color-muted)" }}
                            >
                              Requires
                            </div>
                            <ul className="space-y-0.5">
                              {s.requires.map((r, i) => (
                                <li key={i} className="font-mono text-[11.5px]">{r}</li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <div
                              className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-1"
                              style={{ color: "var(--color-muted)" }}
                            >
                              Produces
                            </div>
                            <ul className="space-y-0.5">
                              {s.produces.map((p, i) => (
                                <li key={i} className="text-[11.5px]">{p}</li>
                              ))}
                            </ul>
                          </div>
                          {(s.source_file || s.docs_url) && (
                            <div className="md:col-span-2 flex flex-wrap gap-3 pt-2 border-t" style={{ borderColor: "var(--color-border)" }}>
                              {s.source_file && (
                                <span
                                  className="text-[10.5px] font-mono"
                                  style={{ color: "var(--color-muted)" }}
                                >
                                  source: {s.source_file}
                                </span>
                              )}
                              {s.docs_url && (
                                <a
                                  href={s.docs_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-[11.5px]"
                                  style={{ color: "var(--color-accent)" }}
                                >
                                  upstream docs <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                          )}
                        </div>
                        <ServiceProbeButton service={s} index={connectorIndex} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))
      )}
    </div>
  );
}


/* ── Service health probe ──────────────────────────────────────────────
 *
 *  Replaces the deleted standalone /connectors page. EDR / email-
 *  gateway / sandbox / SOAR rows in Service Inventory render a
 *  "Probe health" button when they map to one of those groups; the
 *  button calls /intel/<group>/<name>/health and shows the result
 *  inline. Configuration (env vars / API keys) lives one tab over in
 *  the existing key-entry form, so this page is the canonical place
 *  for both setup and verification.
 */
function ServiceProbeButton({
  service,
  index,
}: {
  service: ServiceInventoryEntry;
  index: Map<string, { group: P3ConnectorGroup; name: string }>;
}) {
  const lookup = (() => {
    const lower = service.name.trim().toLowerCase();
    if (index.has(lower)) return index.get(lower);
    // Fallback: trim parenthetical suffixes like " (Palo Alto)" or
    // " (OSS — self-hosted)" and retry.
    const stripped = lower.replace(/\s*\(.*?\)\s*$/, "").trim();
    if (index.has(stripped)) return index.get(stripped);
    // Final fallback: prefix match.
    for (const [k, v] of index.entries()) {
      if (k.startsWith(stripped) || stripped.startsWith(k)) return v;
    }
    return undefined;
  })();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ConnectorHealth | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (!lookup) return null;

  const onProbe = async () => {
    setBusy(true);
    setResult(null);
    setErr(null);
    try {
      const r = await api.connectorHealth(lookup.group, lookup.name);
      setResult(r);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "probe failed");
    } finally {
      setBusy(false);
    }
  };

  const ok = result?.success === true;
  const note = result?.note ?? null;
  const errMsg = err ?? result?.error ?? null;

  return (
    <div
      className="pt-2 mt-2 flex flex-wrap items-center gap-3"
      style={{ borderTop: "1px solid var(--color-border)" }}
    >
      <button
        type="button"
        onClick={onProbe}
        disabled={busy}
        className="inline-flex items-center gap-1.5 h-7 px-2.5 text-[11.5px] font-semibold transition-colors"
        style={{
          borderRadius: 4,
          border: "1px solid var(--color-border)",
          background: busy ? "var(--color-surface)" : "var(--color-canvas)",
          color: "var(--color-ink)",
          cursor: busy ? "wait" : "pointer",
        }}
        title={`GET /intel/${lookup.group}/${lookup.name}/health`}
      >
        {busy ? "Probing…" : "Probe health"}
      </button>
      <span
        className="text-[10.5px] font-mono"
        style={{ color: "var(--color-muted)" }}
      >
        {lookup.group}/{lookup.name}
      </span>
      {result !== null && (
        <span
          className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-semibold"
          style={{
            borderRadius: 3,
            background: ok ? "rgba(35,134,54,0.10)" : "rgba(218,54,51,0.10)",
            color: ok ? "#1F7A2A" : "#7A2920",
            border: `1px solid ${ok ? "rgba(35,134,54,0.30)" : "rgba(218,54,51,0.30)"}`,
          }}
        >
          {ok ? "✓ reachable" : "✗ unreachable"}
        </span>
      )}
      {note && (
        <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
          {note}
        </span>
      )}
      {errMsg && (
        <span className="text-[11px]" style={{ color: "#7A2920" }}>
          {errMsg}
        </span>
      )}
    </div>
  );
}

function ChevronRightIcon({ open }: { open: boolean }) {
  return (
    <svg
      className="w-3.5 h-3.5 mt-1.5 shrink-0"
      style={{
        color: "var(--color-muted)",
        transform: open ? "rotate(90deg)" : "rotate(0deg)",
        transition: "transform 0.15s",
      }}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M5 3l6 5-6 5" />
    </svg>
  );
}

function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Date.now() - t;
  const m = Math.round(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}


/* Inline API-key entry rendered inside the expanded Services row.
 * Saves to /admin/settings (which writes to app_settings + invalidates
 * the integration_keys cache so the next provider call uses the new
 * value within ~5s). Replaces the standalone Integrations tab. */

function ServiceKeyEntryForm({
  service,
  onSaved,
}: {
  service: ServiceInventoryEntry;
  onSaved: () => Promise<void> | void;
}) {
  const { toast } = useToast();
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [reveal, setReveal] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      let saved = 0;
      for (const f of service.key_fields) {
        const v = (drafts[f.key] ?? "").trim();
        if (!v) continue;
        await api.admin.upsertSetting(`integration.${f.key}.api_key`, {
          key: `integration.${f.key}.api_key`,
          value: v,
          value_type: "string",
          category: "integrations",
          description: `${service.name} ${f.label}`,
        });
        saved++;
      }
      if (saved === 0) {
        toast("info", "Nothing to save — type a value into a field first");
      } else {
        toast("success", `${service.name}: ${saved} field(s) saved`);
        setDrafts({});
        await onSaved();
      }
    } catch (err) {
      toast("error", `Save failed: ${(err as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    if (!confirm(
      `Remove ${service.name} DB-stored credentials? Provider falls back to env if set, else inactive.`,
    )) return;
    setSaving(true);
    try {
      for (const f of service.key_fields) {
        if (f.source === "db") {
          await api.admin.deleteSetting(`integration.${f.key}.api_key`);
        }
      }
      toast("success", `${service.name} DB credentials cleared`);
      await onSaved();
    } catch (err) {
      toast("error", `Remove failed: ${(err as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  const hasDb = service.key_fields.some((f) => f.source === "db");

  return (
    <div
      className="px-3 py-2.5 space-y-2"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 4,
      }}
    >
      <div
        className="text-[10.5px] font-bold uppercase tracking-[0.6px]"
        style={{ color: "var(--color-muted)" }}
      >
        Configure
      </div>
      {service.key_fields.map((f) => {
        const isPwd = f.label.toLowerCase().includes("key") ||
                       f.label.toLowerCase().includes("secret") ||
                       f.label.toLowerCase().includes("token") ||
                       f.label.toLowerCase().includes("password");
        const masked = !reveal[f.key];
        const sourceLabel =
          f.source === "db" ? "DB" :
          f.source === "env" ? `env: ${f.env_var}` :
          `unset · env: ${f.env_var}`;
        const sourceColor =
          f.source === "db" ? "var(--color-success-dark)" :
          f.source === "env" ? "#1D4ED8" :
          "var(--color-muted)";
        return (
          <div key={f.key}>
            <div className="flex items-center justify-between mb-0.5">
              <label
                className="text-[10.5px] font-bold uppercase tracking-[0.6px]"
                style={{ color: "var(--color-muted)" }}
              >
                {f.label}
              </label>
              <span
                className="text-[10px] font-mono"
                style={{ color: sourceColor }}
              >
                {f.masked_value && (
                  <span style={{ color: "var(--color-body)" }}>
                    {f.masked_value}{" "}
                  </span>
                )}
                ({sourceLabel})
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type={isPwd && masked ? "password" : "text"}
                value={drafts[f.key] ?? ""}
                onChange={(e) => setDrafts((d) => ({ ...d, [f.key]: e.target.value }))}
                placeholder={
                  f.source === "unset" ? "(unset)" :
                  f.source === "env" ? "type new value to override env…" :
                  "type new value to replace…"
                }
                className="flex-1 h-8 px-2 text-[12.5px] outline-none font-mono"
                style={{
                  borderRadius: 3,
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-ink)",
                }}
                autoComplete="off"
                spellCheck={false}
              />
              {isPwd && (
                <button
                  type="button"
                  onClick={() => setReveal((r) => ({ ...r, [f.key]: !r[f.key] }))}
                  className="p-1.5"
                  style={{
                    background: "transparent",
                    border: "1px solid var(--color-border)",
                    borderRadius: 3,
                    color: "var(--color-muted)",
                    cursor: "pointer",
                  }}
                  aria-label={masked ? "Reveal" : "Hide"}
                >
                  {masked ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                </button>
              )}
            </div>
          </div>
        );
      })}
      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving || !service.key_fields.some((f) => (drafts[f.key] ?? "").trim())}
          className="inline-flex items-center gap-1.5 h-7 px-3 text-[11.5px] font-semibold"
          style={{
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            border: "none",
            borderRadius: 3,
            cursor: saving ? "not-allowed" : "pointer",
            opacity: saving ? 0.5 : 1,
          }}
        >
          {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
          Save
        </button>
        {hasDb && (
          <button
            type="button"
            onClick={handleRemove}
            disabled={saving}
            className="inline-flex items-center gap-1 h-7 px-2.5 text-[11px] font-medium"
            style={{
              background: "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 3,
              color: "var(--color-error-dark)",
              cursor: "pointer",
            }}
            title="Remove DB-stored values; falls back to env if set"
          >
            <Trash2 className="w-3 h-3" />
            Clear DB value
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Tech Stack Tab (Admin) ────────────────────────────────────────────────
 *
 * The org's declared technology stack. Used by the feed-triage agent
 * (src/agents/feed_triage.py) as the org-context anchor when deciding
 * whether a CISA KEV / advisory entry is "is_threat: true" for this
 * org. Without it the LLM correctly refuses to fire alerts; with it
 * the LLM can correlate vendor/product names from feeds against the
 * declared stack and produce actionable, org-specific alerts.
 *
 * Categories are free-form: the LLM is keyword-driven, so adding a
 * "biometrics" category with "Onfido" in it is just as effective as
 * any of the seeded ones.
 *
 * Source of truth: `organizations.tech_stack` JSONB column,
 * Record<category, list[vendor]>. Edited via PATCH /organizations/current.
 */

function TechStackTab() {
  const { toast } = useToast();
  const [org, setOrg] = useState<Org | null>(null);
  const [stack, setStack] = useState<Record<string, string[]>>({});
  const [latestTriage, setLatestTriage] = useState<TriageRunSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [newCategory, setNewCategory] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [o, t] = await Promise.allSettled([
        api.getCurrentOrg(),
        api.getLatestTriageRun(),
      ]);
      if (o.status === "fulfilled") {
        setOrg(o.value);
        setStack(normalizeStack(o.value.tech_stack));
        setDirty(false);
      } else {
        toast("error", "Failed to load organisation");
      }
      if (t.status === "fulfilled") setLatestTriage(t.value);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const totalItems = useMemo(
    () => Object.values(stack).reduce((acc, arr) => acc + arr.length, 0),
    [stack],
  );

  const updateCategory = (category: string, items: string[]) => {
    setStack((prev) => ({ ...prev, [category]: items }));
    setDirty(true);
  };
  const removeCategory = (category: string) => {
    setStack((prev) => {
      const { [category]: _drop, ...rest } = prev;
      return rest;
    });
    setDirty(true);
  };
  const addItem = (category: string, item: string) => {
    const trimmed = item.trim();
    if (!trimmed) return;
    const existing = stack[category] || [];
    if (existing.some((x) => x.toLowerCase() === trimmed.toLowerCase())) return;
    updateCategory(category, [...existing, trimmed]);
  };
  const addCategory = () => {
    const key = slugCategory(newCategory);
    if (!key) return;
    if (stack[key]) {
      toast("error", `Category "${key}" already exists`);
      return;
    }
    updateCategory(key, []);
    setNewCategory("");
  };

  const handleSave = async () => {
    if (saving) return;
    setSaving(true);
    try {
      // Strip empty categories before sending so we don't persist
      // dead buckets the agent has to skip over.
      const payload: Record<string, string[]> = {};
      Object.entries(stack).forEach(([k, v]) => {
        if (v.length > 0) payload[k] = v;
      });
      const updated = await api.updateCurrentOrg({ tech_stack: payload });
      setOrg(updated);
      setStack(normalizeStack(updated.tech_stack));
      setDirty(false);
      toast("success", "Tech stack saved — next triage will use this profile");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to save tech stack");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-5 h-5 animate-spin" style={{ color: "var(--color-muted)" }} />
      </div>
    );
  }

  const categoryKeys = Object.keys(stack).sort();

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3
            className="text-[16px] font-semibold tracking-[-0.01em]"
            style={{ color: "var(--color-ink)" }}
          >
            Tech stack — {org?.name ?? "current organisation"}
          </h3>
          <p className="text-[12.5px] mt-1 leading-relaxed" style={{ color: "var(--color-muted)" }}>
            The AI Triage Agent uses this list to decide which CVEs and
            advisories actually target you. Add what you actually run;
            remove what you don&apos;t. Saves apply on the next triage.
          </p>
        </div>
        <button
          type="button"
          onClick={handleSave}
          disabled={!dirty || saving}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-opacity disabled:opacity-50 shrink-0"
          style={{
            background: dirty ? "var(--color-accent)" : "var(--color-surface-muted)",
            color: dirty ? "#fffefb" : "var(--color-muted)",
            borderRadius: 4,
            border: `1px solid ${dirty ? "var(--color-accent)" : "var(--color-border)"}`,
          }}
        >
          {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
          {saving ? "Saving…" : dirty ? "Save changes" : "Saved"}
        </button>
      </div>

      <TriageSignal totalItems={totalItems} latestTriage={latestTriage} />

      {categoryKeys.length === 0 && (
        <div
          className="px-4 py-6 text-[13px] text-center"
          style={{
            background: "var(--color-surface-muted)",
            border: "1px dashed var(--color-border)",
            borderRadius: 5,
            color: "var(--color-muted)",
          }}
        >
          No tech-stack categories yet. Add one below to start.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {categoryKeys.map((category) => (
          <TechStackCategory
            key={category}
            category={category}
            items={stack[category]}
            onChange={(next) => updateCategory(category, next)}
            onRemove={() => removeCategory(category)}
            onAddItem={(v) => addItem(category, v)}
          />
        ))}
      </div>

      <div
        className="flex items-center gap-2 p-3"
        style={{
          background: "var(--color-surface-muted)",
          border: "1px solid var(--color-border)",
          borderRadius: 5,
        }}
      >
        <Plus className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
        <input
          type="text"
          value={newCategory}
          onChange={(e) => setNewCategory(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") addCategory(); }}
          placeholder="Add a category (e.g. biometrics, core_banking, etl)"
          className="flex-1 h-8 px-2 text-[13px] outline-none"
          style={{ background: "transparent", border: "none", color: "var(--color-ink)" }}
        />
        <button
          type="button"
          onClick={addCategory}
          disabled={!newCategory.trim()}
          className="h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
          style={{
            background: "var(--color-surface)",
            color: "var(--color-ink)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
          }}
        >
          Add category
        </button>
      </div>
    </div>
  );
}

function TriageSignal({
  totalItems,
  latestTriage,
}: {
  totalItems: number;
  latestTriage: TriageRunSummary | null;
}) {
  let body: React.ReactNode;
  let tone: "info" | "warn" | "ok" = "info";
  if (totalItems === 0) {
    tone = "warn";
    body = (
      <>
        <strong>Triage is starved.</strong> With zero declared
        components the LLM has nothing to correlate feeds against and
        will mark everything as background noise. Add at least the
        components you know you run (web servers, MDM, VPN, document
        viewers).
      </>
    );
  } else if (!latestTriage) {
    body = (
      <>
        {totalItems} component{totalItems === 1 ? "" : "s"} declared. No
        triage run yet — trigger one from the dashboard to see how this
        list affects alert generation.
      </>
    );
  } else if (latestTriage.alerts_generated === 0) {
    tone = "warn";
    body = (
      <>
        Last triage scanned <strong>{latestTriage.entries_processed.toLocaleString()}</strong>{" "}
        feed entries against your <strong>{totalItems}</strong> declared
        components and produced <strong>0 alerts</strong>. Either the
        feed window is quiet or the declared stack doesn&apos;t match
        upstream advisory keywords. Try adding more vendor names.
      </>
    );
  } else {
    tone = "ok";
    body = (
      <>
        Last triage matched{" "}
        <strong>
          {latestTriage.alerts_generated} alert{latestTriage.alerts_generated === 1 ? "" : "s"}
        </strong>{" "}
        from <strong>{latestTriage.entries_processed.toLocaleString()}</strong>{" "}
        feed entries against your <strong>{totalItems}</strong> declared components.
      </>
    );
  }

  const colors: Record<typeof tone, { bg: string; border: string; ink: string; icon: typeof Info }> = {
    info: { bg: "rgba(59,130,246,0.06)",  border: "rgba(59,130,246,0.25)",  ink: "var(--color-body)", icon: Info },
    warn: { bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.30)",  ink: "var(--color-body)", icon: AlertTriangle },
    ok:   { bg: "rgba(34,197,94,0.08)",   border: "rgba(34,197,94,0.30)",   ink: "var(--color-body)", icon: CheckCircle2 },
  };
  const c = colors[tone];
  const Icon = c.icon;
  return (
    <div
      className="px-4 py-3 flex items-start gap-3"
      style={{ background: c.bg, border: `1px solid ${c.border}`, borderRadius: 5 }}
    >
      <Icon className="w-4 h-4 mt-0.5 shrink-0" style={{ color: c.ink }} />
      <p className="text-[12.5px] leading-relaxed" style={{ color: c.ink }}>
        {body}
      </p>
    </div>
  );
}

function TechStackCategory({
  category,
  items,
  onChange,
  onRemove,
  onAddItem,
}: {
  category: string;
  items: string[];
  onChange: (next: string[]) => void;
  onRemove: () => void;
  onAddItem: (item: string) => void;
}) {
  const [draft, setDraft] = useState("");

  const submit = () => {
    if (!draft.trim()) return;
    onAddItem(draft);
    setDraft("");
  };

  return (
    <div
      className="p-3"
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <h4
          className="text-[12px] font-semibold uppercase tracking-[0.6px]"
          style={{ color: "var(--color-muted)" }}
        >
          {prettyCategory(category)}
        </h4>
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Remove category ${category}`}
          className="flex items-center justify-center w-6 h-6 transition-opacity hover:opacity-70"
          style={{ color: "var(--color-muted)", background: "transparent", border: "none", cursor: "pointer", borderRadius: 3 }}
          title="Remove this entire category"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="flex flex-wrap gap-1.5 mb-2">
        {items.length === 0 ? (
          <span className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>
            No items — add the products you actually run below.
          </span>
        ) : (
          items.map((item, i) => (
            <span
              key={`${item}-${i}`}
              className="inline-flex items-center gap-1.5 px-2 py-1 text-[12px]"
              style={{
                background: "var(--color-surface-muted)",
                border: "1px solid var(--color-border)",
                borderRadius: 3,
                color: "var(--color-ink)",
              }}
            >
              {item}
              <button
                type="button"
                onClick={() => onChange(items.filter((_, j) => j !== i))}
                aria-label={`Remove ${item}`}
                className="flex items-center justify-center w-4 h-4 transition-opacity hover:opacity-70"
                style={{ color: "var(--color-muted)", background: "transparent", border: "none", cursor: "pointer" }}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))
        )}
      </div>

      <div className="flex items-center gap-2">
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
          placeholder="Add product / vendor"
          className="flex-1 h-8 px-2 text-[13px] outline-none"
          style={{
            background: "var(--color-surface-muted)",
            border: "1px solid var(--color-border)",
            color: "var(--color-ink)",
            borderRadius: 4,
          }}
        />
        <button
          type="button"
          onClick={submit}
          disabled={!draft.trim()}
          className="h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
          style={{
            background: "var(--color-surface-muted)",
            color: "var(--color-ink)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
          }}
        >
          Add
        </button>
      </div>
    </div>
  );
}

function normalizeStack(raw: Record<string, string[]> | null): Record<string, string[]> {
  if (!raw) return {};
  const out: Record<string, string[]> = {};
  Object.entries(raw).forEach(([k, v]) => {
    if (Array.isArray(v)) {
      out[k] = v.filter((x): x is string => typeof x === "string");
    }
  });
  return out;
}

function prettyCategory(slug: string): string {
  return slug
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function slugCategory(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}
