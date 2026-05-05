"use client";

/**
 * Notifications — multi-tab production console.
 *
 * Tabs:
 *   - Inbox            per-user in-app inbox (mark read, archive, deep-link)
 *   - Channels         CRUD on adapter channels (slack/teams/email/webhook/...)
 *   - Rules            CRUD on routing rules (event_kinds, severity, quiet hours)
 *   - Delivery Log     append-only log of every adapter call with drill-down
 *   - Preferences      per-user opt-outs / DND / escalation / frequency caps
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Archive,
  Bell,
  BookOpen,
  Check,
  CheckCheck,
  ClipboardList,
  Eye,
  EyeOff,
  Filter,
  Inbox as InboxIcon,
  Layers,
  ListChecks,
  Mail,
  MessageSquare,
  Plus,
  RefreshCw,
  Save,
  Send,
  Settings as SettingsIcon,
  Siren,
  Sparkles,
  Trash2,
  Webhook,
  X,
} from "lucide-react";
import {
  api,
  ApiError,
  type NotificationChannelKind,
  type NotificationChannelResponse,
  type NotificationDeliveryResponse,
  type NotificationInboxItemResponse,
  type NotificationPreferences,
  type NotificationQuietHours,
  type NotificationRuleResponse,
  type Org,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Select } from "@/components/shared/select";
import { timeAgo } from "@/lib/utils";

// ─── types & constants ──────────────────────────────────────────────────

const TABS = [
  { key: "inbox", label: "Inbox", icon: InboxIcon },
  { key: "channels", label: "Channels", icon: Webhook },
  { key: "rules", label: "Rules", icon: ListChecks },
  { key: "deliveries", label: "Delivery Log", icon: Layers },
  { key: "preferences", label: "Preferences", icon: SettingsIcon },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const CHANNEL_KINDS: { value: NotificationChannelKind; label: string; secret: string; configHint: string }[] = [
  { value: "slack", label: "Slack", secret: "Webhook URL", configHint: '{"webhook_url":"https://hooks.slack.com/..."} (or paste in secret)' },
  { value: "teams", label: "Microsoft Teams", secret: "Webhook URL", configHint: '{"webhook_url":"https://outlook.office.com/webhook/..."}' },
  { value: "email", label: "Email (SMTP)", secret: "SMTP password", configHint: '{"smtp_host":"smtp.example.com","smtp_port":587,"start_tls":true,"from_address":"argus@example.com","recipients":["soc@example.com"],"username":"..."}' },
  { value: "webhook", label: "Generic webhook", secret: "HMAC secret (optional)", configHint: '{"url":"https://example.com/notify","headers":{}}' },
  { value: "pagerduty", label: "PagerDuty", secret: "Routing key", configHint: '{}' },
  { value: "opsgenie", label: "Opsgenie", secret: "API key", configHint: '{"responders":[{"type":"team","name":"soc"}]}' },
  { value: "apprise", label: "Apprise (multi-target OSS)", secret: "(unused)", configHint: '{"urls":["mattermost://...","ntfy://..."]}' },
  { value: "jasmin_sms", label: "Jasmin SMS Gateway", secret: "Jasmin password", configHint: '{"endpoint":"http://jasmin:1401","username":"argus","recipients":["+9715..."]}' },
];

const EVENT_KINDS = [
  "alert", "case_transition", "sla_breach", "discovery_finding",
  "security_rating_drop", "dmarc_failure", "phishing_detection",
  "impersonation_detection", "data_leakage", "system_health", "test",
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITIES)[number];

const SEV_TONE: Record<string, { bg: string; fg: string }> = {
  critical: { bg: "rgba(183,29,24,0.12)", fg: "#B71D18" },
  high:     { bg: "rgba(255,86,48,0.12)", fg: "#B71D18" },
  medium:   { bg: "rgba(183,110,0,0.12)", fg: "#7B4B00" },
  low:      { bg: "rgba(0,145,255,0.12)", fg: "#0064B0" },
  info:     { bg: "rgba(99,115,129,0.12)", fg: "#454F5B" },
};

const STATUS_TONE: Record<string, string> = {
  succeeded: "#1e8e3e",
  failed: "#B71D18",
  skipped: "#637381",
  pending: "#B76E00",
  dry_run: "#637381",
};

// ─── shared atoms ───────────────────────────────────────────────────────

function Pill({ tone, children }: { tone?: { bg: string; fg: string }; children: ReactNode }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
      style={{
        borderRadius: 4,
        background: tone?.bg ?? "rgba(99,115,129,0.10)",
        color: tone?.fg ?? "#454F5B",
      }}
    >
      {children}
    </span>
  );
}

function Card({ children, padded = true }: { children: ReactNode; padded?: boolean }) {
  return (
    <div
      className={padded ? "p-5" : ""}
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 6,
      }}
    >
      {children}
    </div>
  );
}

function PrimaryButton({
  children,
  onClick,
  disabled,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
      style={{
        borderRadius: 5,
        background: "var(--color-surface-dark)",
        color: "var(--color-on-dark)",
        border: "1px solid var(--color-border-strong)",
      }}
    >
      {children}
    </button>
  );
}

function GhostButton({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-medium transition-colors disabled:opacity-40"
      style={{
        borderRadius: 5,
        background: "var(--color-canvas)",
        color: "var(--color-body)",
        border: "1px solid var(--color-border)",
      }}
    >
      {children}
    </button>
  );
}

function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="block">
      <div className="text-[12px] font-semibold mb-1.5" style={{ color: "var(--color-ink)" }}>
        {label}
      </div>
      {children}
      {hint && (
        <div className="text-[11px] mt-1" style={{ color: "var(--color-muted)" }}>
          {hint}
        </div>
      )}
    </label>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full h-9 px-3 text-[13px]"
      style={{
        borderRadius: 5,
        background: "var(--color-canvas)",
        color: "var(--color-ink)",
        border: "1px solid var(--color-border)",
      }}
    />
  );
}

function TextArea({
  value,
  onChange,
  rows = 4,
  placeholder,
  mono,
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      className={`w-full p-3 text-[12px] ${mono ? "font-mono" : ""}`}
      style={{
        borderRadius: 5,
        background: "var(--color-canvas)",
        color: "var(--color-ink)",
        border: "1px solid var(--color-border)",
        resize: "vertical",
      }}
    />
  );
}

// ─── Page shell ─────────────────────────────────────────────────────────

export default function NotificationsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgId] = useState<string>("");
  const [tab, setTab] = useState<TabKey>("inbox");
  const [unread, setUnread] = useState<number>(0);
  const { toast } = useToast();

  // Load orgs once.
  useEffect(() => {
    (async () => {
      try {
        const o = await api.getOrgs();
        setOrgs(o);
        if (o.length > 0 && !orgId) setOrgId(o[0].id);
      } catch (e) {
        toast("error", e instanceof Error ? e.message : "Failed to load organizations");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll unread count every 5s — drives the tab badge.
  useEffect(() => {
    let cancelled = false;
    const fetchCount = async () => {
      try {
        const r = await api.notifications.inboxUnreadCount();
        if (!cancelled) setUnread(r.unread || 0);
      } catch {
        // Silent — preserve last known count.
      }
    };
    fetchCount();
    const t = setInterval(fetchCount, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const orgOptions = useMemo(
    () => orgs.map((o) => ({ value: o.id, label: o.name })),
    [orgs],
  );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Notifications
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Routes, channels, in-app inbox and per-user preferences.
          </p>
        </div>
        {tab !== "inbox" && tab !== "preferences" && orgs.length > 0 && (
          <div style={{ minWidth: 240 }}>
            <Select<string>
              value={orgId}
              onChange={(v) => setOrgId(v)}
              options={orgOptions}
              placeholder="Organization"
            />
          </div>
        )}
      </div>

      <div
        className="flex items-center gap-1 px-2 py-1.5 overflow-x-auto"
        style={{
          borderRadius: 6,
          border: "1px solid var(--color-border)",
          background: "var(--color-surface-muted)",
        }}
      >
        {TABS.map((t) => {
          const active = t.key === tab;
          const Icon = t.icon;
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className="inline-flex items-center gap-2 h-8 px-3 text-[12px] font-semibold transition-colors"
              style={{
                borderRadius: 5,
                color: active ? "var(--color-on-dark)" : "var(--color-body)",
                background: active ? "var(--color-surface-dark)" : "transparent",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
              {t.key === "inbox" && unread > 0 && (
                <span
                  className="inline-flex items-center justify-center text-[10px] font-bold"
                  style={{
                    minWidth: 18,
                    height: 18,
                    padding: "0 5px",
                    borderRadius: 9,
                    background: active ? "rgba(255,86,48,0.85)" : "#FF5630",
                    color: "white",
                  }}
                >
                  {unread > 99 ? "99+" : unread}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {tab === "inbox" && <InboxTab onUnreadChange={setUnread} />}
      {tab === "channels" && orgId && <ChannelsTab orgId={orgId} />}
      {tab === "rules" && orgId && <RulesTab orgId={orgId} />}
      {tab === "deliveries" && orgId && <DeliveriesTab orgId={orgId} />}
      {tab === "preferences" && <PreferencesTab orgId={orgId} />}
    </div>
  );
}

// ─── Tab: Inbox ─────────────────────────────────────────────────────────

function InboxTab({ onUnreadChange }: { onUnreadChange: (n: number) => void }) {
  const [items, setItems] = useState<NotificationInboxItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const { toast } = useToast();

  const refresh = useCallback(async () => {
    try {
      const list = await api.notifications.listInbox({
        unread_only: unreadOnly,
        include_archived: includeArchived,
        limit: 200,
      });
      setItems(list);
      const unreadCount = list.filter((i) => !i.read_at && !i.archived_at).length;
      onUnreadChange(unreadCount);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load inbox");
    } finally {
      setLoading(false);
    }
  }, [unreadOnly, includeArchived, onUnreadChange, toast]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  async function handleToggleRead(item: NotificationInboxItemResponse) {
    setBusyId(item.id);
    try {
      const updated = await api.notifications.markInboxRead(item.id, Boolean(item.read_at));
      setItems((prev) => prev.map((i) => (i.id === item.id ? updated : i)));
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed");
    } finally {
      setBusyId(null);
    }
  }

  async function handleArchive(item: NotificationInboxItemResponse) {
    setBusyId(item.id);
    try {
      const updated = await api.notifications.archiveInbox(item.id, Boolean(item.archived_at));
      setItems((prev) => prev.map((i) => (i.id === item.id ? updated : i)));
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed");
    } finally {
      setBusyId(null);
    }
  }

  async function handleMarkAll() {
    try {
      const r = await api.notifications.markAllInboxRead();
      toast("success", `Marked ${r.updated} read`);
      await refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed");
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <GhostButton onClick={() => setUnreadOnly((v) => !v)}>
            <Filter className="w-3.5 h-3.5" />
            {unreadOnly ? "Showing unread" : "All"}
          </GhostButton>
          <GhostButton onClick={() => setIncludeArchived((v) => !v)}>
            <Archive className="w-3.5 h-3.5" />
            {includeArchived ? "+ archived" : "Active only"}
          </GhostButton>
          <GhostButton onClick={refresh}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </GhostButton>
        </div>
        <PrimaryButton onClick={handleMarkAll}>
          <CheckCheck className="w-3.5 h-3.5" /> Mark all read
        </PrimaryButton>
      </div>

      {loading && items.length === 0 ? (
        <Card>
          <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading inbox…
          </div>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center py-8 text-center">
            <Bell className="w-7 h-7 mb-3" style={{ color: "var(--color-muted)" }} />
            <div className="text-[14px] font-medium mb-1" style={{ color: "var(--color-ink)" }}>
              Nothing in your inbox
            </div>
            <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
              Successful deliveries will appear here for in-app review.
            </div>
          </div>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <InboxRow
              key={item.id}
              item={item}
              busy={busyId === item.id}
              onToggleRead={() => handleToggleRead(item)}
              onArchive={() => handleArchive(item)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function InboxRow({
  item,
  busy,
  onToggleRead,
  onArchive,
}: {
  item: NotificationInboxItemResponse;
  busy: boolean;
  onToggleRead: () => void;
  onArchive: () => void;
}) {
  const tone = SEV_TONE[item.severity] ?? SEV_TONE.info;
  return (
    <div
      className="p-4 transition-colors"
      style={{
        background: item.read_at ? "var(--color-canvas)" : "rgba(0,123,196,0.04)",
        border: `1px solid ${item.read_at ? "var(--color-border)" : "rgba(0,123,196,0.25)"}`,
        borderRadius: 6,
        opacity: item.archived_at ? 0.55 : 1,
      }}
    >
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <Pill tone={tone}>{item.severity}</Pill>
            <Pill>{item.event_kind}</Pill>
            {item.archived_at && <Pill>archived</Pill>}
            <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
              {timeAgo(item.created_at)}
            </span>
          </div>
          <div className="text-[14px] font-semibold mb-1" style={{ color: "var(--color-ink)" }}>
            {item.title}
          </div>
          {item.summary && (
            <div className="text-[12px] whitespace-pre-wrap" style={{ color: "var(--color-body)" }}>
              {item.summary}
            </div>
          )}
          {item.link_path && (
            <a
              href={item.link_path}
              className="inline-flex items-center gap-1 text-[12px] mt-2"
              style={{ color: "var(--color-accent)" }}
            >
              Open <Sparkles className="w-3 h-3" />
            </a>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <button
            onClick={onToggleRead}
            disabled={busy}
            title={item.read_at ? "Mark unread" : "Mark read"}
            className="inline-flex items-center justify-center w-8 h-8 transition-colors"
            style={{
              borderRadius: 5,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            {item.read_at ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={onArchive}
            disabled={busy}
            title={item.archived_at ? "Unarchive" : "Archive"}
            className="inline-flex items-center justify-center w-8 h-8 transition-colors"
            style={{
              borderRadius: 5,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <Archive className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Channels ──────────────────────────────────────────────────────

function ChannelsTab({ orgId }: { orgId: string }) {
  const [items, setItems] = useState<NotificationChannelResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<NotificationChannelResponse | null>(null);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.notifications.listChannels(orgId);
      setItems(list);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load channels");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleDelete(c: NotificationChannelResponse) {
    if (!window.confirm(`Delete channel "${c.name}"?`)) return;
    try {
      await api.notifications.deleteChannel(c.id);
      toast("success", "Channel deleted");
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to delete");
    }
  }

  async function handleTest(c: NotificationChannelResponse) {
    try {
      await api.notifications.testChannel(c.id);
      toast("success", `Test sent to "${c.name}"`);
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Test failed");
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {items.length} channel{items.length === 1 ? "" : "s"}
        </div>
        <PrimaryButton onClick={() => setCreating(true)}>
          <Plus className="w-3.5 h-3.5" /> New channel
        </PrimaryButton>
      </div>

      {loading ? (
        <Card>
          <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading…
          </div>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center py-8 text-center">
            <Webhook className="w-7 h-7 mb-3" style={{ color: "var(--color-muted)" }} />
            <div className="text-[14px] font-medium mb-1" style={{ color: "var(--color-ink)" }}>
              No channels configured
            </div>
            <div className="text-[12px] mb-3" style={{ color: "var(--color-muted)" }}>
              Add a Slack webhook, SMTP relay, PagerDuty service, etc.
            </div>
            <PrimaryButton onClick={() => setCreating(true)}>
              <Plus className="w-3.5 h-3.5" /> Add first channel
            </PrimaryButton>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {items.map((c) => (
            <ChannelCard
              key={c.id}
              c={c}
              onEdit={() => setEditing(c)}
              onDelete={() => handleDelete(c)}
              onTest={() => handleTest(c)}
            />
          ))}
        </div>
      )}

      {(creating || editing) && (
        <ChannelEditor
          orgId={orgId}
          channel={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={() => {
            setCreating(false);
            setEditing(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}

function ChannelCard({
  c,
  onEdit,
  onDelete,
  onTest,
}: {
  c: NotificationChannelResponse;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
}) {
  const meta = CHANNEL_KINDS.find((k) => k.value === c.kind);
  return (
    <Card>
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Pill>{meta?.label ?? c.kind}</Pill>
            {!c.enabled && <Pill tone={{ bg: "rgba(99,115,129,0.10)", fg: "#637381" }}>disabled</Pill>}
            {c.last_status === "succeeded" && (
              <Pill tone={{ bg: "rgba(34,197,94,0.10)", fg: "#1e8e3e" }}>healthy</Pill>
            )}
            {c.last_status === "failed" && (
              <Pill tone={{ bg: "rgba(183,29,24,0.10)", fg: "#B71D18" }}>failing</Pill>
            )}
          </div>
          <div className="text-[14px] font-semibold truncate" style={{ color: "var(--color-ink)" }}>
            {c.name}
          </div>
          {c.last_used_at && (
            <div className="text-[11px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Last used {timeAgo(c.last_used_at)} · {c.last_status ?? "—"}
            </div>
          )}
          {c.last_error && (
            <div className="text-[11px] mt-1 px-2 py-1" style={{ background: "rgba(255,86,48,0.08)", borderRadius: 4, color: "#B71D18" }}>
              {c.last_error}
            </div>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: "1px solid var(--color-border)" }}>
        <GhostButton onClick={onTest}>
          <Send className="w-3.5 h-3.5" /> Test
        </GhostButton>
        <GhostButton onClick={onEdit}>
          <SettingsIcon className="w-3.5 h-3.5" /> Edit
        </GhostButton>
        <div className="flex-1" />
        <button
          onClick={onDelete}
          className="inline-flex items-center justify-center w-9 h-9"
          title="Delete"
          style={{
            borderRadius: 5,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "#B71D18",
          }}
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </Card>
  );
}

function ChannelEditor({
  orgId,
  channel,
  onClose,
  onSaved,
}: {
  orgId: string;
  channel: NotificationChannelResponse | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = Boolean(channel);
  const [name, setName] = useState(channel?.name ?? "");
  const [kind, setKind] = useState<NotificationChannelKind>(
    (channel?.kind as NotificationChannelKind) ?? "slack",
  );
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [configText, setConfigText] = useState<string>(
    channel ? JSON.stringify(channel.config ?? {}, null, 2) : "{}",
  );
  const [secret, setSecret] = useState("");
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  const meta = CHANNEL_KINDS.find((k) => k.value === kind);

  async function handleSave() {
    let parsedConfig: Record<string, unknown> = {};
    try {
      parsedConfig = JSON.parse(configText || "{}");
    } catch {
      toast("error", "Config must be valid JSON");
      return;
    }
    setSaving(true);
    try {
      if (isEdit && channel) {
        await api.notifications.updateChannel(channel.id, {
          name,
          config: parsedConfig,
          enabled,
          secret: secret ? secret : undefined,
        });
      } else {
        await api.notifications.createChannel({
          organization_id: orgId,
          name,
          kind,
          config: parsedConfig,
          enabled,
          secret: secret || undefined,
        });
      }
      toast("success", isEdit ? "Channel updated" : "Channel created");
      onSaved();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title={isEdit ? `Edit channel — ${channel?.name}` : "New channel"} onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name">
          <TextInput value={name} onChange={setName} placeholder="Production SOC Slack" />
        </Field>

        <Field label="Adapter kind">
          <Select<NotificationChannelKind>
            value={kind}
            onChange={(v) => setKind(v)}
            options={CHANNEL_KINDS.map((k) => ({ value: k.value, label: k.label }))}
            disabled={isEdit}
          />
        </Field>

        <Field label="Config (JSON)" hint={meta?.configHint}>
          <TextArea value={configText} onChange={setConfigText} mono rows={6} />
        </Field>

        <Field
          label={isEdit ? `Rotate secret — ${meta?.secret}` : `Secret — ${meta?.secret}`}
          hint={isEdit ? "Leave blank to keep existing" : undefined}
        >
          <TextInput
            type="password"
            value={secret}
            onChange={setSecret}
            placeholder={isEdit ? "(unchanged)" : meta?.secret ?? ""}
          />
        </Field>

        <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--color-body)" }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
      </div>

      <ModalFooter>
        <GhostButton onClick={onClose}>
          <X className="w-3.5 h-3.5" /> Cancel
        </GhostButton>
        <PrimaryButton onClick={handleSave} disabled={saving || !name}>
          <Save className="w-3.5 h-3.5" /> {saving ? "Saving…" : "Save"}
        </PrimaryButton>
      </ModalFooter>
    </ModalShell>
  );
}

// ─── Tab: Rules ─────────────────────────────────────────────────────────

function RulesTab({ orgId }: { orgId: string }) {
  const [rules, setRules] = useState<NotificationRuleResponse[]>([]);
  const [channels, setChannels] = useState<NotificationChannelResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<NotificationRuleResponse | null>(null);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [r, c] = await Promise.all([
        api.notifications.listRules(orgId),
        api.notifications.listChannels(orgId),
      ]);
      setRules(r);
      setChannels(c);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load rules");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleDelete(r: NotificationRuleResponse) {
    if (!window.confirm(`Delete rule "${r.name}"?`)) return;
    try {
      await api.notifications.deleteRule(r.id);
      toast("success", "Rule deleted");
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to delete");
    }
  }

  async function handleToggle(r: NotificationRuleResponse) {
    try {
      await api.notifications.updateRule(r.id, { enabled: !r.enabled });
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to toggle");
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {rules.length} rule{rules.length === 1 ? "" : "s"}
        </div>
        <PrimaryButton onClick={() => setCreating(true)} disabled={channels.length === 0}>
          <Plus className="w-3.5 h-3.5" /> New rule
        </PrimaryButton>
      </div>

      {channels.length === 0 && (
        <Card>
          <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
            Create a channel first — rules need at least one fan-out target.
          </div>
        </Card>
      )}

      {loading ? (
        <Card>
          <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading…
          </div>
        </Card>
      ) : rules.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center py-8 text-center">
            <ListChecks className="w-7 h-7 mb-3" style={{ color: "var(--color-muted)" }} />
            <div className="text-[14px] font-medium mb-1" style={{ color: "var(--color-ink)" }}>
              No rules configured
            </div>
            <div className="text-[12px] mb-3" style={{ color: "var(--color-muted)" }}>
              A rule routes events to channels based on kind, severity and tags.
            </div>
          </div>
        </Card>
      ) : (
        <div className="space-y-2">
          {rules.map((r) => (
            <RuleCard
              key={r.id}
              rule={r}
              channels={channels}
              onEdit={() => setEditing(r)}
              onDelete={() => handleDelete(r)}
              onToggle={() => handleToggle(r)}
            />
          ))}
        </div>
      )}

      {(creating || editing) && (
        <RuleEditor
          orgId={orgId}
          channels={channels}
          rule={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={() => {
            setCreating(false);
            setEditing(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}

function RuleCard({
  rule,
  channels,
  onEdit,
  onDelete,
  onToggle,
}: {
  rule: NotificationRuleResponse;
  channels: NotificationChannelResponse[];
  onEdit: () => void;
  onDelete: () => void;
  onToggle: () => void;
}) {
  const channelNames = rule.channel_ids
    .map((id) => channels.find((c) => c.id === id)?.name ?? id.slice(0, 6))
    .slice(0, 3);
  const hasQuiet = Boolean(rule.quiet_hours);
  return (
    <Card>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <div className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              {rule.name}
            </div>
            <Pill tone={rule.enabled ? { bg: "rgba(34,197,94,0.10)", fg: "#1e8e3e" } : undefined}>
              {rule.enabled ? "enabled" : "disabled"}
            </Pill>
            <Pill tone={SEV_TONE[rule.min_severity]}>≥ {rule.min_severity}</Pill>
            {hasQuiet && <Pill tone={{ bg: "rgba(255,171,0,0.12)", fg: "#7B4B00" }}>quiet hours</Pill>}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[12px]">
            <div>
              <div className="font-semibold mb-0.5" style={{ color: "var(--color-muted)" }}>
                Event kinds
              </div>
              <div style={{ color: "var(--color-body)" }}>
                {rule.event_kinds.length === 0
                  ? "ALL"
                  : rule.event_kinds.slice(0, 4).join(", ") +
                    (rule.event_kinds.length > 4 ? ` +${rule.event_kinds.length - 4}` : "")}
              </div>
            </div>
            <div>
              <div className="font-semibold mb-0.5" style={{ color: "var(--color-muted)" }}>
                Channels
              </div>
              <div style={{ color: "var(--color-body)" }}>
                {channelNames.join(", ")}
                {rule.channel_ids.length > 3 ? ` +${rule.channel_ids.length - 3}` : ""}
              </div>
            </div>
            <div>
              <div className="font-semibold mb-0.5" style={{ color: "var(--color-muted)" }}>
                Dedup window
              </div>
              <div style={{ color: "var(--color-body)" }}>{rule.dedup_window_seconds}s</div>
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <GhostButton onClick={onToggle}>
            {rule.enabled ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {rule.enabled ? "Disable" : "Enable"}
          </GhostButton>
          <GhostButton onClick={onEdit}>
            <SettingsIcon className="w-3.5 h-3.5" /> Edit
          </GhostButton>
          <button
            onClick={onDelete}
            className="inline-flex items-center justify-center w-9 h-9"
            title="Delete"
            style={{
              borderRadius: 5,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "#B71D18",
            }}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </Card>
  );
}

function RuleEditor({
  orgId,
  channels,
  rule,
  onClose,
  onSaved,
}: {
  orgId: string;
  channels: NotificationChannelResponse[];
  rule: NotificationRuleResponse | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = Boolean(rule);
  const [name, setName] = useState(rule?.name ?? "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [eventKinds, setEventKinds] = useState<string[]>(rule?.event_kinds ?? []);
  const [minSev, setMinSev] = useState<Severity>((rule?.min_severity as Severity) ?? "medium");
  const [criticalities, setCriticalities] = useState<string[]>(rule?.asset_criticalities ?? []);
  const [assetTypes, setAssetTypes] = useState<string[]>(rule?.asset_types ?? []);
  const [tagsText, setTagsText] = useState<string>((rule?.tags_any ?? []).join(", "));
  const [chanIds, setChanIds] = useState<string[]>(rule?.channel_ids ?? []);
  const [dedup, setDedup] = useState<number>(rule?.dedup_window_seconds ?? 300);
  const [quietEnabled, setQuietEnabled] = useState<boolean>(Boolean(rule?.quiet_hours));
  const [qh, setQh] = useState<NotificationQuietHours>(
    rule?.quiet_hours ?? { start: "22:00", end: "07:00", tz: "UTC", except_severity: null },
  );
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  function toggleSet(set: string[], v: string): string[] {
    return set.includes(v) ? set.filter((x) => x !== v) : [...set, v];
  }

  async function handleSave() {
    if (chanIds.length === 0) {
      toast("error", "Pick at least one channel");
      return;
    }
    const tags = tagsText
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    const payload = {
      name,
      enabled,
      event_kinds: eventKinds,
      min_severity: minSev,
      asset_criticalities: criticalities,
      asset_types: assetTypes,
      tags_any: tags,
      channel_ids: chanIds,
      dedup_window_seconds: dedup,
      quiet_hours: quietEnabled ? qh : null,
    };
    setSaving(true);
    try {
      if (isEdit && rule) {
        await api.notifications.updateRule(rule.id, payload);
      } else {
        await api.notifications.createRule({
          organization_id: orgId,
          ...payload,
        });
      }
      toast("success", isEdit ? "Rule updated" : "Rule created");
      onSaved();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <ModalShell title={isEdit ? `Edit rule — ${rule?.name}` : "New rule"} onClose={onClose}>
      <div className="space-y-4">
        <Field label="Name">
          <TextInput value={name} onChange={setName} placeholder="Critical alerts → SOC pager" />
        </Field>

        <Field label="Event kinds (none = all)">
          <div className="flex flex-wrap gap-1.5">
            {EVENT_KINDS.map((ek) => {
              const on = eventKinds.includes(ek);
              return (
                <button
                  key={ek}
                  type="button"
                  onClick={() => setEventKinds((prev) => toggleSet(prev, ek))}
                  className="px-2.5 py-1 text-[11px] font-semibold transition-colors"
                  style={{
                    borderRadius: 4,
                    border: "1px solid var(--color-border)",
                    background: on ? "var(--color-surface-dark)" : "var(--color-canvas)",
                    color: on ? "var(--color-on-dark)" : "var(--color-body)",
                  }}
                >
                  {ek}
                </button>
              );
            })}
          </div>
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Minimum severity">
            <Select<Severity>
              value={minSev}
              onChange={(v) => setMinSev(v)}
              options={SEVERITIES.map((s) => ({ value: s, label: s }))}
            />
          </Field>
          <Field label="Dedup window (seconds)">
            <TextInput
              type="number"
              value={String(dedup)}
              onChange={(v) => setDedup(Math.max(0, parseInt(v || "0", 10)))}
            />
          </Field>
        </div>

        <Field label="Asset criticalities (none = all)">
          <div className="flex flex-wrap gap-1.5">
            {["crown_jewel", "high", "medium", "low"].map((c) => {
              const on = criticalities.includes(c);
              return (
                <button
                  key={c}
                  type="button"
                  onClick={() => setCriticalities((prev) => toggleSet(prev, c))}
                  className="px-2.5 py-1 text-[11px] font-semibold"
                  style={{
                    borderRadius: 4,
                    border: "1px solid var(--color-border)",
                    background: on ? "var(--color-surface-dark)" : "var(--color-canvas)",
                    color: on ? "var(--color-on-dark)" : "var(--color-body)",
                  }}
                >
                  {c}
                </button>
              );
            })}
          </div>
        </Field>

        <Field label="Tags-any (comma separated, none = match any)">
          <TextInput value={tagsText} onChange={setTagsText} placeholder="phishing, credential" />
        </Field>

        <Field label="Channels (fan-out)">
          <div className="flex flex-col gap-1.5">
            {channels.map((c) => {
              const on = chanIds.includes(c.id);
              const meta = CHANNEL_KINDS.find((k) => k.value === c.kind);
              return (
                <label
                  key={c.id}
                  className="flex items-center gap-2 px-2 py-1.5 text-[12px] cursor-pointer transition-colors"
                  style={{
                    borderRadius: 4,
                    border: `1px solid ${on ? "var(--color-border-strong)" : "var(--color-border)"}`,
                    background: on ? "rgba(0,123,196,0.05)" : "var(--color-canvas)",
                    color: "var(--color-body)",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={() => setChanIds((prev) => toggleSet(prev, c.id))}
                  />
                  <span style={{ color: "var(--color-ink)", fontWeight: 600 }}>{c.name}</span>
                  <Pill>{meta?.label ?? c.kind}</Pill>
                </label>
              );
            })}
          </div>
        </Field>

        <div
          className="p-3"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: 5,
            background: "var(--color-surface-muted)",
          }}
        >
          <label className="flex items-center gap-2 text-[12px] font-semibold mb-2">
            <input
              type="checkbox"
              checked={quietEnabled}
              onChange={(e) => setQuietEnabled(e.target.checked)}
            />
            Quiet hours
          </label>
          {quietEnabled && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              <Field label="Start (HH:MM)">
                <TextInput value={qh.start} onChange={(v) => setQh({ ...qh, start: v })} />
              </Field>
              <Field label="End (HH:MM)">
                <TextInput value={qh.end} onChange={(v) => setQh({ ...qh, end: v })} />
              </Field>
              <Field label="Timezone">
                <TextInput value={qh.tz} onChange={(v) => setQh({ ...qh, tz: v })} />
              </Field>
              <Field label="Bypass severity">
                <Select<string>
                  value={qh.except_severity ?? ""}
                  onChange={(v) => setQh({ ...qh, except_severity: v || null })}
                  options={[
                    { value: "", label: "(none)" },
                    ...SEVERITIES.map((s) => ({ value: s, label: s })),
                  ]}
                />
              </Field>
            </div>
          )}
        </div>

        <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--color-body)" }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
      </div>

      <ModalFooter>
        <GhostButton onClick={onClose}>
          <X className="w-3.5 h-3.5" /> Cancel
        </GhostButton>
        <PrimaryButton onClick={handleSave} disabled={saving || !name}>
          <Save className="w-3.5 h-3.5" /> {saving ? "Saving…" : "Save"}
        </PrimaryButton>
      </ModalFooter>
    </ModalShell>
  );
}

// ─── Tab: Delivery Log ──────────────────────────────────────────────────

function DeliveriesTab({ orgId }: { orgId: string }) {
  const [items, setItems] = useState<NotificationDeliveryResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [eventKindFilter, setEventKindFilter] = useState<string>("");
  const [channels, setChannels] = useState<NotificationChannelResponse[]>([]);
  const [channelFilter, setChannelFilter] = useState<string>("");
  const [open, setOpen] = useState<NotificationDeliveryResponse | null>(null);
  const { toast } = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [d, c] = await Promise.all([
        api.notifications.listDeliveries({
          organization_id: orgId,
          status: statusFilter || undefined,
          event_kind: eventKindFilter || undefined,
          channel_id: channelFilter || undefined,
          limit: 200,
        }),
        api.notifications.listChannels(orgId),
      ]);
      setItems(d.data);
      setChannels(c);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load deliveries");
    } finally {
      setLoading(false);
    }
  }, [orgId, statusFilter, eventKindFilter, channelFilter, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div style={{ minWidth: 160 }}>
          <Select<string>
            value={statusFilter}
            onChange={setStatusFilter}
            options={[
              { value: "", label: "All statuses" },
              { value: "succeeded", label: "Succeeded" },
              { value: "failed", label: "Failed" },
              { value: "skipped", label: "Skipped" },
              { value: "pending", label: "Pending" },
            ]}
          />
        </div>
        <div style={{ minWidth: 200 }}>
          <Select<string>
            value={eventKindFilter}
            onChange={setEventKindFilter}
            options={[
              { value: "", label: "All event kinds" },
              ...EVENT_KINDS.map((k) => ({ value: k, label: k })),
            ]}
          />
        </div>
        <div style={{ minWidth: 220 }}>
          <Select<string>
            value={channelFilter}
            onChange={setChannelFilter}
            options={[
              { value: "", label: "All channels" },
              ...channels.map((c) => ({ value: c.id, label: c.name })),
            ]}
          />
        </div>
        <GhostButton onClick={refresh}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </GhostButton>
      </div>

      {loading ? (
        <Card>
          <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            Loading…
          </div>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
            No deliveries match these filters.
          </div>
        </Card>
      ) : (
        <Card padded={false}>
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr style={{ background: "var(--color-surface-muted)" }}>
                  {["When", "Status", "Severity", "Event", "Channel", "Latency", ""].map((h) => (
                    <th
                      key={h}
                      className="px-3 py-2 text-left font-semibold"
                      style={{ color: "var(--color-muted)", borderBottom: "1px solid var(--color-border)" }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((d) => {
                  const ch = channels.find((c) => c.id === d.channel_id);
                  return (
                    <tr key={d.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                      <td className="px-3 py-2" style={{ color: "var(--color-body)" }}>{timeAgo(d.created_at)}</td>
                      <td className="px-3 py-2">
                        <Pill
                          tone={{
                            bg: "rgba(99,115,129,0.1)",
                            fg: STATUS_TONE[d.status] ?? "#637381",
                          }}
                        >
                          {d.status}
                        </Pill>
                      </td>
                      <td className="px-3 py-2">
                        <Pill tone={SEV_TONE[d.event_severity]}>{d.event_severity}</Pill>
                      </td>
                      <td className="px-3 py-2" style={{ color: "var(--color-ink)" }}>{d.event_kind}</td>
                      <td className="px-3 py-2" style={{ color: "var(--color-body)" }}>{ch?.name ?? d.channel_id.slice(0, 8)}</td>
                      <td className="px-3 py-2" style={{ color: "var(--color-body)" }}>{d.latency_ms ?? "—"}ms</td>
                      <td className="px-3 py-2 text-right">
                        <button
                          onClick={() => setOpen(d)}
                          className="text-[12px] font-semibold"
                          style={{ color: "var(--color-accent)" }}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {open && <DeliveryDrawer delivery={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

function DeliveryDrawer({
  delivery,
  onClose,
}: {
  delivery: NotificationDeliveryResponse;
  onClose: () => void;
}) {
  return (
    <ModalShell title="Delivery details" onClose={onClose} wide>
      <div className="space-y-4 text-[12px]">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <KV label="Status" value={delivery.status} />
          <KV label="Event kind" value={delivery.event_kind} />
          <KV label="Severity" value={delivery.event_severity} />
          <KV label="Attempts" value={String(delivery.attempts)} />
          <KV label="Latency" value={`${delivery.latency_ms ?? "—"}ms`} />
          <KV label="HTTP" value={String(delivery.response_status ?? "—")} />
          {delivery.cluster_count != null && (
            <KV label="Cluster size" value={String(delivery.cluster_count)} />
          )}
          {delivery.event_dedup_key && (
            <KV label="Dedup key" value={delivery.event_dedup_key} mono />
          )}
        </div>

        {delivery.error_message && (
          <Field label="Error">
            <pre
              className="p-3 text-[11px] font-mono whitespace-pre-wrap"
              style={{
                background: "rgba(255,86,48,0.08)",
                color: "#B71D18",
                borderRadius: 5,
                border: "1px solid rgba(255,86,48,0.25)",
              }}
            >
              {delivery.error_message}
            </pre>
          </Field>
        )}

        <Field label="Event payload">
          <JsonBlock value={delivery.event_payload} />
        </Field>

        <Field label="Rendered payload (Bridge agents)">
          <JsonBlock value={delivery.rendered_payload ?? null} />
        </Field>

        {delivery.response_body && (
          <Field label="Response body (truncated)">
            <pre
              className="p-3 text-[11px] font-mono whitespace-pre-wrap"
              style={{
                background: "var(--color-surface-muted)",
                borderRadius: 5,
                border: "1px solid var(--color-border)",
                color: "var(--color-body)",
              }}
            >
              {delivery.response_body}
            </pre>
          </Field>
        )}
      </div>
      <ModalFooter>
        <PrimaryButton onClick={onClose}>
          <X className="w-3.5 h-3.5" /> Close
        </PrimaryButton>
      </ModalFooter>
    </ModalShell>
  );
}

function KV({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
        {label}
      </div>
      <div className={`text-[12px] ${mono ? "font-mono" : ""}`} style={{ color: "var(--color-ink)" }}>
        {value}
      </div>
    </div>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre
      className="p-3 text-[11px] font-mono whitespace-pre-wrap overflow-x-auto"
      style={{
        background: "var(--color-surface-muted)",
        borderRadius: 5,
        border: "1px solid var(--color-border)",
        color: "var(--color-body)",
        maxHeight: 320,
      }}
    >
      {value === null || value === undefined
        ? "—"
        : JSON.stringify(value, null, 2)}
    </pre>
  );
}

// ─── Tab: Preferences ───────────────────────────────────────────────────

function PreferencesTab({ orgId }: { orgId: string }) {
  const [prefs, setPrefs] = useState<NotificationPreferences | null>(null);
  const [channels, setChannels] = useState<NotificationChannelResponse[]>([]);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    (async () => {
      try {
        const [p, c] = await Promise.all([
          api.notifications.getMyPreferences(),
          orgId ? api.notifications.listChannels(orgId) : Promise.resolve([]),
        ]);
        setPrefs(p);
        setChannels(c);
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
          setPrefs({
            opt_out_channels: [],
            max_per_rule_per_hour: 0,
            escalation_after_min: 0,
            do_not_disturb: false,
            dnd_until: null,
          });
        } else {
          toast("error", e instanceof Error ? e.message : "Failed to load preferences");
        }
      } finally {
        setLoading(false);
      }
    })();
  }, [orgId, toast]);

  async function handleSave() {
    if (!prefs) return;
    setSaving(true);
    try {
      const saved = await api.notifications.putMyPreferences(prefs);
      setPrefs(saved);
      toast("success", "Preferences saved");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading || !prefs) {
    return (
      <Card>
        <div className="text-[13px]" style={{ color: "var(--color-muted)" }}>
          Loading preferences…
        </div>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <div className="text-[14px] font-semibold mb-3" style={{ color: "var(--color-ink)" }}>
          Do not disturb
        </div>
        <label className="flex items-center gap-2 text-[12px] mb-3" style={{ color: "var(--color-body)" }}>
          <input
            type="checkbox"
            checked={prefs.do_not_disturb}
            onChange={(e) => setPrefs({ ...prefs, do_not_disturb: e.target.checked })}
          />
          Mute every channel right now
        </label>
        <Field
          label="Auto-resume at (ISO timestamp, blank = indefinite)"
          hint="Eg. 2026-05-06T08:00:00Z"
        >
          <TextInput
            value={prefs.dnd_until ?? ""}
            onChange={(v) => setPrefs({ ...prefs, dnd_until: v || null })}
          />
        </Field>
      </Card>

      <Card>
        <div className="text-[14px] font-semibold mb-3" style={{ color: "var(--color-ink)" }}>
          Frequency &amp; escalation
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Max per rule per hour" hint="0 = unlimited">
            <TextInput
              type="number"
              value={String(prefs.max_per_rule_per_hour)}
              onChange={(v) =>
                setPrefs({ ...prefs, max_per_rule_per_hour: Math.max(0, parseInt(v || "0", 10)) })
              }
            />
          </Field>
          <Field label="Escalate if unread after (minutes)" hint="0 = no escalation">
            <TextInput
              type="number"
              value={String(prefs.escalation_after_min)}
              onChange={(v) =>
                setPrefs({ ...prefs, escalation_after_min: Math.max(0, parseInt(v || "0", 10)) })
              }
            />
          </Field>
        </div>
      </Card>

      <div className="md:col-span-2">
        <Card>
          <div className="text-[14px] font-semibold mb-3" style={{ color: "var(--color-ink)" }}>
            Opt out per channel
          </div>
          {channels.length === 0 ? (
            <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
              No channels configured for the selected organization.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {channels.map((c) => {
                const off = prefs.opt_out_channels.includes(c.id);
                return (
                  <label
                    key={c.id}
                    className="flex items-center gap-2 px-3 py-2 text-[12px] cursor-pointer"
                    style={{
                      border: `1px solid ${off ? "rgba(255,86,48,0.4)" : "var(--color-border)"}`,
                      borderRadius: 5,
                      background: off ? "rgba(255,86,48,0.05)" : "var(--color-canvas)",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={off}
                      onChange={() =>
                        setPrefs({
                          ...prefs,
                          opt_out_channels: off
                            ? prefs.opt_out_channels.filter((x) => x !== c.id)
                            : [...prefs.opt_out_channels, c.id],
                        })
                      }
                    />
                    <span style={{ color: "var(--color-ink)", fontWeight: 600 }}>{c.name}</span>
                    <Pill>{c.kind}</Pill>
                  </label>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      <div className="md:col-span-2 flex justify-end">
        <PrimaryButton onClick={handleSave} disabled={saving}>
          <Save className="w-3.5 h-3.5" /> {saving ? "Saving…" : "Save preferences"}
        </PrimaryButton>
      </div>
    </div>
  );
}

// ─── Modal shell — local lightweight ────────────────────────────────────

function ModalShell({
  title,
  onClose,
  wide = false,
  children,
}: {
  title: string;
  onClose: () => void;
  wide?: boolean;
  children: ReactNode;
}) {
  // Close on Escape.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.45)", zIndex: 100 }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="flex flex-col"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
          width: wide ? "min(900px, 95vw)" : "min(600px, 95vw)",
          maxHeight: "85vh",
        }}
      >
        <div
          className="flex items-center justify-between px-5 py-3"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <div className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>
            {title}
          </div>
          <button
            onClick={onClose}
            className="inline-flex items-center justify-center w-8 h-8"
            style={{
              borderRadius: 5,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="p-5 overflow-y-auto flex-1">{children}</div>
      </div>
    </div>
  );
}

function ModalFooter({ children }: { children: ReactNode }) {
  return (
    <div
      className="flex items-center justify-end gap-2 mt-5 pt-4"
      style={{ borderTop: "1px solid var(--color-border)" }}
    >
      {children}
    </div>
  );
}
