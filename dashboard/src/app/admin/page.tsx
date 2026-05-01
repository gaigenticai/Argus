"use client";

/**
 * Admin / runtime configuration page.
 *
 * Backed by `/api/v1/admin/{settings,crawler-targets,feed-health,subsidiary-allowlist}`.
 * Every tab reads from the database on mount and writes through to the
 * same endpoints — there are no UI-only fields.
 *
 * Tabs:
 *   - Configuration:  AppSetting CRUD (typed key/value config)
 *   - Crawler Targets: CrawlerTarget CRUD (Tor / I2P / Matrix / Telegram / etc.)
 *   - Feed Health:    Read-only health panel + per-feed history
 *   - Subsidiary Allowlist: Domains / brand names that are NOT typosquats
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Settings as SettingsIcon,
  Bot,
  Activity,
  ShieldCheck,
  Clock,
  Plus,
  RefreshCw,
  Trash2,
  Save,
  Pencil,
  X,
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  CirclePause,
  ChevronRight,
  Link2Off,
} from "lucide-react";
import {
  api,
  type AppSettingCategory,
  type AppSettingResponse,
  type AppSettingValueType,
  type AllowlistEntry,
  type AllowlistKind,
  type CrawlerKind,
  type CrawlerTargetResponse,
  type FeedHealthEntry,
  type FeedHealthStatus,
  type SlaPolicyResponse,
  type SlaBreachResponse,
  type SlaTicketBindingResponse,
  type SlaTicketBindingCreatePayload,
} from "@/lib/api";
import { useAuth } from "@/components/auth/auth-provider";
import { useToast } from "@/components/shared/toast";
import { formatDate } from "@/lib/utils";

const TABS = [
  { id: "settings", label: "Configuration", icon: SettingsIcon },
  { id: "crawlers", label: "Crawler Targets", icon: Bot },
  { id: "feeds", label: "Feed Health", icon: Activity },
  { id: "allowlist", label: "Subsidiary Allowlist", icon: ShieldCheck },
  { id: "sla", label: "SLA Policies", icon: Clock },
] as const;

type TabId = (typeof TABS)[number]["id"];

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

export default function AdminPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<TabId>("settings");

  if (!user || user.role !== "admin") {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-center">
          <AlertTriangle className="w-10 h-10 mx-auto mb-3" style={{ color: "#FFAB00" }} />
          <p className="text-[16px] font-semibold" style={{ color: "var(--color-ink)" }}>Admin only</p>
          <p className="text-[13px] mt-1" style={{ color: "var(--color-muted)" }}>
            This page edits live runtime configuration. You need the admin role.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Admin</h2>
        <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          Database-backed runtime configuration. Every change is audit-logged with before/after JSON.
        </p>
      </div>

      <div className="flex gap-0" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {TABS.map((t) => {
          const Icon = t.icon;
          const isActive = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className="flex items-center gap-2 px-4 py-3 text-[13px] font-semibold transition-colors"
              style={{
                color: isActive ? "var(--color-accent)" : "var(--color-muted)",
                background: "transparent",
                boxShadow: isActive ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
              }}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "settings" && <SettingsTab />}
      {tab === "crawlers" && <CrawlerTargetsTab />}
      {tab === "feeds" && <FeedHealthTab />}
      {tab === "allowlist" && <AllowlistTab />}
      {tab === "sla" && <SlaTab />}
    </div>
  );
}

/* ─────────────────────────── Settings tab ─────────────────────────── */

const SETTING_CATEGORIES: AppSettingCategory[] = [
  "fraud", "impersonation", "brand", "rating", "auto_case", "crawler", "general",
];
const SETTING_TYPES: AppSettingValueType[] = ["string", "integer", "float", "boolean", "json"];

function SettingsTab() {
  const { toast } = useToast();
  const [rows, setRows] = useState<AppSettingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState<AppSettingCategory | "">("");
  const [showCreate, setShowCreate] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [draftValue, setDraftValue] = useState<string>("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.admin.listSettings(filterCategory || undefined);
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load settings");
    }
    setLoading(false);
  }, [filterCategory, toast]);

  useEffect(() => { load(); }, [load]);

  function startEdit(row: AppSettingResponse) {
    setEditingKey(row.key);
    setDraftValue(
      row.value_type === "json"
        ? JSON.stringify(row.value, null, 2)
        : String(row.value ?? ""),
    );
  }

  function cancelEdit() {
    setEditingKey(null);
    setDraftValue("");
  }

  async function saveEdit(row: AppSettingResponse) {
    let parsed: unknown;
    try {
      parsed = parseValue(row.value_type, draftValue);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Invalid value");
      return;
    }
    try {
      await api.admin.upsertSetting(row.key, {
        key: row.key, category: row.category, value_type: row.value_type,
        value: parsed, description: row.description, minimum: row.minimum, maximum: row.maximum,
      });
      toast("success", `Saved ${row.key}`);
      cancelEdit();
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Save failed");
    }
  }

  async function handleDelete(row: AppSettingResponse) {
    if (!confirm(`Reset ${row.key} to its in-code default?`)) return;
    try {
      await api.admin.deleteSetting(row.key);
      toast("success", `Reset ${row.key}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-2 items-end">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-[0.07em] mb-1" style={{ color: "var(--color-muted)" }}>Category</label>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value as AppSettingCategory | "")}
              className="h-10 px-3 text-[13px] outline-none"
              style={inputStyle}
            >
              <option value="">All</option>
              {SETTING_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        </div>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnPrimary}>
          <Plus className="w-4 h-4" /> New setting
        </button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? (
          <Spinner />
        ) : rows.length === 0 ? (
          <EmptyState icon={SettingsIcon} title="No settings yet" body="Detector defaults are baked in code; rows appear here the first time a detector reads a setting." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Key", "Category", "Type", "Value", "Updated", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const isEditing = editingKey === r.key;
                return (
                  <tr key={r.id} className="align-top" style={{ borderBottom: "1px solid var(--color-border)" }}>
                    <td className="px-4 py-3 text-[13px] font-mono font-semibold" style={{ color: "var(--color-ink)" }}>{r.key}</td>
                    <td className="px-4 py-3 text-[13px]"><Pill>{r.category}</Pill></td>
                    <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>{r.value_type}</td>
                    <td className="px-4 py-3 text-[13px] max-w-[420px]" style={{ color: "var(--color-body)" }}>
                      {isEditing ? (
                        <textarea
                          value={draftValue}
                          onChange={(e) => setDraftValue(e.target.value)}
                          rows={r.value_type === "json" ? 6 : 1}
                          className="w-full px-2 py-1 text-[12px] font-mono outline-none"
                          style={inputStyle}
                        />
                      ) : (
                        <code className="text-[12px] font-mono break-all whitespace-pre-wrap" style={{ color: "var(--color-body)" }}>
                          {formatSettingValue(r.value, r.value_type)}
                        </code>
                      )}
                      {r.description && !isEditing && (
                        <p className="text-[11px] mt-1" style={{ color: "var(--color-muted)" }}>{r.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(r.updated_at)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {isEditing ? (
                        <div className="flex gap-1">
                          <button onClick={() => saveEdit(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#22C55E" }}>
                            <Save className="w-3.5 h-3.5" /> Save
                          </button>
                          <button onClick={cancelEdit} className="flex items-center gap-1 text-[12px] font-semibold ml-3 transition-colors" style={{ color: "var(--color-muted)" }}>
                            <X className="w-3.5 h-3.5" /> Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex gap-3">
                          <button onClick={() => startEdit(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "var(--color-accent)" }}>
                            <Pencil className="w-3.5 h-3.5" /> Edit
                          </button>
                          <button onClick={() => handleDelete(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#FF5630" }}>
                            <Trash2 className="w-3.5 h-3.5" /> Reset
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && (
        <SettingCreateModal onClose={() => setShowCreate(false)} onSaved={() => { setShowCreate(false); load(); }} />
      )}
    </div>
  );
}

function SettingCreateModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { toast } = useToast();
  const [key, setKey] = useState("");
  const [category, setCategory] = useState<AppSettingCategory>("general");
  const [valueType, setValueType] = useState<AppSettingValueType>("float");
  const [valueStr, setValueStr] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const value = parseValue(valueType, valueStr);
      await api.admin.upsertSetting(key, { key, category, value_type: valueType, value, description: description || null });
      toast("success", `Created ${key}`);
      onSaved();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Save failed");
    }
    setSaving(false);
  }

  return (
    <Modal title="New setting" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Key (dotted, unique)">
          <input type="text" required value={key} onChange={(e) => setKey(e.target.value)} placeholder="e.g. fraud.threshold" className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Category">
            <select value={category} onChange={(e) => setCategory(e.target.value as AppSettingCategory)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
              {SETTING_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </Field>
          <Field label="Type">
            <select value={valueType} onChange={(e) => setValueType(e.target.value as AppSettingValueType)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
              {SETTING_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
        </div>
        <Field label="Value">
          <textarea required value={valueStr} onChange={(e) => setValueStr(e.target.value)} rows={valueType === "json" ? 6 : 1} placeholder={valueType === "json" ? '{"weight": 0.45}' : valueType === "boolean" ? "true / false" : valueType === "integer" ? "42" : valueType === "float" ? "0.4" : "value"} className="w-full px-3 py-2 text-[13px] font-mono outline-none" style={inputStyle} />
        </Field>
        <Field label="Description (optional)">
          <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle} />
        </Field>
        <div className="flex gap-2 pt-2">
          <button type="button" onClick={onClose} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>Cancel</button>
          <button type="submit" disabled={saving} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>{saving ? "Saving..." : "Create"}</button>
        </div>
      </form>
    </Modal>
  );
}

/* ─────────────────────────── Crawler Targets tab ─────────────────────────── */

const CRAWLER_KINDS: { value: CrawlerKind; label: string; idHint: string }[] = [
  { value: "tor_forum", label: "Tor — forum", idHint: "http://abcdef.onion/forum" },
  { value: "tor_marketplace", label: "Tor — marketplace", idHint: "http://abcdef.onion/" },
  { value: "i2p_eepsite", label: "I2P — eepsite", idHint: "http://example.i2p/" },
  { value: "lokinet_site", label: "Lokinet site", idHint: "http://example.loki/" },
  { value: "telegram_channel", label: "Telegram channel", idHint: "@channel-name" },
  { value: "matrix_room", label: "Matrix room", idHint: "!room:matrix.org" },
  { value: "forum", label: "Clearnet forum", idHint: "https://forum.example.com/" },
  { value: "ransomware_leak_group", label: "Ransomware leak group", idHint: "http://leak.onion/" },
  { value: "stealer_marketplace", label: "Stealer marketplace", idHint: "http://stealer.onion/" },
];

function CrawlerTargetsTab() {
  const { toast } = useToast();
  const [rows, setRows] = useState<CrawlerTargetResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [filterKind, setFilterKind] = useState<CrawlerKind | "">("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.admin.listCrawlerTargets(filterKind ? { kind: filterKind } : undefined);
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load");
    }
    setLoading(false);
  }, [filterKind, toast]);

  useEffect(() => { load(); }, [load]);

  async function toggleActive(r: CrawlerTargetResponse) {
    try {
      await api.admin.updateCrawlerTarget(r.id, { is_active: !r.is_active });
      toast("success", `${r.identifier} ${r.is_active ? "disabled" : "enabled"}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Update failed");
    }
  }

  async function handleDelete(r: CrawlerTargetResponse) {
    if (!confirm(`Remove crawler target ${r.identifier}?`)) return;
    try {
      await api.admin.deleteCrawlerTarget(r.id);
      toast("success", `Removed ${r.identifier}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-2 items-end">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-[0.07em] mb-1" style={{ color: "var(--color-muted)" }}>Kind</label>
            <select value={filterKind} onChange={(e) => setFilterKind(e.target.value as CrawlerKind | "")} className="h-10 px-3 text-[13px] outline-none" style={inputStyle}>
              <option value="">All kinds</option>
              {CRAWLER_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
          </div>
          <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}><RefreshCw className="w-4 h-4" /> Refresh</button>
        </div>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnPrimary}><Plus className="w-4 h-4" /> New target</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={Bot} title="No crawler targets yet" body="Without a target the crawlers are dormant. Add a Tor / I2P / Matrix / Telegram target above to activate." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Kind", "Identifier", "Status", "Last run", "Failures", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="align-top" style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 py-3 text-[13px]"><Pill>{r.kind}</Pill></td>
                  <td className="px-4 py-3 text-[13px] max-w-[300px]">
                    <div className="font-semibold truncate" style={{ color: "var(--color-ink)" }}>{r.display_name || r.identifier}</div>
                    <div className="font-mono text-[11px] truncate" style={{ color: "var(--color-muted)" }}>{r.identifier}</div>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleActive(r)}
                      className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center transition-opacity hover:opacity-80"
                      style={{ borderRadius: "4px", background: r.is_active ? "rgba(0,167,111,0.1)" : "var(--color-surface-muted)", color: r.is_active ? "#007B55" : "var(--color-muted)" }}
                    >
                      {r.is_active ? "Active" : "Paused"}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                    {r.last_run_at ? (
                      <>
                        <div>{formatDate(r.last_run_at)}</div>
                        <div className="text-[11px]">{r.last_run_status || "—"}</div>
                      </>
                    ) : <span className="italic">never</span>}
                  </td>
                  <td className="px-4 py-3 text-[13px]">
                    {r.consecutive_failures > 0 ? (
                      <span className="font-semibold" style={{ color: "#FF5630" }}>{r.consecutive_failures}</span>
                    ) : <span style={{ color: "var(--color-muted)" }}>0</span>}
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleDelete(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#FF5630" }}>
                      <Trash2 className="w-3.5 h-3.5" /> Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && <CrawlerTargetCreateModal onClose={() => setShowCreate(false)} onSaved={() => { setShowCreate(false); load(); }} />}
    </div>
  );
}

function CrawlerTargetCreateModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { toast } = useToast();
  const [kind, setKind] = useState<CrawlerKind>("tor_forum");
  const [identifier, setIdentifier] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [configJson, setConfigJson] = useState("{}");
  const [saving, setSaving] = useState(false);

  const idHint = useMemo(() => CRAWLER_KINDS.find((k) => k.value === kind)?.idHint, [kind]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      let config: Record<string, unknown> = {};
      try { config = configJson.trim() ? JSON.parse(configJson) : {}; }
      catch { toast("error", "Config must be valid JSON"); setSaving(false); return; }
      await api.admin.createCrawlerTarget({ kind, identifier: identifier.trim(), display_name: displayName.trim() || undefined, config, is_active: true });
      toast("success", `Added ${identifier}`);
      onSaved();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Save failed");
    }
    setSaving(false);
  }

  return (
    <Modal title="New crawler target" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value as CrawlerKind)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
            {CRAWLER_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </Field>
        <Field label="Identifier (URL / handle / room id)">
          <input type="text" required value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder={idHint} className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
        </Field>
        <Field label="Display name (optional)">
          <input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle} />
        </Field>
        <Field label="Crawler-specific config (JSON)">
          <textarea value={configJson} onChange={(e) => setConfigJson(e.target.value)} rows={6} placeholder='{"keywords": ["mybank"], "selector_profile": "xenforo"}' className="w-full px-3 py-2 text-[13px] font-mono outline-none" style={inputStyle} />
        </Field>
        <div className="flex gap-2 pt-2">
          <button type="button" onClick={onClose} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>Cancel</button>
          <button type="submit" disabled={saving} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>{saving ? "Saving..." : "Create"}</button>
        </div>
      </form>
    </Modal>
  );
}

/* ─────────────────────────── Feed Health tab ─────────────────────────── */

function FeedHealthTab() {
  const { toast } = useToast();
  const [rows, setRows] = useState<FeedHealthEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeFeed, setActiveFeed] = useState<string | null>(null);
  const [history, setHistory] = useState<FeedHealthEntry[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.admin.listFeedHealth();
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load");
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  async function openHistory(feed: string) {
    setActiveFeed(feed);
    try {
      const data = await api.admin.feedHealthHistory(feed, 100);
      setHistory(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load history");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>Latest run per feed. Click a row to see history.</p>
        <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={Activity} title="No feed runs recorded yet" body="Once the worker dispatches a feed, a row will land here. Missing API keys appear as 'unconfigured', not as silent zeros." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Feed", "Status", "Rows ingested", "Duration", "Detail", "Last run", " "].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} onClick={() => openHistory(r.feed_name)} className="cursor-pointer transition-colors" style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 py-3 text-[13px] font-mono font-semibold" style={{ color: "var(--color-ink)" }}>{r.feed_name}</td>
                  <td className="px-4 py-3"><FeedStatusBadge status={r.status} /></td>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>{r.rows_ingested.toLocaleString()}</td>
                  <td className="px-4 py-3 text-[13px]" style={{ color: "var(--color-muted)" }}>{r.duration_ms != null ? `${r.duration_ms} ms` : "—"}</td>
                  <td className="px-4 py-3 text-[12px] max-w-[300px] truncate" style={{ color: "var(--color-muted)" }}>{r.detail || "—"}</td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(r.observed_at)}</td>
                  <td className="px-4 py-3"><ChevronRight className="w-4 h-4" style={{ color: "var(--color-muted)" }} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {activeFeed && (
        <Modal title={`History — ${activeFeed}`} onClose={() => { setActiveFeed(null); setHistory([]); }} wide>
          <div className="max-h-[60vh] overflow-y-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                  {["When", "Status", "Rows", "Duration", "Detail"].map((h) => (
                    <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                    <td className="px-4 py-2 text-[12px] whitespace-nowrap" style={{ color: "var(--color-body)" }}>{formatDate(h.observed_at)}</td>
                    <td className="px-4 py-2"><FeedStatusBadge status={h.status} /></td>
                    <td className="px-4 py-2 text-[12px] font-mono" style={{ color: "var(--color-body)" }}>{h.rows_ingested}</td>
                    <td className="px-4 py-2 text-[12px]" style={{ color: "var(--color-muted)" }}>{h.duration_ms != null ? `${h.duration_ms} ms` : "—"}</td>
                    <td className="px-4 py-2 text-[12px] max-w-[400px] break-words" style={{ color: "var(--color-muted)" }}>{h.detail || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Modal>
      )}
    </div>
  );
}

function FeedStatusBadge({ status }: { status: FeedHealthStatus }) {
  const config: Record<FeedHealthStatus, { bg: string; color: string; label: string; Icon: typeof CheckCircle2 }> = {
    ok:            { bg: "rgba(0,167,111,0.1)",  color: "#007B55",  label: "ok",            Icon: CheckCircle2 },
    unconfigured:  { bg: "rgba(255,171,0,0.1)",  color: "#B76E00",  label: "unconfigured",  Icon: CircleAlert },
    auth_error:    { bg: "rgba(255,86,48,0.1)",  color: "#B71D18",  label: "auth error",    Icon: AlertTriangle },
    network_error: { bg: "rgba(255,86,48,0.1)",  color: "#B71D18",  label: "network error", Icon: AlertTriangle },
    rate_limited:  { bg: "rgba(255,171,0,0.1)",  color: "#B76E00",  label: "rate limited",  Icon: CircleAlert },
    parse_error:   { bg: "rgba(255,86,48,0.1)",  color: "#B71D18",  label: "parse error",   Icon: AlertTriangle },
    disabled:      { bg: "var(--color-surface-muted)", color: "var(--color-muted)", label: "disabled", Icon: CirclePause },
  };
  const c = config[status] || config.disabled;
  const I = c.Icon;
  return (
    <span className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center gap-1" style={{ borderRadius: "4px", background: c.bg, color: c.color }}>
      <I className="w-3 h-3" /> {c.label}
    </span>
  );
}

/* ─────────────────────────── Allowlist tab ─────────────────────────── */

const ALLOWLIST_KINDS: { value: AllowlistKind; label: string }[] = [
  { value: "domain", label: "Domain" },
  { value: "brand_name", label: "Brand name" },
  { value: "email_domain", label: "Email domain" },
];

function AllowlistTab() {
  const { toast } = useToast();
  const [rows, setRows] = useState<AllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.admin.listAllowlist();
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load");
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  async function handleDelete(r: AllowlistEntry) {
    if (!confirm(`Remove ${r.kind} ${r.value} from allowlist?`)) return;
    try {
      await api.admin.removeAllowlistEntry(r.id);
      toast("success", `Removed ${r.value}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px] max-w-2xl" style={{ color: "var(--color-muted)" }}>
          Domains, email domains, and brand names that legitimately belong to you. The brand-typosquat scanner consults this list before creating a SuspectDomain row.
        </p>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnPrimary}><Plus className="w-4 h-4" /> Add entry</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="Allowlist empty" body="Add your subsidiary domains and brand names so the typosquat scanner doesn't flag them as impersonators." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Kind", "Value", "Note", "Added", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 py-3 text-[13px]"><Pill>{r.kind}</Pill></td>
                  <td className="px-4 py-3 text-[13px] font-mono font-semibold" style={{ color: "var(--color-ink)" }}>{r.value}</td>
                  <td className="px-4 py-3 text-[12px] max-w-[400px] truncate" style={{ color: "var(--color-muted)" }}>{r.note || "—"}</td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(r.created_at)}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleDelete(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#FF5630" }}>
                      <Trash2 className="w-3.5 h-3.5" /> Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && <AllowlistCreateModal onClose={() => setShowCreate(false)} onSaved={() => { setShowCreate(false); load(); }} />}
    </div>
  );
}

function AllowlistCreateModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { toast } = useToast();
  const [kind, setKind] = useState<AllowlistKind>("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await api.admin.addAllowlistEntry({ kind, value: value.trim(), note: note.trim() || undefined });
      toast("success", `Added ${value}`);
      onSaved();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Save failed");
    }
    setSaving(false);
  }

  return (
    <Modal title="New allowlist entry" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value as AllowlistKind)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
            {ALLOWLIST_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </Field>
        <Field label="Value">
          <input type="text" required value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === "brand_name" ? "MyBank Cards" : "subsidiary.example.com"} className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
        </Field>
        <Field label="Note (optional)">
          <input type="text" value={note} onChange={(e) => setNote(e.target.value)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle} />
        </Field>
        <div className="flex gap-2 pt-2">
          <button type="button" onClick={onClose} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>Cancel</button>
          <button type="submit" disabled={saving} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>{saving ? "Saving..." : "Add"}</button>
        </div>
      </form>
    </Modal>
  );
}

/* ─────────────────────────── SLA Policies tab ─────────────────────────── */

const SLA_SEVERITIES = ["critical", "high", "medium", "low"] as const;
type SlaSeverity = (typeof SLA_SEVERITIES)[number];

const SLA_SYSTEMS = ["jira", "servicenow", "linear", "github", "custom"] as const;
type SlaSystem = (typeof SLA_SYSTEMS)[number];

function SlaTab() {
  const { toast } = useToast();
  const [orgId, setOrgId] = useState<string | null>(null);

  useEffect(() => {
    api.getOrgs().then((orgs) => { if (orgs[0]) setOrgId(orgs[0].id); }).catch((err) => {
      toast("error", err instanceof Error ? err.message : "Failed to load organization");
    });
  }, [toast]);

  if (!orgId) return <Spinner />;

  return (
    <div className="space-y-8">
      <SlaPoliciesSection orgId={orgId} />
      <SlaBreachesSection orgId={orgId} />
      <SlaTicketBindingsSection orgId={orgId} />
    </div>
  );
}

function SlaPoliciesSection({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<SlaPolicyResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState<SlaSeverity>("critical");
  const [firstResponse, setFirstResponse] = useState<string>("60");
  const [remediation, setRemediation] = useState<string>("480");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.sla.listPolicies(orgId);
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load SLA policies");
    }
    setLoading(false);
  }, [orgId, toast]);

  useEffect(() => { load(); }, [load]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    const frMin = parseInt(firstResponse, 10);
    const remMin = parseInt(remediation, 10);
    if (!Number.isFinite(frMin) || frMin <= 0) { toast("error", "First response minutes must be a positive integer"); return; }
    if (!Number.isFinite(remMin) || remMin <= 0) { toast("error", "Remediation minutes must be a positive integer"); return; }
    setSaving(true);
    try {
      await api.sla.upsertPolicy({ organization_id: orgId, severity, first_response_minutes: frMin, remediation_minutes: remMin });
      toast("success", `Saved SLA policy for ${severity}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Save failed");
    }
    setSaving(false);
  }

  async function handleDelete(row: SlaPolicyResponse) {
    if (!confirm(`Delete SLA policy for ${row.severity}?`)) return;
    try {
      await api.sla.deletePolicy(row.id);
      toast("success", `Deleted SLA policy for ${row.severity}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>Policies</h3>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>Define first-response and remediation SLA targets per severity level.</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={Clock} title="No SLA policies yet" body="Use the form below to add a policy for each severity level." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Severity", "First Response (min)", "Remediation (min)", "Updated", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <td className="px-4 py-3 text-[13px]"><SlaSeverityPill severity={r.severity} /></td>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-ink)" }}>{r.first_response_minutes.toLocaleString()}</td>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-ink)" }}>{r.remediation_minutes.toLocaleString()}</td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(r.updated_at)}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleDelete(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#FF5630" }}>
                      <Trash2 className="w-3.5 h-3.5" /> Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="p-6" style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}>
        <h4 className="text-[13px] font-semibold mb-4" style={{ color: "var(--color-ink)" }}>Add / Update Policy</h4>
        <form onSubmit={handleSave} className="flex flex-wrap gap-4 items-end">
          <div className="flex-1 min-w-[140px]">
            <Field label="Severity">
              <select value={severity} onChange={(e) => setSeverity(e.target.value as SlaSeverity)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
                {SLA_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>
          <div className="flex-1 min-w-[160px]">
            <Field label="First Response (min)">
              <input type="number" required min={1} value={firstResponse} onChange={(e) => setFirstResponse(e.target.value)} className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
            </Field>
          </div>
          <div className="flex-1 min-w-[160px]">
            <Field label="Remediation (min)">
              <input type="number" required min={1} value={remediation} onChange={(e) => setRemediation(e.target.value)} className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
            </Field>
          </div>
          <button type="submit" disabled={saving} className="flex items-center gap-2 h-10 px-6 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>
            <Save className="w-4 h-4" /> {saving ? "Saving..." : "Save"}
          </button>
        </form>
      </div>
    </div>
  );
}

function SlaBreachesSection({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<SlaBreachResponse[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.sla.listBreaches({ organization_id: orgId });
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load SLA breaches");
    }
    setLoading(false);
  }, [orgId, toast]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>Breaches</h3>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>Cases where the SLA threshold was exceeded.</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={CheckCircle2} title="No SLA breaches" body="All cases are on track. Breaches will appear here when a first-response or remediation deadline is missed." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Case ID", "Kind", "Severity", "Threshold (min)", "Detected", "Notified?"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>…{r.case_id.slice(-8)}</td>
                  <td className="px-4 py-3 text-[13px]"><Pill>{r.kind === "first_response" ? "first response" : "remediation"}</Pill></td>
                  <td className="px-4 py-3 text-[13px]"><SlaSeverityPill severity={r.severity} /></td>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-ink)" }}>{r.threshold_minutes.toLocaleString()}</td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(r.detected_at)}</td>
                  <td className="px-4 py-3 text-[13px]">
                    {r.notified ? (
                      <span className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center" style={{ borderRadius: "4px", background: "rgba(0,167,111,0.1)", color: "#007B55" }}>Yes</span>
                    ) : (
                      <span className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-muted)" }}>No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function SlaTicketBindingsSection({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<SlaTicketBindingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [caseId, setCaseId] = useState("");
  const [system, setSystem] = useState<SlaSystem>("jira");
  const [externalId, setExternalId] = useState("");
  const [binding, setBinding] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.sla.listTickets({ organization_id: orgId });
      setRows(data);
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to load ticket bindings");
    }
    setLoading(false);
  }, [orgId, toast]);

  useEffect(() => { load(); }, [load]);

  async function handleBind(e: React.FormEvent) {
    e.preventDefault();
    if (!caseId.trim() || !externalId.trim()) { toast("error", "Case ID and External ID are required"); return; }
    setBinding(true);
    try {
      const payload: SlaTicketBindingCreatePayload = { organization_id: orgId, case_id: caseId.trim(), system, external_id: externalId.trim() };
      await api.sla.bindTicket(payload);
      toast("success", `Bound ${system} ticket ${externalId}`);
      setCaseId(""); setExternalId("");
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Bind failed");
    }
    setBinding(false);
  }

  async function handleUnbind(row: SlaTicketBindingResponse) {
    if (!confirm(`Unbind ${row.system} ticket ${row.external_id}?`)) return;
    try {
      await api.sla.unbindTicket(row.id);
      toast("success", `Unbound ticket ${row.external_id}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Unbind failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--color-ink)" }}>Ticket Bindings</h3>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>Link cases to external ticketing systems (Jira, ServiceNow, Linear, GitHub, etc.).</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 h-10 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
        {loading ? <Spinner /> : rows.length === 0 ? (
          <EmptyState icon={Clock} title="No ticket bindings yet" body="Use the form below to link a case to an external ticket in Jira, ServiceNow, Linear, GitHub, or a custom system." />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Case ID", "System", "External ID", "Status", "Last Sync", "Actions"].map((h) => (
                  <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>…{r.case_id.slice(-8)}</td>
                  <td className="px-4 py-3 text-[13px]"><Pill>{r.system}</Pill></td>
                  <td className="px-4 py-3 text-[13px] font-mono" style={{ color: "var(--color-ink)" }}>
                    {r.external_url ? (
                      <a href={r.external_url} target="_blank" rel="noopener noreferrer" className="transition-colors" style={{ color: "var(--color-accent)" }} onMouseEnter={e => (e.currentTarget.style.textDecoration = "underline")} onMouseLeave={e => (e.currentTarget.style.textDecoration = "none")}>{r.external_id}</a>
                    ) : r.external_id}
                  </td>
                  <td className="px-4 py-3 text-[13px]">
                    {r.status ? <Pill>{r.status}</Pill> : <span style={{ color: "var(--color-muted)" }}>—</span>}
                  </td>
                  <td className="px-4 py-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                    {r.last_synced_at ? formatDate(r.last_synced_at) : <span className="italic">never</span>}
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleUnbind(r)} className="flex items-center gap-1 text-[12px] font-semibold transition-colors" style={{ color: "#FF5630" }}>
                      <Link2Off className="w-3.5 h-3.5" /> Unbind
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="p-6" style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}>
        <h4 className="text-[13px] font-semibold mb-4" style={{ color: "var(--color-ink)" }}>Bind Ticket</h4>
        <form onSubmit={handleBind} className="flex flex-wrap gap-4 items-end">
          <div className="flex-1 min-w-[200px]">
            <Field label="Case ID">
              <input type="text" required value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
            </Field>
          </div>
          <div className="flex-1 min-w-[140px]">
            <Field label="System">
              <select value={system} onChange={(e) => setSystem(e.target.value as SlaSystem)} className="w-full h-10 px-3 text-[13px] outline-none" style={inputStyle}>
                {SLA_SYSTEMS.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>
          <div className="flex-1 min-w-[160px]">
            <Field label="External ID">
              <input type="text" required value={externalId} onChange={(e) => setExternalId(e.target.value)} placeholder="e.g. PROJECT-123" className="w-full h-10 px-3 text-[13px] font-mono outline-none" style={inputStyle} />
            </Field>
          </div>
          <button type="submit" disabled={binding} className="flex items-center gap-2 h-10 px-6 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>
            <Plus className="w-4 h-4" /> {binding ? "Binding..." : "Bind"}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ── SLA severity colour pill ── */

function SlaSeverityPill({ severity }: { severity: string }) {
  const cfg: Record<string, { bg: string; color: string }> = {
    critical: { bg: "rgba(255,86,48,0.1)",  color: "#B71D18" },
    high:     { bg: "rgba(255,171,0,0.1)",  color: "#B76E00" },
    medium:   { bg: "rgba(255,214,102,0.15)", color: "#B76E00" },
    low:      { bg: "var(--color-surface-muted)", color: "var(--color-muted)" },
  };
  const c = cfg[severity.toLowerCase()] ?? cfg.low;
  return (
    <span className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center" style={{ borderRadius: "4px", background: c.bg, color: c.color }}>
      {severity}
    </span>
  );
}

/* ─────────────────────────── Shared UI ─────────────────────────── */

function Pill({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
      {children}
    </span>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[12px] font-semibold uppercase tracking-[0.07em] mb-1.5" style={{ color: "var(--color-muted)" }}>{label}</label>
      {children}
    </div>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center h-[300px]">
      <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
    </div>
  );
}

function EmptyState({ icon: Icon, title, body }: { icon: typeof SettingsIcon; title: string; body: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-[300px] text-center px-6">
      <Icon className="w-8 h-8 mb-3" style={{ color: "var(--color-border)" }} />
      <p className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{title}</p>
      <p className="text-[12px] mt-1 max-w-md" style={{ color: "var(--color-muted)" }}>{body}</p>
    </div>
  );
}

function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(32,21,21,0.5)" }} onClick={onClose}>
      <div className={`p-8 w-full ${wide ? "max-w-4xl" : "max-w-md"}`} style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-[17px] font-semibold" style={{ color: "var(--color-ink)" }}>{title}</h3>
          <button onClick={onClose} className="p-1 transition-opacity hover:opacity-70">
            <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ─────────────────────────── helpers ─────────────────────────── */

function parseValue(type: AppSettingValueType, raw: string): unknown {
  const trimmed = raw.trim();
  switch (type) {
    case "string": return trimmed;
    case "integer": {
      if (!/^-?\d+$/.test(trimmed)) throw new Error("Value must be an integer");
      return parseInt(trimmed, 10);
    }
    case "float": {
      const n = Number(trimmed);
      if (!Number.isFinite(n)) throw new Error("Value must be a number");
      return n;
    }
    case "boolean": {
      const lower = trimmed.toLowerCase();
      if (["true", "1", "yes", "on"].includes(lower)) return true;
      if (["false", "0", "no", "off"].includes(lower)) return false;
      throw new Error("Boolean must be true/false");
    }
    case "json":
      if (!trimmed) return null;
      try { return JSON.parse(trimmed); }
      catch { throw new Error("JSON value is not valid JSON"); }
  }
}

function formatSettingValue(value: unknown, type: AppSettingValueType): string {
  if (value === null || value === undefined) return "—";
  if (type === "json") return JSON.stringify(value, null, 2);
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}
