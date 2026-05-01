"use client";

import { useEffect, useState, useCallback } from "react";
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
} from "lucide-react";
import {
  api,
  type UserResponse,
  type APIKeyResponse,
  type APIKeyCreatedResponse,
  type AuditLogEntry,
} from "@/lib/api";
import { useAuth } from "@/components/auth/auth-provider";
import { useToast } from "@/components/shared/toast";
import { formatDate } from "@/lib/utils";

const TABS: { id: string; label: string; icon: typeof User; adminOnly?: boolean }[] = [
  { id: "profile", label: "Profile", icon: User },
  { id: "users", label: "Users", icon: Users, adminOnly: true },
  { id: "apikeys", label: "API Keys", icon: Key },
  { id: "audit", label: "Audit Log", icon: ScrollText, adminOnly: true },
];

type TabId = "profile" | "users" | "apikeys" | "audit";

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
  const [tab, setTab] = useState<TabId>("profile");

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
      {tab === "users" && isAdmin && <UsersTab />}
      {tab === "apikeys" && <APIKeysTab />}
      {tab === "audit" && isAdmin && <AuditTab />}
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
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u, e.target.value)}
                      className="h-8 px-2 text-[12px] font-semibold outline-none capitalize"
                      style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                    >
                      {USER_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
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
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full h-10 px-3 text-[13px] outline-none capitalize"
                  style={inputStyle}
                >
                  {USER_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
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
              <select
                value={action}
                onChange={(e) => { setAction(e.target.value); setOffset(0); }}
                className="h-10 px-3 text-[13px] outline-none"
                style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
              >
                {AUDIT_ACTIONS.map((a) => <option key={a} value={a}>{a === "all" ? "All actions" : a.replace(/_/g, " ")}</option>)}
              </select>
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
