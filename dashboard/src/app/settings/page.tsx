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

export default function SettingsPage() {
  const { user, refreshUser } = useAuth();
  const { toast } = useToast();
  const [tab, setTab] = useState<TabId>("profile");

  const isAdmin = user?.role === "admin";

  const availableTabs = TABS.filter((t) => !t.adminOnly || isAdmin);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[22px] font-bold text-grey-900">Settings</h2>
        <p className="text-[14px] text-grey-500 mt-0.5">
          Manage your account, users, API keys, and audit logs
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-grey-200">
        {availableTabs.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id as TabId)}
              className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold border-b-2 transition-colors ${
                tab === t.id
                  ? "border-primary text-primary"
                  : "border-transparent text-grey-500 hover:text-grey-700"
              }`}
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
      <div className="bg-white rounded-xl border border-grey-200 p-6 space-y-6">
        <div>
          <h3 className="text-[16px] font-bold text-grey-900 mb-4">Account Details</h3>
          <div className="space-y-3">
            <div className="flex justify-between text-[13px]">
              <span className="text-grey-500">Email</span>
              <span className="text-grey-800 font-medium">{user.email}</span>
            </div>
            <div className="flex justify-between text-[13px]">
              <span className="text-grey-500">Username</span>
              <span className="text-grey-800 font-medium">{user.username}</span>
            </div>
            <div className="flex justify-between text-[13px]">
              <span className="text-grey-500">Role</span>
              <span className="text-grey-800 font-medium capitalize">{user.role}</span>
            </div>
            <div className="flex justify-between text-[13px]">
              <span className="text-grey-500">Member since</span>
              <span className="text-grey-800 font-medium">{formatDate(user.created_at)}</span>
            </div>
            {user.last_login_at && (
              <div className="flex justify-between text-[13px]">
                <span className="text-grey-500">Last login</span>
                <span className="text-grey-800 font-medium">{formatDate(user.last_login_at)}</span>
              </div>
            )}
          </div>
        </div>

        <hr className="border-grey-200" />

        <form onSubmit={handleUpdateProfile} className="space-y-4">
          <h3 className="text-[16px] font-bold text-grey-900">Update Profile</h3>
          <div>
            <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Display Name</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            />
          </div>

          <hr className="border-grey-200" />

          <h4 className="text-[14px] font-bold text-grey-800">Change Password</h4>
          <div>
            <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
              autoComplete="current-password"
            />
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
              autoComplete="new-password"
            />
          </div>
          <button
            type="submit"
            disabled={saving}
            className="h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
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

  // Create user form state
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

  useEffect(() => {
    load();
  }, [load]);

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
      setNewEmail("");
      setNewUsername("");
      setNewDisplayName("");
      setNewPassword("");
      setNewRole("viewer");
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
        <p className="text-[14px] text-grey-500">{total} users</p>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add User
          </button>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-grey-100">
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">User</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Email</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Role</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Status</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Login</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="h-[52px] border-b border-grey-100 last:border-b-0">
                  <td className="px-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-grey-200 flex items-center justify-center text-grey-600 text-[12px] font-bold">
                        {u.display_name?.charAt(0)?.toUpperCase() || "U"}
                      </div>
                      <div>
                        <div className="text-[13px] font-semibold text-grey-800">{u.display_name}</div>
                        <div className="text-[11px] text-grey-500">@{u.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 text-[13px] text-grey-600">{u.email}</td>
                  <td className="px-4">
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u, e.target.value)}
                      className="h-8 px-2 rounded-lg border border-grey-300 text-[12px] font-semibold outline-none focus:border-primary bg-white capitalize"
                    >
                      {USER_ROLES.map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4">
                    <span
                      className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${
                        u.is_active
                          ? "bg-success-lighter text-success-dark"
                          : "bg-grey-200 text-grey-600"
                      }`}
                    >
                      {u.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                    {u.last_login_at ? formatDate(u.last_login_at) : "Never"}
                  </td>
                  <td className="px-4">
                    <button
                      onClick={() => handleToggleActive(u)}
                      className="text-[12px] font-semibold text-grey-500 hover:text-grey-700 transition-colors"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowCreate(false)}>
          <div className="bg-white rounded-2xl shadow-z24 p-8 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">Create User</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 rounded hover:bg-grey-100">
                <X className="w-5 h-5 text-grey-500" />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Email</label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Username</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Display Name</label>
                <input
                  type="text"
                  required
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Password</label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary capitalize"
                >
                  {USER_ROLES.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>
              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
                >
                  {creating ? "Creating..." : "Create"}
                </button>
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

  useEffect(() => {
    load();
  }, [load]);

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
        <p className="text-[14px] text-grey-500">{keys.length} API keys</p>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create API Key
        </button>
      </div>

      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[200px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : keys.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[200px] text-grey-500">
            <Key className="w-8 h-8 mb-2 text-grey-400" />
            <p className="text-[14px]">No API keys yet</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-grey-100">
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Name</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Prefix</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Status</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Used</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Created</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="h-[52px] border-b border-grey-100 last:border-b-0">
                  <td className="px-4 text-[13px] font-semibold text-grey-800">{k.name}</td>
                  <td className="px-4 text-[13px] font-mono text-grey-600">{k.key_prefix}...</td>
                  <td className="px-4">
                    <span
                      className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${
                        k.is_active
                          ? "bg-success-lighter text-success-dark"
                          : "bg-grey-200 text-grey-600"
                      }`}
                    >
                      {k.is_active ? "Active" : "Revoked"}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                    {k.last_used_at ? formatDate(k.last_used_at) : "Never"}
                  </td>
                  <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                    {formatDate(k.created_at)}
                  </td>
                  <td className="px-4">
                    {k.is_active && (
                      <button
                        onClick={() => handleRevoke(k.id)}
                        className="flex items-center gap-1 text-[12px] font-semibold text-error hover:text-error-dark transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Revoke
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setShowCreate(false); setCreatedKey(null); }}>
          <div className="bg-white rounded-2xl shadow-z24 p-8 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">
                {createdKey ? "API Key Created" : "Create API Key"}
              </h3>
              <button onClick={() => { setShowCreate(false); setCreatedKey(null); }} className="p-1 rounded hover:bg-grey-100">
                <X className="w-5 h-5 text-grey-500" />
              </button>
            </div>

            {createdKey ? (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-warning-lighter border border-warning/30">
                  <p className="text-[13px] font-semibold text-warning-dark mb-2">
                    Copy this key now. It will not be shown again.
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-[13px] font-mono text-grey-800 bg-white px-3 py-2 rounded border border-grey-300 break-all">
                      {createdKey.raw_key}
                    </code>
                    <button
                      onClick={() => handleCopy(createdKey.raw_key)}
                      className="p-2 rounded-lg hover:bg-grey-100 transition-colors shrink-0"
                    >
                      {copied ? (
                        <Check className="w-4 h-4 text-success" />
                      ) : (
                        <Copy className="w-4 h-4 text-grey-500" />
                      )}
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => { setShowCreate(false); setCreatedKey(null); }}
                  className="w-full h-10 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors"
                >
                  Done
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreate} className="space-y-4">
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Key Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. CI/CD Pipeline"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowCreate(false)}
                    className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating}
                    className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
                  >
                    {creating ? "Creating..." : "Create"}
                  </button>
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

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-end">
        <div>
          <label className="block text-[11px] font-bold text-grey-500 uppercase tracking-wider mb-1">Action</label>
          <select
            value={action}
            onChange={(e) => { setAction(e.target.value); setOffset(0); }}
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
          >
            {AUDIT_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a === "all" ? "All actions" : a.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[11px] font-bold text-grey-500 uppercase tracking-wider mb-1">Since</label>
          <input
            type="date"
            value={since}
            onChange={(e) => { setSince(e.target.value); setOffset(0); }}
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
          />
        </div>
        <div>
          <label className="block text-[11px] font-bold text-grey-500 uppercase tracking-wider mb-1">Until</label>
          <input
            type="date"
            value={until}
            onChange={(e) => { setUntil(e.target.value); setOffset(0); }}
            className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
          />
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      <p className="text-[13px] text-grey-500">{total} entries</p>

      {/* Table */}
      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
            <p className="text-[14px]">No audit logs found</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-grey-100">
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Time</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Action</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Resource</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">IP</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="h-[52px] border-b border-grey-100 last:border-b-0">
                  <td className="px-4 text-[13px] text-grey-600 whitespace-nowrap">
                    {formatDate(log.timestamp)}
                  </td>
                  <td className="px-4">
                    <span className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-grey-200 text-grey-700">
                      {log.action.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] text-grey-600">
                    {log.resource_type && (
                      <span className="text-grey-500">
                        {log.resource_type}
                        {log.resource_id && (
                          <span className="font-mono text-[11px] ml-1 text-grey-400">
                            {log.resource_id.substring(0, 8)}...
                          </span>
                        )}
                      </span>
                    )}
                  </td>
                  <td className="px-4 text-[13px] text-grey-500 font-mono">
                    {log.ip_address || "-"}
                  </td>
                  <td className="px-4 text-[12px] text-grey-500 max-w-[200px] truncate">
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
          <p className="text-[13px] text-grey-500">
            Page {currentPage} of {totalPages}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors disabled:opacity-50"
            >
              Previous
            </button>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
