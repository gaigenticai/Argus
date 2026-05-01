"use client";

import { useEffect, useState, useCallback } from "react";
import {
  RefreshCw,
  Plus,
  X,
  Globe,
  ToggleLeft,
  ToggleRight,
  Zap,
} from "lucide-react";
import { api, type Source, type SourceTestResult } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate, timeAgo } from "@/lib/utils";

const SOURCE_TYPES = [
  "tor_forum",
  "tor_marketplace",
  "i2p_eepsite",
  "lokinet_site",
  "telegram_channel",
  "stealer_market",
  "ransomware_leak",
  "underground_forum",
  "matrix_room",
];

const HEALTH_BADGE: Record<string, { bg: string; color: string }> = {
  healthy: { bg: "rgba(0,167,111,0.1)", color: "#007B55" },
  degraded: { bg: "rgba(255,171,0,0.12)", color: "#B76E00" },
  unreachable: { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
  blocked: { bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
  unknown: { bg: "var(--color-surface-muted)", color: "var(--color-muted)" },
};

export default function SourcesPage() {
  const { toast } = useToast();
  const [sources, setSources] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState(SOURCE_TYPES[0]);
  const [formUrl, setFormUrl] = useState("");
  const [formMirrors, setFormMirrors] = useState("");
  const [formLanguage, setFormLanguage] = useState("en");
  const [formInterval, setFormInterval] = useState(30);
  const [formMaxPages, setFormMaxPages] = useState(5);
  const [formSelectors, setFormSelectors] = useState("");
  const [formNotes, setFormNotes] = useState("");
  const [creating, setCreating] = useState(false);

  const [editSource, setEditSource] = useState<Source | null>(null);
  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editInterval, setEditInterval] = useState(30);
  const [editMaxPages, setEditMaxPages] = useState(5);
  const [editNotes, setEditNotes] = useState("");
  const [editSelectors, setEditSelectors] = useState("");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getSources();
      setSources(data);
    } catch {
      toast("error", "Failed to load sources");
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      let selectors: Record<string, unknown> | undefined;
      if (formSelectors.trim()) selectors = JSON.parse(formSelectors);
      await api.createSource({
        name: formName,
        source_type: formType,
        url: formUrl,
        mirror_urls: formMirrors ? formMirrors.split("\n").map((s) => s.trim()).filter(Boolean) : undefined,
        language: formLanguage,
        crawl_interval_minutes: formInterval,
        max_pages: formMaxPages,
        selectors,
        notes: formNotes || undefined,
      });
      toast("success", `Source "${formName}" created`);
      setShowCreate(false);
      resetCreateForm();
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to create source");
    }
    setCreating(false);
  }

  function resetCreateForm() {
    setFormName(""); setFormType(SOURCE_TYPES[0]); setFormUrl("");
    setFormMirrors(""); setFormLanguage("en"); setFormInterval(30);
    setFormMaxPages(5); setFormSelectors(""); setFormNotes("");
  }

  async function handleTest(id: string) {
    setTesting(id);
    try {
      const result = await api.testSource(id);
      if (result.reachable && !result.blocked) {
        toast("success", `Reachable (${result.status_code}) in ${result.response_time_ms}ms`);
      } else if (result.blocked) {
        toast("warning", `Blocked: ${result.content_preview?.substring(0, 80) || "Detection triggered"}`);
      } else {
        toast("error", `Unreachable: ${result.error || "Connection failed"}`);
      }
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Test failed");
    }
    setTesting(null);
  }

  async function handleToggleEnabled(source: Source) {
    try {
      await api.updateSource(source.id, { enabled: !source.enabled });
      toast("success", `${source.name} ${source.enabled ? "disabled" : "enabled"}`);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to toggle source");
    }
  }

  function openEdit(source: Source) {
    setEditSource(source);
    setEditName(source.name);
    setEditUrl(source.url);
    setEditInterval(source.crawl_interval_minutes);
    setEditMaxPages(source.max_pages);
    setEditNotes(source.notes || "");
    setEditSelectors(source.selectors ? JSON.stringify(source.selectors, null, 2) : "");
  }

  async function handleSaveEdit(e: React.FormEvent) {
    e.preventDefault();
    if (!editSource) return;
    setSaving(true);
    try {
      let selectors: Record<string, unknown> | undefined;
      if (editSelectors.trim()) selectors = JSON.parse(editSelectors);
      await api.updateSource(editSource.id, {
        name: editName,
        url: editUrl,
        crawl_interval_minutes: editInterval,
        max_pages: editMaxPages,
        notes: editNotes || undefined,
        selectors,
      });
      toast("success", "Source updated");
      setEditSource(null);
      load();
    } catch (err) {
      toast("error", err instanceof Error ? err.message : "Failed to update source");
    }
    setSaving(false);
  }

  const cardStyle = {
    background: "var(--color-canvas)",
    border: "1px solid var(--color-border)",
    borderRadius: "5px",
  } as React.CSSProperties;

  const inputCls = "w-full h-10 px-3 text-[13px] outline-none transition-colors";
  const inputStyle = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
  } as React.CSSProperties;

  const textareaCls = "w-full px-3 py-2 text-[13px] outline-none resize-none transition-colors";
  const btnPrimary = {
    borderRadius: "4px",
    border: "1px solid var(--color-accent)",
    background: "var(--color-accent)",
    color: "var(--color-on-dark)",
  } as React.CSSProperties;

  const btnSecondary = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-body)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Sources</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {sources.length} crawler sources configured
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={btnSecondary}
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={btnPrimary}
          >
            <Plus className="w-4 h-4" />
            Add Source
          </button>
        </div>
      </div>

      {/* Sources Table */}
      <div className="overflow-hidden" style={cardStyle}>
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div
              className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
              style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
            />
          </div>
        ) : sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px]" style={{ color: "var(--color-muted)" }}>
            <Globe className="w-8 h-8 mb-2" style={{ color: "var(--color-border)" }} />
            <p className="text-[13px]">No sources configured</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface-muted)" }}>
                  {["Name", "Type", "URL", "Health", "Enabled", "Last Crawled", "Items", "Actions"].map(h => (
                    <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const badge = HEALTH_BADGE[source.health_status] || HEALTH_BADGE.unknown;
                  return (
                    <tr
                      key={source.id}
                      className="h-[52px] transition-colors"
                      style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="px-4">
                        <button
                          onClick={() => openEdit(source)}
                          className="text-[13px] font-semibold text-left transition-colors"
                          style={{ color: "var(--color-ink)" }}
                          onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                          onMouseLeave={e => (e.currentTarget.style.color = "var(--color-ink)")}
                        >
                          {source.name}
                        </button>
                      </td>
                      <td className="px-4">
                        <span
                          className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                          style={{ borderRadius: "4px", background: "rgba(0,187,217,0.08)", color: "#007B8A" }}
                        >
                          {source.source_type.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-4 text-[13px] font-mono max-w-[200px] truncate" style={{ color: "var(--color-body)" }}>
                        {source.url}
                      </td>
                      <td className="px-4">
                        <span
                          className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                          style={{ borderRadius: "4px", background: badge.bg, color: badge.color }}
                        >
                          {source.health_status}
                        </span>
                      </td>
                      <td className="px-4">
                        <button onClick={() => handleToggleEnabled(source)} className="transition-colors">
                          {source.enabled ? (
                            <ToggleRight className="w-6 h-6" style={{ color: "var(--color-accent)" }} />
                          ) : (
                            <ToggleLeft className="w-6 h-6" style={{ color: "var(--color-muted)" }} />
                          )}
                        </button>
                      </td>
                      <td className="px-4 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                        {source.last_crawled_at ? timeAgo(source.last_crawled_at) : "Never"}
                      </td>
                      <td className="px-4 text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>
                        {source.total_items_collected.toLocaleString()}
                      </td>
                      <td className="px-4">
                        <button
                          onClick={() => handleTest(source.id)}
                          disabled={testing === source.id}
                          className="flex items-center gap-1 px-2.5 h-7 text-[12px] font-semibold transition-colors disabled:opacity-50"
                          style={{
                            borderRadius: "4px",
                            background: "var(--color-surface-muted)",
                            color: "var(--color-body)",
                          }}
                        >
                          <Zap className="w-3 h-3" />
                          {testing === source.id ? "Testing..." : "Test"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Source Modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto py-8"
          style={{ background: "rgba(32,21,21,0.5)" }}
          onClick={() => setShowCreate(false)}
        >
          <div
            className="p-8 w-full max-w-lg"
            style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-medium" style={{ color: "var(--color-ink)" }}>Add Source</h3>
              <button
                onClick={() => setShowCreate(false)}
                className="p-1 transition-colors"
                style={{ borderRadius: "4px" }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Name</label>
                <input type="text" required value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="e.g. BreachForums Main" className={inputCls} style={inputStyle} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Type</label>
                  <select value={formType} onChange={(e) => setFormType(e.target.value)} className={inputCls} style={inputStyle}>
                    {SOURCE_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Language</label>
                  <input type="text" value={formLanguage} onChange={(e) => setFormLanguage(e.target.value)} className={inputCls} style={inputStyle} />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>URL</label>
                <input type="text" required value={formUrl} onChange={(e) => setFormUrl(e.target.value)} placeholder="http://example.onion/..." className={inputCls + " font-mono"} style={inputStyle} />
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Mirror URLs (one per line)</label>
                <textarea value={formMirrors} onChange={(e) => setFormMirrors(e.target.value)} rows={2} className={textareaCls + " font-mono"} style={inputStyle} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Interval (min)</label>
                  <input type="number" value={formInterval} onChange={(e) => setFormInterval(Number(e.target.value))} min={1} className={inputCls} style={inputStyle} />
                </div>
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Max Pages</label>
                  <input type="number" value={formMaxPages} onChange={(e) => setFormMaxPages(Number(e.target.value))} min={1} className={inputCls} style={inputStyle} />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Selectors (JSON)</label>
                <textarea value={formSelectors} onChange={(e) => setFormSelectors(e.target.value)} rows={3} placeholder='{"post_selector": ".post-content"}' className={textareaCls + " font-mono text-[12px]"} style={inputStyle} />
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Notes</label>
                <textarea value={formNotes} onChange={(e) => setFormNotes(e.target.value)} rows={2} className={textareaCls} style={inputStyle} />
              </div>
              <div className="flex gap-2 pt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}>
                  Cancel
                </button>
                <button type="submit" disabled={creating} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>
                  {creating ? "Creating..." : "Create Source"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Source Modal */}
      {editSource && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto py-8"
          style={{ background: "rgba(32,21,21,0.5)" }}
          onClick={() => setEditSource(null)}
        >
          <div
            className="p-8 w-full max-w-lg"
            style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-medium" style={{ color: "var(--color-ink)" }}>Edit Source</h3>
              <button onClick={() => setEditSource(null)} className="p-1 transition-colors" style={{ borderRadius: "4px" }} onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>
            <form onSubmit={handleSaveEdit} className="space-y-4">
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Name</label>
                <input type="text" required value={editName} onChange={(e) => setEditName(e.target.value)} className={inputCls} style={inputStyle} />
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>URL</label>
                <input type="text" required value={editUrl} onChange={(e) => setEditUrl(e.target.value)} className={inputCls + " font-mono"} style={inputStyle} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Interval (min)</label>
                  <input type="number" value={editInterval} onChange={(e) => setEditInterval(Number(e.target.value))} min={1} className={inputCls} style={inputStyle} />
                </div>
                <div>
                  <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Max Pages</label>
                  <input type="number" value={editMaxPages} onChange={(e) => setEditMaxPages(Number(e.target.value))} min={1} className={inputCls} style={inputStyle} />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Selectors (JSON)</label>
                <textarea value={editSelectors} onChange={(e) => setEditSelectors(e.target.value)} rows={3} className={textareaCls + " font-mono text-[12px]"} style={inputStyle} />
              </div>
              <div>
                <label className="block text-[13px] font-semibold mb-1.5" style={{ color: "var(--color-body)" }}>Notes</label>
                <textarea value={editNotes} onChange={(e) => setEditNotes(e.target.value)} rows={2} className={textareaCls} style={inputStyle} />
              </div>
              <div className="flex gap-2 pt-2">
                <button type="button" onClick={() => setEditSource(null)} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}>
                  Cancel
                </button>
                <button type="submit" disabled={saving} className="flex-1 h-10 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50" style={btnPrimary}>
                  {saving ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
