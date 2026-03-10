"use client";

import { useEffect, useState, useCallback } from "react";
import {
  RefreshCw,
  Plus,
  X,
  Activity,
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

const HEALTH_COLORS: Record<string, { bg: string; text: string }> = {
  healthy: { bg: "bg-success-lighter", text: "text-success-dark" },
  degraded: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  unreachable: { bg: "bg-error-lighter", text: "text-error-dark" },
  blocked: { bg: "bg-error-lighter", text: "text-error-dark" },
  unknown: { bg: "bg-grey-200", text: "text-grey-600" },
};

export default function SourcesPage() {
  const { toast } = useToast();
  const [sources, setSources] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  // Create form
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

  // Edit modal
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

  useEffect(() => {
    load();
  }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      let selectors: Record<string, unknown> | undefined;
      if (formSelectors.trim()) {
        selectors = JSON.parse(formSelectors);
      }
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
    setFormName("");
    setFormType(SOURCE_TYPES[0]);
    setFormUrl("");
    setFormMirrors("");
    setFormLanguage("en");
    setFormInterval(30);
    setFormMaxPages(5);
    setFormSelectors("");
    setFormNotes("");
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
      if (editSelectors.trim()) {
        selectors = JSON.parse(editSelectors);
      }
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Sources</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            {sources.length} crawler sources configured
          </p>
        </div>
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
            Add Source
          </button>
        </div>
      </div>

      {/* Sources Table */}
      <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-[300px] text-grey-500">
            <Globe className="w-8 h-8 mb-2 text-grey-400" />
            <p className="text-[14px]">No sources configured</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-grey-100">
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Name</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Type</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">URL</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Health</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Enabled</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Crawled</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Items</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const health = HEALTH_COLORS[source.health_status] || HEALTH_COLORS.unknown;
                  return (
                    <tr key={source.id} className="h-[52px] border-b border-grey-100 last:border-b-0 hover:bg-grey-50 transition-colors">
                      <td className="px-4">
                        <button
                          onClick={() => openEdit(source)}
                          className="text-[13px] font-semibold text-grey-800 hover:text-primary transition-colors text-left"
                        >
                          {source.name}
                        </button>
                      </td>
                      <td className="px-4">
                        <span className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-secondary-lighter text-secondary-dark">
                          {source.source_type.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-4 text-[13px] text-grey-600 font-mono max-w-[200px] truncate">
                        {source.url}
                      </td>
                      <td className="px-4">
                        <span className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${health.bg} ${health.text}`}>
                          {source.health_status}
                        </span>
                      </td>
                      <td className="px-4">
                        <button onClick={() => handleToggleEnabled(source)} className="text-grey-500 hover:text-grey-700 transition-colors">
                          {source.enabled ? (
                            <ToggleRight className="w-6 h-6 text-primary" />
                          ) : (
                            <ToggleLeft className="w-6 h-6 text-grey-400" />
                          )}
                        </button>
                      </td>
                      <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
                        {source.last_crawled_at ? timeAgo(source.last_crawled_at) : "Never"}
                      </td>
                      <td className="px-4 text-[13px] text-grey-600 font-semibold">
                        {source.total_items_collected.toLocaleString()}
                      </td>
                      <td className="px-4">
                        <button
                          onClick={() => handleTest(source.id)}
                          disabled={testing === source.id}
                          className="flex items-center gap-1 px-2.5 h-7 rounded-lg text-[12px] font-bold bg-grey-100 text-grey-600 hover:bg-grey-200 transition-colors disabled:opacity-50"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 overflow-y-auto py-8" onClick={() => setShowCreate(false)}>
          <div className="bg-white rounded-2xl shadow-z24 p-8 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">Add Source</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 rounded hover:bg-grey-100">
                <X className="w-5 h-5 text-grey-500" />
              </button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Name</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. BreachForums Main"
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Type</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value)}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary"
                  >
                    {SOURCE_TYPES.map((t) => (
                      <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Language</label>
                  <input
                    type="text"
                    value={formLanguage}
                    onChange={(e) => setFormLanguage(e.target.value)}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">URL</label>
                <input
                  type="text"
                  required
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="http://example.onion/..."
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Mirror URLs (one per line)</label>
                <textarea
                  value={formMirrors}
                  onChange={(e) => setFormMirrors(e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[14px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Interval (min)</label>
                  <input
                    type="number"
                    value={formInterval}
                    onChange={(e) => setFormInterval(Number(e.target.value))}
                    min={1}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Max Pages</label>
                  <input
                    type="number"
                    value={formMaxPages}
                    onChange={(e) => setFormMaxPages(Number(e.target.value))}
                    min={1}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Selectors (JSON)</label>
                <textarea
                  value={formSelectors}
                  onChange={(e) => setFormSelectors(e.target.value)}
                  rows={3}
                  placeholder='{"post_selector": ".post-content", "author_selector": ".author"}'
                  className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[13px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Notes</label>
                <textarea
                  value={formNotes}
                  onChange={(e) => setFormNotes(e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
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
                  {creating ? "Creating..." : "Create Source"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Source Modal */}
      {editSource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 overflow-y-auto py-8" onClick={() => setEditSource(null)}>
          <div className="bg-white rounded-2xl shadow-z24 p-8 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">Edit Source</h3>
              <button onClick={() => setEditSource(null)} className="p-1 rounded hover:bg-grey-100">
                <X className="w-5 h-5 text-grey-500" />
              </button>
            </div>
            <form onSubmit={handleSaveEdit} className="space-y-4">
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Name</label>
                <input
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">URL</label>
                <input
                  type="text"
                  required
                  value={editUrl}
                  onChange={(e) => setEditUrl(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Interval (min)</label>
                  <input
                    type="number"
                    value={editInterval}
                    onChange={(e) => setEditInterval(Number(e.target.value))}
                    min={1}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Max Pages</label>
                  <input
                    type="number"
                    value={editMaxPages}
                    onChange={(e) => setEditMaxPages(Number(e.target.value))}
                    min={1}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Selectors (JSON)</label>
                <textarea
                  value={editSelectors}
                  onChange={(e) => setEditSelectors(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[13px] font-mono outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
              <div>
                <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">Notes</label>
                <textarea
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 rounded-lg border border-grey-300 bg-white text-[14px] outline-none focus:border-primary focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
              <div className="flex gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditSource(null)}
                  className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="flex-1 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
                >
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
