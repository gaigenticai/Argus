"use client";

import { useEffect, useState } from "react";
import {
  Puzzle,
  CheckCircle,
  Clock,
  AlertTriangle,
  Settings,
  Zap,
  RefreshCw,
  Loader2,
  X,
  Lock,
} from "lucide-react";
import { api, type IntegrationTool } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

const STATUS_CONFIG: Record<string, { label: string; icon: typeof CheckCircle; color: string; bg: string }> = {
  connected: { label: "Connected", icon: CheckCircle, color: "text-success-dark", bg: "bg-success-lighter" },
  error: { label: "Error", icon: AlertTriangle, color: "text-error-dark", bg: "bg-error-lighter" },
  unconfigured: { label: "Not Configured", icon: Clock, color: "text-grey-600", bg: "bg-grey-200" },
};

const CATEGORY_COLORS: Record<string, string> = {
  "Threat Intelligence": "#2196F3",
  "SIEM / EDR": "#00A76F",
  "Vulnerability Scanning": "#8E33FF",
  "Malware Analysis": "#FF5630",
  "Detection Rules": "#FFAB00",
  "OSINT": "#00BBD9",
  "Network IDS": "#FF8B00",
  "SOAR": "#FF6C40",
  "Phishing Simulation": "#8E33FF",
  "Cloud Security": "#00A76F",
};

export default function IntegrationsPage() {
  const [tools, setTools] = useState<IntegrationTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [configuring, setConfiguring] = useState<string | null>(null);
  const [configForm, setConfigForm] = useState({ api_url: "", api_key: "" });
  const [testing, setTesting] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<string | null>(null);
  const { toast } = useToast();

  const load = async () => {
    try {
      const data = await api.getIntegrations();
      setTools(data);
    } catch {
      // Fallback to empty — endpoint might not exist yet
      setTools([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleTest = async (name: string) => {
    setTesting(name);
    try {
      const result = await api.testIntegration(name);
      if (result.connected) {
        toast("success", `${name}: ${result.message}`);
      } else {
        toast("warning", `${name}: ${result.message}`);
      }
      await load();
    } catch {
      toast("error", `Failed to test ${name}`);
    } finally {
      setTesting(null);
    }
  };

  const handleSync = async (name: string) => {
    setSyncing(name);
    try {
      await api.syncIntegration(name);
      toast("success", `Sync dispatched for ${name}`);
    } catch (err) {
      toast("error", `Sync failed: ${err instanceof Error ? err.message : "Unknown"}`);
    } finally {
      setTimeout(() => setSyncing(null), 2000);
    }
  };

  const handleSaveConfig = async (name: string) => {
    try {
      await api.updateIntegration(name, {
        api_url: configForm.api_url,
        api_key: configForm.api_key || undefined,
        enabled: true,
      });
      toast("success", `${name} configured and enabled`);
      setConfiguring(null);
      await load();
    } catch {
      toast("error", `Failed to save configuration`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-[14px] text-grey-500">Loading integrations...</p>
        </div>
      </div>
    );
  }

  const connectedCount = tools.filter((t) => t.health_status === "connected").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Integrations</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Connect open-source security tools to build an all-in-one platform
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); load(); }}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 text-grey-700 hover:bg-grey-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 px-6 py-4 bg-white rounded-xl border border-grey-200">
        <div>
          <span className="text-[28px] font-extrabold text-grey-900">{tools.length}</span>
          <p className="text-[12px] text-grey-500">Available</p>
        </div>
        <div className="w-px h-10 bg-grey-200" />
        <div>
          <span className="text-[28px] font-extrabold text-success">{connectedCount}</span>
          <p className="text-[12px] text-grey-500">Connected</p>
        </div>
        <div className="w-px h-10 bg-grey-200" />
        <div>
          <span className="text-[28px] font-extrabold text-grey-500">{tools.length - connectedCount}</span>
          <p className="text-[12px] text-grey-500">Available to connect</p>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-2 text-[13px] text-grey-500">
          <Lock className="w-4 h-4" />
          All open-source with commercial-friendly licenses
        </div>
      </div>

      {/* Integration grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {tools.map((tool) => {
          const statusCfg = STATUS_CONFIG[tool.health_status] || STATUS_CONFIG.unconfigured;
          const StatusIcon = statusCfg.icon;
          const catColor = CATEGORY_COLORS[tool.category] || "#637381";
          const isConfiguring = configuring === tool.tool_name;
          const isTesting = testing === tool.tool_name;
          const isSyncing = syncing === tool.tool_name;

          return (
            <div
              key={tool.tool_name}
              className="bg-white rounded-xl border border-grey-200 overflow-hidden hover:border-grey-300 transition-colors"
            >
              <div className="p-5">
                <div className="flex items-start gap-4">
                  {/* Icon */}
                  <div
                    className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 text-[16px] font-extrabold text-white"
                    style={{ backgroundColor: catColor }}
                  >
                    {tool.display_name.charAt(0)}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-[15px] font-bold text-grey-900">{tool.display_name}</h3>
                      <span className={`inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full ${statusCfg.bg} ${statusCfg.color}`}>
                        <StatusIcon className="w-3 h-3" />
                        {statusCfg.label}
                      </span>
                    </div>
                    <p className="text-[13px] text-grey-600 leading-snug mb-2">
                      {tool.description}
                    </p>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-medium text-grey-500 bg-grey-100 px-2 py-0.5 rounded">
                        {tool.category}
                      </span>
                      <span className="text-[11px] font-mono text-grey-400">{tool.license}</span>
                      {tool.last_sync_at && (
                        <span className="text-[11px] text-grey-500">
                          Synced {timeAgo(tool.last_sync_at)}
                        </span>
                      )}
                    </div>
                    {tool.last_error && (
                      <p className="text-[11px] text-error mt-1 truncate">{tool.last_error}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Action bar */}
              <div className="flex items-center gap-2 px-5 py-3 border-t border-grey-100 bg-grey-50">
                <button
                  onClick={() => {
                    setConfiguring(isConfiguring ? null : tool.tool_name);
                    setConfigForm({ api_url: tool.api_url || "", api_key: "" });
                  }}
                  className="flex items-center gap-1.5 h-8 px-3 rounded-lg text-[12px] font-bold border border-grey-300 text-grey-700 hover:bg-white transition-colors"
                >
                  <Settings className="w-3.5 h-3.5" />
                  Configure
                </button>
                {tool.health_status !== "unconfigured" && (
                  <>
                    <button
                      onClick={() => handleTest(tool.tool_name)}
                      disabled={isTesting}
                      className="flex items-center gap-1.5 h-8 px-3 rounded-lg text-[12px] font-bold border border-grey-300 text-grey-700 hover:bg-white transition-colors disabled:opacity-50"
                    >
                      {isTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                      Test
                    </button>
                    {tool.enabled && (
                      <button
                        onClick={() => handleSync(tool.tool_name)}
                        disabled={isSyncing}
                        className="flex items-center gap-1.5 h-8 px-3 rounded-lg text-[12px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
                      >
                        {isSyncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                        Sync
                      </button>
                    )}
                  </>
                )}
              </div>

              {/* Config form */}
              {isConfiguring && (
                <div className="px-5 py-4 border-t border-grey-200 bg-grey-50">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-[13px] font-bold text-grey-800">Configure {tool.display_name}</h4>
                    <button onClick={() => setConfiguring(null)} className="p-1 hover:bg-grey-200 rounded">
                      <X className="w-4 h-4 text-grey-500" />
                    </button>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <label className="text-[12px] font-bold text-grey-600 mb-1 block">API URL</label>
                      <input
                        type="url"
                        value={configForm.api_url}
                        onChange={(e) => setConfigForm({ ...configForm, api_url: e.target.value })}
                        placeholder="https://opencti.example.com"
                        className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                      />
                    </div>
                    <div>
                      <label className="text-[12px] font-bold text-grey-600 mb-1 block">API Key</label>
                      <input
                        type="password"
                        value={configForm.api_key}
                        onChange={(e) => setConfigForm({ ...configForm, api_key: e.target.value })}
                        placeholder="Enter API key..."
                        className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                      />
                    </div>
                    <button
                      onClick={() => handleSaveConfig(tool.tool_name)}
                      className="h-9 px-4 rounded-lg text-[13px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors"
                    >
                      Save & Enable
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
