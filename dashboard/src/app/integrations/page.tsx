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
  PackagePlus,
} from "lucide-react";
import { api, type IntegrationTool } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

const STATUS_CONFIG: Record<string, { label: string; icon: typeof CheckCircle; bg: string; color: string }> = {
  connected: { label: "Connected", icon: CheckCircle, bg: "rgba(0,167,111,0.1)", color: "#007B55" },
  error: { label: "Error", icon: AlertTriangle, bg: "rgba(255,86,48,0.1)", color: "#B71D18" },
  available: { label: "Available", icon: PackagePlus, bg: "rgba(0,187,217,0.1)", color: "#007B8A" },
  unconfigured: { label: "Not Configured", icon: Clock, bg: "var(--color-surface-muted)", color: "var(--color-muted)" },
};

const CATEGORY_COLORS: Record<string, string> = {
  "Threat Intelligence": "#2196F3",
  "SIEM / EDR": "#00A76F",
  "Vulnerability Scanning": "var(--color-accent)",
  "Malware Analysis": "#FF5630",
  "Detection Rules": "#FFAB00",
  "OSINT": "#00BBD9",
  "Network IDS": "#FF8B00",
  "SOAR": "#FF6C40",
  "Phishing Simulation": "var(--color-accent)",
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
      setTools([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

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
      setConfigForm({ api_url: "", api_key: "" });
      await load();
    } catch {
      toast("error", `Failed to save configuration`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div
            className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
          <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>Loading integrations...</p>
        </div>
      </div>
    );
  }

  const connectedCount = tools.filter((t) => t.health_status === "connected").length;
  const availableCount = tools.filter((t) => t.health_status === "available").length;

  const inputCls = "w-full h-10 px-3 text-[13px] outline-none transition-colors";
  const inputStyle = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Integrations
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Open-source security tools — installed locally or connect your own instances
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); load(); }}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-body)",
          }}
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Stats bar */}
      <div
        className="flex items-center gap-6 px-6 py-4"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        <div>
          <span className="text-[28px] font-bold" style={{ color: "var(--color-ink)" }}>{tools.length}</span>
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Total</p>
        </div>
        <div className="w-px h-10" style={{ background: "var(--color-border)" }} />
        <div>
          <span className="text-[28px] font-bold" style={{ color: "#00A76F" }}>{connectedCount}</span>
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Installed</p>
        </div>
        <div className="w-px h-10" style={{ background: "var(--color-border)" }} />
        <div>
          <span className="text-[28px] font-bold" style={{ color: "#00BBD9" }}>{availableCount}</span>
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Available</p>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-2 text-[13px]" style={{ color: "var(--color-muted)" }}>
          <Lock className="w-4 h-4" />
          All open-source with commercial-friendly licenses
        </div>
      </div>

      {/* Integration grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {tools.map((tool) => {
          const statusCfg = STATUS_CONFIG[tool.health_status] || STATUS_CONFIG.unconfigured;
          const StatusIcon = statusCfg.icon;
          const catColor = CATEGORY_COLORS[tool.category] || "var(--color-muted)";
          const isConfiguring = configuring === tool.tool_name;
          const isTesting = testing === tool.tool_name;
          const isSyncing = syncing === tool.tool_name;

          return (
            <div
              key={tool.tool_name}
              className="overflow-hidden transition-colors"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
              }}
            >
              <div className="p-5">
                <div className="flex items-start gap-4">
                  {/* Icon */}
                  <div
                    className="w-11 h-11 flex items-center justify-center shrink-0 text-[16px] font-bold text-white"
                    style={{ borderRadius: "5px", backgroundColor: catColor }}
                  >
                    {tool.display_name.charAt(0)}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>{tool.display_name}</h3>
                      <span
                        className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5"
                        style={{
                          borderRadius: "20px",
                          background: statusCfg.bg,
                          color: statusCfg.color,
                        }}
                      >
                        <StatusIcon className="w-3 h-3" />
                        {statusCfg.label}
                      </span>
                    </div>
                    <p className="text-[13px] leading-snug mb-2" style={{ color: "var(--color-body)" }}>
                      {tool.description}
                    </p>
                    <div className="flex items-center gap-3">
                      <span
                        className="text-[11px] font-medium px-2 py-0.5"
                        style={{
                          borderRadius: "4px",
                          background: "var(--color-surface-muted)",
                          color: "var(--color-muted)",
                        }}
                      >
                        {tool.category}
                      </span>
                      <span className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>{tool.license}</span>
                      {tool.last_sync_at && (
                        <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                          Synced {timeAgo(tool.last_sync_at)}
                        </span>
                      )}
                    </div>
                    {tool.last_error && (
                      <p className="text-[11px] mt-1 truncate" style={{ color: "var(--color-error)" }}>{tool.last_error}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Action bar */}
              <div
                className="flex items-center gap-2 px-5 py-3"
                style={{
                  borderTop: "1px solid var(--color-border)",
                  background: "var(--color-surface)",
                }}
              >
                <button
                  onClick={() => {
                    setConfiguring(isConfiguring ? null : tool.tool_name);
                    setConfigForm({ api_url: tool.api_url || "", api_key: "" });
                  }}
                  className="flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold transition-colors"
                  style={{
                    borderRadius: "4px",
                    border: "1px solid var(--color-border)",
                    background: "var(--color-canvas)",
                    color: "var(--color-body)",
                  }}
                >
                  <Settings className="w-3.5 h-3.5" />
                  Configure
                </button>
                {tool.health_status !== "unconfigured" && (
                  <>
                    <button
                      onClick={() => handleTest(tool.tool_name)}
                      disabled={isTesting}
                      className="flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold transition-colors disabled:opacity-50"
                      style={{
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                        background: "var(--color-canvas)",
                        color: "var(--color-body)",
                      }}
                    >
                      {isTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                      Test
                    </button>
                    {tool.enabled && (
                      <button
                        onClick={() => handleSync(tool.tool_name)}
                        disabled={isSyncing}
                        className="flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold transition-colors disabled:opacity-50"
                        style={{
                          borderRadius: "4px",
                          border: "1px solid var(--color-accent)",
                          background: "var(--color-accent)",
                          color: "var(--color-on-dark)",
                        }}
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
                <div
                  className="px-5 py-4"
                  style={{
                    borderTop: "1px solid var(--color-border)",
                    background: "var(--color-surface)",
                  }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>Configure {tool.display_name}</h4>
                    <button
                      onClick={() => setConfiguring(null)}
                      className="p-1 transition-colors"
                      style={{ borderRadius: "4px" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <X className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                    </button>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <label className="text-[12px] font-semibold mb-1 block" style={{ color: "var(--color-muted)" }}>API URL</label>
                      <input
                        type="url"
                        value={configForm.api_url}
                        onChange={(e) => setConfigForm({ ...configForm, api_url: e.target.value })}
                        placeholder="https://opencti.example.com"
                        className={inputCls}
                        style={inputStyle}
                      />
                    </div>
                    <div>
                      <label className="text-[12px] font-semibold mb-1 block" style={{ color: "var(--color-muted)" }}>API Key</label>
                      <input
                        type="password"
                        autoComplete="new-password"
                        spellCheck={false}
                        value={configForm.api_key}
                        onChange={(e) => setConfigForm({ ...configForm, api_key: e.target.value })}
                        placeholder="Enter API key..."
                        className={inputCls}
                        style={inputStyle}
                      />
                    </div>
                    <button
                      onClick={() => handleSaveConfig(tool.tool_name)}
                      className="h-9 px-4 text-[13px] font-semibold transition-colors"
                      style={{
                        borderRadius: "4px",
                        border: "1px solid var(--color-accent)",
                        background: "var(--color-accent)",
                        color: "var(--color-on-dark)",
                      }}
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
