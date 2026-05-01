"use client";

import { useEffect, useState } from "react";
import { Bell, Send, Check, X, MessageSquare, Mail, Siren } from "lucide-react";
import { api, type WebhookConfig } from "@/lib/api";

export default function NotificationsPage() {
  const [config, setConfig] = useState<WebhookConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const c = await api.getWebhookConfig();
        setConfig(c);
      } catch {}
      setLoading(false);
    }
    load();
  }, []);

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      await api.testWebhook();
      setTestResult("success");
    } catch {
      setTestResult("error");
    }
    setTesting(false);
  }

  const channels = [
    {
      name: "Slack",
      icon: MessageSquare,
      iconColor: "var(--color-accent)",
      enabled: config?.slack ?? false,
      description: "Send alerts to a Slack channel via webhook",
      envVar: "ARGUS_NOTIFY_SLACK_WEBHOOK_URL",
    },
    {
      name: "Email",
      icon: Mail,
      iconColor: "#00BBD9",
      enabled: config?.email ?? false,
      description: "Send alert emails via SMTP",
      envVar: "ARGUS_NOTIFY_EMAIL_SMTP_HOST",
    },
    {
      name: "PagerDuty",
      icon: Siren,
      iconColor: "#FF5630",
      enabled: config?.pagerduty ?? false,
      description: "Trigger PagerDuty incidents for critical alerts",
      envVar: "ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Notifications</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Configure alert notification channels
          </p>
        </div>
        <button
          onClick={handleTest}
          disabled={testing}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border-strong)",
            background: "var(--color-surface-dark)",
            color: "var(--color-on-dark)",
          }}
        >
          <Send className="w-4 h-4" />
          {testing ? "Sending..." : "Send test"}
        </button>
      </div>

      {testResult && (
        <div
          className="flex items-center gap-2 px-4 py-3 text-[13px] font-medium"
          style={{
            borderRadius: "5px",
            background: testResult === "success" ? "rgba(0,167,111,0.08)" : "rgba(255,86,48,0.08)",
            color: testResult === "success" ? "#007B55" : "#B71D18",
            border: `1px solid ${testResult === "success" ? "rgba(0,167,111,0.2)" : "rgba(255,86,48,0.2)"}`,
          }}
        >
          {testResult === "success" ? (
            <><Check className="w-4 h-4" /> Test notification sent successfully</>
          ) : (
            <><X className="w-4 h-4" /> Failed to send test notification</>
          )}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {channels.map((ch) => (
            <div
              key={ch.name}
              className="p-6"
              style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}
            >
              <div className="flex items-center gap-3 mb-4">
                <ch.icon className="w-6 h-6" style={{ color: ch.iconColor }} />
                <div>
                  <h3 role="heading" className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>{ch.name}</h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ background: ch.enabled ? "#22C55E" : "var(--color-muted)" }}
                    />
                    <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                      {ch.enabled ? "Configured" : "Not configured"}
                    </span>
                  </div>
                </div>
              </div>
              <p className="text-[13px] mb-3" style={{ color: "var(--color-body)" }}>{ch.description}</p>
              {!ch.enabled && (
                <p
                  className="text-[11px] font-mono px-2 py-1"
                  style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-muted)" }}
                >
                  Set {ch.envVar} in .env
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <div
        className="p-6"
        style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}
      >
        <h3 role="heading" className="text-[15px] font-semibold mb-2" style={{ color: "var(--color-ink)" }}>Configuration</h3>
        <p className="text-[13px] mb-4" style={{ color: "var(--color-body)" }}>
          Notification channels are configured via environment variables in your{" "}
          <code
            className="px-1.5 py-0.5 text-[12px]"
            style={{ borderRadius: "4px", background: "rgba(255,86,48,0.08)", color: "#B71D18" }}
          >
            .env
          </code>{" "}
          file. Argus will automatically use any configured channel when new alerts are generated.
        </p>
        <div
          className="p-4 font-mono text-[12px] leading-relaxed overflow-x-auto"
          style={{ background: "#161C24", borderRadius: "5px" }}
        >
          <div style={{ color: "rgba(147,144,132,0.5)" }}># Slack</div>
          <div style={{ color: "#22C55E" }}>ARGUS_NOTIFY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...</div>
          <div className="mt-2" style={{ color: "rgba(147,144,132,0.5)" }}># Email</div>
          <div style={{ color: "#22C55E" }}>ARGUS_NOTIFY_EMAIL_SMTP_HOST=smtp.gmail.com</div>
          <div style={{ color: "#22C55E" }}>ARGUS_NOTIFY_EMAIL_TO=[&quot;security@company.com&quot;]</div>
          <div className="mt-2" style={{ color: "rgba(147,144,132,0.5)" }}># PagerDuty</div>
          <div style={{ color: "#22C55E" }}>ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY=your-routing-key</div>
        </div>
      </div>
    </div>
  );
}
