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
      color: "#00A76F",
      bg: "#C8FAD6",
      enabled: config?.slack ?? false,
      description: "Send alerts to a Slack channel via webhook",
      envVar: "ARGUS_NOTIFY_SLACK_WEBHOOK_URL",
    },
    {
      name: "Email",
      icon: Mail,
      color: "#00BBD9",
      bg: "#CAFDF5",
      enabled: config?.email ?? false,
      description: "Send alert emails via SMTP",
      envVar: "ARGUS_NOTIFY_EMAIL_SMTP_HOST",
    },
    {
      name: "PagerDuty",
      icon: Siren,
      color: "#FF5630",
      bg: "#FFE9D5",
      enabled: config?.pagerduty ?? false,
      description: "Trigger PagerDuty incidents for critical alerts",
      envVar: "ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-bold text-[#1C252E]">Notifications</h2>
          <p className="text-[14px] text-[#637381] mt-0.5">
            Configure alert notification channels
          </p>
        </div>
        <button
          onClick={handleTest}
          disabled={testing}
          className="flex items-center gap-2 px-4 py-2.5 bg-[#1C252E] text-white rounded-xl text-[13px] font-bold hover:bg-[#454F5B] transition-colors disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
          {testing ? "Sending..." : "Send test"}
        </button>
      </div>

      {testResult && (
        <div
          className={`flex items-center gap-2 px-4 py-3 rounded-xl text-[13px] font-medium ${
            testResult === "success"
              ? "bg-[#D3FCD2] text-[#118D57]"
              : "bg-[#FFE9D5] text-[#B71D18]"
          }`}
        >
          {testResult === "success" ? (
            <>
              <Check className="w-4 h-4" />
              Test notification sent successfully
            </>
          ) : (
            <>
              <X className="w-4 h-4" />
              Failed to send test notification
            </>
          )}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {channels.map((ch) => (
            <div
              key={ch.name}
              className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]"
            >
              <div className="flex items-center gap-3 mb-4">
                <div
                  className="w-11 h-11 rounded-xl flex items-center justify-center"
                  style={{ backgroundColor: ch.bg }}
                >
                  <ch.icon className="w-6 h-6" style={{ color: ch.color }} />
                </div>
                <div>
                  <h3 className="text-[14px] font-bold text-[#1C252E]">{ch.name}</h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <div
                      className={`w-2 h-2 rounded-full ${ch.enabled ? "bg-[#22C55E]" : "bg-[#919EAB]"}`}
                    />
                    <span className="text-[11px] text-[#919EAB]">
                      {ch.enabled ? "Configured" : "Not configured"}
                    </span>
                  </div>
                </div>
              </div>
              <p className="text-[13px] text-[#637381] mb-3">{ch.description}</p>
              {!ch.enabled && (
                <p className="text-[11px] text-[#919EAB] font-mono bg-[#F4F6F8] px-2 py-1 rounded">
                  Set {ch.envVar} in .env
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
        <h3 className="text-[16px] font-bold text-[#1C252E] mb-2">Configuration</h3>
        <p className="text-[14px] text-[#637381] mb-4">
          Notification channels are configured via environment variables in your <code className="text-[#FF5630] bg-[#FFE9D5] px-1.5 py-0.5 rounded text-[12px]">.env</code> file.
          Argus will automatically use any configured channel when new alerts are generated.
        </p>
        <div className="bg-[#1C252E] rounded-xl p-4 font-mono text-[12px] text-[#5BE49B] leading-relaxed overflow-x-auto">
          <div className="text-[#637381]"># Slack</div>
          <div>ARGUS_NOTIFY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...</div>
          <div className="mt-2 text-[#637381]"># Email</div>
          <div>ARGUS_NOTIFY_EMAIL_SMTP_HOST=smtp.gmail.com</div>
          <div>ARGUS_NOTIFY_EMAIL_TO=[&quot;security@company.com&quot;]</div>
          <div className="mt-2 text-[#637381]"># PagerDuty</div>
          <div>ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY=your-routing-key</div>
        </div>
      </div>
    </div>
  );
}
