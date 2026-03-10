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
      color: "text-primary",
      enabled: config?.slack ?? false,
      description: "Send alerts to a Slack channel via webhook",
      envVar: "ARGUS_NOTIFY_SLACK_WEBHOOK_URL",
    },
    {
      name: "Email",
      icon: Mail,
      color: "text-info",
      enabled: config?.email ?? false,
      description: "Send alert emails via SMTP",
      envVar: "ARGUS_NOTIFY_EMAIL_SMTP_HOST",
    },
    {
      name: "PagerDuty",
      icon: Siren,
      color: "text-error",
      enabled: config?.pagerduty ?? false,
      description: "Trigger PagerDuty incidents for critical alerts",
      envVar: "ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Notifications</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Configure alert notification channels
          </p>
        </div>
        <button
          onClick={handleTest}
          disabled={testing}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-grey-800 text-white hover:bg-grey-700 transition-colors disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
          {testing ? "Sending..." : "Send test"}
        </button>
      </div>

      {testResult && (
        <div
          className={`flex items-center gap-2 px-4 py-3 rounded-lg text-[13px] font-medium ${
            testResult === "success"
              ? "bg-success-lighter text-success-dark"
              : "bg-error-lighter text-error-dark"
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
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {channels.map((ch) => (
            <div
              key={ch.name}
              className="bg-white rounded-xl border border-grey-200 p-6"
            >
              <div className="flex items-center gap-3 mb-4">
                <ch.icon className={`w-6 h-6 ${ch.color}`} />
                <div>
                  <h3 role="heading" className="text-[14px] font-bold text-grey-900">{ch.name}</h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <div
                      className={`w-2 h-2 rounded-full ${ch.enabled ? "bg-success" : "bg-grey-500"}`}
                    />
                    <span className="text-[11px] text-grey-500">
                      {ch.enabled ? "Configured" : "Not configured"}
                    </span>
                  </div>
                </div>
              </div>
              <p className="text-[13px] text-grey-600 mb-3">{ch.description}</p>
              {!ch.enabled && (
                <p className="text-[11px] text-grey-500 font-mono bg-grey-200 px-2 py-1 rounded">
                  Set {ch.envVar} in .env
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="bg-white rounded-xl border border-grey-200 p-6">
        <h3 role="heading" className="text-[16px] font-bold text-grey-900 mb-2">Configuration</h3>
        <p className="text-[14px] text-grey-600 mb-4">
          Notification channels are configured via environment variables in your <code className="text-error bg-error-lighter px-1.5 py-0.5 rounded text-[12px]">.env</code> file.
          Argus will automatically use any configured channel when new alerts are generated.
        </p>
        <div className="bg-grey-900 rounded-xl p-4 font-mono text-[12px] text-success leading-relaxed overflow-x-auto">
          <div className="text-grey-600"># Slack</div>
          <div>ARGUS_NOTIFY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...</div>
          <div className="mt-2 text-grey-600"># Email</div>
          <div>ARGUS_NOTIFY_EMAIL_SMTP_HOST=smtp.gmail.com</div>
          <div>ARGUS_NOTIFY_EMAIL_TO=[&quot;security@company.com&quot;]</div>
          <div className="mt-2 text-grey-600"># PagerDuty</div>
          <div>ARGUS_NOTIFY_PAGERDUTY_ROUTING_KEY=your-routing-key</div>
        </div>
      </div>
    </div>
  );
}
