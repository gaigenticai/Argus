"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Briefcase,
  Compass,
  Lock,
  Search,
  ShieldCheck,
  Sparkles,
  Unlock,
} from "lucide-react";
import {
  api,
  type AgentPosture,
  type AgentSettings,
} from "@/lib/api";
import {
  PageHeader,
  Section,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";


export default function AgentSettingsPage() {
  const { toast } = useToast();
  const [settings, setSettings] = useState<AgentSettings | null>(null);
  const [posture, setPosture] = useState<AgentPosture | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const [s, p] = await Promise.all([
        api.agents.getSettings(),
        api.agents.posture(),
      ]);
      setSettings(s);
      setPosture(p);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load agent settings",
      );
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const updateField = useCallback(
    async (key: keyof AgentSettings, value: boolean | number | null) => {
      if (!settings) return;
      const previous = settings;
      setSettings({ ...settings, [key]: value });
      setSaving(true);
      try {
        const updated = await api.agents.patchSettings({ [key]: value });
        setSettings(updated);
        toast("success", "Saved");
      } catch (e) {
        setSettings(previous);
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to save",
        );
      } finally {
        setSaving(false);
      }
    },
    [settings, toast],
  );

  if (!settings || !posture) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow={{ icon: Sparkles, label: "Agentic" }}
          title="Agent Settings"
          description="Per-organisation agent toggles and auto-action overrides."
        />
        <p style={{ fontSize: "13px", color: "var(--color-muted)", fontStyle: "italic" }}>Loading…</p>
      </div>
    );
  }

  const masterHilOn = posture.human_in_loop_required;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Agent Settings"
        description={
          "Turn each agent on or off for this organisation. Auto-action " +
          "overrides at the bottom only have effect when the master " +
          "human-in-the-loop guard is relaxed in the deployment env."
        }
      />

      {/* Master posture banner */}
      <div
        role="status"
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
          borderRadius: "5px",
          border: masterHilOn ? "1px solid rgba(0,167,111,0.4)" : "1px solid rgba(255,86,48,0.4)",
          background: masterHilOn ? "rgba(0,167,111,0.08)" : "rgba(255,86,48,0.08)",
          padding: "12px 16px",
        }}
      >
        {masterHilOn ? (
          <Lock style={{ width: "20px", height: "20px", marginTop: "2px", color: "#007B55", flexShrink: 0 }} />
        ) : (
          <Unlock style={{ width: "20px", height: "20px", marginTop: "2px", color: "#B71D18", flexShrink: 0 }} />
        )}
        <div style={{ flex: 1 }}>
          <p style={{ fontSize: "13px", fontWeight: 700, color: masterHilOn ? "#007B55" : "#B71D18" }}>
            Master human-in-the-loop guard:{" "}
            {masterHilOn ? "ON (default, recommended)" : "OFF (relaxed)"}
          </p>
          <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "4px" }}>
            {masterHilOn ? (
              <>
                Set via{" "}
                <code style={{ fontFamily: "monospace" }}>
                  ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED=true
                </code>
                . While ON, no auto-action will fire — even if you flip
                the per-feature toggles below. To opt out you must set
                the env var to <code style={{ fontFamily: "monospace" }}>false</code>{" "}
                AND keep this on the per-org auto-* toggle.
              </>
            ) : (
              <>
                Auto-actions are eligible to fire when both the
                deployment-wide env var AND the per-org toggle below are
                on. Every bypass is audit-logged.
              </>
            )}
          </p>
        </div>
      </div>

      {/* Agent enable toggles */}
      <Section className="overflow-visible">
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--color-border)" }}>
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>Agents</h3>
          <p style={{ fontSize: "12px", color: "var(--color-muted)", marginTop: "2px" }}>
            Disabling an agent stops new runs from being queued for this
            organisation. Existing runs aren&apos;t cancelled.
          </p>
        </div>
        <ToggleRow
          icon={Search}
          label="Investigation Agent"
          description="Auto-runs on HIGH and CRITICAL alerts. 5 tools, max 6 iterations."
          enabled={settings.investigation_enabled}
          onChange={(v) => updateField("investigation_enabled", v)}
          disabled={saving}
        />
        <ToggleRow
          icon={ShieldCheck}
          label="Brand Defender"
          description="Triggers on suspect domains with similarity ≥ 0.80."
          enabled={settings.brand_defender_enabled}
          onChange={(v) => updateField("brand_defender_enabled", v)}
          disabled={saving}
        />
        <ToggleRow
          icon={Briefcase}
          label="Case Copilot"
          description="Manual trigger from the case detail page."
          enabled={settings.case_copilot_enabled}
          onChange={(v) => updateField("case_copilot_enabled", v)}
          disabled={saving}
        />
        <ToggleRow
          icon={Compass}
          label="Threat Hunter"
          description="Weekly scheduled hunt + manual ad-hoc triggers."
          enabled={settings.threat_hunter_enabled}
          onChange={(v) => updateField("threat_hunter_enabled", v)}
          disabled={saving}
          last
        />
      </Section>

      {/* Internal routing */}
      <Section>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--color-border)" }}>
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Internal routing
          </h3>
          <p style={{ fontSize: "12px", color: "var(--color-muted)", marginTop: "2px" }}>
            These don&apos;t take external action — they just route
            internal work between agents.
          </p>
        </div>
        <ToggleRow
          icon={Sparkles}
          label="Chain Investigation → Threat Hunter"
          description="When an investigation completes critical with correlated actors, queue a hunt anchored on the first one."
          enabled={settings.chain_investigation_to_hunt}
          onChange={(v) => updateField("chain_investigation_to_hunt", v)}
          disabled={saving}
          last
        />
      </Section>

      {/* Auto-action overrides — danger zone */}
      <Section>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--color-border)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <AlertTriangle style={{ width: "16px", height: "16px", color: "#B71D18" }} />
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
              Auto-action overrides (danger zone)
            </h3>
          </div>
          <p style={{ fontSize: "12px", color: "var(--color-muted)", marginTop: "4px" }}>
            These bypass the human-in-the-loop default for a narrow set
            of high-confidence cases. Master guard{" "}
            <code style={{ fontFamily: "monospace" }}>
              ARGUS_AGENT_HUMAN_IN_LOOP_REQUIRED
            </code>{" "}
            must also be relaxed in the deployment env for any of these
            to take effect. Every bypass is audit-logged.
          </p>
        </div>
        <ToggleRow
          icon={Briefcase}
          label="Auto-promote critical investigations"
          description="When an investigation completes with severity_assessment=critical, create a Case row without the analyst's Promote click."
          enabled={settings.auto_promote_critical}
          onChange={(v) => updateField("auto_promote_critical", v)}
          disabled={saving}
          danger
        />
        <ToggleRow
          icon={ShieldCheck}
          label="Auto-takedown high-confidence brand actions"
          description="When Brand Defender returns recommendation=takedown_now AND confidence ≥ 0.95, file the takedown ticket without Submit."
          enabled={settings.auto_takedown_high_confidence}
          onChange={(v) => updateField("auto_takedown_high_confidence", v)}
          disabled={saving}
          danger
          last
        />
      </Section>
    </div>
  );
}


function ToggleRow({
  icon: Icon,
  label,
  description,
  enabled,
  onChange,
  disabled,
  danger,
  last,
}: {
  icon: typeof Sparkles;
  label: string;
  description: string;
  enabled: boolean;
  onChange: (next: boolean) => void;
  disabled: boolean;
  danger?: boolean;
  last?: boolean;
}) {
  return (
    <div style={{
      display: "flex",
      alignItems: "flex-start",
      gap: "16px",
      padding: "16px 20px",
      borderBottom: last ? "none" : "1px solid var(--color-border)",
    }}>
      <div style={{
        width: "36px",
        height: "36px",
        borderRadius: "5px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
        background: danger ? "rgba(255,86,48,0.08)" : "var(--color-surface-muted)",
      }}>
        <Icon style={{ width: "16px", height: "16px", color: danger ? "#B71D18" : "var(--color-body)" }} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: "13.5px", fontWeight: 700, color: danger ? "#B71D18" : "var(--color-ink)" }}>
          {label}
        </p>
        <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "2px" }}>{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        onClick={() => onChange(!enabled)}
        disabled={disabled}
        style={{
          flexShrink: 0,
          width: "40px",
          height: "24px",
          borderRadius: "20px",
          position: "relative",
          border: "none",
          background: enabled
            ? danger
              ? "#B71D18"
              : "var(--color-border-strong)"
            : "var(--color-surface-muted)",
          cursor: disabled ? "not-allowed" : "pointer",
          opacity: disabled ? 0.5 : 1,
          transition: "background 0.2s",
        }}
      >
        <span style={{
          position: "absolute",
          top: "2px",
          left: enabled ? "18px" : "2px",
          width: "20px",
          height: "20px",
          borderRadius: "50%",
          background: "var(--color-canvas)",
          boxShadow: "0 1px 3px rgba(0,0,0,0.2)",
          transition: "left 0.2s",
        }} />
      </button>
    </div>
  );
}
