"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus, Shield, Trash2 } from "lucide-react";

import {
  api,
  type AgentSettings,
  type BrandAllowlistEntry,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Section } from "@/components/shared/page-primitives";

import { useBrandContext } from "./use-brand-context";


/** Subsidiary allowlist editor + per-org Brand Defender knobs.
 *
 *  Lives at the top of the Terms tab. Two sections:
 *
 *  1. **Allowlist** — add/list/delete patterns. New patterns go through
 *     the existing /brand/allowlist endpoints. The "Apply to existing"
 *     button retroactively dismisses already-stored open suspects that
 *     match — without it, a new rule only affects future ingest.
 *  2. **Defender knobs** — read/PATCH OrganizationAgentSettings for
 *     ``brand_defence_min_similarity`` and ``brand_defence_plan_approval``.
 */
export function AllowlistCard() {
  const { orgId } = useBrandContext();
  const { toast } = useToast();
  const [entries, setEntries] = useState<BrandAllowlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [pattern, setPattern] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [sweepBusy, setSweepBusy] = useState(false);

  // Defender knobs
  const [settings, setSettings] = useState<AgentSettings | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [list, s] = await Promise.all([
        api.brand.listAllowlist(orgId),
        api.agents.getSettings().catch(() => null),
      ]);
      setEntries(list);
      setSettings(s);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load allowlist");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    if (!orgId || !pattern.trim()) return;
    setBusy(true);
    try {
      await api.brand.createAllowlist({
        organization_id: orgId,
        pattern: pattern.trim(),
        reason: reason.trim() || undefined,
      });
      toast("success", `Allowlisted ${pattern.trim()}`);
      setPattern("");
      setReason("");
      void load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Add failed");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string, p: string) => {
    if (!confirm(`Remove allowlist entry ${p}?`)) return;
    try {
      await api.brand.deleteAllowlist(id);
      toast("success", `Removed ${p}`);
      void load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Remove failed");
    }
  };

  const sweep = async () => {
    if (!orgId) return;
    setSweepBusy(true);
    try {
      const res = await api.brand.sweepAllowlist(orgId);
      toast(
        "success",
        `Swept ${res.swept} open suspects — dismissed ${res.dismissed} matches`,
      );
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Sweep failed");
    } finally {
      setSweepBusy(false);
    }
  };

  const saveSetting = async (patch: Partial<AgentSettings>) => {
    setSavingSettings(true);
    try {
      const next = await api.agents.patchSettings(patch);
      setSettings(next);
      toast("success", "Saved");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setSavingSettings(false);
    }
  };

  return (
    <Section>
      <div
        className="px-4 py-3 flex items-center justify-between"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
          <h3 style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
            Brand Defender — allowlist & thresholds
          </h3>
        </div>
        <span style={{ fontSize: 11, color: "var(--color-muted)" }}>
          {entries.length} allowlisted · auto-dismiss on ingest
        </span>
      </div>
      <div className="p-4 space-y-5">
        {/* Defender knobs */}
        <div
          className="grid gap-4"
          style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)" }}
        >
          <div>
            <label
              className="block mb-2 text-[11px] font-bold uppercase tracking-[0.06em]"
              style={{ color: "var(--color-muted)" }}
            >
              Auto-defend threshold
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0.5}
                max={0.99}
                step={0.01}
                value={settings?.brand_defence_min_similarity ?? 0.8}
                onChange={(e) =>
                  setSettings((prev) =>
                    prev
                      ? { ...prev, brand_defence_min_similarity: Number(e.target.value) }
                      : prev,
                  )
                }
                onMouseUp={(e) =>
                  saveSetting({
                    brand_defence_min_similarity: Number(
                      (e.currentTarget as HTMLInputElement).value,
                    ),
                  })
                }
                onTouchEnd={(e) =>
                  saveSetting({
                    brand_defence_min_similarity: Number(
                      (e.currentTarget as HTMLInputElement).value,
                    ),
                  })
                }
                disabled={!settings || savingSettings}
                style={{
                  flex: 1,
                  accentColor: "var(--color-accent)",
                }}
              />
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 14,
                  fontWeight: 700,
                  color: "var(--color-ink)",
                  minWidth: 56,
                  textAlign: "right",
                }}
              >
                {settings
                  ? Math.round(settings.brand_defence_min_similarity! * 100) + "%"
                  : "—"}
              </span>
            </div>
            <p
              className="mt-2 text-[11px]"
              style={{ color: "var(--color-muted)" }}
            >
              Suspects above this similarity auto-queue a Brand Defender run.
              Default 80%.
            </p>
          </div>

          <div>
            <label
              className="block mb-2 text-[11px] font-bold uppercase tracking-[0.06em]"
              style={{ color: "var(--color-muted)" }}
            >
              Plan approval gate
            </label>
            <label
              className="inline-flex items-center gap-2 cursor-pointer"
              style={{ fontSize: 12.5, color: "var(--color-body)" }}
            >
              <input
                type="checkbox"
                checked={!!settings?.brand_defence_plan_approval}
                onChange={(e) =>
                  saveSetting({ brand_defence_plan_approval: e.target.checked })
                }
                disabled={!settings || savingSettings}
                style={{ accentColor: "var(--color-accent)" }}
              />
              Pause for analyst plan-approval before each defence
            </label>
            <p
              className="mt-2 text-[11px]"
              style={{ color: "var(--color-muted)" }}
            >
              When on, every Defender run pauses after iteration 1 with the
              proposed plan. Off by default.
            </p>
          </div>
        </div>

        {/* Allowlist add form */}
        <div
          className="p-3 rounded-[5px]"
          style={{
            border: "1px solid var(--color-border)",
            background: "var(--color-surface)",
          }}
        >
          <div className="flex items-end gap-2 flex-wrap">
            <div style={{ flex: 1, minWidth: 220 }}>
              <label
                className="block mb-1 text-[11px] font-bold uppercase tracking-[0.06em]"
                style={{ color: "var(--color-muted)" }}
              >
                Pattern
              </label>
              <input
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder="corp.example.com or *.example.com"
                style={{
                  width: "100%",
                  height: 36,
                  padding: "0 12px",
                  borderRadius: 4,
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-ink)",
                  fontFamily: "monospace",
                  fontSize: 13,
                  outline: "none",
                }}
              />
            </div>
            <div style={{ flex: 1.5, minWidth: 240 }}>
              <label
                className="block mb-1 text-[11px] font-bold uppercase tracking-[0.06em]"
                style={{ color: "var(--color-muted)" }}
              >
                Reason (optional)
              </label>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g. official subsidiary — Liv. on liv.me"
                style={{
                  width: "100%",
                  height: 36,
                  padding: "0 12px",
                  borderRadius: 4,
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-ink)",
                  fontSize: 13,
                  outline: "none",
                }}
              />
            </div>
            <button
              onClick={add}
              disabled={busy || !pattern.trim()}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50"
              style={{
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
                border: "1px solid var(--color-accent)",
                borderRadius: 4,
              }}
            >
              <Plus className="w-3.5 h-3.5" />
              Add
            </button>
            <button
              onClick={sweep}
              disabled={sweepBusy || entries.length === 0}
              className="inline-flex items-center gap-1.5 h-9 px-3 text-[12px] font-bold disabled:opacity-50"
              style={{
                background: "var(--color-canvas)",
                color: "var(--color-body)",
                border: "1px solid var(--color-border)",
                borderRadius: 4,
              }}
              title="Retroactively dismiss already-stored open suspects matching the current allowlist."
            >
              {sweepBusy ? "Sweeping…" : "Apply to existing"}
            </button>
          </div>
        </div>

        {/* Allowlist table */}
        {loading ? (
          <p
            className="text-[12px] text-center"
            style={{ color: "var(--color-muted)" }}
          >
            Loading…
          </p>
        ) : entries.length === 0 ? (
          <p
            className="text-[12px] text-center py-4"
            style={{ color: "var(--color-muted)" }}
          >
            No allowlist entries yet. Add a pattern above — the agent and
            ingest paths will auto-dismiss matching suspects.
          </p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
            {entries.map((e) => (
              <li
                key={e.id}
                className="flex items-center gap-3 px-3 py-2"
                style={{
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                  background: "var(--color-canvas)",
                }}
              >
                <span
                  style={{
                    fontFamily: "monospace",
                    fontSize: 12.5,
                    color: "var(--color-ink)",
                    fontWeight: 600,
                  }}
                >
                  {e.pattern}
                </span>
                <span
                  style={{
                    fontSize: 12,
                    color: "var(--color-body)",
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {e.reason || "—"}
                </span>
                <button
                  onClick={() => remove(e.id, e.pattern)}
                  aria-label={`Remove ${e.pattern}`}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "var(--color-muted)",
                    cursor: "pointer",
                    padding: 4,
                  }}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}
