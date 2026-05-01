"use client";

import { useEffect, useMemo, useState } from "react";
import { Download, FileText, Plus, RefreshCw, X } from "lucide-react";
import {
  api,
  type ComplianceExportFormat,
  type ComplianceExportLanguageMode,
  type ComplianceExportResponse,
  type ComplianceExportStatus,
  type ComplianceFrameworkSummary,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";
import { Select as ThemedSelect } from "@/components/shared/select";

const STATUS_PRESENTATION: Record<
  ComplianceExportStatus,
  { label: string; bg: string; fg: string; border: string }
> = {
  pending: {
    label: "Pending",
    bg: "rgba(217, 188, 122, 0.18)",
    fg: "#7A5B1F",
    border: "rgba(217, 188, 122, 0.45)",
  },
  running: {
    label: "Running",
    bg: "rgba(255, 79, 0, 0.12)",
    fg: "#A53400",
    border: "rgba(255, 79, 0, 0.35)",
  },
  completed: {
    label: "Completed",
    bg: "rgba(76, 142, 91, 0.16)",
    fg: "#2D5C39",
    border: "rgba(76, 142, 91, 0.4)",
  },
  failed: {
    label: "Failed",
    bg: "rgba(190, 64, 49, 0.15)",
    fg: "#7A2920",
    border: "rgba(190, 64, 49, 0.4)",
  },
  expired: {
    label: "Expired",
    bg: "rgba(120, 120, 120, 0.15)",
    fg: "#454545",
    border: "rgba(120, 120, 120, 0.4)",
  },
};

const PERIOD_PRESETS = [
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
  { label: "Last 365 days", days: 365 },
];

function todayMinus(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

function isoDayStart(date: string): string {
  return new Date(`${date}T00:00:00.000Z`).toISOString();
}

function isoDayEnd(date: string): string {
  return new Date(`${date}T23:59:59.999Z`).toISOString();
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFrameworkSummary[]>([]);
  const [exports, setExports] = useState<ComplianceExportResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  // Form
  const [frameworkCode, setFrameworkCode] = useState("");
  const [languageMode, setLanguageMode] =
    useState<ComplianceExportLanguageMode>("en");
  const [format, setFormat] = useState<ComplianceExportFormat>("pdf");
  const [periodFrom, setPeriodFrom] = useState(todayMinus(90));
  const [periodTo, setPeriodTo] = useState(todayMinus(0));

  useEffect(() => {
    async function load() {
      try {
        const [fw, ex] = await Promise.all([
          api.compliance.listFrameworks(),
          api.compliance.listExports({ limit: 50 }),
        ]);
        setFrameworks(fw);
        setExports(ex);
        if (fw.length > 0 && !frameworkCode) {
          setFrameworkCode(fw[0].code);
        }
      } catch {
        toast("error", "Failed to load compliance data");
      }
      setLoading(false);
    }
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll any pending/running exports every 5s
  useEffect(() => {
    const inFlight = exports.filter(
      (e) => e.status === "pending" || e.status === "running",
    );
    if (inFlight.length === 0) return;
    const t = setInterval(async () => {
      try {
        const fresh = await api.compliance.listExports({ limit: 50 });
        setExports(fresh);
      } catch {
        /* swallow — next tick will retry */
      }
    }, 5000);
    return () => clearInterval(t);
  }, [exports]);

  async function refresh() {
    try {
      const ex = await api.compliance.listExports({ limit: 50 });
      setExports(ex);
    } catch {
      toast("error", "Failed to refresh");
    }
  }

  async function handleCreate() {
    if (!frameworkCode) return;
    setCreating(true);
    try {
      const res = await api.compliance.createExport({
        framework_code: frameworkCode,
        language_mode: languageMode,
        format,
        period_from: isoDayStart(periodFrom),
        period_to: isoDayEnd(periodTo),
      });
      setExports((prev) => [res, ...prev]);
      setShowCreate(false);
      toast("success", "Export queued — check status below");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Export failed";
      toast("error", msg);
    } finally {
      setCreating(false);
    }
  }

  function handleDownload(id: string) {
    window.open(api.compliance.downloadExportUrl(id), "_blank");
  }

  const frameworkOptions = useMemo(
    () =>
      frameworks.map((f) => ({
        value: f.code,
        label: `${f.name_en} (v${f.version})`,
      })),
    [frameworks],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2
            className="text-[24px] font-medium tracking-[-0.02em]"
            style={{ color: "var(--color-ink)" }}
          >
            Compliance Evidence Pack
          </h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Generate regulator-ready evidence packs in OSCAL JSON or PDF, in
            English / Arabic / bilingual.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="flex items-center gap-2 h-9 px-3 text-[13px] transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
            aria-label="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <Plus className="w-4 h-4" />
            New export
          </button>
        </div>
      </div>

      {/* Frameworks summary */}
      <div
        className="p-4"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "8px",
        }}
      >
        <h3
          className="text-[12px] font-semibold uppercase tracking-[0.07em] mb-3"
          style={{ color: "var(--color-muted)" }}
        >
          Available frameworks
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {frameworks.map((fw) => (
            <div
              key={fw.id}
              className="p-3"
              style={{
                background: "var(--color-canvas-subtle)",
                border: "1px solid var(--color-border)",
                borderRadius: "6px",
              }}
            >
              <div className="flex items-center justify-between">
                <div
                  className="text-[13px] font-semibold"
                  style={{ color: "var(--color-ink)" }}
                >
                  {fw.name_en}
                </div>
                <div
                  className="text-[11px]"
                  style={{ color: "var(--color-muted)" }}
                >
                  v{fw.version}
                </div>
              </div>
              <div
                className="text-[11px] mt-1 line-clamp-2"
                style={{ color: "var(--color-muted)" }}
              >
                {fw.description_en}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Exports table */}
      <div
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "8px",
          overflow: "hidden",
        }}
      >
        <div
          className="px-4 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3
            className="text-[13px] font-semibold"
            style={{ color: "var(--color-ink)" }}
          >
            Past exports
          </h3>
          <span
            className="text-[11px]"
            style={{ color: "var(--color-muted)" }}
          >
            {exports.length} record{exports.length === 1 ? "" : "s"}
          </span>
        </div>

        {loading ? (
          <div
            className="px-4 py-8 text-center text-[13px]"
            style={{ color: "var(--color-muted)" }}
          >
            Loading…
          </div>
        ) : exports.length === 0 ? (
          <div
            className="px-4 py-8 text-center text-[13px]"
            style={{ color: "var(--color-muted)" }}
          >
            No exports yet — click "New export" to generate one.
          </div>
        ) : (
          <table className="w-full text-[13px]">
            <thead>
              <tr style={{ background: "var(--color-canvas-subtle)" }}>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Framework
                </th>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Format
                </th>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Language
                </th>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Period
                </th>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Status
                </th>
                <th
                  className="text-left px-4 py-2 text-[11px] uppercase tracking-[0.07em] font-semibold"
                  style={{ color: "var(--color-muted)" }}
                >
                  Created
                </th>
                <th className="text-right px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {exports.map((ex) => {
                const status = STATUS_PRESENTATION[ex.status];
                return (
                  <tr
                    key={ex.id}
                    style={{ borderTop: "1px solid var(--color-border)" }}
                  >
                    <td className="px-4 py-2.5" style={{ color: "var(--color-ink)" }}>
                      <div className="font-medium">{ex.framework_name_en}</div>
                      <div
                        className="text-[11px]"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {ex.framework_code}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 uppercase text-[11px]" style={{ color: "var(--color-muted)" }}>
                      {ex.format}
                    </td>
                    <td className="px-4 py-2.5 text-[11px]" style={{ color: "var(--color-muted)" }}>
                      {ex.language_mode}
                    </td>
                    <td className="px-4 py-2.5 text-[11px]" style={{ color: "var(--color-muted)" }}>
                      {ex.period_from && ex.period_to
                        ? `${ex.period_from.slice(0, 10)} → ${ex.period_to.slice(0, 10)}`
                        : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className="inline-flex items-center px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.05em]"
                        style={{
                          background: status.bg,
                          color: status.fg,
                          border: `1px solid ${status.border}`,
                          borderRadius: "3px",
                        }}
                      >
                        {status.label}
                      </span>
                      {ex.error_message && (
                        <div
                          className="text-[11px] mt-1"
                          style={{ color: "#7A2920" }}
                          title={ex.error_message}
                        >
                          {ex.error_message.slice(0, 100)}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-[12px]" style={{ color: "var(--color-muted)" }}>
                      {formatDate(ex.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {ex.status === "completed" && (
                        <button
                          onClick={() => handleDownload(ex.id)}
                          className="inline-flex items-center gap-1.5 h-7 px-2.5 text-[11px] font-semibold transition-colors"
                          style={{
                            borderRadius: "4px",
                            border: "1px solid var(--color-border)",
                            background: "var(--color-canvas)",
                            color: "var(--color-ink)",
                          }}
                        >
                          <Download className="w-3.5 h-3.5" />
                          Download
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Create modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: "rgba(32,21,21,0.5)" }}
        >
          <div
            className="p-6 w-full max-w-md"
            style={{
              background: "var(--color-canvas)",
              borderRadius: "8px",
              boxShadow: "var(--shadow-z24)",
            }}
          >
            <div className="flex items-center justify-between mb-6">
              <h3
                className="text-[17px] font-semibold"
                style={{ color: "var(--color-ink)" }}
              >
                New compliance export
              </h3>
              <button
                onClick={() => setShowCreate(false)}
                className="p-1 transition-opacity hover:opacity-70"
                aria-label="Close"
              >
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label
                  className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  Framework
                </label>
                <ThemedSelect
                  value={frameworkCode}
                  onChange={setFrameworkCode}
                  options={frameworkOptions}
                  placeholder="Select a framework"
                  ariaLabel="Framework"
                />
              </div>

              <div>
                <label
                  className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  Language
                </label>
                <ThemedSelect
                  value={languageMode}
                  onChange={(v) =>
                    setLanguageMode(v as ComplianceExportLanguageMode)
                  }
                  options={[
                    { value: "en", label: "English" },
                    { value: "ar", label: "Arabic" },
                    { value: "bilingual", label: "Bilingual (AR exec + EN body)" },
                  ]}
                  ariaLabel="Language mode"
                />
              </div>

              <div>
                <label
                  className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
                  style={{ color: "var(--color-muted)" }}
                >
                  Format
                </label>
                <ThemedSelect
                  value={format}
                  onChange={(v) => setFormat(v as ComplianceExportFormat)}
                  options={[
                    { value: "pdf", label: "PDF (regulator-facing)" },
                    { value: "json", label: "OSCAL JSON (machine-readable)" },
                  ]}
                  ariaLabel="Format"
                />
              </div>

              <div className="flex gap-2">
                {PERIOD_PRESETS.map((p) => (
                  <button
                    key={p.days}
                    onClick={() => {
                      setPeriodFrom(todayMinus(p.days));
                      setPeriodTo(todayMinus(0));
                    }}
                    className="text-[11px] h-7 px-2"
                    style={{
                      borderRadius: "4px",
                      border: "1px solid var(--color-border)",
                      background: "var(--color-canvas-subtle)",
                      color: "var(--color-muted)",
                    }}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label
                    className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
                    style={{ color: "var(--color-muted)" }}
                  >
                    From
                  </label>
                  <input
                    type="date"
                    value={periodFrom}
                    onChange={(e) => setPeriodFrom(e.target.value)}
                    className="w-full h-9 px-2 text-[13px]"
                    style={{
                      borderRadius: "4px",
                      border: "1px solid var(--color-border)",
                      background: "var(--color-canvas)",
                      color: "var(--color-ink)",
                    }}
                  />
                </div>
                <div>
                  <label
                    className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5"
                    style={{ color: "var(--color-muted)" }}
                  >
                    To
                  </label>
                  <input
                    type="date"
                    value={periodTo}
                    onChange={(e) => setPeriodTo(e.target.value)}
                    className="w-full h-9 px-2 text-[13px]"
                    style={{
                      borderRadius: "4px",
                      border: "1px solid var(--color-border)",
                      background: "var(--color-canvas)",
                      color: "var(--color-ink)",
                    }}
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreate(false)}
                disabled={creating}
                className="h-9 px-3 text-[13px]"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-ink)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !frameworkCode || periodFrom >= periodTo}
                className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-accent)",
                  background: "var(--color-accent)",
                  color: "var(--color-on-dark)",
                }}
              >
                <FileText className="w-4 h-4" />
                {creating ? "Queueing…" : "Queue export"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
