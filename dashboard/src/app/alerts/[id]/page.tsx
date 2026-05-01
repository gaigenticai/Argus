"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Brain,
  CheckCircle,
  ClipboardList,
  Target,
  ThumbsUp,
  ThumbsDown,
  MessageSquare,
} from "lucide-react";
import { api, type Alert, type FeedbackCreatePayload, type FeedbackResponse } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";
import { Select as ThemedSelect } from "@/components/shared/select";

const STATUS_OPTIONS = [
  "new",
  "triaged",
  "investigating",
  "confirmed",
  "false_positive",
  "resolved",
];

const ALERT_CATEGORIES = [
  "phishing",
  "malware",
  "ransomware",
  "data_breach",
  "vulnerability",
  "fraud",
  "underground",
  "brand_abuse",
  "actor_mention",
  "credential_leak",
];

const ALERT_SEVERITIES = ["critical", "high", "medium", "low"];

export default function AlertDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<FeedbackResponse | null | undefined>(undefined);
  const [feedbackForm, setFeedbackForm] = useState<{
    is_true_positive: boolean | null;
    corrected_category: string;
    corrected_severity: string;
    feedback_notes: string;
  }>({ is_true_positive: null, corrected_category: "", corrected_severity: "", feedback_notes: "" });
  const [feedbackSaving, setFeedbackSaving] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    async function load() {
      try {
        const [data, feedbackData] = await Promise.all([
          api.getAlert(params.id as string),
          api.feedback.list({ alert_id: params.id as string }),
        ]);
        setAlert(data);
        setNotes(data.analyst_notes || "");
        setFeedback(feedbackData[0] || null);
      } catch {
        toast("error", "Alert not found");
        router.push("/alerts");
      }
    }
    load();
  }, [params.id]);

  const handleStatusChange = async (newStatus: string) => {
    if (!alert) return;
    setSaving(true);
    try {
      const updated = await api.updateAlert(alert.id, { status: newStatus });
      setAlert(updated);
      toast("success", `Status updated to ${newStatus.replace("_", " ")}`);
    } catch {
      toast("error", "Failed to update status");
    }
    setSaving(false);
  };

  const handleSaveNotes = async () => {
    if (!alert) return;
    setSaving(true);
    try {
      const updated = await api.updateAlert(alert.id, { analyst_notes: notes });
      setAlert(updated);
      toast("success", "Notes saved");
    } catch {
      toast("error", "Failed to save notes");
    }
    setSaving(false);
  };

  const handleFeedbackSubmit = async () => {
    if (!alert || feedbackForm.is_true_positive === null) return;
    setFeedbackSaving(true);
    try {
      const payload: FeedbackCreatePayload = {
        alert_id: alert.id,
        is_true_positive: feedbackForm.is_true_positive,
        corrected_category: feedbackForm.corrected_category || null,
        corrected_severity: feedbackForm.corrected_severity || null,
        feedback_notes: feedbackForm.feedback_notes || null,
      };
      const result = await api.feedback.submit(payload);
      setFeedback(result);
      toast("success", "Feedback submitted");
    } catch {
      toast("error", "Failed to submit feedback");
    }
    setFeedbackSaving(false);
  };

  if (!alert) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div
          className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
          style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
        />
      </div>
    );
  }

  const inputCls = "w-full px-3 rounded-[4px] border text-[13px] outline-none resize-none transition-colors"
    + " bg-[var(--color-canvas)] border-[var(--color-border)] text-[var(--color-ink)]"
    + " placeholder:text-[var(--color-muted)] focus:border-[var(--color-border-strong)]";

  return (
    <main className="space-y-6 max-w-4xl">
      {/* Back button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-[13px] transition-colors"
        style={{ color: "var(--color-muted)" }}
        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-ink)")}
        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-muted)")}
      >
        <ArrowLeft className="w-4 h-4" />
        Back to alerts
      </button>

      {/* Header */}
      <div
        className="p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
              {categoryLabels[alert.category] || alert.category}
            </span>
          </div>
          <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
            {formatDate(alert.created_at)}
          </span>
        </div>

        <h1 className="text-[22px] font-medium tracking-[-0.02em] mb-2" style={{ color: "var(--color-ink)" }}>
          {alert.title}
        </h1>
        <p className="text-[13px] leading-relaxed" style={{ color: "var(--color-body)" }}>
          {alert.summary}
        </p>

        <div className="mt-4 flex items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>
            Confidence:
          </span>
          <div
            className="w-32 h-1.5 rounded-full overflow-hidden"
            style={{ background: "var(--color-surface-muted)" }}
          >
            <div
              className="h-full rounded-full"
              style={{
                width: `${alert.confidence * 100}%`,
                backgroundColor:
                  alert.confidence >= 0.8 ? "#22C55E" : alert.confidence >= 0.5 ? "#FFAB00" : "var(--color-muted)",
              }}
            />
          </div>
          <span className="text-[12px] font-bold" style={{ color: "var(--color-ink)" }}>
            {Math.round(alert.confidence * 100)}%
          </span>
        </div>
      </div>

      {/* AI Analysis */}
      {alert.agent_reasoning && (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5" style={{ color: "var(--color-accent)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>AI analysis</h3>
          </div>
          <p className="text-[13px] leading-relaxed whitespace-pre-wrap" style={{ color: "var(--color-body)" }}>
            {alert.agent_reasoning}
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Matched entities */}
        {alert.matched_entities && Object.keys(alert.matched_entities).length > 0 && (
          <div
            className="p-6"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
            }}
          >
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-5 h-5" style={{ color: "var(--color-error)" }} />
              <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>Matched entities</h3>
            </div>
            <div className="space-y-2">
              {Object.entries(alert.matched_entities).map(([key, val]) => (
                <div key={key} className="flex items-start gap-2">
                  <span className="text-[13px] font-semibold shrink-0" style={{ color: "var(--color-ink)" }}>{key}:</span>
                  <span className="text-[13px]" style={{ color: "var(--color-body)" }}>{val}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended actions */}
        {alert.recommended_actions && alert.recommended_actions.length > 0 && (
          <div
            className="p-6"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
            }}
          >
            <div className="flex items-center gap-2 mb-3">
              <ClipboardList className="w-5 h-5" style={{ color: "var(--color-accent)" }} />
              <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>Recommended actions</h3>
            </div>
            <ul className="space-y-2">
              {alert.recommended_actions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-[13px]" style={{ color: "var(--color-body)" }}>
                  <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" style={{ color: "var(--color-accent)" }} />
                  {action}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Status update + Analyst notes */}
      <div
        className="p-6"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        <h3 className="text-[14px] font-semibold mb-4" style={{ color: "var(--color-ink)" }}>Actions</h3>

        <div className="flex gap-3 mb-4 flex-wrap items-center">
          <label className="text-[13px] font-semibold self-center" style={{ color: "var(--color-muted)" }}>Status:</label>
          <div className="flex gap-2 flex-wrap">
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => handleStatusChange(s)}
                disabled={saving}
                className="px-3 py-1.5 text-[12px] font-semibold capitalize transition-colors"
                style={{
                  borderRadius: "4px",
                  border: alert.status === s ? "1px solid #22C55E" : "1px solid var(--color-border)",
                  background: alert.status === s ? "#22C55E" : "var(--color-canvas)",
                  color: alert.status === s ? "#fff" : "var(--color-body)",
                }}
              >
                {s.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="text-[13px] font-semibold block mb-2" style={{ color: "var(--color-muted)" }}>
            Analyst notes
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Add your investigation notes..."
            rows={4}
            className={inputCls}
            style={{ height: "auto", padding: "0.75rem" }}
          />
          <button
            onClick={handleSaveNotes}
            disabled={saving}
            className="mt-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border-strong)",
              background: "var(--color-surface-dark)",
              color: "var(--color-on-dark)",
            }}
          >
            {saving ? "Saving..." : "Save notes"}
          </button>
        </div>
      </div>

      {/* Analyst Feedback */}
      {feedback === undefined ? (
        <div
          className="p-6 flex items-center justify-center min-h-[80px]"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div
            className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
        </div>
      ) : (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center gap-2 mb-4">
            <MessageSquare className="w-5 h-5" style={{ color: "var(--color-body)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>Analyst Feedback</h3>
          </div>

          {feedback !== null ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                {feedback.is_true_positive ? (
                  <ThumbsUp className="w-5 h-5" style={{ color: "#22C55E" }} />
                ) : (
                  <ThumbsDown className="w-5 h-5" style={{ color: "var(--color-error)" }} />
                )}
                <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                  You marked this as{" "}
                  <span style={{ color: feedback.is_true_positive ? "#22C55E" : "var(--color-error)" }}>
                    {feedback.is_true_positive ? "True Positive" : "False Positive"}
                  </span>{" "}
                  on {formatDate(feedback.created_at)}
                </span>
              </div>
              {feedback.corrected_category && (
                <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
                  <span className="font-semibold">Corrected category:</span>{" "}
                  {feedback.corrected_category}
                </p>
              )}
              {feedback.corrected_severity && (
                <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
                  <span className="font-semibold">Corrected severity:</span>{" "}
                  {feedback.corrected_severity}
                </p>
              )}
              {feedback.feedback_notes && (
                <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
                  <span className="font-semibold">Notes:</span> {feedback.feedback_notes}
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {/* TP / FP radio */}
              <div>
                <label className="text-[13px] font-semibold block mb-2" style={{ color: "var(--color-muted)" }}>
                  Verdict <span style={{ color: "var(--color-error)" }}>*</span>
                </label>
                <div className="flex gap-3">
                  <button
                    onClick={() => setFeedbackForm((f) => ({ ...f, is_true_positive: true }))}
                    className="flex items-center gap-2 px-4 py-2 text-[13px] font-semibold transition-colors"
                    style={{
                      borderRadius: "4px",
                      border: feedbackForm.is_true_positive === true
                        ? "1px solid #22C55E"
                        : "1px solid var(--color-border)",
                      background: feedbackForm.is_true_positive === true
                        ? "#D3FCD2"
                        : "var(--color-canvas)",
                      color: feedbackForm.is_true_positive === true ? "#166534" : "var(--color-body)",
                    }}
                  >
                    <ThumbsUp className="w-4 h-4" />
                    True Positive
                  </button>
                  <button
                    onClick={() => setFeedbackForm((f) => ({ ...f, is_true_positive: false }))}
                    className="flex items-center gap-2 px-4 py-2 text-[13px] font-semibold transition-colors"
                    style={{
                      borderRadius: "4px",
                      border: feedbackForm.is_true_positive === false
                        ? "1px solid var(--color-error)"
                        : "1px solid var(--color-border)",
                      background: feedbackForm.is_true_positive === false
                        ? "#FFE4DE"
                        : "var(--color-canvas)",
                      color: feedbackForm.is_true_positive === false ? "var(--color-error)" : "var(--color-body)",
                    }}
                  >
                    <ThumbsDown className="w-4 h-4" />
                    False Positive
                  </button>
                </div>
              </div>

              {/* Corrected category */}
              <div>
                <label className="text-[13px] font-semibold block mb-2" style={{ color: "var(--color-muted)" }}>
                  Corrected category <span style={{ color: "var(--color-muted)" }}>(optional)</span>
                </label>
                <ThemedSelect
                  value={feedbackForm.corrected_category}
                  onChange={(v) => setFeedbackForm((f) => ({ ...f, corrected_category: v }))}
                  ariaLabel="Corrected category"
                  options={[
                    { value: "", label: "— No change —" },
                    ...ALERT_CATEGORIES.map((cat) => ({ value: cat, label: categoryLabels[cat] || cat })),
                  ]}
                  style={{ width: "100%" }}
                />
              </div>

              {/* Corrected severity */}
              <div>
                <label className="text-[13px] font-semibold block mb-2" style={{ color: "var(--color-muted)" }}>
                  Corrected severity <span style={{ color: "var(--color-muted)" }}>(optional)</span>
                </label>
                <ThemedSelect
                  value={feedbackForm.corrected_severity}
                  onChange={(v) => setFeedbackForm((f) => ({ ...f, corrected_severity: v }))}
                  ariaLabel="Corrected severity"
                  options={[
                    { value: "", label: "— No change —" },
                    ...ALERT_SEVERITIES.map((sev) => ({ value: sev, label: sev.charAt(0).toUpperCase() + sev.slice(1) })),
                  ]}
                  style={{ width: "100%" }}
                />
              </div>

              {/* Feedback notes */}
              <div>
                <label className="text-[13px] font-semibold block mb-2" style={{ color: "var(--color-muted)" }}>
                  Notes <span style={{ color: "var(--color-muted)" }}>(optional)</span>
                </label>
                <textarea
                  value={feedbackForm.feedback_notes}
                  onChange={(e) => setFeedbackForm((f) => ({ ...f, feedback_notes: e.target.value }))}
                  placeholder="Explain your verdict..."
                  rows={3}
                  className={inputCls}
                  style={{ padding: "0.75rem" }}
                />
              </div>

              <button
                onClick={handleFeedbackSubmit}
                disabled={feedbackSaving || feedbackForm.is_true_positive === null}
                className="h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-accent)",
                  background: "var(--color-accent)",
                  color: "var(--color-on-dark)",
                }}
              >
                {feedbackSaving ? "Submitting..." : "Submit feedback"}
              </button>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
