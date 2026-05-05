"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Brain,
  CheckCircle,
  ClipboardList,
  ExternalLink,
  FolderOpen,
  Link2,
  Newspaper,
  Pencil,
  Shield,
  Target,
  ThumbsUp,
  ThumbsDown,
  MessageSquare,
  Database,
  UserSquare,
  Workflow,
} from "lucide-react";
import {
  api,
  type Alert,
  type AlertRelationsResponse,
  type AlertSourceResponse,
  type AlertThresholdsResponse,
  type AttributionScore,
  type FeedbackCreatePayload,
  type FeedbackResponse,
  type IOCItem,
} from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";
import { Select as ThemedSelect } from "@/components/shared/select";

const STATUS_OPTIONS = [
  "new",
  "needs_review",
  "triaged",
  "investigating",
  "confirmed",
  "false_positive",
  "resolved",
];

// Canonical category list mirrors src/models/threat.py::ThreatCategory.
// The backend now rejects values not in this set (Pydantic validates
// ThreatCategory enum), so the dropdown must match exactly. Order
// follows the enum definition for stable UI.
const ALERT_CATEGORIES = [
  "credential_leak",
  "data_breach",
  "stealer_log",
  "ransomware",
  "ransomware_victim",
  "access_sale",
  "exploit",
  "phishing",
  "impersonation",
  "doxxing",
  "insider_threat",
  "brand_abuse",
  "dark_web_mention",
  "underground_chatter",
  "initial_access",
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
  const [iocs, setIocs] = useState<IOCItem[] | null>(null);
  // Source raw-intel provenance. ``undefined`` = loading; ``null`` =
  // alert has no source (legacy/synthetic) or source was purged. The
  // /source endpoint 404s in those cases — caught and stored as null
  // rather than blowing up the whole page.
  const [source, setSource] = useState<AlertSourceResponse | null | undefined>(undefined);
  // Attribution scoring — ranked candidate threat actors with factor
  // breakdowns. ``null`` means the section is hidden (no candidates,
  // or fetch failed). Shown when at least one candidate scores > 0.
  const [attribution, setAttribution] = useState<AttributionScore[] | null>(null);
  // Cross-table relations — cases, takedowns, actor sightings touching
  // this alert. ``null`` until first fetch completes; empty lists when
  // nothing is linked yet (the section auto-hides in that case).
  const [relations, setRelations] = useState<AlertRelationsResponse | null>(null);
  // Org's configured confidence thresholds. Defaults match the legacy
  // hardcoded values (0.5 / 0.8) so the bar still tiers correctly
  // before the fetch resolves; the live values arrive on first render.
  const [thresholds, setThresholds] = useState<AlertThresholdsResponse>({
    needs_review_below: 0.5,
    high_above: 0.8,
  });
  // Override modal — null = closed; "severity" or "category" = which
  // field the analyst is overriding. Reason is required server-side.
  const [overrideField, setOverrideField] = useState<"severity" | "category" | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    async function load() {
      try {
        // Source fetch may legitimately 404 (alert has no
        // raw_intel_id, or the source row was purged). Use a settled
        // promise so the rest of the page still loads when source is
        // missing — only the main getAlert() failure boots the user
        // back to /alerts.
        const [data, feedbackData, iocList, sourceRes, attribRes, relationsRes, thresholdsRes] = await Promise.all([
          api.getAlert(params.id as string),
          api.feedback.list({ alert_id: params.id as string }),
          api.getIOCs({ source_alert_id: params.id as string, limit: 100 }),
          api
            .getAlertSource(params.id as string)
            .then((s) => s as AlertSourceResponse | null)
            .catch(() => null as AlertSourceResponse | null),
          api
            .getAlertAttribution(params.id as string, 5)
            .then((r) => r.scores)
            .catch(() => [] as AttributionScore[]),
          api
            .getAlertRelations(params.id as string)
            .catch(() => ({ cases: [], takedowns: [], sightings: [] } as AlertRelationsResponse)),
          api
            .getAlertThresholds(params.id as string)
            .catch(() => null as AlertThresholdsResponse | null),
        ]);
        setAlert(data);
        setNotes(data.analyst_notes || "");
        setFeedback(feedbackData[0] || null);
        setIocs(iocList);
        setSource(sourceRes);
        // Filter out actors whose only signal is the recency baseline.
        // The scorer gives every recently-seen actor a small recency
        // contribution regardless of fit, which floods the list with
        // unrelated APTs at 5%. Only show actors with at least one
        // non-recency factor contributing — i.e. there's a real link
        // (sighting, TTP, IOC, infra) between this alert and the actor.
        setAttribution(
          attribRes.filter((s) =>
            s.factors.some(
              (f) => f.name !== "recency" && f.contribution > 0,
            ),
          ),
        );
        setRelations(relationsRes);
        if (thresholdsRes) setThresholds(thresholdsRes);
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

  const handleOverrideSubmit = async (
    field: "severity" | "category",
    value: string,
    reason: string,
  ) => {
    if (!alert) return;
    setSaving(true);
    try {
      const payload: { severity?: string; category?: string; override_reason: string } = {
        override_reason: reason,
      };
      if (field === "severity") payload.severity = value;
      else payload.category = value;
      const updated = await api.updateAlert(alert.id, payload);
      setAlert(updated);
      toast("success", `${field[0].toUpperCase() + field.slice(1)} → ${value}`);
      setOverrideField(null);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : `Failed to update ${field}`);
    } finally {
      setSaving(false);
    }
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
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1">
              <SeverityBadge severity={alert.severity} />
              <button
                onClick={() => setOverrideField("severity")}
                title="Override severity (audit-logged)"
                className="p-1 rounded transition-colors"
                style={{ color: "var(--color-muted)" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-ink)")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-muted)")}
              >
                <Pencil className="w-3 h-3" />
              </button>
            </div>
            <StatusBadge status={alert.status} />
            <div className="flex items-center gap-1">
              <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                {categoryLabels[alert.category] || alert.category}
              </span>
              <button
                onClick={() => setOverrideField("category")}
                title="Override category (audit-logged)"
                className="p-1 rounded transition-colors"
                style={{ color: "var(--color-muted)" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-ink)")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-muted)")}
              >
                <Pencil className="w-3 h-3" />
              </button>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={async () => {
                try {
                  const res = await api.investigations.create(alert.id);
                  toast(
                    "success",
                    res.status === "queued"
                      ? "Investigation queued — opening it"
                      : "Investigation already in flight — opening it",
                  );
                  router.push(`/investigations?id=${res.id}`);
                } catch (e) {
                  toast(
                    "error",
                    e instanceof Error ? e.message : "Failed to queue investigation",
                  );
                }
              }}
              className="inline-flex items-center gap-1.5 h-7 px-2.5 text-[11px] font-semibold transition-colors"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
                background: "var(--color-accent)",
                color: "var(--color-on-dark)",
              }}
              title="Run an agentic investigation on this alert"
            >
              Run investigation →
            </button>
            <a
              href={api.getAlertNavigatorLayerUrl(alert.id)}
              download
              className="inline-flex items-center gap-1.5 h-7 px-2.5 text-[11px] font-semibold transition-colors"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
              }}
              title="Download MITRE ATT&CK Navigator layer (v4.5)"
            >
              Navigator layer ↓
            </a>
            <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
              {formatDate(alert.created_at)}
            </span>
          </div>
        </div>

        <h1 dir="auto" className="text-[22px] font-medium tracking-[-0.02em] mb-2" style={{ color: "var(--color-ink)" }}>
          {alert.title}
        </h1>
        <p dir="auto" className="text-[13px] leading-relaxed" style={{ color: "var(--color-body)" }}>
          {alert.summary}
        </p>

        {/* Confidence bar — tiers reflect the alert's org's actual
            configured thresholds. Below ``needs_review_below`` the
            ingestion pipeline would have routed this to NEEDS_REVIEW
            (red); at or above ``high_above`` (0.85) the org's
            auto-action gates are eligible (green); in between is
            standard confidence (amber). The tooltip surfaces the
            numbers so the analyst knows what they mean. */}
        <div className="mt-4 flex items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>
            Confidence:
          </span>
          <div
            className="w-32 h-1.5 rounded-full overflow-hidden"
            style={{ background: "var(--color-surface-muted)" }}
            title={
              `Org thresholds: needs-review below ${Math.round(thresholds.needs_review_below * 100)}%, ` +
              `high-confidence ≥ ${Math.round(thresholds.high_above * 100)}%`
            }
          >
            <div
              className="h-full rounded-full"
              style={{
                width: `${alert.confidence * 100}%`,
                backgroundColor:
                  alert.confidence >= thresholds.high_above
                    ? "#22C55E"
                    : alert.confidence >= thresholds.needs_review_below
                      ? "#FFAB00"
                      : "var(--color-muted)",
              }}
            />
          </div>
          <span className="text-[12px] font-bold" style={{ color: "var(--color-ink)" }}>
            {Math.round(alert.confidence * 100)}%
          </span>
        </div>
      </div>

      {/* Source — the raw_intel item the triage agent reasoned about.
          Hidden when ``source === null`` (alert has no raw_intel_id or
          source row was purged). The original article URL is the
          single most useful provenance link an analyst can have. */}
      {source && (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center gap-2 mb-3">
            <Newspaper className="w-5 h-5" style={{ color: "var(--color-body)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              Source
            </h3>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="inline-flex items-center px-1.5 py-0.5 text-[11px] font-mono"
                style={{
                  background: "var(--color-surface-muted)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 3,
                  color: "var(--color-body)",
                }}
                title="Source type — surface_web / tor_forum / telegram / etc."
              >
                {source.source_type}
              </span>
              {source.source_name && (
                <span
                  className="text-[12.5px] font-semibold"
                  style={{ color: "var(--color-ink)" }}
                >
                  {source.source_name}
                </span>
              )}
              {source.author && (
                <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                  · {source.author}
                </span>
              )}
              {source.published_at && (
                <span
                  className="text-[12px]"
                  style={{ color: "var(--color-muted)" }}
                  title={`Published ${formatDate(source.published_at)}`}
                >
                  · published {formatDate(source.published_at)}
                </span>
              )}
            </div>
            {source.title && (
              <div
                dir="auto"
                className="text-[13.5px] leading-snug"
                style={{ color: "var(--color-ink)" }}
              >
                {source.title}
              </div>
            )}
            {source.source_url && (
              <a
                href={source.source_url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="inline-flex items-center gap-1.5 text-[12.5px] font-semibold break-all"
                style={{ color: "var(--color-accent)" }}
              >
                Open original article
                <ExternalLink className="w-3.5 h-3.5 shrink-0" />
              </a>
            )}
          </div>
        </div>
      )}

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

      {/* Threat actor attribution — ranked candidates with factor
          breakdowns. Hidden when there are no candidates (alert has no
          actor signal). Each card links to /actors/{id} for the actor
          dossier. The same scoring drives /actors/[id]'s timeline. */}
      {attribution && attribution.length > 0 && (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center gap-2 mb-1">
            <UserSquare className="w-5 h-5" style={{ color: "var(--color-accent)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              Likely actors
            </h3>
            <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
              ranked by confidence
            </span>
          </div>
          <p className="text-[12px] mb-3" style={{ color: "var(--color-muted)" }}>
            Argus scored these candidates from direct sightings, TTP overlap,
            IOC overlap, recency, and infrastructure clusters. A high score
            isn&apos;t attribution — it&apos;s a starting hypothesis to investigate.
          </p>
          <div className="space-y-3">
            {attribution.slice(0, 5).map((sc) => (
              <Link
                key={sc.actor_id}
                href={`/actors/${sc.actor_id}`}
                className="block p-3 transition-colors"
                style={{
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                  background: "var(--color-canvas)",
                }}
              >
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className="text-[14px] font-semibold"
                        style={{ color: "var(--color-ink)" }}
                      >
                        {sc.primary_alias}
                      </span>
                      {sc.aliases.slice(0, 4).map((a) => (
                        <span
                          key={a}
                          className="inline-flex items-center px-1.5 py-0.5 text-[10.5px] font-mono"
                          style={{
                            background: "var(--color-surface-muted)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 3,
                            color: "var(--color-muted)",
                          }}
                        >
                          {a}
                        </span>
                      ))}
                      {sc.aliases.length > 4 && (
                        <span
                          className="text-[10.5px]"
                          style={{ color: "var(--color-muted)" }}
                        >
                          +{sc.aliases.length - 4}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div
                      className="text-[16px] font-bold tabular-nums"
                      style={{
                        color:
                          sc.confidence >= 0.7
                            ? "#22C55E"
                            : sc.confidence >= 0.4
                              ? "#FFAB00"
                              : "var(--color-body)",
                      }}
                    >
                      {Math.round(sc.confidence * 100)}%
                    </div>
                    <div
                      className="text-[10px] uppercase tracking-[0.7px]"
                      style={{ color: "var(--color-muted)" }}
                    >
                      confidence
                    </div>
                  </div>
                </div>
                {/* Factor breakdown — each factor a thin row with a bar.
                    contribution = raw * weight, so "contribution" sums
                    to confidence. Only show factors that contributed
                    > 0 to keep the breakdown readable. */}
                <div className="space-y-1">
                  {sc.factors
                    .filter((f) => f.contribution > 0 || f.raw > 0)
                    .map((f) => (
                      <div key={f.name} className="flex items-center gap-2 text-[11.5px]">
                        <span
                          className="w-32 shrink-0"
                          style={{ color: "var(--color-body)" }}
                          title={f.detail || undefined}
                        >
                          {f.name.replace(/_/g, " ")}
                        </span>
                        <div
                          className="flex-1 h-1 rounded-full overflow-hidden"
                          style={{ background: "var(--color-surface-muted)" }}
                        >
                          <div
                            className="h-full"
                            style={{
                              width: `${Math.min(f.contribution * 100 / 0.5, 100)}%`,
                              background: "var(--color-accent)",
                            }}
                          />
                        </div>
                        <span
                          className="w-16 text-right tabular-nums font-mono text-[10.5px]"
                          style={{ color: "var(--color-muted)" }}
                          title={`raw=${f.raw.toFixed(2)} × weight=${f.weight} = ${f.contribution.toFixed(3)}`}
                        >
                          {(f.contribution * 100).toFixed(1)}%
                        </span>
                      </div>
                    ))}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Related — cases, takedowns, actor sightings touching this
          alert. Section auto-hides when nothing is linked. Each entry
          deep-links into the corresponding page so the analyst doesn't
          have to navigate elsewhere and search for the alert id. */}
      {relations && (relations.cases.length + relations.takedowns.length + relations.sightings.length > 0) && (
        <div
          className="p-6"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center gap-2 mb-3">
            <Link2 className="w-5 h-5" style={{ color: "var(--color-body)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>Related</h3>
          </div>
          <div className="space-y-4">
            {relations.cases.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <FolderOpen className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                  <span className="text-[11px] font-bold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                    Cases ({relations.cases.length})
                  </span>
                </div>
                <ul className="space-y-1.5">
                  {relations.cases.map((c) => (
                    <li key={c.id}>
                      <Link
                        href={`/cases/${c.id}`}
                        className="flex items-center gap-2 text-[13px] py-1 px-2 rounded transition-colors"
                        style={{ color: "var(--color-ink)" }}
                      >
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.6px]"
                          style={{
                            borderRadius: 3,
                            background: "var(--color-surface-muted)",
                            color: "var(--color-body)",
                          }}
                        >
                          {c.state.replace(/_/g, " ")}
                        </span>
                        <span className="truncate">{c.title}</span>
                        {c.is_primary && (
                          <span
                            className="inline-flex items-center px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-[0.6px]"
                            style={{
                              borderRadius: 3,
                              background: "rgba(255,79,0,0.12)",
                              color: "var(--color-accent)",
                            }}
                          >
                            primary
                          </span>
                        )}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {relations.takedowns.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Workflow className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                  <span className="text-[11px] font-bold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                    Takedowns ({relations.takedowns.length})
                  </span>
                </div>
                <ul className="space-y-1.5">
                  {relations.takedowns.map((t) => (
                    <li key={t.id}>
                      <Link
                        href={`/takedowns`}
                        className="flex items-center gap-2 text-[13px] py-1 px-2 rounded transition-colors"
                        style={{ color: "var(--color-ink)" }}
                      >
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.6px]"
                          style={{
                            borderRadius: 3,
                            background: "var(--color-surface-muted)",
                            color: "var(--color-body)",
                          }}
                        >
                          {t.state.replace(/_/g, " ")}
                        </span>
                        <span className="font-mono text-[12px] truncate">{t.target_identifier}</span>
                        <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                          · {t.partner}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {relations.sightings.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                  <span className="text-[11px] font-bold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                    Actor sightings ({relations.sightings.length})
                  </span>
                </div>
                <ul className="space-y-1.5">
                  {relations.sightings.map((s) => (
                    <li key={s.id}>
                      <Link
                        href={`/actors/${s.threat_actor_id}`}
                        className="flex items-center gap-2 text-[13px] py-1 px-2 rounded transition-colors"
                        style={{ color: "var(--color-ink)" }}
                      >
                        <span className="font-semibold">{s.actor_alias}</span>
                        <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                          as <span className="font-mono">{s.alias_used}</span> on {s.source_platform}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
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

        {/* Indicators (IOCs) backing this alert. Wired by feed
            triage: every IOC the LLM batch-reasoned about gets
            ``source_alert_id`` set on the alert it produced. */}
        {iocs && iocs.length > 0 && (
          <div
            className="p-6"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
            }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
                <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
                  Indicators ({iocs.length})
                </h3>
              </div>
              <Link
                href={`/iocs?source_alert_id=${alert.id}`}
                className="text-[12px] font-semibold"
                style={{ color: "var(--color-accent)" }}
              >
                View in IOC explorer →
              </Link>
            </div>
            <p className="text-[12.5px] mb-3" style={{ color: "var(--color-muted)" }}>
              The feed-triage agent reasoned about these indicators when it
              created this alert. They&apos;re the evidence — block, hunt, or
              correlate against your telemetry.
            </p>
            <div
              className="overflow-hidden"
              style={{ border: "1px solid var(--color-border)", borderRadius: 4 }}
            >
              <table className="w-full text-[12.5px]" style={{ borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--color-surface-muted)" }}>
                    <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                      Type
                    </th>
                    <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                      Value
                    </th>
                    <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                      Tags
                    </th>
                    <th className="px-3 py-2 text-right text-[10px] font-semibold uppercase tracking-[0.7px]" style={{ color: "var(--color-muted)" }}>
                      Confidence
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.slice(0, 25).map((ioc) => (
                    <tr key={ioc.id} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                      <td className="px-3 py-2 align-top">
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 text-[11px] font-mono"
                          style={{
                            background: "var(--color-surface-muted)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 3,
                            color: "var(--color-body)",
                          }}
                        >
                          {ioc.ioc_type}
                        </span>
                      </td>
                      <td className="px-3 py-2 align-top">
                        <Link
                          href={`/iocs/${ioc.id}`}
                          className="font-mono text-[12px] break-all"
                          style={{ color: "var(--color-accent)" }}
                        >
                          {ioc.value}
                        </Link>
                      </td>
                      <td className="px-3 py-2 align-top">
                        <div className="flex flex-wrap gap-1">
                          {(ioc.tags || []).slice(0, 3).map((t, i) => (
                            <span
                              key={`${t}-${i}`}
                              className="inline-flex items-center px-1.5 py-0.5 text-[10px]"
                              style={{
                                background: "var(--color-surface-muted)",
                                border: "1px solid var(--color-border)",
                                borderRadius: 3,
                                color: "var(--color-muted)",
                              }}
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2 align-top text-right font-mono text-[12px]" style={{ color: "var(--color-body)" }}>
                        {Math.round(ioc.confidence * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {iocs.length > 25 && (
              <p className="text-[11.5px] mt-2" style={{ color: "var(--color-muted)" }}>
                Showing 25 of {iocs.length}. Use the IOC explorer for the full list.
              </p>
            )}
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

        {alert.status === "needs_review" && (
          <div
            className="mb-4 p-3 flex items-start gap-3"
            style={{
              background: "rgba(255,171,0,0.08)",
              border: "1px solid rgba(255,171,0,0.3)",
              borderRadius: 5,
            }}
          >
            <div className="flex-1">
              <div className="text-[13px] font-semibold" style={{ color: "#B76E00" }}>
                Awaiting human review
              </div>
              <p className="text-[12px] mt-0.5" style={{ color: "var(--color-body)" }}>
                The triage agent flagged this below the org&apos;s confidence threshold
                (<strong>{Math.round((alert.confidence ?? 0) * 100)}%</strong>) and
                deferred to an analyst. Approve to promote it to a regular alert,
                or mark it as a false positive to suppress similar future signals.
              </p>
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                onClick={() => handleStatusChange("triaged")}
                disabled={saving}
                title="Promote this needs-review alert into the regular pool — analyst confirms it is real and worth investigating."
                className="px-3 py-1.5 text-[12px] font-semibold transition-colors disabled:opacity-50"
                style={{
                  borderRadius: 4,
                  border: "1px solid #22C55E",
                  background: "#22C55E",
                  color: "#fff",
                }}
              >
                Approve
              </button>
              <button
                onClick={() => handleStatusChange("false_positive")}
                disabled={saving}
                className="px-3 py-1.5 text-[12px] font-semibold transition-colors disabled:opacity-50"
                style={{
                  borderRadius: 4,
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-body)",
                }}
              >
                Reject
              </button>
            </div>
          </div>
        )}

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

      {overrideField && alert && (
        <OverrideModal
          field={overrideField}
          currentValue={
            overrideField === "severity" ? alert.severity : alert.category
          }
          onClose={() => setOverrideField(null)}
          onSubmit={(value, reason) =>
            handleOverrideSubmit(overrideField, value, reason)
          }
          saving={saving}
        />
      )}
    </main>
  );
}

// Modal: analyst override of severity / category. Both legs require a
// non-empty reason — the backend 422s if it's missing — so the audit
// trail captures *why* the analyst disagreed with the agent. The
// reason is saved into audit_logs.after.override_reason as structured
// JSON (not into analyst_notes free text), so compliance can grep it.
function OverrideModal({
  field,
  currentValue,
  onClose,
  onSubmit,
  saving,
}: {
  field: "severity" | "category";
  currentValue: string;
  onClose: () => void;
  onSubmit: (value: string, reason: string) => void;
  saving: boolean;
}) {
  const [value, setValue] = useState(currentValue);
  const [reason, setReason] = useState("");
  const options =
    field === "severity"
      ? ALERT_SEVERITIES.map((s) => ({
          value: s,
          label: s.charAt(0).toUpperCase() + s.slice(1),
        }))
      : ALERT_CATEGORIES.map((c) => ({
          value: c,
          label: categoryLabels[c] || c,
        }));
  const canSubmit = value !== currentValue && reason.trim().length > 0 && !saving;
  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.32)",
          zIndex: 70,
        }}
      />
      <div
        role="dialog"
        aria-label={`Override ${field}`}
        style={{
          position: "fixed",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          width: "min(440px, 92vw)",
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 6,
          zIndex: 71,
          boxShadow: "0 16px 48px rgba(0,0,0,0.22)",
        }}
      >
        <header
          style={{
            padding: "14px 18px",
            borderBottom: "1px solid var(--color-border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h3 className="text-[14px] font-semibold capitalize" style={{ color: "var(--color-ink)" }}>
            Override {field}
          </h3>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-muted)",
              fontSize: 18,
              cursor: "pointer",
              padding: 0,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </header>
        <div className="p-5 space-y-4">
          <p className="text-[12.5px]" style={{ color: "var(--color-body)" }}>
            Mutates this alert&apos;s {field} and writes an audit-log row. The
            agent&apos;s original {field} stays in audit history. Use this when
            you&apos;re confident the agent got it wrong — feedback alone
            doesn&apos;t change the live alert.
          </p>
          <div>
            <label className="text-[11px] font-bold uppercase tracking-[0.6px] block mb-2" style={{ color: "var(--color-muted)" }}>
              New {field}
            </label>
            <ThemedSelect
              value={value}
              onChange={setValue}
              ariaLabel={`New ${field}`}
              options={options}
              style={{ width: "100%" }}
            />
          </div>
          <div>
            <label className="text-[11px] font-bold uppercase tracking-[0.6px] block mb-2" style={{ color: "var(--color-muted)" }}>
              Reason <span style={{ color: "var(--color-error)" }}>*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why are you overriding the agent? Goes to the audit trail."
              rows={3}
              className="w-full px-3 py-2 rounded-[4px] border text-[13px] outline-none resize-none transition-colors bg-[var(--color-canvas)] border-[var(--color-border)] text-[var(--color-ink)] placeholder:text-[var(--color-muted)] focus:border-[var(--color-border-strong)]"
            />
          </div>
        </div>
        <footer
          style={{
            padding: "12px 18px",
            borderTop: "1px solid var(--color-border)",
            display: "flex",
            justifyContent: "flex-end",
            gap: 8,
          }}
        >
          <button
            onClick={onClose}
            disabled={saving}
            className="h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Cancel
          </button>
          <button
            onClick={() => onSubmit(value, reason.trim())}
            disabled={!canSubmit}
            className="h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            {saving ? "Saving..." : "Apply override"}
          </button>
        </footer>
      </div>
    </>
  );
}
