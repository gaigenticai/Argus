"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Brain,
  CheckCircle,
  ClipboardList,
  Target,
} from "lucide-react";
import { api, type Alert } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { categoryLabels, formatDate } from "@/lib/utils";

const STATUS_OPTIONS = [
  "new",
  "triaged",
  "investigating",
  "confirmed",
  "false_positive",
  "resolved",
];

export default function AlertDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getAlert(params.id as string);
        setAlert(data);
        setNotes(data.analyst_notes || "");
      } catch {
        // not found
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
    } catch {
      // error
    }
    setSaving(false);
  };

  const handleSaveNotes = async () => {
    if (!alert) return;
    setSaving(true);
    try {
      const updated = await api.updateAlert(alert.id, { analyst_notes: notes });
      setAlert(updated);
    } catch {
      // error
    }
    setSaving(false);
  };

  if (!alert) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Back button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-[14px] text-[#637381] hover:text-[#1C252E] transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to alerts
      </button>

      {/* Header */}
      <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="text-[12px] text-[#919EAB]">
              {categoryLabels[alert.category] || alert.category}
            </span>
          </div>
          <span className="text-[13px] text-[#919EAB]">
            {formatDate(alert.created_at)}
          </span>
        </div>

        <h1 className="text-[24px] font-bold text-[#1C252E] mb-2">{alert.title}</h1>
        <p className="text-[14px] text-[#637381] leading-relaxed">{alert.summary}</p>

        <div className="mt-4 flex items-center gap-2">
          <span className="text-[12px] font-semibold text-[#919EAB]">Confidence:</span>
          <div className="w-32 h-2 bg-[#F4F6F8] rounded-full overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{
                width: `${alert.confidence * 100}%`,
                backgroundColor:
                  alert.confidence >= 0.8 ? "#22C55E" : alert.confidence >= 0.5 ? "#FFAB00" : "#919EAB",
              }}
            />
          </div>
          <span className="text-[12px] font-bold text-[#1C252E]">
            {Math.round(alert.confidence * 100)}%
          </span>
        </div>
      </div>

      {/* AI Analysis */}
      {alert.agent_reasoning && (
        <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5 text-[#8E33FF]" />
            <h3 className="text-[16px] font-bold text-[#1C252E]">AI analysis</h3>
          </div>
          <p className="text-[14px] text-[#454F5B] leading-relaxed whitespace-pre-wrap">
            {alert.agent_reasoning}
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Matched entities */}
        {alert.matched_entities && Object.keys(alert.matched_entities).length > 0 && (
          <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-5 h-5 text-[#FF5630]" />
              <h3 className="text-[16px] font-bold text-[#1C252E]">Matched entities</h3>
            </div>
            <div className="space-y-2">
              {Object.entries(alert.matched_entities).map(([key, val]) => (
                <div key={key} className="flex items-start gap-2">
                  <span className="text-[13px] font-semibold text-[#1C252E] shrink-0">{key}:</span>
                  <span className="text-[13px] text-[#637381]">{val}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended actions */}
        {alert.recommended_actions && alert.recommended_actions.length > 0 && (
          <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
            <div className="flex items-center gap-2 mb-3">
              <ClipboardList className="w-5 h-5 text-[#00A76F]" />
              <h3 className="text-[16px] font-bold text-[#1C252E]">Recommended actions</h3>
            </div>
            <ul className="space-y-2">
              {alert.recommended_actions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-[13px] text-[#454F5B]">
                  <CheckCircle className="w-4 h-4 text-[#00A76F] shrink-0 mt-0.5" />
                  {action}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Status update + Analyst notes */}
      <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
        <h3 className="text-[16px] font-bold text-[#1C252E] mb-4">Actions</h3>

        <div className="flex gap-3 mb-4">
          <label className="text-[13px] font-semibold text-[#637381] self-center">Status:</label>
          <div className="flex gap-2 flex-wrap">
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => handleStatusChange(s)}
                disabled={saving}
                className={`px-3 py-1.5 rounded-lg text-[12px] font-semibold capitalize transition-colors ${
                  alert.status === s
                    ? "bg-[#00A76F] text-white"
                    : "bg-[#F4F6F8] text-[#637381] hover:bg-[#DFE3E8]"
                }`}
              >
                {s.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="text-[13px] font-semibold text-[#637381] block mb-2">
            Analyst notes
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Add your investigation notes..."
            rows={4}
            className="w-full p-3 rounded-xl border border-[#DFE3E8] text-[14px] text-[#1C252E] placeholder:text-[#C4CDD5] outline-none focus:border-[#00A76F] transition-colors resize-none"
          />
          <button
            onClick={handleSaveNotes}
            disabled={saving}
            className="mt-2 px-4 py-2 bg-[#1C252E] text-white text-[13px] font-bold rounded-xl hover:bg-[#454F5B] transition-colors disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save notes"}
          </button>
        </div>
      </div>
    </div>
  );
}
