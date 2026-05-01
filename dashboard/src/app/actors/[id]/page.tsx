"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  RefreshCw,
  Shield,
  Globe,
  Languages,
  Calendar,
  Crosshair,
  AlertTriangle,
} from "lucide-react";
import {
  api,
  type ThreatActorDetail,
  type TimelineEntry,
  type IOCItem,
  type Alert,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { formatDate, timeAgo } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatusBadge } from "@/components/shared/status-badge";

function riskColor(score: number): { bar: string; text: string; label: string } {
  if (score >= 0.8) return { bar: "#FF5630", text: "#B71D18", label: "Critical" };
  if (score >= 0.6) return { bar: "#FFAB00", text: "#B76E00", label: "High" };
  if (score >= 0.4) return { bar: "#00BBD9", text: "#007B8A", label: "Medium" };
  return { bar: "var(--color-muted)", text: "var(--color-muted)", label: "Low" };
}

const TYPE_COLORS: Record<string, { bg: string; color: string }> = {
  ipv4: { bg: "rgba(0,187,217,0.08)", color: "#007B8A" },
  ipv6: { bg: "rgba(0,187,217,0.08)", color: "#007B8A" },
  domain: { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)" },
  url: { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)" },
  email: { bg: "rgba(255,171,0,0.08)", color: "#B76E00" },
  md5: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  sha1: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  sha256: { bg: "var(--color-surface-muted)", color: "var(--color-body)" },
  btc_address: { bg: "rgba(255,171,0,0.08)", color: "#B76E00" },
  xmr_address: { bg: "rgba(255,171,0,0.08)", color: "#B76E00" },
  cve: { bg: "rgba(255,86,48,0.08)", color: "#B71D18" },
};

const btnSecondary: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-body)",
};

export default function ActorDetailPage() {
  const params = useParams();
  const actorId = params.id as string;
  const { toast } = useToast();

  const [actor, setActor] = useState<ThreatActorDetail | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [iocs, setIOCs] = useState<IOCItem[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState<"timeline" | "iocs" | "alerts">("timeline");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [actorData, timelineData, iocsData, alertsData] = await Promise.allSettled([
        api.getActor(actorId),
        api.getActorTimeline(actorId),
        api.getActorIOCs(actorId),
        api.getActorAlerts(actorId),
      ]);

      if (actorData.status === "fulfilled") setActor(actorData.value);
      else toast("error", "Failed to load actor details");

      if (timelineData.status === "fulfilled") setTimeline(timelineData.value);
      if (iocsData.status === "fulfilled") setIOCs(iocsData.value);
      if (alertsData.status === "fulfilled") setAlerts(alertsData.value);
    } catch {
      toast("error", "Failed to load actor data");
    }
    setLoading(false);
  }, [actorId, toast]);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[400px]">
        <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
      </div>
    );
  }

  if (!actor) {
    return (
      <div className="flex flex-col items-center justify-center h-[400px]" style={{ color: "var(--color-muted)" }}>
        <Shield className="w-8 h-8 mb-2" style={{ color: "var(--color-border)" }} />
        <p className="text-[13px]">Actor not found</p>
        <Link href="/actors" className="text-[13px] font-semibold mt-2 transition-colors" style={{ color: "var(--color-accent)" }}>
          Back to Threat Actors
        </Link>
      </div>
    );
  }

  const risk = riskColor(actor.risk_score);

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        href="/actors"
        className="inline-flex items-center gap-2 text-[13px] font-semibold transition-colors"
        style={{ color: "var(--color-muted)" }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-body)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-muted)")}
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Threat Actors
      </Link>

      {/* Profile Header */}
      <div
        className="p-6"
        style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}
      >
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>{actor.primary_alias}</h2>
            {actor.aliases.length > 0 && (
              <p className="text-[13px] mt-1" style={{ color: "var(--color-muted)" }}>
                Also known as: {actor.aliases.join(", ")}
              </p>
            )}
            {actor.description && (
              <p className="text-[13px] mt-3 max-w-2xl" style={{ color: "var(--color-body)" }}>{actor.description}</p>
            )}
          </div>
          <button onClick={load} className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors" style={btnSecondary}>
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {/* Risk Score */}
          <div className="p-4" style={{ background: "var(--color-surface)", borderRadius: "5px" }}>
            <div className="text-[10px] font-semibold uppercase tracking-[0.07em] mb-2" style={{ color: "var(--color-muted)" }}>Risk Score</div>
            <div className="flex items-center gap-3">
              <span className="text-[28px] font-bold" style={{ color: risk.text }}>
                {Math.round(actor.risk_score * 100)}
              </span>
              <div className="flex-1">
                <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: "var(--color-surface-muted)" }}>
                  <div className="h-full rounded-full" style={{ width: `${actor.risk_score * 100}%`, background: risk.bar }} />
                </div>
                <span className="text-[11px] font-semibold mt-0.5" style={{ color: risk.text }}>{risk.label}</span>
              </div>
            </div>
          </div>

          {/* Sightings */}
          <div className="p-4" style={{ background: "var(--color-surface)", borderRadius: "5px" }}>
            <div className="text-[10px] font-semibold uppercase tracking-[0.07em] mb-2" style={{ color: "var(--color-muted)" }}>Total Sightings</div>
            <div className="text-[28px] font-bold" style={{ color: "var(--color-ink)" }}>{actor.total_sightings}</div>
          </div>

          {/* Platforms */}
          <div className="p-4" style={{ background: "var(--color-surface)", borderRadius: "5px" }}>
            <div className="flex items-center gap-1.5 mb-2">
              <Globe className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Platforms</span>
            </div>
            <div className="flex gap-1 flex-wrap">
              {actor.forums_active.length > 0 ? actor.forums_active.map((p) => (
                <span
                  key={p}
                  className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                  style={{ borderRadius: "4px", background: "rgba(0,187,217,0.08)", color: "#007B8A" }}
                >
                  {p}
                </span>
              )) : <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>None recorded</span>}
            </div>
          </div>

          {/* Languages */}
          <div className="p-4" style={{ background: "var(--color-surface)", borderRadius: "5px" }}>
            <div className="flex items-center gap-1.5 mb-2">
              <Languages className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Languages</span>
            </div>
            <div className="flex gap-1 flex-wrap">
              {actor.languages.length > 0 ? actor.languages.map((l) => (
                <span
                  key={l}
                  className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                  style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                >
                  {l}
                </span>
              )) : <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>Unknown</span>}
            </div>
          </div>

          {/* Timeline */}
          <div className="p-4" style={{ background: "var(--color-surface)", borderRadius: "5px" }}>
            <div className="flex items-center gap-1.5 mb-2">
              <Calendar className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>Active Period</span>
            </div>
            <div className="text-[12px]" style={{ color: "var(--color-body)" }}>
              <div>First: {formatDate(actor.first_seen)}</div>
              <div>Last: {timeAgo(actor.last_seen)}</div>
            </div>
          </div>
        </div>

        {/* TTPs */}
        {actor.known_ttps.length > 0 && (
          <div className="mt-4 pt-4" style={{ borderTop: "1px solid var(--color-border)" }}>
            <div className="text-[10px] font-semibold uppercase tracking-[0.07em] mb-2" style={{ color: "var(--color-muted)" }}>Known TTPs (MITRE ATT&amp;CK)</div>
            <div className="flex gap-1 flex-wrap">
              {actor.known_ttps.map((ttp) => (
                <span
                  key={ttp}
                  className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                  style={{ borderRadius: "4px", background: "rgba(255,86,48,0.08)", color: "#B71D18" }}
                >
                  {ttp}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Section Tabs */}
      <div className="flex gap-0" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {[
          { id: "timeline" as const, icon: Calendar, label: `Timeline (${timeline.length})` },
          { id: "iocs" as const, icon: Crosshair, label: `IOCs (${iocs.length})` },
          { id: "alerts" as const, icon: AlertTriangle, label: `Alerts (${alerts.length})` },
        ].map(({ id, icon: Icon, label }) => {
          const isActive = activeSection === id;
          return (
            <button
              key={id}
              onClick={() => setActiveSection(id)}
              className="flex items-center gap-2 px-4 py-3 text-[13px] font-semibold transition-colors"
              style={{
                color: isActive ? "var(--color-accent)" : "var(--color-muted)",
                borderBottom: "none",
                boxShadow: isActive ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
                background: "transparent",
              }}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          );
        })}
      </div>

      {/* Timeline */}
      {activeSection === "timeline" && (
        <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
          {timeline.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px]" style={{ color: "var(--color-muted)" }}>
              <p className="text-[13px]">No sightings recorded</p>
            </div>
          ) : (
            <div style={{ borderColor: "var(--color-border)" }} className="divide-y">
              {timeline.map((sighting, idx) => (
                <div key={idx} className="px-6 py-4 flex items-start gap-4">
                  <div className="w-2 h-2 rounded-full mt-2 shrink-0" style={{ background: "var(--color-accent)" }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{sighting.alias_used}</span>
                      <span
                        className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                        style={{ borderRadius: "4px", background: "rgba(0,187,217,0.08)", color: "#007B8A" }}
                      >
                        {sighting.platform}
                      </span>
                    </div>
                    <div className="text-[12px]" style={{ color: "var(--color-muted)" }}>
                      {formatDate(sighting.timestamp)}
                    </div>
                    {sighting.context && (
                      <pre
                        className="text-[12px] font-mono p-2 mt-2 overflow-x-auto max-w-full"
                        style={{ background: "var(--color-surface)", borderRadius: "4px", color: "var(--color-body)" }}
                      >
                        {JSON.stringify(sighting.context, null, 2)}
                      </pre>
                    )}
                    <div className="flex gap-3 mt-2">
                      {sighting.alert_id && (
                        <Link
                          href={`/alerts/${sighting.alert_id}`}
                          className="text-[12px] font-semibold transition-colors"
                          style={{ color: "var(--color-accent)" }}
                        >
                          View Alert
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Linked IOCs */}
      {activeSection === "iocs" && (
        <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
          {iocs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px]" style={{ color: "var(--color-muted)" }}>
              <p className="text-[13px]">No linked IOCs</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                  {["Type", "Value", "Confidence", "Sightings", "Last Seen"].map((h) => (
                    <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => {
                  const colors = TYPE_COLORS[ioc.ioc_type] || { bg: "var(--color-surface-muted)", color: "var(--color-body)" };
                  return (
                    <tr
                      key={ioc.id}
                      className="h-[52px]"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="px-4">
                        <span
                          className="inline-flex h-[20px] px-2 text-[10px] font-semibold uppercase tracking-wide items-center"
                          style={{ borderRadius: "4px", background: colors.bg, color: colors.color }}
                        >
                          {ioc.ioc_type}
                        </span>
                      </td>
                      <td className="px-4 text-[13px] font-mono max-w-[300px] truncate" style={{ color: "var(--color-ink)" }}>{ioc.value}</td>
                      <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>{Math.round(ioc.confidence * 100)}%</td>
                      <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>{ioc.sighting_count}</td>
                      <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>{formatDate(ioc.last_seen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Linked Alerts */}
      {activeSection === "alerts" && (
        <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px]" style={{ color: "var(--color-muted)" }}>
              <p className="text-[13px]">No linked alerts</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                  {["Severity", "Title", "Category", "Status", "Date"].map((h) => (
                    <th key={h} className="text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]" style={{ color: "var(--color-muted)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="h-[52px] transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="px-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-4">
                      <Link
                        href={`/alerts/${alert.id}`}
                        className="text-[13px] font-semibold line-clamp-1 transition-colors"
                        style={{ color: "var(--color-ink)" }}
                        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-ink)")}
                      >
                        {alert.title}
                      </Link>
                    </td>
                    <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>{alert.category.replace(/_/g, " ")}</td>
                    <td className="px-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="px-4 text-[13px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                      {formatDate(alert.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
