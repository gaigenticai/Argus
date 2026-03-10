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
  if (score >= 0.8) return { bar: "bg-error", text: "text-error-dark", label: "Critical" };
  if (score >= 0.6) return { bar: "bg-warning", text: "text-warning-dark", label: "High" };
  if (score >= 0.4) return { bar: "bg-info", text: "text-info-dark", label: "Medium" };
  return { bar: "bg-grey-400", text: "text-grey-600", label: "Low" };
}

const TYPE_COLORS: Record<string, { bg: string; text: string }> = {
  ipv4: { bg: "bg-info-lighter", text: "text-info-dark" },
  ipv6: { bg: "bg-info-lighter", text: "text-info-dark" },
  domain: { bg: "bg-primary-lighter", text: "text-primary-dark" },
  url: { bg: "bg-primary-lighter", text: "text-primary-dark" },
  email: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  md5: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  sha1: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  sha256: { bg: "bg-secondary-lighter", text: "text-secondary-dark" },
  btc_address: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  xmr_address: { bg: "bg-warning-lighter", text: "text-warning-dark" },
  cve: { bg: "bg-error-lighter", text: "text-error-dark" },
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

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[400px]">
        <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!actor) {
    return (
      <div className="flex flex-col items-center justify-center h-[400px] text-grey-500">
        <Shield className="w-8 h-8 mb-2 text-grey-400" />
        <p className="text-[14px]">Actor not found</p>
        <Link href="/actors" className="text-primary text-[14px] font-semibold mt-2 hover:text-primary-dark">
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
        className="inline-flex items-center gap-2 text-[14px] font-semibold text-grey-500 hover:text-grey-700 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Threat Actors
      </Link>

      {/* Profile Header */}
      <div className="bg-white rounded-xl border border-grey-200 p-6">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-[22px] font-bold text-grey-900">{actor.primary_alias}</h2>
            {actor.aliases.length > 0 && (
              <p className="text-[14px] text-grey-500 mt-1">
                Also known as: {actor.aliases.join(", ")}
              </p>
            )}
            {actor.description && (
              <p className="text-[14px] text-grey-600 mt-3 max-w-2xl">{actor.description}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={load}
              className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {/* Risk Score */}
          <div className="bg-grey-50 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-grey-500 mb-2">Risk Score</div>
            <div className="flex items-center gap-3">
              <span className={`text-[28px] font-bold ${risk.text}`}>
                {Math.round(actor.risk_score * 100)}
              </span>
              <div className="flex-1">
                <div className="w-full h-2 bg-grey-200 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${risk.bar}`} style={{ width: `${actor.risk_score * 100}%` }} />
                </div>
                <span className={`text-[11px] font-bold ${risk.text} mt-0.5`}>{risk.label}</span>
              </div>
            </div>
          </div>

          {/* Sightings */}
          <div className="bg-grey-50 rounded-lg p-4">
            <div className="text-[11px] font-bold uppercase tracking-wider text-grey-500 mb-2">Total Sightings</div>
            <div className="text-[28px] font-bold text-grey-900">{actor.total_sightings}</div>
          </div>

          {/* Platforms */}
          <div className="bg-grey-50 rounded-lg p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <Globe className="w-3.5 h-3.5 text-grey-500" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-grey-500">Platforms</span>
            </div>
            <div className="flex gap-1 flex-wrap">
              {actor.forums_active.length > 0 ? actor.forums_active.map((p) => (
                <span key={p} className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-secondary-lighter text-secondary-dark">
                  {p}
                </span>
              )) : <span className="text-[13px] text-grey-400">None recorded</span>}
            </div>
          </div>

          {/* Languages */}
          <div className="bg-grey-50 rounded-lg p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <Languages className="w-3.5 h-3.5 text-grey-500" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-grey-500">Languages</span>
            </div>
            <div className="flex gap-1 flex-wrap">
              {actor.languages.length > 0 ? actor.languages.map((l) => (
                <span key={l} className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-info-lighter text-info-dark">
                  {l}
                </span>
              )) : <span className="text-[13px] text-grey-400">Unknown</span>}
            </div>
          </div>

          {/* Timeline */}
          <div className="bg-grey-50 rounded-lg p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <Calendar className="w-3.5 h-3.5 text-grey-500" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-grey-500">Active Period</span>
            </div>
            <div className="text-[12px] text-grey-600">
              <div>First: {formatDate(actor.first_seen)}</div>
              <div>Last: {timeAgo(actor.last_seen)}</div>
            </div>
          </div>
        </div>

        {/* TTPs */}
        {actor.known_ttps.length > 0 && (
          <div className="mt-4 pt-4 border-t border-grey-200">
            <div className="text-[11px] font-bold uppercase tracking-wider text-grey-500 mb-2">Known TTPs (MITRE ATT&CK)</div>
            <div className="flex gap-1 flex-wrap">
              {actor.known_ttps.map((ttp) => (
                <span key={ttp} className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-error-lighter text-error-dark">
                  {ttp}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Section Tabs */}
      <div className="flex gap-1 border-b border-grey-200">
        <button
          onClick={() => setActiveSection("timeline")}
          className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold border-b-2 transition-colors ${
            activeSection === "timeline" ? "border-primary text-primary" : "border-transparent text-grey-500 hover:text-grey-700"
          }`}
        >
          <Calendar className="w-4 h-4" />
          Timeline ({timeline.length})
        </button>
        <button
          onClick={() => setActiveSection("iocs")}
          className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold border-b-2 transition-colors ${
            activeSection === "iocs" ? "border-primary text-primary" : "border-transparent text-grey-500 hover:text-grey-700"
          }`}
        >
          <Crosshair className="w-4 h-4" />
          IOCs ({iocs.length})
        </button>
        <button
          onClick={() => setActiveSection("alerts")}
          className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold border-b-2 transition-colors ${
            activeSection === "alerts" ? "border-primary text-primary" : "border-transparent text-grey-500 hover:text-grey-700"
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          Alerts ({alerts.length})
        </button>
      </div>

      {/* Timeline */}
      {activeSection === "timeline" && (
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          {timeline.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-grey-500">
              <p className="text-[14px]">No sightings recorded</p>
            </div>
          ) : (
            <div className="divide-y divide-grey-100">
              {timeline.map((sighting, idx) => (
                <div key={idx} className="px-6 py-4 flex items-start gap-4">
                  <div className="w-2 h-2 rounded-full bg-primary mt-2 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-[13px] font-semibold text-grey-800">{sighting.alias_used}</span>
                      <span className="inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center bg-secondary-lighter text-secondary-dark">
                        {sighting.platform}
                      </span>
                    </div>
                    <div className="text-[12px] text-grey-500">
                      {formatDate(sighting.timestamp)}
                    </div>
                    {sighting.context && (
                      <pre className="text-[12px] font-mono text-grey-600 bg-grey-50 rounded-lg p-2 mt-2 overflow-x-auto max-w-full">
                        {JSON.stringify(sighting.context, null, 2)}
                      </pre>
                    )}
                    <div className="flex gap-3 mt-2">
                      {sighting.alert_id && (
                        <Link
                          href={`/alerts/${sighting.alert_id}`}
                          className="text-[12px] font-semibold text-primary hover:text-primary-dark transition-colors"
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
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          {iocs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-grey-500">
              <p className="text-[14px]">No linked IOCs</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-grey-100">
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Type</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Value</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Confidence</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Sightings</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => {
                  const colors = TYPE_COLORS[ioc.ioc_type] || { bg: "bg-grey-200", text: "text-grey-700" };
                  return (
                    <tr key={ioc.id} className="h-[52px] border-b border-grey-100 last:border-b-0">
                      <td className="px-4">
                        <span className={`inline-flex h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide items-center ${colors.bg} ${colors.text}`}>
                          {ioc.ioc_type}
                        </span>
                      </td>
                      <td className="px-4 text-[13px] font-mono text-grey-800 max-w-[300px] truncate">{ioc.value}</td>
                      <td className="px-4 text-[13px] text-grey-600">{Math.round(ioc.confidence * 100)}%</td>
                      <td className="px-4 text-[13px] text-grey-600">{ioc.sighting_count}</td>
                      <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">{formatDate(ioc.last_seen)}</td>
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
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-grey-500">
              <p className="text-[14px]">No linked alerts</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-grey-100">
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Severity</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Title</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Category</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Status</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold uppercase text-grey-600 tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id} className="h-[52px] border-b border-grey-100 last:border-b-0 hover:bg-grey-50 transition-colors">
                    <td className="px-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-4">
                      <Link
                        href={`/alerts/${alert.id}`}
                        className="text-[14px] font-semibold text-grey-800 hover:text-primary transition-colors line-clamp-1"
                      >
                        {alert.title}
                      </Link>
                    </td>
                    <td className="px-4 text-[13px] text-grey-600">{alert.category.replace(/_/g, " ")}</td>
                    <td className="px-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="px-4 text-[13px] text-grey-500 whitespace-nowrap">
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
