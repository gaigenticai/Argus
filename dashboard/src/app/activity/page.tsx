"use client";

import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Bot,
  Brain,
  Database,
  Globe,
  Bell,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  Pause,
  Play,
  Trash2,
  ChevronDown,
  Zap,
  Shield,
  Radio,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface ActivityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  agent: string;
  message: string;
  details: Record<string, unknown>;
  severity: string;
}

const AGENT_CONFIG: Record<string, { icon: typeof Activity; color: string; bg: string; label: string }> = {
  crawler: { icon: Bot, color: "#00A76F", bg: "rgba(0,167,111,0.12)", label: "Crawler" },
  triage: { icon: Brain, color: "var(--color-accent)", bg: "rgba(255,79,0,0.1)", label: "Triage Agent" },
  pipeline: { icon: Database, color: "#00BBD9", bg: "rgba(0,187,217,0.1)", label: "Pipeline" },
  scan: { icon: Globe, color: "#FFAB00", bg: "rgba(255,171,0,0.12)", label: "Scanner" },
  notification: { icon: Bell, color: "#FF5630", bg: "rgba(255,86,48,0.1)", label: "Notifier" },
  system: { icon: Zap, color: "var(--color-muted)", bg: "rgba(147,144,132,0.12)", label: "System" },
};

const SEVERITY_CONFIG: Record<string, { icon: typeof CheckCircle; color: string }> = {
  info: { icon: CheckCircle, color: "#00BBD9" },
  warning: { icon: AlertTriangle, color: "#FFAB00" },
  error: { icon: XCircle, color: "#FF5630" },
};

function getAgentConfig(eventType: string) {
  const prefix = eventType.split("_")[0];
  return AGENT_CONFIG[prefix] || AGENT_CONFIG.system;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatTimeFull(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export default function ActivityPage() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const feedRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const pausedEventsRef = useRef<ActivityEvent[]>([]);

  useEffect(() => {
    const es = new EventSource(`${API_BASE}/activity/stream`);
    eventSourceRef.current = es;
    es.onopen = () => setConnected(true);
    es.onmessage = (msg) => {
      try {
        const event: ActivityEvent = JSON.parse(msg.data);
        if (paused) {
          pausedEventsRef.current.push(event);
        } else {
          setEvents((prev) => {
            if (prev.some((e) => e.id === event.id)) return prev;
            const next = [...prev, event];
            return next.length > 1000 ? next.slice(-1000) : next;
          });
        }
      } catch {}
    };
    es.onerror = () => setConnected(false);
    return () => { es.close(); eventSourceRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!paused && pausedEventsRef.current.length > 0) {
      setEvents((prev) => {
        const merged = [...prev, ...pausedEventsRef.current];
        pausedEventsRef.current = [];
        return merged.length > 1000 ? merged.slice(-1000) : merged;
      });
    }
  }, [paused]);

  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  function handleScroll() {
    if (!feedRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 60);
  }

  const filteredEvents = events.filter((e) => {
    if (agentFilter !== "all") {
      const prefix = e.event_type.split("_")[0];
      if (prefix !== agentFilter) return false;
    }
    if (filter) {
      const q = filter.toLowerCase();
      return e.message.toLowerCase().includes(q) || e.event_type.toLowerCase().includes(q) || e.agent.toLowerCase().includes(q);
    }
    return true;
  });

  const agentTypes = Array.from(new Set(events.map((e) => e.event_type.split("_")[0])));

  return (
    <div className="flex flex-col h-[calc(100vh-72px)]">
      {/* Header */}
      <div className="shrink-0">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
              Live activity
            </h2>
            <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              Real-time view of all agent, crawler, and scanner operations
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div
              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium"
              style={{
                borderRadius: "20px",
                background: connected ? "rgba(0,167,111,0.1)" : "rgba(255,86,48,0.1)",
                color: connected ? "#007B55" : "#B71D18",
              }}
            >
              <Radio className="w-3.5 h-3.5" />
              {connected ? "Connected" : "Disconnected"}
            </div>
            <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
              {events.length} events
            </span>
          </div>
        </div>

        {/* Toolbar */}
        <div className="flex gap-2 items-center mt-4 mb-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--color-muted)" }} />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter events..."
              className="w-full h-10 pl-9 pr-3 text-[13px] outline-none transition-colors"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
              }}
            />
          </div>

          <div className="relative">
            <select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              className="appearance-none h-10 pl-3 pr-8 text-[13px] outline-none cursor-pointer"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              <option value="all">All agents</option>
              {agentTypes.map((t) => (
                <option key={t} value={t}>{AGENT_CONFIG[t]?.label || t}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: "var(--color-muted)" }} />
          </div>

          <button
            onClick={() => setPaused(!paused)}
            className="flex items-center gap-1.5 h-10 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: paused ? "1px solid #FFAB00" : "1px solid var(--color-border-strong)",
              background: paused ? "#FFAB00" : "var(--color-surface-dark)",
              color: "var(--color-on-dark)",
            }}
          >
            {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            {paused ? `Resume (${pausedEventsRef.current.length} queued)` : "Pause"}
          </button>

          <button
            onClick={() => { setEvents([]); pausedEventsRef.current = []; }}
            className="flex items-center gap-1.5 h-10 px-4 text-[13px] font-semibold transition-colors"
            style={{
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Event feed — dark terminal preserved */}
      <div
        ref={feedRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
        style={{
          background: "#161C24",
          border: "1px solid rgba(54,52,46,0.6)",
          borderRadius: "5px",
        }}
      >
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-20">
            <Activity className="w-12 h-12 mb-4" style={{ color: "rgba(147,144,132,0.3)" }} />
            <h3 className="text-[15px] font-semibold mb-1" style={{ color: "rgba(147,144,132,0.6)" }}>
              {events.length === 0 ? "Waiting for activity..." : "No matching events"}
            </h3>
            <p className="text-[13px] max-w-sm" style={{ color: "rgba(147,144,132,0.4)" }}>
              {events.length === 0
                ? "Run a crawler, trigger a scan, or start the pipeline to see live events here."
                : "Try adjusting your filter or agent selection."}
            </p>
          </div>
        ) : (
          <div style={{ borderColor: "rgba(54,52,46,0.4)" }} className="divide-y divide-[rgba(54,52,46,0.4)]">
            {filteredEvents.map((event) => {
              const config = getAgentConfig(event.event_type);
              const sevConfig = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info;
              const Icon = config.icon;
              const isExpanded = expandedId === event.id;

              return (
                <div
                  key={event.id}
                  className="group px-4 py-2.5 cursor-pointer transition-colors"
                  style={{}}
                  onMouseEnter={e => (e.currentTarget.style.background = "rgba(54,52,46,0.3)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  onClick={() => setExpandedId(isExpanded ? null : event.id)}
                >
                  <div className="flex items-start gap-3">
                    <span className="text-[11px] font-mono mt-0.5 shrink-0 w-[68px]" style={{ color: "rgba(147,144,132,0.5)" }}>
                      {formatTime(event.timestamp)}
                    </span>

                    <div
                      className="w-6 h-6 flex items-center justify-center shrink-0"
                      style={{ borderRadius: "4px", background: config.bg }}
                    >
                      <Icon className="w-3.5 h-3.5" style={{ color: config.color }} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: config.color }}>
                          {event.agent}
                        </span>
                        <span className="text-[11px] font-mono" style={{ color: "rgba(147,144,132,0.4)" }}>
                          {event.event_type}
                        </span>
                      </div>
                      <p className="text-[13px] mt-0.5 leading-snug" style={{ color: "rgba(255,254,251,0.7)" }}>
                        {event.message}
                      </p>

                      {isExpanded && Object.keys(event.details).length > 0 && (
                        <div
                          className="mt-2 p-3"
                          style={{
                            background: "#0A0E12",
                            borderRadius: "4px",
                            border: "1px solid rgba(54,52,46,0.5)",
                          }}
                        >
                          <div className="text-[10px] font-semibold uppercase tracking-[0.8px] mb-1.5" style={{ color: "rgba(147,144,132,0.5)" }}>Details</div>
                          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                            {Object.entries(event.details).map(([key, val]) => (
                              <div key={key} className="contents">
                                <span className="text-[12px] font-mono" style={{ color: "rgba(147,144,132,0.6)" }}>{key}:</span>
                                <span className="text-[12px] font-mono truncate" style={{ color: "rgba(147,144,132,0.5)" }}>
                                  {typeof val === "object" ? JSON.stringify(val) : String(val)}
                                </span>
                              </div>
                            ))}
                          </div>
                          <div className="text-[11px] font-mono mt-2" style={{ color: "rgba(147,144,132,0.3)" }}>
                            {formatTimeFull(event.timestamp)} · id:{event.id}
                          </div>
                        </div>
                      )}
                    </div>

                    {event.severity !== "info" && (
                      <div className="shrink-0 mt-0.5">
                        {(() => {
                          const SevIcon = sevConfig.icon;
                          return <SevIcon className="w-4 h-4" style={{ color: sevConfig.color }} />;
                        })()}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && filteredEvents.length > 0 && (
        <button
          onClick={() => {
            setAutoScroll(true);
            if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
          }}
          className="absolute bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-1.5 px-4 py-2 text-[12px] font-semibold transition-colors"
          style={{
            borderRadius: "20px",
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
            boxShadow: "var(--shadow-z16)",
          }}
        >
          <ChevronDown className="w-4 h-4" />
          New events below
        </button>
      )}
    </div>
  );
}
