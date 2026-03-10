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

// Map event_type prefix to visual config
const AGENT_CONFIG: Record<string, { icon: typeof Activity; color: string; bg: string; label: string }> = {
  crawler: { icon: Bot, color: "#00A76F", bg: "bg-[#00A76F]/10", label: "Crawler" },
  triage: { icon: Brain, color: "#8E33FF", bg: "bg-[#8E33FF]/10", label: "Triage Agent" },
  pipeline: { icon: Database, color: "#00BBD9", bg: "bg-[#00BBD9]/10", label: "Pipeline" },
  scan: { icon: Globe, color: "#FFAB00", bg: "bg-[#FFAB00]/10", label: "Scanner" },
  notification: { icon: Bell, color: "#FF5630", bg: "bg-[#FF5630]/10", label: "Notifier" },
  system: { icon: Zap, color: "#637381", bg: "bg-[#637381]/10", label: "System" },
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

  // SSE connection
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
            // Deduplicate by id
            if (prev.some((e) => e.id === event.id)) return prev;
            const next = [...prev, event];
            // Keep last 1000 events in memory
            return next.length > 1000 ? next.slice(-1000) : next;
          });
        }
      } catch {
        // Ignore parse errors (keepalive comments, etc.)
      }
    };

    es.onerror = () => {
      setConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle pause/resume
  useEffect(() => {
    if (!paused && pausedEventsRef.current.length > 0) {
      setEvents((prev) => {
        const merged = [...prev, ...pausedEventsRef.current];
        pausedEventsRef.current = [];
        return merged.length > 1000 ? merged.slice(-1000) : merged;
      });
    }
  }, [paused]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  // Handle scroll to detect manual scrolling
  function handleScroll() {
    if (!feedRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 60;
    setAutoScroll(isAtBottom);
  }

  // Filter events
  const filteredEvents = events.filter((e) => {
    if (agentFilter !== "all") {
      const prefix = e.event_type.split("_")[0];
      if (prefix !== agentFilter) return false;
    }
    if (filter) {
      const q = filter.toLowerCase();
      return (
        e.message.toLowerCase().includes(q) ||
        e.event_type.toLowerCase().includes(q) ||
        e.agent.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Unique agent types for filter dropdown
  const agentTypes = Array.from(new Set(events.map((e) => e.event_type.split("_")[0])));

  return (
    <div className="flex flex-col h-[calc(100vh-72px)]">
      {/* Header */}
      <div className="shrink-0">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-[22px] font-bold text-grey-900">Live activity</h2>
            <p className="text-[14px] text-grey-500 mt-0.5">
              Real-time view of all agent, crawler, and scanner operations
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Connection indicator */}
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium ${
              connected
                ? "bg-success-lighter text-success-dark"
                : "bg-error-lighter text-error-dark"
            }`}>
              <Radio className="w-3.5 h-3.5" />
              {connected ? "Connected" : "Disconnected"}
            </div>
            <span className="text-[12px] text-grey-500">
              {events.length} events
            </span>
          </div>
        </div>

        {/* Toolbar */}
        <div className="flex gap-2 items-center mt-4 mb-3">
          {/* Search */}
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-grey-500" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter events..."
              className="w-full h-10 pl-9 pr-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white placeholder:text-grey-300"
            />
          </div>

          {/* Agent filter */}
          <div className="relative">
            <select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              className="appearance-none h-10 pl-3 pr-8 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white cursor-pointer"
            >
              <option value="all">All agents</option>
              {agentTypes.map((t) => (
                <option key={t} value={t}>{AGENT_CONFIG[t]?.label || t}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-grey-500 pointer-events-none" />
          </div>

          {/* Pause / Resume */}
          <button
            onClick={() => setPaused(!paused)}
            className={`flex items-center gap-1.5 h-10 px-4 rounded-lg text-[14px] font-bold transition-colors ${
              paused
                ? "bg-warning text-white hover:bg-[#B76E00]"
                : "bg-grey-800 text-white hover:bg-grey-700"
            }`}
          >
            {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            {paused ? `Resume (${pausedEventsRef.current.length} queued)` : "Pause"}
          </button>

          {/* Clear */}
          <button
            onClick={() => { setEvents([]); pausedEventsRef.current = []; }}
            className="flex items-center gap-1.5 h-10 px-4 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Event feed — dark terminal theme preserved */}
      <div
        ref={feedRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto bg-[#161C24] rounded-xl border border-grey-800"
      >
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-20">
            <Activity className="w-12 h-12 text-grey-700 mb-4" />
            <h3 className="text-[16px] font-bold text-grey-500 mb-1">
              {events.length === 0 ? "Waiting for activity..." : "No matching events"}
            </h3>
            <p className="text-[13px] text-grey-600 max-w-sm">
              {events.length === 0
                ? "Run a crawler, trigger a scan, or start the pipeline to see live events here."
                : "Try adjusting your filter or agent selection."}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-grey-800">
            {filteredEvents.map((event) => {
              const config = getAgentConfig(event.event_type);
              const sevConfig = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info;
              const Icon = config.icon;
              const isExpanded = expandedId === event.id;

              return (
                <div
                  key={event.id}
                  className="group px-4 py-2.5 hover:bg-grey-800/60 cursor-pointer transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : event.id)}
                >
                  <div className="flex items-start gap-3">
                    {/* Time */}
                    <span className="text-[11px] font-mono text-grey-600 mt-0.5 shrink-0 w-[68px]">
                      {formatTime(event.timestamp)}
                    </span>

                    {/* Agent icon */}
                    <div
                      className={`w-6 h-6 rounded-md flex items-center justify-center shrink-0 ${config.bg}`}
                    >
                      <Icon className="w-3.5 h-3.5" style={{ color: config.color }} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className="text-[11px] font-bold uppercase tracking-wider"
                          style={{ color: config.color }}
                        >
                          {event.agent}
                        </span>
                        <span className="text-[11px] text-grey-700 font-mono">
                          {event.event_type}
                        </span>
                      </div>
                      <p className="text-[13px] text-grey-300 mt-0.5 leading-snug">
                        {event.message}
                      </p>

                      {/* Expanded details */}
                      {isExpanded && Object.keys(event.details).length > 0 && (
                        <div className="mt-2 p-3 bg-[#0A0E12] rounded-lg border border-grey-800">
                          <div className="text-[11px] font-bold text-grey-600 uppercase mb-1.5">Details</div>
                          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                            {Object.entries(event.details).map(([key, val]) => (
                              <div key={key} className="contents">
                                <span className="text-[12px] text-grey-600 font-mono">{key}:</span>
                                <span className="text-[12px] text-grey-500 font-mono truncate">
                                  {typeof val === "object" ? JSON.stringify(val) : String(val)}
                                </span>
                              </div>
                            ))}
                          </div>
                          <div className="text-[11px] text-grey-700 mt-2 font-mono">
                            {formatTimeFull(event.timestamp)} · id:{event.id}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Severity indicator */}
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
          className="absolute bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-1.5 px-4 py-2 bg-primary text-white rounded-full text-[12px] font-bold shadow-z16 hover:bg-primary-dark transition-colors"
        >
          <ChevronDown className="w-4 h-4" />
          New events below
        </button>
      )}
    </div>
  );
}
