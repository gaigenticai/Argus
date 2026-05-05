"use client";

/**
 * Crawlers page — manage and monitor intelligence collection agents.
 *
 * Argus ships 9 crawler KINDS (tor_forum / tor_marketplace /
 * telegram_channel / i2p_eepsite / lokinet_site / matrix_room /
 * forum / ransomware_leak_group / stealer_marketplace) — each one
 * is a code-defined agent that knows how to talk to a particular
 * category of source. Operators don't add new KINDS from this UI
 * (that needs a new Python crawler class); they add TARGETS to
 * existing kinds — e.g. "monitor the LockBit leak site under the
 * ransomware_leak_group kind."
 *
 * Per kind we render a friendly per-kind form (channel handle,
 * onion URLs as one-per-line textareas, etc.) so adding a target
 * doesn't require operators to know the underlying JSON shape.
 * "Advanced (JSON)" toggle is available for power users who want
 * to override.
 *
 * Every existing target is editable (display name, config, active
 * flag) and removable inline.
 */

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Activity,
  Bot,
  Play,
  CheckCircle,
  Clock,
  RefreshCw,
  Zap,
  AlertTriangle,
  CircleSlash,
  Plus,
  Trash2,
  Loader2,
  ChevronDown,
  ChevronRight,
  Info,
  Pencil,
  X,
  Check,
} from "lucide-react";
import {
  api,
  type Crawler,
  type CrawlerKind,
  type CrawlerTargetResponse,
  SSE_BASE,
} from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";

// Mirrors the shape of the events emitted by ``src/core/activity.py``.
// Kept local because the activity stream isn't typed in lib/api.ts.
interface ActivityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  agent: string;
  message: string;
  details: Record<string, unknown>;
  severity: string;
}

// ---------------------------------------------------------------------------
// Per-kind UI schema
//
// Maps each CrawlerKind to a friendly form spec. Fields can target
// the row's ``identifier`` / ``display_name`` columns or any
// dotted path inside ``config``. Operators never see raw JSON
// unless they flip the "Advanced" toggle.
//
// Stay in sync with ``ck_crawler_targets_kind`` in
// src/models/admin.py and the ``KWARG_NAME`` mapping in
// src/core/scheduler.py.
// ---------------------------------------------------------------------------

type FieldType = "text" | "textarea-lines" | "number" | "url" | "checkbox";

interface FieldDef {
  name: string;            // form-internal name
  label: string;
  type: FieldType;
  placeholder?: string;
  hint?: string;
  required?: boolean;
  mapTo: string;           // 'identifier' | 'display_name' | 'config.<key>' | 'config.<key>[]'
  defaultValue?: string | number | boolean | string[];
}

interface KindSchema {
  label: string;          // human-friendly category name
  description: string;
  exampleIdentifier: string;
  fields: FieldDef[];
}

const KIND_SCHEMAS: Record<string, KindSchema> = {
  telegram_channel: {
    label: "Telegram channel",
    description: "Public Telegram channels that publish security or threat-intel content.",
    exampleIdentifier: "DarkfeedNews",
    fields: [
      { name: "identifier", label: "Channel handle", type: "text", required: true,
        placeholder: "DarkfeedNews", hint: "Public channel handle (no @ prefix).",
        mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        placeholder: "Darkfeed News", mapTo: "display_name" },
    ],
  },
  matrix_room: {
    label: "Matrix room",
    description: "Public Matrix rooms federated through any homeserver.",
    exampleIdentifier: "#cybersecurity:matrix.org",
    fields: [
      { name: "identifier", label: "Room ID", type: "text", required: true,
        placeholder: "#cybersecurity:matrix.org",
        hint: "Format: #room:homeserver. Public rooms only.",
        mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "homeserver", label: "Homeserver URL", type: "url", required: true,
        placeholder: "https://matrix.org",
        defaultValue: "https://matrix.org",
        mapTo: "config.homeserver" },
    ],
  },
  ransomware_leak_group: {
    label: "Ransomware leak group",
    description: "Tor onion sites operated by ransomware crews to publish victim data.",
    exampleIdentifier: "lockbit",
    fields: [
      { name: "identifier", label: "Group slug", type: "text", required: true,
        placeholder: "lockbit",
        hint: "Short lowercase identifier (e.g. lockbit, akira, ransomhub).",
        mapTo: "identifier" },
      { name: "display_name", label: "Group name", type: "text",
        placeholder: "LockBit 3.0",
        mapTo: "display_name" },
      { name: "group_name", label: "Internal group name (optional)", type: "text",
        hint: "Defaults to the group slug when blank.",
        mapTo: "config.group_name" },
      { name: "onion_urls", label: "Onion URLs", type: "textarea-lines", required: true,
        placeholder: "http://lockbitapt....onion\nhttp://lockbit3753....onion",
        hint: "One per line. Argus will round-robin and time-out fast on dead mirrors.",
        mapTo: "config.onion_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, hint: "Higher = more thorough but slower.",
        mapTo: "config.max_pages" },
    ],
  },
  tor_forum: {
    label: "Tor forum",
    description: "Onion forums for general underground discussion (Dread, Exploit, etc.).",
    exampleIdentifier: "dread",
    fields: [
      { name: "identifier", label: "Forum slug", type: "text", required: true,
        placeholder: "dread", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "onion_urls", label: "Onion URLs", type: "textarea-lines", required: true,
        placeholder: "http://....onion",
        hint: "One per line.",
        mapTo: "config.onion_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  tor_marketplace: {
    label: "Tor marketplace",
    description: "Onion marketplaces — operator decides legal/policy fit before adding.",
    exampleIdentifier: "abacus",
    fields: [
      { name: "identifier", label: "Marketplace slug", type: "text", required: true,
        placeholder: "abacus", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "onion_urls", label: "Onion URLs", type: "textarea-lines", required: true,
        placeholder: "http://....onion",
        mapTo: "config.onion_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  stealer_marketplace: {
    label: "Stealer-log marketplace",
    description: "Sites selling credentials harvested by infostealers.",
    exampleIdentifier: "russianmarket",
    fields: [
      { name: "identifier", label: "Marketplace slug", type: "text", required: true,
        placeholder: "russianmarket", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "onion_urls", label: "Onion URLs", type: "textarea-lines", required: true,
        mapTo: "config.onion_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  i2p_eepsite: {
    label: "I2P eepsite",
    description: "Sites on the I2P network (.i2p / .b32.i2p addresses).",
    exampleIdentifier: "stats.i2p",
    fields: [
      { name: "identifier", label: "Eepsite slug", type: "text", required: true,
        placeholder: "stats.i2p", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "i2p_urls", label: "I2P URLs", type: "textarea-lines", required: true,
        placeholder: "http://....i2p",
        mapTo: "config.i2p_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  lokinet_site: {
    label: "Lokinet site",
    description: "Sites hosted on the Oxen / Lokinet network.",
    exampleIdentifier: "demo.loki",
    fields: [
      { name: "identifier", label: "Site slug", type: "text", required: true,
        placeholder: "demo.loki", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "loki_urls", label: "Lokinet URLs", type: "textarea-lines", required: true,
        placeholder: "http://....loki",
        mapTo: "config.loki_urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  forum: {
    label: "Clearnet forum",
    description: "Regular HTTP/HTTPS forums (xss.is alternatives, breach communities, etc.).",
    exampleIdentifier: "myforum",
    fields: [
      { name: "identifier", label: "Forum slug", type: "text", required: true,
        placeholder: "myforum", mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        mapTo: "display_name" },
      { name: "urls", label: "URLs to crawl", type: "textarea-lines", required: true,
        placeholder: "https://forum.example/threads",
        mapTo: "config.urls[]" },
      { name: "max_pages", label: "Max pages per crawl", type: "number",
        defaultValue: 3, mapTo: "config.max_pages" },
    ],
  },
  custom_http: {
    label: "Custom HTTP / RSS / JSON",
    description:
      "Generic poller — point it at any RSS feed, JSON API, or HTML page. Use this for blogs, vendor advisory feeds, threat-intel APIs, or anything that doesn't fit the kinds above. No code needed.",
    exampleIdentifier: "krebs-rss",
    fields: [
      { name: "identifier", label: "Source slug", type: "text", required: true,
        placeholder: "krebs-rss",
        hint: "Short identifier, used in logs and the IOC tags. Lowercase + dashes.",
        mapTo: "identifier" },
      { name: "display_name", label: "Display name (optional)", type: "text",
        placeholder: "Krebs on Security RSS",
        mapTo: "display_name" },
      { name: "url", label: "URL to poll", type: "url", required: true,
        placeholder: "https://krebsonsecurity.com/feed/",
        hint: "Full URL of the feed / API / page. Argus polls on the schedule shown above.",
        mapTo: "config.url" },
      { name: "parser", label: "Parser", type: "text", required: true,
        defaultValue: "rss",
        placeholder: "rss",
        hint: "One of: rss · json · html-css. RSS handles Atom + RSS 2.0; JSON walks an items array; html-css extracts items via a CSS selector.",
        mapTo: "config.parser" },
      { name: "items_path", label: "JSON items path (optional)", type: "text",
        placeholder: "data.results",
        hint: "Only for parser=json. Dotted path to the array of items, e.g. 'data.results' or 'records[*]'.",
        mapTo: "config.items_path" },
      { name: "title_field", label: "JSON title field", type: "text",
        defaultValue: "title",
        hint: "Field on each JSON item that holds the title.",
        mapTo: "config.title_field" },
      { name: "link_field", label: "JSON link field", type: "text",
        defaultValue: "url",
        hint: "Field on each JSON item that holds the canonical URL.",
        mapTo: "config.link_field" },
      { name: "item_selector", label: "CSS item selector (optional)", type: "text",
        placeholder: "article.post",
        hint: "Only for parser=html-css. CSS selector matching one item per page.",
        mapTo: "config.item_selector" },
      { name: "max_items", label: "Max items per poll", type: "number",
        defaultValue: 50,
        hint: "Hard cap so a runaway feed can't drown ingestion. Argus also caps at 100 internally.",
        mapTo: "config.max_items" },
    ],
  },
};

const STATUS_PRESENTATION: Record<
  string,
  { label: string; color: string; bg: string; icon: typeof CheckCircle }
> = {
  ok:            { label: "Healthy",       color: "var(--color-success-dark)", bg: "rgba(34,197,94,0.10)",  icon: CheckCircle },
  unconfigured:  { label: "Unconfigured",  color: "var(--color-muted)",        bg: "var(--color-surface-muted)", icon: CircleSlash },
  network_error: { label: "Network error", color: "var(--color-error-dark)",   bg: "rgba(239,68,68,0.10)",  icon: AlertTriangle },
  auth_error:    { label: "Auth error",    color: "#B76E00",                   bg: "rgba(255,171,0,0.10)",  icon: AlertTriangle },
  rate_limited:  { label: "Rate limited",  color: "#B76E00",                   bg: "rgba(255,171,0,0.10)",  icon: AlertTriangle },
  parse_error:   { label: "Parse error",   color: "var(--color-error-dark)",   bg: "rgba(239,68,68,0.10)",  icon: AlertTriangle },
  disabled:      { label: "Disabled",      color: "var(--color-muted)",        bg: "var(--color-surface-muted)", icon: CircleSlash },
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function CrawlersPage() {
  const [crawlers, setCrawlers] = useState<Crawler[]>([]);
  const [targetsByKind, setTargetsByKind] = useState<Record<string, CrawlerTargetResponse[]>>({});
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  useEffect(() => { void load(); }, []);

  // ``silent=true`` skips the loading spinner toggle so a mid-run
  // refresh (triggered from a CrawlerCard when its run completes)
  // doesn't swap the grid for a spinner — that would unmount every
  // card and wipe their per-card RunProgressPanel state. Initial
  // page mount still uses the loud variant for a proper skeleton.
  async function load(silent = false) {
    if (!silent) setLoading(true);
    try {
      const [crawlersData, targets] = await Promise.all([
        api.getCrawlers(),
        api.admin.listCrawlerTargets(),
      ]);
      setCrawlers(crawlersData);
      const grouped: Record<string, CrawlerTargetResponse[]> = {};
      for (const t of targets) {
        const k = String(t.kind);
        if (!grouped[k]) grouped[k] = [];
        grouped[k].push(t);
      }
      setTargetsByKind(grouped);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load crawlers");
    } finally {
      if (!silent) setLoading(false);
    }
  }

  async function handleTriggerAll() {
    let count = 0;
    for (const c of crawlers) {
      try { await api.triggerCrawler(c.name); count++; } catch { /* per-kind failure ok */ }
    }
    toast("success", `Triggered ${count}/${crawlers.length} crawlers`);
    setTimeout(() => void load(), 3000);
  }

  const toggleExpand = (kind: string) => {
    setExpanded((s) => {
      const next = new Set(s);
      if (next.has(kind)) next.delete(kind); else next.add(kind);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
            Crawlers
          </h2>
          <p className="text-[13px] mt-1 max-w-[760px]" style={{ color: "var(--color-muted)" }}>
            Argus ships {crawlers.length} crawler kinds out-of-the-box — each connects to a different
            kind of source (Tor forums, Matrix rooms, ransomware leak sites, …). Add the specific
            sites or channels you want to monitor as <em>targets</em> below; the worker polls each
            kind on its own schedule. To support a new <em>kind</em> of source, ship a new Python
            crawler class.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => { void load(); }}
            className="flex items-center gap-2 h-9 px-3 text-[13px] font-semibold"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-surface)",
              color: "var(--color-body)",
            }}
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={handleTriggerAll}
            className="flex items-center gap-2 h-9 px-3 text-[13px] font-semibold"
            style={{
              borderRadius: 4,
              background: "var(--color-accent)",
              color: "#fffefb",
              border: "1px solid var(--color-accent)",
            }}
          >
            <Zap className="w-4 h-4" />
            Run all
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <Loader2 className="w-6 h-6 animate-spin" style={{ color: "var(--color-muted)" }} />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {crawlers.map((crawler) => (
            <CrawlerCard
              key={crawler.name}
              crawler={crawler}
              targets={targetsByKind[crawler.name] || []}
              expanded={expanded.has(crawler.name)}
              onToggle={() => toggleExpand(crawler.name)}
              onTargetsChanged={() => load(true)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

type RunState = "idle" | "running" | "complete" | "error";

function CrawlerCard({
  crawler,
  targets,
  expanded,
  onToggle,
  onTargetsChanged,
}: {
  crawler: Crawler;
  targets: CrawlerTargetResponse[];
  expanded: boolean;
  onToggle: () => void;
  onTargetsChanged: () => void;
}) {
  const { toast } = useToast();
  const status = crawler.last_status ?? (crawler.last_run ? "ok" : "unconfigured");
  const pres = STATUS_PRESENTATION[status] ?? STATUS_PRESENTATION.unconfigured;
  const Icon = pres.icon;
  const Chevron = expanded ? ChevronDown : ChevronRight;
  const schema = KIND_SCHEMAS[crawler.name];

  // Per-card run progress. Run-now opens a short-lived SSE connection
  // to /activity/stream, filters events for this crawler.name, and
  // surfaces them inline so the operator can actually see what
  // happens after they click — instead of just a fire-and-forget toast.
  const [runState, setRunState] = useState<RunState>("idle");
  const [runEvents, setRunEvents] = useState<ActivityEvent[]>([]);
  const [runStartedAt, setRunStartedAt] = useState<number | null>(null);
  const [runFinishedAt, setRunFinishedAt] = useState<number | null>(null);
  const [runSummary, setRunSummary] = useState<{ results: number; alerts: number } | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [, setNowTick] = useState(0);
  const esRef = useRef<EventSource | null>(null);

  // Tick once per second while running so the elapsed timer updates.
  useEffect(() => {
    if (runState !== "running") return;
    const t = setInterval(() => setNowTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [runState]);

  // Auto-collapse the panel ~30s after a run completes/errors so it
  // doesn't linger forever; user can dismiss manually before then.
  useEffect(() => {
    if (runState !== "complete" && runState !== "error") return;
    const t = setTimeout(() => setRunState("idle"), 30000);
    return () => clearTimeout(t);
  }, [runState]);

  // Always close the SSE + stop the polling fallback on unmount.
  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, []);

  const closeStream = () => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  };

  // Polling fallback ref. The SSE stream is the primary signal, but if
  // it drops (network blip, browser tab backgrounded, or events get
  // missed) we still need the panel and the backend to stay in sync.
  // The poller checks the persisted ``last_run`` field on the crawler
  // every few seconds while a run is in flight; if the timestamp
  // advances past our run-start instant, we synthesize the "Complete"
  // state from ``last_rows_ingested`` even without SSE help.
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleRunNow = async () => {
    if (runState === "running") return;
    const startedAt = Date.now();
    setRunState("running");
    setRunEvents([]);
    setRunStartedAt(startedAt);
    setRunFinishedAt(null);
    setRunSummary(null);
    setRunError(null);

    // The SSE endpoint replays the last 50 historical events on
    // connect (see ``src/api/routes/activity.py``), and a previous
    // run's ``crawler_complete`` may be in there. Two-stage filter:
    //   1. ``triggerAcked`` — false until our POST returns. Drops the
    //      bulk of the history replay.
    //   2. ``sawLiveStart`` — false until we see a fresh
    //      ``crawler_start`` after the ack. Drops any history that
    //      slipped through the first gate (the SSE flush can finish
    //      after the POST returns since they race).
    // A ``crawler_complete`` without a preceding live start is, by
    // definition, from a previous run.
    let triggerAcked = false;
    let sawLiveStart = false;

    closeStream();
    const es = new EventSource(`${SSE_BASE}/activity/stream`);
    esRef.current = es;
    es.onmessage = (msg) => {
      try {
        const evt: ActivityEvent = JSON.parse(msg.data);
        if (evt.agent !== crawler.name) return;
        if (!triggerAcked) return;  // still draining history; ignore.

        if (evt.event_type === "crawler_start") {
          sawLiveStart = true;
          // Realign the elapsed clock to the server-perceived start
          // moment so the panel's timer reflects actual run time
          // instead of click-to-start latency.
          setRunStartedAt(Date.now());
        }
        // Reject any complete/error that arrives before we've seen
        // a live start — it's a leftover from the prior run.
        if (
          !sawLiveStart &&
          (evt.event_type === "crawler_complete" || evt.event_type === "crawler_error")
        ) {
          return;
        }

        setRunEvents((prev) => {
          if (prev.some((e) => e.id === evt.id)) return prev;
          const next = [...prev, evt];
          return next.length > 50 ? next.slice(-50) : next;
        });

        if (evt.event_type === "crawler_complete") {
          const d = evt.details ?? {};
          setRunSummary({
            results: Number(d.results) || 0,
            alerts: Number(d.alerts) || 0,
          });
          setRunFinishedAt(Date.now());
          setRunState("complete");
          closeStream();
          stopPolling();
          onTargetsChanged();
        } else if (evt.event_type === "crawler_error") {
          setRunError(String(evt.details?.error ?? evt.message));
          setRunFinishedAt(Date.now());
          setRunState("error");
          closeStream();
          stopPolling();
          onTargetsChanged();
        }
      } catch { /* ignore malformed event */ }
    };
    es.onerror = () => {
      // Connection blip — the polling fallback below will keep things
      // honest if SSE dies mid-run.
    };

    try {
      await api.triggerCrawler(crawler.name);
      triggerAcked = true;
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to trigger";
      toast("error", msg);
      setRunError(msg);
      setRunFinishedAt(Date.now());
      setRunState("error");
      closeStream();
      return;
    }

    // Polling fallback for sync — see the comment above the ref.
    // ``last_run`` is the persisted source-of-truth; if it advances
    // past ``startedAt`` we can declare the run complete even if SSE
    // never delivered the event. Browser clock skew is fine here
    // because we compare ``last_run`` against itself: the new value
    // must be different from the value at click-time.
    stopPolling();
    const lastRunAtClick =
      crawler.last_run ? new Date(crawler.last_run).getTime() : 0;
    pollRef.current = setInterval(async () => {
      try {
        const list = await api.getCrawlers();
        const me = list.find((c) => c.name === crawler.name);
        if (!me || !me.last_run) return;
        const lastRunMs = new Date(me.last_run).getTime();
        if (lastRunMs <= lastRunAtClick) return;  // still the old timestamp.
        // Backend persisted a fresh run. Mark complete using whatever
        // we have — SSE events if they showed up, the persisted
        // last_rows_ingested + last_alerts_created counts otherwise.
        setRunSummary((prev) =>
          prev ?? {
            results: me.last_rows_ingested ?? 0,
            alerts: me.last_alerts_created ?? 0,
          }
        );
        setRunFinishedAt(Date.now());
        setRunState((prev) => (prev === "running" ? "complete" : prev));
        closeStream();
        stopPolling();
        onTargetsChanged();
      } catch { /* keep trying on next tick */ }
    }, 3000);
  };

  const elapsedMs =
    runStartedAt === null
      ? 0
      : (runFinishedAt ?? Date.now()) - runStartedAt;
  const elapsedLabel = formatElapsed(elapsedMs);

  return (
    <div
      className="overflow-hidden"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <div className="p-5">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <Bot className="w-6 h-6 shrink-0" style={{ color: "var(--color-muted)" }} />
            <div className="min-w-0">
              <h3 className="text-[15px] font-semibold truncate" style={{ color: "var(--color-ink)" }}>
                {schema?.label ?? crawler.name}
              </h3>
              <p className="text-[11.5px] font-mono" style={{ color: "var(--color-muted)" }}>
                kind: {crawler.name}
              </p>
              <p className="text-[12px] mt-0.5" style={{ color: "var(--color-muted)" }}>
                Every {Math.round(crawler.interval_seconds / 60)}m ·{" "}
                {targets.length} target{targets.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.6px] shrink-0"
            style={{ background: pres.bg, color: pres.color, borderRadius: 3 }}
            title={crawler.last_detail ?? undefined}
          >
            <Icon className="w-3 h-3" />
            {pres.label}
          </span>
        </div>

        {schema && (
          <p className="text-[12px] mb-3" style={{ color: "var(--color-body)" }}>
            {schema.description}
          </p>
        )}

        <div className="flex items-center gap-2 text-[12px]" style={{ color: "var(--color-body)" }}>
          {crawler.last_run ? (
            <>
              <Clock className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              <span>
                Last run {timeAgo(crawler.last_run)}
                {(crawler.last_rows_ingested > 0 || crawler.last_alerts_created > 0) && (
                  <>
                    {" · "}
                    {crawler.last_rows_ingested.toLocaleString()} item
                    {crawler.last_rows_ingested === 1 ? "" : "s"}
                    {" · "}
                    {crawler.last_alerts_created.toLocaleString()} alert
                    {crawler.last_alerts_created === 1 ? "" : "s"}
                  </>
                )}
              </span>
            </>
          ) : (
            <>
              <Clock className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
              <span style={{ color: "var(--color-muted)" }}>Never run</span>
            </>
          )}
        </div>

        {crawler.last_detail && status !== "ok" && (
          <p className="text-[11.5px] mt-2 leading-relaxed" style={{ color: "var(--color-muted)" }}>
            {crawler.last_detail}
          </p>
        )}

        <div className="flex items-center gap-2 mt-3">
          <button
            onClick={onToggle}
            className="flex items-center gap-1 text-[12px] font-semibold transition-opacity"
            style={{ color: "var(--color-accent)", background: "transparent", border: "none", cursor: "pointer" }}
          >
            <Chevron className="w-3.5 h-3.5" />
            {expanded ? "Hide targets" : `Manage targets (${targets.length})`}
          </button>
          <Link
            href={`/activity?q=${encodeURIComponent(crawler.name)}`}
            title={crawler.last_run ? `View activity events for ${crawler.name}` : "Crawler hasn't run yet"}
            className="flex items-center gap-1.5 px-3 h-7 text-[12px] font-semibold ml-auto"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <Activity className="w-3.5 h-3.5" />
            View activity
          </Link>
          <button
            onClick={handleRunNow}
            disabled={runState === "running" || targets.length === 0}
            title={targets.length === 0 ? "Add at least one target before running" : "Run this crawler now"}
            className="flex items-center gap-1.5 px-3 h-7 text-[12px] font-semibold disabled:opacity-50"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-surface-muted)",
              color: "var(--color-body)",
              cursor: runState === "running" ? "wait" : "pointer",
            }}
          >
            {runState === "running" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Run now
          </button>
        </div>
      </div>

      {runState !== "idle" && (
        <RunProgressPanel
          state={runState}
          events={runEvents}
          elapsedLabel={elapsedLabel}
          summary={runSummary}
          error={runError}
          crawlerName={crawler.name}
          onDismiss={() => {
            closeStream();
            stopPolling();
            setRunState("idle");
          }}
        />
      )}

      {expanded && (
        <div
          className="px-5 py-4 space-y-3"
          style={{ background: "var(--color-surface)", borderTop: "1px solid var(--color-border)" }}
        >
          <SetupGuide kind={crawler.name} targets={targets} />
          {targets.length === 0 ? (
            <p className="text-[12.5px]" style={{ color: "var(--color-muted)" }}>
              No targets yet. Add one below to bring this crawler online.
            </p>
          ) : (
            <ul className="space-y-1.5">
              {targets.map((t) => (
                <TargetRow
                  key={t.id}
                  target={t}
                  schema={schema}
                  onChanged={onTargetsChanged}
                />
              ))}
            </ul>
          )}
          {schema && (
            <TargetForm
              kind={crawler.name as CrawlerKind}
              schema={schema}
              onSaved={onTargetsChanged}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run progress panel
//
// Inline status surface for a crawler that's currently being run via
// "Run now". Shows the live tail of activity-stream events for this
// crawler kind, an elapsed-time counter, and (on completion) a
// summary of items collected and alerts created.
// ---------------------------------------------------------------------------

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s - m * 60);
  return `${m}m ${r}s`;
}

function RunProgressPanel({
  state,
  events,
  elapsedLabel,
  summary,
  error,
  crawlerName,
  onDismiss,
}: {
  state: RunState;
  events: ActivityEvent[];
  elapsedLabel: string;
  summary: { results: number; alerts: number } | null;
  error: string | null;
  crawlerName: string;
  onDismiss: () => void;
}) {
  // Auto-scroll the log tail to the bottom as new events stream in.
  const logRef = useRef<HTMLUListElement>(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [events.length]);

  const headerLabel =
    state === "running" ? "Running…"
    : state === "complete" ? "Complete"
    : "Failed";

  const headerColor =
    state === "running" ? "var(--color-accent)"
    : state === "complete" ? "var(--color-success-dark)"
    : "var(--color-error-dark)";

  const headerIcon =
    state === "running" ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
    : state === "complete" ? <CheckCircle className="w-3.5 h-3.5" />
    : <AlertTriangle className="w-3.5 h-3.5" />;

  // CRAWLER_RESULT events are 1-per-item — handy proxy for "items
  // seen so far" while the run is still in flight (the authoritative
  // total only arrives in the CRAWLER_COMPLETE summary).
  const liveItemCount = events.filter((e) => e.event_type === "crawler_result").length;

  return (
    <div
      className="px-5 py-3"
      style={{
        borderTop: "1px solid var(--color-border)",
        background: "var(--color-surface)",
      }}
    >
      <div className="flex items-center gap-2 mb-2">
        <span style={{ color: headerColor }}>{headerIcon}</span>
        <span className="text-[12px] font-semibold" style={{ color: "var(--color-ink)" }}>
          {headerLabel}
        </span>
        <span className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
          {elapsedLabel}
        </span>
        {state === "running" && (
          <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
            · {liveItemCount} item{liveItemCount === 1 ? "" : "s"} so far
          </span>
        )}
        <button
          onClick={onDismiss}
          aria-label="Dismiss progress"
          className="ml-auto p-1"
          style={{
            background: "transparent",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
            color: "var(--color-muted)",
            cursor: "pointer",
          }}
        >
          <X className="w-3 h-3" />
        </button>
      </div>

      {events.length > 0 && (
        <ul
          ref={logRef}
          className="space-y-0.5 max-h-[120px] overflow-y-auto px-2.5 py-2 mb-2"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
          }}
        >
          {events.map((e) => (
            <li
              key={e.id}
              className="text-[11px] font-mono leading-snug truncate"
              style={{
                color: e.severity === "error"
                  ? "var(--color-error-dark)"
                  : e.severity === "warning"
                  ? "#B76E00"
                  : "var(--color-body)",
              }}
              title={e.message}
            >
              <span style={{ color: "var(--color-muted)" }}>
                {new Date(e.timestamp).toLocaleTimeString()}
              </span>{" "}
              · {e.message}
            </li>
          ))}
        </ul>
      )}

      {state === "running" && events.length === 0 && (
        <p className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>
          Waiting for the scheduler to pick up the run… the first events
          should arrive within a few seconds.
        </p>
      )}

      {state === "complete" && summary && (
        <div className="flex items-center gap-3 text-[12px] flex-wrap" style={{ color: "var(--color-body)" }}>
          <span>
            <strong style={{ color: "var(--color-ink)" }}>{summary.results}</strong> item
            {summary.results === 1 ? "" : "s"} collected
          </span>
          <span>·</span>
          <span>
            <strong style={{ color: "var(--color-ink)" }}>{summary.alerts}</strong> alert
            {summary.alerts === 1 ? "" : "s"} created
          </span>
          <Link
            href={`/activity?q=${encodeURIComponent(crawlerName)}`}
            className="inline-flex items-center gap-1 ml-auto text-[11.5px] font-semibold"
            style={{ color: "var(--color-accent)" }}
          >
            <Activity className="w-3 h-3" />
            View full activity log
          </Link>
        </div>
      )}

      {state === "error" && error && (
        <p className="text-[11.5px]" style={{ color: "var(--color-error-dark)" }}>
          {error}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Setup guide — inline, kind-aware help that auto-shows when the
// onboarding orchestrator (src/onboarding/intel_setup.py) seeded
// placeholder targets that the operator still needs to finish wiring.
//
// Detection signal: any target whose ``config._setup_hint`` is set OR
// whose URL contains the well-known placeholder ``REPLACE_FEED_ID``.
// Once the operator pastes a real URL and removes the hint, the
// banner disappears automatically.
// ---------------------------------------------------------------------------

function SetupGuide({
  kind,
  targets,
}: {
  kind: string;
  targets: CrawlerTargetResponse[];
}) {
  const [collapsed, setCollapsed] = useState(false);

  const placeholders = targets.filter((t) => {
    const cfg = (t.config ?? {}) as Record<string, unknown>;
    if (cfg._setup_hint) return true;
    const url = typeof cfg.url === "string" ? cfg.url : "";
    if (url.includes("REPLACE_FEED_ID")) return true;
    if (Array.isArray(cfg.onion_urls) && cfg.onion_urls.length === 0) return true;
    return false;
  });
  if (placeholders.length === 0) return null;

  // Per-kind content. We hardcode the two kinds that the orchestrator
  // currently seeds — adding a new placeholder kind means adding a
  // ``case`` here too. That's intentional: the help text is editorial
  // (specific to the upstream provider's UI) and shouldn't drift
  // around in JSON config.
  let content: React.ReactNode = null;
  let title = "Setup required";

  if (kind === "custom_http") {
    title = "Google Alerts — finish setup";
    content = (
      <>
        <p className="mb-2">
          {placeholders.length} placeholder target{placeholders.length === 1 ? "" : "s"}{" "}
          waiting for an RSS URL. Set up one Google Alert per brand keyword,
          then paste each feed URL below.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-[0.6px] mb-1" style={{ color: "var(--color-muted)" }}>
              On google.com/alerts
            </div>
            <ol className="text-[11.5px] space-y-1 list-decimal pl-4" style={{ color: "var(--color-body)" }}>
              <li>Sign in at <a href="https://www.google.com/alerts" target="_blank" rel="noopener noreferrer" style={{ color: "var(--color-accent)", textDecoration: "underline" }}>google.com/alerts</a></li>
              <li>Click <strong>Create alert</strong></li>
              <li>In <em>Search query</em>, type the brand keyword (e.g. <code>&quot;Emirates NBD&quot;</code>)</li>
              <li>Click <strong>Show options</strong> → set <strong>Deliver to: RSS feed</strong></li>
              <li>Click <strong>Create alert</strong></li>
              <li>In the alerts list, right-click the orange RSS icon next to your alert → <strong>Copy link</strong></li>
              <li>Repeat per brand keyword</li>
            </ol>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase tracking-[0.6px] mb-1" style={{ color: "var(--color-muted)" }}>
              Then in Argus (below)
            </div>
            <ol className="text-[11.5px] space-y-1 list-decimal pl-4" style={{ color: "var(--color-body)" }}>
              <li>Click the pencil/edit icon next to each <code>Google Alerts —</code> placeholder</li>
              <li>Paste the matching RSS feed URL into the <strong>URL</strong> field</li>
              <li>Save changes — the target stays paused until you toggle it active</li>
              <li>Click the <strong>play</strong> icon on the target to enable it</li>
              <li>Click <strong>Run now</strong> on the card to verify ingestion</li>
            </ol>
          </div>
        </div>
      </>
    );
  } else if (kind === "stealer_marketplace") {
    title = "Stealer marketplaces — finish setup";
    content = (
      <>
        <p className="mb-2">
          {placeholders.length} disabled marketplace placeholder
          {placeholders.length === 1 ? "" : "s"} seeded. We don&apos;t ship
          live onion URLs — they rotate weekly and operator authority
          to scrape varies per market. Enable only those you have
          authority for.
        </p>
        <ol className="text-[11.5px] space-y-1 list-decimal pl-4" style={{ color: "var(--color-body)" }}>
          <li>Verify legal authority to scrape the marketplace (jurisdictional + contractual)</li>
          <li>Find the current onion URL via your TI feeds or trusted research outlets</li>
          <li>Click the pencil/edit icon next to a placeholder, paste the onion URL into <code>onion_urls</code> (one per line)</li>
          <li>Save, then toggle the target active</li>
          <li>Hits are matched against your VIP email permutations — add VIPs first via <strong>/admin → VIPs</strong> for best signal</li>
        </ol>
      </>
    );
  } else {
    return null;  // unknown kind — don't render an empty banner
  }

  return (
    <div
      className="px-3 py-2.5"
      style={{
        background: "rgba(255,79,0,0.05)",
        border: "1px solid rgba(255,79,0,0.25)",
        borderRadius: 5,
        color: "var(--color-body)",
      }}
    >
      <div className="flex items-center gap-2">
        <Info className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-accent)" }} />
        <span className="text-[12.5px] font-semibold" style={{ color: "var(--color-ink)" }}>
          {title}
        </span>
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          className="ml-auto text-[11px] font-semibold"
          style={{
            background: "transparent",
            border: "none",
            color: "var(--color-accent)",
            cursor: "pointer",
          }}
        >
          {collapsed ? "Show steps" : "Hide steps"}
        </button>
      </div>
      {!collapsed && (
        <div className="mt-2 text-[12px]">
          {content}
        </div>
      )}
    </div>
  );
}


// ---------------------------------------------------------------------------
// Target row + edit
// ---------------------------------------------------------------------------

function TargetRow({
  target,
  schema,
  onChanged,
}: {
  target: CrawlerTargetResponse;
  schema?: KindSchema;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);

  const handleDelete = async () => {
    if (!window.confirm(`Remove target "${target.identifier}"?`)) return;
    setBusy(true);
    try {
      await api.admin.deleteCrawlerTarget(target.id);
      toast("success", `Removed ${target.identifier}`);
      onChanged();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to remove target");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleActive = async () => {
    setBusy(true);
    try {
      await api.admin.updateCrawlerTarget(target.id, { is_active: !target.is_active });
      toast("success", `${target.identifier} ${target.is_active ? "paused" : "resumed"}`);
      onChanged();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to update target");
    } finally {
      setBusy(false);
    }
  };

  if (editing && schema) {
    return (
      <li
        className="px-2.5 py-2"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-accent)",
          borderRadius: 4,
        }}
      >
        <TargetForm
          kind={target.kind as CrawlerKind}
          schema={schema}
          existing={target}
          onSaved={() => { setEditing(false); onChanged(); }}
          onCancel={() => setEditing(false)}
        />
      </li>
    );
  }

  return (
    <li
      className="flex items-center gap-2 px-2.5 py-2"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: 4,
        opacity: target.is_active ? 1 : 0.6,
      }}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <div className="text-[12.5px] font-mono" style={{ color: "var(--color-ink)" }}>
            {target.identifier}
          </div>
          {!target.is_active && (
            <span
              className="text-[9.5px] font-bold uppercase tracking-[0.6px] px-1.5 py-0.5"
              style={{
                background: "var(--color-surface-muted)",
                color: "var(--color-muted)",
                borderRadius: 3,
              }}
            >
              Paused
            </span>
          )}
        </div>
        {target.display_name && target.display_name !== target.identifier && (
          <div className="text-[11px]" style={{ color: "var(--color-muted)" }}>
            {target.display_name}
          </div>
        )}
        {target.last_run_at && (
          <div className="text-[10.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Last attempt {timeAgo(target.last_run_at)}
            {target.last_run_status && ` · ${target.last_run_status}`}
            {target.consecutive_failures > 0 && (
              <span style={{ color: "var(--color-error-dark)" }}>
                {" "}· {target.consecutive_failures} consecutive failures
              </span>
            )}
          </div>
        )}
      </div>
      <button
        onClick={handleToggleActive}
        disabled={busy}
        aria-label={target.is_active ? `Pause ${target.identifier}` : `Resume ${target.identifier}`}
        title={target.is_active ? "Pause this target" : "Resume polling"}
        className="flex items-center justify-center w-7 h-7 disabled:opacity-50"
        style={{
          background: "transparent",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
          cursor: "pointer",
        }}
      >
        {target.is_active ? <CircleSlash className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
      </button>
      <button
        onClick={() => setEditing(true)}
        disabled={busy}
        aria-label={`Edit ${target.identifier}`}
        className="flex items-center justify-center w-7 h-7 disabled:opacity-50"
        style={{
          background: "transparent",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
          cursor: "pointer",
        }}
      >
        <Pencil className="w-3.5 h-3.5" />
      </button>
      <button
        onClick={handleDelete}
        disabled={busy}
        aria-label={`Remove ${target.identifier}`}
        className="flex items-center justify-center w-7 h-7 disabled:opacity-50"
        style={{
          background: "transparent",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
          cursor: "pointer",
        }}
      >
        {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
      </button>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Friendly form (covers add + edit)
// ---------------------------------------------------------------------------

type FormValues = Record<string, string | number | boolean | string[]>;

function TargetForm({
  kind,
  schema,
  existing,
  onSaved,
  onCancel,
}: {
  kind: CrawlerKind;
  schema: KindSchema;
  existing?: CrawlerTargetResponse;
  onSaved: () => void;
  onCancel?: () => void;
}) {
  const { toast } = useToast();
  const isEdit = !!existing;

  const buildInitial = (): FormValues => {
    const v: FormValues = {};
    for (const f of schema.fields) {
      if (existing) {
        v[f.name] = readMapped(existing, f);
      } else if (f.defaultValue !== undefined) {
        v[f.name] = f.defaultValue;
      } else if (f.type === "checkbox") {
        v[f.name] = false;
      } else if (f.type === "number") {
        v[f.name] = "";
      } else if (f.type === "textarea-lines") {
        v[f.name] = [];
      } else {
        v[f.name] = "";
      }
    }
    return v;
  };

  const [values, setValues] = useState<FormValues>(buildInitial);
  const [advanced, setAdvanced] = useState(false);
  const [advancedJson, setAdvancedJson] = useState(() =>
    existing ? JSON.stringify(existing.config ?? {}, null, 2) : "{}"
  );
  const [active, setActive] = useState(existing?.is_active ?? true);
  const [saving, setSaving] = useState(false);
  const [showFormatHelp, setShowFormatHelp] = useState(false);

  // The same form covers add + edit. ``identifier`` is the row's
  // unique key so we make it read-only when editing — the operator
  // deletes-and-recreates if they need a different one.
  const isReadonlyField = (f: FieldDef) => isEdit && f.mapTo === "identifier";

  const submit = async () => {
    // Validate required.
    for (const f of schema.fields) {
      if (!f.required) continue;
      const raw = values[f.name];
      const empty =
        raw === undefined ||
        raw === null ||
        (typeof raw === "string" && raw.trim() === "") ||
        (Array.isArray(raw) && raw.length === 0);
      if (empty) {
        toast("error", `${f.label} is required`);
        return;
      }
    }

    let identifier = String(values["identifier"] ?? existing?.identifier ?? "").trim();
    let displayName: string | undefined;
    let config: Record<string, unknown> = advanced
      ? safeParseJson(advancedJson)
      : { ...(existing?.config ?? {}) };

    if (!advanced) {
      // Build config from per-field mapTo paths.
      for (const f of schema.fields) {
        const raw = values[f.name];
        if (f.mapTo === "identifier") continue;
        if (f.mapTo === "display_name") {
          const v = String(raw ?? "").trim();
          displayName = v || undefined;
          continue;
        }
        const m = f.mapTo.match(/^config\.([\w]+)(\[\])?$/);
        if (!m) continue;
        const key = m[1];
        const isArray = Boolean(m[2]);
        if (isArray) {
          if (Array.isArray(raw)) {
            config[key] = raw.map((s) => String(s).trim()).filter(Boolean);
          } else if (typeof raw === "string") {
            config[key] = raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          }
        } else if (f.type === "number") {
          const n = typeof raw === "number" ? raw : Number(raw);
          if (!Number.isNaN(n) && raw !== "") config[key] = n;
        } else if (f.type === "checkbox") {
          config[key] = Boolean(raw);
        } else {
          const v = typeof raw === "string" ? raw.trim() : raw;
          if (v !== "" && v !== undefined) config[key] = v;
        }
      }
    } else {
      // Advanced JSON path: identifier still comes from the dedicated
      // input, display_name still comes from values for new rows.
      if (!isEdit) {
        const dn = String(values["display_name"] ?? "").trim();
        if (dn) displayName = dn;
      }
    }

    setSaving(true);
    try {
      if (isEdit && existing) {
        await api.admin.updateCrawlerTarget(existing.id, {
          display_name: displayName ?? null,
          config,
          is_active: active,
        });
        toast("success", `Updated ${identifier}`);
      } else {
        await api.admin.createCrawlerTarget({
          kind,
          identifier,
          display_name: displayName,
          config,
          is_active: active,
        });
        toast("success", `Added ${identifier}`);
      }
      onSaved();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to save target");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className={isEdit ? "" : "p-3 space-y-3"}
      style={isEdit ? {} : {
        background: "var(--color-canvas)",
        border: "1px dashed var(--color-border)",
        borderRadius: 4,
      }}
    >
      {!isEdit && (
        <div className="flex items-center justify-between">
          <h4
            className="text-[10.5px] font-semibold uppercase tracking-[0.7px]"
            style={{ color: "var(--color-muted)" }}
          >
            Add target — {schema.label}
          </h4>
          <label
            className="inline-flex items-center gap-1 text-[10.5px] cursor-pointer"
            style={{ color: "var(--color-muted)" }}
            title="Edit raw JSON config (power users)"
          >
            <input
              type="checkbox"
              checked={advanced}
              onChange={(e) => setAdvanced(e.target.checked)}
            />
            Advanced (JSON)
          </label>
        </div>
      )}

      {!advanced && (
        <div className="space-y-2.5">
          {schema.fields.map((f) => (
            <FieldInput
              key={f.name}
              field={f}
              value={values[f.name]}
              readOnly={isReadonlyField(f)}
              onChange={(v) =>
                setValues((cur) => ({ ...cur, [f.name]: v }))
              }
            />
          ))}
          <label
            className="inline-flex items-center gap-1.5 text-[12px] cursor-pointer"
            style={{ color: "var(--color-body)" }}
          >
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
            />
            Active (poll on schedule)
          </label>
        </div>
      )}

      {advanced && (
        <div className="space-y-2">
          <p className="text-[11px]" style={{ color: "var(--color-muted)" }}>
            Raw JSON config — overrides any field values above. The kind, identifier and
            display name still use the dedicated inputs.
          </p>
          <textarea
            value={advancedJson}
            onChange={(e) => setAdvancedJson(e.target.value)}
            rows={6}
            className="w-full px-2 py-1.5 text-[12px] font-mono"
            style={{
              background: "var(--color-surface-muted)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-ink)",
            }}
          />
        </div>
      )}

      <div className="flex items-center justify-between gap-2">
        {!isEdit && (
          <button
            type="button"
            onClick={() => setShowFormatHelp(true)}
            className="inline-flex items-center gap-1 text-[11px]"
            style={{
              color: "var(--color-muted)",
              background: "transparent",
              border: "none",
              padding: 0,
              cursor: "pointer",
            }}
          >
            <Info className="w-3 h-3" /> Format reference
          </button>
        )}
        <div className="flex items-center gap-2 ml-auto">
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex items-center gap-1 h-8 px-3 text-[12px]"
              style={{
                background: "transparent",
                border: "1px solid var(--color-border)",
                borderRadius: 4,
                color: "var(--color-body)",
              }}
            >
              <X className="w-3.5 h-3.5" /> Cancel
            </button>
          )}
          <button
            type="button"
            onClick={submit}
            disabled={saving}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-semibold disabled:opacity-50"
            style={{
              background: "var(--color-accent)",
              color: "#fffefb",
              borderRadius: 4,
              border: "1px solid var(--color-accent)",
            }}
          >
            {saving
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
              : isEdit ? <Check className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />
            }
            {isEdit ? "Save changes" : "Add target"}
          </button>
        </div>
      </div>

      {showFormatHelp && (
        <FormatHelpModal
          kind={kind}
          schema={schema}
          onClose={() => setShowFormatHelp(false)}
        />
      )}
    </div>
  );
}

function FormatHelpModal({
  kind,
  schema,
  onClose,
}: {
  kind: CrawlerKind;
  schema: KindSchema;
  onClose: () => void;
}) {
  // ESC closes; small QoL.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Build a sample JSON config from each field's mapTo path so the
  // operator can copy-paste it into the Advanced (JSON) editor.
  const sampleConfig: Record<string, unknown> = {};
  for (const f of schema.fields) {
    const m = f.mapTo.match(/^config\.([\w]+)(\[\])?$/);
    if (!m) continue;
    const key = m[1];
    const isArray = Boolean(m[2]);
    if (isArray) {
      sampleConfig[key] = [f.placeholder?.split(/\r?\n/)[0] ?? "..."];
    } else if (f.defaultValue !== undefined) {
      sampleConfig[key] = f.defaultValue;
    } else {
      sampleConfig[key] = f.placeholder ?? "...";
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto py-8 px-4"
      style={{ background: "rgba(32,21,21,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[560px] p-6"
        style={{
          background: "var(--color-canvas)",
          borderRadius: 8,
          boxShadow: "var(--shadow-z24)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 mb-3">
          <div>
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--color-ink)" }}>
              {schema.label} — format reference
            </h3>
            <p className="text-[11.5px] font-mono mt-0.5" style={{ color: "var(--color-muted)" }}>
              kind: {kind}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1"
            style={{
              background: "transparent",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-muted)",
              cursor: "pointer",
            }}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-[12.5px] mb-4" style={{ color: "var(--color-body)" }}>
          {schema.description}
        </p>

        <div className="mb-4">
          <div
            className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Fields
          </div>
          <ul className="space-y-2">
            {schema.fields.map((f) => (
              <li
                key={f.name}
                className="px-3 py-2"
                style={{
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 4,
                }}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12.5px] font-semibold" style={{ color: "var(--color-ink)" }}>
                    {f.label}
                  </span>
                  <span
                    className="text-[10px] font-mono px-1.5 py-0.5"
                    style={{
                      background: "var(--color-surface-muted)",
                      color: "var(--color-muted)",
                      borderRadius: 3,
                    }}
                  >
                    {f.type}
                  </span>
                  {f.required && (
                    <span
                      className="text-[10px] font-bold uppercase tracking-[0.6px] px-1.5 py-0.5"
                      style={{
                        background: "rgba(255,79,0,0.10)",
                        color: "var(--color-accent)",
                        borderRadius: 3,
                      }}
                    >
                      Required
                    </span>
                  )}
                  <span className="text-[10.5px] font-mono ml-auto" style={{ color: "var(--color-muted)" }}>
                    {f.mapTo}
                  </span>
                </div>
                {f.hint && (
                  <p className="text-[11.5px] mt-1" style={{ color: "var(--color-muted)" }}>
                    {f.hint}
                  </p>
                )}
                {f.placeholder && (
                  <p className="text-[11px] font-mono mt-1" style={{ color: "var(--color-body)" }}>
                    e.g. {f.placeholder.replace(/\n/g, " · ")}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div
            className="text-[10.5px] font-bold uppercase tracking-[0.6px] mb-2"
            style={{ color: "var(--color-muted)" }}
          >
            Advanced (JSON) shape
          </div>
          <pre
            className="text-[11.5px] font-mono px-3 py-2 overflow-x-auto whitespace-pre"
            style={{
              background: "var(--color-surface-muted)",
              border: "1px solid var(--color-border)",
              borderRadius: 4,
              color: "var(--color-ink)",
            }}
          >
{JSON.stringify(sampleConfig, null, 2)}
          </pre>
          <p className="text-[10.5px] mt-1.5" style={{ color: "var(--color-muted)" }}>
            Identifier &amp; display name use their dedicated inputs; everything else lives under <code>config</code>.
          </p>
        </div>
      </div>
    </div>
  );
}

function FieldInput({
  field,
  value,
  readOnly,
  onChange,
}: {
  field: FieldDef;
  value: string | number | boolean | string[] | undefined;
  readOnly?: boolean;
  onChange: (v: string | number | boolean | string[]) => void;
}) {
  const baseStyle: React.CSSProperties = {
    background: readOnly ? "var(--color-surface-muted)" : "var(--color-canvas)",
    border: "1px solid var(--color-border)",
    borderRadius: 4,
    color: "var(--color-ink)",
  };

  return (
    <div>
      <label
        className="block text-[11px] font-semibold mb-1"
        style={{ color: "var(--color-body)" }}
      >
        {field.label}
        {field.required && (
          <span style={{ color: "var(--color-accent)" }}> *</span>
        )}
      </label>
      {field.type === "textarea-lines" ? (
        <textarea
          value={Array.isArray(value) ? value.join("\n") : String(value ?? "")}
          onChange={(e) =>
            onChange(e.target.value.split(/\r?\n/).map((s) => s).filter((_, _i, arr) => true))
          }
          onBlur={(e) =>
            onChange(e.target.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))
          }
          placeholder={field.placeholder}
          readOnly={readOnly}
          rows={Math.max(2, Math.min(5, Array.isArray(value) ? value.length + 1 : 2))}
          className="w-full px-2 py-1.5 text-[12.5px] font-mono"
          style={baseStyle}
        />
      ) : field.type === "checkbox" ? (
        <label className="inline-flex items-center gap-1.5 text-[12px]" style={{ color: "var(--color-body)" }}>
          <input
            type="checkbox"
            checked={Boolean(value)}
            disabled={readOnly}
            onChange={(e) => onChange(e.target.checked)}
          />
          {field.placeholder ?? "Enabled"}
        </label>
      ) : (
        <input
          type={field.type === "number" ? "number" : (field.type === "url" ? "url" : "text")}
          value={typeof value === "number" || typeof value === "string" ? String(value) : ""}
          onChange={(e) =>
            onChange(field.type === "number" ? (e.target.value === "" ? "" : Number(e.target.value)) : e.target.value)
          }
          placeholder={field.placeholder}
          readOnly={readOnly}
          className="w-full h-8 px-2 text-[12.5px]"
          style={baseStyle}
        />
      )}
      {field.hint && (
        <p className="text-[10.5px] mt-1" style={{ color: "var(--color-muted)" }}>
          <Info className="inline w-2.5 h-2.5 mr-0.5" style={{ color: "var(--color-muted)" }} />
          {field.hint}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function readMapped(target: CrawlerTargetResponse, f: FieldDef): string | number | boolean | string[] {
  if (f.mapTo === "identifier") return target.identifier;
  if (f.mapTo === "display_name") return target.display_name ?? "";
  const m = f.mapTo.match(/^config\.([\w]+)(\[\])?$/);
  if (!m) return f.defaultValue ?? "";
  const key = m[1];
  const isArray = Boolean(m[2]);
  const cfg = target.config ?? {};
  const raw = (cfg as Record<string, unknown>)[key];
  if (isArray) {
    return Array.isArray(raw) ? raw.map((s) => String(s)) : [];
  }
  if (raw === undefined || raw === null) {
    return f.defaultValue ?? "";
  }
  if (f.type === "number") return Number(raw);
  if (f.type === "checkbox") return Boolean(raw);
  return String(raw);
}

function safeParseJson(text: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(text || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    /* fall through */
  }
  return {};
}
