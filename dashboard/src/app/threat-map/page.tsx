"use client";

import {
  useRef,
  useState,
  useCallback,
  useEffect,
  useMemo,
} from "react";
import MapGL, {
  Source,
  Layer,
  Popup,
  NavigationControl,
  type MapRef,
  type ViewStateChangeEvent,
  type MapLayerMouseEvent,
} from "react-map-gl/maplibre";
import "maplibre-gl/dist/maplibre-gl.css";
import {
  Search,
  Layers,
  Clock,
  Radio,
  Shield,
  Bug,
  Crosshair,
  Globe,
  Skull,
  Server,
  Loader2,
  AlertTriangle,
  Eye,
  EyeOff,
  Lock,
  Network,
  MessageCircle,
  Target,
  ShieldAlert,
  Ban,
  Fish,
  Activity,
  Zap,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import {
  api,
  type ThreatMapLayer,
  type ThreatMapEntry,
  type ThreatMapEntryDetail,
  type GlobalThreatStats,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAP_STYLE =
  "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

const INITIAL_VIEW = {
  longitude: 15,
  latitude: 25,
  zoom: 2.2,
  pitch: 0,
  bearing: 0,
};

const TIME_RANGES = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "48h", hours: 48 },
  { label: "7d", hours: 168 },
] as const;

const SEVERITY_RADIUS: Record<string, number> = {
  critical: 10,
  high: 8,
  medium: 6,
  low: 5,
  info: 4,
};

const INFOCON_COLORS: Record<string, string> = {
  green: "#22C55E",
  yellow: "#FFAB00",
  orange: "#FF8B00",
  red: "#FF5630",
  blue: "#00BBD9",
};

const LAYER_ICONS: Record<
  string,
  React.ComponentType<{ className?: string }>
> = {
  ransomware: Skull,
  botnet_c2: Radio,
  phishing: Fish,
  malware: Bug,
  honeypot: Target,
  tor_exit: EyeOff,
  ip_reputation: Ban,
  exploited_cve: ShieldAlert,
  ssl_abuse: Lock,
  bgp_hijack: Network,
  underground: MessageCircle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function severityColor(s: string): string {
  switch (s) {
    case "critical":
      return "#FF5630";
    case "high":
      return "#FF8B00";
    case "medium":
      return "#FFAB00";
    case "low":
      return "#00BBD9";
    default:
      return "#637381";
  }
}

/** Build a location string from city + country code */
function formatLocation(city?: string | null, countryCode?: string | null): string | null {
  if (!city && !countryCode) return null;
  const parts: string[] = [];
  if (city) parts.push(city);
  if (countryCode) {
    try {
      const name = new Intl.DisplayNames(["en"], { type: "region" }).of(countryCode);
      parts.push(name || countryCode);
    } catch {
      parts.push(countryCode);
    }
  }
  return parts.join(", ");
}

/** Extract enriched metadata fields from feed_metadata for display */
function extractMetaHighlights(
  entry: ThreatMapEntryDetail
): { label: string; value: string }[] {
  const meta = entry.feed_metadata;
  const out: { label: string; value: string }[] = [];
  if (!meta) return out;

  // Malware family / name
  const malware = meta.malware_family || meta.malware || meta.threat;
  if (malware && typeof malware === "string" && malware !== "none") {
    out.push({ label: "Malware", value: malware });
  }

  // Threat type (from ThreatFox)
  if (meta.threat_type && typeof meta.threat_type === "string") {
    out.push({ label: "Threat type", value: meta.threat_type });
  }

  // Tags
  const tags = meta.tags;
  if (tags) {
    const tagStr = Array.isArray(tags)
      ? (tags as string[]).filter(Boolean).join(", ")
      : typeof tags === "string" && tags.trim() ? tags : null;
    if (tagStr) out.push({ label: "Tags", value: tagStr });
  }

  // CVE-specific: vendor + product
  if (meta.vendor && typeof meta.vendor === "string") {
    const product = meta.product ? ` ${meta.product}` : "";
    out.push({ label: "Vendor", value: `${meta.vendor}${product}` });
  }

  // Ransomware use (CISA KEV)
  if (meta.ransomware_use === "Known") {
    out.push({ label: "Ransomware", value: "Known campaign use" });
  }

  // Due date (CISA KEV)
  if (meta.due_date && typeof meta.due_date === "string") {
    out.push({ label: "Remediation due", value: meta.due_date });
  }

  // Abuse score (AbuseIPDB)
  if (typeof meta.abuse_confidence_score === "number") {
    out.push({ label: "Abuse score", value: `${meta.abuse_confidence_score}%` });
  }

  // Attack count (DShield)
  if (typeof meta.attacks === "number") {
    out.push({ label: "Attacks", value: formatNumber(meta.attacks as number) });
  }

  // IP reputation score
  if (typeof meta.score === "number") {
    out.push({ label: "Rep. score", value: `${meta.score}/8` });
  }

  // URL status (URLhaus)
  if (meta.status && typeof meta.status === "string") {
    out.push({ label: "Status", value: meta.status });
  }

  // Port (SSL blacklist)
  if (meta.port && typeof meta.port === "string") {
    out.push({ label: "Port", value: meta.port });
  }

  // Reference link
  if (meta.reference && typeof meta.reference === "string") {
    out.push({ label: "Reference", value: meta.reference });
  }

  return out;
}

// ---------------------------------------------------------------------------
// GeoJSON builder
// ---------------------------------------------------------------------------

function entriesToGeoJSON(
  entries: ThreatMapEntry[],
  layerColors: Record<string, string>
) {
  return {
    type: "FeatureCollection" as const,
    features: entries
      .filter((e) => e.latitude != null && e.longitude != null)
      .map((e) => ({
        type: "Feature" as const,
        geometry: {
          type: "Point" as const,
          coordinates: [e.longitude!, e.latitude!],
        },
        properties: {
          id: e.id,
          label: e.label || e.value,
          severity: e.severity,
          layer: e.layer,
          value: e.value,
          feed_name: e.feed_name,
          entry_type: e.entry_type,
          confidence: e.confidence,
          first_seen: e.first_seen,
          last_seen: e.last_seen,
          country_code: e.country_code || "",
          color: layerColors[e.layer] || "#637381",
          radius: SEVERITY_RADIUS[e.severity] || 5,
        },
      })),
  };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function InfoconBadge({ level }: { level: string }) {
  const color = INFOCON_COLORS[level.toLowerCase()] || "#637381";
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative">
        <div
          className="w-2 h-2 rounded-full"
          style={{ backgroundColor: color }}
        />
        <div
          className="absolute inset-0 w-2 h-2 rounded-full animate-ping"
          style={{ backgroundColor: color, opacity: 0.4 }}
        />
      </div>
      <span
        className="text-[10px] font-bold uppercase tracking-[0.15em]"
        style={{ color }}
      >
        INFOCON {level.toUpperCase()}
      </span>
    </div>
  );
}

function StatPill({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-white/[0.03]">
      <span
        className="text-sm font-bold tabular-nums leading-none"
        style={{ color: color || "#DFE3E8" }}
      >
        {formatNumber(value)}
      </span>
      <span style={{ fontSize: "9px", color: "rgba(147,144,132,0.6)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 500, lineHeight: 1 }}>
        {label}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function ThreatMapPage() {
  const mapRef = useRef<MapRef>(null);

  // Data state
  const [layers, setLayers] = useState<ThreatMapLayer[]>([]);
  const [entries, setEntries] = useState<ThreatMapEntry[]>([]);
  const [stats, setStats] = useState<GlobalThreatStats | null>(null);
  const [activeLayers, setActiveLayers] = useState<Set<string>>(new Set());
  const [selectedEntry, setSelectedEntry] = useState<ThreatMapEntryDetail | null>(
    null
  );
  const [detailLoading, setDetailLoading] = useState(false);

  // UI state
  const [hours, setHours] = useState(168);
  const [layerSearch, setLayerSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Debounce ref for viewport fetching
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Layer color map
  const layerColors = useMemo(() => {
    const m: Record<string, string> = {};
    layers.forEach((l) => {
      m[l.name] = l.color;
    });
    return m;
  }, [layers]);

  // GeoJSON data
  const geojson = useMemo(() => {
    const filtered = entries.filter((e) => activeLayers.has(e.layer));
    return entriesToGeoJSON(filtered, layerColors);
  }, [entries, activeLayers, layerColors]);

  // ----- Data fetching ---------------------------------------------------

  const fetchStats = useCallback(async () => {
    try {
      const s = await api.getThreatMapStats();
      setStats(s);
    } catch {
      // stats fetch failure is non-critical
    }
  }, []);

  const fetchEntries = useCallback(
    async (params?: {
      min_lat?: number;
      max_lat?: number;
      min_lng?: number;
      max_lng?: number;
    }) => {
      setEntriesLoading(true);
      try {
        const activeLayerNames = Array.from(activeLayers);

        if (activeLayerNames.length === 0) {
          setEntries([]);
          return;
        }

        let allEntries: ThreatMapEntry[];

        if (activeLayerNames.length === layers.length) {
          allEntries = await api.getThreatMapEntries({
            hours,
            limit: 5000,
            ...params,
          });
        } else {
          const results = await Promise.all(
            activeLayerNames.map((layer) =>
              api
                .getThreatMapEntries({
                  layer,
                  hours,
                  limit: Math.floor(5000 / activeLayerNames.length),
                  ...params,
                })
                .catch(() => [] as ThreatMapEntry[])
            )
          );
          allEntries = results.flat();
        }

        setEntries(allEntries);
      } catch (err) {
        console.error("Failed to fetch entries:", err);
      } finally {
        setEntriesLoading(false);
      }
    },
    [activeLayers, hours, layers.length]
  );

  // Initial load
  useEffect(() => {
    let cancelled = false;

    async function init() {
      setLoading(true);
      setError(null);
      try {
        const [layerData, statsData] = await Promise.allSettled([
          api.getThreatMapLayers(),
          api.getThreatMapStats(),
        ]);

        if (cancelled) return;

        if (layerData.status === "fulfilled") {
          setLayers(layerData.value);
          setActiveLayers(new Set(layerData.value.map((l) => l.name)));
        }
        if (statsData.status === "fulfilled") {
          setStats(statsData.value);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to load threat map data"
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    init();
    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch entries when active layers or hours change
  useEffect(() => {
    if (layers.length === 0 && !loading) return;
    if (loading) return;
    fetchEntries();
  }, [activeLayers, hours, loading]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh stats every 60s
  useEffect(() => {
    const interval = setInterval(fetchStats, 60_000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  // ----- Viewport-based refetching ----------------------------------------

  const handleMoveEnd = useCallback(
    (evt: ViewStateChangeEvent) => {
      if (debounceRef.current) clearTimeout(debounceRef.current);

      debounceRef.current = setTimeout(() => {
        const map = mapRef.current?.getMap();
        if (!map) return;
        const bounds = map.getBounds();
        if (!bounds) return;

        fetchEntries({
          min_lat: bounds.getSouth(),
          max_lat: bounds.getNorth(),
          min_lng: bounds.getWest(),
          max_lng: bounds.getEast(),
        });
      }, 500);
    },
    [fetchEntries]
  );

  // ----- Layer toggles ----------------------------------------------------

  const toggleLayer = useCallback((layerName: string) => {
    setActiveLayers((prev) => {
      const next = new Set(prev);
      if (next.has(layerName)) {
        next.delete(layerName);
      } else {
        next.add(layerName);
      }
      return next;
    });
  }, []);

  const toggleAllLayers = useCallback(() => {
    if (activeLayers.size === layers.length) {
      setActiveLayers(new Set());
    } else {
      setActiveLayers(new Set(layers.map((l) => l.name)));
    }
  }, [activeLayers.size, layers]);

  // ----- Map click --------------------------------------------------------

  const handleMapClick = useCallback(
    async (evt: MapLayerMouseEvent) => {
      const feature = evt.features?.[0];
      if (!feature || !feature.properties) {
        setSelectedEntry(null);
        return;
      }

      const props = feature.properties;
      const entry = entries.find((e) => e.id === props.id);
      if (!entry) return;

      // Show popup immediately with basic data, then enrich
      setSelectedEntry(entry as unknown as ThreatMapEntryDetail);
      setDetailLoading(true);
      try {
        const detail = await api.getThreatMapEntry(entry.id);
        setSelectedEntry(detail);
      } catch {
        // Keep the basic entry data if detail fetch fails
      } finally {
        setDetailLoading(false);
      }
    },
    [entries]
  );

  // ----- Filtered layers --------------------------------------------------

  const filteredLayers = useMemo(() => {
    if (!layerSearch.trim()) return layers;
    const q = layerSearch.toLowerCase();
    return layers.filter(
      (l) =>
        l.display_name.toLowerCase().includes(q) ||
        l.name.toLowerCase().includes(q)
    );
  }, [layers, layerSearch]);

  // ----- Circle paint & layout -------------------------------------------

  const circlePaint = useMemo(
    () => ({
      "circle-color": ["get", "color"] as unknown as string,
      "circle-radius": [
        "interpolate",
        ["linear"],
        ["zoom"],
        1,
        ["*", ["get", "radius"], 0.5],
        4,
        ["*", ["get", "radius"], 1],
        8,
        ["*", ["get", "radius"], 1.6],
        12,
        ["*", ["get", "radius"], 2.2],
      ] as unknown as number,
      "circle-opacity": [
        "interpolate",
        ["linear"],
        ["get", "confidence"],
        0,
        0.4,
        0.5,
        0.65,
        1,
        0.9,
      ] as unknown as number,
      "circle-stroke-width": 1,
      "circle-stroke-color": ["get", "color"] as unknown as string,
      "circle-stroke-opacity": 0.4,
    }),
    []
  );

  const glowPaint = useMemo(
    () => ({
      "circle-color": ["get", "color"] as unknown as string,
      "circle-radius": [
        "interpolate",
        ["linear"],
        ["zoom"],
        1,
        ["*", ["get", "radius"], 1.2],
        4,
        ["*", ["get", "radius"], 2.2],
        8,
        ["*", ["get", "radius"], 3.5],
        12,
        ["*", ["get", "radius"], 5],
      ] as unknown as number,
      "circle-opacity": 0.12,
      "circle-blur": 1,
    }),
    []
  );

  const outerGlowPaint = useMemo(
    () => ({
      "circle-color": ["get", "color"] as unknown as string,
      "circle-radius": [
        "interpolate",
        ["linear"],
        ["zoom"],
        1,
        ["*", ["get", "radius"], 2],
        4,
        ["*", ["get", "radius"], 3.5],
        8,
        ["*", ["get", "radius"], 5.5],
        12,
        ["*", ["get", "radius"], 8],
      ] as unknown as number,
      "circle-opacity": 0.04,
      "circle-blur": 1,
    }),
    []
  );

  // Count active entries per layer
  const layerEntryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    entries.forEach((e) => {
      counts[e.layer] = (counts[e.layer] || 0) + 1;
    });
    return counts;
  }, [entries]);

  // ----- Render -----------------------------------------------------------

  if (loading) {
    return (
      <div style={{ height: "100vh", width: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "#161C24" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "16px" }}>
          <div style={{ position: "relative" }}>
            <Globe style={{ width: "40px", height: "40px", color: "rgba(255,79,0,0.3)" }} />
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Loader2 style={{ width: "20px", height: "20px", color: "var(--color-accent)" }} className="animate-spin" />
            </div>
          </div>
          <div style={{ textAlign: "center" }}>
            <p style={{ color: "rgba(147,144,132,0.6)", fontSize: "14px", fontWeight: 500 }}>
              Initializing Threat Map
            </p>
            <p style={{ color: "rgba(147,144,132,0.4)", fontSize: "12px", marginTop: "4px" }}>
              Loading layers and intelligence feeds...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ height: "100vh", width: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "#161C24" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "16px", maxWidth: "400px", textAlign: "center" }}>
          <AlertTriangle style={{ width: "40px", height: "40px", color: "#FF5630" }} />
          <p style={{ color: "rgba(255,254,251,0.7)", fontSize: "14px" }}>{error}</p>
          <button
            onClick={() => window.location.reload()}
            style={{ padding: "8px 16px", background: "rgba(255,86,48,0.1)", color: "#FF5630", borderRadius: "4px", border: "1px solid rgba(255,86,48,0.3)", fontSize: "12px", fontWeight: 600, cursor: "pointer" }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-screen w-full flex flex-col bg-grey-900 overflow-hidden">
      {/* ================================================================= */}
      {/* DEFCON-STYLE GLOBAL THREAT STATUS BAR                             */}
      {/* ================================================================= */}
      <div className="threat-status-bar relative z-30 flex items-center justify-between px-5 h-11 shrink-0">
        {/* Left: INFOCON + key stats */}
        <div className="flex items-center gap-4">
          {stats && <InfoconBadge level={stats.infocon_level} />}

          <div className="w-px h-5 bg-white/[0.08]" />

          {stats && (
            <div className="flex items-center gap-2">
              <StatPill
                label="Active Threats"
                value={stats.total_entries}
                color="#DFE3E8"
              />
              <StatPill
                label="C2 Servers"
                value={stats.active_c2_servers}
                color="#FF8B00"
              />
              <StatPill
                label="Ransomware"
                value={stats.active_ransomware_groups}
                color="#FF5630"
              />
              <StatPill
                label="Phishing"
                value={stats.active_phishing_campaigns}
                color="#FFAB00"
              />
              <StatPill
                label="CVEs"
                value={stats.exploited_cves_count}
                color="#00BBD9"
              />
            </div>
          )}
        </div>

        {/* Right: loading indicator + marker count */}
        <div className="flex items-center gap-3">
          {entriesLoading && (
            <div className="flex items-center gap-1.5">
              <Activity className="w-3 h-3 text-primary animate-pulse" />
              <span className="text-[10px] text-primary/70 font-medium">
                Updating
              </span>
            </div>
          )}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/[0.03]">
            <Zap className="w-3 h-3 text-grey-500" />
            <span className="text-[10px] text-grey-400 tabular-nums font-bold">
              {geojson.features.length.toLocaleString()}
            </span>
            <span className="text-[9px] text-grey-600">on map</span>
          </div>
          {stats?.last_updated && (
            <span className="text-[10px] text-grey-600 tabular-nums">
              {timeAgo(stats.last_updated)}
            </span>
          )}
        </div>
      </div>

      {/* ================================================================= */}
      {/* MAP + OVERLAY PANELS                                              */}
      {/* ================================================================= */}
      <div className="flex-1 relative min-h-0">
        {/* ---- MAP ---- */}
        <MapGL
          ref={mapRef}
          initialViewState={INITIAL_VIEW}
          style={{ width: "100%", height: "100%" }}
          mapStyle={MAP_STYLE}
          onMoveEnd={handleMoveEnd}
          onClick={handleMapClick}
          interactiveLayerIds={["threat-circles"]}
          cursor="default"
          attributionControl={false}
          maxZoom={14}
          minZoom={1.5}
        >
          <NavigationControl position="bottom-right" showCompass={false} />

          <Source
            id="threats"
            type="geojson"
            data={geojson}
            cluster={false}
          >
            {/* Outer glow (atmosphere) */}
            <Layer
              id="threat-outer-glow"
              type="circle"
              paint={outerGlowPaint}
            />
            {/* Inner glow */}
            <Layer id="threat-glow" type="circle" paint={glowPaint} />
            {/* Main circles */}
            <Layer id="threat-circles" type="circle" paint={circlePaint} />
          </Source>

          {/* Popup */}
          {selectedEntry &&
            selectedEntry.latitude != null &&
            selectedEntry.longitude != null && (
              <Popup
                longitude={selectedEntry.longitude}
                latitude={selectedEntry.latitude}
                anchor="bottom"
                onClose={() => setSelectedEntry(null)}
                closeOnClick={false}
                className="threat-popup"
                maxWidth="380px"
                offset={12}
              >
                <div className="popup-inner">
                  {/* Header with severity accent line */}
                  <div
                    className="popup-accent"
                    style={{
                      background: `linear-gradient(90deg, ${severityColor(selectedEntry.severity)}, transparent)`,
                    }}
                  />

                  {/* Layer + severity */}
                  <div className="flex items-center justify-between mb-2.5 pt-1">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-1.5 h-1.5 rounded-full"
                        style={{
                          backgroundColor:
                            layerColors[selectedEntry.layer] || "#637381",
                          boxShadow: `0 0 6px ${layerColors[selectedEntry.layer] || "#637381"}`,
                        }}
                      />
                      <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-[#919EAB]">
                        {selectedEntry.layer.replace(/_/g, " ")}
                      </span>
                    </div>
                    <span
                      className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-sm tracking-wider"
                      style={{
                        color: severityColor(selectedEntry.severity),
                        backgroundColor: `${severityColor(selectedEntry.severity)}15`,
                        border: `1px solid ${severityColor(selectedEntry.severity)}30`,
                      }}
                    >
                      {selectedEntry.severity}
                    </span>
                  </div>

                  {/* Value */}
                  <p className="text-[13px] font-semibold text-[#F4F6F8] mb-0.5 break-all leading-snug">
                    {selectedEntry.label || selectedEntry.value}
                  </p>
                  {selectedEntry.label && (
                    <p className="text-[11px] text-[#637381] mb-3 break-all font-mono">
                      {selectedEntry.value}
                    </p>
                  )}

                  {/* Description (from detail endpoint) */}
                  {selectedEntry.description && (
                    <p className="text-[11px] text-[#919EAB] mb-3 leading-relaxed line-clamp-3">
                      {selectedEntry.description}
                    </p>
                  )}

                  {/* Location bar */}
                  {(() => {
                    const loc = formatLocation(selectedEntry.city, selectedEntry.country_code);
                    return loc ? (
                      <div className="popup-location-bar">
                        <Globe className="w-3 h-3 text-[#637381] flex-shrink-0" />
                        <span className="text-[11px] text-[#C4CDD5]">{loc}</span>
                        {selectedEntry.asn && (
                          <span className="text-[10px] text-[#637381] ml-auto font-mono truncate max-w-[140px]">
                            {selectedEntry.asn}
                          </span>
                        )}
                      </div>
                    ) : null;
                  })()}

                  {/* Core meta grid */}
                  <div className="popup-meta-grid">
                    <div className="popup-meta-item">
                      <span className="popup-meta-label">Feed</span>
                      <span className="popup-meta-value">
                        {selectedEntry.feed_name}
                      </span>
                    </div>
                    <div className="popup-meta-item">
                      <span className="popup-meta-label">Confidence</span>
                      <span className="popup-meta-value">
                        {Math.round(selectedEntry.confidence * 100)}%
                      </span>
                    </div>
                    <div className="popup-meta-item">
                      <span className="popup-meta-label">Type</span>
                      <span className="popup-meta-value">
                        {selectedEntry.entry_type}
                      </span>
                    </div>
                    <div className="popup-meta-item">
                      <span className="popup-meta-label">First seen</span>
                      <span className="popup-meta-value">
                        {timeAgo(selectedEntry.first_seen)}
                      </span>
                    </div>
                    <div className="popup-meta-item">
                      <span className="popup-meta-label">Last seen</span>
                      <span className="popup-meta-value">
                        {timeAgo(selectedEntry.last_seen)}
                      </span>
                    </div>
                    {selectedEntry.expires_at && (
                      <div className="popup-meta-item">
                        <span className="popup-meta-label">Expires</span>
                        <span className="popup-meta-value">
                          {timeAgo(selectedEntry.expires_at).replace(" ago", "")}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Enriched metadata from feed_metadata */}
                  {(() => {
                    const highlights = extractMetaHighlights(selectedEntry);
                    if (!highlights.length) return null;
                    return (
                      <div className="popup-enriched">
                        {highlights.map((h, i) => (
                          <div key={i} className="popup-enriched-row">
                            <span className="popup-meta-label">{h.label}</span>
                            <span className="popup-enriched-value">{h.value}</span>
                          </div>
                        ))}
                      </div>
                    );
                  })()}

                  {/* Loading indicator for detail fetch */}
                  {detailLoading && (
                    <div className="flex items-center justify-center pt-2 pb-1">
                      <Loader2 className="w-3 h-3 text-[#637381] animate-spin" />
                    </div>
                  )}
                </div>
              </Popup>
            )}
        </MapGL>

        {/* ---- LAYER PANEL (floating, right side) ---- */}
        <div
          className={`absolute top-3 right-3 z-20 transition-all duration-300 ${sidebarOpen ? "w-[256px]" : "w-10"}`}
        >
          {sidebarOpen ? (
            <div className="layer-panel flex flex-col max-h-[calc(100vh-140px)]">
              {/* Panel header */}
              <div className="px-3.5 pt-3.5 pb-2.5 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-3.5 h-3.5 text-grey-500" />
                    <span className="text-[10px] font-bold uppercase tracking-[0.15em] text-grey-400">
                      Threat Layers
                    </span>
                    <span className="text-[9px] text-grey-600 tabular-nums font-medium">
                      {activeLayers.size}/{layers.length}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={toggleAllLayers}
                      className="text-[10px] text-primary/70 hover:text-primary font-semibold transition-colors px-1.5 py-0.5 rounded hover:bg-primary/10"
                    >
                      {activeLayers.size === layers.length ? "None" : "All"}
                    </button>
                    <button
                      onClick={() => setSidebarOpen(false)}
                      className="p-1 rounded hover:bg-white/[0.06] text-grey-500 hover:text-grey-300 transition-colors"
                    >
                      <ChevronUp className="w-3.5 h-3.5 rotate-90" />
                    </button>
                  </div>
                </div>

                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-grey-600" />
                  <input
                    type="text"
                    placeholder="Filter..."
                    value={layerSearch}
                    onChange={(e) => setLayerSearch(e.target.value)}
                    className="w-full pl-7 pr-2.5 py-1.5 bg-white/[0.03] border border-white/[0.06] rounded-md text-[11px] text-grey-300 placeholder:text-grey-600 outline-none focus:border-primary/30 transition-colors"
                  />
                </div>
              </div>

              {/* Layer list */}
              <div className="flex-1 overflow-y-auto px-1.5 pb-3 space-y-px scrollbar-thin">
                {filteredLayers.length === 0 && (
                  <div className="px-3 py-8 text-center">
                    <p className="text-[11px] text-grey-600">
                      No layers match
                    </p>
                  </div>
                )}
                {filteredLayers.map((layer) => {
                  const isActive = activeLayers.has(layer.name);
                  const Icon = LAYER_ICONS[layer.name] || Radio;
                  const liveCount = layerEntryCounts[layer.name] || 0;

                  return (
                    <button
                      key={layer.id}
                      onClick={() => toggleLayer(layer.name)}
                      className={`layer-item w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-left transition-all duration-150 group ${
                        isActive
                          ? "bg-white/[0.05] layer-item-active"
                          : "bg-transparent hover:bg-white/[0.03] opacity-40 hover:opacity-60"
                      }`}
                    >
                      {/* Color indicator */}
                      <div className="relative shrink-0">
                        <div
                          className="w-2.5 h-2.5 rounded-full transition-all duration-200"
                          style={{
                            backgroundColor: isActive
                              ? layer.color
                              : "transparent",
                            border: `2px solid ${layer.color}`,
                            boxShadow: isActive
                              ? `0 0 8px ${layer.color}50`
                              : "none",
                          }}
                        />
                      </div>

                      {/* Icon */}
                      <span
                        className="w-3.5 h-3.5 shrink-0 transition-colors"
                        style={{
                          color: isActive ? layer.color : "#454F5B",
                        }}
                      >
                        <Icon className="w-3.5 h-3.5" />
                      </span>

                      {/* Label */}
                      <div className="flex-1 min-w-0">
                        <span
                          className={`text-[11px] font-medium block truncate leading-tight ${
                            isActive ? "text-grey-200" : "text-grey-500"
                          }`}
                        >
                          {layer.display_name}
                        </span>
                      </div>

                      {/* Count */}
                      <span
                        className={`text-[9px] font-bold tabular-nums px-1.5 py-0.5 rounded transition-colors ${
                          isActive && liveCount > 0
                            ? "bg-white/[0.06] text-grey-300"
                            : "text-grey-600"
                        }`}
                      >
                        {liveCount > 0
                          ? formatNumber(liveCount)
                          : formatNumber(layer.entry_count)}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            /* Collapsed sidebar toggle */
            <button
              onClick={() => setSidebarOpen(true)}
              className="layer-panel w-10 h-10 flex items-center justify-center rounded-lg hover:bg-white/[0.08] transition-colors"
              title="Show layers"
            >
              <Layers className="w-4 h-4 text-grey-400" />
            </button>
          )}
        </div>

        {/* ---- TIME RANGE SELECTOR (floating, bottom center) ---- */}
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-20">
          <div className="time-range-bar flex items-center gap-1 px-2 py-1.5">
            <Clock className="w-3 h-3 text-grey-600 mx-1" />
            {TIME_RANGES.map((tr) => (
              <button
                key={tr.hours}
                onClick={() => setHours(tr.hours)}
                className={`time-range-btn px-3 py-1 rounded text-[11px] font-semibold transition-all duration-150 ${
                  hours === tr.hours
                    ? "time-range-btn-active"
                    : "text-grey-500 hover:text-grey-300 hover:bg-white/[0.06]"
                }`}
              >
                {tr.label}
              </button>
            ))}
          </div>
        </div>

        {/* ---- EMPTY STATE ---- */}
        {!entriesLoading && geojson.features.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <div className="flex flex-col items-center gap-3 text-center p-8 rounded-xl bg-grey-900/60 backdrop-blur-sm">
              <Globe className="w-12 h-12 text-grey-700" />
              <p className="text-grey-500 text-sm font-medium">
                No geolocated threat data
              </p>
              <p className="text-grey-600 text-xs max-w-xs leading-relaxed">
                Run threat feeds to populate the map. Entries with resolved
                geolocation will appear as markers.
              </p>
            </div>
          </div>
        )}

        {/* ---- SCANLINE OVERLAY (subtle CRT effect) ---- */}
        <div className="scanline-overlay" />
      </div>

      {/* ================================================================= */}
      {/* STYLES                                                            */}
      {/* ================================================================= */}
      <style jsx global>{`
        /* Status bar */
        .threat-status-bar {
          background: linear-gradient(
            90deg,
            rgba(20, 26, 33, 0.97) 0%,
            rgba(28, 37, 46, 0.95) 50%,
            rgba(20, 26, 33, 0.97) 100%
          );
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
          backdrop-filter: blur(16px);
        }

        /* Layer panel */
        .layer-panel {
          background: rgba(20, 26, 33, 0.88);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 10px;
          backdrop-filter: blur(20px);
          box-shadow: 0 8px 40px rgba(0, 0, 0, 0.4),
            0 0 1px rgba(255, 255, 255, 0.05);
        }

        /* Time range bar */
        .time-range-bar {
          background: rgba(20, 26, 33, 0.88);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 8px;
          backdrop-filter: blur(20px);
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
        }

        .time-range-btn-active {
          background: rgba(0, 167, 111, 0.15);
          color: #5be49b;
          box-shadow: inset 0 0 0 1px rgba(0, 167, 111, 0.25);
        }

        /* Popup */
        .threat-popup .maplibregl-popup-content {
          background: rgba(28, 37, 46, 0.95);
          backdrop-filter: blur(20px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 10px;
          padding: 0;
          box-shadow: 0 12px 48px rgba(0, 0, 0, 0.6),
            0 0 0 1px rgba(255, 255, 255, 0.03);
          min-width: 260px;
          overflow: hidden;
        }

        .popup-inner {
          padding: 12px 16px 16px;
          font-family: "Public Sans", system-ui, -apple-system, sans-serif;
        }

        .popup-accent {
          height: 2px;
          width: 100%;
        }

        .popup-meta-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 6px 16px;
          padding-top: 10px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
        }

        .popup-meta-label {
          font-size: 10px;
          color: #637381;
          margin-right: 4px;
        }

        .popup-meta-value {
          font-size: 11px;
          color: #c4cdd5;
          font-weight: 500;
        }

        .popup-meta-item {
          display: flex;
          flex-direction: column;
          gap: 1px;
        }

        .popup-location-bar {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 6px 8px;
          margin-bottom: 10px;
          background: rgba(255, 255, 255, 0.03);
          border-radius: 6px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .popup-enriched {
          margin-top: 8px;
          padding-top: 8px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .popup-enriched-row {
          display: flex;
          align-items: baseline;
          gap: 8px;
        }

        .popup-enriched-row .popup-meta-label {
          flex-shrink: 0;
          min-width: 72px;
        }

        .popup-enriched-value {
          font-size: 11px;
          color: #F4F6F8;
          font-weight: 500;
          word-break: break-word;
        }

        .threat-popup .maplibregl-popup-tip {
          border-top-color: rgba(28, 37, 46, 0.95);
        }

        .threat-popup .maplibregl-popup-close-button {
          color: #637381;
          font-size: 18px;
          padding: 6px 10px;
          right: 2px;
          top: 4px;
          line-height: 1;
        }

        .threat-popup .maplibregl-popup-close-button:hover {
          color: #dfe3e8;
          background: transparent;
        }

        /* Map controls */
        .maplibregl-ctrl-group {
          background: rgba(20, 26, 33, 0.85) !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 8px !important;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3) !important;
          backdrop-filter: blur(12px);
        }

        .maplibregl-ctrl-group button {
          border-color: rgba(255, 255, 255, 0.06) !important;
        }

        .maplibregl-ctrl-group button + button {
          border-top-color: rgba(255, 255, 255, 0.06) !important;
        }

        .maplibregl-ctrl-group button .maplibregl-ctrl-icon {
          filter: invert(0.7);
        }

        .maplibregl-ctrl-attrib {
          display: none !important;
        }

        /* Scanline overlay */
        .scanline-overlay {
          position: absolute;
          inset: 0;
          pointer-events: none;
          z-index: 15;
          background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0, 0, 0, 0.015) 2px,
            rgba(0, 0, 0, 0.015) 4px
          );
          mix-blend-mode: multiply;
        }

        /* Scrollbar */
        .scrollbar-thin::-webkit-scrollbar {
          width: 4px;
        }
        .scrollbar-thin::-webkit-scrollbar-track {
          background: transparent;
        }
        .scrollbar-thin::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.08);
          border-radius: 2px;
        }
        .scrollbar-thin::-webkit-scrollbar-thumb:hover {
          background: rgba(255, 255, 255, 0.15);
        }
      `}</style>
    </div>
  );
}
