const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("argus_token") : null;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { ...headers, ...options?.headers },
    ...options,
  });

  if (res.status === 401) {
    // Try to refresh token
    const refreshToken = typeof window !== "undefined" ? localStorage.getItem("argus_refresh_token") : null;
    if (refreshToken && !path.includes("/auth/login") && !path.includes("/auth/refresh")) {
      try {
        const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        if (refreshRes.ok) {
          const data = await refreshRes.json() as { access_token: string };
          localStorage.setItem("argus_token", data.access_token);
          // Retry original request with new token
          const retryRes = await fetch(`${API_BASE}${path}`, {
            headers: { ...headers, Authorization: `Bearer ${data.access_token}`, ...options?.headers },
            ...options,
          });
          if (!retryRes.ok) {
            throw new Error(`API error: ${retryRes.status} ${retryRes.statusText}`);
          }
          return retryRes.json() as Promise<T>;
        } else {
          // Refresh failed — clear tokens
          localStorage.removeItem("argus_token");
          localStorage.removeItem("argus_refresh_token");
          if (typeof window !== "undefined") window.location.href = "/login";
        }
      } catch {
        localStorage.removeItem("argus_token");
        localStorage.removeItem("argus_refresh_token");
        if (typeof window !== "undefined") window.location.href = "/login";
      }
    }
    throw new Error(`API error: ${res.status} Unauthorized`);
  }

  if (!res.ok) {
    const body = await res.text();
    let detail = `${res.status} ${res.statusText}`;
    try {
      const parsed = JSON.parse(body);
      if (parsed.detail) detail = parsed.detail;
    } catch { /* ignore */ }
    throw new Error(detail);
  }

  // Handle 204 No Content
  if (res.status === 204) return undefined as T;

  return res.json() as Promise<T>;
}

async function requestBlob(path: string): Promise<Blob> {
  const token = typeof window !== "undefined" ? localStorage.getItem("argus_token") : null;
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.blob();
}

// Organizations
export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  register: (data: RegisterRequest) =>
    request<UserResponse>("/auth/register", { method: "POST", body: JSON.stringify(data) }),
  refreshToken: (refresh_token: string) =>
    request<{ access_token: string; token_type: string }>("/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token }) }),
  getMe: () => request<UserResponse>("/auth/me"),
  updateMe: (data: ProfileUpdateRequest) =>
    request<UserResponse>("/auth/me", { method: "PATCH", body: JSON.stringify(data) }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),

  // Users (admin)
  getUsers: (params?: { limit?: number; offset?: number; is_active?: boolean; role?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    if (params?.is_active !== undefined) qs.set("is_active", String(params.is_active));
    if (params?.role) qs.set("role", params.role);
    return request<UserListResponse>(`/users/?${qs.toString()}`);
  },
  getUser: (id: string) => request<UserResponse>(`/users/${id}`),
  updateUser: (id: string, data: UserUpdateRequest) =>
    request<UserResponse>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteUser: (id: string) =>
    request<void>(`/users/${id}`, { method: "DELETE" }),
  getUserApiKeys: (userId: string) =>
    request<APIKeyResponse[]>(`/users/${userId}/api-keys`),
  createApiKey: (userId: string, data: { name: string; expires_at?: string }) =>
    request<APIKeyCreatedResponse>(`/users/${userId}/api-keys`, { method: "POST", body: JSON.stringify(data) }),
  revokeApiKey: (userId: string, keyId: string) =>
    request<void>(`/users/${userId}/api-keys/${keyId}`, { method: "DELETE" }),

  // Audit
  getAuditLogs: (params?: AuditParams) => {
    const qs = new URLSearchParams();
    if (params?.action) qs.set("action", params.action);
    if (params?.user_id) qs.set("user_id", params.user_id);
    if (params?.resource_type) qs.set("resource_type", params.resource_type);
    if (params?.since) qs.set("since", params.since);
    if (params?.until) qs.set("until", params.until);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    return request<AuditListResponse>(`/audit/?${qs.toString()}`);
  },
  getAuditStats: (days?: number) =>
    request<AuditStatsResponse>(`/audit/stats${days ? `?days=${days}` : ""}`),

  // Orgs
  getOrgs: () => request<Org[]>("/organizations/"),
  createOrg: (data: CreateOrg) =>
    request<Org>("/organizations/", { method: "POST", body: JSON.stringify(data) }),
  getOrg: (id: string) => request<Org>(`/organizations/${id}`),
  addVip: (orgId: string, data: CreateVip) =>
    request(`/organizations/${orgId}/vips`, { method: "POST", body: JSON.stringify(data) }),
  getVips: (orgId: string) => request<Vip[]>(`/organizations/${orgId}/vips`),
  getAssets: (orgId: string) => request<OrgAsset[]>(`/organizations/${orgId}/assets`),
  addAsset: (orgId: string, data: CreateAsset) =>
    request(`/organizations/${orgId}/assets`, { method: "POST", body: JSON.stringify(data) }),

  // Alerts
  getAlerts: (params?: AlertParams) => {
    const qs = new URLSearchParams();
    if (params?.org_id) qs.set("org_id", params.org_id);
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.category) qs.set("category", params.category);
    if (params?.status) qs.set("status", params.status);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    return request<Alert[]>(`/alerts/?${qs.toString()}`);
  },
  getAlertStats: (orgId?: string) =>
    request<AlertStats>(`/alerts/stats${orgId ? `?org_id=${orgId}` : ""}`),
  getAlert: (id: string) => request<Alert>(`/alerts/${id}`),
  updateAlert: (id: string, data: UpdateAlert) =>
    request<Alert>(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  // Crawlers
  getCrawlers: () => request<Crawler[]>("/crawlers/"),
  triggerCrawler: (name: string) =>
    request(`/crawlers/${name}/run`, { method: "POST" }),

  // Sources
  getSources: (params?: { source_type?: string; enabled?: boolean; health_status?: string }) => {
    const qs = new URLSearchParams();
    if (params?.source_type) qs.set("source_type", params.source_type);
    if (params?.enabled !== undefined) qs.set("enabled", String(params.enabled));
    if (params?.health_status) qs.set("health_status", params.health_status);
    return request<Source[]>(`/sources/?${qs.toString()}`);
  },
  getSource: (id: string) => request<Source>(`/sources/${id}`),
  createSource: (data: SourceCreateRequest) =>
    request<Source>("/sources/", { method: "POST", body: JSON.stringify(data) }),
  updateSource: (id: string, data: SourceUpdateRequest) =>
    request<Source>(`/sources/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteSource: (id: string) =>
    request<void>(`/sources/${id}`, { method: "DELETE" }),
  testSource: (id: string) =>
    request<SourceTestResult>(`/sources/${id}/test`, { method: "POST" }),
  getSourceHealth: () => request<SourceHealthSummary>("/sources/health"),

  // IOCs
  getIOCs: (params?: IOCParams) => {
    const qs = new URLSearchParams();
    if (params?.ioc_type) qs.set("ioc_type", params.ioc_type);
    if (params?.min_confidence) qs.set("confidence_min", String(params.min_confidence / 100));
    if (params?.search) qs.set("value_search", params.search);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    return request<IOCItem[]>(`/iocs/?${qs.toString()}`);
  },
  getIOC: (id: string) => request<IOCItem>(`/iocs/${id}`),
  getIOCStats: () => request<IOCStats>("/iocs/stats"),
  searchIOCs: (values: string[]) =>
    request<BulkSearchResult[]>("/iocs/search", { method: "POST", body: JSON.stringify({ values }) }),
  exportSTIX: () => requestBlob("/iocs/export/stix"),
  exportCSV: () => requestBlob("/iocs/export/csv"),

  // Actors
  getActors: (params?: { limit?: number; offset?: number; search?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    if (params?.search) qs.set("search", params.search);
    return request<ThreatActor[]>(`/actors/?${qs.toString()}`);
  },
  getActor: (id: string) => request<ThreatActorDetail>(`/actors/${id}`),
  updateActor: (id: string, data: Partial<ThreatActor>) =>
    request<ThreatActor>(`/actors/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  getActorTimeline: (id: string) =>
    request<TimelineEntry[]>(`/actors/${id}/timeline`),
  getActorIOCs: (actorId: string) => {
    return request<IOCItem[]>(`/iocs/?threat_actor_id=${actorId}&limit=100`);
  },
  getActorAlerts: (actorId: string) =>
    request<ThreatActorDetail>(`/actors/${actorId}`).then((d) =>
      d.linked_alert_ids.length > 0
        ? Promise.all(d.linked_alert_ids.slice(0, 20).map((id) => request<Alert>(`/alerts/${id}`).catch(() => null))).then((r) => r.filter(Boolean) as Alert[])
        : []
    ),
  getActorStats: () => request<ActorStats>("/actors/stats"),

  // Scanning
  scanSubdomains: (orgId: string) =>
    request(`/scan/${orgId}/subdomains`, { method: "POST" }),
  scanExposures: (orgId: string) =>
    request(`/scan/${orgId}/exposures`, { method: "POST" }),

  // Reports
  generateReport: (orgId: string, dateFrom: string, dateTo: string) =>
    fetch(`${API_BASE}/reports/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(typeof window !== "undefined" && localStorage.getItem("argus_token")
          ? { Authorization: `Bearer ${localStorage.getItem("argus_token")}` }
          : {}),
      },
      body: JSON.stringify({ org_id: orgId, date_from: dateFrom, date_to: dateTo }),
    }),
  getReports: () => request<Report[]>("/reports/"),

  // Webhooks
  getWebhookConfig: () => request<WebhookConfig>("/webhooks/config"),
  testWebhook: () => request("/webhooks/test", { method: "POST" }),

  // Search
  searchAlerts: (q: string) => request<Alert[]>(`/alerts/search?q=${encodeURIComponent(q)}&limit=10`),
  searchOrgs: (q: string) => request<Org[]>(`/organizations/search?q=${encodeURIComponent(q)}`),

  // Report download
  downloadReport: (id: string) =>
    fetch(`${API_BASE}/reports/${id}`, {
      method: "GET",
      headers: {
        ...(typeof window !== "undefined" && localStorage.getItem("argus_token")
          ? { Authorization: `Bearer ${localStorage.getItem("argus_token")}` }
          : {}),
      },
    }),

  // Threat Map
  getThreatMapLayers: () => request<ThreatMapLayer[]>("/threat-map/layers"),
  getThreatMapEntries: (params?: ThreatMapParams) => {
    const qs = new URLSearchParams();
    if (params?.layer) qs.set("layer", params.layer);
    if (params?.min_lat !== undefined) qs.set("min_lat", String(params.min_lat));
    if (params?.max_lat !== undefined) qs.set("max_lat", String(params.max_lat));
    if (params?.min_lng !== undefined) qs.set("min_lng", String(params.min_lng));
    if (params?.max_lng !== undefined) qs.set("max_lng", String(params.max_lng));
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.hours) qs.set("hours", String(params.hours));
    if (params?.limit) qs.set("limit", String(params.limit));
    return request<{ items: ThreatMapEntry[]; total: number }>(`/threat-map/entries?${qs}`).then(r => r.items);
  },
  getThreatMapEntry: (id: string) => request<ThreatMapEntryDetail>(`/threat-map/entry/${id}`),
  getThreatMapStats: () => request<GlobalThreatStats>("/threat-map/stats"),
  getThreatMapHeatmap: (params?: { layer?: string; hours?: number }) => {
    const qs = new URLSearchParams();
    if (params?.layer) qs.set("layer", params.layer);
    if (params?.hours) qs.set("hours", String(params.hours));
    return request<HeatmapEntry[]>(`/threat-map/heatmap?${qs}`);
  },
  // Feeds
  getFeeds: () => request<FeedSummary>("/feeds/"),
  triggerFeed: (name: string) =>
    request<FeedTriggerResponse>("/feeds/" + name + "/trigger", { method: "POST" }),
  triggerFeedTriage: (hours: number = 6) =>
    request<{ message: string; status: string }>(`/feeds/triage?hours=${hours}`, { method: "POST" }),
  backfillGeolocation: () =>
    request<{ message: string; status: string }>("/feeds/backfill-geo", { method: "POST" }),
};

// Auth Types
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: UserResponse;
}

export interface UserResponse {
  id: string;
  email: string;
  username: string;
  display_name: string;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
  updated_at?: string;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
  display_name: string;
  role?: string;
}

export interface ProfileUpdateRequest {
  display_name?: string;
  current_password?: string;
  new_password?: string;
}

export interface UserUpdateRequest {
  role?: string;
  is_active?: boolean;
  display_name?: string;
}

export interface UserListResponse {
  users: UserResponse[];
  total: number;
}

export interface APIKeyResponse {
  id: string;
  name: string;
  key_prefix: string;
  is_active: boolean;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface APIKeyCreatedResponse extends APIKeyResponse {
  raw_key: string;
}

// Audit Types
export interface AuditParams {
  action?: string;
  user_id?: string;
  resource_type?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
}

export interface AuditListResponse {
  logs: AuditLogEntry[];
  total: number;
}

export interface AuditStatsResponse {
  total_events: number;
  actions_per_day: { date: string; count: number }[];
  top_users: { user_id: string; count: number }[];
  actions_breakdown: Record<string, number>;
}

// Source Types
export interface Source {
  id: string;
  name: string;
  source_type: string;
  url: string;
  mirror_urls: string[] | null;
  selectors: Record<string, unknown> | null;
  auth_config: Record<string, unknown> | null;
  language: string;
  enabled: boolean;
  priority: number;
  crawl_interval_minutes: number;
  max_pages: number;
  last_crawled_at: string | null;
  last_success_at: string | null;
  health_status: string;
  consecutive_failures: number;
  total_items_collected: number;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface SourceCreateRequest {
  name: string;
  source_type: string;
  url: string;
  mirror_urls?: string[];
  selectors?: Record<string, unknown>;
  auth_config?: Record<string, unknown>;
  language?: string;
  enabled?: boolean;
  priority?: number;
  crawl_interval_minutes?: number;
  max_pages?: number;
  notes?: string;
}

export interface SourceUpdateRequest {
  name?: string;
  url?: string;
  mirror_urls?: string[];
  selectors?: Record<string, unknown>;
  auth_config?: Record<string, unknown>;
  language?: string;
  enabled?: boolean;
  priority?: number;
  crawl_interval_minutes?: number;
  max_pages?: number;
  notes?: string;
}

export interface SourceTestResult {
  reachable: boolean;
  status_code: number | null;
  response_time_ms: number | null;
  content_preview: string | null;
  error: string | null;
  blocked: boolean;
}

export interface SourceHealthSummary {
  total: number;
  healthy: number;
  degraded: number;
  unreachable: number;
  blocked: number;
  unknown: number;
  enabled: number;
  disabled: number;
}

// IOC Types
export interface IOCItem {
  id: string;
  ioc_type: string;
  value: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  sighting_count: number;
  tags: string[] | null;
  context: Record<string, unknown> | null;
  source_alert_id: string | null;
  source_raw_intel_id: string | null;
  threat_actor_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IOCParams {
  ioc_type?: string;
  min_confidence?: number;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface BulkSearchResult {
  value: string;
  found: boolean;
  ioc: IOCItem | null;
}

export interface IOCStats {
  total: number;
  by_type: Record<string, number>;
  top_iocs: { id: string; ioc_type: string; value: string; sighting_count: number; confidence: number; last_seen: string }[];
}

// Actor Types
export interface ThreatActor {
  id: string;
  primary_alias: string;
  aliases: string[];
  description: string | null;
  forums_active: string[];
  languages: string[];
  pgp_fingerprints: string[];
  known_ttps: string[];
  risk_score: number;
  first_seen: string;
  last_seen: string;
  total_sightings: number;
  profile_data: Record<string, unknown> | null;
  created_at: string;
}

export interface ThreatActorDetail extends ThreatActor {
  recent_sightings: { id: string; timestamp: string; platform: string; alias_used: string; alert_id: string | null }[];
  ioc_count: number;
  linked_alert_ids: string[];
}

export interface TimelineEntry {
  timestamp: string;
  platform: string;
  alias_used: string;
  raw_intel_id: string | null;
  alert_id: string | null;
  context: Record<string, unknown> | null;
}

export interface ActorStats {
  total_actors: number;
  avg_risk_score: number;
  by_platform: Record<string, number>;
  high_risk_count: number;
  active_last_30_days: number;
}

// Organization Types
export interface Org {
  id: string;
  name: string;
  domains: string[];
  keywords: string[];
  industry: string | null;
  tech_stack: Record<string, unknown> | null;
}

export interface CreateOrg {
  name: string;
  domains: string[];
  keywords: string[];
  industry?: string;
  tech_stack?: Record<string, unknown>;
}

export interface Vip {
  id: string;
  name: string;
  title: string | null;
  emails: string[];
}

export interface CreateVip {
  name: string;
  title?: string;
  emails?: string[];
  usernames?: string[];
}

export interface CreateAsset {
  asset_type: string;
  value: string;
}

export interface OrgAsset {
  id: string;
  type: string;
  value: string;
  details: Record<string, unknown> | null;
}

export interface Alert {
  id: string;
  organization_id: string;
  category: string;
  severity: string;
  status: string;
  title: string;
  summary: string;
  confidence: number;
  agent_reasoning: string | null;
  recommended_actions: string[] | null;
  matched_entities: Record<string, string> | null;
  analyst_notes: string | null;
  created_at: string;
}

export interface AlertParams {
  org_id?: string;
  severity?: string;
  category?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface AlertStats {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_status: Record<string, number>;
}

export interface UpdateAlert {
  status?: string;
  analyst_notes?: string;
}

export interface Crawler {
  name: string;
  crawler_name: string;
  interval_seconds: number;
  last_run: string | null;
}

export interface Report {
  id: string;
  title: string;
  date_from: string;
  date_to: string;
  created_at: string;
}

export interface WebhookConfig {
  slack: boolean;
  email: boolean;
  pagerduty: boolean;
}

// Threat Map Types
export interface ThreatMapLayer {
  id: string;
  name: string;
  display_name: string;
  icon: string;
  color: string;
  enabled: boolean;
  entry_count: number;
  refresh_interval_seconds: number;
  description: string | null;
}

export interface ThreatMapEntry {
  id: string;
  feed_name: string;
  layer: string;
  entry_type: string;
  value: string;
  label: string | null;
  severity: string;
  confidence: number;
  latitude: number | null;
  longitude: number | null;
  country_code: string | null;
  first_seen: string;
  last_seen: string;
}

export interface ThreatMapEntryDetail extends ThreatMapEntry {
  description: string | null;
  city: string | null;
  asn: string | null;
  feed_metadata: Record<string, unknown> | null;
  expires_at: string | null;
}

export interface GlobalThreatStats {
  infocon_level: string;
  active_ransomware_groups: number;
  active_c2_servers: number;
  active_phishing_campaigns: number;
  exploited_cves_count: number;
  tor_exit_nodes_count: number;
  malware_urls_count: number;
  malicious_ips_count: number;
  total_entries: number;
  last_updated: string | null;
}

export interface HeatmapEntry {
  country_code: string;
  count: number;
}

export interface ThreatMapParams {
  layer?: string;
  min_lat?: number;
  max_lat?: number;
  min_lng?: number;
  max_lng?: number;
  severity?: string;
  hours?: number;
  limit?: number;
  offset?: number;
}

export interface FeedInfo {
  feed_name: string;
  layer: string;
  display_name: string;
  icon: string;
  color: string;
  enabled: boolean;
  refresh_interval_seconds: number;
  description: string | null;
  active_entry_count: number;
  total_entry_count: number;
  latest_entry_at: string | null;
}

export interface FeedSummary {
  total_feeds: number;
  total_active_entries: number;
  feeds: FeedInfo[];
}

export interface FeedTriggerResponse {
  feed_name: string;
  message: string;
  status: string;
}
