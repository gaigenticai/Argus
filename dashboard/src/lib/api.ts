// Adversarial audit D-3 — refuse to fall back to a hard-coded loopback URL
// in client bundles. A missing NEXT_PUBLIC_API_URL in a production build
// would silently leak credentials at http://localhost:8000 on whatever
// machine the bundle runs on. Fail loud at module load so the misconfig
// is impossible to ship.
const _API_BASE_RAW = process.env.NEXT_PUBLIC_API_URL;
if (!_API_BASE_RAW) {
  throw new Error(
    "NEXT_PUBLIC_API_URL is required at build time. " +
      "Set it in .env.local for development (e.g. http://localhost:8000/api/v1) " +
      "and in your deployment env for production."
  );
}
const API_BASE = _API_BASE_RAW;

/**
 * Server-sent-event URL — for ``EventSource`` only.
 *
 * Why this exists:
 *   - Regular REST fetches use ``API_BASE`` which (in dev) is the
 *     relative ``/api/v1`` path that Next.js rewrites to
 *     ``http://localhost:8000``. That works fine for normal request /
 *     response.
 *   - SSE goes through the same rewrite **but Next.js dev (Turbopack
 *     16.x) buffers the response body** so events queue up and the
 *     browser's ``EventSource`` never sees them — the connection
 *     opens (``onopen`` fires) but ``onmessage`` is silent. Direct
 *     curl confirms the backend stream is healthy; the dev rewrite
 *     is the choke point.
 *
 * Resolution order:
 *   1. ``NEXT_PUBLIC_SSE_URL`` env var — operator override for prod
 *      deployments where API + dashboard are on different origins.
 *   2. If ``API_BASE`` is already absolute (``http(s)://...``), just
 *      use it directly — the proxy isn't in the way.
 *   3. Otherwise compute ``http://<window-host>:8000/api/v1`` at
 *      runtime. This bypasses the Next dev rewrite cleanly.
 *
 * The SSE endpoint (``/activity/stream``) doesn't require auth so
 * cross-port access doesn't need cookies; the URL is the only thing
 * that has to differ.
 */
function _computeSseBase(): string {
  const override = process.env.NEXT_PUBLIC_SSE_URL;
  if (override) return override;
  if (/^https?:\/\//i.test(API_BASE)) return API_BASE;
  // API_BASE is path-relative (e.g. ``/api/v1``). In the browser we
  // can derive the dev backend URL from window.location; on the
  // server (SSR) we just return the relative path — there's no
  // EventSource consumer there anyway.
  if (typeof window !== "undefined") {
    return `${window.location.protocol}//${window.location.hostname}:8000${API_BASE}`;
  }
  return API_BASE;
}

export const SSE_BASE = _computeSseBase();

/**
 * Audit D20 — flatten the global error envelope into a readable string.
 *
 * The backend wraps every error as ``{detail, request_id}`` (Audit D2).
 * ``detail`` is one of:
 *   - ``string``                              → human-readable, return as-is.
 *   - ``Array<{loc, msg, type}>``             → Pydantic v2 validation list.
 *   - ``object`` with ``errors``/``field``    → custom 422 shapes.
 *   - anything else                           → JSON-stringify, last resort.
 *
 * The request_id (when present) is appended in parentheses so the SOC
 * can correlate against the JSON log line (Audit C5).
 */
export function flattenApiError(parsed: unknown, fallback: string): string {
  if (parsed === null || parsed === undefined) return fallback;
  if (typeof parsed === "string") return parsed;
  if (typeof parsed !== "object") return String(parsed);

  const env = parsed as { detail?: unknown; request_id?: string };
  const detail = env.detail !== undefined ? env.detail : parsed;
  const reqId = typeof env.request_id === "string" ? env.request_id : null;

  const stringify = (d: unknown): string => {
    if (d === null || d === undefined) return fallback;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      // Pydantic v2: [{loc:["body","field"], msg:"...", type:"..."}]
      const lines = d.map((e) => {
        if (e && typeof e === "object") {
          const { loc, msg, message } = e as {
            loc?: unknown[];
            msg?: string;
            message?: string;
          };
          const path = Array.isArray(loc)
            ? loc.filter((p) => typeof p !== "number" || p > 0).join(".")
            : "";
          const text = msg || message || JSON.stringify(e);
          return path ? `${path}: ${text}` : text;
        }
        return String(e);
      });
      return lines.join("; ");
    }
    if (typeof d === "object") {
      const obj = d as Record<string, unknown>;
      if (typeof obj.message === "string") return obj.message;
      if (typeof obj.error === "string") return obj.error;
      if (Array.isArray(obj.errors)) return stringify(obj.errors);
      // Last resort — flatten as ``key: value`` pairs.
      try {
        return Object.entries(obj)
          .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
          .join("; ");
      } catch {
        return fallback;
      }
    }
    return fallback;
  };

  const text = stringify(detail) || fallback;
  return reqId ? `${text} (request_id=${reqId})` : text;
}

/**
 * Pagination metadata returned alongside list payloads. The backend
 * sets these headers via Audit B6's pagination middleware.
 */
export interface PageMeta {
  total: number | null;
  limit: number | null;
  offset: number | null;
}

function _readPageMeta(res: Response): PageMeta {
  const num = (h: string): number | null => {
    const v = res.headers.get(h);
    if (!v) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  return {
    total: num("X-Total-Count"),
    limit: num("X-Page-Limit"),
    offset: num("X-Page-Offset"),
  };
}

/**
 * Like {@link request} but additionally returns pagination metadata.
 * Use it for list endpoints where the UI needs total counts (most do).
 */
export async function requestPaginated<T>(
  path: string,
  options?: RequestInit
): Promise<{ data: T; page: PageMeta }> {
  const { data, response } = await requestRaw<T>(path, options);
  return { data, page: _readPageMeta(response) };
}

async function requestRaw<T>(
  path: string,
  options?: RequestInit
): Promise<{ data: T; response: Response }> {
  // Adversarial audit D-1 — auth now travels as HttpOnly cookies set
  // by the backend. The browser ships them automatically with
  // `credentials: "include"`; we no longer touch localStorage.
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { ...headers, ...options?.headers },
    ...options,
  });

  if (res.status === 401) {
    // Try to refresh: cookie-bound, so the browser ships the
    // refresh token automatically. /auth/refresh sets a new
    // access cookie on success.
    if (!path.includes("/auth/login") && !path.includes("/auth/refresh")) {
      try {
        const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
        });
        if (refreshRes.ok) {
          const retryRes = await fetch(`${API_BASE}${path}`, {
            credentials: "include",
            headers: { ...headers, ...options?.headers },
            ...options,
          });
          if (!retryRes.ok) {
            const body = await retryRes.text();
            let detail = `${retryRes.status} ${retryRes.statusText}`;
            try {
              detail = flattenApiError(JSON.parse(body), detail);
            } catch { /* body wasn't JSON */ }
            throw new ApiError(detail, retryRes.status);
          }
          if (retryRes.status === 204) {
            return { data: undefined as T, response: retryRes };
          }
          return { data: (await retryRes.json()) as T, response: retryRes };
        } else if (typeof window !== "undefined" && window.location.pathname !== "/login") {
          // Skip the hard redirect when we're already on /login —
          // otherwise the auth-provider's mount-time getMe() reloads
          // the page in a loop while it discovers the user isn't
          // logged in. The auth-provider catches the throw below and
          // shows the form on its own.
          window.location.href = "/login";
        }
      } catch (e) {
        if (e instanceof ApiError) throw e;
        if (typeof window !== "undefined" && window.location.pathname !== "/login") {
          window.location.href = "/login";
        }
      }
    }
    throw new ApiError("Unauthorized", 401);
  }

  if (!res.ok) {
    const body = await res.text();
    let detail = `${res.status} ${res.statusText}`;
    try {
      detail = flattenApiError(JSON.parse(body), detail);
    } catch { /* body wasn't JSON */ }
    throw new ApiError(detail, res.status);
  }

  if (res.status === 204) {
    return { data: undefined as T, response: res };
  }
  return { data: (await res.json()) as T, response: res };
}

/**
 * Typed error so call sites can branch on status code without parsing
 * the message. ``status`` is 0 for network errors.
 */
export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const { data } = await requestRaw<T>(path, options);
  return data;
}

async function requestBlob(path: string): Promise<Blob> {
  // Audit D-1 — cookie-only auth.
  const res = await fetch(`${API_BASE}${path}`, { credentials: "include" });
  if (!res.ok) {
    const body = await res.text();
    let detail = `${res.status} ${res.statusText}`;
    try {
      detail = flattenApiError(JSON.parse(body), detail);
    } catch { /* body wasn't JSON */ }
    throw new ApiError(detail, res.status);
  }
  return res.blob();
}

/**
 * Multipart form upload helper. Used by evidence vault, asset CSV,
 * VIP photo upload, brand logo upload, etc. Refresh-token flow is
 * intentionally NOT applied here — uploads should fail loudly so the
 * UI can surface "auth expired, please log in again" rather than
 * silently retry a 50 MB file.
 */
async function requestMultipart<T>(
  path: string,
  fd: FormData,
  options?: { method?: string }
): Promise<T> {
  // Audit D-1 — cookie auth.
  const res = await fetch(`${API_BASE}${path}`, {
    method: options?.method || "POST",
    credentials: "include",
    body: fd,
  });
  if (!res.ok) {
    const body = await res.text();
    let detail = `${res.status} ${res.statusText}`;
    try {
      detail = flattenApiError(JSON.parse(body), detail);
    } catch { /* body wasn't JSON */ }
    throw new ApiError(detail, res.status);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/**
 * Build a query string from an object. Skips null / undefined values
 * and arrays-of-zero entries; serialises arrays as repeated keys
 * (FastAPI convention).
 */
function _qs(params: object | undefined): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) {
      for (const x of v) sp.append(k, String(x));
    } else if (typeof v === "boolean") {
      sp.set(k, v ? "true" : "false");
    } else {
      sp.set(k, String(v));
    }
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
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

  // Org locale (P1 #1.2 — Hijri / Asia/Riyadh)
  organizations: {
    getLocale: () => request<LocaleResponse>("/organizations/current/locale"),
    updateLocale: (body: { timezone?: string; calendar_system?: string }) =>
      request<LocaleResponse>("/organizations/current/locale", {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
  },

  // Single-tenant current-org helpers — backed by /organizations/current
  // (admin only PATCH). Used by Settings → Tech Stack.
  getCurrentOrg: () => request<Org>("/organizations/current"),
  updateCurrentOrg: (body: Partial<Pick<Org, "name" | "domains" | "keywords" | "industry" | "tech_stack">>) =>
    request<Org>("/organizations/current", {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

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
  getAlertSource: (id: string) =>
    request<AlertSourceResponse>(`/alerts/${id}/source`),
  getAlertAttribution: (id: string, limit = 5) =>
    request<AlertAttributionResponse>(
      `/alerts/${id}/attribution?limit=${limit}`,
    ),
  getAlertRelations: (id: string) =>
    request<AlertRelationsResponse>(`/alerts/${id}/relations`),
  getAlertThresholds: (id: string) =>
    request<AlertThresholdsResponse>(`/alerts/${id}/thresholds`),
  updateAlert: (id: string, data: UpdateAlert) =>
    request<Alert>(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  // Crawlers
  getCrawlers: () => request<Crawler[]>("/crawlers/"),
  triggerCrawler: (name: string) =>
    request(`/crawlers/${name}/run`, { method: "POST" }),

  // IOCs
  getIOCs: (params?: IOCParams) => {
    const qs = new URLSearchParams();
    if (params?.ioc_type) qs.set("ioc_type", params.ioc_type);
    if (params?.min_confidence) qs.set("confidence_min", String(params.min_confidence / 100));
    if (params?.search) qs.set("value_search", params.search);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    if (params?.source_alert_id) qs.set("source_alert_id", params.source_alert_id);
    return request<IOCItem[]>(`/iocs/?${qs.toString()}`);
  },
  getIOC: (id: string) => request<IOCItem>(`/iocs/${id}`),
  getIOCStats: () => request<IOCStats>("/iocs/stats"),
  searchIOCs: (values: string[]) =>
    request<BulkSearchResult[]>("/iocs/search", { method: "POST", body: JSON.stringify({ values }) }),
  exportSTIX: () => requestBlob("/iocs/export/stix"),
  exportCSV: () => requestBlob("/iocs/export/csv"),
  // Production write ops + enrichment + sightings + pivot
  createIOC: (body: {
    ioc_type: string;
    value: string;
    confidence?: number;
    tags?: string[];
    source_feed?: string;
  }) =>
    request<IOCItem>("/iocs/", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  editIOC: (
    id: string,
    body: {
      confidence?: number;
      tags?: string[];
      is_allowlisted?: boolean;
      allowlist_reason?: string;
      expires_at?: string | null;
      confidence_half_life_days?: number;
    },
  ) =>
    request<IOCItem>(`/iocs/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteIOC: (id: string) =>
    request<void>(`/iocs/${id}`, { method: "DELETE" }),
  toggleAllowlist: (id: string, on: boolean, reason?: string) => {
    const qs = new URLSearchParams({ on: String(on) });
    if (reason) qs.set("reason", reason);
    return request<IOCItem>(`/iocs/${id}/allowlist?${qs.toString()}`, {
      method: "POST",
    });
  },
  enrichIOC: (id: string) =>
    request<IOCItem>(`/iocs/${id}/enrich`, { method: "POST" }),
  getIOCSightings: (id: string, limit = 100) =>
    request<{
      id: string;
      ioc_id: string;
      source: string;
      source_id: string | null;
      source_url: string | null;
      seen_at: string;
      context: Record<string, unknown>;
      created_at: string;
    }[]>(`/iocs/${id}/sightings?limit=${limit}`),
  getIOCPivot: (id: string) =>
    request<{
      ioc_id: string;
      related_via_articles: IOCItem[];
      related_via_actor: IOCItem[];
      articles: { id: string; title: string; url: string }[];
    }>(`/iocs/${id}/pivot`),
  getIOCDefanged: (id: string) =>
    request<{ value: string; defanged: string }>(`/iocs/${id}/defang`),
  bulkImportIOCs: (rows: Array<{
    ioc_type: string;
    value: string;
    confidence?: number;
    tags?: string[];
    source_feed?: string;
  }>) =>
    request<{ inserted: number; updated: number; errors: string[] }>(
      "/iocs/import",
      { method: "POST", body: JSON.stringify({ rows }) },
    ),
  decayIOCs: () => request<{ decayed: number; sunsetted: number; total_evaluated: number }>("/iocs/decay", { method: "POST" }),
  getIOCAudit: (id: string, limit = 50) =>
    request<{
      id: string;
      action: string;
      user_id: string | null;
      before: Record<string, unknown> | null;
      after: Record<string, unknown> | null;
      created_at: string;
    }[]>(`/iocs/${id}/audit?limit=${limit}`),

  // Actors
  getActors: (params?: {
    limit?: number;
    offset?: number;
    search?: string;
    sector?: string;
    region?: string;
    country?: string;
    technique?: string;
    confidence_min?: number;
    has_mitre_id?: boolean;
    risk_score_min?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    if (params?.search) qs.set("search", params.search);
    if (params?.sector) qs.set("sector", params.sector);
    if (params?.region) qs.set("region", params.region);
    if (params?.country) qs.set("country", params.country);
    if (params?.technique) qs.set("technique", params.technique);
    if (params?.confidence_min !== undefined) qs.set("confidence_min", String(params.confidence_min));
    if (params?.has_mitre_id !== undefined) qs.set("has_mitre_id", String(params.has_mitre_id));
    if (params?.risk_score_min !== undefined) qs.set("risk_score_min", String(params.risk_score_min));
    return request<ThreatActor[]>(`/actors/?${qs.toString()}`);
  },
  importActorsFromMitre: () =>
    request<{ written: number }>("/actors/import-from-mitre", { method: "POST" }),
  exportActorStix: async (id: string): Promise<Record<string, unknown>> =>
    request<Record<string, unknown>>(`/actors/${id}/stix`),
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
  getActorNavigatorLayerUrl: (id: string, matrix: "enterprise" | "ics" = "enterprise") =>
    `${API_BASE}/actors/${id}/navigator-layer?matrix=${matrix}`,
  getAlertNavigatorLayerUrl: (id: string, matrix: "enterprise" | "ics" = "enterprise") =>
    `${API_BASE}/alerts/${id}/navigator-layer?matrix=${matrix}`,

  // Scanning
  scanSubdomains: (orgId: string) =>
    request(`/scan/${orgId}/subdomains`, { method: "POST" }),
  scanExposures: (orgId: string) =>
    request(`/scan/${orgId}/exposures`, { method: "POST" }),

  // Reports
  generateReport: (orgId: string, dateFrom: string, dateTo: string) =>
    fetch(`${API_BASE}/reports/generate`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
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
      credentials: "include",
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
  // Integrations / Tools
  getIntegrations: () => request<IntegrationTool[]>("/tools/"),
  getIntegration: (name: string) => request<IntegrationTool>(`/tools/${name}`),
  updateIntegration: (name: string, data: IntegrationUpdateRequest) =>
    request(`/tools/${name}`, { method: "PUT", body: JSON.stringify(data) }),
  testIntegration: (name: string) =>
    request<{ tool_name: string; connected: boolean; message: string }>(`/tools/${name}/test`, { method: "POST" }),
  syncIntegration: (name: string) =>
    request<{ tool_name: string; message: string; status: string }>(`/tools/${name}/sync`, { method: "POST" }),
  getTriageHistory: (limit: number = 20) =>
    request<TriageRunItem[]>(`/tools/triage/history?limit=${limit}`),

  // ── P3 connectors (EDR / email-gateway / sandbox / SOAR / breach /
  //                   forensics / telegram / adversary-emulation) ──
  // Each group exposes: a list of {name, label, configured} entries
  // and a per-name health probe.
  listConnectors: (group: P3ConnectorGroup) =>
    request<{ connectors?: ConnectorRow[]; providers?: ConnectorRow[] }>(
      `/intel/${P3_GROUP_PATH[group]}`,
    ),
  connectorHealth: (group: P3ConnectorGroup, name: string) =>
    request<ConnectorHealth>(
      `/intel/${P3_GROUP_PATH[group]}/${name}/health`,
    ),
  forensicsAvailability: () =>
    request<{
      volatility: { available: boolean; cli_path: string | null };
      velociraptor: { configured: boolean };
    }>(`/intel/forensics/availability`),
  telegramAvailability: () =>
    request<{
      configured: boolean;
      curated_total: number;
      curated_active: number;
    }>(`/intel/telegram/availability`),
  telegramChannels: () =>
    request<{ channels: TelegramChannel[] }>(`/intel/telegram/channels`),
  adversaryEmulationAvailability: () =>
    request<{
      atomic_red_team: {
        filesystem_path: string | null;
        filesystem_active: boolean;
        curated_count: number;
        techniques_indexed: number;
      };
      caldera: { configured: boolean };
    }>(`/intel/adversary-emulation/availability`),

  // ── User-self-service feed subscriptions (P3 #3.4) ──
  listFeedSubscriptions: () =>
    request<FeedSubscriptionRow[]>(`/feed-subscriptions`),
  createFeedSubscription: (body: FeedSubscriptionCreate) =>
    request<FeedSubscriptionRow>(`/feed-subscriptions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteFeedSubscription: (id: string) =>
    request<void>(`/feed-subscriptions/${id}`, { method: "DELETE" }),
  testFeedSubscription: (id: string, alert: Record<string, unknown>) =>
    request<{ matches: boolean }>(
      `/feed-subscriptions/${id}/test`,
      { method: "POST", body: JSON.stringify({ alert }) },
    ),

  // ── Admin OSS-tools onboarding (P3 #3.4 closeout) ──
  ossCatalog: () => request<{ tools: OssToolCatalogEntry[] }>(`/oss-tools/catalog`),
  ossPreflight: () => request<OssPreflight>(`/oss-tools/preflight`),
  ossStates: () => request<{ tools: OssToolState[] }>(`/oss-tools/`),
  ossInstall: (tools: string[]) =>
    request<{ started: string[]; preflight: OssPreflight }>(`/oss-tools/install`, {
      method: "POST",
      body: JSON.stringify({ tools }),
    }),
  ossSkip: () => request<{ complete: boolean }>(`/oss-tools/onboarding/skip`, {
    method: "POST",
  }),
  ossOnboardingStatus: () =>
    request<{ complete: boolean; installer_enabled: boolean }>(
      `/oss-tools/onboarding`,
    ),

  // Asset Registry (Phase 0.1)
  listAssets: (params: AssetListParams) => {
    const qs = new URLSearchParams();
    qs.set("organization_id", params.organization_id);
    if (params.asset_type) qs.set("asset_type", params.asset_type);
    if (params.criticality) qs.set("criticality", params.criticality);
    if (params.tag) qs.set("tag", params.tag);
    if (params.is_active !== undefined) qs.set("is_active", String(params.is_active));
    if (params.monitoring_enabled !== undefined) qs.set("monitoring_enabled", String(params.monitoring_enabled));
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    if (params.offset) qs.set("offset", String(params.offset));
    return request<AssetRecord[]>(`/assets?${qs.toString()}`);
  },
  countAssets: (organizationId: string) =>
    request<AssetCounts>(`/assets/count?organization_id=${organizationId}`),
  getAsset: (id: string) => request<AssetRecord>(`/assets/${id}`),
  createAsset: (data: AssetCreatePayload) =>
    request<AssetRecord>("/assets", { method: "POST", body: JSON.stringify(data) }),
  updateAsset: (id: string, data: AssetPatchPayload) =>
    request<AssetRecord>(`/assets/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteAsset: (id: string) =>
    request<void>(`/assets/${id}`, { method: "DELETE" }),
  bulkImportAssets: (data: BulkImportPayload) =>
    request<BulkImportResult>("/assets/bulk", { method: "POST", body: JSON.stringify(data) }),
  bulkImportAssetsCSV: async (organizationId: string, file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_BASE}/assets/bulk/csv?organization_id=${organizationId}`, {
      method: "POST",
      credentials: "include",
      body: fd,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json() as Promise<BulkImportResult>;
  },
  getAssetSchemas: () => request<Record<string, unknown>>("/assets/types/schema"),

  // Domain management on an org (list / add / remove). Each domain
  // tracks its own verification state — see ``domainVerification``.
  orgDomains: {
    list: (orgId: string) =>
      request<OrgDomainListItem[]>(`/organizations/${orgId}/domains`),
    add: (orgId: string, domain: string, makePrimary = false) =>
      request<OrgDomainListItem[]>(`/organizations/${orgId}/domains`, {
        method: "POST",
        body: JSON.stringify({ domain, make_primary: makePrimary }),
      }),
    remove: (orgId: string, domain: string) =>
      request<OrgDomainListItem[]>(
        `/organizations/${orgId}/domains/${encodeURIComponent(domain)}`,
        { method: "DELETE" },
      ),
  },

  // Operator-curated monitoring scope: which Telegram channels to
  // scrape and which email addresses to look up against breach
  // corpora. Both are stored on ``Organization.settings`` and read by
  // the production workers (telegram_monitor + the credential checker).
  monitoredSources: {
    get: () =>
      request<MonitoredSourcesResponse>("/organizations/current/monitored-sources"),
    update: (body: { telegram_channels: string[]; breach_emails: string[] }) =>
      request<MonitoredSourcesResponse>("/organizations/current/monitored-sources", {
        method: "PUT",
        body: JSON.stringify(body),
      }),
  },

  // Domain ownership verification — DNS TXT or HTTP-file challenge.
  // Backend gates discovery + triage when
  // ``ARGUS_REQUIRE_DOMAIN_VERIFICATION=true``; frontend always shows
  // the banner so even on demo deployments operators see how the
  // proof-of-ownership step would work.
  domainVerification: {
    status: (orgId: string, domain: string) =>
      request<DomainVerificationStatus>(
        `/organizations/${orgId}/verification?domain=${encodeURIComponent(domain)}`,
      ),
    request: (orgId: string, domain: string) =>
      request<DomainVerificationStatus>(
        `/organizations/${orgId}/verification/request?domain=${encodeURIComponent(domain)}`,
        { method: "POST" },
      ),
    check: (orgId: string, domain: string) =>
      request<DomainVerificationCheck>(
        `/organizations/${orgId}/verification/check?domain=${encodeURIComponent(domain)}`,
        { method: "POST" },
      ),
  },

  // First-run quickstart — minimal "see the AI work in 2 minutes"
  // path. The 5-step session-based wizard below is the deeper rollout
  // tool for serious onboarding. Both are reachable via /onboarding,
  // but a fresh login goes through quickstart first.
  getOnboardingState: () =>
    request<OnboardingState>("/onboarding/state"),
  quickstart: (data: {
    org_name: string;
    primary_domain: string;
    brand_keyword: string;
    industry?: string;
  }) =>
    request<QuickstartResponse>("/onboarding/quickstart", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Onboarding (Phase 0.2)
  createOnboardingSession: (data: { organization_id?: string; notes?: string }) =>
    request<OnboardingSessionRecord>("/onboarding/sessions", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  listOnboardingSessions: (params?: {
    state?: "draft" | "completed" | "abandoned";
    mine_only?: boolean;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.state) qs.set("state", params.state);
    if (params?.mine_only) qs.set("mine_only", "true");
    if (params?.limit) qs.set("limit", String(params.limit));
    return request<OnboardingSessionRecord[]>(`/onboarding/sessions?${qs.toString()}`);
  },
  getOnboardingSession: (id: string) =>
    request<OnboardingSessionRecord>(`/onboarding/sessions/${id}`),
  patchOnboardingSession: (id: string, data: { step: OnboardingStepKey; data: unknown; advance?: boolean }) =>
    request<OnboardingSessionRecord>(`/onboarding/sessions/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  validateOnboardingSession: (id: string) =>
    request<OnboardingValidationReport[]>(`/onboarding/sessions/${id}/validate`, {
      method: "POST",
    }),
  completeOnboardingSession: (id: string) =>
    request<OnboardingCompletionResult>(`/onboarding/sessions/${id}/complete`, {
      method: "POST",
    }),
  abandonOnboardingSession: (id: string) =>
    request<OnboardingSessionRecord>(`/onboarding/sessions/${id}/abandon`, {
      method: "POST",
    }),
  listDiscoveryJobs: (params?: { organization_id?: string; status?: string; kind?: string; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.organization_id) qs.set("organization_id", params.organization_id);
    if (params?.status) qs.set("status", params.status);
    if (params?.kind) qs.set("kind", params.kind);
    if (params?.limit) qs.set("limit", String(params.limit));
    return request<DiscoveryJobRecord[]>(`/onboarding/discovery-jobs?${qs.toString()}`);
  },
  cancelDiscoveryJob: (id: string) =>
    request<DiscoveryJobRecord>(`/onboarding/discovery-jobs/${id}/cancel`, { method: "POST" }),

  // Feeds
  getFeeds: () => request<FeedSummary>("/feeds/"),
  triggerFeed: (name: string) =>
    request<FeedTriggerResponse>("/feeds/" + name + "/trigger", { method: "POST" }),
  triggerFeedTriage: (hours: number = 6) =>
    request<{ message: string; status: string; previous_run_id: string | null }>(
      `/feeds/triage?hours=${hours}`,
      { method: "POST" },
    ),
  getLatestTriageRun: () => request<TriageRunSummary | null>("/feeds/triage/latest"),
  getDashboardExposure: () => request<DashboardExposure>("/dashboard/exposure"),
  getFeedEntries: (feedName: string, opts?: { limit?: number; severity?: string }) => {
    const qs = new URLSearchParams();
    if (opts?.limit) qs.set("limit", String(opts.limit));
    if (opts?.severity) qs.set("severity", opts.severity);
    const q = qs.toString();
    return request<FeedEntriesResponse>(`/feeds/${encodeURIComponent(feedName)}/entries${q ? `?${q}` : ""}`);
  },
  getFeedStats: (feedName: string) =>
    request<FeedStatsResponse>(`/feeds/${encodeURIComponent(feedName)}/stats`),
  getLayerSummary: (layer: string) =>
    request<LayerSummaryResponse>(`/feeds/layers/${encodeURIComponent(layer)}/summary`),
  backfillGeolocation: () =>
    request<{ message: string; status: string }>("/feeds/backfill-geo", { method: "POST" }),

  // ====================================================================
  // Phase 1+ namespaces (Audit B1).
  //
  // Backend-side endpoints documented in src/api/routes/<name>.py and
  // grouped under OpenAPI tags via src/api/app.py::_OPENAPI_TAGS.
  //
  // List endpoints use ``requestPaginated`` so call sites can read
  // ``X-Total-Count`` (Audit B6) for paged UIs without a second
  // round-trip. Mutation endpoints surface ``flattenApiError`` so
  // Pydantic validation errors render as human strings (Audit D20).
  // ====================================================================

  investigations: {
    list: (
      params: {
        alert_id?: string;
        case_id?: string;
        status?: string;
        limit?: number;
      } = {},
    ) =>
      request<InvestigationListItem[]>(`/investigations${_qs(params)}`),
    get: (id: string) =>
      request<InvestigationDetail>(`/investigations/${id}`),
    create: (alertId: string) =>
      request<{ id: string; status: string; alert_id: string }>(
        `/investigations/${alertId}`,
        { method: "POST" },
      ),
    promote: (id: string) =>
      request<{ investigation_id: string; case_id: string; already_promoted: boolean }>(
        `/investigations/${id}/promote`,
        { method: "POST" },
      ),
    rerun: (id: string, extra_context?: string) =>
      request<{ id: string; status: string; alert_id: string }>(
        `/investigations/${id}/rerun`,
        {
          method: "POST",
          body: JSON.stringify(extra_context ? { extra_context } : {}),
        },
      ),
    approvePlan: (id: string, plan?: InvestigationPlanStep[]) =>
      request<{ id: string; status: string; alert_id: string }>(
        `/investigations/${id}/approve-plan`,
        {
          method: "POST",
          body: JSON.stringify(plan ? { plan } : {}),
        },
      ),
    stats: (days = 30) =>
      request<InvestigationStatsResponse>(
        `/investigations/stats?days=${days}`,
      ),
    compare: (aId: string, bId: string) =>
      request<InvestigationCompareDiff>(
        `/investigations/compare?ids=${aId},${bId}`,
      ),
    /** Absolute SSE URL — caller passes to EventSource. Routes through
     *  the same SSE_BASE the activity stream uses so dev rewrites
     *  don't buffer the response. */
    streamUrl: (id: string) => `${SSE_BASE}/investigations/${id}/stream`,
  },

  agents: {
    posture: () => request<AgentPosture>(`/agents/posture`),
    getSettings: () => request<AgentSettings>(`/agents/settings`),
    patchSettings: (body: Partial<AgentSettings>) =>
      request<AgentSettings>(`/agents/settings`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    activity: (params: { limit?: number } = {}) =>
      request<AgentActivityItem[]>(`/agents/activity${_qs(params)}`),
  },

  threatHunts: {
    list: (params: { status?: string; limit?: number } = {}) =>
      request<HuntListItem[]>(`/threat-hunts${_qs(params)}`),
    get: (id: string) =>
      request<HuntDetail>(`/threat-hunts/${id}`),
    create: (templateId?: string) =>
      request<{ id: string; status: string }>(
        `/threat-hunts${templateId ? `?template_id=${templateId}` : ""}`,
        { method: "POST" },
      ),
    listTemplates: (organizationId?: string) =>
      request<{
        id: string;
        organization_id: string | null;
        name: string;
        hypothesis: string;
        description: string | null;
        methodology: string;
        mitre_technique_ids: string[];
        data_sources: string[];
        tags: string[];
        is_global: boolean;
      }[]>(`/threat-hunts/templates${organizationId ? `?organization_id=${organizationId}` : ""}`),
    seedTemplates: () =>
      request<{ inserted: number; updated: number; total: number }>(
        "/threat-hunts/templates/seed-builtins",
        { method: "POST" },
      ),
    listNotes: (runId: string) =>
      request<{ id: string; body: string; author_user_id: string | null; created_at: string }[]>(
        `/threat-hunts/${runId}/notes`,
      ),
    addNote: (runId: string, body: string) =>
      request<{ id: string; body: string }>(`/threat-hunts/${runId}/notes`, {
        method: "POST",
        body: JSON.stringify({ body }),
      }),
    transition: (runId: string, next_state: string, reason?: string) =>
      request<HuntDetail>(`/threat-hunts/${runId}/transition`, {
        method: "POST",
        body: JSON.stringify({ next_state, reason }),
      }),
    assign: (runId: string, user_id: string | null) =>
      request<HuntDetail>(`/threat-hunts/${runId}/assign`, {
        method: "POST",
        body: JSON.stringify({ user_id }),
      }),
    escalate: (runId: string, opts?: { finding_indices?: number[]; case_title?: string }) =>
      request<{ case_id: string; title: string }>(`/threat-hunts/${runId}/escalate`, {
        method: "POST",
        body: JSON.stringify(opts || {}),
      }),
    report: (runId: string) =>
      request<{ markdown: string }>(`/threat-hunts/${runId}/report`),
  },

  caseCopilot: {
    latest: (caseId: string) =>
      request<CopilotRunDetail | null>(`/cases/${caseId}/copilot`),
    create: (caseId: string) =>
      request<{ id: string; status: string; case_id: string }>(
        `/cases/${caseId}/copilot`,
        { method: "POST" },
      ),
    get: (runId: string) =>
      request<CopilotRunDetail>(`/copilot-runs/${runId}`),
    apply: (runId: string) =>
      request<{
        run_id: string;
        applied_at: string;
        already_applied: boolean;
        mitre_attached: number;
        comment_added: boolean;
        playbooks_queued: number;
      }>(`/copilot-runs/${runId}/apply`, { method: "POST" }),
  },

  brandActions: {
    list: (
      params: {
        suspect_domain_id?: string;
        status?: string;
        recommendation?: string;
        limit?: number;
      } = {},
    ) =>
      request<BrandActionListItem[]>(`/brand-actions${_qs(params)}`),
    get: (id: string) =>
      request<BrandActionDetail>(`/brand-actions/${id}`),
    create: (suspectDomainId: string) =>
      request<{ id: string; status: string; suspect_domain_id: string }>(
        `/brand-actions/${suspectDomainId}`,
        { method: "POST" },
      ),
    submitTakedown: (id: string, body: { partner?: string } = {}) =>
      request<{
        action_id: string;
        ticket_id: string;
        partner: string;
        already_submitted: boolean;
      }>(`/brand-actions/${id}/submit-takedown`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    rerun: (id: string, extra_context?: string) =>
      request<{ id: string; status: string; suspect_domain_id: string }>(
        `/brand-actions/${id}/rerun`,
        {
          method: "POST",
          body: JSON.stringify(extra_context ? { extra_context } : {}),
        },
      ),
    approvePlan: (id: string, plan?: InvestigationPlanStep[]) =>
      request<{ id: string; status: string; suspect_domain_id: string }>(
        `/brand-actions/${id}/approve-plan`,
        {
          method: "POST",
          body: JSON.stringify(plan ? { plan } : {}),
        },
      ),
    stats: (days = 30) =>
      request<BrandActionStatsResponse>(
        `/brand-actions/stats?days=${days}`,
      ),
    compare: (aId: string, bId: string) =>
      request<BrandActionCompareDiff>(
        `/brand-actions/compare?ids=${aId},${bId}`,
      ),
    streamUrl: (id: string) => `${SSE_BASE}/brand-actions/${id}/stream`,
  },

  cases: {
    list: (params: CaseListParams) =>
      requestPaginated<CaseResponse[]>(`/cases${_qs(params)}`),
    count: (organizationId: string) =>
      request<CaseCounts>(`/cases/count?organization_id=${organizationId}`),
    get: (id: string) => request<CaseDetailResponse>(`/cases/${id}`),
    create: (body: CaseCreatePayload) =>
      request<CaseResponse>("/cases", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    update: (id: string, body: CaseUpdatePayload) =>
      request<CaseResponse>(`/cases/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    delete: (id: string) =>
      request<void>(`/cases/${id}`, { method: "DELETE" }),
    transition: (id: string, body: CaseTransitionPayload) =>
      request<CaseResponse>(`/cases/${id}/transitions`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    addFinding: (id: string, body: CaseFindingCreatePayload) =>
      request<CaseFindingResponse>(`/cases/${id}/findings`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    removeFinding: (caseId: string, findingId: string) =>
      request<void>(`/cases/${caseId}/findings/${findingId}`, {
        method: "DELETE",
      }),
    addComment: (id: string, body: { body: string }) =>
      request<CaseCommentResponse>(`/cases/${id}/comments`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateComment: (caseId: string, commentId: string, body: { body: string }) =>
      request<CaseCommentResponse>(`/cases/${caseId}/comments/${commentId}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    deleteComment: (caseId: string, commentId: string) =>
      request<void>(`/cases/${caseId}/comments/${commentId}`, {
        method: "DELETE",
      }),
  },

  brand: {
    overview: (organizationId: string) =>
      request<BrandOverviewResponse>(
        `/brand/overview?organization_id=${organizationId}`
      ),
    listTerms: (organizationId: string) =>
      request<BrandTermResponse[]>(
        `/brand/terms?organization_id=${organizationId}`
      ),
    createTerm: (body: BrandTermCreatePayload) =>
      request<BrandTermResponse>("/brand/terms", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deleteTerm: (id: string) =>
      request<void>(`/brand/terms/${id}`, { method: "DELETE" }),
    runScan: (body: { organization_id: string }) =>
      request<BrandScanResponse>(
        `/brand/scan?organization_id=${encodeURIComponent(body.organization_id)}`,
        { method: "POST" },
      ),
    listSuspects: (params: SuspectListParams) =>
      requestPaginated<SuspectDomainResponse[]>(`/brand/suspects${_qs(params)}`),
    transitionSuspect: (id: string, body: SuspectStatePayload) =>
      request<SuspectDomainResponse>(`/brand/suspects/${id}/state`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listLogos: (organizationId: string) =>
      request<BrandLogoResponse[]>(
        `/brand/logos?organization_id=${organizationId}`
      ),
    deleteLogo: (id: string) =>
      request<void>(`/brand/logos/${id}`, { method: "DELETE" }),
    listLogoMatches: (organizationId: string) =>
      request<LogoMatchResponse[]>(
        `/brand/logos/matches?organization_id=${organizationId}`
      ),
    listProbes: (params: {
      organization_id: string;
      verdict?: string;
      limit?: number;
      offset?: number;
    }) => requestPaginated<LiveProbeResponse[]>(`/brand/probes${_qs(params)}`),
    listProbesForSuspect: (suspectId: string, limit?: number) =>
      request<LiveProbeResponse[]>(
        `/brand/suspects/${suspectId}/probes${_qs({ limit })}`,
      ),
    runProbe: (body: LiveProbeRunPayload) =>
      request<LiveProbeResponse>(
        `/brand/suspects/${body.suspect_domain_id}/probe`,
        { method: "POST" },
      ),
    runFeedIngest: (body: FeedIngestPayload) =>
      request<FeedIngestResponse>("/brand/feed/ingest", {
        method: "POST",
        body: JSON.stringify({
          organization_id: body.organization_id,
          domains: body.candidates,
          source: body.source,
          min_similarity: body.min_similarity,
        }),
      }),
    // -- Subsidiary allowlist (T78) -----------------------------------
    listAllowlist: (organizationId: string) =>
      request<BrandAllowlistEntry[]>(
        `/brand/allowlist?organization_id=${organizationId}`,
      ),
    createAllowlist: (body: {
      organization_id: string;
      pattern: string;
      reason?: string;
    }) =>
      request<BrandAllowlistEntry>("/brand/allowlist", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deleteAllowlist: (id: string) =>
      request<void>(`/brand/allowlist/${id}`, { method: "DELETE" }),
    sweepAllowlist: (organizationId: string) =>
      request<BrandAllowlistSweepResponse>(
        `/brand/allowlist/sweep?organization_id=${organizationId}`,
        { method: "POST" },
      ),
    // -- Re-probe scheduler queue (T80) -------------------------------
    listScheduledProbes: (
      organizationId: string,
      limit = 100,
    ) =>
      request<BrandScheduledProbe[]>(
        `/brand/probes/scheduled?organization_id=${organizationId}&limit=${limit}`,
      ),
    /** Lazy WHOIS lookup for a suspect (T91). Cached server-side
     *  for 24h; pass refresh=true to force a fresh WHOIS. */
    getSuspectWhois: (suspectId: string, refresh = false) =>
      request<BrandSuspectWhois>(
        `/brand/suspects/${suspectId}/whois${refresh ? "?refresh=true" : ""}`,
      ),
    /** Campaign clustering — groups open suspects by shared
     *  nameserver / IP / matched_term (T92). */
    listSuspectClusters: (organizationId: string, minSize = 2) =>
      request<{ clusters: BrandSuspectCluster[] }>(
        `/brand/suspects/clusters?organization_id=${organizationId}&min_size=${minSize}`,
      ),
  },

  easm: {
    enqueueScan: (body: EasmScanPayload) =>
      request<{ job_id: string }>("/easm/scan", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listChanges: (params: { organization_id: string; limit?: number }) =>
      requestPaginated<EasmChangeResponse[]>(`/easm/changes${_qs(params)}`),
    listFindings: (params: EasmFindingListParams) =>
      requestPaginated<EasmFindingResponse[]>(`/easm/findings${_qs(params)}`),
    promoteFinding: (id: string) =>
      request<EasmFindingResponse>(`/easm/findings/${id}/promote`, {
        method: "POST",
      }),
    dismissFinding: (id: string, body?: { reason?: string }) =>
      request<EasmFindingResponse>(`/easm/findings/${id}/dismiss`, {
        method: "POST",
        body: JSON.stringify(body || {}),
      }),
    listExposures: (params: ExposureListParams) =>
      requestPaginated<ExposureResponse[]>(`/easm/exposures${_qs(params)}`),
    getExposure: (id: string) =>
      request<ExposureResponse>(`/easm/exposures/${id}`),
    transitionExposure: (id: string, body: ExposureStatePayload) =>
      request<ExposureResponse>(`/easm/exposures/${id}/state`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    linkExposureAsset: (id: string, body: ExposureLinkAssetPayload) =>
      request<ExposureResponse>(`/easm/exposures/${id}/link-asset`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    triageExposures: (orgId: string, body?: ExposureTriagePayload) =>
      request<ExposureTriageResponse>(
        `/easm/exposures/triage?organization_id=${orgId}`,
        { method: "POST", body: JSON.stringify(body || {}) },
      ),
  },

  surface: {
    listAssets: (params: SurfaceAssetsParams) =>
      request<SurfaceAsset[]>(`/surface/assets${_qs(params)}`),
    getAsset: (id: string) =>
      request<SurfaceAssetDetail>(`/surface/assets/${id}`),
    listAssetExposures: (id: string, state?: string) =>
      request<SurfaceAssetExposure[]>(
        `/surface/assets/${id}/exposures${state ? `?state=${state}` : ""}`,
      ),
    listChanges: (params: SurfaceChangesParams) =>
      request<SurfaceChange[]>(`/surface/changes${_qs(params)}`),
    recomputeRisk: (orgId: string) =>
      request<{ updated: number; total_assets: number }>(
        "/surface/recompute-risk",
        {
          method: "POST",
          body: JSON.stringify({ organization_id: orgId }),
        },
      ),
    classify: (
      orgId: string,
      opts?: {
        use_llm?: boolean;
        only_unclassified?: boolean;
        asset_ids?: string[];
      },
    ) =>
      request<SurfaceClassifyResponse>("/surface/classify", {
        method: "POST",
        body: JSON.stringify({ organization_id: orgId, ...(opts || {}) }),
      }),
    stats: (orgId: string) =>
      request<SurfaceStats>(`/surface/stats?organization_id=${orgId}`),
  },

  tprm: {
    seedTemplates: (orgId: string) =>
      request<TprmTemplateResponse[]>(
        `/tprm/templates/seed-builtins?organization_id=${orgId}`,
        { method: "POST" },
      ),
    listTemplates: (orgId?: string) =>
      request<TprmTemplateResponse[]>(
        orgId ? `/tprm/templates?organization_id=${orgId}` : "/tprm/templates",
      ),
    getTemplate: (id: string) =>
      request<TprmTemplateResponse>(`/tprm/templates/${id}`),
    createTemplate: (body: TprmTemplateCreatePayload) =>
      request<TprmTemplateResponse>("/tprm/templates", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listOnboarding: (organizationId: string) =>
      request<TprmOnboardingResponse[]>(
        `/tprm/onboarding?organization_id=${organizationId}`
      ),
    createOnboarding: (body: TprmOnboardingCreatePayload) =>
      request<TprmOnboardingResponse>("/tprm/onboarding", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listScorecards: (params: {
      organization_id: string;
      vendor_asset_id?: string;
      is_current?: boolean;
      limit?: number;
      offset?: number;
    }) =>
      requestPaginated<TprmScorecardResponse[]>(
        `/tprm/scorecards${_qs(params)}`
      ),
    recomputeScorecard: (vendorAssetId: string) =>
      request<TprmScorecardResponse>(
        `/tprm/scorecards/recompute?vendor_asset_id=${vendorAssetId}`,
        { method: "POST" }
      ),
    transitionOnboarding: (
      workflowId: string,
      body: TprmOnboardingTransitionPayload,
    ) =>
      request<TprmOnboardingResponse>(
        `/tprm/onboarding/${workflowId}/transition`,
        { method: "POST", body: JSON.stringify(body) },
      ),
    // --- TPRM full-audit additions --------------------------------
    collectPosture: (orgId: string, vendorAssetId: string) =>
      request<Record<string, { score: number; evidence: unknown }>>(
        "/tprm/posture/collect",
        {
          method: "POST",
          body: JSON.stringify({
            organization_id: orgId,
            vendor_asset_id: vendorAssetId,
          }),
        },
      ),
    listPosture: (vendorAssetId: string) =>
      request<VendorPostureSignal[]>(`/tprm/posture/${vendorAssetId}`),
    snapshots: (vendorAssetId: string, days = 180) =>
      request<VendorScorecardSnapshotsResponse>(
        `/tprm/scorecards/${vendorAssetId}/snapshots?days=${days}`,
      ),
    percentile: (vendorAssetId: string) =>
      request<VendorPercentileResponse>(
        `/tprm/scorecards/${vendorAssetId}/percentile`,
      ),
    execDashboard: (orgId: string) =>
      request<TprmExecDashboard>(
        `/tprm/exec-dashboard?organization_id=${orgId}`,
      ),
    listEvidence: (vendorAssetId: string) =>
      request<VendorEvidenceFileResponse[]>(`/tprm/evidence/${vendorAssetId}`),
    listContracts: (vendorAssetId: string) =>
      request<VendorContractResponse[]>(`/tprm/contracts/${vendorAssetId}`),
    autofillQuestionnaire: (instanceId: string, useLlm = true) =>
      request<{ filled: number; skipped: number; total_questions: number; posture: unknown }>(
        "/tprm/questionnaires/autofill",
        {
          method: "POST",
          body: JSON.stringify({
            questionnaire_instance_id: instanceId,
            use_llm: useLlm,
          }),
        },
      ),
    brief: (vendorAssetId: string, useLlm = true) =>
      request<VendorBriefResponse>("/tprm/agents/brief", {
        method: "POST",
        body: JSON.stringify({
          vendor_asset_id: vendorAssetId,
          use_llm: useLlm,
        }),
      }),
    playbook: (
      vendorAssetId: string,
      failingPillar: string,
      useLlm = true,
    ) =>
      request<VendorPlaybookResponse>("/tprm/agents/playbook", {
        method: "POST",
        body: JSON.stringify({
          vendor_asset_id: vendorAssetId,
          failing_pillar: failingPillar,
          use_llm: useLlm,
        }),
      }),
    quarterlyHealthCheck: (orgId: string, dropThreshold = 20) =>
      request<{
        vendors_total: number;
        computed: number;
        drops_detected: Array<Record<string, unknown>>;
      }>("/tprm/agents/quarterly-health-check", {
        method: "POST",
        body: JSON.stringify({
          organization_id: orgId,
          drop_threshold: dropThreshold,
        }),
      }),
    portalToken: (instanceId: string) =>
      request<{ instance_id: string; token: string }>(
        `/tprm/portal/${instanceId}/token`,
      ),
  },

  takedown: {
    listPartners: () => request<TakedownPartnerInfo>("/takedown/partners"),
    listTickets: (params: TakedownListParams) =>
      requestPaginated<TakedownTicketResponse[]>(
        `/takedown/tickets${_qs(params)}`
      ),
    getTicket: (id: string) =>
      request<TakedownTicketResponse>(`/takedown/tickets/${id}`),
    createTicket: (body: TakedownTicketCreatePayload) =>
      request<TakedownTicketResponse>("/takedown/tickets", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    transitionTicket: (id: string, body: TakedownTransitionPayload) =>
      request<TakedownTicketResponse>(`/takedown/tickets/${id}/transitions`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    syncTicket: (id: string) =>
      request<TakedownTicketResponse>(`/takedown/tickets/${id}/sync`, {
        method: "POST",
      }),
    getTicketHistory: (id: string) =>
      request<TakedownTicketHistoryResponse>(
        `/takedown/tickets/${id}/history`
      ),
  },

  exec: {
    // The backend's /exec-summary endpoint streams a PDF — there is no
    // JSON variant. The dashboard's Exec Summary page builds the view
    // from individual rollup endpoints (cases.count, brand.overview,
    // ratings.current, sla.listBreaches) and offers this download for
    // board-meeting export.
    downloadPdf: (params: { organization_id: string; days?: number }) =>
      requestBlob(`/exec-summary${_qs(params)}`),
    // CIO-grade enrichment endpoints — see src/api/routes/exec_briefing.py.
    briefing: (params: { organization_id: string; force_refresh?: boolean }) =>
      request<ExecBriefingResponse>(`/exec/briefing${_qs(params)}`, {
        method: "POST",
      }),
    topRisks: (params: { organization_id: string; limit?: number }) =>
      request<ExecTopRisksResponse>(`/exec/top-risks${_qs(params)}`),
    changes: (params: { organization_id: string; window_days?: number }) =>
      request<ExecChangesResponse>(`/exec/changes${_qs(params)}`),
    compliance: (params: { organization_id: string }) =>
      request<ExecComplianceResponse>(`/exec/compliance${_qs(params)}`),
    suggestedActions: (params: { organization_id: string }) =>
      request<ExecSuggestedActionsResponse>(`/exec/suggested-actions${_qs(params)}`),

    // ── Playbook execution layer ─────────────────────────────────
    playbookCatalog: (params: {
      organization_id: string;
      /** ``all`` (default) merges global + investigation; pass
       *  ``global`` or ``investigation`` to filter to one surface. */
      scope?: "global" | "investigation" | "all";
    }) =>
      request<PlaybookCatalogResponse>(`/exec/playbook-catalog${_qs(params)}`),
    playbookPreview: (body: PlaybookPreviewPayload) =>
      request<PlaybookPreviewResponse>("/exec/playbook-preview", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookExecute: (body: PlaybookExecutePayload) =>
      request<PlaybookExecutionResponse>("/exec/playbook-execute", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookApprove: (body: { execution_id: string; note?: string }) =>
      request<PlaybookExecutionResponse>("/exec/playbook-approve", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookDeny: (body: { execution_id: string; reason: string }) =>
      request<PlaybookExecutionResponse>("/exec/playbook-deny", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookStepAdvance: (body: { execution_id: string }) =>
      request<PlaybookExecutionResponse>("/exec/playbook-step-advance", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookCancel: (body: { execution_id: string; reason?: string }) =>
      request<PlaybookExecutionResponse>("/exec/playbook-cancel", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    playbookHistory: (params: {
      organization_id: string;
      status?: PlaybookStatus;
      playbook_id?: string;
      case_id?: string;
      copilot_run_id?: string;
      limit?: number;
      offset?: number;
    }) => request<PlaybookHistoryResponse>(`/exec/playbook-history${_qs(params)}`),
    playbookPendingApprovals: (params: {
      organization_id: string;
      limit?: number;
    }) =>
      request<PlaybookHistoryResponse>(
        `/exec/playbook-pending-approvals${_qs(params)}`,
      ),
    playbookExecution: (executionId: string) =>
      request<PlaybookExecutionResponse>(
        `/exec/playbook-execution/${executionId}`,
      ),
  },

  leakage: {
    listBins: (organizationId?: string) =>
      request<BinResponse[]>(
        `/leakage/bins${_qs({ organization_id: organizationId })}`,
      ),
    runCardScan: (body: CardScanPayload) =>
      request<CardScanResponse>("/leakage/cards/scan", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listCardFindings: (params: {
      organization_id: string;
      state?: string;
      limit?: number;
    }) => request<CardLeakageResponse[]>(`/leakage/cards${_qs(params)}`),
    transitionCardFinding: (
      id: string,
      body: { state: string; reason?: string },
    ) =>
      request<CardLeakageResponse>(`/leakage/cards/${id}/state`, {
        method: "POST",
        // Backend expects ``to_state`` (the column name); accept either
        // shape from callers and normalise here.
        body: JSON.stringify({ to_state: body.state, reason: body.reason }),
      }),
    listDlpPolicies: (organizationId: string) =>
      request<DlpPolicyResponse[]>(
        `/leakage/policies?organization_id=${organizationId}`,
      ),
    createDlpPolicy: (body: DlpPolicyCreatePayload) =>
      request<DlpPolicyResponse>("/leakage/policies", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deleteDlpPolicy: (id: string) =>
      request<void>(`/leakage/policies/${id}`, { method: "DELETE" }),
    testDlpPolicy: (id: string, text: string) =>
      request<DlpPolicyTestResult>(`/leakage/policies/${id}/test`, {
        method: "POST",
        body: JSON.stringify({ text }),
      }),
    runDlpScan: (body: DlpScanPayload) =>
      request<DlpScanResponse>("/leakage/dlp/scan", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listDlpFindings: (params: DlpFindingListParams) =>
      request<DlpFindingResponse[]>(`/leakage/dlp${_qs(params)}`),
    transitionDlpFinding: (
      id: string,
      body: { state: string; reason?: string },
    ) =>
      request<DlpFindingResponse>(`/leakage/dlp/${id}/state`, {
        method: "POST",
        body: JSON.stringify({ to_state: body.state, reason: body.reason }),
      }),
    draftTakedownDlp: (id: string) =>
      request<TakedownDraftResponse>(`/leakage/dlp/${id}/draft-takedown`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
    draftTakedownCard: (id: string) =>
      request<TakedownDraftResponse>(`/leakage/cards/${id}/draft-takedown`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
    findingAgentSummary: (id: string, kind?: "dlp" | "card") =>
      request<AgentSummaryResponse>(
        `/leakage/findings/${id}/agent-summary${
          kind ? `?kind=${kind}` : ""
        }`,
      ),
    runPolicyTune: (organizationId: string) =>
      request<PolicyTuneResponse>("/leakage/policies/tune", {
        method: "POST",
        body: JSON.stringify({ organization_id: organizationId }),
      }),
    importBins: (organizationId: string | undefined, file: File) => {
      const fd = new FormData();
      if (organizationId) fd.append("organization_id", organizationId);
      fd.append("file", file);
      return requestMultipart<BinImportResponse>(
        "/leakage/bins/import",
        fd,
      );
    },
  },

  notifications: {
    listAdapters: () => request<NotificationAdapterInfo[]>("/notifications/adapters"),
    listChannels: (organizationId: string) =>
      request<NotificationChannelResponse[]>(
        `/notifications/channels?organization_id=${organizationId}`
      ),
    getChannel: (id: string) =>
      request<NotificationChannelResponse>(`/notifications/channels/${id}`),
    createChannel: (body: NotificationChannelCreatePayload) =>
      request<NotificationChannelResponse>("/notifications/channels", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateChannel: (id: string, body: NotificationChannelUpdatePayload) =>
      request<NotificationChannelResponse>(`/notifications/channels/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    deleteChannel: (id: string) =>
      request<void>(`/notifications/channels/${id}`, { method: "DELETE" }),
    testChannel: (id: string) =>
      request<NotificationDeliveryResponse>(
        `/notifications/channels/${id}/test`,
        { method: "POST" }
      ),
    listRules: (organizationId: string) =>
      request<NotificationRuleResponse[]>(
        `/notifications/rules?organization_id=${organizationId}`
      ),
    createRule: (body: NotificationRuleCreatePayload) =>
      request<NotificationRuleResponse>("/notifications/rules", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateRule: (id: string, body: NotificationRuleUpdatePayload) =>
      request<NotificationRuleResponse>(`/notifications/rules/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    deleteRule: (id: string) =>
      request<void>(`/notifications/rules/${id}`, { method: "DELETE" }),
    listDeliveries: (params: NotificationDeliveryListParams) =>
      requestPaginated<NotificationDeliveryResponse[]>(
        `/notifications/deliveries${_qs(params)}`
      ),
    listInbox: (params?: { unread_only?: boolean; include_archived?: boolean; limit?: number }) =>
      request<NotificationInboxItemResponse[]>(
        `/notifications/inbox${_qs(params || {})}`,
      ),
    inboxUnreadCount: () => request<{ unread: number }>("/notifications/inbox/unread-count"),
    markInboxRead: (id: string, unread = false) =>
      request<NotificationInboxItemResponse>(
        `/notifications/inbox/${id}/read${unread ? "?unread=true" : ""}`,
        { method: "POST" },
      ),
    markAllInboxRead: () =>
      request<{ updated: number }>("/notifications/inbox/read-all", { method: "POST" }),
    archiveInbox: (id: string, unarchive = false) =>
      request<NotificationInboxItemResponse>(
        `/notifications/inbox/${id}/archive${unarchive ? "?unarchive=true" : ""}`,
        { method: "POST" },
      ),
    getMyPreferences: () =>
      request<NotificationPreferences>("/notifications/preferences/me"),
    putMyPreferences: (body: NotificationPreferences) =>
      request<NotificationPreferences>("/notifications/preferences/me", {
        method: "PUT",
        body: JSON.stringify(body),
      }),
    dispatch: (body: {
      organization_id: string;
      kind: string;
      severity: string;
      title: string;
      summary: string;
      dedup_key?: string;
      tags?: string[];
      extra?: Record<string, unknown>;
      dry_run?: boolean;
    }) =>
      request<NotificationDeliveryResponse[]>("/notifications/dispatch", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },

  intel: {
    syncNvd: (source?: string) =>
      request<IntelSyncResponse>("/intel/sync/nvd", {
        method: "POST",
        body: JSON.stringify({ source: source || null }),
      }),
    syncEpss: (source?: string) =>
      request<IntelSyncResponse>("/intel/sync/epss", {
        method: "POST",
        body: JSON.stringify({ source: source || null }),
      }),
    syncKev: (source?: string) =>
      request<IntelSyncResponse>("/intel/sync/kev", {
        method: "POST",
        body: JSON.stringify({ source: source || null }),
      }),
    listSyncs: (limit?: number) =>
      request<IntelSyncRow[]>(`/intel/syncs${_qs({ limit })}`),
    getCve: (cveId: string) => request<CveResponse>(`/intel/cves/${cveId}`),
    listCves: (params: CveListParams) =>
      request<CveResponse[]>(`/intel/cves${_qs(params)}`),
    listActorPlaybooks: () =>
      request<ActorPlaybookResponse[]>("/intel/actor-playbooks"),
  },

  news: {
    listFeeds: (organizationId?: string) =>
      request<NewsFeedResponse[]>(
        `/news/feeds${_qs({ organization_id: organizationId })}`,
      ),
    createFeed: (body: NewsFeedCreatePayload) =>
      request<NewsFeedResponse>("/news/feeds", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listArticles: (params: NewsArticleListParams) =>
      request<NewsArticleResponse[]>(`/news/articles${_qs(params)}`),
    getArticle: (id: string) =>
      request<NewsArticleResponse>(`/news/articles/${id}`),
    listAdvisories: (params: {
      organization_id?: string;
      severity?: string;
      state?: string;
      limit?: number;
    }) => request<AdvisoryResponse[]>(`/news/advisories${_qs(params)}`),
    getAdvisory: (id: string) =>
      request<AdvisoryResponse>(`/news/advisories/${id}`),
    createAdvisory: (body: AdvisoryCreatePayload) =>
      request<AdvisoryResponse>("/news/advisories", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateAdvisory: (id: string, body: AdvisoryUpdatePayload) =>
      request<AdvisoryResponse>(`/news/advisories/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    publishAdvisory: (id: string) =>
      request<AdvisoryResponse>(`/news/advisories/${id}/publish`, {
        method: "POST",
      }),
    revokeAdvisory: (id: string, reason: string) =>
      request<AdvisoryResponse>(`/news/advisories/${id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      }),
    ingestCisaKev: () =>
      request<{ inserted: number; updated: number; total: number }>(
        "/news/advisories/ingest/cisa-kev",
        { method: "POST" },
      ),
    triageAdvisory: (id: string, triage_state: string, assigned_to_user_id?: string) =>
      request<AdvisoryResponse>(`/news/advisories/${id}/triage`, {
        method: "POST",
        body: JSON.stringify({ triage_state, assigned_to_user_id }),
      }),
    listAdvisoryComments: (id: string) =>
      request<{ id: string; body: string; author_user_id: string | null; created_at: string }[]>(
        `/news/advisories/${id}/comments`,
      ),
    addAdvisoryComment: (id: string, body: string) =>
      request<{ id: string; body: string; created_at: string }>(
        `/news/advisories/${id}/comments`,
        { method: "POST", body: JSON.stringify({ body }) },
      ),
    listSubscriptions: (organizationId: string) =>
      request<{
        id: string;
        organization_id: string;
        user_id: string | null;
        name: string;
        severity_threshold: string;
        kev_only: boolean;
        sources: string[];
        keyword_filters: string[];
        active: boolean;
      }[]>(`/news/advisories/subscriptions?organization_id=${organizationId}`),
    createSubscription: (body: {
      organization_id: string;
      name: string;
      severity_threshold?: string;
      kev_only?: boolean;
      sources?: string[];
      keyword_filters?: string[];
      active?: boolean;
    }) =>
      request<Record<string, unknown>>("/news/advisories/subscriptions", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deleteSubscription: (id: string) =>
      request<void>(`/news/advisories/subscriptions/${id}`, { method: "DELETE" }),
    affectedAssets: (advisoryId: string, organizationId: string) =>
      request<{ id: string; cve_ids: string[]; severity: string | null; asset_value: string | null; title: string | null }[]>(
        `/news/advisories/${advisoryId}/affected?organization_id=${organizationId}`,
      ),
    seedFeedCatalog: () =>
      request<{ inserted: number; updated: number; total: number }>("/news/feeds/seed-catalog", { method: "POST" }),
    syncAllFeeds: (opts?: { only_due?: boolean; max_feeds?: number; process_bodies?: boolean }) => {
      const qs = new URLSearchParams();
      if (opts?.only_due !== undefined) qs.set("only_due", String(opts.only_due));
      if (opts?.max_feeds) qs.set("max_feeds", String(opts.max_feeds));
      if (opts?.process_bodies !== undefined) qs.set("process_bodies", String(opts.process_bodies));
      return request<{ feeds: number; parsed: number; new: number; dup: number; iocs: number; techniques: number; errors: number }>(
        `/news/feeds/sync-all?${qs.toString()}`,
        { method: "POST" },
      );
    },
  },

  mitre: {
    sync: (matrix: "enterprise" | "mobile" | "ics" = "enterprise") =>
      request<MitreSyncReport>("/mitre/sync", {
        method: "POST",
        body: JSON.stringify({ matrix }),
      }),
    listSyncs: () => request<MitreSyncRow[]>("/mitre/syncs"),
    listTactics: () => request<MitreTacticResponse[]>("/mitre/tactics"),
    listTechniques: (params?: {
      tactic?: string;
      matrix?: string;
      include_subtechniques?: boolean;
      q?: string;
      limit?: number;
    }) =>
      request<MitreTechniqueResponse[]>(`/mitre/techniques${_qs(params)}`),
    getTechnique: (externalId: string) =>
      request<MitreTechniqueResponse>(`/mitre/techniques/${externalId}`),
    listMitigations: () =>
      request<MitreMitigationResponse[]>("/mitre/mitigations"),
    listGroups: (params?: { matrix?: string; sector?: string; country?: string; q?: string; limit?: number }) =>
      request<{
        id: string;
        matrix: string;
        external_id: string;
        name: string;
        aliases: string[];
        description: string | null;
        country_codes: string[];
        sectors_targeted: string[];
        regions_targeted: string[];
        references: { source_name?: string; url: string; description?: string }[];
        url: string | null;
      }[]>(`/mitre/groups${_qs(params)}`),
    getGroup: (externalId: string) =>
      request<{
        group: Record<string, unknown>;
        techniques: string[];
        software: string[];
        campaigns: string[];
      }>(`/mitre/groups/${externalId}`),
    listSoftware: (params?: { matrix?: string; software_type?: "malware" | "tool"; q?: string; limit?: number }) =>
      request<{
        id: string;
        matrix: string;
        external_id: string;
        name: string;
        aliases: string[];
        software_type: string;
        description: string | null;
        platforms: string[];
        references: { source_name?: string; url: string }[];
        url: string | null;
      }[]>(`/mitre/software${_qs(params)}`),
    listDataSources: (params?: { matrix?: string }) =>
      request<{
        id: string;
        matrix: string;
        external_id: string;
        name: string;
        description: string | null;
        platforms: string[];
        collection_layers: string[];
        data_components: { name: string; description: string }[];
        url: string | null;
      }[]>(`/mitre/data-sources${_qs(params)}`),
    listCampaigns: (params?: { matrix?: string }) =>
      request<{
        id: string;
        matrix: string;
        external_id: string;
        name: string;
        aliases: string[];
        description: string | null;
        first_seen: string | null;
        last_seen: string | null;
        url: string | null;
      }[]>(`/mitre/campaigns${_qs(params)}`),
    techniqueGroups: (externalId: string, matrix?: string) =>
      request<{
        id: string;
        external_id: string;
        name: string;
        aliases: string[];
        description: string | null;
        country_codes: string[];
      }[]>(`/mitre/techniques/${externalId}/groups${matrix ? `?matrix=${matrix}` : ""}`),
    importActorsFromGroups: (organizationId: string) =>
      request<{ written: number }>(`/mitre/import-actors?organization_id=${organizationId}`, {
        method: "POST",
      }),
    listLayers: (organizationId: string) =>
      request<{
        id: string;
        organization_id: string;
        name: string;
        description: string | null;
        matrix: string;
        technique_scores: Record<string, number>;
        color_palette: Record<string, string>;
        created_at: string;
        updated_at: string;
      }[]>(`/mitre/layers?organization_id=${organizationId}`),
    createLayer: (body: {
      organization_id: string;
      name: string;
      description?: string;
      matrix?: string;
      technique_scores: Record<string, number>;
    }) =>
      request<Record<string, unknown>>("/mitre/layers", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateLayer: (
      id: string,
      body: {
        organization_id: string;
        name: string;
        description?: string;
        matrix?: string;
        technique_scores: Record<string, number>;
      },
    ) =>
      request<Record<string, unknown>>(`/mitre/layers/${id}`, {
        method: "PUT",
        body: JSON.stringify(body),
      }),
    deleteLayer: (id: string) =>
      request<void>(`/mitre/layers/${id}`, { method: "DELETE" }),
    exportNavigatorJson: (id: string) =>
      request<Record<string, unknown>>(`/mitre/layers/${id}/navigator`),
    listCoverage: (organizationId: string, matrix?: string) =>
      request<{
        id: string;
        matrix: string;
        technique_external_id: string;
        score: number;
        covered_by: string[];
        notes: string | null;
        updated_at: string;
      }[]>(`/mitre/coverage?organization_id=${organizationId}${matrix ? `&matrix=${matrix}` : ""}`),
    bulkUpsertCoverage: (body: {
      organization_id: string;
      matrix?: string;
      entries: { technique_external_id: string; score: number; covered_by: string[]; notes?: string }[];
    }) =>
      request<{ upserted: number }>("/mitre/coverage/bulk", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },

  ratings: {
    getRubric: () => request<SecurityRubric>("/ratings/rubric"),
    recompute: (organizationId: string) =>
      request<SecurityRatingDetail>(
        `/ratings/recompute?organization_id=${organizationId}`,
        { method: "POST" }
      ),
    current: (organizationId: string) =>
      request<SecurityRatingDetail>(
        `/ratings/current?organization_id=${organizationId}`
      ),
    history: (params: { organization_id: string; limit?: number }) =>
      request<SecurityRatingResponse[]>(`/ratings/history${_qs(params)}`),
    get: (id: string) => request<SecurityRatingDetail>(`/ratings/${id}`),
  },

  sla: {
    listPolicies: (organizationId: string) =>
      request<SlaPolicyResponse[]>(
        `/sla/policies?organization_id=${organizationId}`
      ),
    upsertPolicy: (body: SlaPolicyUpsertPayload) =>
      request<SlaPolicyResponse>("/sla/policies", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deletePolicy: (id: string) =>
      request<void>(`/sla/policies/${id}`, { method: "DELETE" }),
    evaluate: (organizationId: string) =>
      request<SlaEvaluateResponse>(
        `/sla/evaluate?organization_id=${organizationId}`,
        { method: "POST" }
      ),
    listBreaches: (params: { organization_id: string; case_id?: string; limit?: number }) =>
      request<SlaBreachResponse[]>(`/sla/breaches${_qs(params)}`),
    listTickets: (params: { organization_id: string; case_id?: string; limit?: number }) =>
      request<SlaTicketBindingResponse[]>(`/sla/tickets${_qs(params)}`),
    bindTicket: (body: SlaTicketBindingCreatePayload) =>
      request<SlaTicketBindingResponse>("/sla/tickets", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    unbindTicket: (id: string) =>
      request<void>(`/sla/tickets/${id}`, { method: "DELETE" }),
  },

  feedback: {
    submit: (body: FeedbackCreatePayload) =>
      request<FeedbackResponse>("/feedback/", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    list: (params: { alert_id?: string; is_true_positive?: boolean; limit?: number }) =>
      request<FeedbackResponse[]>(`/feedback/${_qs(params)}`),
    stats: () => request<FeedbackStats>("/feedback/stats"),
  },

  evidence: {
    list: (params: EvidenceListParams) =>
      request<EvidenceBlobResponse[]>(`/evidence${_qs(params)}`),
    get: (id: string) => request<EvidenceBlobResponse>(`/evidence/${id}`),
    upload: (
      organizationId: string,
      file: File,
      opts?: {
        kind?: string;
        description?: string;
        capture_source?: string;
      },
    ) => {
      const fd = new FormData();
      fd.append("organization_id", organizationId);
      if (opts?.kind) fd.append("kind", opts.kind);
      if (opts?.description) fd.append("description", opts.description);
      if (opts?.capture_source) fd.append("capture_source", opts.capture_source);
      fd.append("file", file);
      return requestMultipart<EvidenceBlobResponse>("/evidence/upload", fd);
    },
    download: (id: string) =>
      request<{ url: string; ttl_seconds: number; sha256: string }>(
        `/evidence/${id}/download`,
      ),
    inlineUrl: (id: string): string => `${API_BASE}/evidence/${id}/inline`,
    delete: (id: string, reason?: string) =>
      request<EvidenceBlobResponse>(
        `/evidence/${id}${_qs({ reason })}`,
        { method: "DELETE" },
      ),
    restore: (id: string) =>
      request<EvidenceBlobResponse>(`/evidence/${id}/restore`, {
        method: "POST",
      }),
    auditChain: (id: string) =>
      request<EvidenceAuditChainEntry[]>(`/evidence/${id}/audit-chain`),
    verifyChain: (organizationId: string) =>
      request<EvidenceAuditChainVerify>(
        `/evidence/audit-chain/verify${_qs({ organization_id: organizationId })}`,
      ),
    narrateCoc: (id: string, refresh: boolean = false) =>
      request<EvidenceCoCNarrative>(
        `/evidence/${id}/narrate-coc${_qs({ refresh: refresh ? "true" : undefined })}`,
        { method: "POST" },
      ),
    similar: (id: string, limit: number = 10) =>
      request<EvidenceSimilarResponse>(
        `/evidence/${id}/similar${_qs({ limit })}`,
      ),
  },

  retention: {
    listPolicies: () =>
      request<RetentionPolicyResponse[]>("/retention/"),
    createPolicy: (body: RetentionPolicyCreatePayload) =>
      request<RetentionPolicyResponse>("/retention/", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updatePolicy: (id: string, body: RetentionPolicyUpdatePayload) =>
      request<RetentionPolicyResponse>(`/retention/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    deletePolicy: (id: string) =>
      request<void>(`/retention/${id}`, { method: "DELETE" }),
    runCleanup: (dryRun: boolean = false) =>
      request<RetentionCleanupResult[]>(
        `/retention/cleanup?dry_run=${dryRun ? "true" : "false"}`,
        { method: "POST" },
      ),
    stats: () => request<RetentionStats>("/retention/stats"),
    setLegalHold: (body: LegalHoldPayload) =>
      request<void>("/retention/legal-hold", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listFrameworks: () =>
      request<RetentionComplianceFramework[]>(
        "/retention/compliance-frameworks",
      ),
    translateRegulation: (body: {
      regulation_text: string;
      organization_id?: string;
    }) =>
      request<RetentionRegulationSuggestion>(
        "/retention/translate-regulation",
        { method: "POST", body: JSON.stringify(body) },
      ),
    listDsar: (params?: {
      organization_id?: string;
      status?: string;
      limit?: number;
    }) =>
      request<DsarRequestResponse[]>(`/retention/dsar${_qs(params || {})}`),
    getDsar: (id: string) =>
      request<DsarRequestResponse>(`/retention/dsar/${id}`),
    createDsar: (body: DsarCreatePayload) =>
      request<DsarRequestResponse>("/retention/dsar", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    scanDsar: (id: string) =>
      request<DsarRequestResponse>(`/retention/dsar/${id}/scan`, {
        method: "POST",
      }),
    draftDsarResponse: (id: string) =>
      request<DsarRequestResponse>(`/retention/dsar/${id}/draft-response`, {
        method: "POST",
      }),
    updateDsarDraft: (id: string, draft: string) =>
      request<DsarRequestResponse>(`/retention/dsar/${id}/draft`, {
        method: "PATCH",
        body: JSON.stringify({ draft_response: draft }),
      }),
    closeDsar: (
      id: string,
      body: { closed_reason: string; final_response?: string },
    ) =>
      request<DsarRequestResponse>(`/retention/dsar/${id}/close`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    generateAttestation: (params?: {
      organization_id?: string;
      period_days?: number;
    }) =>
      request<{
        queued: boolean;
        task_id: string;
        status: string;
        period_days: number;
      }>(`/retention/attestation${_qs(params || {})}`, { method: "POST" }),
    listAttestations: (params?: {
      organization_id?: string;
      limit?: number;
    }) =>
      request<RetentionAttestationResponse[]>(
        `/retention/attestations${_qs(params || {})}`,
      ),
  },

  social: {
    listVips: (organizationId: string) =>
      request<VipResponse[]>(`/social/vips?organization_id=${organizationId}`),
    createVip: (body: VipCreatePayload) =>
      request<VipResponse>("/social/vips", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    listAccounts: (organizationId: string) =>
      request<SocialAccountResponse[]>(
        `/social/accounts?organization_id=${organizationId}`
      ),
    listImpersonations: (params: ImpersonationListParams) =>
      requestPaginated<ImpersonationFindingResponse[]>(
        `/social/impersonations${_qs(params)}`
      ),
    listMobileApps: (params: MobileAppListParams) =>
      requestPaginated<MobileAppFindingResponse[]>(
        `/social/mobile-apps${_qs(params)}`
      ),
    listFraud: (params: FraudListParams) =>
      requestPaginated<FraudFindingResponse[]>(`/social/fraud${_qs(params)}`),
  },

  audit: {
    soc2Bundle: (params: { organization_id: string; window_days?: number }) =>
      requestBlob(`/audit/export/soc2-bundle${_qs(params)}`),
  },

  dmarc: {
    listReports: (params: {
      organization_id: string;
      domain?: string;
      limit?: number;
    }) => request<DmarcReportResponse[]>(`/dmarc/reports${_qs(params)}`),
    getReport: (id: string) =>
      request<DmarcReportResponse>(`/dmarc/reports/${id}`),
    listRecords: (id: string) =>
      request<DmarcRecordResponse[]>(`/dmarc/reports/${id}/records`),
    listForensic: (params: {
      organization_id: string;
      domain?: string;
      limit?: number;
    }) =>
      request<DmarcForensicResponse[]>(`/dmarc/forensic${_qs(params)}`),
    getForensic: (id: string) =>
      request<DmarcForensicResponse>(`/dmarc/forensic/${id}`),
    runWizard: (
      domain: string,
      body: {
        sending_ips?: string[];
        sending_includes?: string[];
        dkim_selectors?: string[];
        rua_endpoint?: string;
        ruf_endpoint?: string;
      },
    ) =>
      request<DmarcWizardResponse>(`/dmarc/wizard/${domain}`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    dnsCheck: (domain: string) =>
      request<DmarcDnsCheckResponse>(
        `/dmarc/check?domain=${encodeURIComponent(domain)}`,
      ),
    posture: (orgId: string) =>
      request<DmarcPostureEntry[]>(`/dmarc/posture/${orgId}`),
    trends: (
      domain: string,
      params: { organization_id: string; days?: number },
    ) =>
      request<DmarcTrendPoint[]>(
        `/dmarc/trends/${encodeURIComponent(domain)}${_qs(params)}`,
      ),
    planRollout: (params: { organization_id: string; domain: string }) =>
      request<DmarcPlanRolloutResponse>(`/dmarc/plan-rollout${_qs(params)}`, {
        method: "POST",
      }),
    listMailboxConfigs: (organization_id?: string) =>
      request<DmarcMailboxConfigResponse[]>(
        `/dmarc/mailbox-config${organization_id ? `?organization_id=${organization_id}` : ""}`,
      ),
    upsertMailboxConfig: (body: DmarcMailboxConfigCreate) =>
      request<DmarcMailboxConfigResponse>(`/dmarc/mailbox-config`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    deleteMailboxConfig: (id: string) =>
      request<void>(`/dmarc/mailbox-config/${id}`, { method: "DELETE" }),
  },

  /* ─────────────────── Admin runtime configuration ─────────────────── */
  // Talks to /api/v1/admin/* — the four operator-tunable runtime tables:
  // app_settings, crawler_targets, feed_health, subsidiary_allowlist.
  admin: {
    listSettings: (category?: string) =>
      request<AppSettingResponse[]>(
        category
          ? `/admin/settings?category=${encodeURIComponent(category)}`
          : "/admin/settings",
      ),
    upsertSetting: (key: string, body: AppSettingUpsert) =>
      request<AppSettingResponse>(`/admin/settings/${encodeURIComponent(key)}`, {
        method: "PUT",
        body: JSON.stringify({ ...body, key }),
      }),
    deleteSetting: (key: string) =>
      request<{ deleted: boolean; key: string }>(
        `/admin/settings/${encodeURIComponent(key)}`,
        { method: "DELETE" },
      ),

    listCrawlerTargets: (params?: { kind?: string; is_active?: boolean }) => {
      const q = new URLSearchParams();
      if (params?.kind) q.set("kind", params.kind);
      if (params?.is_active !== undefined)
        q.set("is_active", String(params.is_active));
      const qs = q.toString();
      return request<CrawlerTargetResponse[]>(
        `/admin/crawler-targets${qs ? `?${qs}` : ""}`,
      );
    },
    createCrawlerTarget: (body: CrawlerTargetCreate) =>
      request<CrawlerTargetResponse>("/admin/crawler-targets", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    updateCrawlerTarget: (id: string, body: CrawlerTargetUpdate) =>
      request<CrawlerTargetResponse>(`/admin/crawler-targets/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    deleteCrawlerTarget: (id: string) =>
      request<{ deleted: boolean; id: string }>(
        `/admin/crawler-targets/${id}`,
        { method: "DELETE" },
      ),

    listFeedHealth: () =>
      request<FeedHealthEntry[]>("/admin/feed-health"),

    platformReadiness: () =>
      request<PlatformReadinessResponse>("/admin/platform-readiness"),

    listIntegrations: () =>
      request<IntegrationDef[]>("/admin/integrations"),

    serviceInventory: () =>
      request<ServiceInventoryResponse>("/admin/service-inventory"),

    servicesForPage: (pageKey: string) =>
      request<ServicesForPageResponse>(
        `/admin/service-inventory/page/${encodeURIComponent(pageKey)}`,
      ),
    serviceCoverage: () =>
      request<ServiceCoverageResponse>("/admin/service-coverage"),
    feedHealthHistory: (feedName: string, limit = 100) =>
      request<FeedHealthEntry[]>(
        `/admin/feed-health/${encodeURIComponent(feedName)}?limit=${limit}`,
      ),

    listAllowlist: (kind?: string) =>
      request<AllowlistEntry[]>(
        kind
          ? `/admin/subsidiary-allowlist?kind=${encodeURIComponent(kind)}`
          : "/admin/subsidiary-allowlist",
      ),
    addAllowlistEntry: (body: AllowlistCreate) =>
      request<AllowlistEntry>("/admin/subsidiary-allowlist", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    removeAllowlistEntry: (id: string) =>
      request<{ deleted: boolean; id: string }>(
        `/admin/subsidiary-allowlist/${id}`,
        { method: "DELETE" },
      ),
  },

  // Compliance Evidence Pack (P1 #1.3)
  compliance: {
    listFrameworks: () =>
      request<ComplianceFrameworkSummary[]>("/compliance/frameworks"),
    createExport: (req: ComplianceExportRequest) =>
      request<ComplianceExportResponse>("/compliance/exports", {
        method: "POST",
        body: JSON.stringify(req),
      }),
    listExports: (params?: { framework_code?: string; limit?: number }) => {
      const qs = new URLSearchParams();
      if (params?.framework_code) qs.set("framework_code", params.framework_code);
      if (params?.limit) qs.set("limit", String(params.limit));
      const tail = qs.toString() ? `?${qs.toString()}` : "";
      return request<ComplianceExportResponse[]>(`/compliance/exports${tail}`);
    },
    getExport: (id: string) =>
      request<ComplianceExportResponse>(`/compliance/exports/${id}`),
    downloadExportUrl: (id: string) =>
      `${API_BASE}/compliance/exports/${id}/download`,
  },
};

/* ─────────────────── Admin types ─────────────────── */

export type AppSettingValueType = "string" | "integer" | "float" | "boolean" | "json";
export type AppSettingCategory =
  | "fraud" | "impersonation" | "brand" | "rating" | "auto_case" | "crawler" | "general" | "integrations";

export interface AppSettingResponse {
  id: string;
  key: string;
  category: AppSettingCategory;
  value_type: AppSettingValueType;
  value: unknown;
  description: string | null;
  minimum: number | null;
  maximum: number | null;
  updated_at: string;
}

export interface AppSettingUpsert {
  key: string;
  category: AppSettingCategory;
  value_type: AppSettingValueType;
  value: unknown;
  description?: string | null;
  minimum?: number | null;
  maximum?: number | null;
}

export type CrawlerKind =
  | "tor_forum" | "tor_marketplace" | "i2p_eepsite" | "lokinet_site"
  | "telegram_channel" | "matrix_room" | "forum"
  | "ransomware_leak_group" | "stealer_marketplace"
  // Generic operator-configured poller (RSS / JSON / HTML-CSS).
  // No new Python class needed; configuration lives in the
  // CrawlerTarget.config JSON.
  | "custom_http";

export interface CrawlerTargetResponse {
  id: string;
  kind: CrawlerKind;
  identifier: string;
  display_name: string | null;
  config: Record<string, unknown>;
  is_active: boolean;
  last_run_at: string | null;
  last_run_status: string | null;
  last_run_summary: Record<string, unknown> | null;
  consecutive_failures: number;
  updated_at: string;
}

export interface CrawlerTargetCreate {
  kind: CrawlerKind;
  identifier: string;
  display_name?: string;
  config?: Record<string, unknown>;
  is_active?: boolean;
}

export interface CrawlerTargetUpdate {
  display_name?: string | null;
  config?: Record<string, unknown> | null;
  is_active?: boolean | null;
}

export type FeedHealthStatus =
  | "ok" | "unconfigured" | "auth_error" | "network_error"
  | "rate_limited" | "parse_error" | "disabled";

export interface ServiceKeyField {
  key: string;
  env_var: string;
  label: string;
  source: "db" | "env" | "unset";
  masked_value: string | null;
}

// 3-state taxonomy — every row in Settings → Services lands in one
// of these. Engineering sub-reasons (auth_failed, schema_changed,
// daemon_not_detected, ...) live in `sub_reason` and surface in the
// evidence line, never as a separate pill.
export type ServiceStatusValue = "ok" | "needs_key" | "not_installed";

export interface ServiceInventoryEntry {
  name: string;
  category: string;
  description: string;
  requires: string[];
  produces: string[];
  produces_pages: string[];
  key_fields: ServiceKeyField[];
  no_oss_substitute: boolean;
  legacy_only: boolean;
  self_hosted: boolean;
  self_host_install_hint: string | null;
  // When set, this self-hosted entry can be installed via the
  // /oss-tools/install endpoint. The merged Services tab uses this
  // to render an inline Install button driven by ossStates.
  oss_install_name: string | null;
  source_file: string;
  docs_url: string | null;
  status: ServiceStatusValue;
  sub_reason: string | null;
  evidence: string;
  last_observed_at: string | null;
  last_rows_ingested: number | null;
}

export interface ServiceInventoryResponse {
  categories: string[];
  services: ServiceInventoryEntry[];
  summary: Record<string, number>;
  total: number;
}

// Coverage map — drives UI auto-hide. The dashboard sidebar and any
// page that depends on a single data type checks `pages[<slug>]` to
// decide whether to render. Reactive: as soon as the operator pastes
// a key in Settings → Services, the corresponding entries flip true
// and surfaces appear on the next refresh.
export interface ServiceCoverageResponse {
  pages: Record<string, boolean>;
  categories: Record<string, boolean>;
  ok_count: number;
  total: number;
}

export interface ServicesForPageResponse {
  page_key: string;
  services: ServiceInventoryEntry[];
  summary: Record<string, number>;
  total: number;
}

export interface IntegrationField {
  key: string;
  env_var: string;
  label: string;
  type: "password" | "text";
  source: "db" | "env" | "unset";
  masked_value: string | null;
}

export interface IntegrationDef {
  name: string;
  label: string;
  purpose: string;
  cost_note: string | null;
  help_url: string | null;
  fields: IntegrationField[];
  is_configured: boolean;
}

export interface PlatformReadinessItem {
  severity: "blocker" | "warning" | "info";
  category: string;
  title: string;
  detail: string;
  href: string | null;
}

export interface PlatformReadinessCategory {
  key: string;
  label: string;
  score: number;
  summary: string;
  items: PlatformReadinessItem[];
}

export interface PlatformReadinessResponse {
  overall_score: number;
  categories: PlatformReadinessCategory[];
  blockers: PlatformReadinessItem[];
  generated_at: string;
}

export interface FeedHealthEntry {
  id: string;
  feed_name: string;
  status: FeedHealthStatus;
  detail: string | null;
  rows_ingested: number;
  duration_ms: number | null;
  observed_at: string;
}

export type AllowlistKind = "domain" | "brand_name" | "email_domain";

export interface AllowlistEntry {
  id: string;
  kind: AllowlistKind;
  value: string;
  note: string | null;
  created_at: string;
}

export interface AllowlistCreate {
  kind: AllowlistKind;
  value: string;
  note?: string;
}

export interface DmarcReportResponse {
  id: string;
  organization_id: string;
  asset_id: string | null;
  kind: string;
  domain: string;
  org_name: string | null;
  report_id: string;
  date_begin: string;
  date_end: string;
  policy_p: string | null;
  policy_pct: number | null;
  total_messages: number;
  pass_count: number;
  fail_count: number;
  quarantine_count: number;
  reject_count: number;
  parsed: Record<string, unknown>;
  posture_score: Record<string, unknown> | null;
  rca: Record<string, unknown> | null;
  agent_summary: Record<string, unknown> | null;
  raw_xml_sha256: string | null;
  created_at: string;
  updated_at: string;
}

export interface DmarcRecordResponse {
  id: string;
  report_id: string;
  domain: string;
  source_ip: string;
  count: number;
  disposition: string | null;
  spf_result: string | null;
  dkim_result: string | null;
  spf_aligned: boolean | null;
  dkim_aligned: boolean | null;
  header_from: string | null;
  envelope_from: string | null;
}

export interface DmarcWizardResponse {
  domain: string;
  spf_record: string;
  dkim_records: Array<Record<string, string>>;
  dmarc_records_progression: Array<Record<string, string>>;
  rua_endpoint: string;
  ruf_endpoint: string | null;
  rationale: string;
}

export interface DmarcForensicResponse {
  id: string;
  organization_id: string;
  domain: string;
  feedback_type: string | null;
  arrival_date: string | null;
  source_ip: string | null;
  reported_domain: string | null;
  original_envelope_from: string | null;
  original_envelope_to: string | null;
  original_mail_from: string | null;
  original_rcpt_to: string | null;
  auth_failure: string | null;
  delivery_result: string | null;
  dkim_domain: string | null;
  dkim_selector: string | null;
  spf_domain: string | null;
  raw_headers: string | null;
  extras: Record<string, unknown>;
  agent_summary: Record<string, unknown> | null;
  received_at: string;
}

export interface DmarcDnsCheckResponse {
  domain: string;
  record_present: boolean;
  raw_record: string | null;
  parsed_tags: Record<string, string>;
  warnings: string[];
  bimi_present: boolean;
  mta_sts_present: boolean;
  tls_rpt_present: boolean;
  age_unknown_or_seconds: number | null;
  recommendations: string[];
}

export interface DmarcPostureEntry {
  domain: string;
  score: number;
  components: Record<string, number | string>;
  computed_at: string;
}

export interface DmarcTrendPoint {
  day: string;
  total: number;
  passed: number;
  pass_pct: number;
}

export interface DmarcPlanRolloutResponse {
  task_id: string;
  status: string;
  markdown: string | null;
  alignment_pct: number | null;
  current_policy: string | null;
  ruf_count: number | null;
}

export interface DmarcMailboxConfigResponse {
  id: string;
  organization_id: string;
  host: string;
  port: number;
  username: string;
  folder: string;
  enabled: boolean;
  last_seen_uid: number | null;
  last_polled_at: string | null;
  last_error: string | null;
}

export interface DmarcMailboxConfigCreate {
  organization_id: string;
  host: string;
  port?: number;
  username: string;
  password: string;
  folder?: string;
  enabled?: boolean;
}

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
  is_allowlisted?: boolean;
  allowlist_reason?: string | null;
  expires_at?: string | null;
  confidence_half_life_days?: number;
  enrichment_data?: Record<string, unknown>;
  enrichment_fetched_at?: string | null;
  source_feed?: string | null;
  created_at: string;
  updated_at: string;
}

export interface IOCParams {
  ioc_type?: string;
  min_confidence?: number;
  search?: string;
  limit?: number;
  offset?: number;
  source_alert_id?: string;
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
  mitre_group_id?: string | null;
  country_codes?: string[];
  sectors_targeted?: string[];
  regions_targeted?: string[];
  malware_families?: string[];
  references?: { source_name?: string; url: string; description?: string; external_id?: string }[];
  confidence?: number;
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
  // tech_stack is a JSONB column; in practice every category maps
  // to a list of vendor/product strings (see
  // src/core/industry_defaults.py). Other shapes are tolerated by
  // the backend but the dashboard only edits the string-list shape.
  tech_stack: Record<string, string[]> | null;
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
  /** Analyst override — write the canonical wire string (e.g.
   *  "exploit") for category and ("high"/"critical"/...) for
   *  severity. Backend validates against the live enums and 422s
   *  unknown values. ``override_reason`` is required server-side
   *  whenever severity or category is set. */
  severity?: string;
  category?: string;
  override_reason?: string;
}

export interface AttributionFactor {
  name: string;
  weight: number;
  raw: number;
  contribution: number;
  detail: string | null;
}

export interface AttributionScore {
  actor_id: string;
  primary_alias: string;
  aliases: string[];
  confidence: number;
  factors: AttributionFactor[];
}

export interface AlertAttributionResponse {
  scores: AttributionScore[];
}

export interface RelatedCase {
  id: string;
  title: string;
  state: string;
  severity: string;
  is_primary: boolean;
  linked_at: string;
}

export interface RelatedTakedown {
  id: string;
  state: string;
  partner: string;
  target_kind: string;
  target_identifier: string;
  submitted_at: string;
}

export interface RelatedSighting {
  id: string;
  threat_actor_id: string;
  actor_alias: string;
  source_platform: string;
  alias_used: string;
  seen_at: string;
}

/** Triage confidence thresholds for the alert's org. Drives the
 *  confidence-bar tier colours so the bar reflects the org's actual
 *  configured cutoffs (org.settings.confidence_threshold) instead of
 *  hardcoded magic numbers. */
export interface AlertThresholdsResponse {
  needs_review_below: number;
  high_above: number;
}

/** Cross-table linkage for one alert. Drives the "Related" section
 *  on the detail page. Empty arrays mean "nothing linked yet". */
export interface AlertRelationsResponse {
  cases: RelatedCase[];
  takedowns: RelatedTakedown[];
  sightings: RelatedSighting[];
}

/** Provenance for an alert — the raw intel item that produced it.
 *  Returned by GET /alerts/{id}/source. 404s if the alert has no
 *  raw_intel_id (legacy/synthetic) or if the source row was purged. */
export interface AlertSourceResponse {
  raw_intel_id: string;
  source_type: string;
  source_name: string | null;
  source_url: string | null;
  title: string | null;
  author: string | null;
  published_at: string | null;
  collected_at: string;
}

export interface Crawler {
  name: string;
  crawler_name: string;
  interval_seconds: number;
  last_run: string | null;
  // Per-tick result from feed_health: ok / unconfigured /
  // network_error / auth_error / etc. Null when the worker has
  // never recorded a tick for this kind.
  last_status: string | null;
  last_detail: string | null;
  /** Items collected — number of fresh ``RawIntel`` rows persisted
   *  on the most recent tick. Decoupled from alerts_created. */
  last_rows_ingested: number;
  /** Alerts created — number of org-scoped alerts the triage step
   *  emitted on top of those items. May be 0 even when items > 0,
   *  e.g. a Telegram channel pulled 50 messages but none matched
   *  any org's brand terms. */
  last_alerts_created: number;
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

export interface FeedEntryRow {
  id: string;
  entry_type: string;
  value: string;
  label: string | null;
  severity: string;
  confidence: number;
  country_code: string | null;
  asn: string | null;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
}

export interface FeedEntriesResponse {
  feed_name: string;
  layer: string;
  total_returned: number;
  entries: FeedEntryRow[];
}

export interface TypeCount {
  entry_type: string;
  count: number;
}

export interface CountryCount {
  country_code: string;
  count: number;
}

export interface FetchHealthRow {
  status: string;          // ok | unconfigured | auth_error | network_error | rate_limited | parse_error | disabled
  detail: string | null;
  rows_ingested: number;
  duration_ms: number | null;
  observed_at: string;
}

export interface FeedStatsResponse {
  feed_name: string;
  layer: string;
  total_entries: number;
  active_entries: number;
  by_type: TypeCount[];
  by_country: CountryCount[];
  iocs_promoted: number;
  alerts_referencing: number;
  latest_entry_at: string | null;
  last_fetch: FetchHealthRow | null;
  recent_fetches: FetchHealthRow[];
}

export interface FeedInLayer {
  feed_name: string;
  active_entry_count: number;
  total_entry_count: number;
  latest_entry_at: string | null;
  enabled: boolean;
}

export interface LayerSummaryResponse {
  layer: string;
  display_name: string;
  description: string | null;
  color: string;
  icon: string;
  total_entries: number;
  active_entries: number;
  by_severity: TypeCount[];
  by_country: CountryCount[];
  feeds: FeedInLayer[];
  latest_entry_at: string | null;
}

export interface CVEPreview {
  cve_id: string | null;
  title: string | null;
  severity: string | null;
  matched_terms: string[];
}

export interface DashboardExposure {
  org_id: string;
  org_name: string;
  declared_components: number;
  cves_affecting_you: number;
  cves_sample: CVEPreview[];
  open_alerts: number;
  tracked_iocs: number;
}

export interface TriageRunSummary {
  id: string;
  status: string;          // running | completed | error
  trigger: string;         // manual | scheduled | post_feed
  hours_window: number;
  entries_processed: number;
  iocs_created: number;
  alerts_generated: number;
  duration_seconds: number;
  error_message: string | null;
  created_at: string;
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

export interface IntegrationTool {
  tool_name: string;
  display_name: string;
  category: string;
  description: string;
  license: string;
  enabled: boolean;
  health_status: string;
  api_url: string;
  last_sync_at: string | null;
  last_error: string | null;
  sync_interval_seconds: number;
  id: string | null;
}

export interface IntegrationUpdateRequest {
  enabled?: boolean;
  api_url?: string;
  api_key?: string;
  extra_settings?: Record<string, unknown>;
  sync_interval_seconds?: number;
}

export interface TriageRunItem {
  id: string;
  trigger: string;
  hours_window: number;
  entries_processed: number;
  iocs_created: number;
  alerts_generated: number;
  duration_seconds: number;
  status: string;
  error_message: string | null;
  created_at: string;
}

// --- Asset Registry (Phase 0.1) -----------------------------------------

export type AssetTypeName =
  | "domain"
  | "subdomain"
  | "ip_address"
  | "ip_range"
  | "service"
  | "email_domain"
  | "executive"
  | "brand"
  | "mobile_app"
  | "social_handle"
  | "vendor"
  | "code_repository"
  | "cloud_account";

export type AssetCriticalityLevel = "crown_jewel" | "high" | "medium" | "low";

export type DiscoveryMethodName =
  | "manual"
  | "bulk_import"
  | "onboarding_wizard"
  | "easm_discovery"
  | "dns_enumeration"
  | "cert_transparency"
  | "port_scan"
  | "httpx_probe"
  | "agent_discovery"
  | "api_import";

export interface AssetRecord {
  id: string;
  organization_id: string;
  asset_type: AssetTypeName;
  value: string;
  details: Record<string, unknown> | null;
  criticality: AssetCriticalityLevel;
  tags: string[];
  monitoring_profile: Record<string, unknown> | null;
  owner_user_id: string | null;
  parent_asset_id: string | null;
  discovery_method: DiscoveryMethodName;
  discovered_at: string | null;
  verified_at: string | null;
  last_scanned_at: string | null;
  last_change_at: string | null;
  is_active: boolean;
  monitoring_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AssetListParams {
  organization_id: string;
  asset_type?: AssetTypeName;
  criticality?: AssetCriticalityLevel;
  tag?: string;
  is_active?: boolean;
  monitoring_enabled?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface AssetCounts {
  total: number;
  by_type: Record<string, number>;
  by_criticality: Record<string, number>;
}

export interface AssetCreatePayload {
  organization_id: string;
  asset_type: AssetTypeName;
  value: string;
  details?: Record<string, unknown>;
  criticality?: AssetCriticalityLevel;
  tags?: string[];
  monitoring_profile?: Record<string, unknown>;
  parent_asset_id?: string;
  discovery_method?: DiscoveryMethodName;
}

export interface AssetPatchPayload {
  details?: Record<string, unknown>;
  criticality?: AssetCriticalityLevel;
  tags?: string[];
  monitoring_profile?: Record<string, unknown>;
  is_active?: boolean;
  monitoring_enabled?: boolean;
  verified_at?: string;
  owner_user_id?: string;
}

export interface BulkImportRow {
  asset_type: AssetTypeName;
  value: string;
  details?: Record<string, unknown>;
  criticality?: AssetCriticalityLevel;
  tags?: string[];
}

export interface BulkImportPayload {
  organization_id: string;
  rows: BulkImportRow[];
}

export interface BulkImportResult {
  inserted: number;
  skipped_duplicates: number;
  errors: { index?: number; value?: string; error: unknown }[];
}

// --- Onboarding (Phase 0.2) ---------------------------------------------

export type OnboardingStepKey =
  | "organization"
  | "infra"
  | "people_and_brand"
  | "vendors"
  | "review";

export type OnboardingStateName = "draft" | "completed" | "abandoned";

export type OnboardingNextAction =
  | "ready"
  | "welcome_demo"
  | "quickstart"
  | "trigger_triage"
  | "review_alerts";

export interface OnboardingState {
  current_user_email: string;
  is_demo_user: boolean;
  seed_mode: string;
  user_org_count: number;
  seed_org_count: number;
  seed_org_names: string[];
  has_user_created_org: boolean;
  has_recent_triage: boolean;
  has_alerts: boolean;
  next_action: OnboardingNextAction;
}

export interface QuickstartResponse {
  organization_id: string;
  asset_id: string;
  brand_term_ids: string[];
}

export interface TelegramChannelCatalogEntry {
  handle: string;
  cluster: string;
  language: string;
  rationale: string;
  actor_link: string | null;
  status: "active" | "defunct" | "private";
  region_focus: string[];
}

export interface MonitoredSourcesResponse {
  telegram_channels: string[];
  breach_emails: string[];
  catalog: {
    telegram_channels: TelegramChannelCatalogEntry[];
    suggested_emails: string[];
  };
}

export interface OrgDomainListItem {
  domain: string;
  is_primary: boolean;
  verification_status: "unverified" | "pending" | "verified" | "expired";
  verified_at: string | null;
  expires_at: string | null;
}

export interface DomainVerificationStatus {
  domain: string;
  status: "unverified" | "pending" | "verified" | "expired";
  token: string | null;
  requested_at: string | null;
  expires_at: string | null;
  expires_in_hours: number | null;
  ttl_hours: number;
  verified_at: string | null;
  last_checked_at: string | null;
  last_error: string | null;
  gate_required: boolean;
  dns: {
    record_type: string;
    record_name: string;
    record_value: string;
    instructions: string;
  } | null;
  resolvers: string[];
  quorum_required: number;
  last_check_report: {
    quorum_required: number;
    resolvers_consulted: number;
    matches: number;
    votes: { resolver: string; matched: boolean; error: string | null }[];
  } | null;
}

export interface DomainVerificationCheck {
  domain: string;
  verified: boolean;
  status: "unverified" | "pending" | "verified" | "expired";
  matches: number;
  quorum_required: number;
  resolvers_consulted: number;
  votes: { resolver: string; matched: boolean; error: string | null }[];
  last_checked_at: string | null;
  last_error: string | null;
}

export interface OnboardingSessionRecord {
  id: string;
  organization_id: string | null;
  state: OnboardingStateName;
  current_step: number;
  step_data: Record<string, unknown>;
  completed_at: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface OnboardingValidationReport {
  step: OnboardingStepKey;
  valid: boolean;
  errors: { loc?: unknown[]; msg?: string; [k: string]: unknown }[];
}

export interface OnboardingCompletionResult {
  organization_id: string;
  session_id: string;
  assets_created: number;
  discovery_jobs_enqueued: number;
  warnings: string[];
}

export type DiscoveryJobKindName =
  | "subdomain_enum"
  | "port_scan"
  | "httpx_probe"
  | "ct_log_backfill"
  | "whois_refresh"
  | "dns_refresh";

export type DiscoveryJobStatusName =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface DiscoveryJobRecord {
  id: string;
  organization_id: string;
  asset_id: string | null;
  kind: DiscoveryJobKindName;
  status: DiscoveryJobStatusName;
  target: string;
  parameters: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
  result_summary: Record<string, unknown> | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

// ====================================================================
// Phase 1+ types (Audit B1).
//
// Each domain section maps 1:1 to src/api/routes/<name>.py response
// models. ``string`` is used everywhere a UUID lands at the wire
// (TypeScript can't enforce UUID format without a branded type and
// the runtime check would just throw a string back at us anyway).
// ====================================================================

// ---- Cases (Operations) ---------------------------------------------

export type CaseSeverityValue = "critical" | "high" | "medium" | "low" | "info";
export type CaseStateValue =
  | "open"
  | "triaged"
  | "in_progress"
  | "remediated"
  | "verified"
  | "closed";

export interface CaseListParams {
  organization_id: string;
  state?: CaseStateValue;
  severity?: CaseSeverityValue;
  assignee_user_id?: string;
  tag?: string;
  q?: string;
  overdue?: boolean;
  limit?: number;
  offset?: number;
}

// ---- Agentic investigations ----------------------------------------

export type InvestigationStatus =
  | "queued"
  | "running"
  | "awaiting_plan_approval"
  | "completed"
  | "failed";

export type InvestigationStopReason =
  | "high_confidence"
  | "max_iterations"
  | "no_new_evidence"
  | "llm_error"
  | "user_aborted";

export interface InvestigationListItem {
  id: string;
  alert_id: string;
  status: InvestigationStatus;
  severity_assessment: string | null;
  iterations: number;
  model_id: string | null;
  duration_ms: number | null;
  created_at: string;
  finished_at: string | null;
  case_id: string | null;
  /** Why the agent stopped — null on legacy rows or in-flight runs. */
  stop_reason: InvestigationStopReason | null;
  /** Agent's self-reported confidence in the verdict (0..1). */
  final_confidence: number | null;
  /** Deduped, ordered list of tool names the agent invoked. */
  tools_used: string[] | null;
  /** Joined alert metadata so list rows can show a title instead of a uuid. */
  alert_title: string | null;
  alert_severity: string | null;
  alert_category: string | null;
}

export interface InvestigationTraceStep {
  iteration: number;
  thought: string;
  tool: string | null;
  args: Record<string, unknown> | null;
  result: unknown;
  /** ISO timestamp at which the iteration started. New runs only. */
  started_at?: string | null;
  /** Wall-clock duration of the iteration in ms. New runs only. */
  duration_ms?: number | null;
}

export interface InvestigationPlanStep {
  /** Plan items emitted by the plan-then-act gate. ``rationale`` is the
   *  agent's one-liner explaining why this tool, in this position. */
  tool?: string;
  rationale?: string;
  /** Used by /rerun's extra_context shape — distinct from a tool step. */
  kind?: "extra_context";
  text?: string;
}

export interface InvestigationDetail extends InvestigationListItem {
  final_assessment: string | null;
  correlated_iocs: string[];
  correlated_actors: string[];
  recommended_actions: string[];
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
  case_id: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  /** Populated when the org has plan-then-act gating enabled and the
   *  agent has emitted a plan awaiting operator review. Also carries
   *  rerun extra_context shape. */
  plan: InvestigationPlanStep[] | null;
}

// Per-investigation stats response (T52 analytics page).
export interface InvestigationStatsResponse {
  total: number;
  by_status: Record<string, number>;
  success_rate: number;
  avg_iterations: number;
  avg_duration_ms: number | null;
  avg_final_confidence: number | null;
  top_tools: Array<{ tool: string; count: number }>;
  top_actors: Array<{ actor: string; count: number }>;
  stop_reasons: Array<{ stop_reason: string; count: number }>;
  daily: Array<{ date: string; total: number; completed: number; failed: number }>;
}

// Compare two investigations (T54).
export interface InvestigationCompareDiff {
  a_id: string;
  b_id: string;
  same_alert: boolean;
  iteration_delta: number;
  duration_delta_ms: number | null;
  confidence_delta: number | null;
  severity_a: string | null;
  severity_b: string | null;
  assessment_a: string | null;
  assessment_b: string | null;
  iocs_added: string[];
  iocs_removed: string[];
  actors_added: string[];
  actors_removed: string[];
  actions_added: string[];
  actions_removed: string[];
  tools_added: string[];
  tools_removed: string[];
}

// ---- Agent admin (posture + settings + cross-agent feed) -----------

export interface AgentPosture {
  human_in_loop_required: boolean;
  features: Record<string, boolean>;
  env_vars: Record<string, string>;
  llm: { provider: string; model: string; label: string };
}

export interface AgentSettings {
  organization_id: string;
  investigation_enabled: boolean;
  brand_defender_enabled: boolean;
  case_copilot_enabled: boolean;
  threat_hunter_enabled: boolean;
  chain_investigation_to_hunt: boolean;
  auto_promote_critical: boolean;
  auto_takedown_high_confidence: boolean;
  threat_hunt_interval_seconds: number | null;
  /** Plan-then-act gate for the Investigation agent. */
  investigation_plan_approval?: boolean;
  /** Min suspect-domain similarity for auto-queueing the Brand
   *  Defender. T77 — replaces the legacy hardcoded 0.80 constant. */
  brand_defence_min_similarity?: number;
  /** Plan-then-act gate for the Brand Defender. */
  brand_defence_plan_approval?: boolean;
}

export type AgentKind =
  | "investigation"
  | "brand_defender"
  | "case_copilot"
  | "threat_hunter";

export interface AgentActivityItem {
  id: string;
  kind: AgentKind;
  status: "queued" | "running" | "completed" | "failed";
  headline: string;
  severity: string | null;
  confidence: number | null;
  iterations: number;
  model_id: string | null;
  duration_ms: number | null;
  created_at: string;
  finished_at: string | null;
  deep_link: string;
}

// ---- Agentic threat hunter -----------------------------------------

export type HuntStatus = "queued" | "running" | "completed" | "failed";

export interface HuntFinding {
  title: string;
  description: string;
  relevance: number;
  mitre_ids: string[];
  ioc_ids: string[];
  recommended_action: string;
}

export interface HuntListItem {
  id: string;
  status: HuntStatus;
  primary_actor_alias: string | null;
  confidence: number | null;
  iterations: number;
  model_id: string | null;
  duration_ms: number | null;
  created_at: string;
  finished_at: string | null;
}

export interface HuntDetail extends HuntListItem {
  primary_actor_id: string | null;
  summary: string | null;
  findings: HuntFinding[] | null;
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
}

// ---- Agentic case copilot ------------------------------------------

export type CopilotStatus = "queued" | "running" | "completed" | "failed";

export interface CopilotRunListItem {
  id: string;
  case_id: string;
  status: CopilotStatus;
  confidence: number | null;
  iterations: number;
  model_id: string | null;
  duration_ms: number | null;
  applied_at: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface CopilotTimelineEvent {
  at: string | null;
  source: string;
  text: string;
}

/** One LLM-picked investigation playbook on a copilot run. The
 *  apply_suggestions endpoint materialises each entry as a real
 *  PlaybookExecution row linked to the case (see /exec/playbook-history
 *  with `case_id` filter). */
export interface CopilotSuggestedPlaybook {
  playbook_id: string;
  params: Record<string, unknown>;
  rationale: string;
}

export interface CopilotRunDetail extends CopilotRunListItem {
  summary: string | null;
  timeline_events: CopilotTimelineEvent[] | null;
  suggested_mitre_ids: string[] | null;
  draft_next_steps: string[] | null;
  suggested_playbooks: CopilotSuggestedPlaybook[] | null;
  similar_case_ids: string[] | null;
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
}

// ---- Agentic brand defence -----------------------------------------

export type BrandActionStatus =
  | "queued"
  | "running"
  | "awaiting_plan_approval"
  | "completed"
  | "failed";
export type BrandActionRecommendation =
  | "takedown_now"
  | "takedown_after_review"
  | "dismiss_subsidiary"
  | "monitor"
  | "insufficient_data";

export interface BrandActionListItem {
  id: string;
  suspect_domain_id: string;
  status: BrandActionStatus;
  recommendation: BrandActionRecommendation | null;
  confidence: number | null;
  risk_signals: string[];
  suggested_partner: string | null;
  iterations: number;
  model_id: string | null;
  duration_ms: number | null;
  created_at: string;
  finished_at: string | null;
  takedown_ticket_id: string | null;
  /** Suspect-domain metadata joined inline so the activity panel
   *  can render meaningful rows without a per-action fetch. */
  suspect_domain: string | null;
  suspect_similarity: number | null;
  suspect_state: string | null;
}

export interface BrandActionDetail extends BrandActionListItem {
  recommendation_reason: string | null;
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
  /** Plan-then-act gate output OR rerun extra_context. */
  plan: InvestigationPlanStep[] | null;
  input_tokens: number | null;
  output_tokens: number | null;
}

export interface BrandActionStatsResponse {
  total: number;
  by_status: Record<string, number>;
  by_recommendation: Record<string, number>;
  avg_confidence: number | null;
  avg_iterations: number;
  avg_duration_ms: number | null;
  top_risk_signals: Array<{ risk_signal: string; count: number }>;
  defence_to_takedown_rate: number;
  daily: Array<{
    date: string;
    total: number;
    completed: number;
    failed: number;
    takedown_now: number;
  }>;
}

export interface BrandActionCompareDiff {
  a_id: string;
  b_id: string;
  same_suspect: boolean;
  iteration_delta: number;
  duration_delta_ms: number | null;
  confidence_delta: number | null;
  recommendation_a: string | null;
  recommendation_b: string | null;
  risk_signals_added: string[];
  risk_signals_removed: string[];
  tools_added: string[];
  tools_removed: string[];
}

export interface BrandAllowlistEntry {
  id: string;
  organization_id: string;
  pattern: string;
  reason: string | null;
  created_by_user_id: string | null;
  created_at: string;
}

export interface BrandAllowlistSweepResponse {
  org_id: string;
  swept: number;
  dismissed: number;
}

export interface BrandScheduledProbe {
  suspect_id: string;
  domain: string;
  last_probed_at: string | null;
  last_verdict: string | null;
  similarity: number;
  due_at: string;
  reason: string;
}

export interface BrandSuspectWhois {
  suspect_id: string;
  domain: string;
  fetched_at: string;
  cached: boolean;
  registrar: string | null;
  registrant_email: string | null;
  registrant_name: string | null;
  registrant_org: string | null;
  registrant_country: string | null;
  abuse_email: string | null;
  registered_at: string | null;
  updated_at: string | null;
  expires_at: string | null;
  raw_excerpt: string | null;
}

export interface BrandSuspectCluster {
  signal_kind: "nameserver" | "ip" | "matched_term";
  signal_value: string;
  count: number;
  max_similarity: number;
  sample_domains: string[];
  sample_suspect_ids: string[];
}

export interface CaseResponse {
  id: string;
  organization_id: string;
  title: string;
  summary: string | null;
  severity: CaseSeverityValue;
  state: CaseStateValue;
  owner_user_id: string | null;
  assignee_user_id: string | null;
  tags: string[];
  sla_due_at: string | null;
  first_response_at: string | null;
  closed_at: string | null;
  closed_by_user_id: string | null;
  close_reason: string | null;
  primary_asset_id: string | null;
  extra: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface CaseFindingResponse {
  id: string;
  /** Nullable since the D12 audit. Polymorphic findings (mobile_app,
   *  suspect_domain, exposure, fraud, impersonation, card_leakage,
   *  dlp, logo_match, live_probe) link via ``finding_type`` +
   *  ``finding_id`` instead of going through the Alert table. */
  alert_id: string | null;
  finding_type: string | null;
  finding_id: string | null;
  is_primary: boolean;
  linked_by_user_id: string | null;
  link_reason: string | null;
  created_at: string;
}

export interface CaseCommentResponse {
  id: string;
  author_user_id: string | null;
  body: string;
  edited_at: string | null;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
}

export interface CaseTransitionResponse {
  id: string;
  from_state: CaseStateValue | null;
  to_state: CaseStateValue;
  reason: string | null;
  transitioned_by_user_id: string | null;
  transitioned_at: string;
}

export interface CaseDetailResponse extends CaseResponse {
  findings: CaseFindingResponse[];
  comments: CaseCommentResponse[];
  transitions: CaseTransitionResponse[];
}

export interface CaseCounts {
  total: number;
  by_state: Record<CaseStateValue, number>;
  by_severity: Record<CaseSeverityValue, number>;
  overdue: number;
}

export interface CaseCreatePayload {
  organization_id: string;
  title: string;
  summary?: string;
  severity: CaseSeverityValue;
  assignee_user_id?: string;
  tags?: string[];
  primary_asset_id?: string;
  sla_due_at?: string;
  initial_alert_ids?: string[];
}

export interface CaseUpdatePayload {
  title?: string;
  summary?: string;
  severity?: CaseSeverityValue;
  assignee_user_id?: string | null;
  tags?: string[];
  sla_due_at?: string | null;
  primary_asset_id?: string | null;
}

export interface CaseTransitionPayload {
  to_state: CaseStateValue;
  reason?: string;
  close_reason?: string;
}

export interface CaseFindingCreatePayload {
  alert_id: string;
  is_primary?: boolean;
  link_reason?: string;
}

// ---- Brand Protection ------------------------------------------------

export type BrandTermKindValue = "apex_domain" | "name" | "product";
export type SuspectStateValue =
  | "open"
  | "confirmed_phishing"
  | "takedown_requested"
  | "dismissed"
  | "cleared";
export type SuspectSourceValue =
  | "dnstwist"
  | "certstream"
  | "whoisds"
  | "manual"
  | "subdomain_fuzz"
  | "phishtank"
  | "openphish"
  | "urlhaus";

export interface BrandTermResponse {
  id: string;
  organization_id: string;
  kind: BrandTermKindValue;
  value: string;
  is_active: boolean;
  keywords: string[];
  created_at: string;
  updated_at: string;
}

export interface BrandTermCreatePayload {
  organization_id: string;
  kind: BrandTermKindValue;
  value: string;
  keywords?: string[];
}

export interface SuspectListParams {
  organization_id: string;
  state?: SuspectStateValue;
  source?: SuspectSourceValue;
  is_resolvable?: boolean;
  /** Backend search across domain + matched_term_value (T79). */
  q?: string;
  limit?: number;
  offset?: number;
}

export interface SuspectDomainResponse {
  id: string;
  organization_id: string;
  domain: string;
  matched_term_value: string;
  similarity: number;
  permutation_kind: string;
  is_resolvable: boolean | null;
  a_records: string[];
  mx_records: string[];
  nameservers: string[];
  first_seen_at: string;
  last_seen_at: string;
  state: SuspectStateValue;
  source: SuspectSourceValue;
  state_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface SuspectStatePayload {
  state: SuspectStateValue;
  reason?: string;
}

export interface BrandScanResponse {
  organization_id: string;
  terms_scanned: number;
  permutations_generated: number;
  candidates_resolved: number;
  suspects_created: number;
  suspects_seen_again: number;
  resolver_errors: number;
}

export interface BrandLogoResponse {
  id: string;
  organization_id: string;
  label: string;
  description: string | null;
  width: number | null;
  height: number | null;
  image_evidence_sha256: string;
  phash_hex: string;
  dhash_hex: string;
  ahash_hex: string;
  created_at: string;
  updated_at: string;
}

export interface LogoMatchResponse {
  id: string;
  organization_id: string;
  brand_logo_id: string;
  suspect_domain_id: string | null;
  live_probe_id: string | null;
  candidate_image_sha256: string;
  phash_distance: number;
  dhash_distance: number;
  ahash_distance: number;
  color_distance: number;
  similarity: number;
  verdict: string;
  matched_at: string;
  extra: Record<string, unknown> | null;
  created_at: string;
}

export interface LiveProbeResponse {
  id: string;
  organization_id: string;
  suspect_domain_id: string | null;
  domain: string;
  url: string | null;
  fetched_at: string;
  http_status: number | null;
  final_url: string | null;
  title: string | null;
  html_evidence_sha256: string | null;
  screenshot_evidence_sha256: string | null;
  verdict: string;
  classifier_name: string;
  confidence: number;
  signals: string[];
  matched_brand_terms: string[];
  rationale: string | null;
  error_message: string | null;
  extra: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface LiveProbeRunPayload {
  organization_id: string;
  suspect_domain_id: string;
  follow_redirects?: boolean;
}

export interface FeedIngestPayload {
  organization_id: string;
  // Backend field is named ``domains`` (see FeedIngestRequest in
  // src/api/routes/brand.py); rename happens at the call boundary.
  candidates: string[];
  source?: SuspectSourceValue;
  min_similarity?: number;
}

export interface FeedIngestResponse {
  candidates: number;
  matches: number;
  suspects_created: number;
  suspects_seen_again: number;
  skipped_invalid: number;
}

export interface BrandOverviewResponse {
  organization_id: string;
  terms: Record<string, number>;
  suspects_total: number;
  suspects_by_state: Record<string, number>;
  suspects_by_source: Record<string, number>;
  suspects_top_similarity: Array<{
    id: string;
    domain: string;
    matched_term: string;
    similarity: number;
    state: SuspectStateValue;
    source: SuspectSourceValue;
  }>;
  logos_count: number;
  logo_matches_total: number;
  logo_matches_by_verdict: Record<string, number>;
  logo_corpus_health: {
    status: "empty" | "active";
    message: string;
  };
  live_probes_total: number;
  live_probes_by_verdict: Record<string, number>;
  recent_phishing_probes: Array<{
    id: string;
    suspect_domain_id: string;
    url: string;
    verdict: string;
    fetched_at: string;
    similarity_to_brand: number | null;
  }>;
  impersonations_total: number;
  impersonations_by_state: Record<string, number>;
  mobile_apps_total: number;
  mobile_apps_by_state: Record<string, number>;
  fraud_findings_total: number;
  fraud_findings_by_state: Record<string, number>;
}

// ---- Social / Impersonation -----------------------------------------

export type SocialPlatformValue =
  | "twitter"
  | "linkedin"
  | "instagram"
  | "tiktok"
  | "facebook"
  | "youtube"
  | "telegram"
  | "discord"
  | "reddit"
  | "mastodon"
  | "bluesky";

export type ImpersonationStateValue =
  | "open"
  | "confirmed"
  | "takedown_requested"
  | "dismissed"
  | "cleared";

export type ImpersonationKindValue = "executive" | "brand_account" | "product";

export interface VipResponse {
  id: string;
  organization_id: string;
  full_name: string;
  title: string | null;
  aliases: string[];
  bio_keywords: string[];
  photo_evidence_sha256s: string[];
  photo_phashes: string[];
  created_at: string;
  updated_at: string;
}

export interface VipCreatePayload {
  organization_id: string;
  full_name: string;
  title?: string;
  aliases?: string[];
  bio_keywords?: string[];
}

export interface SocialAccountResponse {
  id: string;
  organization_id: string;
  vip_profile_id: string | null;
  platform: SocialPlatformValue;
  handle: string;
  profile_url: string | null;
  is_official: boolean;
  keywords: string[];
}

export interface ImpersonationListParams {
  organization_id: string;
  platform?: SocialPlatformValue;
  state?: ImpersonationStateValue;
  kind?: ImpersonationKindValue;
  limit?: number;
  offset?: number;
}

export interface ImpersonationFindingResponse {
  id: string;
  organization_id: string;
  vip_profile_id: string | null;
  platform: SocialPlatformValue;
  candidate_handle: string;
  candidate_display_name: string | null;
  candidate_bio: string | null;
  candidate_url: string | null;
  candidate_photo_sha256: string | null;
  candidate_photo_phash: string | null;
  kind: ImpersonationKindValue;
  name_similarity: number;
  handle_similarity: number;
  bio_similarity: number;
  photo_similarity: number | null;
  aggregate_score: number;
  signals: string[];
  state: ImpersonationStateValue;
  state_reason: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

export interface MobileAppListParams {
  organization_id: string;
  store?: "apple" | "google_play";
  state?: string;
  limit?: number;
  offset?: number;
}

export interface MobileAppFindingResponse {
  id: string;
  organization_id: string;
  store: "apple" | "google_play";
  app_id: string;
  title: string;
  publisher: string | null;
  description: string | null;
  url: string | null;
  icon_sha256: string | null;
  rating: number | null;
  install_estimate: string | null;
  matched_term: string;
  matched_term_kind: string;
  is_official_publisher: boolean;
  state: string;
  state_reason: string | null;
  state_changed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FraudListParams {
  organization_id: string;
  channel?: string;
  state?: string;
  kind?: string;
  limit?: number;
  offset?: number;
}

export interface FraudFindingResponse {
  id: string;
  organization_id: string;
  kind: string;
  channel: string;
  target_identifier: string;
  title: string | null;
  excerpt: string | null;
  matched_brand_terms: string[];
  matched_keywords: string[];
  score: number;
  rationale: string | null;
  detected_at: string;
  state: string;
  state_reason: string | null;
  created_at: string;
  updated_at: string;
}

// ---- EASM / Exposures -----------------------------------------------

export type ExposureSeverityValue = "critical" | "high" | "medium" | "low" | "info";
export type ExposureStateValue =
  | "open"
  | "acknowledged"
  | "accepted_risk"
  | "false_positive"
  | "fixed"
  | "reopened";

export interface EasmScanPayload {
  organization_id: string;
  kind: DiscoveryJobKindName;
  target: string;
  parameters?: Record<string, unknown>;
}

export interface EasmFindingListParams {
  organization_id: string;
  state?: string;
  severity?: ExposureSeverityValue;
  limit?: number;
  offset?: number;
}

export interface EasmFindingResponse {
  id: string;
  organization_id: string;
  discovery_job_id: string | null;
  parent_asset_id: string | null;
  asset_type: string;
  value: string;
  details: Record<string, unknown> | null;
  state: string;
  confidence: number;
  promoted_asset_id: string | null;
  discovered_via: string | null;
  created_at: string;
  updated_at: string;
}

export interface EasmChangeResponse {
  id: string;
  organization_id: string;
  asset_id: string | null;
  discovery_job_id: string | null;
  kind: string;
  severity: ExposureSeverityValue;
  summary: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  detected_at: string;
  created_at: string;
}

export interface ExposureListParams {
  organization_id: string;
  severity?: ExposureSeverityValue;
  state?: ExposureStateValue;
  category?: string;
  source?: string;
  asset_id?: string;
  cve?: string;
  is_kev?: boolean;
  q?: string;
  sort?: "last_seen" | "matched" | "severity" | "cvss" | "epss" | "priority" | "age";
  limit?: number;
  offset?: number;
}

export type RemediationAction =
  | "patched"
  | "mitigated"
  | "waived"
  | "blocked"
  | "false_positive"
  | "other";

export interface ExposureResponse {
  id: string;
  organization_id: string;
  asset_id: string | null;
  asset_value: string | null;
  asset_criticality: string | null;
  discovery_job_id: string | null;
  severity: ExposureSeverityValue;
  category: string;
  state: ExposureStateValue;
  source: string;
  rule_id: string;
  title: string;
  description: string | null;
  target: string;
  matched_at: string;
  last_seen_at: string;
  occurrence_count: number;
  cvss_score: number | null;
  cve_ids: string[];
  cwe_ids: string[];
  references: string[];
  matcher_data: Record<string, unknown> | null;
  state_changed_by_user_id: string | null;
  state_changed_at: string | null;
  state_reason: string | null;
  // NVD/EPSS/KEV enrichment.
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  kev_added_at: string | null;
  // Structured remediation.
  remediation_action: RemediationAction | null;
  remediation_patch_version: string | null;
  remediation_owner: string | null;
  remediation_notes: string | null;
  // AI agent outputs.
  ai_priority: number | null;
  ai_rationale: string | null;
  ai_triaged_at: string | null;
  ai_suggest_dismiss: boolean;
  ai_dismiss_reason: string | null;
  // Computed at read time.
  age_days: number | null;
  blast_radius: number | null;
  created_at: string;
  updated_at: string;
}

export interface ExposureStatePayload {
  state: ExposureStateValue;
  reason?: string;
  remediation_action?: RemediationAction;
  remediation_patch_version?: string;
  remediation_owner?: string;
  remediation_notes?: string;
}

export interface ExposureLinkAssetPayload {
  asset_id: string;
}

export interface SurfaceAssetsParams {
  organization_id: string;
  asset_type?: string;
  parent_asset_id?: string;
  has_open_exposures?: boolean;
  has_kev?: boolean;
  accessible_only?: boolean;
  weak_tls_only?: boolean;
  q?: string;
  sort?: "risk" | "last_seen" | "discovered" | "value" | "criticality" | "exposures";
  limit?: number;
  offset?: number;
}

export interface SurfaceAssetClassification {
  environment: string;
  role: string;
  tags: string[];
  confidence: number;
  rationale: string;
  source: "heuristic" | "llm";
}

export interface SurfaceAsset {
  id: string;
  organization_id: string;
  asset_type: string;
  value: string;
  criticality: string;
  parent_asset_id: string | null;
  discovery_method: string;
  discovered_at: string | null;
  last_scanned_at: string | null;
  last_change_at: string | null;
  is_active: boolean;
  monitoring_enabled: boolean;
  http_status_code: number | null;
  http_title: string | null;
  http_tech: string[];
  ips: string[];
  ports: Array<{ port: number; protocol: string }>;
  tls_grade: string | null;
  tls_issue_counts: Record<string, number> | null;
  has_screenshot: boolean;
  risk_score: number | null;
  risk_score_updated_at: string | null;
  ai_classification: SurfaceAssetClassification | null;
  ai_classified_at: string | null;
  open_exposures: number;
  kev_exposures: number;
  children_count: number;
  tags: string[];
}

export interface SurfaceAssetDetail extends SurfaceAsset {
  details: Record<string, unknown> | null;
  parent_value: string | null;
}

export interface SurfaceAssetExposure {
  id: string;
  title: string;
  severity: string;
  state: string;
  rule_id: string;
  category: string;
  cve_ids: string[];
  is_kev: boolean;
  epss_score: number | null;
  cvss_score: number | null;
  ai_priority: number | null;
  last_seen_at: string | null;
  matched_at: string | null;
}

export interface SurfaceChangesParams {
  organization_id: string;
  asset_id?: string;
  kind?: string;
  severity?: string;
  since_days?: number;
  limit?: number;
  offset?: number;
}

export interface SurfaceChange {
  id: string;
  organization_id: string;
  asset_id: string | null;
  asset_value: string | null;
  discovery_job_id: string | null;
  kind: string;
  severity: string;
  summary: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  detected_at: string;
  created_at: string;
}

export interface SurfaceClassifyResponse {
  classified: number;
  llm_used: number;
  llm_failed: number;
  total_assets: number;
}

export interface SurfaceStats {
  organization_id: string;
  total_assets: number;
  by_type: Record<string, number>;
  by_criticality: Record<string, number>;
  accessible_count: number;
  auth_gated_count: number;
  weak_tls_count: number;
  open_exposures: number;
  kev_exposures: number;
  avg_risk_score: number | null;
  top_risk_score: number | null;
}

export interface ExposureTriagePayload {
  exposure_ids?: string[];
  use_llm?: boolean;
}

export interface ExposureTriageResponse {
  triaged_count: number;
  suppressed_count: number;
  llm_used: boolean;
  llm_failures: number;
  results: Array<{
    exposure_id: string;
    ai_priority: number;
    ai_rationale: string;
    ai_suggest_dismiss: boolean;
    ai_dismiss_reason: string | null;
  }>;
}

// ---- TPRM ------------------------------------------------------------

export interface TprmQuestion {
  id: string;
  text: string;
  answer_kind: string;
  weight: number;
  required: boolean;
}

export interface TprmTemplateResponse {
  id: string;
  organization_id: string | null;
  name: string;
  kind: string;
  description: string | null;
  questions: TprmQuestion[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface TprmTemplateCreatePayload {
  organization_id?: string;
  name: string;
  kind: string;
  description?: string;
  questions: TprmQuestion[];
  is_active?: boolean;
}

export type VendorOnboardingStage =
  | "invited"
  | "questionnaire_sent"
  | "questionnaire_received"
  | "analyst_review"
  | "approved"
  | "rejected"
  | "on_hold";

export type VendorTier = "tier_1" | "tier_2" | "tier_3";
export type VendorCategory =
  | "payment_processor"
  | "cloud_provider"
  | "security_vendor"
  | "hr_payroll"
  | "telecom"
  | "legal"
  | "auditor"
  | "marketing_saas"
  | "data_broker"
  | "other";

export interface VendorPostureSignal {
  id: string;
  kind: string;
  severity: string;
  score: number | null;
  summary: string | null;
  evidence: Record<string, unknown> | null;
  collected_at: string | null;
}

export interface VendorScorecardSnapshot {
  score: number;
  grade: string;
  pillar_scores: Record<string, number>;
  snapshot_at: string;
}

export interface VendorScorecardSnapshotsResponse {
  vendor_id: string;
  snapshots: VendorScorecardSnapshot[];
  drop_alert:
    | {
        from: number;
        to: number;
        delta: number;
        from_at: string;
        to_at: string;
      }
    | null;
}

export interface VendorPercentileResponse {
  vendor_id: string;
  score: number;
  grade: string;
  global: { percentile: number; cohort_size: number; label: string };
  category: {
    percentile: number;
    cohort_size: number;
    category: string;
    label: string;
  };
}

export interface TprmExecDashboard {
  organization_id: string;
  vendors_total: number;
  by_grade: Record<string, number>;
  by_tier: Record<string, number>;
  by_category: Record<string, number>;
  avg_score: number | null;
  below_threshold_count: number;
  top_risk: Array<{
    vendor_id: string;
    vendor_value: string;
    tier: string;
    category: string;
    score: number;
    grade: string;
    pillar_scores: Record<string, number>;
  }>;
  compliant_pct: number;
}

export interface VendorEvidenceFileResponse {
  id: string;
  file_name: string;
  file_size: number;
  mime_type: string | null;
  sha256: string;
  questionnaire_instance_id: string | null;
  question_id: string | null;
  extracted: Record<string, unknown> | null;
  uploaded_by_user_id: string | null;
  created_at: string | null;
}

export interface VendorContractResponse {
  id: string;
  title: string;
  contract_kind: string | null;
  file_name: string;
  file_size: number;
  sha256: string;
  effective_date: string | null;
  expiration_date: string | null;
  extracted_clauses: Record<string, unknown> | null;
  created_at: string | null;
}

export interface VendorBriefResponse {
  vendor_value: string;
  vendor_id: string;
  current_score: number | null;
  current_grade: string | null;
  drop_alert: Record<string, unknown> | null;
  narrative: string;
  llm_used: boolean;
  baseline: string;
}

export interface VendorPlaybookResponse {
  vendor_value: string;
  pillar: string;
  actions: string[];
  current_score: number | null;
  llm_used: boolean;
}

export interface TprmOnboardingResponse {
  id: string;
  organization_id: string;
  vendor_asset_id: string;
  stage: VendorOnboardingStage;
  questionnaire_instance_id: string | null;
  notes: string | null;
  decided_by_user_id: string | null;
  decision_reason: string | null;
  decided_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TprmOnboardingCreatePayload {
  organization_id: string;
  vendor_asset_id: string;
  notes?: string;
}

export interface TprmOnboardingTransitionPayload {
  to_stage: VendorOnboardingStage;
  questionnaire_instance_id?: string;
  reason?: string;
}

export interface TprmScorecardResponse {
  id: string;
  organization_id: string;
  vendor_asset_id: string;
  score: number;
  grade: string;
  is_current: boolean;
  pillar_scores: Record<string, number>;
  summary: Record<string, unknown>;
  computed_at: string;
  created_at: string;
}

// ---- Takedown -------------------------------------------------------

export type TakedownStateValue =
  | "submitted"
  | "acknowledged"
  | "in_progress"
  | "succeeded"
  | "rejected"
  | "failed"
  | "withdrawn";

export type TakedownPartnerValue =
  | "netcraft"
  | "phishlabs"
  | "group_ib"
  | "internal_legal"
  | "manual"
  | "urlhaus"
  | "threatfox"
  | "direct_registrar";

export type TakedownTargetKindValue =
  | "suspect_domain"
  | "impersonation"
  | "mobile_app"
  | "fraud"
  | "other";

export interface TakedownPartnerEntry {
  name: TakedownPartnerValue;
  label: string;
  is_configured: boolean;
  config_hint: string | null;
}

export interface TakedownPartnerInfo {
  partners: TakedownPartnerEntry[];
}

export interface TakedownListParams {
  organization_id: string;
  state?: TakedownStateValue;
  partner?: TakedownPartnerValue;
  target_kind?: TakedownTargetKindValue;
  limit?: number;
  offset?: number;
}

export interface TakedownTicketResponse {
  id: string;
  organization_id: string;
  partner: TakedownPartnerValue;
  state: TakedownStateValue;
  target_kind: TakedownTargetKindValue;
  target_identifier: string;
  source_finding_id: string | null;
  partner_reference: string | null;
  partner_url: string | null;
  submitted_by_user_id: string | null;
  submitted_at: string;
  acknowledged_at: string | null;
  succeeded_at: string | null;
  failed_at: string | null;
  proof_evidence_sha256: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
  /** State machine: states the analyst can move this ticket into.
   *  Computed server-side from _ALLOWED_TRANSITIONS so the
   *  TransitionModal never shows an option that would 422. Empty
   *  list = terminal state. */
  allowed_next: TakedownStateValue[];
  /** Set when the partner returned a state the heuristic mapper
   *  didn't recognise. Dashboard surfaces a yellow badge until the
   *  next sync clears it. */
  needs_review: boolean;
  last_partner_state: string | null;
  /** Raw partner-submit response payload — surfaced as collapsible
   *  JSON in the detail drawer. May be absent on legacy tickets. */
  raw?: Record<string, unknown> | null;
}

export interface TakedownTicketHistoryEntry {
  id: string;
  timestamp: string;
  action: string;
  actor_user_id: string | null;
  actor_email: string | null;
  details: Record<string, unknown> | null;
}

export interface TakedownTicketHistoryResponse {
  entries: TakedownTicketHistoryEntry[];
}

export interface TakedownTicketCreatePayload {
  organization_id: string;
  partner?: TakedownPartnerValue;
  target_kind: TakedownTargetKindValue;
  target_identifier: string;
  source_finding_id?: string;
  reason: string;
  evidence_urls?: string[];
  contact_email?: string;
  metadata?: Record<string, unknown>;
}

export interface TakedownTransitionPayload {
  to_state: TakedownStateValue;
  reason?: string;
  proof_evidence_sha256?: string;
}

// ---- Exec Summary ----------------------------------------------------

export interface ExecSummaryResponse {
  organization_id: string;
  window_days: number;
  generated_at: string;
  cases: { open: number; closed: number; overdue: number };
  exposures: Record<ExposureSeverityValue, number>;
  takedowns: Record<TakedownStateValue, number>;
  brand: { suspects_open: number; impersonations_open: number; mobile_apps_open: number };
  sla: { breaches: number; on_track: number };
  rating: { score: number | null; grade: string | null };
}

// ---- Leakage / DLP --------------------------------------------------

export interface BinResponse {
  id: string;
  organization_id: string | null;
  bin_prefix: string;
  issuer: string | null;
  scheme: string;
  card_type: string;
  country_code: string | null;
  created_at: string;
}

export interface BinImportResult {
  inserted: number;
  skipped_duplicates: number;
  errors: Array<{ index?: number; error: string }>;
}

export interface FindingClassification {
  category: string;
  impact_level: string;
  compliance: string[];
  confidence: number;
  rationale: string;
  classified_at?: string;
  model_id?: string | null;
}

export interface FindingCorrelation {
  match_key?: string;
  matches?: Array<{
    id: string;
    kind: string;
    organization_id: string;
    source_url?: string | null;
    detected_at?: string | null;
  }>;
  distinct_orgs?: number;
  actor_inference?: {
    probable_source: string;
    confidence: number;
    recommended_action: string;
    supply_chain_likelihood: string;
  } | null;
  checked_at?: string;
}

export interface BreachCorrelations {
  emails: Record<string, string[]>;
  checked_at?: string;
  reason?: string;
}

export interface CardLeakageResponse {
  id: string;
  organization_id: string;
  pan_first6: string;
  pan_last4: string;
  pan_sha256: string;
  matched_bin_id: string | null;
  issuer: string | null;
  scheme: string;
  card_type: string;
  source_url: string | null;
  source_kind: string | null;
  excerpt: string | null;
  expiry: string | null;
  state: string;
  state_reason: string | null;
  state_changed_at: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
  classification?: FindingClassification | null;
  correlated_findings?: FindingCorrelation | null;
  breach_correlations?: BreachCorrelations | null;
  takedown_draft?: string | null;
}

export interface CardScanPayload {
  organization_id: string;
  text: string;
  source_url?: string;
  source_kind?: string;
  require_bin_match?: boolean;
}

export interface CardScanResponse {
  candidates: number;
  new_findings: number;
  /** Backend returns ``seen_again`` (existing finding hit again). */
  seen_again?: number;
  /** @deprecated retained so older renderers continue to typecheck */
  duplicates?: number;
  /** @deprecated retained so older renderers continue to typecheck */
  validated?: number;
  /** @deprecated retained so older renderers continue to typecheck */
  bin_matched?: number;
}

export interface DlpPolicyResponse {
  id: string;
  organization_id: string;
  name: string;
  kind: string;
  pattern: string;
  severity: string;
  description: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DlpPolicyCreatePayload {
  organization_id: string;
  name: string;
  kind: string;
  pattern: string;
  severity?: string;
  description?: string;
  enabled?: boolean;
}

export interface DlpPolicyTestResult {
  matched: number;
  excerpts: string[];
  duration_ms: number;
}

export interface DlpScanPayload {
  organization_id: string;
  text: string;
  source_url?: string;
  source_kind?: string;
}

export interface DlpScanResponse {
  policies_evaluated: number;
  findings_created: number;
  matches_found: number;
}

export interface DlpFindingListParams {
  organization_id: string;
  policy_id?: string;
  state?: string;
  severity?: string;
  limit?: number;
}

export interface DlpFindingResponse {
  id: string;
  organization_id: string;
  policy_id: string | null;
  policy_name: string;
  severity: string;
  source_url: string | null;
  source_kind: string | null;
  matched_count: number;
  matched_excerpts: string[];
  state: string;
  state_reason: string | null;
  state_changed_at: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
  classification?: FindingClassification | null;
  correlated_findings?: FindingCorrelation | null;
  breach_correlations?: BreachCorrelations | null;
  takedown_draft?: string | null;
}

export interface TakedownDraftResponse {
  finding_id: string;
  kind: string;
  status: "queued" | "ready";
  draft: string | null;
  queued_task_id: string | null;
}

export interface AgentSummaryResponse {
  finding_id: string;
  kind: string;
  severity: string;
  state: string;
  classification: FindingClassification | null;
  correlated_findings: FindingCorrelation | null;
  breach_correlations: BreachCorrelations | null;
  agent_summary: Record<string, unknown> | null;
  takedown_draft: string | null;
}

export interface PolicyTuneResponse {
  organization_id: string;
  queued_task_id: string;
  status: string;
}

export interface BinImportResponse {
  inserted: number;
  skipped_duplicates: number;
  errors: Array<{ index?: number; error: string }>;
}

// ---- Notifications --------------------------------------------------

export type NotificationChannelKind =
  | "slack"
  | "teams"
  | "email"
  | "webhook"
  | "pagerduty"
  | "opsgenie"
  | "apprise"
  | "jasmin_sms";

export interface NotificationAdapterInfo {
  kind: NotificationChannelKind;
  display_name: string;
  required_config_keys: string[];
  required_secret: boolean;
  description: string;
}

export interface NotificationChannelResponse {
  id: string;
  organization_id: string;
  kind: NotificationChannelKind;
  name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  last_used_at: string | null;
  last_status: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationChannelCreatePayload {
  organization_id: string;
  kind: NotificationChannelKind;
  name: string;
  config: Record<string, unknown>;
  secret?: string;
  enabled?: boolean;
}

export interface NotificationChannelUpdatePayload {
  name?: string;
  config?: Record<string, unknown>;
  secret?: string;
  enabled?: boolean;
}

export interface NotificationQuietHours {
  start: string; // "22:00"
  end: string;   // "07:00"
  tz: string;    // "Asia/Dubai" / "UTC"
  except_severity?: string | null; // e.g. "critical" — bypasses the quiet window
}

export interface NotificationRuleResponse {
  id: string;
  organization_id: string;
  name: string;
  enabled: boolean;
  channel_ids: string[];
  event_kinds: string[];
  min_severity: string;
  asset_criticalities: string[];
  asset_types: string[];
  tags_any: string[];
  dedup_window_seconds: number;
  description?: string | null;
  quiet_hours?: NotificationQuietHours | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationRuleCreatePayload {
  organization_id: string;
  name: string;
  channel_ids: string[];
  event_kinds: string[];
  min_severity?: string;
  asset_criticalities?: string[];
  asset_types?: string[];
  tags_any?: string[];
  dedup_window_seconds?: number;
  enabled?: boolean;
  description?: string | null;
  quiet_hours?: NotificationQuietHours | null;
}

export interface NotificationRuleUpdatePayload {
  name?: string;
  channel_ids?: string[];
  event_kinds?: string[];
  min_severity?: string;
  asset_criticalities?: string[];
  asset_types?: string[];
  tags_any?: string[];
  dedup_window_seconds?: number;
  enabled?: boolean;
  description?: string | null;
  quiet_hours?: NotificationQuietHours | null;
}

export interface NotificationDeliveryListParams {
  organization_id: string;
  channel_id?: string;
  rule_id?: string;
  event_kind?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface NotificationDeliveryResponse {
  id: string;
  organization_id: string;
  rule_id: string;
  channel_id: string;
  event_kind: string;
  event_severity: string;
  event_dedup_key: string | null;
  event_payload?: Record<string, unknown>;
  status: string;
  attempts: number;
  response_status: number | null;
  response_body: string | null;
  error_message: string | null;
  latency_ms: number | null;
  delivered_at: string | null;
  rendered_payload?: Record<string, unknown> | null;
  cluster_count?: number | null;
  cluster_dedup_key?: string | null;
  created_at: string;
}

export interface NotificationInboxItemResponse {
  id: string;
  organization_id: string;
  user_id: string | null;
  rule_id: string | null;
  delivery_id: string | null;
  event_kind: string;
  severity: string;
  title: string;
  summary: string | null;
  link_path: string | null;
  payload: Record<string, unknown>;
  read_at: string | null;
  archived_at: string | null;
  created_at: string;
}

export interface NotificationPreferences {
  opt_out_channels: string[];
  max_per_rule_per_hour: number;
  escalation_after_min: number;
  do_not_disturb: boolean;
  dnd_until: string | null;
}

// ---- Intel (CVE / EPSS / KEV / actor playbooks) ---------------------

export interface IntelSyncResponse {
  source: string;
  source_url: string | null;
  rows_ingested: number;
  rows_updated: number;
  succeeded: boolean;
  error: string | null;
}

export interface IntelSyncRow {
  id: string;
  source: string;
  source_url: string | null;
  rows_ingested: number;
  rows_updated: number;
  succeeded: boolean;
  error: string | null;
  triggered_by_user_id: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface CveListParams {
  is_kev?: boolean;
  min_epss?: number;
  severity?: string;
  limit?: number;
}

export interface CveResponse {
  id: string;
  cve_id: string;
  title: string | null;
  description: string | null;
  cvss3_score: number | null;
  cvss3_vector: string | null;
  cvss_severity: string | null;
  cwe_ids: string[];
  references: string[];
  cpes: string[];
  is_kev: boolean;
  kev_added_at: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  published_at: string | null;
  last_modified_at: string | null;
}

export interface ActorPlaybookResponse {
  id: string;
  actor_name: string;
  ttps: string[];
  technique_external_ids: string[];
  prevention_summary: string | null;
  detection_summary: string | null;
  response_summary: string | null;
  updated_at: string;
}

// ---- News / Advisories ----------------------------------------------

export interface NewsFeedResponse {
  id: string;
  organization_id: string | null;
  name: string;
  url: string;
  kind: string;
  enabled: boolean;
  last_fetched_at: string | null;
  last_status: string | null;
  last_error: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface NewsFeedCreatePayload {
  organization_id?: string;
  name: string;
  url: string;
  kind?: string;
  tags?: string[];
}

export interface NewsArticleListParams {
  feed_id?: string;
  cve?: string;
  q?: string;
  limit?: number;
}

export interface NewsArticleResponse {
  id: string;
  url: string;
  feed_id: string | null;
  title: string;
  summary: string | null;
  author: string | null;
  published_at: string | null;
  fetched_at: string;
  cve_ids: string[];
  tags: string[];
}

export interface AdvisoryResponse {
  id: string;
  organization_id: string | null;
  slug: string;
  title: string;
  body_markdown: string;
  severity: string;
  state: string;
  tags: string[];
  cve_ids: string[];
  references: string[];
  published_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  author_user_id: string | null;
  source?: string;
  external_id?: string | null;
  cvss3_score?: number | null;
  epss_score?: number | null;
  is_kev?: boolean;
  affected_products?: { vendor?: string; product?: string }[];
  remediation_steps?: { action?: string; due_date?: string }[];
  triage_state?: string;
  assigned_to_user_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AdvisoryCreatePayload {
  organization_id?: string;
  slug: string;
  title: string;
  body_markdown: string;
  severity: string;
  tags?: string[];
  cve_ids?: string[];
  references?: string[];
}

export interface AdvisoryUpdatePayload {
  title?: string;
  body_markdown?: string;
  severity?: string;
  tags?: string[];
  cve_ids?: string[];
  references?: string[];
}

// ---- MITRE ATT&CK ---------------------------------------------------

export interface MitreSyncReport {
  rows_ingested: number;
  rows_updated: number;
  techniques: number;
  tactics: number;
  mitigations: number;
  duration_ms: number;
}

export interface MitreSyncRow {
  id: string;
  rows_ingested: number;
  rows_updated: number;
  duration_ms: number;
  succeeded: boolean;
  error_message: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface MitreTacticResponse {
  external_id: string;
  name: string;
  description: string | null;
  shortname: string | null;
}

export interface MitreTechniqueResponse {
  external_id: string;
  name: string;
  description: string | null;
  tactics: string[];
  is_subtechnique: boolean;
  parent_external_id: string | null;
  platforms: string[];
  data_sources: string[];
}

export interface MitreMitigationResponse {
  external_id: string;
  name: string;
  description: string | null;
  technique_external_ids: string[];
}

// ---- Security Ratings -----------------------------------------------

export interface SecurityRubric {
  version: string;
  pillar_weights: Record<string, number>;
  grade_thresholds: Record<string, number>;
  pillar_descriptions: Record<string, string>;
}

export interface SecurityRatingResponse {
  id: string;
  organization_id: string;
  scope: string;
  rubric_version: string;
  score: number;
  grade: string;
  is_current: boolean;
  summary: Record<string, unknown>;
  computed_at: string;
  inputs_hash: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityRatingFactor {
  factor_key: string;
  pillar: string;
  label: string;
  description: string | null;
  weight: number;
  raw_score: number;
  weighted_score: number;
  evidence: Record<string, unknown> | null;
}

export interface SecurityRatingDetail extends SecurityRatingResponse {
  factors: SecurityRatingFactor[];
}

// ---- SLA -------------------------------------------------------------

export interface SlaPolicyResponse {
  id: string;
  organization_id: string;
  severity: string;
  first_response_minutes: number;
  remediation_minutes: number;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface SlaPolicyUpsertPayload {
  organization_id: string;
  severity: "critical" | "high" | "medium" | "low";
  first_response_minutes: number;
  remediation_minutes: number;
  description?: string;
}

export interface SlaEvaluateResponse {
  organization_id: string;
  cases_evaluated: number;
  new_breaches: number;
  rows: Array<{
    case_id: string;
    severity: string;
    first_response_breached: boolean;
    remediation_breached: boolean;
    first_response_due_at: string | null;
    remediation_due_at: string | null;
    new_breaches: number;
  }>;
}

// ── CIO Executive Briefing ─────────────────────────────────────────
// Backed by src/api/routes/exec_briefing.py — schemas mirror the
// Pydantic response models there. The briefing is LLM-generated and
// cached 1h; everything else is deterministic per-call aggregation.

export interface ExecBriefingActionItem {
  /**
   * Stable id of a Playbook in the catalogue
   * (src/core/exec_playbooks). The dashboard opens an in-context
   * drawer keyed on this id rather than navigating to a generic
   * /path the LLM hallucinated. Defensive — still nullable in case a
   * cached pre-v2 briefing slips through.
   */
  playbook_id: string;
  title: string;
  rationale: string;
  /**
   * LLM-seeded params for the playbook (only when the playbook
   * declares input_schema). Operator can edit before clicking
   * Execute.
   */
  params?: Record<string, unknown>;
}

// ── Playbook execution layer (src/api/routes/playbooks.py) ─────────

export interface PlaybookStepDescriptor {
  step_id: string;
  title: string;
  description: string;
}

export interface PlaybookDescriptor {
  id: string;
  title: string;
  category: "brand" | "email" | "asset" | "intel";
  description: string;
  cta_label?: string | null;
  requires_approval: boolean;
  requires_input: boolean;
  permission: "analyst" | "admin";
  input_schema?: Record<string, unknown> | null;
  total_steps: number;
  steps: PlaybookStepDescriptor[];
}

export interface PlaybookCatalogResponse {
  items: PlaybookDescriptor[];
}

export interface PlaybookAffectedItem {
  id: string;
  label: string;
  sub_label?: string | null;
  metadata: Record<string, unknown>;
}

export interface PlaybookPreviewResponse {
  summary: string;
  affected_items: PlaybookAffectedItem[];
  warnings: string[];
  can_execute: boolean;
  blocker_reason?: string | null;
  instructions: string[];
  step_index: number;
  step_id: string;
  step_title: string;
  total_steps: number;
}

export type PlaybookStatus =
  | "pending_approval"
  | "approved"
  | "in_progress"
  | "step_complete"
  | "completed"
  | "failed"
  | "denied"
  | "cancelled";

export type PlaybookTrigger = "exec_briefing" | "manual" | "case_copilot";

export interface PlaybookStepResult {
  step: number;
  step_id: string;
  ok: boolean;
  summary: string;
  items: Array<Record<string, unknown>>;
  error?: string | null;
  completed_at: string;
}

export interface PlaybookExecutionResponse {
  id: string;
  organization_id: string;
  playbook_id: string;
  status: PlaybookStatus;
  params: Record<string, unknown>;
  current_step_index: number;
  total_steps: number;
  step_results: PlaybookStepResult[];
  requested_by_user_id?: string | null;
  approver_user_id?: string | null;
  approval_note?: string | null;
  denial_reason?: string | null;
  error_message?: string | null;
  triggered_from: PlaybookTrigger;
  briefing_action_index?: number | null;
  /** Set when the execution was queued by Case Copilot's Apply, or
   *  by an operator opening the drawer from inside a case. */
  case_id?: string | null;
  copilot_run_id?: string | null;
  created_at: string;
  approved_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  failed_at?: string | null;
}

export interface PlaybookHistoryResponse {
  items: PlaybookExecutionResponse[];
  total: number;
}

export interface PlaybookPreviewPayload {
  playbook_id: string;
  organization_id: string;
  params?: Record<string, unknown>;
  step_index?: number;
  execution_id?: string;
}

export interface PlaybookExecutePayload {
  playbook_id: string;
  organization_id: string;
  params?: Record<string, unknown>;
  idempotency_key: string;
  briefing_action_index?: number | null;
  triggered_from?: PlaybookTrigger;
}

export interface ExecBriefingResponse {
  headline: string;
  narrative: string;
  posture_change: "improving" | "stable" | "deteriorating";
  top_actions: ExecBriefingActionItem[];
  confidence: number;
  generated_at: string;
  cached: boolean;
  rubric_grade?: string | null;
  rubric_score?: number | null;
}

export interface ExecTopRiskItem {
  kind: "case" | "exposure" | "suspect_domain" | "kev_match";
  id: string;
  title: string;
  severity: string | null;
  score: number;
  age_days: number;
  evidence: string;
  link: string;
}

export interface ExecTopRisksResponse {
  items: ExecTopRiskItem[];
  generated_at: string;
}

export interface ExecDeltaMetric {
  label: string;
  current: number;
  previous: number;
  delta: number;
  direction: "up" | "down" | "flat";
  interpretation: "good" | "bad" | "neutral";
  note?: string | null;
}

export interface ExecChangesResponse {
  window_days: number;
  metrics: ExecDeltaMetric[];
  generated_at: string;
}

export interface ExecComplianceMetric {
  key: string;
  label: string;
  value: number | string;
  target?: number | string | null;
  status: "ok" | "warn" | "fail" | "unknown";
  note?: string | null;
}

export interface ExecComplianceResponse {
  metrics: ExecComplianceMetric[];
  generated_at: string;
}

export interface ExecSuggestedAction {
  priority: "high" | "medium" | "low";
  title: string;
  detail: string;
  link?: string | null;
  /**
   * When set, the dashboard opens the in-page ActionDrawer keyed on
   * this playbook id instead of navigating via ``link``. Mirrors
   * the AI Briefing pattern.
   */
  playbook_id?: string | null;
  params?: Record<string, unknown>;
}

export interface ExecSuggestedActionsResponse {
  actions: ExecSuggestedAction[];
  generated_at: string;
}

export interface SlaBreachResponse {
  id: string;
  organization_id: string;
  case_id: string;
  kind: "first_response" | "remediation";
  severity: string;
  threshold_minutes: number;
  detected_at: string;
  notified: boolean;
}

export interface SlaTicketBindingResponse {
  id: string;
  organization_id: string;
  case_id: string;
  system: string;
  external_id: string;
  external_url: string | null;
  project_key: string | null;
  status: string | null;
  last_synced_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface SlaTicketBindingCreatePayload {
  organization_id: string;
  case_id: string;
  system: "jira" | "servicenow" | "linear" | "github" | "custom";
  external_id: string;
  external_url?: string;
  project_key?: string;
  status?: string;
}

// ---- Triage Feedback ------------------------------------------------

export interface FeedbackCreatePayload {
  alert_id: string;
  is_true_positive: boolean;
  corrected_category?: string | null;
  corrected_severity?: string | null;
  feedback_notes?: string | null;
}

export interface FeedbackResponse {
  id: string;
  alert_id: string;
  analyst_id: string;
  original_category: string;
  original_severity: string;
  original_confidence: number;
  corrected_category: string | null;
  corrected_severity: string | null;
  is_true_positive: boolean;
  feedback_notes: string | null;
  created_at: string;
}

export interface FeedbackCategoryAccuracy {
  category: string;
  total: number;
  correct: number;
  accuracy: number;
}

export interface FeedbackStats {
  total_feedback: number;
  true_positives: number;
  false_positives: number;
  true_positive_rate: number;
  false_positive_rate: number;
  category_accuracy: FeedbackCategoryAccuracy[];
  confusion_matrix: Array<{ original_category: string; corrected_category: string; count: number }>;
  weekly_trend: Array<{ week_start: string; total: number; true_positives: number; accuracy: number }>;
}

// ---- Evidence Vault -------------------------------------------------

export type EvidenceKindValue =
  | "screenshot"
  | "html"
  | "pdf"
  | "image"
  | "audio"
  | "video"
  | "document"
  | "log"
  | "other"
  | "app_store_listing";

export interface EvidenceListParams {
  organization_id: string;
  kind?: EvidenceKindValue;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface EvidenceBlobResponse {
  id: string;
  organization_id: string;
  asset_id: string | null;
  sha256: string;
  md5: string | null;
  sha1: string | null;
  perceptual_hash: string | null;
  ssdeep: string | null;
  size_bytes: number;
  content_type: string;
  original_filename: string | null;
  kind: string;
  s3_bucket: string;
  s3_key: string;
  is_deleted: boolean;
  deleted_at: string | null;
  deleted_by_user_id: string | null;
  delete_reason: string | null;
  legal_hold?: boolean;
  captured_at: string;
  captured_by_user_id: string | null;
  capture_source: string | null;
  description: string | null;
  extra: Record<string, unknown> | null;
  agent_summary: Record<string, unknown> | null;
  av_scan: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface EvidenceAuditChainEntry {
  sequence: number;
  organization_id: string | null;
  evidence_blob_id: string | null;
  actor_user_id: string | null;
  action: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  prev_chain_hash: string | null;
  chain_hash: string;
  anchor_id: string | null;
  created_at: string;
}

export interface EvidenceAuditChainVerify {
  valid: boolean;
  broken_at_sequence: number | null;
  total_rows: number;
  head_chain_hash: string | null;
}

export interface EvidenceCoCNarrative {
  blob_id: string;
  narrative: string;
  model_id: string | null;
  rendered_at: string;
}

export interface EvidenceSimilarHit {
  id: string;
  sha256: string;
  md5: string | null;
  perceptual_hash: string | null;
  ssdeep: string | null;
  original_filename: string | null;
  content_type: string;
  size_bytes: number;
  distance: number | null;
  method: string;
  captured_at: string;
}

export interface EvidenceSimilarResponse {
  blob_id: string;
  method: string;
  neighbours: EvidenceSimilarHit[];
  summary: string | null;
  model_id: string | null;
}

// ---- Retention ------------------------------------------------------

export type RetentionDeletionMode =
  | "hard_delete"
  | "soft_delete"
  | "anonymise";

export interface RetentionPolicyResponse {
  id: string;
  organization_id: string | null;
  raw_intel_days: number;
  alerts_days: number;
  audit_logs_days: number;
  iocs_days: number;
  redact_pii: boolean;
  auto_cleanup_enabled: boolean;
  deletion_mode: RetentionDeletionMode;
  compliance_mappings: string[];
  description: string | null;
  last_cleanup_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RetentionPolicyCreatePayload {
  organization_id?: string;
  raw_intel_days?: number;
  alerts_days?: number;
  audit_logs_days?: number;
  iocs_days?: number;
  redact_pii?: boolean;
  auto_cleanup_enabled?: boolean;
  deletion_mode?: RetentionDeletionMode;
  compliance_mappings?: string[];
  description?: string | null;
}

export interface RetentionPolicyUpdatePayload {
  raw_intel_days?: number;
  alerts_days?: number;
  audit_logs_days?: number;
  iocs_days?: number;
  redact_pii?: boolean;
  auto_cleanup_enabled?: boolean;
  deletion_mode?: RetentionDeletionMode;
  compliance_mappings?: string[];
  description?: string | null;
}

export interface RetentionComplianceFramework {
  id: string;
  name: string;
  full_text: string;
  default_retention_days: number;
  citation_url: string;
}

export interface RetentionRegulationSuggestion {
  alerts_days: number;
  audit_logs_days: number;
  raw_intel_days: number;
  iocs_days: number;
  deletion_mode: RetentionDeletionMode;
  compliance_mappings: string[];
  rationale_per_class: Record<string, string>;
  model_id: string | null;
  raw_response: string;
}

export type DsarRequestType =
  | "access"
  | "erasure"
  | "portability"
  | "rectification"
  | "restriction";

export type DsarStatus =
  | "received"
  | "scanning"
  | "ready_for_review"
  | "exported"
  | "closed"
  | "denied";

export interface DsarRequestResponse {
  id: string;
  organization_id: string;
  requested_by_user_id: string | null;
  subject_email: string | null;
  subject_name: string | null;
  subject_phone: string | null;
  subject_id_other: string | null;
  request_type: DsarRequestType;
  regulation: string | null;
  status: DsarStatus;
  deadline_at: string | null;
  matched_tables: string[];
  match_summary: Record<string, { count: number; sample_ids?: string[]; matched_columns?: string[] }>;
  matched_row_count: number;
  draft_response: string | null;
  final_response: string | null;
  notes: string | null;
  closed_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface DsarCreatePayload {
  organization_id: string;
  subject_email?: string | null;
  subject_name?: string | null;
  subject_phone?: string | null;
  subject_id_other?: string | null;
  request_type: DsarRequestType;
  regulation?: string | null;
  notes?: string | null;
  deadline_days?: number;
}

export interface RetentionAttestationResponse {
  id: string;
  organization_id: string | null;
  summary_md: string;
  rows_summarised: number;
  window_start: string | null;
  window_end: string | null;
  model_id: string | null;
  created_at: string;
}

export interface RetentionCleanupResult {
  raw_intel_deleted: number;
  alerts_deleted: number;
  audit_logs_deleted: number;
  iocs_deleted: number;
  news_articles_deleted: number;
  live_probes_deleted: number;
  dlp_findings_deleted: number;
  card_leakage_findings_deleted: number;
  dmarc_reports_deleted: number;
  sla_breach_events_deleted: number;
  total_deleted: number;
  policy_id: string;
  cleanup_at: string;
  dry_run?: boolean;
}

export interface RetentionStats {
  raw_intel_count: number;
  raw_intel_oldest: string | null;
  raw_intel_would_delete: number;
  alerts_count: number;
  alerts_oldest: string | null;
  alerts_would_delete: number;
  audit_logs_count: number;
  audit_logs_oldest: string | null;
  audit_logs_would_delete: number;
  iocs_count: number;
  iocs_oldest: string | null;
  iocs_would_delete: number;
}

export interface LegalHoldPayload {
  resource_type: "evidence_blobs" | "cases" | "audit_logs";
  resource_id: string;
  legal_hold: boolean;
  reason?: string;
}

/* ─────────── Compliance Evidence Pack types (P1 #1.3) ─────────── */

export interface ComplianceFrameworkSummary {
  id: string;
  code: string;
  name_en: string;
  name_ar: string | null;
  version: string;
  source_url: string | null;
  description_en: string | null;
  description_ar: string | null;
}

export type ComplianceExportLanguageMode = "en" | "ar" | "bilingual";
export type ComplianceExportFormat = "pdf" | "json";
export type ComplianceExportStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "expired";

export interface ComplianceExportRequest {
  framework_code: string;
  language_mode: ComplianceExportLanguageMode;
  format: ComplianceExportFormat;
  period_from: string;
  period_to: string;
}

export interface ComplianceExportResponse {
  id: string;
  organization_id: string;
  framework_id: string;
  framework_code: string;
  framework_name_en: string;
  requested_by_user_id: string | null;
  language_mode: ComplianceExportLanguageMode;
  format: ComplianceExportFormat;
  period_from: string | null;
  period_to: string | null;
  status: ComplianceExportStatus;
  hash_sha256: string | null;
  byte_size: number | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  expires_at: string;
}

/* ───────── Locale (P1 #1.2 — Hijri / Asia/Riyadh) ───────── */

export interface LocaleResponse {
  timezone: string;
  calendar_system: string;
  supported: {
    timezones: readonly string[];
    calendars: readonly string[];
    defaults: { timezone: string; calendar_system: string };
  };
}


// ── P3 connector types ─────────────────────────────────────────────

export type P3ConnectorGroup =
  | "edr"
  | "email-gateway"
  | "sandbox"
  | "soar"
  | "breach";

export const P3_GROUP_PATH: Record<P3ConnectorGroup, string> = {
  edr: "edr/connectors",
  "email-gateway": "email-gateway/connectors",
  sandbox: "sandbox/connectors",
  soar: "soar/connectors",
  breach: "breach/providers",
};

export interface ConnectorRow {
  name: string;
  label?: string;
  configured: boolean;
}

export interface ConnectorHealth {
  success?: boolean;
  note?: string | null;
  error?: string | null;
  // Group-specific result fields are tolerated here.
  [extra: string]: unknown;
}

export interface TelegramChannel {
  handle: string;
  cluster: string;
  language: string;
  rationale: string;
  actor_link: string | null;
  status: string;
  region_focus: string[];
}

export interface FeedSubscriptionChannelEntry {
  type: "webhook" | "email" | "slack";
  url?: string;
  address?: string;
  secret?: string;
}

export interface FeedSubscriptionRow {
  id: string;
  name: string;
  description: string | null;
  filter: Record<string, unknown>;
  channels: FeedSubscriptionChannelEntry[];
  active: boolean;
  last_dispatched_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface FeedSubscriptionCreate {
  name: string;
  description?: string | null;
  filter: Record<string, unknown>;
  channels: FeedSubscriptionChannelEntry[];
  active?: boolean;
}


// ── OSS-tools onboarding ────────────────────────────────────────

export interface OssToolCatalogEntry {
  name: string;
  label: string;
  summary: string;
  capability: string;
  ram_estimate_mb: number;
  disk_estimate_gb: number;
  compose_profile: string;
  env_vars: Record<string, string>;
  docs_url: string | null;
  is_heavyweight: boolean;
  post_install_action: string | null;
}

export interface OssToolState {
  tool_name: string;
  state: "pending" | "installing" | "installed" | "failed" | "disabled";
  installed_at: string | null;
  last_attempt_at: string | null;
  error_message: string | null;
}

export interface OssPreflight {
  enabled: boolean;
  host_project: string;
  host_project_mounted: boolean;
  docker_sock_mounted: boolean;
  ready: boolean;
  issues: string[];
}
