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
  getActorNavigatorLayerUrl: (id: string, matrix: "enterprise" | "ics" = "enterprise") =>
    `${API_BASE}/actors/${id}/navigator-layer?matrix=${matrix}`,

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
    request<{ message: string; status: string }>(`/feeds/triage?hours=${hours}`, { method: "POST" }),
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
    create: () =>
      request<{ id: string; status: string }>(`/threat-hunts`, {
        method: "POST",
      }),
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
  },

  tprm: {
    seedTemplates: () =>
      request<TprmTemplateResponse[]>("/tprm/templates/seed-builtins", {
        method: "POST",
      }),
    listTemplates: () => request<TprmTemplateResponse[]>("/tprm/templates"),
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
  },

  exec: {
    // The backend's /exec-summary endpoint streams a PDF — there is no
    // JSON variant. The dashboard's Exec Summary page builds the view
    // from individual rollup endpoints (cases.count, brand.overview,
    // ratings.current, sla.listBreaches) and offers this download for
    // board-meeting export.
    downloadPdf: (params: { organization_id: string; days?: number }) =>
      requestBlob(`/exec-summary${_qs(params)}`),
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
        body: JSON.stringify(body),
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
        body: JSON.stringify(body),
      }),
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
  },

  mitre: {
    sync: () =>
      request<MitreSyncReport>("/mitre/sync", { method: "POST" }),
    listSyncs: () => request<MitreSyncRow[]>("/mitre/syncs"),
    listTactics: () => request<MitreTacticResponse[]>("/mitre/tactics"),
    listTechniques: (params?: { tactic?: string }) =>
      request<MitreTechniqueResponse[]>(`/mitre/techniques${_qs(params)}`),
    getTechnique: (externalId: string) =>
      request<MitreTechniqueResponse>(`/mitre/techniques/${externalId}`),
    listMitigations: () =>
      request<MitreMitigationResponse[]>("/mitre/mitigations"),
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
    runCleanup: () =>
      request<RetentionCleanupResult[]>("/retention/cleanup", {
        method: "POST",
      }),
    stats: () => request<RetentionStats>("/retention/stats"),
    setLegalHold: (body: LegalHoldPayload) =>
      request<void>("/retention/legal-hold", {
        method: "POST",
        body: JSON.stringify(body),
      }),
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
  | "fraud" | "impersonation" | "brand" | "rating" | "auto_case" | "crawler" | "general";

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
  | "ransomware_leak_group" | "stealer_marketplace";

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

export type InvestigationStatus = "queued" | "running" | "completed" | "failed";

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
}

export interface InvestigationTraceStep {
  iteration: number;
  thought: string;
  tool: string | null;
  args: Record<string, unknown> | null;
  result: unknown;
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
}

// ---- Agent admin (posture + settings + cross-agent feed) -----------

export interface AgentPosture {
  human_in_loop_required: boolean;
  features: Record<string, boolean>;
  env_vars: Record<string, string>;
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

export interface CopilotRunDetail extends CopilotRunListItem {
  summary: string | null;
  timeline_events: CopilotTimelineEvent[] | null;
  suggested_mitre_ids: string[] | null;
  draft_next_steps: string[] | null;
  similar_case_ids: string[] | null;
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
}

// ---- Agentic brand defence -----------------------------------------

export type BrandActionStatus = "queued" | "running" | "completed" | "failed";
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
}

export interface BrandActionDetail extends BrandActionListItem {
  recommendation_reason: string | null;
  trace: InvestigationTraceStep[] | null;
  error_message: string | null;
  started_at: string | null;
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
  alert_id: string;
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
  q?: string;
  limit?: number;
  offset?: number;
}

export interface ExposureResponse {
  id: string;
  organization_id: string;
  asset_id: string | null;
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
  created_at: string;
  updated_at: string;
}

export interface ExposureStatePayload {
  state: ExposureStateValue;
  reason?: string;
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
  | "under_review"
  | "approved"
  | "rejected"
  | "on_hold";

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
  | "manual";

export type TakedownTargetKindValue =
  | "suspect_domain"
  | "impersonation"
  | "mobile_app"
  | "fraud"
  | "other";

export interface TakedownPartnerInfo {
  partners: TakedownPartnerValue[];
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
  submitted_at: string;
  acknowledged_at: string | null;
  succeeded_at: string | null;
  failed_at: string | null;
  proof_evidence_sha256: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
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
  validated: number;
  bin_matched: number;
  new_findings: number;
  duplicates: number;
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
}

// ---- Notifications --------------------------------------------------

export type NotificationChannelKind =
  | "slack"
  | "teams"
  | "email"
  | "webhook"
  | "pagerduty"
  | "opsgenie"
  | "sms"
  | "jasmin";

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
}

export interface NotificationDeliveryListParams {
  organization_id: string;
  channel_id?: string;
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
  status: string;
  attempts: number;
  response_status: number | null;
  response_body: string | null;
  error_message: string | null;
  latency_ms: number | null;
  delivered_at: string | null;
  created_at: string;
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
  captured_at: string;
  captured_by_user_id: string | null;
  capture_source: string | null;
  description: string | null;
  extra: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

// ---- Retention ------------------------------------------------------

export interface RetentionPolicyResponse {
  id: string;
  organization_id: string | null;
  raw_intel_days: number;
  alerts_days: number;
  audit_logs_days: number;
  iocs_days: number;
  redact_pii: boolean;
  auto_cleanup_enabled: boolean;
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
}

export interface RetentionPolicyUpdatePayload {
  raw_intel_days?: number;
  alerts_days?: number;
  audit_logs_days?: number;
  iocs_days?: number;
  redact_pii?: boolean;
  auto_cleanup_enabled?: boolean;
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
