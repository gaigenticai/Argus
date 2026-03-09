const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

// Organizations
export const api = {
  // Orgs
  getOrgs: () => request<Org[]>("/organizations/"),
  createOrg: (data: CreateOrg) =>
    request<Org>("/organizations/", { method: "POST", body: JSON.stringify(data) }),
  getOrg: (id: string) => request<Org>(`/organizations/${id}`),
  addVip: (orgId: string, data: CreateVip) =>
    request(`/organizations/${orgId}/vips`, { method: "POST", body: JSON.stringify(data) }),
  getVips: (orgId: string) => request<Vip[]>(`/organizations/${orgId}/vips`),
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

  // Scanning
  scanSubdomains: (orgId: string) =>
    request(`/scan/${orgId}/subdomains`, { method: "POST" }),
  scanExposures: (orgId: string) =>
    request(`/scan/${orgId}/exposures`, { method: "POST" }),

  // Reports
  generateReport: (orgId: string, dateFrom: string, dateTo: string) =>
    fetch(`${API_BASE}/reports/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ org_id: orgId, date_from: dateFrom, date_to: dateTo }),
    }),
  getReports: () => request<Report[]>("/reports/"),

  // Webhooks
  getWebhookConfig: () => request<WebhookConfig>("/webhooks/config"),
  testWebhook: () => request("/webhooks/test", { method: "POST" }),
};

// Types
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
