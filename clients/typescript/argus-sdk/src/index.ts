/**
 * Argus TypeScript / JavaScript SDK (P3 #3.4).
 *
 * Hand-written thin wrapper over the Argus REST API. Uses the
 * platform's built-in fetch, so the SDK has zero runtime dependencies
 * and works in Node ≥18, Deno, Bun, and modern browsers.
 *
 * Usage:
 *
 *   import { ArgusClient } from '@argus/sdk';
 *
 *   const argus = new ArgusClient({
 *     baseUrl: 'https://argus.bank.example',
 *     apiKey:  'argus_...',
 *   });
 *   for (const a of await argus.alerts.list({ severity: 'critical' })) {
 *     console.log(a.title);
 *   }
 *
 * For username/password auth:
 *
 *   await argus.login('alice@bank', 'password');
 *
 * Errors:
 *   Any non-2xx response throws ArgusError with `status` and `detail`.
 */

export class ArgusError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly requestUrl: string;

  constructor(status: number, detail: string, requestUrl = '') {
    super(`HTTP ${status}: ${detail}`);
    this.name = 'ArgusError';
    this.status = status;
    this.detail = detail;
    this.requestUrl = requestUrl;
  }
}

export interface ArgusClientOptions {
  baseUrl: string;
  apiKey?: string;
  accessToken?: string;
  /** Custom fetch implementation (e.g. node-fetch in older Node). */
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds. Default 30 000. */
  timeoutMs?: number;
}

export interface AlertFilter {
  severity?: string;
  status?: string;
  category?: string;
  limit?: number;
  offset?: number;
}

export interface FeedSubscriptionChannel {
  type: 'webhook' | 'email' | 'slack';
  url?: string;
  address?: string;
  secret?: string;
}

export interface CreateSubscriptionInput {
  name: string;
  filter: Record<string, unknown>;
  channels: FeedSubscriptionChannel[];
  active?: boolean;
}

export class ArgusClient {
  readonly baseUrl: string;
  private apiKey: string;
  private accessToken: string;
  private readonly _fetch: typeof fetch;
  private readonly timeoutMs: number;

  readonly alerts: AlertsResource;
  readonly iocs: IOCsResource;
  readonly feeds: FeedsResource;
  readonly subscriptions: SubscriptionsResource;
  readonly intel: IntelResource;

  constructor(opts: ArgusClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.apiKey = opts.apiKey ?? '';
    this.accessToken = opts.accessToken ?? '';
    this._fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.alerts = new AlertsResource(this);
    this.iocs = new IOCsResource(this);
    this.feeds = new FeedsResource(this);
    this.subscriptions = new SubscriptionsResource(this);
    this.intel = new IntelResource(this);
  }

  /** POST /api/v1/auth/login — captures and stores the access token. */
  async login(email: string, password: string): Promise<this> {
    const out = await this._postJson(
      '/api/v1/auth/login',
      { email, password },
      { authRequired: false },
    ) as { access_token?: string };
    if (!out.access_token) {
      throw new ArgusError(500, 'no access_token in login response');
    }
    this.accessToken = out.access_token;
    return this;
  }

  // — Internal request plumbing —

  /** @internal */
  _headers(authRequired = true): Record<string, string> {
    const h: Record<string, string> = { Accept: 'application/json' };
    if (authRequired) {
      if (this.accessToken) h.Authorization = `Bearer ${this.accessToken}`;
      else if (this.apiKey) h['X-API-Key'] = this.apiKey;
    }
    return h;
  }

  /** @internal */
  async _request(
    method: string, path: string,
    opts: { body?: unknown; query?: Record<string, unknown>;
            authRequired?: boolean } = {},
  ): Promise<unknown> {
    const url = new URL(this.baseUrl + path);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v === undefined || v === null) continue;
        url.searchParams.set(k, String(v));
      }
    }
    const headers = this._headers(opts.authRequired ?? true);
    const init: RequestInit = { method, headers };
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    init.signal = ctrl.signal;
    let resp: Response;
    try {
      resp = await this._fetch(url.toString(), init);
    } finally {
      clearTimeout(t);
    }
    if (!resp.ok) {
      let detail = '';
      const text = await resp.text();
      try {
        const j = JSON.parse(text);
        detail = (j as { detail?: string }).detail ?? text;
      } catch {
        detail = text;
      }
      throw new ArgusError(resp.status, String(detail).slice(0, 500),
                            url.toString());
    }
    if (resp.status === 204) return undefined;
    const ct = resp.headers.get('content-type') ?? '';
    if (ct.startsWith('application/json')) return resp.json();
    return resp.text();
  }

  /** @internal */
  async _getJson(path: string, query?: Record<string, unknown>) {
    return this._request('GET', path, { query });
  }
  /** @internal */
  async _postJson(path: string, body: unknown,
                   { authRequired = true }: { authRequired?: boolean } = {}) {
    return this._request('POST', path, { body, authRequired });
  }
  /** @internal */
  async _delete(path: string) {
    return this._request('DELETE', path);
  }
}

// ── Resource sub-clients ────────────────────────────────────────────

class AlertsResource {
  constructor(private readonly p: ArgusClient) {}
  async list(f: AlertFilter = {}): Promise<unknown[]> {
    const q: Record<string, unknown> = {
      limit: f.limit ?? 100, offset: f.offset ?? 0,
    };
    if (f.severity) q.severity = f.severity;
    if (f.status) q.status = f.status;
    if (f.category) q.category = f.category;
    return await this.p._getJson('/api/v1/alerts/', q) as unknown[];
  }
  async get(id: string): Promise<unknown> {
    return await this.p._getJson(`/api/v1/alerts/${id}`);
  }
}

class IOCsResource {
  constructor(private readonly p: ArgusClient) {}
  async list(opts: { iocType?: string; limit?: number;
                      offset?: number } = {}): Promise<unknown[]> {
    const q: Record<string, unknown> = {
      limit: opts.limit ?? 100, offset: opts.offset ?? 0,
    };
    if (opts.iocType) q.ioc_type = opts.iocType;
    return await this.p._getJson('/api/v1/iocs/', q) as unknown[];
  }
}

class FeedsResource {
  constructor(private readonly p: ArgusClient) {}
  async list(): Promise<unknown[]> {
    return await this.p._getJson('/api/v1/feeds') as unknown[];
  }
}

class SubscriptionsResource {
  constructor(private readonly p: ArgusClient) {}
  async list(): Promise<unknown[]> {
    return await this.p._getJson('/api/v1/feed-subscriptions') as unknown[];
  }
  async create(body: CreateSubscriptionInput): Promise<unknown> {
    return await this.p._postJson('/api/v1/feed-subscriptions', {
      name: body.name,
      filter: body.filter,
      channels: body.channels,
      active: body.active ?? true,
    });
  }
  async delete(id: string): Promise<void> {
    await this.p._delete(`/api/v1/feed-subscriptions/${id}`);
  }
}

class IntelResource {
  constructor(private readonly p: ArgusClient) {}
  async sigmaBackends(): Promise<string[]> {
    const out = await this.p._getJson('/api/v1/intel/sigma/backends') as
      { backends?: string[] } | string[];
    if (Array.isArray(out)) return out;
    return out.backends ?? [];
  }
  async yaraAvailability(): Promise<unknown> {
    return await this.p._getJson('/api/v1/intel/yara/availability');
  }
  async taxiiCollections(): Promise<unknown> {
    // TAXII 2.1 mounts collections under the api-root: /taxii2/api/collections/
    // (per the spec — see src/api/routes/taxii.py and the TAXII RFC §4).
    return await this.p._getJson('/taxii2/api/collections/');
  }
  async cves(opts: { cveId?: string; limit?: number } = {}): Promise<unknown> {
    if (opts.cveId) {
      return await this.p._getJson(`/api/v1/intel/cves/${opts.cveId}`);
    }
    return await this.p._getJson('/api/v1/intel/cves',
                                   { limit: opts.limit ?? 100 });
  }
}

export default ArgusClient;
