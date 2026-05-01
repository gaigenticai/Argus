/**
 * Argus TypeScript SDK — unit tests using a fake fetch.
 *
 * The integration suite is in tests/test_python_sdk.py for the Python
 * client; this file covers the TypeScript-specific surface — header
 * priority, error handling, JSON serdes — using a stubbed `fetch` so
 * we don't need a running backend.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ArgusClient, ArgusError } from '../src/index.ts';

function fakeFetch(handler: (url: string, init: RequestInit) => Response) {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    return handler(url, init ?? {});
  };
}

function jsonResp(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('ArgusClient', () => {
  it('sends X-API-Key when only api_key is set', async () => {
    let captured: Record<string, string> | undefined;
    const fetch = fakeFetch((_url, init) => {
      captured = init.headers as Record<string, string>;
      return jsonResp(200, []);
    });
    const c = new ArgusClient({
      baseUrl: 'http://x', apiKey: 'k1', fetch,
    });
    await c.alerts.list();
    assert.equal(captured?.['X-API-Key'], 'k1');
    assert.ok(!('Authorization' in (captured ?? {})));
  });

  it('prefers Bearer token over api_key when both are set', async () => {
    let captured: Record<string, string> | undefined;
    const fetch = fakeFetch((_u, init) => {
      captured = init.headers as Record<string, string>;
      return jsonResp(200, []);
    });
    const c = new ArgusClient({
      baseUrl: 'http://x', apiKey: 'k1',
      accessToken: 't1', fetch,
    });
    await c.alerts.list();
    assert.equal(captured?.Authorization, 'Bearer t1');
    assert.ok(!('X-API-Key' in (captured ?? {})));
  });

  it('login() captures the access_token', async () => {
    const fetch = fakeFetch((url) => {
      assert.ok(url.endsWith('/api/v1/auth/login'));
      return jsonResp(200, { access_token: 'jwt-abc' });
    });
    const c = new ArgusClient({ baseUrl: 'http://x', fetch });
    await c.login('a@b', 'pw');
    let captured: Record<string, string> | undefined;
    const fetch2 = fakeFetch((_u, init) => {
      captured = init.headers as Record<string, string>;
      return jsonResp(200, []);
    });
    // Swap fetch for the next call without re-authenticating.
    (c as unknown as { _fetch: typeof fetch2 })._fetch = fetch2;
    await c.alerts.list();
    assert.equal(captured?.Authorization, 'Bearer jwt-abc');
  });

  it('throws ArgusError on 4xx with parsed detail', async () => {
    const fetch = fakeFetch(() =>
      jsonResp(404, { detail: 'alert not found' }),
    );
    const c = new ArgusClient({
      baseUrl: 'http://x', accessToken: 't', fetch,
    });
    await assert.rejects(
      () => c.alerts.get('nope'),
      (err: unknown) => err instanceof ArgusError &&
                         err.status === 404 &&
                         err.detail === 'alert not found',
    );
  });

  it('builds query parameters from alert filters', async () => {
    let capturedUrl = '';
    const fetch = fakeFetch((url) => {
      capturedUrl = url;
      return jsonResp(200, []);
    });
    const c = new ArgusClient({
      baseUrl: 'http://x', accessToken: 't', fetch,
    });
    await c.alerts.list({ severity: 'critical', limit: 10 });
    const u = new URL(capturedUrl);
    assert.equal(u.searchParams.get('severity'), 'critical');
    assert.equal(u.searchParams.get('limit'), '10');
  });

  it('subscriptions.create posts the right body', async () => {
    let capturedBody = '';
    const fetch = fakeFetch((_u, init) => {
      capturedBody = init.body as string;
      return jsonResp(201, { id: 's-1', name: 'test' });
    });
    const c = new ArgusClient({
      baseUrl: 'http://x', accessToken: 't', fetch,
    });
    const out = await c.subscriptions.create({
      name: 'test',
      filter: { severity: ['critical'] },
      channels: [{ type: 'webhook', url: 'https://x/h' }],
    }) as { id: string; name: string };
    assert.equal(out.id, 's-1');
    const parsed = JSON.parse(capturedBody);
    assert.equal(parsed.name, 'test');
    assert.equal(parsed.active, true);
    assert.equal(parsed.channels[0].type, 'webhook');
  });

  it('intel.sigmaBackends unwraps {backends: [...]} response', async () => {
    const fetch = fakeFetch(() =>
      jsonResp(200, { backends: ['splunk_spl', 'elastic_eql'] }),
    );
    const c = new ArgusClient({
      baseUrl: 'http://x', accessToken: 't', fetch,
    });
    const out = await c.intel.sigmaBackends();
    assert.deepEqual(out, ['splunk_spl', 'elastic_eql']);
  });

  it('handles 204 No Content', async () => {
    const fetch = fakeFetch(() => new Response(null, { status: 204 }));
    const c = new ArgusClient({
      baseUrl: 'http://x', accessToken: 't', fetch,
    });
    await c.subscriptions.delete('s-1');  // no throw
  });

  it('omits credentials when authRequired=false (login path)', async () => {
    let captured: Record<string, string> | undefined;
    const fetch = fakeFetch((_u, init) => {
      captured = init.headers as Record<string, string>;
      return jsonResp(200, { access_token: 'x' });
    });
    const c = new ArgusClient({
      baseUrl: 'http://x', apiKey: 'pre-existing', fetch,
    });
    await c.login('a@b', 'pw');
    assert.ok(!('X-API-Key' in (captured ?? {})));
  });
});
