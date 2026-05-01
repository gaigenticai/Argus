# @argus/sdk

Official TypeScript / JavaScript client for the Argus / Marsad
threat-intelligence platform.

```bash
npm install @argus/sdk
```

```ts
import { ArgusClient } from '@argus/sdk';

const argus = new ArgusClient({
  baseUrl: 'https://argus.bank.example',
  apiKey:  'argus_...',
});

for (const a of await argus.alerts.list({ severity: 'critical' })) {
  console.log(a.title);
}

// User-self-service feed subscription with a webhook delivery
const sub = await argus.subscriptions.create({
  name: 'Phishing → SOC webhook',
  filter: { severity: ['critical', 'high'], category: ['phishing'] },
  channels: [{ type: 'webhook', url: 'https://soc.bank/argus' }],
});
```

## Authentication

- **API key** — pass `apiKey` at construction. Sent as `X-API-Key`.
- **Username / password** — call `await argus.login(email, password)`
  after construction. Stores the JWT access token on the client.
- Bearer token wins when both are set.

## Errors

Every non-2xx response throws `ArgusError`:

```ts
import { ArgusError } from '@argus/sdk';

try {
  await argus.alerts.get('nope');
} catch (err) {
  if (err instanceof ArgusError && err.status === 404) {
    /* ... */
  }
}
```

## Runtime

Zero runtime dependencies. Uses the platform's built-in `fetch`. Tested
on Node ≥18, Deno, Bun, and modern browsers. For older Node, pass a
`fetch` implementation:

```ts
import nodeFetch from 'node-fetch';
new ArgusClient({ baseUrl: '...', fetch: nodeFetch as never });
```

## Schema

The full OpenAPI 3.1 schema is checked in at
[`clients/openapi/argus.openapi.json`](../../openapi/argus.openapi.json).
For full coverage beyond what this hand-written client exposes, run
the codegen script:

```bash
scripts/generate_sdks.sh ts
```
