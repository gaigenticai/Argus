"use client";

/**
 * TAXII discovery page (P3 #3.4 — closes the audit's "no dashboard
 * surface for TAXII discovery" demo-killer).
 *
 * One screen the customer can hand to their downstream Splunk ES /
 * Anomali / ThreatConnect engineer:
 *
 *   - Discovery URL
 *   - API root URL
 *   - Collection ID + URL
 *   - "Copy" buttons + a Bearer-token banner reminding the operator
 *     to mint an API key for the subscriber rather than re-using a
 *     human user's JWT.
 */

import { useEffect, useState } from "react";
import { Copy, ExternalLink, Loader2, Rss } from "lucide-react";
import { useToast } from "@/components/shared/toast";


export default function TaxiiPage() {
  const [origin, setOrigin] = useState<string>("");
  const [collectionId, setCollectionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    setOrigin(window.location.origin);
    // Fetch the collection list to surface the live id. The TAXII
    // routes are mounted at the root, not under /api/v1, so we hit
    // them directly with the user's bearer token.
    const token = localStorage.getItem("argus_access_token") || "";
    fetch("/taxii2/api/collections/", {
      headers: {
        Accept: "application/taxii+json;version=2.1",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const body = await r.json();
        const id = body?.collections?.[0]?.id ?? null;
        setCollectionId(id);
      })
      .catch(() => setCollectionId(null))
      .finally(() => setLoading(false));
  }, []);

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast("success", `${label} copied`);
    } catch {
      toast("error", "Copy failed — your browser blocked clipboard access");
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex items-center gap-3">
        <Rss className="size-6 text-[var(--color-accent)]" aria-hidden />
        <div>
          <h1 className="text-2xl font-semibold">TAXII 2.1 publish</h1>
          <p className="text-sm text-[var(--color-muted)]">
            Wire your downstream Splunk ES / Anomali / ThreatConnect /
            OpenCTI / MISP at the URLs below. Argus serves STIX 2.1
            indicators per TAXII 2.1.
          </p>
        </div>
      </header>

      <div className="rounded-md border border-[var(--color-border)] bg-[rgba(255,171,0,0.08)] p-3 text-sm text-[#996200]">
        <strong>Use a service API key</strong> as the subscriber's
        Bearer token, not a human user's JWT. Mint one at{" "}
        <a className="underline" href="/settings">
          Settings → API keys
        </a>{" "}
        and assign it the analyst role.
      </div>

      <div className="space-y-3">
        <UrlRow
          label="Discovery URL"
          value={`${origin}/taxii2/`}
          onCopy={(v) => copy("Discovery URL", v)}
        />
        <UrlRow
          label="API root"
          value={`${origin}/taxii2/api/`}
          onCopy={(v) => copy("API root", v)}
        />
        <UrlRow
          label="Collections list"
          value={`${origin}/taxii2/api/collections/`}
          onCopy={(v) => copy("Collections URL", v)}
        />
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-[var(--color-muted)]">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            Resolving collection id…
          </div>
        ) : collectionId ? (
          <>
            <UrlRow
              label="Collection id"
              value={collectionId}
              onCopy={(v) => copy("Collection ID", v)}
              mono
            />
            <UrlRow
              label="Objects endpoint"
              value={`${origin}/taxii2/api/collections/${collectionId}/objects/`}
              onCopy={(v) => copy("Objects URL", v)}
            />
          </>
        ) : (
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] p-3 text-xs text-[var(--color-muted)]">
            Collection id unavailable — make sure the deployment has at
            least one organization row and that you're authenticated.
          </div>
        )}
      </div>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-sm">
        <h2 className="text-base font-medium">curl example</h2>
        <p className="mt-1 text-xs text-[var(--color-muted)]">
          Stream every indicator added since 2026-04-01:
        </p>
        <pre className="mt-2 overflow-x-auto rounded-md bg-[var(--color-surface-muted)] p-3 text-xs">
          {`curl -H "Accept: application/taxii+json;version=2.1" \\
     -H "Authorization: Bearer <ARGUS_API_KEY>" \\
     "${origin}/taxii2/api/collections/${collectionId ?? "<COLLECTION_ID>"}/objects/?added_after=2026-04-01T00:00:00Z"`}
        </pre>
      </div>

      <p className="text-xs text-[var(--color-muted)]">
        Spec reference:{" "}
        <a
          className="inline-flex items-center gap-1 underline"
          href="https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html"
          target="_blank"
          rel="noreferrer noopener"
        >
          OASIS TAXII 2.1
          <ExternalLink className="size-3" aria-hidden />
        </a>
      </p>
    </div>
  );
}


function UrlRow({
  label,
  value,
  onCopy,
  mono = false,
}: {
  label: string;
  value: string;
  onCopy: (v: string) => void;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
      <div className="w-32 shrink-0 text-xs uppercase text-[var(--color-muted)]">
        {label}
      </div>
      <code
        className={
          "flex-1 truncate rounded bg-[var(--color-surface-muted)] px-2 py-1 text-xs " +
          (mono ? "font-mono" : "")
        }
        title={value}
      >
        {value}
      </code>
      <button
        type="button"
        onClick={() => onCopy(value)}
        className="inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs hover:bg-[var(--color-surface-muted)]"
      >
        <Copy className="size-3" aria-hidden />
        Copy
      </button>
    </div>
  );
}
