"use client";

/**
 * TAXII discovery page (P3 #3.4).
 */

import { useEffect, useState } from "react";
import { Copy, ExternalLink, Rss, ShieldAlert } from "lucide-react";
import {
  Empty,
  PageHeader,
  Section,
  SkeletonRows,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";


export default function TaxiiPage() {
  const [origin, setOrigin] = useState<string>("");
  const [collectionId, setCollectionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    setOrigin(window.location.origin);
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
        if (!id) throw new Error("no collections returned");
        setCollectionId(id);
      })
      .catch((err) => setError((err as Error).message))
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
      <PageHeader
        eyebrow={{ icon: Rss, label: "TAXII 2.1 publish" }}
        title="Argus as a TAXII feed"
        description="Wire your downstream Splunk ES / Anomali / ThreatConnect / OpenCTI / MISP at the URLs below. Argus serves STIX 2.1 indicators per the TAXII 2.1 spec; subscribers paginate via ?added_after."
      />

      <Section>
        <div
          className="px-5 py-3 flex items-start gap-2"
          style={{
            background: "rgba(245,158,11,0.05)",
            borderBottom: "1px solid var(--color-border)",
            color: "var(--color-warning-dark)",
          }}
        >
          <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
          <div className="text-[12px]">
            <strong>Use a service API key</strong> as the subscriber's Bearer
            token, not a human user's JWT. Mint one under{" "}
            <a className="underline" href="/settings">
              Settings → API keys
            </a>{" "}
            and assign it the analyst role.
          </div>
        </div>

        <div className="px-5 py-4 space-y-2">
          <UrlRow
            label="Discovery URL"
            value={origin ? `${origin}/taxii2/` : ""}
            onCopy={(v) => copy("Discovery URL", v)}
          />
          <UrlRow
            label="API root"
            value={origin ? `${origin}/taxii2/api/` : ""}
            onCopy={(v) => copy("API root", v)}
          />
          <UrlRow
            label="Collections list"
            value={origin ? `${origin}/taxii2/api/collections/` : ""}
            onCopy={(v) => copy("Collections URL", v)}
          />
          {loading ? (
            <SkeletonRows rows={1} columns={3} />
          ) : error ? (
            <Empty
              icon={Rss}
              title="Collection id unavailable"
              description={`Resolving the live collection failed: ${error}. Make sure the deployment has at least one organization row and that you're authenticated.`}
            />
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
                value={
                  origin
                    ? `${origin}/taxii2/api/collections/${collectionId}/objects/`
                    : ""
                }
                onCopy={(v) => copy("Objects URL", v)}
              />
            </>
          ) : null}
        </div>
      </Section>

      <Section>
        <div
          className="px-5 py-3"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h2
            className="text-[14px] font-semibold leading-tight"
            style={{ color: "var(--color-ink)" }}
          >
            curl example
          </h2>
          <p
            className="text-[12px] mt-0.5"
            style={{ color: "var(--color-muted)" }}
          >
            Stream every indicator added since 2026-04-01:
          </p>
        </div>
        <pre
          className="m-5 p-3 overflow-x-auto text-[12px] font-mono"
          style={{
            border: "1px solid var(--color-border)",
            background: "var(--color-surface-muted)",
            borderRadius: "5px",
            color: "var(--color-ink)",
          }}
        >
          {`curl -H "Accept: application/taxii+json;version=2.1" \\
     -H "Authorization: Bearer <ARGUS_API_KEY>" \\
     "${origin || "https://argus.example"}/taxii2/api/collections/${
            collectionId ?? "<COLLECTION_ID>"
          }/objects/?added_after=2026-04-01T00:00:00Z"`}
        </pre>
      </Section>

      <p
        className="text-[11px]"
        style={{ color: "var(--color-muted)" }}
      >
        Spec reference:{" "}
        <a
          className="inline-flex items-center gap-1 underline"
          href="https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html"
          target="_blank"
          rel="noreferrer noopener"
        >
          OASIS TAXII 2.1
          <ExternalLink className="w-3 h-3" aria-hidden />
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
    <div
      className="flex items-center gap-3 px-3 py-2"
      style={{
        border: "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        borderRadius: "5px",
      }}
    >
      <div
        className="w-32 shrink-0 text-[10px] uppercase tracking-[0.8px] font-semibold"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      <code
        className={
          "flex-1 truncate px-2 py-1 text-[12px] " + (mono ? "font-mono" : "")
        }
        style={{
          background: "var(--color-surface-muted)",
          borderRadius: "5px",
          color: "var(--color-ink)",
        }}
        title={value}
      >
        {value || "—"}
      </code>
      <button
        type="button"
        onClick={() => onCopy(value)}
        disabled={!value}
        className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-1"
        style={{
          border: "1px solid var(--color-border)",
          background: "var(--color-canvas)",
          borderRadius: "5px",
          color: "var(--color-ink)",
          opacity: value ? 1 : 0.4,
        }}
      >
        <Copy className="w-3 h-3" aria-hidden />
        Copy
      </button>
    </div>
  );
}
