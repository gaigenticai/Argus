"use client";

/**
 * Connectors page (P3 #3.4 closeout — answers the audit's "no
 * dashboard UI for any P3 connector" finding).
 *
 * One page, one Section per P3 group. Read-only — credentials live in
 * env vars / Helm values; this page surfaces config state and
 * on-demand health probes.
 */

import { useEffect, useState } from "react";
import {
  Plug,
  Lock,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Shield,
  Mail,
  FlaskConical,
  Workflow,
  Database,
  HardDrive,
  Send,
  Crosshair,
  Globe,
} from "lucide-react";
import {
  api,
  type ConnectorRow,
  type ConnectorHealth,
  type P3ConnectorGroup,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  Section,
  SkeletonRows,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";

interface GroupSpec {
  key:
    | P3ConnectorGroup
    | "telegram"
    | "adversary-emulation"
    | "forensics"
    | "urlscan";
  label: string;
  blurb: string;
  icon: typeof Plug;
}

const GROUPS: GroupSpec[] = [
  {
    key: "edr",
    label: "EDR — Endpoint Detection & Response",
    blurb: "CrowdStrike Falcon · SentinelOne · Microsoft Defender for Endpoint.",
    icon: Shield,
  },
  {
    key: "email-gateway",
    label: "Email gateway",
    blurb: "Proofpoint TAP · Mimecast · Abnormal Security.",
    icon: Mail,
  },
  {
    key: "sandbox",
    label: "Sandbox / detonation",
    blurb: "CAPEv2 (self-host) · Joe Sandbox · Hybrid-Analysis · VirusTotal Enterprise.",
    icon: FlaskConical,
  },
  {
    key: "soar",
    label: "SOAR",
    blurb: "Cortex XSOAR · Tines · Splunk SOAR (Phantom).",
    icon: Workflow,
  },
  {
    key: "breach",
    label: "Breach / credential providers",
    blurb: "HaveIBeenPwned Enterprise · IntelX · Dehashed.",
    icon: Database,
  },
  {
    key: "forensics",
    label: "IR workbench",
    blurb: "Volatility 3 (memory) + Velociraptor (live endpoints).",
    icon: HardDrive,
  },
  {
    key: "telegram",
    label: "Telegram MTProto collector",
    blurb: "Iranian-APT + Arabic hacktivist channel monitor (legal-gated).",
    icon: Send,
  },
  {
    key: "adversary-emulation",
    label: "Adversary emulation",
    blurb: "Atomic Red Team + MITRE Caldera. Coverage scoring per ATT&CK technique.",
    icon: Crosshair,
  },
  {
    key: "urlscan",
    label: "urlscan.io enrichment",
    blurb: "Search historical URL scans · submit fresh scans (admin).",
    icon: Globe,
  },
];

export default function ConnectorsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Plug, label: "Phase 3" }}
        title="Connectors"
        description="Vendor and tooling integrations. Credentials are pinned via environment variables / Helm values; this page surfaces config state and on-demand health probes."
      />

      <div className="space-y-4">
        {GROUPS.map((g) => {
          if (g.key === "telegram") return <TelegramSection key={g.key} spec={g} />;
          if (g.key === "adversary-emulation")
            return <AdversaryEmulationSection key={g.key} spec={g} />;
          if (g.key === "forensics") return <ForensicsSection key={g.key} spec={g} />;
          if (g.key === "urlscan") return <UrlscanSection key={g.key} spec={g} />;
          return <StandardGroup key={g.key} spec={g} />;
        })}
      </div>
    </div>
  );
}


// ── Group section shell ─────────────────────────────────────────────


function GroupShell({
  spec,
  children,
}: {
  spec: GroupSpec;
  children: React.ReactNode;
}) {
  const Icon = spec.icon;
  return (
    <Section>
      <div
        className="flex items-start gap-3 px-5 py-4"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <div
          className="w-9 h-9 flex items-center justify-center shrink-0"
          style={{
            background: "var(--color-surface-muted)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <Icon className="w-4 h-4" style={{ color: "var(--color-accent)" }} />
        </div>
        <div className="min-w-0">
          <h2
            className="text-[14px] font-semibold leading-tight"
            style={{ color: "var(--color-ink)" }}
          >
            {spec.label}
          </h2>
          <p className="text-[12px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            {spec.blurb}
          </p>
        </div>
      </div>
      {children}
    </Section>
  );
}


// ── Standard EDR / email-gateway / sandbox / SOAR / breach group ────


function StandardGroup({ spec }: { spec: GroupSpec }) {
  const group = spec.key as P3ConnectorGroup;
  const [rows, setRows] = useState<ConnectorRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [healths, setHealths] = useState<
    Record<string, ConnectorHealth | "checking" | undefined>
  >({});
  const { toast } = useToast();

  useEffect(() => {
    let mounted = true;
    api
      .listConnectors(group)
      .then((data) => {
        if (!mounted) return;
        setRows(data.connectors ?? data.providers ?? []);
      })
      .catch(() => mounted && setRows([]))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, [group]);

  const probe = async (name: string) => {
    setHealths((h) => ({ ...h, [name]: "checking" }));
    try {
      const r = await api.connectorHealth(group, name);
      setHealths((h) => ({ ...h, [name]: r }));
    } catch (err) {
      setHealths((h) => ({
        ...h,
        [name]: { success: false, error: (err as Error).message },
      }));
      toast("error", `Health check failed: ${name}`);
    }
  };

  return (
    <GroupShell spec={spec}>
      {loading ? (
        <SkeletonRows rows={3} columns={4} />
      ) : rows.length === 0 ? (
        <Empty
          icon={spec.icon}
          title="No connectors discovered"
          description="Verify the API service is reachable and re-load. If the connector module is missing, check src/integrations/ on the backend."
        />
      ) : (
        <table className="w-full text-[13px]">
          <thead>
            <tr
              className="text-[10px] uppercase tracking-[0.8px]"
              style={{
                background: "var(--color-surface-muted)",
                color: "var(--color-muted)",
              }}
            >
              <th className="text-left px-5 py-2 font-semibold">Connector</th>
              <th className="text-left px-3 py-2 font-semibold">Status</th>
              <th className="text-left px-3 py-2 font-semibold">Health</th>
              <th className="text-right px-5 py-2 font-semibold">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const health = healths[r.name];
              return (
                <tr
                  key={r.name}
                  style={{ borderTop: "1px solid var(--color-border)" }}
                >
                  <td className="px-5 py-3">
                    <div
                      className="font-semibold"
                      style={{ color: "var(--color-ink)" }}
                    >
                      {r.label ?? r.name}
                    </div>
                    <div
                      className="text-[11px] mt-0.5 font-mono"
                      style={{ color: "var(--color-muted)" }}
                    >
                      {r.name}
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    <ConfiguredPill ok={r.configured} />
                  </td>
                  <td className="px-3 py-3">
                    <HealthCell health={health} />
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => probe(r.name)}
                      disabled={!r.configured || health === "checking"}
                      className="inline-flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                      style={{
                        border: "1px solid var(--color-border)",
                        borderRadius: "5px",
                        background: "var(--color-canvas)",
                        color: "var(--color-ink)",
                      }}
                      title={
                        r.configured
                          ? "Run a live health probe"
                          : "Connector is not configured"
                      }
                    >
                      <RefreshCw className="w-3 h-3" aria-hidden />
                      Probe
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </GroupShell>
  );
}


// ── Forensics / Telegram / Adversary-emulation / urlscan ───────────


function StatGrid({ items }: { items: { label: string; ok: boolean; sub: string }[] }) {
  return (
    <div className="px-5 py-4 grid gap-3 sm:grid-cols-2">
      {items.map((it) => (
        <div
          key={it.label}
          className="px-4 py-3"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <div className="flex items-center justify-between gap-3">
            <span
              className="text-[13px] font-semibold"
              style={{ color: "var(--color-ink)" }}
            >
              {it.label}
            </span>
            <ConfiguredPill ok={it.ok} />
          </div>
          <p
            className="text-[12px] mt-1.5 font-mono"
            style={{ color: "var(--color-muted)" }}
          >
            {it.sub}
          </p>
        </div>
      ))}
    </div>
  );
}


function ForensicsSection({ spec }: { spec: GroupSpec }) {
  const [data, setData] = useState<{
    volatility: { available: boolean; cli_path: string | null };
    velociraptor: { configured: boolean };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let m = true;
    api
      .forensicsAvailability()
      .then((d) => m && setData(d))
      .catch(() => m && setData(null))
      .finally(() => m && setLoading(false));
    return () => {
      m = false;
    };
  }, []);
  return (
    <GroupShell spec={spec}>
      {loading ? (
        <SkeletonRows rows={2} columns={2} />
      ) : !data ? (
        <Empty
          icon={spec.icon}
          title="Forensics availability unknown"
          description="API didn't respond — check that the worker container is running and reachable."
        />
      ) : (
        <StatGrid
          items={[
            {
              label: "Volatility 3",
              ok: data.volatility.available,
              sub: data.volatility.cli_path ?? "vol3 not on PATH — set ARGUS_VOLATILITY_CLI",
            },
            {
              label: "Velociraptor",
              ok: data.velociraptor.configured,
              sub: data.velociraptor.configured
                ? "ARGUS_VELOCIRAPTOR_URL + token present"
                : "Set ARGUS_VELOCIRAPTOR_URL + ARGUS_VELOCIRAPTOR_TOKEN",
            },
          ]}
        />
      )}
    </GroupShell>
  );
}


function TelegramSection({ spec }: { spec: GroupSpec }) {
  const [avail, setAvail] = useState<{
    configured: boolean;
    curated_total: number;
    curated_active: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let m = true;
    api
      .telegramAvailability()
      .then((d) => m && setAvail(d))
      .catch(() => m && setAvail(null))
      .finally(() => m && setLoading(false));
    return () => {
      m = false;
    };
  }, []);
  return (
    <GroupShell spec={spec}>
      {loading ? (
        <SkeletonRows rows={2} columns={2} />
      ) : !avail ? (
        <Empty
          icon={spec.icon}
          title="Telegram availability unknown"
          description="API didn't respond."
        />
      ) : (
        <div className="px-5 py-4 space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-[13px]">
            <ConfiguredPill ok={avail.configured} />
            <span style={{ color: "var(--color-muted)" }}>
              {avail.curated_active} active / {avail.curated_total} curated channels
            </span>
          </div>
          {!avail.configured && (
            <div
              className="px-3 py-2 text-[12px] flex items-start gap-2"
              style={{
                border: "1px solid var(--color-border)",
                background: "var(--color-surface-muted)",
                borderRadius: "5px",
                color: "var(--color-body)",
              }}
            >
              <Lock className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden />
              <span>
                Telethon collector is opt-in. Set <code>ARGUS_TELEGRAM_ENABLED=true</code>{" "}
                after legal review, plus <code>ARGUS_TELEGRAM_API_ID</code>,{" "}
                <code>ARGUS_TELEGRAM_API_HASH</code>,{" "}
                <code>ARGUS_TELEGRAM_SESSION_PATH</code>.
              </span>
            </div>
          )}
        </div>
      )}
    </GroupShell>
  );
}


function AdversaryEmulationSection({ spec }: { spec: GroupSpec }) {
  const [data, setData] = useState<{
    atomic_red_team: {
      filesystem_path: string | null;
      filesystem_active: boolean;
      curated_count: number;
      techniques_indexed: number;
    };
    caldera: { configured: boolean };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let m = true;
    api
      .adversaryEmulationAvailability()
      .then((d) => m && setData(d))
      .catch(() => m && setData(null))
      .finally(() => m && setLoading(false));
    return () => {
      m = false;
    };
  }, []);
  return (
    <GroupShell spec={spec}>
      {loading ? (
        <SkeletonRows rows={2} columns={2} />
      ) : !data ? (
        <Empty
          icon={spec.icon}
          title="Emulation availability unknown"
          description="API didn't respond."
        />
      ) : (
        <StatGrid
          items={[
            {
              label: "Atomic Red Team",
              ok: data.atomic_red_team.techniques_indexed > 0,
              sub: data.atomic_red_team.filesystem_active
                ? `Loaded from ${data.atomic_red_team.filesystem_path}`
                : `Curated starter — ${data.atomic_red_team.curated_count} tests · ${data.atomic_red_team.techniques_indexed} techniques`,
            },
            {
              label: "MITRE Caldera",
              ok: data.caldera.configured,
              sub: data.caldera.configured
                ? "ARGUS_CALDERA_URL + ARGUS_CALDERA_API_KEY set"
                : "Caldera URL + API key not configured",
            },
          ]}
        />
      )}
    </GroupShell>
  );
}


function UrlscanSection({ spec }: { spec: GroupSpec }) {
  const [configured, setConfigured] = useState<boolean | null>(null);
  useEffect(() => {
    let m = true;
    fetch("/api/v1/intel/urlscan/availability", {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${
          typeof window !== "undefined"
            ? localStorage.getItem("argus_access_token") ?? ""
            : ""
        }`,
      },
    })
      .then((r) => r.json())
      .then((j) => m && setConfigured(Boolean(j?.configured)))
      .catch(() => m && setConfigured(false));
    return () => {
      m = false;
    };
  }, []);
  return (
    <GroupShell spec={spec}>
      {configured === null ? (
        <SkeletonRows rows={1} columns={2} />
      ) : (
        <StatGrid
          items={[
            {
              label: "urlscan.io",
              ok: configured,
              sub: configured
                ? "ARGUS_URLSCAN_API_KEY present — search + submit enabled"
                : "Free signup at https://urlscan.io/user/signup/, then set ARGUS_URLSCAN_API_KEY",
            },
          ]}
        />
      )}
    </GroupShell>
  );
}


// ── Atoms ───────────────────────────────────────────────────────────


function ConfiguredPill({ ok }: { ok: boolean }) {
  if (ok) {
    return (
      <span
        className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5"
        style={{
          background: "rgba(16,185,129,0.08)",
          color: "var(--color-success-dark)",
          border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: "999px",
        }}
      >
        <CheckCircle2 className="w-3 h-3" aria-hidden />
        Configured
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5"
      style={{
        background: "var(--color-surface-muted)",
        color: "var(--color-muted)",
        border: "1px solid var(--color-border)",
        borderRadius: "999px",
      }}
    >
      <Lock className="w-3 h-3" aria-hidden />
      Not configured
    </span>
  );
}


function HealthCell({
  health,
}: {
  health: ConnectorHealth | "checking" | undefined;
}) {
  if (health === undefined) {
    return (
      <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>
        —
      </span>
    );
  }
  if (health === "checking") {
    return (
      <span
        className="inline-flex items-center gap-1 text-[11px]"
        style={{ color: "var(--color-muted)" }}
      >
        <RefreshCw className="w-3 h-3 animate-spin" aria-hidden />
        Probing…
      </span>
    );
  }
  if (health.success) {
    return (
      <span
        className="inline-flex items-center gap-1 text-[11px] font-semibold"
        style={{ color: "var(--color-success-dark)" }}
        title={typeof health.note === "string" ? health.note : undefined}
      >
        <CheckCircle2 className="w-3 h-3" aria-hidden />
        Reachable
      </span>
    );
  }
  const detail =
    (typeof health.error === "string" && health.error) ||
    (typeof health.note === "string" && health.note) ||
    "Unreachable";
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] font-semibold max-w-[280px] truncate"
      style={{ color: "var(--color-error-dark)" }}
      title={detail}
    >
      <XCircle className="w-3 h-3 shrink-0" aria-hidden />
      <span className="truncate">{detail}</span>
    </span>
  );
}
