"use client";

/**
 * Connectors page (P3 #3.4 closeout — answers the audit's "no
 * dashboard UI for any P3 connector" finding).
 *
 * One page, one table per P3 group: EDR, email-gateway, sandbox, SOAR,
 * breach providers, forensics, telegram collector, adversary
 * emulation. Each row shows the connector's configured state and a
 * "Health check" action that hits the backend's per-name health
 * endpoint. The page is read-only — credentials are configured via
 * env vars / Helm values on the server.
 */

import { useEffect, useState } from "react";
import {
  Plug,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Lock,
  Shield,
  Mail,
  FlaskConical,
  Workflow,
  Database,
  HardDrive,
  Send,
  Crosshair,
} from "lucide-react";
import {
  api,
  type ConnectorRow,
  type ConnectorHealth,
  type P3ConnectorGroup,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";

interface GroupSpec {
  group: P3ConnectorGroup | "telegram" | "adversary-emulation" | "forensics";
  label: string;
  blurb: string;
  icon: typeof Plug;
}

const GROUPS: GroupSpec[] = [
  {
    group: "edr",
    label: "EDR (Endpoint Detection & Response)",
    blurb: "CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint.",
    icon: Shield,
  },
  {
    group: "email-gateway",
    label: "Email Gateway",
    blurb: "Proofpoint TAP, Mimecast, Abnormal Security.",
    icon: Mail,
  },
  {
    group: "sandbox",
    label: "Sandbox / Detonation",
    blurb: "CAPEv2 (self-host), Joe Sandbox, Hybrid-Analysis, VirusTotal Enterprise.",
    icon: FlaskConical,
  },
  {
    group: "soar",
    label: "SOAR",
    blurb: "Cortex XSOAR, Tines, Splunk SOAR (Phantom).",
    icon: Workflow,
  },
  {
    group: "breach",
    label: "Breach / Credential Providers",
    blurb: "HIBP Enterprise, IntelX, Dehashed.",
    icon: Database,
  },
  {
    group: "forensics",
    label: "IR Workbench",
    blurb: "Volatility 3 (memory) + Velociraptor (live endpoints).",
    icon: HardDrive,
  },
  {
    group: "telegram",
    label: "Telegram MTProto Collector",
    blurb: "Iranian-APT + Arabic hacktivist channel monitor (legal-gated).",
    icon: Send,
  },
  {
    group: "adversary-emulation",
    label: "Adversary Emulation",
    blurb: "Atomic Red Team + MITRE Caldera. Coverage scoring per ATT&CK technique.",
    icon: Crosshair,
  },
];

export default function ConnectorsPage() {
  return (
    <div className="space-y-8">
      <header className="flex items-center gap-3">
        <Plug className="size-6 text-[var(--color-accent)]" aria-hidden />
        <div>
          <h1 className="text-2xl font-semibold">Connectors</h1>
          <p className="text-sm text-[var(--color-muted)]">
            Phase 3 vendor and tooling integrations. Credentials are pinned via
            environment variables / Helm values; this page surfaces config
            state and on-demand health probes.
          </p>
        </div>
      </header>

      {GROUPS.map((g) => {
        if (g.group === "telegram") return <TelegramSection key="telegram" spec={g} />;
        if (g.group === "adversary-emulation") return <AdversaryEmulationSection key="ae" spec={g} />;
        if (g.group === "forensics") return <ForensicsSection key="forensics" spec={g} />;
        return <StandardGroup key={g.group} spec={g} />;
      })}
    </div>
  );
}


// ── Standard EDR / email-gateway / sandbox / SOAR / breach group ────


function StandardGroup({ spec }: { spec: GroupSpec }) {
  const group = spec.group as P3ConnectorGroup;
  const [rows, setRows] = useState<ConnectorRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [healths, setHealths] = useState<Record<string, ConnectorHealth | "checking" | undefined>>({});
  const { toast } = useToast();

  useEffect(() => {
    let mounted = true;
    api
      .listConnectors(group)
      .then((data) => {
        if (!mounted) return;
        const rows = data.connectors ?? data.providers ?? [];
        setRows(rows);
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
    <Section spec={spec}>
      {loading ? (
        <SectionLoading />
      ) : rows.length === 0 ? (
        <SectionEmpty />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-[var(--color-muted)]">
            <tr>
              <th className="py-2 pr-4">Connector</th>
              <th className="py-2 pr-4">Configured</th>
              <th className="py-2 pr-4">Health</th>
              <th className="py-2" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const health = healths[r.name];
              return (
                <tr key={r.name} className="border-t border-[var(--color-border)]">
                  <td className="py-2 pr-4">
                    <div className="font-medium">{r.label ?? r.name}</div>
                    <div className="text-xs text-[var(--color-muted)]">{r.name}</div>
                  </td>
                  <td className="py-2 pr-4">
                    <ConfiguredPill ok={r.configured} />
                  </td>
                  <td className="py-2 pr-4">
                    <HealthCell health={health} />
                  </td>
                  <td className="py-2 text-right">
                    <button
                      type="button"
                      onClick={() => probe(r.name)}
                      disabled={!r.configured || health === "checking"}
                      className="inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs hover:bg-[var(--color-surface-muted)] disabled:opacity-50"
                      title={
                        r.configured
                          ? "Run a live health probe"
                          : "Connector is not configured"
                      }
                    >
                      <RefreshCw className="size-3" aria-hidden />
                      Health
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Section>
  );
}


// ── Forensics — Volatility + Velociraptor (separate availability shape) ──


function ForensicsSection({ spec }: { spec: GroupSpec }) {
  const [data, setData] = useState<{
    volatility: { available: boolean; cli_path: string | null };
    velociraptor: { configured: boolean };
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api
      .forensicsAvailability()
      .then((d) => mounted && setData(d))
      .catch(() => mounted && setData(null))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <Section spec={spec}>
      {loading ? (
        <SectionLoading />
      ) : !data ? (
        <SectionEmpty />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <Stat
            label="Volatility 3"
            ok={data.volatility.available}
            sub={data.volatility.cli_path ?? "vol3 binary not on PATH"}
          />
          <Stat
            label="Velociraptor"
            ok={data.velociraptor.configured}
            sub={
              data.velociraptor.configured
                ? "ARGUS_VELOCIRAPTOR_URL + token present"
                : "Set ARGUS_VELOCIRAPTOR_URL + ARGUS_VELOCIRAPTOR_TOKEN"
            }
          />
        </div>
      )}
    </Section>
  );
}


// ── Telegram MTProto collector ─────────────────────────────────────


function TelegramSection({ spec }: { spec: GroupSpec }) {
  const [avail, setAvail] = useState<{
    configured: boolean;
    curated_total: number;
    curated_active: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api
      .telegramAvailability()
      .then((d) => mounted && setAvail(d))
      .catch(() => mounted && setAvail(null))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <Section spec={spec}>
      {loading ? (
        <SectionLoading />
      ) : !avail ? (
        <SectionEmpty />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <ConfiguredPill ok={avail.configured} />
            <span className="text-[var(--color-muted)]">
              {avail.curated_active} active / {avail.curated_total} curated channels
            </span>
          </div>
          {!avail.configured && (
            <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] p-3 text-xs text-[var(--color-muted)]">
              <Lock className="mr-1 inline size-3" aria-hidden />
              Telethon collector is opt-in. Set{" "}
              <code className="rounded bg-[var(--color-surface)] px-1 py-0.5 text-[10px]">
                ARGUS_TELEGRAM_ENABLED=true
              </code>{" "}
              after legal review, plus{" "}
              <code className="rounded bg-[var(--color-surface)] px-1 py-0.5 text-[10px]">
                ARGUS_TELEGRAM_API_ID
              </code>
              ,{" "}
              <code className="rounded bg-[var(--color-surface)] px-1 py-0.5 text-[10px]">
                ARGUS_TELEGRAM_API_HASH
              </code>
              ,{" "}
              <code className="rounded bg-[var(--color-surface)] px-1 py-0.5 text-[10px]">
                ARGUS_TELEGRAM_SESSION_PATH
              </code>
              .
            </div>
          )}
        </div>
      )}
    </Section>
  );
}


// ── Adversary emulation (Caldera + Atomic Red Team) ────────────────


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
    let mounted = true;
    api
      .adversaryEmulationAvailability()
      .then((d) => mounted && setData(d))
      .catch(() => mounted && setData(null))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <Section spec={spec}>
      {loading ? (
        <SectionLoading />
      ) : !data ? (
        <SectionEmpty />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <Stat
            label="Atomic Red Team"
            ok={data.atomic_red_team.techniques_indexed > 0}
            sub={
              data.atomic_red_team.filesystem_active
                ? `Loaded from ${data.atomic_red_team.filesystem_path}`
                : `Curated starter (${data.atomic_red_team.curated_count} tests · ${data.atomic_red_team.techniques_indexed} techniques)`
            }
          />
          <Stat
            label="MITRE Caldera"
            ok={data.caldera.configured}
            sub={
              data.caldera.configured
                ? "ARGUS_CALDERA_URL + ARGUS_CALDERA_API_KEY set"
                : "Caldera URL + API key not configured"
            }
          />
        </div>
      )}
    </Section>
  );
}


// ── Shared bits ────────────────────────────────────────────────────


function Section({
  spec,
  children,
}: {
  spec: GroupSpec;
  children: React.ReactNode;
}) {
  const Icon = spec.icon;
  return (
    <section className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="mb-3 flex items-start gap-3">
        <Icon
          className="mt-0.5 size-5 text-[var(--color-accent)]"
          aria-hidden
        />
        <div>
          <h2 className="text-base font-medium">{spec.label}</h2>
          <p className="text-xs text-[var(--color-muted)]">{spec.blurb}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

function SectionLoading() {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-[var(--color-muted)]">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      Loading…
    </div>
  );
}

function SectionEmpty() {
  return (
    <div className="py-6 text-sm text-[var(--color-muted)]">
      No connectors discovered. Check that the service is reachable.
    </div>
  );
}

function ConfiguredPill({ ok }: { ok: boolean }) {
  if (ok) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[rgba(0,167,111,0.1)] px-2 py-0.5 text-xs font-medium text-[#007B55]">
        <CheckCircle2 className="size-3" aria-hidden />
        Configured
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-xs text-[var(--color-muted)]">
      <Lock className="size-3" aria-hidden />
      Not configured
    </span>
  );
}

function Stat({ label, ok, sub }: { label: string; ok: boolean; sub: string }) {
  return (
    <div className="rounded-md border border-[var(--color-border)] p-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <ConfiguredPill ok={ok} />
      </div>
      <p className="mt-2 text-xs text-[var(--color-muted)]">{sub}</p>
    </div>
  );
}

function HealthCell({
  health,
}: {
  health: ConnectorHealth | "checking" | undefined;
}) {
  if (health === undefined) {
    return <span className="text-xs text-[var(--color-muted)]">—</span>;
  }
  if (health === "checking") {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-[var(--color-muted)]">
        <Loader2 className="size-3 animate-spin" aria-hidden />
        Checking…
      </span>
    );
  }
  if (health.success) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs text-[#007B55]"
        title={typeof health.note === "string" ? health.note : undefined}
      >
        <CheckCircle2 className="size-3" aria-hidden />
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
      className="inline-flex items-center gap-1 text-xs text-[#B71D18]"
      title={detail}
    >
      <XCircle className="size-3" aria-hidden />
      <span className="max-w-[280px] truncate">{detail}</span>
    </span>
  );
}
