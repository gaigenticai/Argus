"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  ChevronsUpDown,
  GitBranch,
  ShieldAlert,
  Target,
} from "lucide-react";
import {
  OrgSwitcher,
  PageHeader,
  RefreshButton,
} from "@/components/shared/page-primitives";
import { SourcesStrip } from "@/components/shared/sources-strip";
import {
  ExposuresContextProvider,
  useExposuresContext,
} from "./_components/use-exposures-context";
import { ExposuresInbox } from "./_components/exposures-inbox";
import { FindingsTab } from "./_components/findings-tab";
import { ChangesTab } from "./_components/changes-tab";
import { JobsTab } from "./_components/jobs-tab";
import { CoverageGate } from "@/components/shared/coverage-gate";

const TABS = [
  { id: "exposures", label: "Exposures", icon: ShieldAlert },
  { id: "findings", label: "Findings", icon: Target },
  { id: "changes", label: "Asset changes", icon: GitBranch },
  { id: "jobs", label: "Discovery jobs", icon: Activity },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function ExposuresPage() {
  return (
    <CoverageGate pageSlug="exposures" pageLabel="Exposures">
    <ExposuresContextProvider>
      <Shell />
    </ExposuresContextProvider>
      </CoverageGate>
  );
}

function Shell() {
  const { orgs, orgId, setOrgId, bumpRefresh, refreshKey, loading } =
    useExposuresContext();

  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window === "undefined") return "exposures";
    const h = window.location.hash.replace("#", "");
    return (TABS.find((t) => t.id === h)?.id || "exposures") as TabId;
  });

  useEffect(() => {
    const onHash = () => {
      const h = window.location.hash.replace("#", "");
      const next = TABS.find((t) => t.id === h)?.id;
      if (next) setTab(next as TabId);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const switchTab = (raw: string) => {
    const next = (TABS.find((t) => t.id === raw)?.id || "exposures") as TabId;
    setTab(next);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.hash = next === "exposures" ? "" : next;
      window.history.replaceState(null, "", url.toString());
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: ShieldAlert, label: "Brand & Surface" }}
        title="Exposures"
        description="External attack-surface findings — open ports, weak TLS, exposed admin interfaces, leaked CVEs, expired certs. Findings auto-promote to Cases at HIGH+; analysts curate everything below."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
      <SourcesStrip pageKey="exposures" />
            <RefreshButton onClick={bumpRefresh} refreshing={false} />
          </>
        }
      />

      <div className="flex items-center gap-1 -mx-1 overflow-x-auto" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => switchTab(t.id)}
              className="relative h-10 px-3.5 flex items-center gap-2 text-[13px] font-bold whitespace-nowrap transition-colors"
              style={{
                color: active ? "var(--color-ink)" : "var(--color-muted)",
                boxShadow: active ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
              }}
            >
              <Icon
                style={{
                  width: "14px",
                  height: "14px",
                  color: active ? "var(--color-ink)" : "var(--color-muted)",
                }}
              />
              {t.label}
            </button>
          );
        })}
      </div>

      {!orgId && !loading ? (
        <div
          className="p-12 text-center"
          style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
        >
          <ChevronsUpDown style={{ width: "28px", height: "28px", color: "var(--color-border)", margin: "0 auto 12px" }} />
          <p style={{ fontSize: "13.5px", fontWeight: 700, color: "var(--color-ink)" }}>
            No organisation selected
          </p>
          <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "4px" }}>
            Pick or create one to view its external surface.
          </p>
        </div>
      ) : (
        <div key={`${orgId}-${tab}-${refreshKey}`}>
          {tab === "exposures" && <ExposuresInbox />}
          {tab === "findings" && <FindingsTab />}
          {tab === "changes" && <ChangesTab />}
          {tab === "jobs" && <JobsTab />}
        </div>
      )}
    </div>
  );
}
