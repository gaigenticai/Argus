"use client";

import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Globe2,
  Camera,
  Image as ImageIcon,
  UserX,
  Smartphone,
  AlertOctagon,
  Settings2,
} from "lucide-react";
import {
  PageHeader,
  RefreshButton,
  OrgSwitcher,
} from "@/components/shared/page-primitives";

import {
  BrandContextProvider,
  useBrandContext,
} from "./_components/use-brand-context";
import { OverviewTab } from "./_components/overview-tab";
import { SuspectsTab } from "./_components/suspects-tab";
import { ProbesTab } from "./_components/probes-tab";
import { LogosTab } from "./_components/logos-tab";
import { ImpersonationsTab } from "./_components/impersonations-tab";
import { MobileAppsTab } from "./_components/mobile-apps-tab";
import { FraudTab } from "./_components/fraud-tab";
import { TermsTab } from "./_components/terms-tab";

const TABS = [
  { id: "overview", label: "Overview", icon: ShieldCheck },
  { id: "suspects", label: "Suspect domains", icon: Globe2 },
  { id: "probes", label: "Live probes", icon: Camera },
  { id: "logos", label: "Logos", icon: ImageIcon },
  { id: "impersonations", label: "Impersonations", icon: UserX },
  { id: "mobile-apps", label: "Mobile apps", icon: Smartphone },
  { id: "fraud", label: "Fraud", icon: AlertOctagon },
  { id: "terms", label: "Terms & feeds", icon: Settings2 },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function BrandPage() {
  return (
    <BrandContextProvider>
      <BrandShell />
    </BrandContextProvider>
  );
}

function BrandShell() {
  const { orgs, orgId, setOrgId, loading, bumpRefresh, refreshKey } =
    useBrandContext();

  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window === "undefined") return "overview";
    const h = window.location.hash.replace("#", "");
    return (TABS.find((t) => t.id === h)?.id || "overview") as TabId;
  });

  // Sync hash <-> tab so deep links + browser back/forward work as analysts expect
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
    const next = (TABS.find((t) => t.id === raw)?.id || "overview") as TabId;
    setTab(next);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.hash = next === "overview" ? "" : next;
      window.history.replaceState(null, "", url.toString());
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: ShieldCheck, label: "Brand & Surface" }}
        title="Brand Protection"
        description="Typosquats, cloned login pages, rogue social handles, fake mobile apps, and crypto-giveaway scams that target your brand. Detections feed Cases automatically at HIGH or above."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={bumpRefresh} refreshing={false} />
          </>
        }
      />

      {/* Tab strip */}
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
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {!orgId && !loading ? (
        <div className="p-12 text-center" style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
          <p className="text-[13.5px] font-bold" style={{ color: "var(--color-ink)" }}>
            No organisation found
          </p>
          <p className="text-[12.5px] mt-1" style={{ color: "var(--color-body)" }}>
            Create an organisation under Operations → Organizations to begin
            brand monitoring.
          </p>
        </div>
      ) : (
        <div key={`${orgId}-${tab}-${refreshKey}`}>
          {tab === "overview" && <OverviewTab onJumpTab={switchTab} />}
          {tab === "suspects" && <SuspectsTab />}
          {tab === "probes" && <ProbesTab />}
          {tab === "logos" && <LogosTab />}
          {tab === "impersonations" && <ImpersonationsTab />}
          {tab === "mobile-apps" && <MobileAppsTab />}
          {tab === "fraud" && <FraudTab />}
          {tab === "terms" && <TermsTab />}
        </div>
      )}
    </div>
  );
}
