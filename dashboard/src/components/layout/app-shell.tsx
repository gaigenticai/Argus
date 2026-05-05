"use client";

import { usePathname } from "next/navigation";
import { useAuth } from "@/components/auth/auth-provider";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { ScopeVerificationGate } from "@/components/shared/scope-verification-gate";

const NO_SHELL_PATHS = ["/login"];
const FULL_BLEED_PATHS = ["/threat-map"];

// Paths that the scope-verification gate should NEVER blur — onboarding
// flows, the welcome page, and the verify-your-domain wizard itself
// would obviously be useless behind a blur. The gate component
// short-circuits to passthrough when ``pathname`` matches one of these
// prefixes, but we also pass the flag down so it can skip its own
// fetch + listener setup entirely.
const GATE_EXEMPT_PREFIXES = ["/welcome", "/onboarding", "/login", "/settings"];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, loading } = useAuth();

  const isNoShell = NO_SHELL_PATHS.includes(pathname);
  const isFullBleed = FULL_BLEED_PATHS.includes(pathname);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (isNoShell || !user) {
    return <>{children}</>;
  }

  if (isFullBleed) {
    return (
      <>
        <Sidebar />
        <main className="ml-[240px] h-screen overflow-hidden">{children}</main>
      </>
    );
  }

  const exempt = GATE_EXEMPT_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));

  return (
    <>
      <Sidebar />
      <main className="ml-[240px] min-h-screen">
        <Header />
        {exempt ? (
          <div className="px-8 py-6 max-w-[1440px]">{children}</div>
        ) : (
          <ScopeVerificationGate>
            <div className="px-8 py-6 max-w-[1440px]">{children}</div>
          </ScopeVerificationGate>
        )}
      </main>
    </>
  );
}
