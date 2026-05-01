"use client";

import { usePathname } from "next/navigation";
import { useAuth } from "@/components/auth/auth-provider";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";

const NO_SHELL_PATHS = ["/login"];
const FULL_BLEED_PATHS = ["/threat-map"];

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

  return (
    <>
      <Sidebar />
      <main className="ml-[240px] min-h-screen">
        <Header />
        <div className="px-8 py-6 max-w-[1440px]">{children}</div>
      </main>
    </>
  );
}
