"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, type Org } from "@/lib/api";
import { useToast } from "@/components/shared/toast";

/**
 * Org selection + refresh tick are shared across every Brand-Protection
 * tab. Lifting them into a tiny context lets each tab observe org
 * changes without prop-drilling, and triggers a coordinated refresh
 * when the user clicks the page-level Refresh button.
 */
interface BrandContextValue {
  orgs: Org[];
  orgId: string;
  setOrgId: (id: string) => void;
  loading: boolean;
  refreshKey: number;
  bumpRefresh: () => void;
}

const BrandContext = createContext<BrandContextValue | null>(null);

export function BrandContextProvider({ children }: { children: ReactNode }) {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted =
          typeof window !== "undefined"
            ? window.localStorage.getItem("argus_org_id")
            : null;
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgIdState(initial);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load organizations",
        );
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    if (typeof window !== "undefined") {
      window.localStorage.setItem("argus_org_id", id);
    }
  }, []);

  const bumpRefresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  return (
    <BrandContext.Provider
      value={{ orgs, orgId, setOrgId, loading, refreshKey, bumpRefresh }}
    >
      {children}
    </BrandContext.Provider>
  );
}

export function useBrandContext(): BrandContextValue {
  const ctx = useContext(BrandContext);
  if (!ctx) {
    throw new Error("useBrandContext must be used within BrandContextProvider");
  }
  return ctx;
}
