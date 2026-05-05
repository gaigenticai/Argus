"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, type UserResponse } from "@/lib/api";

interface AuthContextValue {
  user: UserResponse | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  loading: true,
  login: async () => {},
  logout: async () => {},
  refreshUser: async () => {},
});

const PUBLIC_PATHS = ["/login"];
const ONBOARDING_PATH = "/onboarding/oss-tools";
const WELCOME_PATH = "/welcome";

// Don't bounce these paths through the welcome / OSS gates — they're
// either part of the onboarding flow itself or escape hatches the
// operator chose explicitly. Anything under /onboarding/* falls into
// this set so the operator can finish the deeper wizard if they
// already started one.
const ONBOARDING_PREFIXES = ["/onboarding", "/welcome"];

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const isPublicPath = PUBLIC_PATHS.includes(pathname);

  // Adversarial audit D-1 — JWTs now live in HttpOnly cookies. The
  // browser ships them automatically with `credentials: "include"`,
  // so the auth-provider just asks /auth/me whether the cookie is
  // valid; if it isn't, the user is logged out.
  const fetchUser = useCallback(async () => {
    try {
      const me = await api.getMe();
      setUser(me);
    } catch {
      setUser(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  useEffect(() => {
    if (loading) return;
    if (!user && !isPublicPath) {
      router.replace("/login");
      return;
    }
    if (user && isPublicPath) {
      router.replace("/");
      return;
    }
    // First-run product gate (precedes the OSS install gate). If
    // the operator hasn't created an organization of their own yet
    // AND we're not on a path that's already part of the onboarding
    // flow, redirect to /welcome so they hit the "see Marsad work in
    // 2 minutes" path before anything else. Demo-seed users
    // (admin@argus.demo) skip this — their next_action comes back as
    // ``welcome_demo`` and they land on / with a one-time banner.
    const inOnboardingFlow = ONBOARDING_PREFIXES.some((p) => pathname.startsWith(p));
    if (user && !isPublicPath && !inOnboardingFlow) {
      api
        .getOnboardingState()
        .then((s) => {
          if (s.next_action === "quickstart") {
            router.replace(WELCOME_PATH);
            return;
          }
          // Admin first-login OSS onboarding gate. Only fires after
          // the welcome gate clears so we never bounce between the
          // two pages. ``/onboarding/oss-tools`` itself is in the
          // onboarding-flow allowlist above.
          if (user.role === "admin") {
            api
              .ossOnboardingStatus()
              .then((oss) => {
                if (!oss.complete) router.replace(ONBOARDING_PATH);
              })
              .catch(() => {
                // Endpoint may not exist on older deployments.
              });
          }
        })
        .catch(() => {
          // /onboarding/state may not exist on older deployments —
          // fall through to the OSS gate so behaviour is unchanged.
          if (user.role === "admin" && pathname !== ONBOARDING_PATH) {
            api
              .ossOnboardingStatus()
              .then((s) => {
                if (!s.complete) router.replace(ONBOARDING_PATH);
              })
              .catch(() => {});
          }
        });
    }
  }, [user, loading, isPublicPath, pathname, router]);

  const login = useCallback(
    async (email: string, password: string) => {
      // /auth/login sets HttpOnly cookies; nothing to stash in JS.
      const res = await api.login(email, password);
      setUser(res.user);
      router.replace("/");
    },
    [router]
  );

  const logout = useCallback(async () => {
    try {
      // /auth/logout clears the HttpOnly cookies server-side.
      await api.logout();
    } catch {
      // Ignore logout errors
    }
    setUser(null);
    router.replace("/login");
  }, [router]);

  const refreshUser = useCallback(async () => {
    try {
      const me = await api.getMe();
      setUser(me);
    } catch {
      // Ignore
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
