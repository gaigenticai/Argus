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
    }
    if (user && isPublicPath) {
      router.replace("/");
    }
  }, [user, loading, isPublicPath, router]);

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
