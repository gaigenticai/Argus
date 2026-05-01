"use client";

import { useState } from "react";
import { Eye, EyeOff, Shield } from "lucide-react";
import { useAuth } from "@/components/auth/auth-provider";

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError("Email and password are required");
      return;
    }
    setError("");
    setLoading(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen grid lg:grid-cols-2"
      style={{ background: "var(--color-canvas)" }}
    >
      {/* Left — brand panel */}
      <div
        className="hidden lg:flex flex-col justify-between p-12"
        style={{
          background: "var(--color-surface-dark)",
          borderRight: "1px solid var(--color-border-strong)",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5">
          <div
            className="w-8 h-8 flex items-center justify-center shrink-0"
            style={{
              background: "var(--color-accent)",
              borderRadius: "4px",
            }}
          >
            <Shield className="w-4 h-4" style={{ color: "#fffefb" }} />
          </div>
          <div className="leading-none">
            <span
              className="text-[16px] font-semibold tracking-[-0.02em]"
              style={{ color: "var(--color-on-dark)" }}
            >
              Argus
            </span>
            <p
              className="text-[9px] tracking-[1.2px] uppercase mt-0.5 font-semibold"
              style={{ color: "var(--color-on-dark-muted)" }}
            >
              The All Seeing
            </p>
          </div>
        </div>

        {/* Headline */}
        <div>
          <h2
            className="text-[44px] font-medium leading-[1.05] tracking-[-0.03em] max-w-sm"
            style={{ color: "var(--color-on-dark)" }}
          >
            Threat intelligence. Every surface. One platform.
          </h2>
          <p
            className="mt-5 text-[14px] leading-[1.6] max-w-sm"
            style={{ color: "var(--color-on-dark-muted)" }}
          >
            Dark-web crawlers, brand defence, MITRE mapping, and agentic
            triage — unified behind one interface.
          </p>

          {/* Feature list */}
          <div className="mt-8 space-y-2">
            {[
              "Dark web & Tor monitoring",
              "Brand protection & takedowns",
              "IOC enrichment & MITRE mapping",
              "AI-powered alert triage",
            ].map((f) => (
              <div key={f} className="flex items-center gap-2.5">
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: "var(--color-accent)" }}
                />
                <span
                  className="text-[13px]"
                  style={{ color: "var(--color-on-dark-muted)" }}
                >
                  {f}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer note */}
        <p
          className="text-[11px]"
          style={{ color: "rgba(197, 192, 177, 0.5)" }}
        >
          Secured access. Contact your administrator for credentials.
        </p>
      </div>

      {/* Right — sign-in form */}
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-[380px]">
          {/* Mobile wordmark */}
          <div
            className="lg:hidden flex items-center gap-2.5 mb-10"
          >
            <div
              className="w-8 h-8 flex items-center justify-center"
              style={{ background: "var(--color-accent)", borderRadius: "4px" }}
            >
              <Shield className="w-4 h-4" style={{ color: "#fffefb" }} />
            </div>
            <span
              className="text-[18px] font-semibold tracking-[-0.02em]"
              style={{ color: "var(--color-ink)" }}
            >
              Argus
            </span>
          </div>

          <h2
            className="text-[32px] font-medium leading-[1.1] tracking-[-0.03em] mb-1"
            style={{ color: "var(--color-ink)" }}
          >
            Sign in
          </h2>
          <p className="text-[14px] mb-8" style={{ color: "var(--color-muted)" }}>
            Enter your credentials to access the platform.
          </p>

          {error && (
            <div
              className="mb-6 px-4 py-3 text-[13px] font-medium"
              style={{
                background: "rgba(239, 68, 68, 0.06)",
                color: "var(--color-error-dark)",
                border: "1px solid rgba(239, 68, 68, 0.2)",
                borderRadius: "5px",
              }}
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                className="block text-[11px] font-semibold uppercase tracking-[0.08em] mb-1.5"
                style={{ color: "var(--color-body)" }}
              >
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
                className="w-full h-10 px-3 text-[14px] outline-none transition-colors"
                style={{
                  background: "var(--color-canvas)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "5px",
                  color: "var(--color-ink)",
                }}
                onFocus={(e) => {
                  (e.target as HTMLInputElement).style.borderColor = "var(--color-accent)";
                }}
                onBlur={(e) => {
                  (e.target as HTMLInputElement).style.borderColor = "var(--color-border)";
                }}
              />
            </div>

            <div>
              <label
                className="block text-[11px] font-semibold uppercase tracking-[0.08em] mb-1.5"
                style={{ color: "var(--color-body)" }}
              >
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  className="w-full h-10 px-3 pr-10 text-[14px] outline-none transition-colors"
                  style={{
                    background: "var(--color-canvas)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "5px",
                    color: "var(--color-ink)",
                  }}
                  onFocus={(e) => {
                    (e.target as HTMLInputElement).style.borderColor = "var(--color-accent)";
                  }}
                  onBlur={(e) => {
                    (e.target as HTMLInputElement).style.borderColor = "var(--color-border)";
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: "var(--color-muted)" }}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full h-10 text-[14px] font-semibold transition-opacity disabled:opacity-60 flex items-center justify-center gap-2 mt-6"
              style={{
                background: "var(--color-accent)",
                color: "#fffefb",
                borderRadius: "4px",
                border: "1px solid var(--color-accent)",
              }}
              onMouseEnter={(e) => {
                if (!loading) (e.currentTarget as HTMLElement).style.opacity = "0.88";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.opacity = "";
              }}
            >
              {loading && (
                <div
                  className="w-4 h-4 border-2 border-t-transparent rounded-full animate-spin"
                  style={{ borderColor: "rgba(255,254,251,0.4)", borderTopColor: "transparent" }}
                />
              )}
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <p
            className="text-center text-[12px] mt-8"
            style={{ color: "var(--color-muted)" }}
          >
            First time? Contact your administrator for access.
          </p>
        </div>
      </div>
    </div>
  );
}
