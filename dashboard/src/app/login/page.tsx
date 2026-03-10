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
    <div className="min-h-screen flex items-center justify-center bg-grey-100 px-4">
      <div className="w-full max-w-[420px]">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-10">
          <div className="w-10 h-10 rounded-xl bg-grey-900 flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div className="leading-none">
            <h1 className="text-grey-900 text-[20px] font-extrabold tracking-wider">ARGUS</h1>
            <p className="text-grey-500 text-[10px] tracking-[1.5px] uppercase mt-0.5">Threat Intelligence</p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-white rounded-2xl border border-grey-200 shadow-z8 p-8">
          <h2 className="text-[22px] font-bold text-grey-900 mb-1">Sign in</h2>
          <p className="text-[14px] text-grey-500 mb-8">Enter your credentials to access the platform</p>

          {error && (
            <div className="mb-6 px-4 py-3 rounded-lg bg-error-lighter border border-error/20 text-[13px] font-semibold text-error-dark">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
                className="w-full h-11 px-3 rounded-lg border border-grey-300 bg-white text-[14px] text-grey-800 placeholder:text-grey-400 outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
              />
            </div>
            <div>
              <label className="block text-[13px] font-semibold text-grey-700 mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  className="w-full h-11 px-3 pr-10 rounded-lg border border-grey-300 bg-white text-[14px] text-grey-800 placeholder:text-grey-400 outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-grey-400 hover:text-grey-600"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full h-11 rounded-lg text-[14px] font-bold bg-grey-900 text-white hover:bg-grey-800 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading && (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              )}
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>

        <p className="text-center text-[13px] text-grey-500 mt-6">
          First time? Contact your administrator for access.
        </p>
      </div>
    </div>
  );
}
