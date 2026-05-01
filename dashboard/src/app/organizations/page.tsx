"use client";

import { useEffect, useState } from "react";
import {
  Building2,
  Plus,
  Globe,
  Search,
  X,
} from "lucide-react";
import { api, type Org, type CreateOrg } from "@/lib/api";
import { useToast } from "@/components/shared/toast";

export default function OrganizationsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [keywords, setKeywords] = useState("");
  const [industry, setIndustry] = useState("");

  useEffect(() => { loadOrgs(); }, []);

  async function loadOrgs() {
    try {
      const data = await api.getOrgs();
      setOrgs(data);
    } catch {
      toast("error", "Failed to load organizations");
    }
    setLoading(false);
  }

  async function handleCreate() {
    if (!name.trim()) return;
    try {
      await api.createOrg({
        name,
        domains: domains.split(",").map((d) => d.trim()).filter(Boolean),
        keywords: keywords.split(",").map((k) => k.trim()).filter(Boolean),
        industry: industry || undefined,
      });
      setName(""); setDomains(""); setKeywords(""); setIndustry("");
      setShowCreate(false);
      loadOrgs();
      toast("success", `Organization "${name}" created successfully`);
    } catch {
      toast("error", "Failed to create organization");
    }
  }

  const inputCls = "w-full h-10 px-3 text-[13px] outline-none transition-colors";
  const inputStyle = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Organizations</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Monitored organizations and their assets
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-accent)",
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
          }}
        >
          <Plus className="w-4 h-4" />
          Add organization
        </button>
      </div>

      {/* Create modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: "rgba(32,21,21,0.5)" }}
        >
          <div
            className="p-6 w-full max-w-md"
            style={{
              background: "var(--color-canvas)",
              borderRadius: "8px",
              boxShadow: "var(--shadow-z24)",
            }}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-medium" style={{ color: "var(--color-ink)" }}>New organization</h3>
              <button
                onClick={() => setShowCreate(false)}
                className="p-1 transition-colors"
                style={{ borderRadius: "4px" }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[13px] font-semibold block mb-1.5" style={{ color: "var(--color-body)" }}>
                  Organization name *
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Acme Corporation"
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold block mb-1.5" style={{ color: "var(--color-body)" }}>
                  Domains (comma-separated)
                </label>
                <input
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder="acme.com, acme.io"
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold block mb-1.5" style={{ color: "var(--color-body)" }}>
                  Keywords (comma-separated)
                </label>
                <input
                  value={keywords}
                  onChange={(e) => setKeywords(e.target.value)}
                  placeholder="Acme Corp, AcmeTech"
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold block mb-1.5" style={{ color: "var(--color-body)" }}>
                  Industry
                </label>
                <input
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  placeholder="Financial Services"
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 h-10 text-[13px] font-semibold transition-colors"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  color: "var(--color-body)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="flex-1 h-10 text-[13px] font-semibold transition-colors"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-accent)",
                  background: "var(--color-accent)",
                  color: "var(--color-on-dark)",
                }}
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Org cards */}
      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div
            className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
            style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }}
          />
        </div>
      ) : orgs.length === 0 ? (
        <div
          className="p-12 flex flex-col items-center text-center"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
          }}
        >
          <Building2 className="w-12 h-12 mb-4" style={{ color: "var(--color-border)" }} />
          <h3 className="text-[14px] font-semibold mb-1" style={{ color: "var(--color-ink)" }}>No organizations yet</h3>
          <p className="text-[13px] max-w-sm" style={{ color: "var(--color-muted)" }}>
            Add your first organization to start monitoring for threats, credential leaks, and dark web mentions.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {orgs.map((org) => (
            <div
              key={org.id}
              className="p-6 transition-colors"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
              }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--color-border-strong)")}
              onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--color-border)")}
            >
              <div className="flex items-start gap-3 mb-4">
                <div
                  className="w-11 h-11 flex items-center justify-center"
                  style={{
                    borderRadius: "5px",
                    background: "rgba(255,79,0,0.08)",
                  }}
                >
                  <Building2 className="w-6 h-6" style={{ color: "var(--color-accent)" }} />
                </div>
                <div>
                  <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>{org.name}</h3>
                  {org.industry && (
                    <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>{org.industry}</p>
                  )}
                </div>
              </div>

              {org.domains.length > 0 && (
                <div className="mb-3">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Globe className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
                    <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Domains</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.domains.map((d) => (
                      <span
                        key={d}
                        className="px-2 py-0.5 text-[12px] font-medium"
                        style={{
                          borderRadius: "4px",
                          background: "var(--color-surface-muted)",
                          color: "var(--color-body)",
                        }}
                      >
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {org.keywords.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Search className="w-3.5 h-3.5" style={{ color: "var(--color-muted)" }} />
                    <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Keywords</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.keywords.map((k) => (
                      <span
                        key={k}
                        className="px-2 py-0.5 text-[12px] font-medium"
                        style={{
                          borderRadius: "4px",
                          background: "rgba(0,187,217,0.08)",
                          color: "#007B8A",
                        }}
                      >
                        {k}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
