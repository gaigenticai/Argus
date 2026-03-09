"use client";

import { useEffect, useState } from "react";
import {
  Building2,
  Plus,
  Globe,
  Users,
  Search,
  X,
} from "lucide-react";
import { api, type Org, type CreateOrg } from "@/lib/api";

export default function OrganizationsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);

  // Form state
  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [keywords, setKeywords] = useState("");
  const [industry, setIndustry] = useState("");

  useEffect(() => {
    loadOrgs();
  }, []);

  async function loadOrgs() {
    try {
      const data = await api.getOrgs();
      setOrgs(data);
    } catch {}
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
      setName("");
      setDomains("");
      setKeywords("");
      setIndustry("");
      setShowCreate(false);
      loadOrgs();
    } catch {}
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-bold text-[#1C252E]">Organizations</h2>
          <p className="text-[14px] text-[#637381] mt-0.5">
            Monitored organizations and their assets
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-[#1C252E] text-white rounded-xl text-[13px] font-bold hover:bg-[#454F5B] transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add organization
        </button>
      </div>

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-[#1C252E]">New organization</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-[#F4F6F8] rounded-lg">
                <X className="w-5 h-5 text-[#637381]" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                  Organization name *
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Acme Corporation"
                  className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F] transition-colors"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                  Domains (comma-separated)
                </label>
                <input
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder="acme.com, acme.io"
                  className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F] transition-colors"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                  Keywords (comma-separated)
                </label>
                <input
                  value={keywords}
                  onChange={(e) => setKeywords(e.target.value)}
                  placeholder="Acme Corp, AcmeTech"
                  className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F] transition-colors"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                  Industry
                </label>
                <input
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  placeholder="Financial Services"
                  className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F] transition-colors"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 py-2.5 rounded-xl text-[13px] font-bold text-[#637381] border border-[#DFE3E8] hover:bg-[#F4F6F8] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="flex-1 py-2.5 rounded-xl text-[13px] font-bold text-white bg-[#00A76F] hover:bg-[#007867] transition-colors"
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
          <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : orgs.length === 0 ? (
        <div className="bg-white rounded-2xl p-12 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] flex flex-col items-center text-center">
          <Building2 className="w-12 h-12 text-[#C4CDD5] mb-4" />
          <h3 className="text-[16px] font-bold text-[#1C252E] mb-1">No organizations yet</h3>
          <p className="text-[14px] text-[#919EAB] max-w-sm">
            Add your first organization to start monitoring for threats, credential leaks, and dark web mentions.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {orgs.map((org) => (
            <div
              key={org.id}
              className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] hover:shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_20px_40px_-4px_rgba(145,158,171,0.16)] transition-shadow"
            >
              <div className="flex items-start gap-3 mb-4">
                <div className="w-11 h-11 rounded-xl bg-[#C8FAD6] flex items-center justify-center">
                  <Building2 className="w-6 h-6 text-[#00A76F]" />
                </div>
                <div>
                  <h3 className="text-[16px] font-bold text-[#1C252E]">{org.name}</h3>
                  {org.industry && (
                    <p className="text-[12px] text-[#919EAB]">{org.industry}</p>
                  )}
                </div>
              </div>

              {org.domains.length > 0 && (
                <div className="mb-3">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Globe className="w-3.5 h-3.5 text-[#919EAB]" />
                    <span className="text-[11px] font-bold text-[#919EAB] uppercase">Domains</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.domains.map((d) => (
                      <span
                        key={d}
                        className="px-2 py-0.5 bg-[#F4F6F8] rounded text-[12px] text-[#637381] font-medium"
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
                    <Search className="w-3.5 h-3.5 text-[#919EAB]" />
                    <span className="text-[11px] font-bold text-[#919EAB] uppercase">Keywords</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.keywords.map((k) => (
                      <span
                        key={k}
                        className="px-2 py-0.5 bg-[#EFD6FF] rounded text-[12px] text-[#8E33FF] font-medium"
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
