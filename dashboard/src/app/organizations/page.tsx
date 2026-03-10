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
import { useToast } from "@/components/shared/toast";

export default function OrganizationsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

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
      setName("");
      setDomains("");
      setKeywords("");
      setIndustry("");
      setShowCreate(false);
      loadOrgs();
      toast("success", `Organization "${name}" created successfully`);
    } catch {
      toast("error", "Failed to create organization");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Organizations</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Monitored organizations and their assets
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-grey-800 text-white hover:bg-grey-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add organization
        </button>
      </div>

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-z24 p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">New organization</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-grey-100 rounded-lg">
                <X className="w-5 h-5 text-grey-600" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                  Organization name *
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Acme Corporation"
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                  Domains (comma-separated)
                </label>
                <input
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder="acme.com, acme.io"
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                  Keywords (comma-separated)
                </label>
                <input
                  value={keywords}
                  onChange={(e) => setKeywords(e.target.value)}
                  placeholder="Acme Corp, AcmeTech"
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                />
              </div>
              <div>
                <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                  Industry
                </label>
                <input
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  placeholder="Financial Services"
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 h-10 rounded-lg text-[14px] font-bold border border-grey-300 text-grey-700 hover:bg-grey-100 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="flex-1 h-10 rounded-lg text-[14px] font-bold text-white bg-primary hover:bg-primary-dark transition-colors"
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
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : orgs.length === 0 ? (
        <div className="bg-white rounded-xl border border-grey-200 p-12 flex flex-col items-center text-center">
          <Building2 className="w-12 h-12 text-grey-300 mb-4" />
          <h3 className="text-[16px] font-bold text-grey-900 mb-1">No organizations yet</h3>
          <p className="text-[14px] text-grey-500 max-w-sm">
            Add your first organization to start monitoring for threats, credential leaks, and dark web mentions.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {orgs.map((org) => (
            <div
              key={org.id}
              className="bg-white rounded-xl border border-grey-200 p-6 hover:shadow-z8 transition-shadow"
            >
              <div className="flex items-start gap-3 mb-4">
                <div className="w-11 h-11 rounded-xl bg-primary-lighter flex items-center justify-center">
                  <Building2 className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <h3 className="text-[16px] font-bold text-grey-900">{org.name}</h3>
                  {org.industry && (
                    <p className="text-[12px] text-grey-500">{org.industry}</p>
                  )}
                </div>
              </div>

              {org.domains.length > 0 && (
                <div className="mb-3">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Globe className="w-3.5 h-3.5 text-grey-500" />
                    <span className="text-[11px] font-bold text-grey-500 uppercase">Domains</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.domains.map((d) => (
                      <span
                        key={d}
                        className="px-2 py-0.5 bg-grey-200 rounded text-[12px] text-grey-600 font-medium"
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
                    <Search className="w-3.5 h-3.5 text-grey-500" />
                    <span className="text-[11px] font-bold text-grey-500 uppercase">Keywords</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {org.keywords.map((k) => (
                      <span
                        key={k}
                        className="px-2 py-0.5 bg-secondary-lighter rounded text-[12px] text-secondary font-medium"
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
