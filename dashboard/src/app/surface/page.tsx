"use client";

import { useEffect, useState } from "react";
import { Globe, Scan, Shield, AlertTriangle, RefreshCw } from "lucide-react";
import { api, type Org } from "@/lib/api";

export default function SurfacePage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>("");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<{ discovered: number; subdomains: Array<{ subdomain: string; ip: string | null }> } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const o = await api.getOrgs();
        setOrgs(o);
        if (o.length > 0) setSelectedOrg(o[0].id);
      } catch {}
      setLoading(false);
    }
    load();
  }, []);

  async function handleScanSubdomains() {
    if (!selectedOrg) return;
    setScanning(true);
    setScanResults(null);
    try {
      const res = await api.scanSubdomains(selectedOrg) as { discovered: number; subdomains: Array<{ subdomain: string; ip: string | null }> };
      setScanResults(res);
    } catch {}
    setScanning(false);
  }

  async function handleScanExposures() {
    if (!selectedOrg) return;
    try {
      await api.scanExposures(selectedOrg);
    } catch {}
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[24px] font-bold text-[#1C252E]">Attack surface</h2>
        <p className="text-[14px] text-[#637381] mt-0.5">
          Discover and monitor public-facing assets
        </p>
      </div>

      {/* Org selector + scan buttons */}
      <div className="flex gap-3 items-center flex-wrap">
        <select
          value={selectedOrg}
          onChange={(e) => setSelectedOrg(e.target.value)}
          className="px-4 py-2.5 bg-white rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F]"
        >
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>
        <button
          onClick={handleScanSubdomains}
          disabled={scanning || !selectedOrg}
          className="flex items-center gap-2 px-4 py-2.5 bg-[#00A76F] text-white rounded-xl text-[13px] font-bold hover:bg-[#007867] transition-colors disabled:opacity-50"
        >
          <Scan className="w-4 h-4" />
          {scanning ? "Scanning..." : "Discover subdomains"}
        </button>
        <button
          onClick={handleScanExposures}
          disabled={!selectedOrg}
          className="flex items-center gap-2 px-4 py-2.5 bg-[#1C252E] text-white rounded-xl text-[13px] font-bold hover:bg-[#454F5B] transition-colors disabled:opacity-50"
        >
          <Shield className="w-4 h-4" />
          Check exposures
        </button>
      </div>

      {/* Results */}
      {scanResults && (
        <div className="bg-white rounded-2xl shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#F4F6F8] flex items-center justify-between">
            <h3 className="text-[16px] font-bold text-[#1C252E]">
              Discovered subdomains ({scanResults.discovered})
            </h3>
          </div>
          {scanResults.subdomains.length === 0 ? (
            <div className="p-12 text-center text-[14px] text-[#919EAB]">
              No subdomains discovered
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#F4F6F8]">
                  <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Subdomain</th>
                  <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">IP Address</th>
                </tr>
              </thead>
              <tbody>
                {scanResults.subdomains.map((sub, i) => (
                  <tr key={i} className="border-b border-[#F4F6F8] last:border-b-0 hover:bg-[#F9FAFB]">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-[#00A76F]" />
                        <span className="text-[14px] font-medium text-[#1C252E]">{sub.subdomain}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-[13px] text-[#637381] font-mono">
                      {sub.ip || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {!scanResults && !scanning && (
        <div className="bg-white rounded-2xl p-12 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] flex flex-col items-center text-center">
          <Globe className="w-12 h-12 text-[#C4CDD5] mb-4" />
          <h3 className="text-[16px] font-bold text-[#1C252E] mb-1">Attack surface discovery</h3>
          <p className="text-[14px] text-[#919EAB] max-w-sm">
            Select an organization and run a scan to discover subdomains, exposed services, and misconfigurations.
          </p>
        </div>
      )}
    </div>
  );
}
