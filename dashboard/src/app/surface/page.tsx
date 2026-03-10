"use client";

import { useEffect, useState, useCallback } from "react";
import { Globe, Scan, Shield, Server, Network, Wifi, ExternalLink } from "lucide-react";
import { api, type Org, type OrgAsset } from "@/lib/api";
import { useToast } from "@/components/shared/toast";

interface SubdomainResult {
  subdomain: string;
  ip: string | null;
}

export default function SurfacePage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>("");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<{ discovered: number; subdomains: SubdomainResult[] } | null>(null);
  const [assets, setAssets] = useState<OrgAsset[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    async function load() {
      try {
        const o = await api.getOrgs();
        setOrgs(o);
        if (o.length > 0) setSelectedOrg(o[0].id);
      } catch {
        toast("error", "Failed to load organizations");
      }
      setLoading(false);
    }
    load();
  }, []);

  const loadAssets = useCallback(async (orgId: string) => {
    if (!orgId) return;
    setLoadingAssets(true);
    try {
      const data = await api.getAssets(orgId);
      setAssets(data);
    } catch {
      setAssets([]);
    }
    setLoadingAssets(false);
  }, []);

  // Load assets when org changes
  useEffect(() => {
    if (selectedOrg) {
      loadAssets(selectedOrg);
      setScanResults(null);
    }
  }, [selectedOrg, loadAssets]);

  const selectedOrgData = orgs.find((o) => o.id === selectedOrg);
  const subdomainAssets = assets.filter((a) => a.type === "subdomain");

  async function handleScanSubdomains() {
    if (!selectedOrg) return;
    setScanning(true);
    setScanResults(null);
    try {
      const res = await api.scanSubdomains(selectedOrg) as { discovered: number; subdomains: SubdomainResult[] };
      setScanResults(res);
      toast("success", `Discovered ${res.discovered} subdomain(s)`);
      // Reload assets to get newly stored ones
      await loadAssets(selectedOrg);
    } catch {
      toast("error", "Subdomain scan failed");
    }
    setScanning(false);
  }

  async function handleScanExposures() {
    if (!selectedOrg) return;
    try {
      await api.scanExposures(selectedOrg);
      toast("info", "Exposure scan started in background");
    } catch {
      toast("error", "Exposure scan failed");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[22px] font-bold text-grey-900">Attack surface</h2>
        <p className="text-[14px] text-grey-500 mt-0.5">
          Discover and monitor public-facing assets
        </p>
      </div>

      {/* Org selector + scan buttons */}
      <div className="flex gap-3 items-center flex-wrap">
        <select
          value={selectedOrg}
          onChange={(e) => setSelectedOrg(e.target.value)}
          className="h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
        >
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>
        <button
          onClick={handleScanSubdomains}
          disabled={scanning || !selectedOrg}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
        >
          <Scan className="w-4 h-4" />
          {scanning ? "Scanning..." : "Discover subdomains"}
        </button>
        <button
          onClick={handleScanExposures}
          disabled={!selectedOrg}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-grey-800 text-white hover:bg-grey-700 transition-colors disabled:opacity-50"
        >
          <Shield className="w-4 h-4" />
          Check exposures
        </button>
      </div>

      {/* Overview stats for selected org */}
      {selectedOrgData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white rounded-xl border border-grey-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="w-4 h-4 text-grey-500" />
              <span className="text-[12px] font-bold text-grey-500 uppercase tracking-wider">Domains</span>
            </div>
            <div className="space-y-1">
              {selectedOrgData.domains.map((d) => (
                <div key={d} className="text-[14px] font-medium text-grey-800 font-mono">{d}</div>
              ))}
            </div>
          </div>
          <div className="bg-white rounded-xl border border-grey-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Network className="w-4 h-4 text-grey-500" />
              <span className="text-[12px] font-bold text-grey-500 uppercase tracking-wider">Discovered assets</span>
            </div>
            <p className="text-[28px] font-extrabold text-grey-900">{subdomainAssets.length}</p>
            <p className="text-[12px] text-grey-500">subdomains in database</p>
          </div>
          <div className="bg-white rounded-xl border border-grey-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Wifi className="w-4 h-4 text-grey-500" />
              <span className="text-[12px] font-bold text-grey-500 uppercase tracking-wider">Industry</span>
            </div>
            <p className="text-[14px] font-semibold text-grey-800">{selectedOrgData.industry || "Not specified"}</p>
          </div>
        </div>
      )}

      {/* Existing discovered assets from DB */}
      {subdomainAssets.length > 0 && !scanResults && (
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          <div className="px-4 h-12 flex items-center border-b border-grey-200">
            <h3 className="text-[14px] font-bold text-grey-800">
              Known assets ({subdomainAssets.length})
            </h3>
          </div>
          <table className="w-full">
            <thead>
              <tr className="bg-grey-100 border-b border-grey-200">
                <th className="text-left h-12 px-4 text-[12px] font-bold text-grey-600 uppercase tracking-wider">Asset</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold text-grey-600 uppercase tracking-wider">Type</th>
                <th className="text-left h-12 px-4 text-[12px] font-bold text-grey-600 uppercase tracking-wider">IP</th>
              </tr>
            </thead>
            <tbody>
              {subdomainAssets.map((asset) => (
                <tr key={asset.id} className="h-[52px] border-b border-grey-200 last:border-b-0 hover:bg-grey-50">
                  <td className="px-4 text-[14px] font-mono text-grey-800">{asset.value}</td>
                  <td className="px-4">
                    <span className="inline-flex items-center h-[22px] px-2 rounded text-[11px] font-semibold bg-grey-100 text-grey-600 uppercase">
                      {asset.type}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] font-mono text-grey-500">
                    {(asset.details as Record<string, string>)?.ip || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Fresh scan results */}
      {scanResults && (
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          <div className="px-4 h-12 flex items-center justify-between border-b border-grey-200">
            <h3 className="text-[14px] font-bold text-grey-800">
              Scan results — {scanResults.discovered} subdomain(s) discovered
            </h3>
          </div>
          {scanResults.subdomains.length === 0 ? (
            <div className="p-12 text-center w-full text-[14px] text-grey-500">
              No subdomains discovered
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-grey-100 border-b border-grey-200">
                  <th className="text-left h-12 px-4 text-[12px] font-bold text-grey-600 uppercase tracking-wider">Subdomain</th>
                  <th className="text-left h-12 px-4 text-[12px] font-bold text-grey-600 uppercase tracking-wider">IP Address</th>
                </tr>
              </thead>
              <tbody>
                {scanResults.subdomains.map((sub, i) => (
                  <tr key={i} className="h-[52px] border-b border-grey-200 last:border-b-0 hover:bg-grey-50">
                    <td className="px-4">
                      <span className="text-[14px] font-mono font-medium text-grey-800">{sub.subdomain}</span>
                    </td>
                    <td className="px-4 text-[13px] text-grey-500 font-mono">
                      {sub.ip || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Empty state — only if no assets and no scan results */}
      {!scanResults && !scanning && subdomainAssets.length === 0 && !loadingAssets && (
        <div className="bg-white rounded-xl border border-grey-200 p-12 flex flex-col items-center justify-center text-center w-full">
          <Globe className="w-12 h-12 text-grey-300 mb-4" />
          <h3 className="text-[16px] font-bold text-grey-900 mb-1">Attack surface discovery</h3>
          <p className="text-[14px] text-grey-500 max-w-sm">
            Select an organization and run a scan to discover subdomains, exposed services, and misconfigurations.
          </p>
        </div>
      )}
    </div>
  );
}
