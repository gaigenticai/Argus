"use client";

import { useEffect, useState, useCallback } from "react";
import {
  AlertTriangle,
  Globe,
  Scan,
  Shield,
  Network,
  Wifi,
} from "lucide-react";
import { api, type Org, type OrgAsset } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { Select } from "@/components/shared/select";

interface SubdomainResult {
  subdomain: string;
  ip: string | null;
}

interface ScanResults {
  discovered: number;
  subdomains: SubdomainResult[];
  scan_status?: "ok" | "partial" | "failed";
  errors?: string[];
  domains_scanned?: string[];
}

export default function SurfacePage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>("");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
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
      const res = (await api.scanSubdomains(selectedOrg)) as ScanResults;
      setScanResults(res);
      if (res.scan_status === "failed") {
        toast("error", "Subdomain scan failed — every passive source returned an error");
      } else if (res.scan_status === "partial") {
        toast("info", `Discovered ${res.discovered} subdomain(s) — partial result, some sources failed`);
      } else {
        toast("success", `Discovered ${res.discovered} subdomain(s)`);
      }
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

  const thCls = "text-left h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]";
  const cardStyle = {
    background: "var(--color-canvas)",
    border: "1px solid var(--color-border)",
    borderRadius: "5px",
  } as React.CSSProperties;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>
          Attack surface
        </h2>
        <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
          Discover and monitor public-facing assets
        </p>
      </div>

      {/* Org selector + scan buttons */}
      <div className="flex gap-3 items-center flex-wrap">
        <Select
          value={selectedOrg}
          onChange={setSelectedOrg}
          ariaLabel="Organization"
          options={orgs.map((o) => ({ value: o.id, label: o.name }))}
        />
        <button
          onClick={handleScanSubdomains}
          disabled={scanning || !selectedOrg}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-accent)",
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
          }}
        >
          <Scan className="w-4 h-4" />
          {scanning ? "Scanning..." : "Discover subdomains"}
        </button>
        <button
          onClick={handleScanExposures}
          disabled={!selectedOrg}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-border-strong)",
            background: "var(--color-surface-dark)",
            color: "var(--color-on-dark)",
          }}
        >
          <Shield className="w-4 h-4" />
          Check exposures
        </button>
      </div>

      {/* Overview stats for selected org */}
      {selectedOrgData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4" style={cardStyle}>
            <div className="flex items-center gap-2 mb-2">
              <Globe className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Domains</span>
            </div>
            <div className="space-y-1">
              {selectedOrgData.domains.map((d) => (
                <div key={d} className="text-[13px] font-medium font-mono" style={{ color: "var(--color-body)" }}>{d}</div>
              ))}
            </div>
          </div>
          <div className="p-4" style={cardStyle}>
            <div className="flex items-center gap-2 mb-2">
              <Network className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Discovered assets</span>
            </div>
            <p className="text-[28px] font-bold" style={{ color: "var(--color-ink)" }}>{subdomainAssets.length}</p>
            <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>subdomains in database</p>
          </div>
          <div className="p-4" style={cardStyle}>
            <div className="flex items-center gap-2 mb-2">
              <Wifi className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.8px]" style={{ color: "var(--color-muted)" }}>Industry</span>
            </div>
            <p className="text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>{selectedOrgData.industry || "Not specified"}</p>
          </div>
        </div>
      )}

      {/* Existing discovered assets from DB */}
      {subdomainAssets.length > 0 && !scanResults && (
        <div className="overflow-hidden" style={cardStyle}>
          <div
            className="px-4 h-12 flex items-center"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              Known assets ({subdomainAssets.length})
            </h3>
          </div>
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface-muted)", borderBottom: "1px solid var(--color-border)" }}>
                <th className={thCls} style={{ color: "var(--color-muted)" }}>Asset</th>
                <th className={thCls} style={{ color: "var(--color-muted)" }}>Type</th>
                <th className={thCls} style={{ color: "var(--color-muted)" }}>IP</th>
              </tr>
            </thead>
            <tbody>
              {subdomainAssets.map((asset) => (
                <tr
                  key={asset.id}
                  className="h-[52px] transition-colors"
                  style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4 text-[13px] font-mono" style={{ color: "var(--color-body)" }}>{asset.value}</td>
                  <td className="px-4">
                    <span
                      className="inline-flex items-center h-[20px] px-2 text-[10px] font-semibold uppercase"
                      style={{
                        borderRadius: "4px",
                        background: "var(--color-surface-muted)",
                        color: "var(--color-muted)",
                      }}
                    >
                      {asset.type}
                    </span>
                  </td>
                  <td className="px-4 text-[13px] font-mono" style={{ color: "var(--color-muted)" }}>
                    {(asset.details as Record<string, string>)?.ip || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Scan-status banner */}
      {scanResults && scanResults.scan_status && scanResults.scan_status !== "ok" ? (
        <div
          role="alert"
          className="flex items-start gap-3 px-4 py-3"
          style={{
            borderRadius: "5px",
            border: scanResults.scan_status === "failed"
              ? "1px solid rgba(255,86,48,0.4)"
              : "1px solid rgba(255,171,0,0.4)",
            background: scanResults.scan_status === "failed"
              ? "rgba(255,86,48,0.06)"
              : "rgba(255,171,0,0.06)",
          }}
        >
          <AlertTriangle
            className="w-5 h-5 mt-0.5 shrink-0"
            style={{
              color: scanResults.scan_status === "failed" ? "#B71D18" : "#B76E00",
            }}
          />
          <div className="flex-1 min-w-0">
            <p
              className="text-[13px] font-semibold"
              style={{ color: scanResults.scan_status === "failed" ? "#B71D18" : "#B76E00" }}
            >
              {scanResults.scan_status === "failed"
                ? "Scan failed — passive sources unreachable"
                : "Partial result — some sources failed"}
            </p>
            <p className="text-[12px] mt-0.5" style={{ color: "var(--color-body)" }}>
              {scanResults.scan_status === "failed"
                ? "An empty result here does not mean the surface is clean. Verify connectivity and retry."
                : "An empty result here may be incomplete. Retry the scan once the upstream stabilises."}
            </p>
            {scanResults.errors && scanResults.errors.length > 0 ? (
              <ul className="mt-2 space-y-0.5">
                {scanResults.errors.slice(0, 6).map((e, i) => (
                  <li key={i} className="text-[11.5px] font-mono truncate" style={{ color: "var(--color-muted)" }}>
                    · {e}
                  </li>
                ))}
                {scanResults.errors.length > 6 ? (
                  <li className="text-[11.5px]" style={{ color: "var(--color-muted)" }}>
                    …and {scanResults.errors.length - 6} more
                  </li>
                ) : null}
              </ul>
            ) : null}
          </div>
        </div>
      ) : null}

      {/* Fresh scan results */}
      {scanResults && (
        <div className="overflow-hidden" style={cardStyle}>
          <div
            className="px-4 h-12 flex items-center justify-between"
            style={{ borderBottom: "1px solid var(--color-border)" }}
          >
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
              Scan results — {scanResults.discovered} subdomain(s) discovered
              {scanResults.scan_status === "partial" ? (
                <span className="ml-2 text-[10px] font-semibold uppercase tracking-wider" style={{ color: "#B76E00" }}>
                  · partial
                </span>
              ) : scanResults.scan_status === "failed" ? (
                <span className="ml-2 text-[10px] font-semibold uppercase tracking-wider" style={{ color: "#B71D18" }}>
                  · failed
                </span>
              ) : null}
            </h3>
          </div>
          {scanResults.subdomains.length === 0 ? (
            <div className="p-12 text-center text-[13px]" style={{ color: "var(--color-muted)" }}>
              {scanResults.scan_status === "failed"
                ? "No data — scan failed (see banner above)"
                : scanResults.scan_status === "partial"
                ? "No subdomains discovered — partial result, see banner above"
                : "No subdomains discovered"}
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface-muted)", borderBottom: "1px solid var(--color-border)" }}>
                  <th className={thCls} style={{ color: "var(--color-muted)" }}>Subdomain</th>
                  <th className={thCls} style={{ color: "var(--color-muted)" }}>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {scanResults.subdomains.map((sub, i) => (
                  <tr
                    key={i}
                    className="h-[52px] transition-colors"
                    style={{ borderBottom: "1px solid var(--color-surface-muted)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="px-4">
                      <span className="text-[13px] font-mono font-medium" style={{ color: "var(--color-body)" }}>{sub.subdomain}</span>
                    </td>
                    <td className="px-4 text-[13px] font-mono" style={{ color: "var(--color-muted)" }}>
                      {sub.ip || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Empty state */}
      {!scanResults && !scanning && subdomainAssets.length === 0 && !loadingAssets && (
        <div
          className="p-12 flex flex-col items-center justify-center text-center w-full"
          style={cardStyle}
        >
          <Globe className="w-12 h-12 mb-4" style={{ color: "var(--color-border)" }} />
          <h3 className="text-[14px] font-semibold mb-1" style={{ color: "var(--color-ink)" }}>Attack surface discovery</h3>
          <p className="text-[13px] max-w-sm" style={{ color: "var(--color-muted)" }}>
            Select an organization and run a scan to discover subdomains, exposed services, and misconfigurations.
          </p>
        </div>
      )}
    </div>
  );
}
