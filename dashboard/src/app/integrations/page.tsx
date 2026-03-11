"use client";

import {
  Puzzle,
  ExternalLink,
  CheckCircle,
  Clock,
  Lock,
} from "lucide-react";

interface Integration {
  name: string;
  description: string;
  license: string;
  status: "available" | "coming_soon" | "connected";
  category: string;
  color: string;
}

const INTEGRATIONS: Integration[] = [
  {
    name: "OpenCTI",
    description: "Cyber threat intelligence platform — STIX 2.1 knowledge graph, threat correlation, relationship mapping",
    license: "Apache-2.0",
    status: "coming_soon",
    category: "Threat Intelligence",
    color: "#2196F3",
  },
  {
    name: "Wazuh",
    description: "Unified XDR + SIEM — endpoint monitoring, log analysis, file integrity, compliance",
    license: "GPL-2.0",
    status: "coming_soon",
    category: "SIEM / EDR",
    color: "#00A76F",
  },
  {
    name: "Nuclei",
    description: "Template-based vulnerability scanner — 11,000+ templates for CVEs, misconfigs, exposures",
    license: "MIT",
    status: "coming_soon",
    category: "Vulnerability Scanning",
    color: "#8E33FF",
  },
  {
    name: "YARA",
    description: "Pattern matching engine for malware classification — rule-based detection on files and memory",
    license: "BSD-3",
    status: "coming_soon",
    category: "Malware Analysis",
    color: "#FF5630",
  },
  {
    name: "Sigma Rules",
    description: "Universal detection rule format — 3,000+ community rules mapped to MITRE ATT&CK",
    license: "DRL 1.1",
    status: "coming_soon",
    category: "Detection Rules",
    color: "#FFAB00",
  },
  {
    name: "SpiderFoot",
    description: "OSINT automation with 200+ modules — domains, emails, leaked creds, dark web, infrastructure",
    license: "MIT",
    status: "coming_soon",
    category: "OSINT",
    color: "#00BBD9",
  },
  {
    name: "Suricata",
    description: "High-performance network IDS/IPS — deep packet inspection, protocol analysis, EVE JSON logging",
    license: "GPL-2.0",
    status: "coming_soon",
    category: "Network IDS",
    color: "#FF8B00",
  },
  {
    name: "Shuffle",
    description: "SOAR platform — visual workflow builder, 200+ app integrations, automated playbooks",
    license: "AGPL-3.0",
    status: "coming_soon",
    category: "SOAR",
    color: "#FF6C40",
  },
  {
    name: "GoPhish",
    description: "Phishing simulation framework — campaigns, tracking, security awareness reporting",
    license: "MIT",
    status: "coming_soon",
    category: "Phishing Simulation",
    color: "#8E33FF",
  },
  {
    name: "Prowler",
    description: "Cloud security posture management — AWS, Azure, GCP compliance checks (CIS, NIST, PCI-DSS)",
    license: "Apache-2.0",
    status: "coming_soon",
    category: "Cloud Security",
    color: "#00A76F",
  },
];

const STATUS_CONFIG = {
  connected: { label: "Connected", icon: CheckCircle, color: "text-success", bg: "bg-success-lighter" },
  available: { label: "Available", icon: Clock, color: "text-info-dark", bg: "bg-info-lighter" },
  coming_soon: { label: "Coming Soon", icon: Clock, color: "text-grey-600", bg: "bg-grey-200" },
};

export default function IntegrationsPage() {
  const categories = Array.from(new Set(INTEGRATIONS.map((i) => i.category)));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-[22px] font-bold text-grey-900">Integrations</h2>
        <p className="text-[14px] text-grey-500 mt-0.5">
          Connect world-class open-source security tools to build an all-in-one platform
        </p>
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 px-6 py-4 bg-white rounded-xl border border-grey-200">
        <div>
          <span className="text-[28px] font-extrabold text-grey-900">{INTEGRATIONS.length}</span>
          <p className="text-[12px] text-grey-500">Total integrations</p>
        </div>
        <div className="w-px h-10 bg-grey-200" />
        <div>
          <span className="text-[28px] font-extrabold text-success">
            {INTEGRATIONS.filter((i) => i.status === "connected").length}
          </span>
          <p className="text-[12px] text-grey-500">Connected</p>
        </div>
        <div className="w-px h-10 bg-grey-200" />
        <div>
          <span className="text-[28px] font-extrabold text-grey-500">
            {INTEGRATIONS.filter((i) => i.status === "coming_soon").length}
          </span>
          <p className="text-[12px] text-grey-500">In development</p>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-2 text-[13px] text-grey-500">
          <Lock className="w-4 h-4" />
          All tools are open-source with commercial-friendly licenses
        </div>
      </div>

      {/* Integration grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {INTEGRATIONS.map((integration) => {
          const statusCfg = STATUS_CONFIG[integration.status];
          const StatusIcon = statusCfg.icon;

          return (
            <div
              key={integration.name}
              className="bg-white rounded-xl border border-grey-200 p-5 hover:border-grey-300 transition-colors"
            >
              <div className="flex items-start gap-4">
                {/* Icon */}
                <div
                  className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 text-[16px] font-extrabold text-white"
                  style={{ backgroundColor: integration.color }}
                >
                  {integration.name.charAt(0)}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-[15px] font-bold text-grey-900">{integration.name}</h3>
                    <span className={`inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full ${statusCfg.bg} ${statusCfg.color}`}>
                      <StatusIcon className="w-3 h-3" />
                      {statusCfg.label}
                    </span>
                  </div>
                  <p className="text-[13px] text-grey-600 leading-snug mb-2">
                    {integration.description}
                  </p>
                  <div className="flex items-center gap-3">
                    <span className="text-[11px] font-medium text-grey-500 bg-grey-100 px-2 py-0.5 rounded">
                      {integration.category}
                    </span>
                    <span className="text-[11px] font-mono text-grey-400">
                      {integration.license}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
