import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const severityConfig: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: "text-[#FF5630]", bg: "bg-[#FFE9D5]", label: "Critical" },
  high: { color: "text-[#B76E00]", bg: "bg-[#FFF5CC]", label: "High" },
  medium: { color: "text-[#B76E00]", bg: "bg-[#FFF8D6]", label: "Medium" },
  low: { color: "text-[#006C9C]", bg: "bg-[#CAFDF5]", label: "Low" },
  info: { color: "text-[#637381]", bg: "bg-[#F4F6F8]", label: "Info" },
};

export const statusConfig: Record<string, { color: string; bg: string }> = {
  new: { color: "text-[#FF5630]", bg: "bg-[#FFE9D5]" },
  triaged: { color: "text-[#B76E00]", bg: "bg-[#FFF5CC]" },
  investigating: { color: "text-[#006C9C]", bg: "bg-[#CAFDF5]" },
  confirmed: { color: "text-[#B71D18]", bg: "bg-[#FFE9D5]" },
  false_positive: { color: "text-[#637381]", bg: "bg-[#F4F6F8]" },
  resolved: { color: "text-[#118D57]", bg: "bg-[#D3FCD2]" },
};

export const categoryLabels: Record<string, string> = {
  credential_leak: "Credential Leak",
  data_breach: "Data Breach",
  vulnerability: "Vulnerability",
  exploit: "Exploit",
  ransomware: "Ransomware",
  phishing: "Phishing",
  impersonation: "Impersonation",
  doxxing: "Doxxing",
  insider_threat: "Insider Threat",
  brand_abuse: "Brand Abuse",
  dark_web_mention: "Dark Web Mention",
  paste_leak: "Paste Leak",
  code_leak: "Code Leak",
};

export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
