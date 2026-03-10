import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const severityConfig: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: "text-error", bg: "bg-error-lighter", label: "Critical" },
  high: { color: "text-warning-dark", bg: "bg-warning-lighter", label: "High" },
  medium: { color: "text-warning-dark", bg: "bg-warning-lighter", label: "Medium" },
  low: { color: "text-info-dark", bg: "bg-info-lighter", label: "Low" },
  info: { color: "text-grey-600", bg: "bg-grey-200", label: "Info" },
};

export const statusConfig: Record<string, { color: string; bg: string }> = {
  new: { color: "text-error", bg: "bg-error-lighter" },
  needs_review: { color: "text-secondary", bg: "bg-secondary-lighter" },
  triaged: { color: "text-warning-dark", bg: "bg-warning-lighter" },
  investigating: { color: "text-info-dark", bg: "bg-info-lighter" },
  confirmed: { color: "text-error-dark", bg: "bg-error-lighter" },
  false_positive: { color: "text-grey-600", bg: "bg-grey-200" },
  resolved: { color: "text-success-dark", bg: "bg-success-lighter" },
};

export const categoryLabels: Record<string, string> = {
  credential_leak: "Credential Leak",
  data_breach: "Data Breach",
  stealer_log: "Stealer Log",
  ransomware: "Ransomware",
  ransomware_victim: "Ransomware Victim",
  access_sale: "Access Sale",
  exploit: "Exploit",
  phishing: "Phishing",
  impersonation: "Impersonation",
  doxxing: "Doxxing",
  insider_threat: "Insider Threat",
  brand_abuse: "Brand Abuse",
  dark_web_mention: "Dark Web Mention",
  underground_chatter: "Underground Chatter",
  initial_access: "Initial Access",
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
