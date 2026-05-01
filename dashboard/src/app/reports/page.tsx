"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Plus, X, Calendar } from "lucide-react";
import { api, type Org, type Report } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { useToast } from "@/components/shared/toast";

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showGenerate, setShowGenerate] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  // Form
  const [orgId, setOrgId] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const [r, o] = await Promise.all([api.getReports(), api.getOrgs()]);
        setReports(r);
        setOrgs(o);
        if (o.length > 0) setOrgId(o[0].id);
      } catch {
        toast("error", "Failed to load reports");
      }
      setLoading(false);
    }
    load();
  }, []);

  async function handleGenerate() {
    if (!orgId || !dateFrom || !dateTo) return;
    setGenerating(true);
    try {
      const res = await api.generateReport(orgId, dateFrom, dateTo);
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `argus-report-${dateFrom}-${dateTo}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        toast("success", "Report generated and downloaded");
      } else {
        toast("error", "Report generation failed");
      }
      setShowGenerate(false);
      const r = await api.getReports();
      setReports(r);
    } catch {
      toast("error", "Report generation failed");
    }
    setGenerating(false);
  }

  const inputStyle: React.CSSProperties = {
    borderRadius: "4px",
    border: "1px solid var(--color-border)",
    background: "var(--color-canvas)",
    color: "var(--color-ink)",
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-medium tracking-[-0.02em]" style={{ color: "var(--color-ink)" }}>Reports</h2>
          <p className="text-[13px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Generate executive threat intelligence reports
          </p>
        </div>
        <button
          onClick={() => setShowGenerate(true)}
          className="flex items-center gap-2 h-9 px-4 text-[13px] font-semibold transition-colors"
          style={{
            borderRadius: "4px",
            border: "1px solid var(--color-accent)",
            background: "var(--color-accent)",
            color: "var(--color-on-dark)",
          }}
        >
          <Plus className="w-4 h-4" />
          Generate report
        </button>
      </div>

      {/* Generate modal */}
      {showGenerate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: "rgba(32,21,21,0.5)" }}
        >
          <div
            className="p-6 w-full max-w-md"
            style={{ background: "var(--color-canvas)", borderRadius: "8px", boxShadow: "var(--shadow-z24)" }}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[17px] font-semibold" style={{ color: "var(--color-ink)" }}>Generate report</h3>
              <button
                onClick={() => setShowGenerate(false)}
                className="p-1 transition-opacity hover:opacity-70"
              >
                <X className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5" style={{ color: "var(--color-muted)" }}>
                  Organization
                </label>
                <select
                  value={orgId}
                  onChange={(e) => setOrgId(e.target.value)}
                  className="w-full h-10 px-3 text-[13px] outline-none"
                  style={inputStyle}
                >
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>{o.name}</option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5" style={{ color: "var(--color-muted)" }}>
                    From
                  </label>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    className="w-full h-10 px-3 text-[13px] outline-none"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="text-[12px] font-semibold uppercase tracking-[0.07em] block mb-1.5" style={{ color: "var(--color-muted)" }}>
                    To
                  </label>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    className="w-full h-10 px-3 text-[13px] outline-none"
                    style={inputStyle}
                  />
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowGenerate(false)}
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
                onClick={handleGenerate}
                disabled={generating || !orgId || !dateFrom || !dateTo}
                className="flex-1 h-10 text-[13px] font-semibold transition-colors disabled:opacity-50"
                style={{
                  borderRadius: "4px",
                  border: "1px solid var(--color-accent)",
                  background: "var(--color-accent)",
                  color: "var(--color-on-dark)",
                }}
              >
                {generating ? "Generating..." : "Generate PDF"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reports list */}
      {loading ? (
        <div className="flex items-center justify-center h-[300px]">
          <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: "var(--color-accent)", borderTopColor: "transparent" }} />
        </div>
      ) : reports.length === 0 ? (
        <div
          className="p-12 flex flex-col items-center text-center"
          style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px" }}
        >
          <FileText className="w-12 h-12 mb-4" style={{ color: "var(--color-border)" }} />
          <h3 className="text-[15px] font-semibold mb-1" style={{ color: "var(--color-ink)" }}>No reports yet</h3>
          <p className="text-[13px] max-w-sm" style={{ color: "var(--color-muted)" }}>
            Generate your first threat intelligence report to share with stakeholders.
          </p>
        </div>
      ) : (
        <div style={{ background: "var(--color-canvas)", border: "1px solid var(--color-border)", borderRadius: "5px", overflow: "hidden" }}>
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--color-border)" }}>
                {["Report", "Period", "Generated", ""].map((h, i) => (
                  <th
                    key={i}
                    className={`${i === 3 ? "text-right" : "text-left"} h-9 px-4 text-[10px] font-semibold uppercase tracking-[0.07em]`}
                    style={{ color: "var(--color-muted)" }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr
                  key={report.id}
                  className="h-[52px]"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="px-4">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5" style={{ color: "#FF5630" }} />
                      <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{report.title}</span>
                    </div>
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-body)" }}>
                    {formatDate(report.date_from)} — {formatDate(report.date_to)}
                  </td>
                  <td className="px-4 text-[13px]" style={{ color: "var(--color-muted)" }}>
                    {formatDate(report.created_at)}
                  </td>
                  <td className="px-4 text-right">
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.downloadReport(report.id);
                          if (res.ok) {
                            const blob = await res.blob();
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `${report.title.replace(/[^a-zA-Z0-9-_ ]/g, "")}.pdf`;
                            a.click();
                            URL.revokeObjectURL(url);
                          }
                        } catch {
                          // download failed
                        }
                      }}
                      className="p-2 transition-colors"
                      style={{ borderRadius: "4px" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <Download className="w-4 h-4" style={{ color: "var(--color-body)" }} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
