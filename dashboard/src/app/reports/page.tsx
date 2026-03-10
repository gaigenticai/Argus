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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[22px] font-bold text-grey-900">Reports</h2>
          <p className="text-[14px] text-grey-500 mt-0.5">
            Generate executive threat intelligence reports
          </p>
        </div>
        <button
          onClick={() => setShowGenerate(true)}
          className="flex items-center gap-2 h-10 px-4 rounded-lg text-[14px] font-bold bg-grey-800 text-white hover:bg-grey-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Generate report
        </button>
      </div>

      {/* Generate modal */}
      {showGenerate && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-z24 p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-grey-900">Generate report</h3>
              <button onClick={() => setShowGenerate(false)} className="p-1 hover:bg-grey-200 rounded-lg">
                <X className="w-5 h-5 text-grey-600" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                  Organization
                </label>
                <select
                  value={orgId}
                  onChange={(e) => setOrgId(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                >
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>{o.name}</option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                    From
                  </label>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                  />
                </div>
                <div>
                  <label className="text-[13px] font-semibold text-grey-600 block mb-1.5">
                    To
                  </label>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    className="w-full h-10 px-3 rounded-lg border border-grey-300 text-[14px] outline-none focus:border-primary bg-white"
                  />
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowGenerate(false)}
                className="flex-1 h-10 rounded-lg text-[14px] font-bold border border-grey-300 bg-white text-grey-700 hover:bg-grey-100 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generating || !orgId || !dateFrom || !dateTo}
                className="flex-1 h-10 rounded-lg text-[14px] font-bold text-white bg-primary hover:bg-primary-dark transition-colors disabled:opacity-50"
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
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : reports.length === 0 ? (
        <div className="bg-white rounded-xl border border-grey-200 p-12 flex flex-col items-center text-center">
          <FileText className="w-12 h-12 text-grey-300 mb-4" />
          <h3 className="text-[16px] font-bold text-grey-900 mb-1">No reports yet</h3>
          <p className="text-[14px] text-grey-500 max-w-sm">
            Generate your first threat intelligence report to share with stakeholders.
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-grey-200 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-grey-200">
                <th className="text-left px-6 py-3 text-[12px] font-bold text-grey-600 uppercase">Report</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-grey-600 uppercase">Period</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-grey-600 uppercase">Generated</th>
                <th className="text-right px-6 py-3 text-[12px] font-bold text-grey-600 uppercase">Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id} className="border-b border-grey-200 last:border-b-0 hover:bg-grey-100">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-error" />
                      <span className="text-[14px] font-semibold text-grey-900">{report.title}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-[13px] text-grey-600">
                    {formatDate(report.date_from)} — {formatDate(report.date_to)}
                  </td>
                  <td className="px-6 py-4 text-[13px] text-grey-500">
                    {formatDate(report.created_at)}
                  </td>
                  <td className="px-6 py-4 text-right">
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
                      className="p-2 rounded-lg hover:bg-grey-200 text-grey-600 hover:text-grey-900 transition-colors"
                    >
                      <Download className="w-4 h-4" />
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
