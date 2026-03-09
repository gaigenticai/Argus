"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Plus, X, Calendar } from "lucide-react";
import { api, type Org, type Report } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showGenerate, setShowGenerate] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [loading, setLoading] = useState(true);

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
      } catch {}
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
      }
      setShowGenerate(false);
      // Refresh reports list
      const r = await api.getReports();
      setReports(r);
    } catch {}
    setGenerating(false);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[24px] font-bold text-[#1C252E]">Reports</h2>
          <p className="text-[14px] text-[#637381] mt-0.5">
            Generate executive threat intelligence reports
          </p>
        </div>
        <button
          onClick={() => setShowGenerate(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-[#1C252E] text-white rounded-xl text-[13px] font-bold hover:bg-[#454F5B] transition-colors"
        >
          <Plus className="w-4 h-4" />
          Generate report
        </button>
      </div>

      {/* Generate modal */}
      {showGenerate && (
        <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-[18px] font-bold text-[#1C252E]">Generate report</h3>
              <button onClick={() => setShowGenerate(false)} className="p-1 hover:bg-[#F4F6F8] rounded-lg">
                <X className="w-5 h-5 text-[#637381]" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                  Organization
                </label>
                <select
                  value={orgId}
                  onChange={(e) => setOrgId(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F] bg-white"
                >
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>{o.name}</option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                    From
                  </label>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F]"
                  />
                </div>
                <div>
                  <label className="text-[13px] font-semibold text-[#637381] block mb-1.5">
                    To
                  </label>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl border border-[#DFE3E8] text-[14px] outline-none focus:border-[#00A76F]"
                  />
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowGenerate(false)}
                className="flex-1 py-2.5 rounded-xl text-[13px] font-bold text-[#637381] border border-[#DFE3E8] hover:bg-[#F4F6F8] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generating || !orgId || !dateFrom || !dateTo}
                className="flex-1 py-2.5 rounded-xl text-[13px] font-bold text-white bg-[#00A76F] hover:bg-[#007867] transition-colors disabled:opacity-50"
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
          <div className="w-8 h-8 border-3 border-[#00A76F] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : reports.length === 0 ? (
        <div className="bg-white rounded-2xl p-12 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] flex flex-col items-center text-center">
          <FileText className="w-12 h-12 text-[#C4CDD5] mb-4" />
          <h3 className="text-[16px] font-bold text-[#1C252E] mb-1">No reports yet</h3>
          <p className="text-[14px] text-[#919EAB] max-w-sm">
            Generate your first threat intelligence report to share with stakeholders.
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-2xl shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)] overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#F4F6F8]">
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Report</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Period</th>
                <th className="text-left px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Generated</th>
                <th className="text-right px-6 py-3 text-[12px] font-bold text-[#637381] uppercase">Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id} className="border-b border-[#F4F6F8] last:border-b-0 hover:bg-[#F9FAFB]">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-[#FF5630]" />
                      <span className="text-[14px] font-semibold text-[#1C252E]">{report.title}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-[13px] text-[#637381]">
                    {formatDate(report.date_from)} — {formatDate(report.date_to)}
                  </td>
                  <td className="px-6 py-4 text-[13px] text-[#919EAB]">
                    {formatDate(report.created_at)}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="p-2 rounded-lg hover:bg-[#F4F6F8] text-[#637381] hover:text-[#1C252E] transition-colors">
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
