"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Download,
  FileText,
  Image as ImageIcon,
  Lock,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import {
  api,
  type EvidenceAuditChainEntry,
  type EvidenceAuditChainVerify,
  type EvidenceBlobResponse,
  type EvidenceCoCNarrative,
  type EvidenceSimilarResponse,
  type Org,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";

import { SourcesStrip } from "@/components/shared/sources-strip";
const KIND_OPTIONS = [
  { value: "all", label: "Any kind" },
  { value: "screenshot", label: "Screenshot" },
  { value: "html", label: "HTML" },
  { value: "pdf", label: "PDF" },
  { value: "image", label: "Image" },
  { value: "video", label: "Video" },
  { value: "audio", label: "Audio" },
  { value: "document", label: "Document" },
  { value: "log", label: "Log" },
  { value: "app_store_listing", label: "App store listing" },
  { value: "other", label: "Other" },
];

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

export default function EvidencePage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [rows, setRows] = useState<EvidenceBlobResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [kind, setKind] = useState("all");
  const [showDeleted, setShowDeleted] = useState(false);
  const [search, setSearch] = useState("");
  const [showUpload, setShowUpload] = useState(false);
  const [legalHoldTarget, setLegalHoldTarget] =
    useState<EvidenceBlobResponse | null>(null);
  const [deleteTarget, setDeleteTarget] =
    useState<EvidenceBlobResponse | null>(null);
  const [drawerTarget, setDrawerTarget] =
    useState<EvidenceBlobResponse | null>(null);
  const [chainStatus, setChainStatus] =
    useState<EvidenceAuditChainVerify | null>(null);
  const [chainBusy, setChainBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted = localStorage.getItem("argus_org_id");
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgIdState(initial);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load organizations",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    localStorage.setItem("argus_org_id", id);
  }, []);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await api.evidence.list({
        organization_id: orgId,
        kind: kind === "all" ? undefined : (kind as never),
        q: search || undefined,
        limit: 200,
      });
      setRows(showDeleted ? data : data.filter((r) => !r.is_deleted));
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load evidence",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, kind, search, showDeleted, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const download = async (b: EvidenceBlobResponse) => {
    try {
      const r = await api.evidence.download(b.id);
      window.open(r.url, "_blank", "noopener,noreferrer");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Download failed");
    }
  };

  const restore = async (b: EvidenceBlobResponse) => {
    try {
      await api.evidence.restore(b.id);
      toast("success", "Evidence restored");
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Restore failed");
    }
  };

  const setLegalHold = async (
    b: EvidenceBlobResponse,
    enabled: boolean,
    reason: string,
  ) => {
    try {
      await api.retention.setLegalHold({
        resource_type: "evidence_blobs",
        resource_id: b.id,
        legal_hold: enabled,
        reason: reason || undefined,
      });
      toast(
        "success",
        enabled ? "Legal hold applied" : "Legal hold released",
      );
      setLegalHoldTarget(null);
      await load();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Legal hold update failed",
      );
    }
  };

  const verifyChain = useCallback(async () => {
    if (!orgId) return;
    setChainBusy(true);
    try {
      const r = await api.evidence.verifyChain(orgId);
      setChainStatus(r);
      toast(
        r.valid ? "success" : "error",
        r.valid
          ? `Audit chain verified — ${r.total_rows} rows, head ${(r.head_chain_hash || "").slice(0, 12)}…`
          : `Audit chain BROKEN at sequence ${r.broken_at_sequence}. Treat as a security incident.`,
      );
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Verify failed");
    } finally {
      setChainBusy(false);
    }
  }, [orgId, toast]);

  const remove = async (b: EvidenceBlobResponse, reason: string) => {
    try {
      await api.evidence.delete(b.id, reason);
      toast("success", "Evidence soft-deleted");
      setDeleteTarget(null);
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Delete failed");
    }
  };

  const totalSize = rows.reduce((s, r) => s + r.size_bytes, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: FileText, label: "Governance" }}
        title="Evidence Vault"
        description="MinIO-backed object store for detection evidence — screenshots, HTML snapshots, PDFs, app-store listings, breach evidence. SHA-256 dedup, magic-byte MIME validation, soft-delete with legal-hold flag."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
      <SourcesStrip pageKey="evidence" />
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={() => setShowUpload(true)}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Upload className="w-4 h-4" />
              Upload
            </button>
          </>
        }
      />

      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <div className="grid grid-cols-2 md:grid-cols-3">
          <Stat label="Blobs" value={rows.length.toString()} />
          <Stat label="Total size" value={formatBytes(totalSize)} />
          <Stat
            label="Soft-deleted"
            value={rows.filter((r) => r.is_deleted).length.toString()}
            tone="muted"
          />
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search hash, filename, OCR text…"
          className="h-10 px-3 w-[260px] text-[12.5px] font-mono"
          style={inputStyle}
        />
        <Select
          ariaLabel="Kind"
          value={kind}
          options={KIND_OPTIONS}
          onChange={setKind}
        />
        <button
          onClick={() => setShowDeleted((v) => !v)}
          className="h-10 px-3 text-[12px] font-bold transition-colors"
          style={showDeleted
            ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-ink)", color: "var(--color-on-dark)" }
            : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
          }
        >
          {showDeleted ? "Including deleted" : "Active only"}
        </button>
        <button
          onClick={verifyChain}
          disabled={chainBusy || !orgId}
          className="h-10 px-3 text-[12px] font-bold transition-colors inline-flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          style={
            chainStatus == null
              ? { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
              : chainStatus.valid
                ? { borderRadius: "4px", border: "1px solid #36B37E", background: "#36B37E", color: "var(--color-on-dark)" }
                : { borderRadius: "4px", border: "1px solid #B71D18", background: "#B71D18", color: "var(--color-on-dark)" }
          }
          title="Verify the Merkle audit chain for this organization"
        >
          {chainStatus == null ? (
            <ShieldCheck className="w-3.5 h-3.5" />
          ) : chainStatus.valid ? (
            <ShieldCheck className="w-3.5 h-3.5" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5" />
          )}
          {chainBusy
            ? "Verifying…"
            : chainStatus == null
              ? "Verify chain integrity"
              : chainStatus.valid
                ? `Chain OK (${chainStatus.total_rows})`
                : `BROKEN @ seq ${chainStatus.broken_at_sequence}`}
        </button>
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ImageIcon}
            title="No evidence yet"
            description="Upload screenshots, HTML, PDFs, or app-store listings. Detectors also write evidence here automatically (live probes, brand logos, fraud excerpts)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">
                    File
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Kind
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Size
                  </Th>
                  <Th align="left" className="w-[160px]">
                    SHA-256
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Status
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Captured
                  </Th>
                  <Th align="right" className="pr-4 w-[160px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <tr
                    key={b.id}
                    className="h-12 transition-colors cursor-pointer"
                    style={{
                      borderBottom: "1px solid var(--color-border)",
                      opacity: b.is_deleted ? 0.7 : 1,
                      background: b.is_deleted ? "var(--color-surface)" : "transparent",
                    }}
                    onMouseEnter={e => { if (!b.is_deleted) e.currentTarget.style.background = "var(--color-surface)"; }}
                    onMouseLeave={e => { if (!b.is_deleted) e.currentTarget.style.background = "transparent"; }}
                    onClick={() => setDrawerTarget(b)}
                  >
                    <td className="pl-4">
                      <div className="text-[13px] font-semibold line-clamp-1 max-w-[320px]" style={{ color: "var(--color-ink)" }}>
                        {b.original_filename || (
                          <span className="italic" style={{ color: "var(--color-muted)" }}>
                            unnamed
                          </span>
                        )}
                      </div>
                      <div className="text-[10.5px] font-mono tabular-nums truncate" style={{ color: "var(--color-muted)" }}>
                        {b.content_type}
                      </div>
                    </td>
                    <td className="px-3">
                      <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
                        {b.kind.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 font-mono text-[12px] tabular-nums" style={{ color: "var(--color-body)" }}>
                      {formatBytes(b.size_bytes)}
                    </td>
                    <td className="px-3 font-mono text-[10.5px] tabular-nums truncate" style={{ color: "var(--color-muted)" }}>
                      {b.sha256.slice(0, 12)}…
                    </td>
                    <td className="px-3">
                      {b.is_deleted ? (
                        <StatePill label="DELETED" tone="muted" />
                      ) : (
                        <StatePill label="ACTIVE" tone="success" />
                      )}
                    </td>
                    <td className="px-3 font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {timeAgo(b.captured_at)}
                    </td>
                    <td
                      className="pr-4"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => download(b)}
                          className="p-1.5 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          onMouseEnter={e => { e.currentTarget.style.background = "var(--color-surface-muted)"; e.currentTarget.style.color = "var(--color-ink)"; }}
                          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--color-muted)"; }}
                          title="Pre-signed download"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setLegalHoldTarget(b)}
                          className="p-1.5 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          onMouseEnter={e => { e.currentTarget.style.background = "var(--color-surface-muted)"; e.currentTarget.style.color = "var(--color-ink)"; }}
                          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--color-muted)"; }}
                          title="Legal hold"
                        >
                          <Lock className="w-3.5 h-3.5" />
                        </button>
                        {b.is_deleted ? (
                          <button
                            onClick={() => restore(b)}
                            className="inline-flex items-center gap-1 h-7 px-2 text-[11px] font-bold transition-colors"
                            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                            onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
                          >
                            <RotateCcw className="w-3 h-3" />
                            RESTORE
                          </button>
                        ) : (
                          <button
                            onClick={() => setDeleteTarget(b)}
                            className="p-1.5 transition-colors"
                            style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                            onMouseEnter={e => { e.currentTarget.style.background = "rgba(255,86,48,0.1)"; e.currentTarget.style.color = "#B71D18"; }}
                            onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--color-muted)"; }}
                            aria-label="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {showUpload && (
        <UploadModal
          orgId={orgId}
          onClose={() => setShowUpload(false)}
          onUploaded={() => {
            setShowUpload(false);
            load();
          }}
        />
      )}
      {legalHoldTarget && (
        <LegalHoldModal
          target={legalHoldTarget}
          onClose={() => setLegalHoldTarget(null)}
          onSubmit={(enabled, reason) =>
            setLegalHold(legalHoldTarget, enabled, reason)
          }
        />
      )}
      {deleteTarget && (
        <DeleteModal
          target={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onSubmit={(reason) => remove(deleteTarget, reason)}
        />
      )}
      {drawerTarget && (
        <DetailDrawer
          target={drawerTarget}
          onClose={() => setDrawerTarget(null)}
        />
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string;
  tone?: "neutral" | "muted";
}) {
  return (
    <div className="px-4 py-4" style={{ borderRight: "1px solid var(--color-border)" }}>
      <div className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
        {label}
      </div>
      <div
        className="mt-1.5 font-mono tabular-nums text-[24px] leading-none font-extrabold tracking-[-0.01em]"
        style={{ color: tone === "muted" ? "var(--color-muted)" : "var(--color-ink)" }}
      >
        {value}
      </div>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
}

function UploadModal({
  orgId,
  onClose,
  onUploaded,
}: {
  orgId: string;
  onClose: () => void;
  onUploaded: () => void;
}) {
  const { toast } = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [kind, setKind] = useState("screenshot");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!file || busy) return;
    setBusy(true);
    try {
      await api.evidence.upload(orgId, file, {
        kind,
        description: description.trim() || undefined,
        capture_source: "manual",
      });
      toast("success", "Evidence uploaded");
      onUploaded();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Upload evidence" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="File" required>
          <label className="block">
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="block w-full text-[13px]
                file:mr-3 file:py-2 file:px-3 file:border-0
                file:text-[12px] file:font-bold file:cursor-pointer cursor-pointer"
              style={{ color: "var(--color-body)" }}
            />
          </label>
          {file ? (
            <p className="text-[11.5px] font-mono mt-1.5" style={{ color: "var(--color-muted)" }}>
              {file.name} · {formatBytes(file.size)}
            </p>
          ) : null}
        </Field>
        <Field
          label="Kind"
          required
          hint="Drives the magic-byte allow/deny list at the upload boundary."
        >
          <Select
            ariaLabel="Kind"
            value={kind}
            options={KIND_OPTIONS.filter((o) => o.value !== "all")}
            onChange={setKind}
          />
        </Field>
        <Field label="Description" hint="Optional analyst note.">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={inputStyle}
            placeholder="Captured from probe of marsad-fake-login.com on 2026-04-29."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Uploading…" : "Upload"}
        disabled={!file || busy}
      />
    </ModalShell>
  );
}

function LegalHoldModal({
  target,
  onClose,
  onSubmit,
}: {
  target: EvidenceBlobResponse;
  onClose: () => void;
  onSubmit: (enabled: boolean, reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <ModalShell title="Legal hold" onClose={onClose}>
      <div className="p-6 space-y-5">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Legal hold prevents the retention engine from purging this blob,
          even after the configured retention window passes. Use during
          regulator inquiries, litigation, and breach investigations.
          Captured on the audit log.
        </p>
        <Field label="Object">
          <pre className="px-3 py-2 text-[11.5px] font-mono break-all" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-body)" }}>
            sha256={target.sha256}
            {"\n"}filename={target.original_filename || "(unnamed)"}
          </pre>
        </Field>
        <Field label="Reason" hint="Captured on the audit log.">
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)", outline: "none" }}
            placeholder="Litigation hold ABC-123; preserved at counsel's request."
          />
        </Field>
      </div>
      <div className="px-6 py-4 flex items-center justify-between gap-2" style={{ background: "var(--color-surface)", borderTop: "1px solid var(--color-border)" }}>
        <button
          onClick={onClose}
          className="h-9 px-3 text-[13px] font-bold transition-colors"
          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
        >
          Cancel
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onSubmit(false, reason)}
            className="h-9 px-3 text-[13px] font-bold transition-colors"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
          >
            Release hold
          </button>
          <button
            onClick={() => onSubmit(true, reason)}
            disabled={!reason.trim()}
            className="h-9 px-3 text-[13px] font-bold disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ borderRadius: "4px", border: "1px solid rgba(255,171,0,0.6)", background: "#FFAB00", color: "#201515" }}
          >
            Apply hold
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

function DeleteModal({
  target,
  onClose,
  onSubmit,
}: {
  target: EvidenceBlobResponse;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <ModalShell title="Soft-delete evidence" onClose={onClose}>
      <div className="p-6 space-y-5">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Soft-delete marks the blob as deleted but keeps the bytes in
          MinIO until the retention engine prunes it. Restorable. Subject
          to legal-hold.
        </p>
        <pre className="px-3 py-2 text-[11.5px] font-mono break-all" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-body)" }}>
          sha256={target.sha256}
        </pre>
        <Field label="Reason" required>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)", outline: "none" }}
            placeholder="e.g. Mistakenly uploaded, duplicate of sha-12abcd…"
            autoFocus
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(reason)}
        submitLabel="Delete"
        submitTone="error"
        disabled={!reason.trim()}
      />
    </ModalShell>
  );
}

function DetailDrawer({
  target,
  onClose,
}: {
  target: EvidenceBlobResponse;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [chain, setChain] = useState<EvidenceAuditChainEntry[] | null>(null);
  const [similar, setSimilar] = useState<EvidenceSimilarResponse | null>(null);
  const [coc, setCoc] = useState<EvidenceCoCNarrative | null>(null);
  const [cocBusy, setCocBusy] = useState(false);
  const [chainBusy, setChainBusy] = useState(true);
  const [similarBusy, setSimilarBusy] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        setChainBusy(true);
        const c = await api.evidence.auditChain(target.id);
        if (alive) setChain(c);
      } catch (e) {
        if (alive) toast("error", e instanceof Error ? e.message : "Audit chain failed");
      } finally {
        if (alive) setChainBusy(false);
      }
    })();
    (async () => {
      try {
        setSimilarBusy(true);
        const s = await api.evidence.similar(target.id);
        if (alive) setSimilar(s);
      } catch (e) {
        if (alive) toast("error", e instanceof Error ? e.message : "Similar lookup failed");
      } finally {
        if (alive) setSimilarBusy(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [target.id, toast]);

  const generateCoc = async () => {
    setCocBusy(true);
    try {
      const r = await api.evidence.narrateCoc(target.id, true);
      setCoc(r);
      toast("success", "Chain-of-custody narrative generated");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "COC narrate failed");
    } finally {
      setCocBusy(false);
    }
  };

  const summary =
    target.agent_summary || null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: "rgba(0,0,0,0.35)" }}
      onClick={onClose}
    >
      <div
        className="h-full w-full max-w-[640px] overflow-y-auto"
        style={{ background: "var(--color-canvas)", borderLeft: "1px solid var(--color-border)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="sticky top-0 z-10 flex items-center justify-between px-5 py-3"
          style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}
        >
          <div>
            <div className="text-[11px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
              Evidence detail
            </div>
            <div className="text-[14px] font-bold" style={{ color: "var(--color-ink)" }}>
              {target.original_filename || "(unnamed)"}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5"
            style={{ borderRadius: "4px", color: "var(--color-muted)" }}
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-6">
          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <div className="text-[11px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                Hashes
              </div>
            </div>
            <div className="px-4 py-3 space-y-1.5 font-mono text-[11.5px]" style={{ color: "var(--color-body)" }}>
              <div><span style={{ color: "var(--color-muted)" }}>sha256:</span> {target.sha256}</div>
              <div><span style={{ color: "var(--color-muted)" }}>md5:   </span> {target.md5 || "—"}</div>
              <div><span style={{ color: "var(--color-muted)" }}>sha1:  </span> {target.sha1 || "—"}</div>
              <div><span style={{ color: "var(--color-muted)" }}>size:  </span> {target.size_bytes} bytes</div>
              <div><span style={{ color: "var(--color-muted)" }}>kind:  </span> {target.kind}</div>
              <div><span style={{ color: "var(--color-muted)" }}>mime:  </span> {target.content_type}</div>
            </div>
          </Section>

          <Section>
            <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <div className="text-[11px] font-bold uppercase tracking-[0.12em] inline-flex items-center gap-2" style={{ color: "var(--color-muted)" }}>
                <Sparkles className="w-3.5 h-3.5" /> Agent summary
              </div>
              <span className="text-[10.5px] font-mono" style={{ color: "var(--color-muted)" }}>
                {summary && typeof summary["model_id"] === "string" ? summary["model_id"] : ""}
              </span>
            </div>
            <div className="px-4 py-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
              {!summary ? (
                <span style={{ color: "var(--color-muted)" }} className="italic">
                  Summariser has not run yet — try refreshing in a few seconds.
                </span>
              ) : summary["parse_failed"] ? (
                <pre className="whitespace-pre-wrap text-[11.5px] font-mono">{String(summary["raw"] || "")}</pre>
              ) : (
                <div className="space-y-2">
                  {Array.isArray(summary["summary_bullets"]) && (
                    <ul className="list-disc pl-5 space-y-0.5">
                      {(summary["summary_bullets"] as string[]).map((b, i) => (
                        <li key={i}>{b}</li>
                      ))}
                    </ul>
                  )}
                  <div className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
                    classification: {String(summary["classification"] || "—")} ·
                    confidence: {String(summary["confidence"] ?? "—")}
                  </div>
                  {Array.isArray(summary["pii_categories"]) && (summary["pii_categories"] as string[]).length > 0 && (
                    <div className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
                      PII: {(summary["pii_categories"] as string[]).join(", ")}
                    </div>
                  )}
                  {Array.isArray(summary["linked_ioc_ids"]) && (
                    <div className="text-[11px] font-mono" style={{ color: "var(--color-muted)" }}>
                      Linked IOCs: {(summary["linked_ioc_ids"] as string[]).length}
                    </div>
                  )}
                </div>
              )}
            </div>
          </Section>

          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <div className="text-[11px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                Audit chain ({chain?.length ?? 0})
              </div>
            </div>
            <div className="px-4 py-3 text-[11.5px] font-mono space-y-2" style={{ color: "var(--color-body)" }}>
              {chainBusy ? "Loading…" : !chain || chain.length === 0 ? (
                <span style={{ color: "var(--color-muted)" }} className="italic">No audit-chain rows yet.</span>
              ) : (
                chain.map((row) => (
                  <div key={row.sequence} className="border-l pl-3" style={{ borderColor: "var(--color-border)" }}>
                    <div>
                      <span style={{ color: "var(--color-muted)" }}>seq {row.sequence}</span> ·{" "}
                      <span className="font-bold">{row.action}</span>
                    </div>
                    <div style={{ color: "var(--color-muted)" }}>
                      {new Date(row.created_at).toISOString()}
                    </div>
                    <div style={{ color: "var(--color-muted)" }}>
                      chain={row.chain_hash.slice(0, 16)}… prev={row.prev_chain_hash ? row.prev_chain_hash.slice(0, 12) + "…" : "(genesis)"}
                    </div>
                  </div>
                ))
              )}
            </div>
          </Section>

          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <div className="text-[11px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                Similar artefacts
              </div>
            </div>
            <div className="px-4 py-3 text-[12px]" style={{ color: "var(--color-body)" }}>
              {similarBusy ? "Loading…" : !similar || similar.neighbours.length === 0 ? (
                <span style={{ color: "var(--color-muted)" }} className="italic">
                  No similar artefacts found ({similar?.method || "—"}).
                </span>
              ) : (
                <div className="space-y-2">
                  <div className="text-[10.5px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                    method: {similar.method}
                  </div>
                  {similar.neighbours.map((h) => (
                    <div
                      key={h.id}
                      className="px-2 py-1.5 font-mono text-[11px]"
                      style={{ borderRadius: "4px", background: "var(--color-surface)" }}
                    >
                      <div>{h.original_filename || "(unnamed)"} · {h.size_bytes}B</div>
                      <div style={{ color: "var(--color-muted)" }}>
                        sha256={h.sha256.slice(0, 16)}… distance={h.distance ?? "n/a"}
                      </div>
                    </div>
                  ))}
                  {similar.summary && (
                    <p className="text-[12px] mt-2" style={{ color: "var(--color-body)" }}>
                      {similar.summary}
                    </p>
                  )}
                </div>
              )}
            </div>
          </Section>

          <Section>
            <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <div className="text-[11px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
                Chain-of-custody narrative
              </div>
              <button
                onClick={generateCoc}
                disabled={cocBusy}
                className="h-7 px-2 text-[11px] font-bold disabled:opacity-50"
                style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
              >
                {cocBusy ? "Generating…" : coc ? "Regenerate" : "Generate"}
              </button>
            </div>
            <div className="px-4 py-3 text-[12px]" style={{ color: "var(--color-body)" }}>
              {!coc ? (
                <span style={{ color: "var(--color-muted)" }} className="italic">
                  Click Generate to render a court-ready Markdown narrative.
                </span>
              ) : (
                <pre className="whitespace-pre-wrap font-mono text-[11.5px]">{coc.narrative}</pre>
              )}
            </div>
          </Section>
        </div>
      </div>
    </div>
  );
}

