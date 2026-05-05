"use client";

import { useCallback, useEffect, useState } from "react";
import { Image as ImageIcon, Trash2, Upload } from "lucide-react";
import {
  ApiError,
  api,
  type BrandLogoResponse,
  type LogoMatchResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  Section,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: "40px",
  padding: "0 12px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  fontSize: "13px",
  outline: "none",
};

const VERDICT_TONE: Record<string, StateTone> = {
  exact: "error-strong",
  match: "warning",
  near: "info",
  miss: "muted",
};

export function LogosTab() {
  const { orgId, bumpRefresh } = useBrandContext();
  const { toast } = useToast();
  const [logos, setLogos] = useState<BrandLogoResponse[]>([]);
  const [matches, setMatches] = useState<LogoMatchResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showUpload, setShowUpload] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [l, m] = await Promise.all([
        api.brand.listLogos(orgId),
        api.brand.listLogoMatches(orgId),
      ]);
      setLogos(l);
      setMatches(m);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load logos",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const removeLogo = async (id: string, label: string) => {
    if (!confirm(`Remove the "${label}" logo from this org's registry?`)) return;
    try {
      await api.brand.deleteLogo(id);
      toast("success", `Removed ${label}`);
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to remove logo",
      );
    }
  };

  return (
    <div className="space-y-5">
      {/* Logos roster */}
      <Section>
        <div
          className="px-4 py-3 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
              Brand logos
            </h3>
            <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
              Reference images the perceptual-hash matcher uses to detect
              cloned login pages and impersonating accounts.
            </p>
          </div>
          <UploadButton onClick={() => setShowUpload(true)}>
            <Upload className="w-3.5 h-3.5" />
            Upload logo
          </UploadButton>
        </div>
        {loading ? (
          <SkeletonRows rows={3} columns={4} />
        ) : logos.length === 0 ? (
          <Empty
            icon={ImageIcon}
            title="No logos registered"
            description="Upload one or more brand assets (PNG, JPEG, SVG) so the matcher can score visual clones across suspect domains and screenshot probes."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3 p-3">
            {logos.map((l) => (
              <LogoCard key={l.id} logo={l} onRemove={() => removeLogo(l.id, l.label)} />
            ))}
          </div>
        )}
      </Section>

      {/* Matches */}
      <Section>
        <div
          className="px-4 py-3"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Recent logo matches
          </h3>
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
            Candidate images compared against the registered logos via
            perceptual-hash distance and color similarity.
          </p>
        </div>
        {loading ? (
          <SkeletonRows rows={4} columns={5} />
        ) : matches.length === 0 ? (
          <Empty
            icon={ImageIcon}
            title="No matches yet"
            description="Matches surface as live probes pull screenshots and the matcher walks them against the registered logos."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">
                    Verdict
                  </Th>
                  <Th align="left">Brand logo</Th>
                  <Th align="left">Candidate sha256</Th>
                  <Th align="left" className="w-[100px]">
                    Sim
                  </Th>
                  <Th align="left" className="w-[140px]">
                    pHash dist
                  </Th>
                  <Th align="right" className="pr-4 w-[120px]">
                    When
                  </Th>
                </tr>
              </thead>
              <tbody>
                {matches.map((m) => {
                  const logo = logos.find((l) => l.id === m.brand_logo_id);
                  return (
                    <MatchRow key={m.id} m={m} logo={logo} />
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {showUpload && (
        <UploadLogoModal
          orgId={orgId}
          onClose={() => setShowUpload(false)}
          onUploaded={() => {
            setShowUpload(false);
            bumpRefresh();
          }}
        />
      )}
    </div>
  );
}

function MatchRow({ m, logo }: { m: LogoMatchResponse; logo?: BrandLogoResponse }) {
  const [hovered, setHovered] = useState(false);
  return (
    <tr
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <td className="pl-4">
        <StatePill
          label={m.verdict}
          tone={VERDICT_TONE[m.verdict] || "neutral"}
        />
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-ink)" }}>
        {logo?.label || (
          <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>deleted</span>
        )}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
        {m.candidate_image_sha256.slice(0, 16)}…
      </td>
      <td className="px-3">
        <SimilarityBar value={m.similarity} />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
        p:{m.phash_distance} d:{m.dhash_distance} a:
        {m.ahash_distance}
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(m.matched_at)}
      </td>
    </tr>
  );
}

function UploadButton({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "36px",
        padding: "0 12px",
        borderRadius: "4px",
        fontSize: "13px",
        fontWeight: 700,
        background: hov ? "#e64600" : "var(--color-accent)",
        color: "var(--color-on-dark)",
        border: "none",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function LogoCard({
  logo,
  onRemove,
}: {
  logo: BrandLogoResponse;
  onRemove: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [btnHov, setBtnHov] = useState(false);
  const hue = parseInt(logo.phash_hex.slice(0, 4), 16) % 360;
  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderRadius: "5px",
        border: "1px solid var(--color-border)",
        background: "var(--color-canvas)",
        overflow: "hidden",
      }}
    >
      <div
        className="aspect-[16/9] flex items-center justify-center"
        style={{
          background: `linear-gradient(135deg, hsl(${hue} 60% 88%), hsl(${(hue + 60) % 360} 60% 78%))`,
        }}
      >
        <span style={{
          fontFamily: "monospace",
          fontSize: "11px",
          color: "var(--color-body)",
          background: "rgba(255,254,251,0.7)",
          padding: "4px 8px",
          borderRadius: "3px",
        }}>
          {logo.image_evidence_sha256.slice(0, 12)}…
        </span>
      </div>
      <div className="px-3 py-2.5">
        <div className="flex items-center justify-between gap-2">
          <h4 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }} className="truncate">
            {logo.label}
          </h4>
          <button
            onClick={onRemove}
            onMouseEnter={() => setBtnHov(true)}
            onMouseLeave={() => setBtnHov(false)}
            style={{
              padding: "4px",
              borderRadius: "4px",
              border: "none",
              background: btnHov ? "rgba(255,86,48,0.1)" : "none",
              color: btnHov ? "#FF5630" : "var(--color-muted)",
              opacity: hovered ? 1 : 0,
              cursor: "pointer",
              transition: "opacity 0.15s, color 0.15s, background 0.15s",
            }}
            aria-label="Remove"
          >
            <Trash2 style={{ width: "14px", height: "14px" }} />
          </button>
        </div>
        {logo.description ? (
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }} className="line-clamp-1">
            {logo.description}
          </p>
        ) : null}
        <div className="flex items-center gap-3 mt-2" style={{ fontSize: "10.5px", color: "var(--color-muted)", fontFamily: "monospace" }}>
          {logo.width && logo.height ? (
            <span>
              {logo.width}×{logo.height}
            </span>
          ) : null}
          <span>p:{logo.phash_hex.slice(0, 8)}</span>
        </div>
      </div>
    </div>
  );
}

function SimilarityBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.9 ? "#FF5630" : pct >= 0.75 ? "#FFAB00" : "#00B8D9";
  return (
    <div className="flex items-center gap-1.5">
      <div style={{ width: "40px", height: "4px", borderRadius: "9999px", background: "var(--color-surface-muted)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct * 100}%`, background: fillColor }} />
      </div>
      <span style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-body)" }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function UploadLogoModal({
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
  const [label, setLabel] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!file || !label.trim() || busy) return;
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("organization_id", orgId);
      fd.append("label", label.trim());
      if (description.trim()) fd.append("description", description.trim());
      fd.append("file", file);
      // Upload via the same multipart path the API expects. Hit the
      // backend directly because this endpoint doesn't have a typed
      // helper yet (its FormData shape doesn't fit requestMultipart's
      // generic signature cleanly enough to be worth a wrapper).
      // Adversarial audit D-1 / D-3 — auth via HttpOnly cookies; we no
      // longer reach for localStorage tokens or fall back to the
      // hard-coded loopback URL.
      const base = process.env.NEXT_PUBLIC_API_URL;
      if (!base) {
        throw new ApiError(
          "NEXT_PUBLIC_API_URL is not configured",
          0,
        );
      }
      const res = await fetch(`${base}/brand/logos`, {
        method: "POST",
        credentials: "include",
        body: fd,
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new ApiError(
          (() => {
            try {
              return JSON.parse(txt).detail || txt;
            } catch {
              return txt || `${res.status} ${res.statusText}`;
            }
          })(),
          res.status,
        );
      }
      toast("success", `Logo "${label.trim()}" registered`);
      onUploaded();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Upload brand logo" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Label" required hint="Short name shown across the UI.">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            style={inputStyle}
            placeholder="e.g. marsad-primary-mark"
            autoFocus
          />
        </Field>
        <Field label="Description" hint="Optional context for analysts.">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            style={inputStyle}
            placeholder="e.g. Square version used on customer login"
          />
        </Field>
        <Field label="Image file" required hint="PNG, JPEG, or SVG.">
          <label className="block">
            <input
              type="file"
              accept="image/*"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              style={{ display: "block", width: "100%", fontSize: "13px", color: "var(--color-body)", cursor: "pointer" }}
            />
          </label>
          {file ? (
            <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "6px", fontFamily: "monospace" }}>
              {file.name} · {(file.size / 1024).toFixed(1)} KB
            </p>
          ) : null}
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Uploading…" : "Upload"}
        disabled={!file || !label.trim() || busy}
      />
    </ModalShell>
  );
}
