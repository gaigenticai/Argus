"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Layers,
  RefreshCw,
  Search,
  X,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Database,
  Shield,
  ShieldAlert,
  Crosshair,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import {
  api,
  type MitreTacticResponse,
  type MitreTechniqueResponse,
  type MitreMitigationResponse,
  type MitreSyncRow,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  Th,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";
import { Select } from "@/components/shared/select";

// ---------------------------------------------------------------------------
//  Tab types
// ---------------------------------------------------------------------------

type Tab =
  | "matrix"
  | "techniques"
  | "mitigations"
  | "groups"
  | "software"
  | "datasources"
  | "campaigns"
  | "layers"
  | "sync";

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "matrix", label: "Matrix" },
  { id: "techniques", label: "Techniques" },
  { id: "groups", label: "Groups" },
  { id: "software", label: "Software" },
  { id: "datasources", label: "Data Sources" },
  { id: "campaigns", label: "Campaigns" },
  { id: "mitigations", label: "Mitigations" },
  { id: "layers", label: "Layers" },
  { id: "sync", label: "Sync History" },
];

// ---------------------------------------------------------------------------
//  Sync status badge
// ---------------------------------------------------------------------------

function SyncStatusBadge({ row }: { row: MitreSyncRow }) {
  if (!row.finished_at && !row.succeeded && !row.error_message) {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 text-[10px] font-bold tracking-wide" style={{ borderRadius: "4px", border: "1px solid rgba(0,187,217,0.3)", background: "rgba(0,187,217,0.1)", color: "#007B8A" }}>
        <Loader2 className="w-3 h-3 animate-spin" />
        RUNNING
      </span>
    );
  }
  if (row.succeeded) {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 text-[10px] font-bold tracking-wide" style={{ borderRadius: "4px", border: "1px solid rgba(0,167,111,0.3)", background: "rgba(0,167,111,0.1)", color: "#007B55" }}>
        <CheckCircle2 className="w-3 h-3" />
        OK
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 h-[22px] px-2 text-[10px] font-bold tracking-wide" style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.3)", background: "rgba(255,86,48,0.1)", color: "#B71D18" }}>
      <AlertTriangle className="w-3 h-3" />
      ERROR
    </span>
  );
}

// ---------------------------------------------------------------------------
//  Technique detail drawer
// ---------------------------------------------------------------------------

function TechniqueDrawer({
  technique,
  mitigations,
  onClose,
}: {
  technique: MitreTechniqueResponse;
  mitigations: MitreMitigationResponse[];
  onClose: () => void;
}) {
  const relatedMitigations = mitigations.filter((m) =>
    (m.technique_external_ids ?? []).includes(technique.external_id),
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-end p-4"
      style={{ background: "rgba(32,21,21,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[560px] h-full overflow-y-auto"
        style={{ background: "var(--color-canvas)", borderRadius: "8px", border: "1px solid var(--color-border)", boxShadow: "var(--shadow-z24)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 px-6 pt-5 pb-4 flex items-start justify-between gap-4" style={{ background: "var(--color-canvas)", borderBottom: "1px solid var(--color-border)" }}>
          <div className="flex-1 min-w-0">
            <span className="text-[11px] font-bold tracking-[0.1em] font-mono" style={{ color: "var(--color-muted)" }}>
              {technique.external_id}
            </span>
            <h2 className="text-[17px] font-bold mt-0.5 leading-snug" style={{ color: "var(--color-ink)" }}>
              {technique.name}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 shrink-0 transition-colors"
            style={{ borderRadius: "4px", color: "var(--color-muted)" }}
            aria-label="Close"
            onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
            onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Meta chips */}
          <div className="flex flex-wrap gap-2">
            {technique.is_subtechnique && (
              <span className="inline-flex items-center h-[22px] px-2 text-[10px] font-bold" style={{ borderRadius: "4px", border: "1px solid rgba(147,144,132,0.4)", background: "rgba(147,144,132,0.1)", color: "var(--color-body)" }}>
                SUB-TECHNIQUE
              </span>
            )}
            {technique.tactics.map((t) => (
              <span
                key={t}
                className="inline-flex items-center h-[22px] px-2 text-[10px] font-bold uppercase tracking-wide"
                style={{ borderRadius: "4px", border: "1px solid rgba(255,79,0,0.3)", background: "rgba(255,79,0,0.08)", color: "var(--color-accent)" }}
              >
                {t.replace(/-/g, " ")}
              </span>
            ))}
          </div>

          {/* Description */}
          {technique.description ? (
            <div>
              <div className="text-[10.5px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-muted)" }}>
                Description
              </div>
              <p className="text-[13px] leading-relaxed whitespace-pre-wrap" style={{ color: "var(--color-body)" }}>
                {technique.description}
              </p>
            </div>
          ) : null}

          {/* Platforms */}
          {technique.platforms.length > 0 ? (
            <div>
              <div className="text-[10.5px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-muted)" }}>
                Platforms
              </div>
              <div className="flex flex-wrap gap-1.5">
                {technique.platforms.map((p) => (
                  <span
                    key={p}
                    className="inline-flex items-center h-[22px] px-2 text-[10px] font-bold"
                    style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-body)" }}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {/* Data sources */}
          {technique.data_sources.length > 0 ? (
            <div>
              <div className="text-[10.5px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-muted)" }}>
                Data Sources
              </div>
              <div className="flex flex-wrap gap-1.5">
                {technique.data_sources.map((ds) => (
                  <span
                    key={ds}
                    className="inline-flex items-center h-[22px] px-2 text-[10px] font-semibold"
                    style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-body)" }}
                  >
                    {ds}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {/* Mitigations */}
          <div>
            <div className="text-[10.5px] font-bold uppercase tracking-[0.1em] mb-2" style={{ color: "var(--color-muted)" }}>
              Mitigations ({relatedMitigations.length})
            </div>
            {relatedMitigations.length === 0 ? (
              <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>No mitigations mapped.</p>
            ) : (
              <div className="space-y-3">
                {relatedMitigations.map((m) => (
                  <div
                    key={m.external_id}
                    className="p-3"
                    style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)" }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-[11px]" style={{ color: "var(--color-muted)" }}>
                        {m.external_id}
                      </span>
                      <span className="text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>
                        {m.name}
                      </span>
                    </div>
                    {m.description ? (
                      <p className="text-[12px] leading-relaxed line-clamp-3" style={{ color: "var(--color-muted)" }}>
                        {m.description}
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Matrix tab
// ---------------------------------------------------------------------------

function MatrixTab({
  tactics,
  loading,
  onTacticClick,
}: {
  tactics: MitreTacticResponse[];
  loading: boolean;
  onTacticClick: (tactic: MitreTacticResponse) => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 style={{ width: "24px", height: "24px", color: "var(--color-muted)" }} className="animate-spin" />
      </div>
    );
  }

  if (tactics.length === 0) {
    return (
      <Empty
        icon={Shield}
        title="No tactics loaded"
        description="Trigger a MITRE sync from the Sync History tab to populate tactics and techniques."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center h-[22px] px-2 text-[10px] font-bold tracking-wide" style={{ borderRadius: "4px", border: "1px solid rgba(255,79,0,0.3)", background: "rgba(255,79,0,0.08)", color: "var(--color-accent)" }}>
          ATT&amp;CK
        </span>
        <span className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {tactics.length} tactics — click any card to explore its techniques
        </span>
      </div>

      {/* Tactic cards grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {tactics.map((tactic) => (
          <button
            key={tactic.external_id}
            onClick={() => onTacticClick(tactic)}
            className="group text-left p-4 transition-all duration-150 focus:outline-none"
            style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = "rgba(255,79,0,0.4)";
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = "var(--color-border)";
            }}
          >
            <div className="flex items-start justify-between gap-2 mb-2">
              <span className="font-mono text-[10.5px] leading-none" style={{ color: "var(--color-muted)" }}>
                {tactic.external_id}
              </span>
              <Shield className="w-3.5 h-3.5 shrink-0 transition-colors" style={{ color: "var(--color-muted)" }} />
            </div>
            <div className="text-[13px] font-bold leading-snug" style={{ color: "var(--color-ink)" }}>
              {tactic.name}
            </div>
            {tactic.description ? (
              <p className="text-[11px] mt-1.5 line-clamp-2 leading-relaxed" style={{ color: "var(--color-muted)" }}>
                {tactic.description}
              </p>
            ) : null}
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Techniques tab
// ---------------------------------------------------------------------------

function TechniquesTab({
  tactics,
  mitigations,
  externalTacticFilter = "",
}: {
  tactics: MitreTacticResponse[];
  mitigations: MitreMitigationResponse[];
  externalTacticFilter?: string;
}) {
  const { toast } = useToast();
  const [techniques, setTechniques] = useState<MitreTechniqueResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState(externalTacticFilter);
  const [showSubs, setShowSubs] = useState(false);
  const [selected, setSelected] = useState<MitreTechniqueResponse | null>(null);

  // Sync parent-driven filter (set when clicking a Matrix card)
  useEffect(() => {
    setTacticFilter(externalTacticFilter);
  }, [externalTacticFilter]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.mitre.listTechniques(
        tacticFilter ? { tactic: tacticFilter } : undefined,
      );
      setTechniques(data);
    } catch {
      toast("error", "Failed to load techniques");
    } finally {
      setLoading(false);
    }
  }, [tacticFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  // Client-side filtering: search + sub-techniques toggle
  const filtered = useMemo(() => {
    let list = techniques;
    if (!showSubs) {
      list = list.filter((t) => !t.is_subtechnique);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.external_id.toLowerCase().includes(q),
      );
    }
    return list;
  }, [techniques, search, showSubs]);

  // Per-technique mitigation count lookup
  const mitigationCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const m of mitigations) {
      for (const tid of m.technique_external_ids ?? []) {
        map.set(tid, (map.get(tid) || 0) + 1);
      }
    }
    return map;
  }, [mitigations]);

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "var(--color-muted)" }} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search techniques…"
            className="w-full h-10 pl-9 pr-3 text-[13px] outline-none"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
          />
        </div>

        <Select
          value={tacticFilter}
          onChange={setTacticFilter}
          ariaLabel="Filter by tactic"
          options={[
            { value: "", label: "All tactics" },
            ...tactics.map((t) => ({
              value: t.shortname || t.external_id,
              label: t.name,
            })),
          ]}
        />

        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showSubs}
            onChange={(e) => setShowSubs(e.target.checked)}
            className="w-4 h-4"
            style={{ accentColor: "var(--color-accent)" }}
          />
          <span className="text-[13px] font-semibold" style={{ color: "var(--color-body)" }}>
            Show sub-techniques
          </span>
        </label>

        <span className="text-[12px] ml-auto" style={{ color: "var(--color-muted)" }}>
          {filtered.length} result{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Techniques table */}
      <Section>
        {loading ? (
          <SkeletonRows rows={10} columns={6} />
        ) : filtered.length === 0 ? (
          <Empty
            icon={Crosshair}
            title="No techniques found"
            description="Try adjusting your filters or search query."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th>External ID</Th>
                  <Th>Name</Th>
                  <Th>Tactics</Th>
                  <Th>Platforms</Th>
                  <Th align="right">Sub-techniques</Th>
                  <Th align="right">Mitigations</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((tech) => {
                  const subCount = techniques.filter(
                    (t) =>
                      t.is_subtechnique &&
                      t.parent_external_id === tech.external_id,
                  ).length;
                  const mitCount =
                    mitigationCountMap.get(tech.external_id) || 0;

                  return (
                    <tr
                      key={tech.external_id}
                      className="h-12 transition-colors cursor-pointer"
                      style={{ borderBottom: "1px solid var(--color-border)", background: tech.is_subtechnique ? "var(--color-surface)" : "transparent" }}
                      onClick={() => setSelected(tech)}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = tech.is_subtechnique ? "var(--color-surface)" : "transparent")}
                    >
                      <td className="px-3">
                        <span
                          className="font-mono text-[11.5px] tabular-nums"
                          style={{ color: tech.is_subtechnique ? "var(--color-muted)" : "var(--color-body)", paddingLeft: tech.is_subtechnique ? "1rem" : undefined }}
                        >
                          {tech.is_subtechnique && (
                            <span style={{ color: "var(--color-border)", marginRight: "0.25rem" }}>&#x21b3;</span>
                          )}
                          {tech.external_id}
                        </span>
                      </td>
                      <td className="px-3">
                        <span
                          className="text-[13px]"
                          style={{ fontWeight: tech.is_subtechnique ? 400 : 600, color: tech.is_subtechnique ? "var(--color-body)" : "var(--color-ink)" }}
                        >
                          {tech.name}
                        </span>
                      </td>
                      <td className="px-3">
                        <div className="flex flex-wrap gap-1">
                          {tech.tactics.slice(0, 3).map((t) => (
                            <span
                              key={t}
                              className="inline-flex items-center h-[18px] px-1.5 text-[9.5px] font-bold uppercase tracking-wide"
                              style={{ borderRadius: "4px", border: "1px solid rgba(255,79,0,0.3)", background: "rgba(255,79,0,0.06)", color: "var(--color-accent)" }}
                            >
                              {t.replace(/-/g, " ")}
                            </span>
                          ))}
                          {tech.tactics.length > 3 && (
                            <span className="text-[10px]" style={{ color: "var(--color-muted)" }}>
                              +{tech.tactics.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3">
                        <div className="flex flex-wrap gap-1">
                          {tech.platforms.slice(0, 2).map((p) => (
                            <span
                              key={p}
                              className="inline-flex items-center h-[18px] px-1.5 text-[9.5px] font-semibold"
                              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", color: "var(--color-body)" }}
                            >
                              {p}
                            </span>
                          ))}
                          {tech.platforms.length > 2 && (
                            <span className="text-[10px]" style={{ color: "var(--color-muted)" }}>
                              +{tech.platforms.length - 2}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 text-right">
                        <span className="font-mono tabular-nums text-[12px]" style={{ color: "var(--color-body)" }}>
                          {tech.is_subtechnique ? "—" : subCount || "—"}
                        </span>
                      </td>
                      <td className="px-3 text-right">
                        <span
                          className="font-mono tabular-nums text-[12px]"
                          style={{ color: mitCount > 0 ? "#007B55" : "var(--color-muted)", fontWeight: mitCount > 0 ? 600 : 400 }}
                        >
                          {mitCount || "—"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* Detail drawer */}
      {selected && (
        <TechniqueDrawer
          technique={selected}
          mitigations={mitigations}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Mitigations tab
// ---------------------------------------------------------------------------

function MitigationsTab() {
  const { toast } = useToast();
  const [mitigations, setMitigations] = useState<MitreMitigationResponse[]>(
    [],
  );
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.mitre.listMitigations();
        setMitigations(data);
      } catch {
        toast("error", "Failed to load mitigations");
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    if (!search.trim()) return mitigations;
    const q = search.toLowerCase();
    return mitigations.filter(
      (m) =>
        m.name.toLowerCase().includes(q) ||
        m.external_id.toLowerCase().includes(q) ||
        (m.description || "").toLowerCase().includes(q),
    );
  }, [mitigations, search]);

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "var(--color-muted)" }} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search mitigations…"
            className="w-full h-10 pl-9 pr-3 text-[13px] outline-none"
            style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
          />
        </div>
        <span className="text-[12px] ml-auto" style={{ color: "var(--color-muted)" }}>
          {filtered.length} mitigation
          {filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Table */}
      <Section>
        {loading ? (
          <SkeletonRows rows={8} columns={3} />
        ) : filtered.length === 0 ? (
          <Empty
            icon={ShieldAlert}
            title="No mitigations found"
            description="Adjust your search or trigger a MITRE sync to load mitigations."
          />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th className="w-8">{" "}</Th>
                <Th>External ID</Th>
                <Th>Name</Th>
                <Th align="right">Covers</Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((m) => {
                const isExpanded = expandedId === m.external_id;
                return (
                  <>
                    <tr
                      key={m.external_id}
                      className="h-12 transition-colors cursor-pointer"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onClick={() =>
                        setExpandedId(isExpanded ? null : m.external_id)
                      }
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="pl-3 pr-1 w-8">
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                        ) : (
                          <ChevronDown className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
                        )}
                      </td>
                      <td className="px-3">
                        <span className="font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                          {m.external_id}
                        </span>
                      </td>
                      <td className="px-3">
                        <span className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                          {m.name}
                        </span>
                      </td>
                      <td className="px-3 text-right">
                        <span className="font-mono tabular-nums text-[12px]" style={{ color: "var(--color-body)" }}>
                          {(m.technique_external_ids ?? []).length} technique
                          {(m.technique_external_ids ?? []).length !== 1 ? "s" : ""}
                        </span>
                      </td>
                    </tr>
                    {isExpanded && m.description && (
                      <tr
                        key={`${m.external_id}-desc`}
                        style={{ borderBottom: "1px solid var(--color-border)" }}
                      >
                        <td colSpan={4} className="px-6 py-3" style={{ background: "var(--color-surface)" }}>
                          <p className="text-[12.5px] leading-relaxed max-w-[720px]" style={{ color: "var(--color-body)" }}>
                            {m.description}
                          </p>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Sync History tab
// ---------------------------------------------------------------------------

function SyncTab() {
  const { toast } = useToast();
  const [syncs, setSyncs] = useState<MitreSyncRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.mitre.listSyncs();
      setSyncs(data);
    } catch {
      toast("error", "Failed to load sync history");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const triggerSync = async () => {
    setTriggering(true);
    try {
      const report = await api.mitre.sync();
      toast(
        "success",
        `Sync complete — ${report.techniques} techniques, ${report.tactics} tactics, ${report.mitigations} mitigations`,
      );
      await load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Sync failed");
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Each sync pulls the latest ATT&amp;CK STIX bundle and upserts tactics,
          techniques and mitigations into the database.
        </p>
        <div className="flex items-center gap-2">
          <RefreshButton onClick={load} refreshing={loading} />
          <button
            onClick={triggerSync}
            disabled={triggering}
            className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold transition-colors disabled:opacity-50"
            style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
          >
            {triggering ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            Trigger Sync
          </button>
        </div>
      </div>

      {/* Sync history table */}
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={8} />
        ) : syncs.length === 0 ? (
          <Empty
            icon={Database}
            title="No syncs yet"
            description="Trigger a sync to pull the latest MITRE ATT&CK data."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th>Status</Th>
                  <Th>Started</Th>
                  <Th>Completed</Th>
                  <Th align="right">Ingested</Th>
                  <Th align="right">Updated</Th>
                  <Th align="right">Duration</Th>
                </tr>
              </thead>
              <tbody>
                {syncs.map((row) => {
                  const durationMs = row.duration_ms ?? 0;
                  const durationLabel =
                    durationMs < 1000
                      ? `${durationMs}ms`
                      : `${(durationMs / 1000).toFixed(1)}s`;

                  return (
                    <tr
                      key={row.id}
                      className="h-12 transition-colors"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="px-3">
                        <SyncStatusBadge row={row} />
                      </td>
                      <td className="px-3 text-[12px] font-mono tabular-nums whitespace-nowrap" style={{ color: "var(--color-body)" }}>
                        {row.started_at ? timeAgo(row.started_at) : "—"}
                      </td>
                      <td className="px-3 text-[12px] whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                        {row.finished_at ? formatDate(row.finished_at) : "—"}
                      </td>
                      <td className="px-3 text-right font-mono tabular-nums text-[12px]" style={{ color: "var(--color-body)" }}>
                        {row.rows_ingested ?? "—"}
                      </td>
                      <td className="px-3 text-right font-mono tabular-nums text-[12px]" style={{ color: "var(--color-body)" }}>
                        {row.rows_updated ?? "—"}
                      </td>
                      <td className="px-3 text-right font-mono tabular-nums text-[12px]" style={{ color: "var(--color-muted)" }}>
                        {durationMs > 0 ? durationLabel : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Error details for failed syncs */}
        {syncs.some((s) => s.error_message) && (
          <div className="px-4 py-3 space-y-2" style={{ borderTop: "1px solid var(--color-border)" }}>
            {syncs
              .filter((s) => s.error_message)
              .map((s) => (
                <div
                  key={`${s.id}-err`}
                  className="text-[11.5px] font-mono px-3 py-1.5"
                  style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.2)", background: "rgba(255,86,48,0.06)", color: "#B71D18" }}
                >
                  <span className="font-semibold">
                    {s.started_at ? timeAgo(s.started_at) : "Unknown"}:{" "}
                  </span>
                  {s.error_message}
                </div>
              ))}
          </div>
        )}
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Page root
// ---------------------------------------------------------------------------

export default function MitrePage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<Tab>("matrix");

  // Tactics + mitigations are loaded at root so:
  //  1. MatrixTab can render without re-fetching when switching tabs.
  //  2. TechniquesTab drawer can show mitigations without a separate fetch.
  const [tactics, setTactics] = useState<MitreTacticResponse[]>([]);
  const [tacticsLoading, setTacticsLoading] = useState(true);
  const [mitigations, setMitigations] = useState<MitreMitigationResponse[]>(
    [],
  );
  const [refreshing, setRefreshing] = useState(false);

  // Pre-selected tactic shortname injected from a Matrix card click
  const [techniquesTacticFilter, setTechniquesTacticFilter] =
    useState<string>("");

  const loadTactics = useCallback(async () => {
    setTacticsLoading(true);
    try {
      const data = await api.mitre.listTactics();
      setTactics(data);
    } catch {
      toast("error", "Failed to load tactics");
    } finally {
      setTacticsLoading(false);
    }
  }, [toast]);

  const loadMitigations = useCallback(async () => {
    try {
      const data = await api.mitre.listMitigations();
      setMitigations(data);
    } catch {
      // Non-critical — Techniques drawer degrades gracefully with no mitigations
    }
  }, []);

  useEffect(() => {
    loadTactics();
    loadMitigations();
  }, [loadTactics, loadMitigations]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([loadTactics(), loadMitigations()]);
    setRefreshing(false);
  };

  const handleTacticClick = (tactic: MitreTacticResponse) => {
    setTechniquesTacticFilter(tactic.shortname || tactic.external_id);
    setActiveTab("techniques");
  };

  // No technique_count on MitreTacticResponse — we show the tactics count only
  const totalMitigations = mitigations.length;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <PageHeader
        eyebrow={{ icon: Layers, label: "Intelligence" }}
        title="MITRE ATT&CK"
        description={
          tacticsLoading
            ? "Loading ATT&CK knowledge base…"
            : `${tactics.length} tactics · ${totalMitigations} mitigations · MITRE ATT&CK adversary knowledge base`
        }
        actions={
          <RefreshButton onClick={handleRefresh} refreshing={refreshing} />
        }
      />

      {/* Tab bar */}
      <div className="flex gap-1" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className="h-10 px-4 text-[13px] font-semibold transition-colors"
            style={{
              color: activeTab === tab.id ? "var(--color-ink)" : "var(--color-muted)",
              boxShadow: activeTab === tab.id ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content — conditional render keeps each tab's local state alive
          only while it is active */}
      {activeTab === "matrix" && (
        <MatrixTab
          tactics={tactics}
          loading={tacticsLoading}
          onTacticClick={handleTacticClick}
        />
      )}

      {activeTab === "techniques" && (
        <TechniquesTab
          tactics={tactics}
          mitigations={mitigations}
          externalTacticFilter={techniquesTacticFilter}
        />
      )}

      {activeTab === "groups" && <GroupsTab />}
      {activeTab === "software" && <SoftwareTab />}
      {activeTab === "datasources" && <DataSourcesTab />}
      {activeTab === "campaigns" && <CampaignsTab />}
      {activeTab === "mitigations" && <MitigationsTab />}
      {activeTab === "layers" && <LayersTab />}

      {activeTab === "sync" && <SyncTab />}
    </div>
  );
}


// --- New tabs ---------------------------------------------------------

function GroupsTab() {
  const { toast } = useToast();
  const [groups, setGroups] = useState<Awaited<ReturnType<typeof api.mitre.listGroups>>>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [country, setCountry] = useState("");
  const [sector, setSector] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.mitre
      .listGroups({
        q: q || undefined,
        country: country || undefined,
        sector: sector || undefined,
        limit: 500,
      })
      .then((r) => { if (!cancelled) setGroups(r); })
      .catch(() => { if (!cancelled) toast("error", "Failed to load groups"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => {
      cancelled = true;
    };
  }, [q, country, sector, toast]);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search G#### / name / description"
          className="h-10 px-3 text-[13px]"
          style={{
            borderRadius: 4,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        />
        <input
          type="text"
          value={country}
          onChange={(e) => setCountry(e.target.value)}
          placeholder="Country (IR, RU, CN…)"
          className="h-10 px-3 text-[13px]"
          style={{
            borderRadius: 4,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        />
        <input
          type="text"
          value={sector}
          onChange={(e) => setSector(e.target.value)}
          placeholder="Sector"
          className="h-10 px-3 text-[13px]"
          style={{
            borderRadius: 4,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-ink)",
          }}
        />
      </div>
      <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        {loading ? "Loading…" : `${groups.length} groups`}
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {groups.map((g) => (
          <div
            key={g.id}
            className="p-4"
            style={{
              borderRadius: 5,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
            }}
          >
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                {g.name}
              </h4>
              <span
                className="text-[10px] font-bold px-1.5 h-[18px] inline-flex items-center"
                style={{
                  borderRadius: 3,
                  background: "rgba(0,124,90,0.10)",
                  color: "#1B5E20",
                }}
              >
                {g.external_id}
              </span>
            </div>
            {(g.aliases ?? []).length > 0 && (
              <p className="text-[11px] mb-1" style={{ color: "var(--color-muted)" }}>
                aka {(g.aliases ?? []).slice(0, 4).join(", ")}
                {(g.aliases ?? []).length > 4 && ` +${(g.aliases ?? []).length - 4}`}
              </p>
            )}
            <div className="flex gap-1 flex-wrap text-[10px]">
              {(g.country_codes ?? []).map((c) => (
                <span
                  key={c}
                  className="px-1.5 h-[18px] inline-flex items-center font-semibold"
                  style={{ borderRadius: 3, background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                >
                  {c}
                </span>
              ))}
              {g.sectors_targeted.slice(0, 3).map((s) => (
                <span
                  key={s}
                  className="px-1.5 h-[18px] inline-flex items-center font-semibold"
                  style={{ borderRadius: 3, background: "rgba(255,79,0,0.08)", color: "var(--color-accent)" }}
                >
                  {s}
                </span>
              ))}
            </div>
            {g.url && (
              <a
                href={g.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-semibold mt-2 inline-block"
                style={{ color: "var(--color-accent)" }}
              >
                attack.mitre.org →
              </a>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function SoftwareTab() {
  const { toast } = useToast();
  const [items, setItems] = useState<Awaited<ReturnType<typeof api.mitre.listSoftware>>>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [type, setType] = useState<"" | "malware" | "tool">("");
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.mitre
      .listSoftware({
        q: q || undefined,
        software_type: (type || undefined) as "malware" | "tool" | undefined,
        limit: 1000,
      })
      .then((r) => { if (!cancelled) setItems(r); })
      .catch(() => { if (!cancelled) toast("error", "Failed to load software"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [q, type, toast]);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search S#### or name"
          className="h-10 px-3 text-[13px]"
          style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value as "" | "malware" | "tool")}
          className="h-10 px-3 text-[13px]"
          style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
        >
          <option value="">All types</option>
          <option value="malware">Malware</option>
          <option value="tool">Tool</option>
        </select>
      </div>
      <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        {loading ? "Loading…" : `${items.length} software entries`}
      </p>
      <div className="overflow-x-auto" style={{ border: "1px solid var(--color-border)", borderRadius: 5 }}>
        <table className="w-full text-[12px]">
          <thead style={{ background: "var(--color-surface)" }}>
            <tr style={{ color: "var(--color-muted)" }}>
              <th className="text-left px-3 py-2">ID</th>
              <th className="text-left px-3 py-2">Name</th>
              <th className="text-left px-3 py-2">Type</th>
              <th className="text-left px-3 py-2">Aliases</th>
              <th className="text-left px-3 py-2">Platforms</th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, 1000).map((s) => (
              <tr key={s.id} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                <td className="px-3 py-2 font-mono">{s.external_id}</td>
                <td className="px-3 py-2 font-semibold" style={{ color: "var(--color-ink)" }}>{s.name}</td>
                <td className="px-3 py-2">{s.software_type}</td>
                <td className="px-3 py-2" style={{ color: "var(--color-muted)" }}>
                  {(s.aliases || []).slice(0, 4).join(", ")}
                </td>
                <td className="px-3 py-2" style={{ color: "var(--color-muted)" }}>
                  {(s.platforms || []).slice(0, 4).join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DataSourcesTab() {
  const { toast } = useToast();
  const [items, setItems] = useState<Awaited<ReturnType<typeof api.mitre.listDataSources>>>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.mitre.listDataSources()
      .then(setItems)
      .catch(() => toast("error", "Failed to load data sources"))
      .finally(() => setLoading(false));
  }, [toast]);
  return (
    <div className="space-y-3">
      <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        {loading ? "Loading…" : `${items.length} data sources`}
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {items.map((d) => (
          <div
            key={d.id}
            className="p-4"
            style={{ borderRadius: 5, border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
          >
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>{d.name}</h4>
              <span
                className="text-[10px] font-bold px-1.5 h-[18px] inline-flex items-center"
                style={{ borderRadius: 3, background: "rgba(142,51,255,0.10)", color: "#6B21A8" }}
              >
                {d.external_id}
              </span>
            </div>
            {d.description && (
              <p className="text-[11px] mb-2" style={{ color: "var(--color-muted)" }}>
                {d.description.slice(0, 200)}{d.description.length > 200 ? "…" : ""}
              </p>
            )}
            {d.data_components && d.data_components.length > 0 && (
              <div className="text-[11px]" style={{ color: "var(--color-body)" }}>
                <span className="font-semibold">Components:</span>{" "}
                {d.data_components.map((c) => c.name).filter(Boolean).slice(0, 6).join(", ")}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function CampaignsTab() {
  const { toast } = useToast();
  const [items, setItems] = useState<Awaited<ReturnType<typeof api.mitre.listCampaigns>>>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.mitre.listCampaigns()
      .then(setItems)
      .catch(() => toast("error", "Failed to load campaigns"))
      .finally(() => setLoading(false));
  }, [toast]);
  return (
    <div className="space-y-3">
      <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        {loading ? "Loading…" : `${items.length} campaigns`}
      </p>
      <div className="overflow-x-auto" style={{ border: "1px solid var(--color-border)", borderRadius: 5 }}>
        <table className="w-full text-[12px]">
          <thead style={{ background: "var(--color-surface)" }}>
            <tr style={{ color: "var(--color-muted)" }}>
              <th className="text-left px-3 py-2">ID</th>
              <th className="text-left px-3 py-2">Name</th>
              <th className="text-left px-3 py-2">First Seen</th>
              <th className="text-left px-3 py-2">Last Seen</th>
              <th className="text-left px-3 py-2">Aliases</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                <td className="px-3 py-2 font-mono">{c.external_id}</td>
                <td className="px-3 py-2 font-semibold" style={{ color: "var(--color-ink)" }}>{c.name}</td>
                <td className="px-3 py-2" style={{ color: "var(--color-muted)" }}>{c.first_seen?.split("T")[0] ?? "—"}</td>
                <td className="px-3 py-2" style={{ color: "var(--color-muted)" }}>{c.last_seen?.split("T")[0] ?? "—"}</td>
                <td className="px-3 py-2" style={{ color: "var(--color-muted)" }}>
                  {(c.aliases || []).slice(0, 4).join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LayersTab() {
  const { toast } = useToast();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [layers, setLayers] = useState<Awaited<ReturnType<typeof api.mitre.listLayers>>>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [scoresText, setScoresText] = useState("");

  useEffect(() => {
    api.getCurrentOrg()
      .then((o) => setOrgId(o?.id || null))
      .catch(() => setOrgId(null));
  }, []);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      setLayers(await api.mitre.listLayers(orgId));
    } catch {
      toast("error", "Failed to load layers");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => { load(); }, [load]);

  if (!orgId) {
    return (
      <p className="text-[13px]" style={{ color: "var(--color-muted)" }}>
        Loading current organization…
      </p>
    );
  }
  const activeOrgId = orgId;

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
          {loading ? "Loading…" : `${layers.length} saved layers`}
        </p>
        <button
          onClick={() => setShowCreate(true)}
          className="h-9 px-4 text-[13px] font-semibold"
          style={{ borderRadius: 4, background: "var(--color-accent)", color: "#fff" }}
        >
          + New layer
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {layers.map((l) => (
          <div
            key={l.id}
            className="p-4"
            style={{ borderRadius: 5, border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
          >
            <h4 className="text-[13px] font-semibold mb-1" style={{ color: "var(--color-ink)" }}>{l.name}</h4>
            <p className="text-[11px] mb-2" style={{ color: "var(--color-muted)" }}>
              {Object.keys(l.technique_scores || {}).length} techniques scored · {l.matrix}
            </p>
            <div className="flex gap-2 mt-2">
              <button
                onClick={async () => {
                  try {
                    const json = await api.mitre.exportNavigatorJson(l.id);
                    const blob = new Blob([JSON.stringify(json, null, 2)], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `${l.name.replace(/[^A-Za-z0-9]+/g, "_")}.layer.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    toast("success", "Navigator JSON downloaded");
                  } catch (e) {
                    toast("error", `Export failed — ${String(e)}`);
                  }
                }}
                className="h-8 px-3 text-[12px] font-semibold"
                style={{ borderRadius: 4, background: "var(--color-accent)", color: "#fff" }}
              >
                Navigator JSON
              </button>
              <button
                onClick={async () => {
                  if (!window.confirm(`Delete layer "${l.name}"?`)) return;
                  try {
                    await api.mitre.deleteLayer(l.id);
                    setLayers((prev) => prev.filter((x) => x.id !== l.id));
                  } catch (e) {
                    toast("error", `Delete failed — ${String(e)}`);
                  }
                }}
                className="h-8 px-3 text-[12px] font-semibold"
                style={{
                  borderRadius: 4,
                  border: "1px solid #B71D18",
                  background: "rgba(183,29,24,0.05)",
                  color: "#B71D18",
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      {showCreate && (
        <div
          className="fixed inset-0 z-[200] flex items-start justify-center pt-16"
          style={{ background: "rgba(0,0,0,0.4)" }}
          onClick={() => setShowCreate(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[640px] p-6"
            style={{ borderRadius: 8, background: "var(--color-canvas)", border: "1px solid var(--color-border)" }}
          >
            <h3 className="text-[18px] font-semibold mb-2" style={{ color: "var(--color-ink)" }}>
              New coverage layer
            </h3>
            <p className="text-[12px] mb-3" style={{ color: "var(--color-muted)" }}>
              Paste a list of techniques + scores, one per line: <code>T1059 80</code>. Score is 0-100.
            </p>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Layer name"
              className="w-full h-9 px-3 text-[13px] mb-3"
              style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
            />
            <textarea
              value={scoresText}
              onChange={(e) => setScoresText(e.target.value)}
              rows={10}
              placeholder={"T1059 80\nT1078 60\nT1486 100"}
              className="w-full p-3 text-[12px] font-mono"
              style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
            />
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowCreate(false)}
                className="h-9 px-4 text-[13px] font-semibold"
                style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
              >
                Cancel
              </button>
              <button
                disabled={!name.trim()}
                onClick={async () => {
                  const scores: Record<string, number> = {};
                  for (const line of scoresText.split(/\r?\n/)) {
                    const m = /^\s*(T\d{4}(?:\.\d{3})?)\s+(\d+)\s*$/.exec(line);
                    if (m) scores[m[1]] = Math.max(0, Math.min(100, Number(m[2])));
                  }
                  try {
                    await api.mitre.createLayer({
                      organization_id: activeOrgId!,
                      name: name.trim(),
                      technique_scores: scores,
                    });
                    setShowCreate(false);
                    setName("");
                    setScoresText("");
                    await load();
                    toast("success", `Layer created with ${Object.keys(scores).length} techniques`);
                  } catch (e) {
                    toast("error", `Create failed — ${String(e)}`);
                  }
                }}
                className="h-9 px-4 text-[13px] font-semibold disabled:opacity-50"
                style={{ borderRadius: 4, background: "var(--color-accent)", color: "#fff" }}
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
