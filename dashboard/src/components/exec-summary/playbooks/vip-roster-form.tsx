"use client";

/**
 * VipRosterForm — input form for the add_vip_roster playbook.
 *
 * The framework supports generic JSON Schema-driven forms via
 * Playbook.input_schema, but for v1 we hand-roll the only
 * requires_input playbook so the operator gets a polished
 * "add multiple VIPs at once" UX instead of a generic schema renderer.
 */

import { Plus, X } from "lucide-react";
import { useEffect } from "react";

export interface VipFormRow {
  name: string;
  title: string;
  emails: string;     // comma-separated, parsed on submit
  usernames: string;  // comma-separated, parsed on submit
}

interface Props {
  rows: VipFormRow[];
  onChange: (rows: VipFormRow[]) => void;
}

export function VipRosterForm({ rows, onChange }: Props) {
  // Always keep at least one empty row so the form never appears blank.
  useEffect(() => {
    if (rows.length === 0) {
      onChange([{ name: "", title: "", emails: "", usernames: "" }]);
    }
  }, [rows, onChange]);

  function update(idx: number, patch: Partial<VipFormRow>) {
    onChange(rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  }

  function add() {
    onChange([...rows, { name: "", title: "", emails: "", usernames: "" }]);
  }

  function remove(idx: number) {
    onChange(rows.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-2">
      {rows.map((row, idx) => (
        <div
          key={idx}
          className="grid grid-cols-12 gap-2 p-2.5"
          style={{
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: 4,
          }}
        >
          <Field
            label="Name"
            placeholder="Sheikh Ahmed Al Maktoum"
            value={row.name}
            onChange={(v) => update(idx, { name: v })}
            colSpan="col-span-4"
            required
          />
          <Field
            label="Title"
            placeholder="CEO"
            value={row.title}
            onChange={(v) => update(idx, { title: v })}
            colSpan="col-span-3"
          />
          <Field
            label="Emails (comma-sep)"
            placeholder="ceo@enbd.com, ahmed@enbd.com"
            value={row.emails}
            onChange={(v) => update(idx, { emails: v })}
            colSpan="col-span-3"
          />
          <Field
            label="Usernames"
            placeholder="@ceo_enbd"
            value={row.usernames}
            onChange={(v) => update(idx, { usernames: v })}
            colSpan="col-span-2"
          />
          {rows.length > 1 && (
            <button
              type="button"
              onClick={() => remove(idx)}
              aria-label={`Remove VIP ${idx + 1}`}
              className="col-span-12 text-[11px] inline-flex items-center gap-1 self-start"
              style={{
                color: "var(--color-muted)",
                background: "transparent",
                border: "none",
                cursor: "pointer",
                marginTop: -4,
              }}
            >
              <X className="w-3 h-3" /> remove this VIP
            </button>
          )}
        </div>
      ))}
      <button
        type="button"
        onClick={add}
        className="inline-flex items-center gap-1.5 h-7 px-3 text-[11.5px] font-semibold"
        style={{
          background: "var(--color-canvas)",
          border: "1px dashed var(--color-border)",
          borderRadius: 4,
          color: "var(--color-muted)",
          cursor: "pointer",
        }}
      >
        <Plus className="w-3 h-3" /> Add another VIP
      </button>
    </div>
  );
}

function Field({
  label,
  placeholder,
  value,
  onChange,
  colSpan,
  required,
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  colSpan: string;
  required?: boolean;
}) {
  return (
    <label className={`${colSpan} flex flex-col gap-0.5`}>
      <span
        className="text-[10px] font-semibold uppercase tracking-[0.7px]"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
        {required && <span style={{ color: "var(--color-error)" }}> *</span>}
      </span>
      <input
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="px-2 py-1 text-[12px]"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 3,
          color: "var(--color-ink)",
        }}
      />
    </label>
  );
}

/** Convert form rows → backend params shape (`{vips: [...]}`). */
export function toVipParams(rows: VipFormRow[]): { vips: Array<{
  name: string;
  title?: string;
  emails: string[];
  usernames: string[];
}> } {
  const vips = rows
    .filter((r) => r.name.trim())
    .map((r) => ({
      name: r.name.trim(),
      title: r.title.trim() || undefined,
      emails: r.emails.split(",").map((s) => s.trim()).filter(Boolean),
      usernames: r.usernames.split(",").map((s) => s.trim()).filter(Boolean),
    }));
  return { vips };
}
