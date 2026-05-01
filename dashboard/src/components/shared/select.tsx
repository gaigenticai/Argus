"use client";

/**
 * Themed dropdown that replaces the native <select> popup.
 *
 * Native <select> defers to the OS for its dropdown rendering — on
 * macOS Dark Mode, that ships a black popup that clashes with our
 * warm-cream theme even after setting ``color-scheme: light``. This
 * component is a drop-in alternative: same prop shape (``value``,
 * ``onChange``, ``options``), keyboard accessible, themed end-to-end.
 *
 * Renders to a portal so it overlays sibling content, with click-outside
 * + Escape close, and arrow-key + Enter navigation.
 */

import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { ChevronDown, Check } from "lucide-react";

export interface SelectOption<V extends string = string> {
  value: V;
  label: ReactNode;
  /** Optional secondary line (rendered muted, smaller). */
  hint?: string;
  disabled?: boolean;
}

interface SelectProps<V extends string> {
  value: V;
  onChange: (value: V) => void;
  options: SelectOption<V>[];
  /** Placeholder when ``value`` doesn't match any option. */
  placeholder?: string;
  disabled?: boolean;
  /** Optional fixed width in px. Defaults to fit-content with min 200. */
  width?: number;
  /** Override className on the trigger button. */
  className?: string;
  /** Override style on the trigger button. */
  style?: CSSProperties;
  /** Visible label for screen readers when there's no <label> attached. */
  ariaLabel?: string;
}

export function Select<V extends string = string>({
  value,
  onChange,
  options,
  placeholder = "Select…",
  disabled = false,
  width,
  className,
  style,
  ariaLabel,
}: SelectProps<V>) {
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState<number>(-1);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popupRef = useRef<HTMLDivElement>(null);
  const [popupRect, setPopupRect] = useState<{ top: number; left: number; width: number } | null>(null);
  const listboxId = useId();

  const selected = options.find((o) => o.value === value);

  const positionPopup = useCallback(() => {
    if (!triggerRef.current) return;
    const r = triggerRef.current.getBoundingClientRect();
    setPopupRect({
      top: r.bottom + 4,
      left: r.left,
      width: width ?? Math.max(r.width, 200),
    });
  }, [width]);

  useLayoutEffect(() => {
    if (!open) return;
    positionPopup();
    const handler = () => positionPopup();
    window.addEventListener("resize", handler);
    window.addEventListener("scroll", handler, true);
    return () => {
      window.removeEventListener("resize", handler);
      window.removeEventListener("scroll", handler, true);
    };
  }, [open, positionPopup]);

  // Click outside / Escape to close
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (
        triggerRef.current?.contains(t) ||
        popupRef.current?.contains(t)
      ) return;
      setOpen(false);
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // When opening, highlight the current value
  useEffect(() => {
    if (open) {
      const idx = options.findIndex((o) => o.value === value);
      setHighlight(idx >= 0 ? idx : 0);
    }
  }, [open, options, value]);

  const commit = (idx: number) => {
    const o = options[idx];
    if (!o || o.disabled) return;
    onChange(o.value);
    setOpen(false);
    triggerRef.current?.focus();
  };

  const onTriggerKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        setOpen(true);
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlight((h) => Math.min(options.length - 1, h + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlight((h) => Math.max(0, h - 1));
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      commit(highlight);
    }
  };

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => !disabled && setOpen((o) => !o)}
        onKeyDown={onTriggerKey}
        className={
          className ??
          "h-10 pl-3 pr-9 text-[13px] font-semibold outline-none transition-colors disabled:opacity-50 inline-flex items-center"
        }
        style={{
          borderRadius: "4px",
          border: "1px solid var(--color-border)",
          background: "var(--color-canvas)",
          color: "var(--color-ink)",
          minWidth: 200,
          textAlign: "left",
          position: "relative",
          ...style,
        }}
      >
        <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {selected?.label ?? <span style={{ color: "var(--color-muted)" }}>{placeholder}</span>}
        </span>
        <ChevronDown
          className="w-4 h-4"
          style={{
            color: "var(--color-muted)",
            position: "absolute",
            right: 10,
            top: "50%",
            transform: `translateY(-50%) ${open ? "rotate(180deg)" : ""}`,
            transition: "transform 0.15s ease",
          }}
        />
      </button>
      {open && popupRect && typeof window !== "undefined"
        ? createPortal(
            <div
              ref={popupRef}
              role="listbox"
              id={listboxId}
              tabIndex={-1}
              style={{
                position: "fixed",
                top: popupRect.top,
                left: popupRect.left,
                width: popupRect.width,
                maxHeight: 320,
                overflowY: "auto",
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderRadius: "5px",
                boxShadow:
                  "0 4px 16px rgba(54, 52, 46, 0.08), 0 1px 4px rgba(54, 52, 46, 0.06)",
                zIndex: 9999,
                padding: "4px",
              }}
            >
              {options.map((o, i) => {
                const isSelected = o.value === value;
                const isActive = i === highlight;
                return (
                  <button
                    key={o.value}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    disabled={o.disabled}
                    onMouseEnter={() => setHighlight(i)}
                    onClick={() => commit(i)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      width: "100%",
                      padding: "8px 10px",
                      borderRadius: "4px",
                      background: isActive
                        ? "var(--color-accent-bg)"
                        : "transparent",
                      color: o.disabled ? "var(--color-muted)" : "var(--color-ink)",
                      fontSize: "13px",
                      fontWeight: isSelected ? 600 : 500,
                      textAlign: "left",
                      cursor: o.disabled ? "not-allowed" : "pointer",
                      border: "none",
                      transition: "background 0.1s ease",
                    }}
                  >
                    <span
                      style={{
                        width: 14,
                        display: "inline-flex",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {isSelected ? (
                        <Check
                          className="w-3.5 h-3.5"
                          style={{ color: "var(--color-accent)" }}
                        />
                      ) : null}
                    </span>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {o.label}
                      {o.hint ? (
                        <span
                          style={{
                            display: "block",
                            fontSize: "11px",
                            fontWeight: 400,
                            color: "var(--color-muted)",
                            marginTop: 1,
                          }}
                        >
                          {o.hint}
                        </span>
                      ) : null}
                    </span>
                  </button>
                );
              })}
              {options.length === 0 ? (
                <div
                  style={{
                    padding: "8px 10px",
                    fontSize: "13px",
                    color: "var(--color-muted)",
                  }}
                >
                  No options
                </div>
              ) : null}
            </div>,
            document.body
          )
        : null}
    </>
  );
}
