// LLM cost rates — published list prices from each provider's docs.
// Used by the dashboard to render an estimated $/run on Investigation
// + Brand-Defender detail panels.
//
// Source links + last-verified date below each rate. The rates change
// infrequently but they DO change — re-verify before relying on the
// numbers in customer-visible reports. Argus's billing pipeline is
// authoritative; this module is for at-a-glance UX only.
//
// Rates are stored as USD per **million tokens** so the math reads
// the same way the provider docs publish them.

export interface ModelRate {
  /** USD per million input tokens (includes cache reads at the same rate
   *  for Claude — anthropic charges separately for cache writes; we lump
   *  them in for simplicity and round up). */
  in_per_mtok: number;
  /** USD per million output tokens. */
  out_per_mtok: number;
  /** Operator-facing label rendered in tooltips. */
  label: string;
  /** Source link the operator can audit. */
  source: string;
  /** When this row was last verified (ISO date). */
  verified: string;
}


// Match by case-insensitive substring on the model_id string. First
// match wins, so order from most-specific to least-specific.
export const MODEL_RATES: Array<{ pattern: string; rate: ModelRate }> = [
  {
    pattern: "opus",
    rate: {
      in_per_mtok: 15,
      out_per_mtok: 75,
      label: "Claude Opus",
      source: "https://www.anthropic.com/pricing",
      verified: "2026-05-04",
    },
  },
  {
    pattern: "sonnet",
    rate: {
      in_per_mtok: 3,
      out_per_mtok: 15,
      label: "Claude Sonnet",
      source: "https://www.anthropic.com/pricing",
      verified: "2026-05-04",
    },
  },
  {
    pattern: "haiku",
    rate: {
      in_per_mtok: 0.8,
      out_per_mtok: 4,
      label: "Claude Haiku",
      source: "https://www.anthropic.com/pricing",
      verified: "2026-05-04",
    },
  },
  {
    pattern: "gpt-4o",
    rate: {
      in_per_mtok: 2.5,
      out_per_mtok: 10,
      label: "OpenAI GPT-4o",
      source: "https://openai.com/api/pricing/",
      verified: "2026-05-04",
    },
  },
  {
    pattern: "gpt-4",
    rate: {
      in_per_mtok: 30,
      out_per_mtok: 60,
      label: "OpenAI GPT-4",
      source: "https://openai.com/api/pricing/",
      verified: "2026-05-04",
    },
  },
];


/** Look up the rate for a model id. Returns null when no rate is
 *  known — the dashboard should show "—" rather than guess. */
export function rateFor(modelId: string | null | undefined): ModelRate | null {
  if (!modelId) return null;
  const lc = modelId.toLowerCase();
  for (const { pattern, rate } of MODEL_RATES) {
    if (lc.includes(pattern)) return rate;
  }
  return null;
}


/** Estimate USD cost for a run given the model + token totals.
 *  Returns null when ANY required input is missing — null propagates
 *  honestly through the FE rather than silently rendering $0.000. */
export function estimateCostUsd(
  modelId: string | null | undefined,
  inputTokens: number | null | undefined,
  outputTokens: number | null | undefined,
): number | null {
  if (
    inputTokens === null
    || inputTokens === undefined
    || outputTokens === null
    || outputTokens === undefined
  ) {
    return null;
  }
  const rate = rateFor(modelId);
  if (!rate) return null;
  return (
    (inputTokens * rate.in_per_mtok + outputTokens * rate.out_per_mtok)
    / 1_000_000
  );
}


/** Render a USD cost as a short string ("$0.018"), or "—" for null. */
export function formatCostUsd(cost: number | null): string {
  if (cost === null) return "—";
  if (cost < 0.001) return "<$0.001";
  if (cost < 0.01) return `$${cost.toFixed(4)}`;
  if (cost < 1) return `$${cost.toFixed(3)}`;
  return `$${cost.toFixed(2)}`;
}
