// Friendly labels + descriptions for the agent's tool catalogue.
// Mirror of the backend's @tool() registry in
// src/agents/investigation_agent.py. Keep this in sync — the union
// drives the per-tool result renderer dispatch in tool-renderers.tsx.

export type ToolName =
  | "lookup_alert"
  | "search_iocs"
  | "lookup_threat_actor"
  | "related_alerts"
  | "lookup_asset_exposure";

export const TOOL_META: Record<
  ToolName,
  { label: string; description: string }
> = {
  lookup_alert: {
    label: "Inspect alert",
    description: "Read the seed alert in full — title, summary, matched entities.",
  },
  search_iocs: {
    label: "Search IOCs",
    description: "Find indicators of compromise that match a value or substring.",
  },
  lookup_threat_actor: {
    label: "Look up actor",
    description: "Pull a threat actor profile by alias, including TTPs and risk score.",
  },
  related_alerts: {
    label: "Related alerts",
    description: "Find recent alerts in the same org that share a category or matched entity.",
  },
  lookup_asset_exposure: {
    label: "Asset exposure",
    description: "Check what's exposed on a specific asset — open ports, services, vulns.",
  },
};

/** Display label for a tool. Falls back to the raw snake_case when the
 *  agent invents a tool not in the registry (or the registry adds new
 *  ones before this map is updated). */
export function toolLabel(tool: string | null | undefined): string {
  if (!tool) return "Thinking";
  return (TOOL_META as Record<string, { label: string }>)[tool]?.label ?? tool;
}
