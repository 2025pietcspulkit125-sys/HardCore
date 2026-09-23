"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { maskSensitiveValue, useMaskingPreference } from "../lib/masking";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type CaseRecord = {
  case_id: string;
  evidence_id: string;
  created_at: string;
  filename: string;
  subject: string;
  sender: string;
  recipient: string;
  classification: string;
  risk_score: number;
  risk_level: string;
  confidence: string;
  sha256: string;
  ips: string[];
  urls: string[];
  domains: string[];
  attachments: string[];
};

type RelatedCase = {
  case_id: string;
  evidence_id: string;
  created_at: string;
  filename: string;
  subject: string;
  sender: string;
  classification: string;
  risk_score: number;
  risk_level: string;
  confidence: string;
  similarity_score: number;
  match_confidence: string;
  shared_indicators: { type: string; values: string[] }[];
  reasons: string[];
};

type GraphNode = {
  id: string;
  type: string;
  label: string;
  value: string;
  properties?: Record<string, unknown>;
};

type GraphEdge = {
  source: string;
  target: string;
  relationship: string;
  evidence_id?: string | null;
  properties?: Record<string, unknown>;
};

type ThreatGraphResponse = {
  status: string;
  case: CaseRecord;
  correlation: {
    status: string;
    related_cases: RelatedCase[];
    related_case_count: number;
    best_match_score: number;
    risk_findings: string[];
    interpretation: string;
  };
  threat_graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    statistics: {
      total_nodes: number;
      total_edges: number;
      node_types: Record<string, number>;
      relationships: Record<string, number>;
    };
    graph_metadata: {
      case_id: string;
      evidence_id: string;
      description: string;
      scope: string;
      related_case_count: number;
      limitations?: string[];
    };
  };
};

type InvestigationsResponse = {
  status: string;
  count: number;
  cases: CaseRecord[];
  detail?: string;
};

type ViewFilter = "ALL" | "CASES" | "INDICATORS";

const NAV = [
  { name: "Dashboard", path: "/", icon: "▦" },
  { name: "Analyze Email", path: "/analyze", icon: "✉" },
  { name: "Investigations", path: "/investigations", icon: "⌕" },
  { name: "Threat Graph", path: "/threat-graph", icon: "◇" },
  { name: "Threat Intelligence", path: "/threat-intelligence", icon: "◈" },
  { name: "AI Investigator", path: "/ai-investigator", icon: "✦" },
  { name: "Reports", path: "/reports", icon: "▤" },
  { name: "Settings", path: "/settings", icon: "⚙" },
];

const NODE_META: Record<
  string,
  {
    label: string;
    icon: string;
    color: string;
    bg: string;
  }
> = {
  EMAIL: {
    label: "Email Case",
    icon: "✉",
    color: "#60a5fa",
    bg: "rgba(37, 99, 235, 0.12)",
  },
  DOMAIN: {
    label: "Domain",
    icon: "◈",
    color: "#a78bfa",
    bg: "rgba(139, 92, 246, 0.12)",
  },
  IP: {
    label: "IP Address",
    icon: "◎",
    color: "#fbbf24",
    bg: "rgba(245, 158, 11, 0.12)",
  },
  URL: {
    label: "URL",
    icon: "↗",
    color: "#34d399",
    bg: "rgba(16, 185, 129, 0.12)",
  },
  ATTACHMENT: {
    label: "Attachment",
    icon: "▣",
    color: "#fb7185",
    bg: "rgba(244, 63, 94, 0.12)",
  },
  CAMPAIGN: {
    label: "Campaign",
    icon: "⌘",
    color: "#e879f9",
    bg: "rgba(217, 70, 239, 0.12)",
  },
  SMTP: {
    label: "SMTP Relay",
    icon: "⇄",
    color: "#94a3b8",
    bg: "rgba(100, 116, 139, 0.12)",
  },
};

function getMeta(type: string) {
  const key = type.toUpperCase();
  return (
    NODE_META[key] || {
      label: type,
      icon: "•",
      color: "#94a3b8",
      bg: "rgba(100, 116, 139, 0.12)",
    }
  );
}

function isCaseNode(node: GraphNode) {
  return node.type.toUpperCase() === "EMAIL";
}

function isIndicatorNode(node: GraphNode) {
  const type = node.type.toUpperCase();
  return ["IP", "DOMAIN", "URL", "ATTACHMENT", "SMTP"].includes(type);
}

function isCampaignNode(node: GraphNode) {
  return node.type.toUpperCase() === "CAMPAIGN";
}

function isCurrentCaseNode(node: GraphNode) {
  return Boolean(node.properties?.current_case) || Boolean(node.properties?.selected);
}

function riskClass(level?: string) {
  switch ((level || "LOW").toUpperCase()) {
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/10 text-red-300";
    case "HIGH":
      return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "MEDIUM":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
    default:
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
}

function truncate(value: string, max = 34) {
  if (!value) return "—";
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function readableRelationship(value: string) {
  return value
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function dateText(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function filterNode(node: GraphNode, view: ViewFilter, query: string) {
  const normalized = query.trim().toLowerCase();

  const typeMatches =
    view === "ALL" ||
    (view === "CASES" && (isCaseNode(node) || isCampaignNode(node))) ||
    (view === "INDICATORS" && isIndicatorNode(node));

  const searchMatches =
    !normalized ||
    [
      node.id,
      node.type,
      node.label,
      node.value,
      JSON.stringify(node.properties || {}),
    ]
      .join(" ")
      .toLowerCase()
      .includes(normalized);

  return typeMatches && searchMatches;
}

function connectedNodeDegree(nodes: GraphNode[], edges: GraphEdge[]) {
  const degree = new Map<string, number>();

  nodes.forEach((node) => degree.set(node.id, 0));

  edges.forEach((edge) => {
    degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
  });

  return degree;
}

function buildDisplayNodes(
  nodes: GraphNode[],
  edges: GraphEdge[],
  view: ViewFilter,
  query: string,
  expanded: boolean,
  selectedNodeId: string
) {
  const filtered = nodes.filter((node) => filterNode(node, view, query));

  if (expanded || query.trim()) {
    return filtered;
  }

  const cases = filtered.filter(isCaseNode);
  const campaigns = filtered.filter(isCampaignNode);
  const indicators = filtered.filter(isIndicatorNode);

  const degree = connectedNodeDegree(nodes, edges);

  // Keep the default graph deliberately compact.
  // Show the most-connected indicators first so the main investigation story
  // is visible without a wall of edges.
  const selectedIndicator = indicators.find(
    (node) => node.id === selectedNodeId
  );

  const rankedIndicators = [...indicators].sort(
    (a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0)
  );

  const topIndicators = rankedIndicators.slice(0, 8);

  if (
    selectedIndicator &&
    !topIndicators.some((node) => node.id === selectedIndicator.id)
  ) {
    topIndicators[topIndicators.length - 1] = selectedIndicator;
  }

  return [...cases, ...campaigns, ...topIndicators];
}

type Position = { x: number; y: number };

function computeLayout(nodes: GraphNode[]) {
  const width = 1160;
  const height = 850;

  const positions: Record<string, Position> = {};

  const cases = nodes.filter(isCaseNode);
  const campaigns = nodes.filter(isCampaignNode);
  const indicators = nodes.filter(isIndicatorNode);

  const currentCase =
    cases.find(isCurrentCaseNode) || cases[0] || null;

  const relatedCases = cases.filter(
    (node) => node.id !== currentCase?.id
  );

  if (currentCase) {
    positions[currentCase.id] = {
      x: 300,
      y: 125,
    };
  }

  // Related cases sit in a clean right-side stack.
  relatedCases.slice(0, 4).forEach((node, index) => {
    positions[node.id] = {
      x: 930,
      y: 90 + index * 120,
    };
  });

  // Campaign/correlation cluster is the bridge between the case and indicators.
  campaigns.slice(0, 2).forEach((node, index) => {
    positions[node.id] = {
      x: 615 + index * 235,
      y: 290,
    };
  });

  // Indicators are laid out in a maximum of 4 cards per row.
  const columns = 4;
  const xStart = 115;
  const xStep = 285;
  const yStart = 485;
  const yStep = 135;

  indicators.forEach((node, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);

    positions[node.id] = {
      x: xStart + column * xStep,
      y: yStart + row * yStep,
    };
  });

  nodes.forEach((node, index) => {
    if (positions[node.id]) return;

    positions[node.id] = {
      x: 115 + (index % 4) * 285,
      y: 485 + Math.floor(index / 4) * 135,
    };
  });

  return { positions, width, height };
}

function getCurvePath(source: Position, target: Position) {
  const dx = target.x - source.x;
  const dy = target.y - source.y;

  const curve = Math.max(60, Math.min(170, Math.abs(dy) * 0.45));

  const control1 = {
    x: source.x + dx * 0.2,
    y: source.y + Math.sign(dy || 1) * curve,
  };

  const control2 = {
    x: target.x - dx * 0.2,
    y: target.y - Math.sign(dy || 1) * curve,
  };

  return `M ${source.x} ${source.y} C ${control1.x} ${control1.y}, ${control2.x} ${control2.y}, ${target.x} ${target.y}`;
}

function ThreatGraphContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const requestedCaseId = searchParams.get("case_id") || "";

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState(requestedCaseId);

  const [graphData, setGraphData] =
    useState<ThreatGraphResponse | null>(null);

  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [search, setSearch] = useState("");
  const [view, setView] = useState<ViewFilter>("ALL");
  const [expanded, setExpanded] = useState(false);
  const [zoom, setZoom] = useState(1);

  const [loadingCases, setLoadingCases] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState("");
  const maskingEnabled = useMaskingPreference();

  const loadCases = useCallback(async () => {
    setLoadingCases(true);

    try {
      const response = await fetch(
        `${API_BASE}/api/investigations?limit=200`,
        { cache: "no-store" }
      );

      const result =
        (await response.json()) as InvestigationsResponse;

      if (!response.ok) {
        throw new Error(
          result.detail || "Unable to load stored investigations."
        );
      }

      const available = Array.isArray(result.cases)
        ? result.cases
        : [];

      setCases(available);

      setSelectedCaseId((current) => {
        if (
          requestedCaseId &&
          available.some(
            (item) => item.case_id === requestedCaseId
          )
        ) {
          return requestedCaseId;
        }

        if (
          current &&
          available.some((item) => item.case_id === current)
        ) {
          return current;
        }

        return available[0]?.case_id || "";
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load investigations."
      );
    } finally {
      setLoadingCases(false);
    }
  }, [requestedCaseId]);

  const loadGraph = useCallback(async (caseId: string) => {
    if (!caseId) {
      setGraphData(null);
      return;
    }

    setLoadingGraph(true);
    setError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/threat-graph/${encodeURIComponent(
          caseId
        )}`,
        { cache: "no-store" }
      );

      const result =
        (await response.json()) as ThreatGraphResponse & {
          detail?: string;
        };

      if (!response.ok) {
        throw new Error(
          result.detail || "Unable to load the threat graph."
        );
      }

      setGraphData(result);

      const firstCase =
        result.threat_graph.nodes.find(isCurrentCaseNode) ||
        result.threat_graph.nodes.find(isCaseNode);

      setSelectedNodeId(firstCase?.id || result.threat_graph.nodes[0]?.id || "");
      setExpanded(false);
      setZoom(1);
    } catch (err) {
      setGraphData(null);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load the threat graph."
      );
    } finally {
      setLoadingGraph(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => loadCases());
  }, [loadCases]);

  useEffect(() => {
    if (selectedCaseId) {
      void Promise.resolve().then(() => loadGraph(selectedCaseId));
    }
  }, [selectedCaseId, loadGraph]);

  const graphNodes = useMemo(() => graphData?.threat_graph.nodes || [], [graphData]);
  const graphEdges = useMemo(() => graphData?.threat_graph.edges || [], [graphData]);

  const displayNodes = useMemo(
    () =>
      buildDisplayNodes(
        graphNodes,
        graphEdges,
        view,
        search,
        expanded,
        selectedNodeId
      ),
    [graphNodes, graphEdges, view, search, expanded, selectedNodeId]
  );

  const displayNodeIds = useMemo(
    () => new Set(displayNodes.map((node) => node.id)),
    [displayNodes]
  );

  const displayEdges = useMemo(
    () =>
      graphEdges.filter(
        (edge) =>
          displayNodeIds.has(edge.source) &&
          displayNodeIds.has(edge.target)
      ),
    [graphEdges, displayNodeIds]
  );

  const layout = useMemo(
    () => computeLayout(displayNodes),
    [displayNodes]
  );

  const selectedNode =
    graphNodes.find((node) => node.id === selectedNodeId) ||
    graphNodes.find(isCurrentCaseNode) ||
    graphNodes.find(isCaseNode) ||
    null;

  const selectedConnections = useMemo(() => {
    if (!selectedNode) return [];

    return graphEdges
      .filter(
        (edge) =>
          edge.source === selectedNode.id ||
          edge.target === selectedNode.id
      )
      .map((edge) => {
        const otherId =
          edge.source === selectedNode.id
            ? edge.target
            : edge.source;

        return {
          edge,
          node: graphNodes.find((node) => node.id === otherId),
        };
      })
      .filter((item) => item.node)
      .slice(0, 10);
  }, [selectedNode, graphEdges, graphNodes]);

  const selectedCase =
    graphData?.case ||
    cases.find((item) => item.case_id === selectedCaseId) ||
    null;

  const relatedCases =
    graphData?.correlation.related_cases || [];

  const indicatorTotal = graphNodes.filter(isIndicatorNode).length;
  const defaultIndicatorCount =
    displayNodes.filter(isIndicatorNode).length;

  const hiddenIndicatorCount = Math.max(
    0,
    indicatorTotal - defaultIndicatorCount
  );

  const setCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    router.replace(
      `/threat-graph?case_id=${encodeURIComponent(caseId)}`
    );
  };

  const activePage =
    pathname === "/threat-graph" ? "Threat Graph" : "";

  return (
    <main className="min-h-screen bg-[#070b12] text-slate-200">
      {/* SIDEBAR */}
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0a0f18]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide text-white">
            MailTrace <span className="text-blue-500">AI</span>
          </div>

          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">
            Email Forensics Platform
          </div>
        </div>

        <nav className="flex-1 px-3 py-5">
          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
            Investigation
          </div>

          {NAV.map((item) => {
            const active = item.name === activePage;

            return (
              <Link
                key={item.name}
                href={item.path}
                className={`mb-1 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-sm transition ${
                  active
                    ? "border border-blue-500/20 bg-blue-500/10 text-blue-300"
                    : "text-slate-400 hover:bg-white/5 hover:text-white"
                }`}
              >
                <span className="w-5 text-center">{item.icon}</span>
                <span>{item.name}</span>

                {active && (
                  <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400" />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-slate-800 px-5 py-4">
          <div className="text-[10px] uppercase tracking-[0.16em] text-slate-600">
            Graph interpretation
          </div>
          <div className="mt-1 text-xs leading-5 text-slate-500">
            Evidence links are observable relationships, not identity proof.
          </div>
        </div>
      </aside>

      {/* MAIN */}
      <section className="ml-64 min-h-screen px-7 py-7">
        <div className="mx-auto max-w-[1600px]">
          <header className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="text-[10px] uppercase tracking-[0.25em] text-blue-400">
                Forensic Visualization
              </div>

              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Threat Graph
              </h1>

              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">
                Follow the evidence from the current email to the most relevant
                domains, IPs, URLs, attachments and related investigations.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void loadGraph(selectedCaseId)}
                disabled={!selectedCaseId || loadingGraph}
                className="rounded-lg border border-blue-500/20 bg-blue-500/10 px-4 py-2.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/15 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loadingGraph ? "Refreshing…" : "↻ Refresh"}
              </button>

              <Link
                href="/analyze"
                className="rounded-lg bg-blue-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-500"
              >
                Analyze New Email
              </Link>
            </div>
          </header>

          {error && (
            <div className="mt-6 rounded-xl border border-red-500/25 bg-red-500/10 px-5 py-4 text-sm text-red-300">
              {error}
            </div>
          )}

          {/* CASE CONTEXT */}
          <section className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-5">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
              <div className="min-w-0">
                <div className="font-mono text-[10px] text-blue-300">
                  {selectedCase?.case_id || "NO CASE SELECTED"}
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <h2 className="truncate text-lg font-semibold text-white">
                    {selectedCase?.subject ||
                      selectedCase?.filename ||
                      "Select an investigation"}
                  </h2>

                  {selectedCase && (
                    <span
                      className={`rounded-full border px-2.5 py-1 text-[9px] font-semibold ${riskClass(
                        selectedCase.risk_level
                      )}`}
                    >
                      {selectedCase.risk_level} · {selectedCase.risk_score}/100
                    </span>
                  )}
                </div>

                <p className="mt-1 truncate text-xs text-slate-500">
                  {selectedCase?.sender || "Choose a stored case from the list below."}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    Nodes
                  </div>
                  <div className="mt-1 text-lg font-bold text-white">
                    {graphData?.threat_graph.statistics.total_nodes || 0}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    Links
                  </div>
                  <div className="mt-1 text-lg font-bold text-white">
                    {graphData?.threat_graph.statistics.total_edges || 0}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    Related
                  </div>
                  <div className="mt-1 text-lg font-bold text-white">
                    {graphData?.correlation.related_case_count || 0}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3">
                  <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    Similarity
                  </div>
                  <div className="mt-1 text-lg font-bold text-white">
                    {graphData?.correlation.best_match_score || 0}
                    <span className="ml-1 text-[10px] font-normal text-slate-600">
                      /100
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <div className="mt-6 grid gap-6 xl:grid-cols-[280px_minmax(0,1fr)_320px]">
            {/* CASE SELECTOR */}
            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white">
                    Investigation Cases
                  </h2>
                  <p className="mt-1 text-[11px] text-slate-500">
                    Switch the graph context
                  </p>
                </div>

                <span className="rounded-full border border-slate-700 px-2.5 py-1 text-[9px] text-slate-500">
                  {cases.length}
                </span>
              </div>

              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search cases or indicators…"
                className="mt-4 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2.5 text-xs text-white outline-none placeholder:text-slate-600 focus:border-blue-500/50"
              />

              <div className="mt-4 max-h-[650px] space-y-2 overflow-y-auto pr-1">
                {loadingCases ? (
                  <div className="py-10 text-center text-xs text-slate-600">
                    Loading cases…
                  </div>
                ) : cases.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-800 p-5 text-center text-xs text-slate-500">
                    Analyze an email to create your first investigation.
                  </div>
                ) : (
                  cases.map((item) => (
                    <button
                      key={item.case_id}
                      type="button"
                      onClick={() => setCase(item.case_id)}
                      className={`w-full rounded-xl border p-3 text-left transition ${
                        item.case_id === selectedCaseId
                          ? "border-blue-500/50 bg-blue-500/10"
                          : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[9px] text-blue-300">
                          {item.case_id}
                        </span>

                        <span
                          className={`rounded-full border px-2 py-1 text-[8px] font-semibold ${riskClass(
                            item.risk_level
                          )}`}
                        >
                          {item.risk_level}
                        </span>
                      </div>

                      <div className="mt-2 truncate text-xs font-semibold text-white">
                        {item.subject || item.filename || "Untitled email"}
                      </div>

                      <div className="mt-1 truncate text-[10px] text-slate-500">
                        {item.sender || "Unknown sender"}
                      </div>

                      <div className="mt-2 text-[9px] text-slate-600">
                        {dateText(item.created_at)}
                      </div>
                    </button>
                  ))
                )}
              </div>
            </section>

            {/* GRAPH */}
            <section className="min-w-0 overflow-hidden rounded-2xl border border-slate-800 bg-[#0d1420]">
              <div className="border-b border-slate-800 px-5 py-4">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      Evidence Relationship Map
                    </h2>

                    <p className="mt-1 text-[11px] text-slate-500">
                      Current case → correlation → observables
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {(["ALL", "CASES", "INDICATORS"] as ViewFilter[]).map(
                      (item) => (
                        <button
                          key={item}
                          type="button"
                          onClick={() => setView(item)}
                          className={`rounded-lg border px-3 py-2 text-[9px] font-semibold ${
                            view === item
                              ? "border-blue-500/40 bg-blue-500/10 text-blue-300"
                              : "border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-300"
                          }`}
                        >
                          {item === "ALL"
                            ? "All"
                            : item === "CASES"
                              ? "Cases"
                              : "Indicators"}
                        </button>
                      )
                    )}

                    <div className="mx-1 h-5 w-px bg-slate-800" />

                    <button
                      type="button"
                      onClick={() => setZoom((value) => Math.min(1.3, Number((value + 0.1).toFixed(2))))}
                      className="rounded-lg border border-slate-800 px-2.5 py-2 text-xs text-slate-400 hover:text-white"
                    >
                      +
                    </button>

                    <button
                      type="button"
                      onClick={() => setZoom((value) => Math.max(0.75, Number((value - 0.1).toFixed(2))))}
                      className="rounded-lg border border-slate-800 px-2.5 py-2 text-xs text-slate-400 hover:text-white"
                    >
                      −
                    </button>

                    <button
                      type="button"
                      onClick={() => setZoom(1)}
                      className="rounded-lg border border-slate-800 px-2.5 py-2 text-[9px] text-slate-500 hover:text-white"
                    >
                      Fit
                    </button>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/30 px-3 py-2.5">
                  <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    Read the map
                  </div>

                  <span className="text-[10px] text-slate-500">
                    <b className="text-cyan-300">1.</b> Current email
                  </span>

                  <span className="text-[10px] text-slate-500">
                    <b className="text-fuchsia-300">2.</b> Campaign/correlation
                  </span>

                  <span className="text-[10px] text-slate-500">
                    <b className="text-slate-300">3.</b> Observable evidence
                  </span>

                  <span className="ml-auto text-[9px] text-slate-600">
                    Click a node to inspect
                  </span>
                </div>
              </div>

              {loadingGraph ? (
                <div className="flex min-h-[720px] items-center justify-center text-xs text-slate-600">
                  Building evidence map…
                </div>
              ) : !graphData ? (
                <div className="flex min-h-[720px] items-center justify-center px-8 text-center">
                  <div>
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-500/10 text-2xl text-blue-300">
                      ◇
                    </div>
                    <h3 className="mt-5 text-lg font-semibold text-white">
                      Select an investigation
                    </h3>
                    <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
                      Choose a stored case on the left to visualize its forensic relationships.
                    </p>
                  </div>
                </div>
              ) : (
                <>
                  <div className="overflow-auto bg-[#070b12] p-3">
                    <div
                      className="relative mx-auto overflow-hidden rounded-xl border border-slate-900 bg-[#080c14]"
                      style={{
                        width: `${layout.width * zoom}px`,
                        height: `${layout.height * zoom}px`,
                      }}
                    >
                      <div
                        className="absolute left-0 top-0 origin-top-left"
                        style={{
                          width: `${layout.width}px`,
                          height: `${layout.height}px`,
                          transform: `scale(${zoom})`,
                        }}
                      >
                        {/* Grid */}
                        <div
                          className="pointer-events-none absolute inset-0 opacity-[0.35]"
                          style={{
                            backgroundImage:
                              "linear-gradient(rgba(71,85,105,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(71,85,105,0.08) 1px, transparent 1px)",
                            backgroundSize: "32px 32px",
                          }}
                        />

                        {/* Lanes */}
                        <div className="pointer-events-none absolute left-5 right-5 top-8">
                          <div className="flex items-center gap-3">
                            <span className="rounded-full border border-blue-500/20 bg-blue-500/5 px-3 py-1 text-[9px] font-semibold uppercase tracking-[0.18em] text-blue-300">
                              Case context
                            </span>
                            <div className="h-px flex-1 bg-slate-900" />
                          </div>
                        </div>

                        <div className="pointer-events-none absolute left-5 right-5 top-[205px]">
                          <div className="flex items-center gap-3">
                            <span className="rounded-full border border-fuchsia-500/20 bg-fuchsia-500/5 px-3 py-1 text-[9px] font-semibold uppercase tracking-[0.18em] text-fuchsia-300">
                              Correlation
                            </span>
                            <div className="h-px flex-1 bg-slate-900" />
                          </div>
                        </div>

                        <div className="pointer-events-none absolute left-5 right-5 top-[405px]">
                          <div className="flex items-center gap-3">
                            <span className="rounded-full border border-slate-800 bg-slate-950/40 px-3 py-1 text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                              Observable evidence
                            </span>
                            <div className="h-px flex-1 bg-slate-900" />
                          </div>
                        </div>

                        <svg
                          width={layout.width}
                          height={layout.height}
                          viewBox={`0 0 ${layout.width} ${layout.height}`}
                          className="absolute inset-0"
                        >
                          <defs>
                            <marker
                              id="mt-arrow"
                              viewBox="0 0 10 10"
                              refX="8"
                              refY="5"
                              markerWidth="5"
                              markerHeight="5"
                              orient="auto-start-reverse"
                            >
                              <path
                                d="M 0 0 L 10 5 L 0 10 z"
                                fill="#475569"
                              />
                            </marker>
                          </defs>

                          {displayEdges.map((edge, index) => {
                            const source = layout.positions[edge.source];
                            const target = layout.positions[edge.target];

                            if (!source || !target) return null;

                            const active =
                              edge.source === selectedNodeId ||
                              edge.target === selectedNodeId;

                            const correlation =
                              edge.relationship === "CORRELATED_WITH" ||
                              edge.relationship === "POTENTIAL_CAMPAIGN";

                            const stroke = active
                              ? "#60a5fa"
                              : correlation
                                ? "#8b5cf6"
                                : "#334155";

                            return (
                              <path
                                key={`${edge.source}-${edge.target}-${edge.relationship}-${index}`}
                                d={getCurvePath(source, target)}
                                fill="none"
                                stroke={stroke}
                                strokeWidth={active ? 2.8 : 1.4}
                                strokeDasharray={
                                  correlation ? "7 6" : undefined
                                }
                                markerEnd={
                                  active
                                    ? "url(#mt-arrow)"
                                    : undefined
                                }
                                opacity={
                                  selectedNodeId && !active
                                    ? 0.45
                                    : 0.9
                                }
                              />
                            );
                          })}
                        </svg>

                        {displayNodes.map((node) => {
                          const position = layout.positions[node.id];
                          if (!position) return null;

                          const meta = getMeta(node.type);
                          const current = isCurrentCaseNode(node);
                          const selected = node.id === selectedNodeId;

                          const connected = selectedConnections.some(
                            (item) => item.node?.id === node.id
                          );

                          return (
                            <button
                              key={node.id}
                              type="button"
                              onClick={() => setSelectedNodeId(node.id)}
                              className={`absolute w-[205px] -translate-x-1/2 -translate-y-1/2 rounded-xl border p-3 text-left shadow-2xl transition duration-150 ${
                                selected
                                  ? "z-30 border-blue-400 ring-2 ring-blue-400/20"
                                  : connected
                                    ? "z-20 border-slate-600"
                                    : "z-10 border-slate-800"
                              } ${
                                current
                                  ? "bg-cyan-500/[0.08]"
                                  : "bg-[#0d1420]"
                              } hover:-translate-y-[53%]`}
                              style={{
                                left: position.x,
                                top: position.y,
                                borderLeftColor: meta.color,
                                borderLeftWidth: 3,
                                opacity:
                                  selectedNodeId &&
                                  !selected &&
                                  !connected
                                    ? 0.72
                                    : 1,
                              }}
                            >
                              <div className="flex items-center justify-between gap-2">
                                <div
                                  className="flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.13em]"
                                  style={{ color: meta.color }}
                                >
                                  <span
                                    className="flex h-7 w-7 items-center justify-center rounded-lg text-xs"
                                    style={{
                                      backgroundColor: meta.bg,
                                    }}
                                  >
                                    {meta.icon}
                                  </span>
                                  {meta.label}
                                </div>

                                {current && (
                                  <span className="rounded-full border border-cyan-400/20 bg-cyan-500/5 px-2 py-1 text-[8px] font-semibold text-cyan-300">
                                    CURRENT
                                  </span>
                                )}
                              </div>

                              <div className="mt-3 truncate text-xs font-semibold text-white">
                                {truncate(
                                  node.label || node.value,
                                  30
                                )}
                              </div>

                              <div className="mt-1 break-all text-[9px] leading-4 text-slate-500">
                                {truncate(node.value, 46)}
                              </div>

                              {current && selectedCase && (
                                <div className="mt-3 flex items-center justify-between border-t border-cyan-400/10 pt-2">
                                  <span
                                    className={`rounded-full border px-2 py-1 text-[8px] font-semibold ${riskClass(
                                      selectedCase.risk_level
                                    )}`}
                                  >
                                    {selectedCase.risk_level}
                                  </span>

                                  <span className="text-[8px] text-slate-600">
                                    {selectedCase.classification}
                                  </span>
                                </div>
                              )}
                            </button>
                          );
                        })}

                        {!displayNodes.length && (
                          <div className="absolute inset-0 flex items-center justify-center text-center">
                            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/80 px-6 py-5">
                              <div className="text-sm font-semibold text-white">
                                No matching nodes
                              </div>
                              <div className="mt-1 text-xs text-slate-500">
                                Clear the search or change the filter.
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col gap-3 border-t border-slate-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[9px] uppercase tracking-[0.15em] text-slate-600">
                        Visible
                      </span>

                      <span className="rounded-full border border-slate-800 bg-slate-950/40 px-2.5 py-1 text-[9px] text-slate-500">
                        {displayNodes.length} nodes
                      </span>

                      <span className="rounded-full border border-slate-800 bg-slate-950/40 px-2.5 py-1 text-[9px] text-slate-500">
                        {displayEdges.length} links
                      </span>
                    </div>

                    {hiddenIndicatorCount > 0 && !expanded && !search.trim() && (
                      <button
                        type="button"
                        onClick={() => setExpanded(true)}
                        className="rounded-lg border border-blue-500/20 bg-blue-500/10 px-3 py-2 text-[10px] font-semibold text-blue-300 hover:bg-blue-500/15"
                      >
                        Show all {indicatorTotal} indicators
                        <span className="ml-1 text-blue-400/60">
                          (+{hiddenIndicatorCount})
                        </span>
                      </button>
                    )}

                    {expanded && (
                      <button
                        type="button"
                        onClick={() => setExpanded(false)}
                        className="rounded-lg border border-slate-800 px-3 py-2 text-[10px] font-semibold text-slate-400 hover:text-white"
                      >
                        Simplify graph
                      </button>
                    )}
                  </div>
                </>
              )}

              <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 px-5 py-4">
                <span className="text-[9px] uppercase tracking-[0.15em] text-slate-600">
                  Legend
                </span>

                {[
                  ["EMAIL", "Email"],
                  ["DOMAIN", "Domain"],
                  ["IP", "IP"],
                  ["URL", "URL"],
                  ["ATTACHMENT", "File"],
                  ["CAMPAIGN", "Campaign"],
                ].map(([type, label]) => {
                  const meta = getMeta(type);

                  return (
                    <span
                      key={type}
                      className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-950/30 px-2.5 py-1 text-[9px] text-slate-500"
                    >
                      <span style={{ color: meta.color }}>
                        {meta.icon}
                      </span>
                      {label}
                    </span>
                  );
                })}

                <span className="ml-auto text-[9px] text-slate-600">
                  Solid = evidence · Dashed = correlation
                </span>
              </div>
            </section>

            {/* INSPECTOR */}
            <aside className="space-y-4">
              <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.19em] text-blue-400">
                      Node Inspector
                    </div>
                    <h2 className="mt-1 text-sm font-semibold text-white">
                      {selectedNode
                        ? getMeta(selectedNode.type).label
                        : "Evidence Details"}
                    </h2>
                  </div>

                  {selectedNode && (
                    <span
                      className="rounded-full border px-2 py-1 text-[9px] font-semibold"
                      style={{
                        color: getMeta(selectedNode.type).color,
                        borderColor: `${getMeta(selectedNode.type).color}33`,
                      }}
                    >
                      {getMeta(selectedNode.type).icon}
                    </span>
                  )}
                </div>

                {selectedNode ? (
                  <div className="mt-5">
                    <div
                      className="rounded-xl border p-4"
                      style={{
                        borderColor: `${getMeta(selectedNode.type).color}33`,
                        backgroundColor: getMeta(selectedNode.type).bg,
                      }}
                    >
                      <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                        Observable
                      </div>

                      <div className="mt-2 break-all font-mono text-sm font-semibold text-white">
                        {maskSensitiveValue(selectedNode.value, maskingEnabled, selectedNode.type === "IP" ? "ip" : selectedNode.type === "EMAIL" ? "email" : "text")}
                      </div>

                      <div className="mt-2 text-xs leading-5 text-slate-500">
                        {selectedNode.label}
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-2 gap-2">
                      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                        <div className="text-[9px] uppercase tracking-wider text-slate-600">
                          Type
                        </div>
                        <div className="mt-1 text-xs font-semibold text-slate-300">
                          {getMeta(selectedNode.type).label}
                        </div>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                        <div className="text-[9px] uppercase tracking-wider text-slate-600">
                          Links
                        </div>
                        <div className="mt-1 text-xs font-semibold text-slate-300">
                          {selectedConnections.length}
                        </div>
                      </div>
                    </div>

                    {isCaseNode(selectedNode) && selectedCase && (
                      <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                        <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                          Investigation
                        </div>

                        <div className="mt-3 space-y-3">
                          <div>
                            <div className="text-[9px] text-slate-600">
                              Case ID
                            </div>
                            <div className="mt-1 font-mono text-[10px] text-blue-300">
                              {selectedCase.case_id}
                            </div>
                          </div>

                          <div>
                            <div className="text-[9px] text-slate-600">
                              Sender
                            </div>
                            <div className="mt-1 break-all text-[10px] text-slate-300">
                              {selectedCase.sender}
                            </div>
                          </div>

                          <div className="flex items-center justify-between">
                            <span
                              className={`rounded-full border px-2 py-1 text-[8px] font-semibold ${riskClass(
                                selectedCase.risk_level
                              )}`}
                            >
                              {selectedCase.risk_level}
                            </span>

                            <span className="text-[9px] text-slate-600">
                              {selectedCase.risk_score}/100
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="mt-4">
                      <div className="flex items-center justify-between">
                        <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">
                          Direct Connections
                        </div>
                        <span className="text-[9px] text-slate-600">
                          {selectedConnections.length}
                        </span>
                      </div>

                      <div className="mt-3 space-y-2">
                        {selectedConnections.length ? (
                          selectedConnections.map(({ edge, node }) => {
                            if (!node) return null;

                            return (
                              <button
                                key={`${edge.source}-${edge.target}-${edge.relationship}`}
                                type="button"
                                onClick={() =>
                                  setSelectedNodeId(node.id)
                                }
                                className="w-full rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-left transition hover:border-slate-700"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="text-[9px] uppercase tracking-[0.11em] text-slate-600">
                                    {readableRelationship(
                                      edge.relationship
                                    )}
                                  </span>

                                  <span
                                    style={{
                                      color: getMeta(node.type).color,
                                    }}
                                  >
                                    {getMeta(node.type).icon}
                                  </span>
                                </div>

                                <div className="mt-1 truncate text-xs text-slate-300">
                                  {node.value}
                                </div>
                              </button>
                            );
                          })
                        ) : (
                          <div className="rounded-lg border border-dashed border-slate-800 p-4 text-[10px] leading-5 text-slate-600">
                            No direct connections are available for this node.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="mt-5 rounded-xl border border-dashed border-slate-800 bg-slate-950/30 p-5 text-center text-xs text-slate-600">
                    Select a graph node to inspect its forensic properties.
                  </div>
                )}
              </section>

              <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-[10px] uppercase tracking-[0.19em] text-fuchsia-300">
                      Cross-Case
                    </div>
                    <h2 className="mt-1 text-sm font-semibold text-white">
                      Related Investigations
                    </h2>
                  </div>

                  <span className="rounded-full border border-slate-800 px-2 py-1 text-[9px] text-slate-500">
                    {relatedCases.length}
                  </span>
                </div>

                {relatedCases.length ? (
                  <div className="mt-4 space-y-2">
                    {relatedCases.slice(0, 4).map((match) => (
                      <button
                        key={match.case_id}
                        type="button"
                        onClick={() => setCase(match.case_id)}
                        className="w-full rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-left transition hover:border-slate-700"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[9px] text-blue-300">
                            {match.case_id}
                          </span>

                          <span className="rounded-full border border-fuchsia-500/20 bg-fuchsia-500/5 px-2 py-1 text-[8px] text-fuchsia-300">
                            {match.similarity_score}/100
                          </span>
                        </div>

                        <div className="mt-2 truncate text-xs font-semibold text-white">
                          {match.subject ||
                            match.filename ||
                            "Related case"}
                        </div>

                        <div className="mt-1 text-[10px] text-slate-500">
                          {match.reasons.slice(0, 2).join(" • ")}
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="mt-4 rounded-lg border border-dashed border-slate-800 p-4 text-[10px] leading-5 text-slate-600">
                    No meaningful cross-case overlap was found.
                  </div>
                )}

                <p className="mt-4 text-[9px] leading-5 text-slate-600">
                  Shared IPs, domains, URLs or other observables are correlation
                  signals; they do not establish that the same actor created the cases.
                </p>
              </section>

              <section className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-5">
                <div className="text-[9px] uppercase tracking-[0.17em] text-amber-300/70">
                  Forensic note
                </div>

                <p className="mt-2 text-[10px] leading-5 text-slate-500">
                  Infrastructure geolocation describes network infrastructure.
                  It is not evidence of a sender&apos;s physical location.
                </p>
              </section>
            </aside>
          </div>
        </div>
      </section>
    </main>
  );
}

export default function ThreatGraphPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#080c14]" />}>
      <ThreatGraphContent />
    </Suspense>
  );
}
