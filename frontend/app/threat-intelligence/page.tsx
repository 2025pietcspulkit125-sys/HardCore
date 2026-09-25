"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import type { InfrastructurePoint } from "./InfrastructureMap";
import { maskSensitiveValue, useMaskingPreference } from "../lib/masking";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const InfrastructureMap = dynamic(() => import("./InfrastructureMap"), { ssr: false });

type ProviderState = {
  provider?: string;
  enabled?: boolean;
  requires_key?: boolean;
  note?: string;
};

type Finding = {
  severity?: string;
  type?: string;
  detail?: string;
};

type IntelligenceItem = {
  indicator: string;
  type: string;
  scope?: string;
  public?: boolean;
  source?: string;
  observation?: string;
  location_basis?: string;
  observed_in_received?: boolean;
  role?: string;
  trust_level?: string;
  is_sender_origin?: boolean;
  sender_geolocation_eligible?: boolean;
  role_reason?: string;
  reverse_dns?: {
    hostname?: string | null;
    aliases?: string[];
  };
  geolocation?: {
    provider?: string;
    status?: string;
    country?: string | null;
    country_code?: string | null;
    region?: string | null;
    city?: string | null;
    asn?: string | number | null;
    organization?: string | null;
    isp?: string | null;
    network_domain?: string | null;
    timezone?: string | null;
    latitude?: number | null;
    longitude?: number | null;
    accuracy_radius?: number | null;
    continent?: string | null;
    region_code?: string | null;
    postal_code?: string | null;
    connection_type?: string | null;
    network?: string | null;
    lookup_timestamp?: string;
    database_version?: string | null;
    security?: Record<string, boolean | null | undefined>;
    message?: string;
    error?: unknown;
    source_note?: string;
  };
  abuseipdb?: {
    provider?: string;
    status?: string;
    abuse_confidence_score?: number | null;
    total_reports?: number | null;
    last_reported_at?: string | null;
    country_code?: string | null;
    usage_type?: string | null;
    isp?: string | null;
    domain?: string | null;
    hostnames?: string[];
    message?: string;
    error?: unknown;
  };
  virustotal?: {
    provider?: string;
    status?: string;
    reputation?: number | null;
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    total?: number;
    id?: string | null;
    message?: string;
    error?: unknown;
  };
  rdap?: {
    provider?: string;
    status?: string;
    handle?: string | null;
    ldh_name?: string | null;
    port43?: string | null;
    start_address?: string | null;
    end_address?: string | null;
    ip_version?: string | null;
    country?: string | null;
    events?: Record<string, string>;
    nameservers?: string[];
    status_codes?: string[];
    message?: string;
    error?: unknown;
  };
  local_analysis?: {
    url?: string;
    hostname?: string;
    findings?: Finding[];
  };
  infrastructure_classification?: {
    type?: string;
    findings?: Array<{ type?: string; source?: string; evidence?: string; confidence?: string }>;
    note?: string;
  };
  domain_intelligence?: {
    domain?: string;
    registrar?: string | null;
    created?: string | null;
    expires?: string | null;
    age_days?: number | null;
    nameservers?: string[];
    a_records?: string[];
    aaaa_records?: string[];
    mx_records?: string[];
    ns_records?: string[];
    cname?: string | null;
    hosting_provider?: string | null;
    source?: string;
    status?: string;
    dns?: {
      status?: string;
      timestamp?: string;
      a_records?: string[];
      aaaa_records?: string[];
      mx_records?: string[];
      ns_records?: string[];
      cname?: string | null;
      source?: string;
    };
  };
  dns?: {
    status?: string;
    timestamp?: string;
    a_records?: string[];
    aaaa_records?: string[];
    mx_records?: string[];
    ns_records?: string[];
    cname?: string | null;
    source?: string;
    note?: string;
  };
  findings?: Finding[];
  forensic_note?: string;
  safety_note?: string;
  transport?: Array<{
    header_name?: string;
    hop?: number;
    header_position?: number;
    raw_header?: string;
    source_hostname?: string | null;
    destination_hostname?: string | null;
    destination_ip?: string | null;
    timestamp?: string | null;
    protocol?: string | null;
    esmtp?: boolean;
    tls?: boolean;
    trust_level?: string;
  }>;
};

type ThreatIntelResponse = {
  status: string;
  evidence_id?: string;
  requested_indicators?: {
    ips?: string[];
    domains?: string[];
    urls?: string[];
  };
  summary?: {
    ip_count?: number;
    domain_count?: number;
    url_count?: number;
    high_findings?: number;
    medium_findings?: number;
    info_findings?: number;
    external_provider_enrichment?: boolean;
  };
  ip_intelligence?: IntelligenceItem[];
  domain_intelligence?: IntelligenceItem[];
  url_intelligence?: IntelligenceItem[];
  providers?: Record<string, ProviderState>;
  limitations?: string[];
  sender_source?: {
    available?: boolean;
    status?: string;
    ip?: string | null;
    role?: string;
    trust_level?: string;
    reason?: string;
    untrusted_metadata_ips?: string[];
    interpretation?: string;
  };
  infrastructure_only?: boolean;
};

type AnalysisResult = {
  status?: string;
  investigation?: {
    case_id?: string;
  };
  evidence?: {
    evidence_id?: string;
    sha256?: string;
  };
  smtp_relay?: Array<{
    header_name?: string;
    hop?: number;
    header_position?: number;
    raw?: string;
    ips?: string[];
    source_hostname?: string | null;
    destination_hostname?: string | null;
    destination_ip?: string | null;
    timestamp?: string | null;
    protocol?: string | null;
    esmtp?: boolean;
    tls?: boolean;
    trust_level?: string;
  }>;
  email?: {
    subject?: string;
    from?: string;
    to?: string;
    reply_to?: string;
    return_path?: string;
    message_id?: string;
    date?: string;
  };
  indicators?: {
    ips?: string[];
    urls?: string[];
  };
  url_analysis?: Array<{
    url?: string;
    hostname?: string;
    findings?: Finding[];
  }>;
  threat_detection?: {
    classification?: string;
    risk_score?: number;
    risk_level?: string;
    confidence?: string;
  };
};

type GeolocationHistory = {
  summary?: {
    observed_emails?: number;
    senders?: number;
    sender_domains?: number;
    recipients?: number;
    cases?: number;
    first_seen?: string | null;
    last_seen?: string | null;
  };
  entries?: Array<{
    case_id?: string;
    evidence_id?: string;
    observed_at?: string;
    subject?: string;
    sender?: string;
    sender_domain?: string;
    classification?: string;
    risk_level?: string;
    risk_score?: number;
    ip?: string;
    hop_numbers?: number[];
  }>;
  limitations?: string[];
};

const sidebarItems = [
  { name: "Dashboard", path: "/", icon: "▦" },
  { name: "Investigation", path: "/investigations", icon: "⌕" },
  { name: "Threat Graph", path: "/threat-graph", icon: "◇" },
  { name: "Geolocation", path: "/threat-intelligence", icon: "◈" },
  { name: "AI Help", path: "/ai-investigator", icon: "✦" },
  { name: "Reports", path: "/reports", icon: "▤" },
  { name: "Help", path: "/help", icon: "?" },
];

function severityClass(severity?: string) {
  const value = (severity || "info").toLowerCase();
  if (value === "high") return "border-red-500/30 bg-red-500/10 text-red-300";
  if (value === "medium") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-slate-700 bg-slate-800/60 text-slate-300";
}

function statusClass(status?: string) {
  const value = (status || "unknown").toLowerCase();
  if (value === "ok" || value === "online") return "text-emerald-400";
  if (value === "not_configured" || value === "skipped") return "text-slate-400";
  return "text-yellow-400";
}

function display(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function ProviderBadge({ label, state }: { label: string; state?: ProviderState }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-slate-200">{label}</span>
        <span className={`text-[11px] font-semibold ${state?.enabled ? "text-emerald-400" : "text-slate-500"}`}>
          {state?.enabled ? "ENABLED" : state?.requires_key ? "KEY REQUIRED" : "AVAILABLE"}
        </span>
      </div>
      <p className="mt-1 text-[11px] text-slate-500">{display(state?.provider, "Provider unavailable")}</p>
    </div>
  );
}

function FindingList({ findings }: { findings?: Finding[] }) {
  if (!findings?.length) {
    return <p className="text-sm text-slate-500">No findings returned for this indicator.</p>;
  }

  return (
    <div className="space-y-2">
      {findings.map((finding, index) => (
        <div key={`${finding.type || "finding"}-${index}`} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${severityClass(finding.severity)}`}>
              {display(finding.severity, "info")}
            </span>
            <span className="text-xs font-medium text-slate-300">{display(finding.type, "indicator")}</span>
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-400">{display(finding.detail)}</p>
        </div>
      ))}
    </div>
  );
}

function StatCard({ label, value, subtitle }: { label: string; value: string | number; subtitle: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#0d1420] p-5">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-3 text-3xl font-bold text-white">{value}</p>
      <p className="mt-2 text-[11px] text-slate-500">{subtitle}</p>
    </div>
  );
}

function IpCard({ item, selected, onSelect }: { item: IntelligenceItem; selected: boolean; onSelect: () => void }) {
  const geo = item.geolocation;
  const abuse = item.abuseipdb;
  const vt = item.virustotal;
  const location = [geo?.city, geo?.region, geo?.country].filter(Boolean).join(", ");
  const asn = geo?.asn ? String(geo.asn).startsWith("AS") ? String(geo.asn) : `AS${geo.asn}` : "—";

  return (
    <button
      onClick={onSelect}
      className={`w-full rounded-xl border p-4 text-left transition ${selected ? "border-blue-500/50 bg-blue-500/5" : "border-slate-800 bg-[#0d1420] hover:border-slate-700"}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm text-white">{item.indicator}</p>
        <p className="mt-1 text-xs text-slate-500">{item.public ? display(item.role, "Public Internet infrastructure IP") : display(item.scope, "IP")}</p>
        </div>
        <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-400">IP</span>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-slate-500">Infrastructure Location</p>
          <p className="mt-1 text-slate-300">{location || "Unavailable"}</p>
        </div>
        <div>
          <p className="text-slate-500">ASN</p>
          <p className="mt-1 text-slate-300">{asn}</p>
        </div>
        <div>
          <p className="text-slate-500">Abuse score</p>
          <p className="mt-1 text-slate-300">{display(abuse?.abuse_confidence_score, "Not configured")}</p>
        </div>
        <div>
          <p className="text-slate-500">VT malicious</p>
          <p className="mt-1 text-slate-300">{display(vt?.malicious, "Not configured")}</p>
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-slate-800 bg-[#0a111c] px-3 py-3">
        <p className="text-[10px] uppercase tracking-[0.14em] text-blue-400">Observed Source</p>
        <p className="mt-1 text-xs text-slate-300">{display(item.role_reason || item.source, "Email headers or content")}</p>
      </div>
    </button>
  );
}

function DomainCard({ item, selected, onSelect }: { item: IntelligenceItem; selected: boolean; onSelect: () => void }) {
  const vt = item.virustotal;
  return (
    <button
      onClick={onSelect}
      className={`w-full rounded-xl border p-4 text-left transition ${selected ? "border-blue-500/50 bg-blue-500/5" : "border-slate-800 bg-[#0d1420] hover:border-slate-700"}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm text-white">{item.indicator}</p>
          <p className="mt-1 text-xs text-slate-500">Domain registration + reputation</p>
        </div>
        <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-400">DOMAIN</span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-slate-500">RDAP</p>
          <p className="mt-1 text-slate-300">{display(item.rdap?.status, "unknown")}</p>
        </div>
        <div>
          <p className="text-slate-500">VT malicious</p>
          <p className="mt-1 text-slate-300">{display(vt?.malicious, "Not configured")}</p>
        </div>
      </div>
    </button>
  );
}

function UrlCard({ item, selected, onSelect }: { item: IntelligenceItem; selected: boolean; onSelect: () => void }) {
  const vt = item.virustotal;
  return (
    <button
      onClick={onSelect}
      className={`w-full rounded-xl border p-4 text-left transition ${selected ? "border-blue-500/50 bg-blue-500/5" : "border-slate-800 bg-[#0d1420] hover:border-slate-700"}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="break-all font-mono text-xs text-white">{item.indicator}</p>
          <p className="mt-1 text-xs text-slate-500">{display(item.local_analysis?.hostname, "URL indicator")}</p>
        </div>
        <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-400">URL</span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-slate-500">Local findings</p>
          <p className="mt-1 text-slate-300">{item.local_analysis?.findings?.length ?? 0}</p>
        </div>
        <div>
          <p className="text-slate-500">VT malicious</p>
          <p className="mt-1 text-slate-300">{display(vt?.malicious, "Not configured")}</p>
        </div>
      </div>
    </button>
  );
}

export default function ThreatIntelligencePage() {
  const router = useRouter();
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [intel, setIntel] = useState<ThreatIntelResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeType, setActiveType] = useState<"ALL" | "IP" | "DOMAIN" | "URL">("ALL");
  const [search, setSearch] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [history, setHistory] = useState<GeolocationHistory | null>(null);
  const maskingEnabled = useMaskingPreference();

  useEffect(() => {
    let cancelled = false;

    const loadAnalysis = async () => {
      try {
        const caseId = new URLSearchParams(window.location.search).get("case_id");
        let parsed: AnalysisResult | null = null;

        if (caseId) {
          const response = await fetch(
            `${API_BASE}/api/investigations/${encodeURIComponent(caseId)}/analysis`,
            { cache: "no-store" }
          );
          const data = await response.json();
          if (!response.ok) throw new Error(data?.detail || "Unable to load this investigation.");
          parsed = data.analysis as AnalysisResult;
        } else {
          const stored = sessionStorage.getItem("mailtrace_analysis");
          if (stored) parsed = JSON.parse(stored) as AnalysisResult;
        }

        if (!cancelled && parsed) setAnalysis(parsed);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "The saved email analysis could not be loaded.");
        }
      } finally {
      }
    };

    void loadAnalysis();

    return () => {
      cancelled = true;
    };
  }, []);

  const runIntelligence = useCallback(async (data: AnalysisResult) => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/api/threat-intelligence`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });

      const result = (await response.json()) as ThreatIntelResponse & { detail?: string };

      if (!response.ok) {
        throw new Error(result.detail || "Threat intelligence lookup failed.");
      }

      setIntel(result);

      const firstIp = result.ip_intelligence?.[0];
      const firstDomain = result.domain_intelligence?.[0];
      const firstUrl = result.url_intelligence?.[0];
      const first = firstIp || firstDomain || firstUrl;

      if (first) {
        setSelectedKey(`${first.type}:${first.indicator}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect to the Threat Intelligence service.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (analysis) {
      void Promise.resolve().then(() => runIntelligence(analysis));
    }
  }, [analysis, runIntelligence]);

  useEffect(() => {
    const sourceIp = intel?.ip_intelligence?.find((item) => item.public)?.indicator;
    if (!sourceIp) {
      return;
    }

    let cancelled = false;
    void fetch(`${API_BASE}/api/geolocation/history?ip=${encodeURIComponent(sourceIp)}`, { cache: "no-store" })
      .then(async (response) => {
        const data = (await response.json()) as GeolocationHistory;
        if (!response.ok) throw new Error("Unable to load IP history.");
        if (!cancelled) setHistory(data);
      })
      .catch(() => {
        if (!cancelled) setHistory(null);
      });

    return () => {
      cancelled = true;
    };
  }, [intel]);

  const allItems = useMemo(() => {
    if (!intel) return [];
    return [
      ...(intel.ip_intelligence || []),
      ...(intel.domain_intelligence || []),
      ...(intel.url_intelligence || []),
    ];
  }, [intel]);

  const filteredItems = useMemo(() => {
    const query = search.trim().toLowerCase();
    return allItems.filter((item) => {
      const typeMatch = activeType === "ALL" || item.type === activeType;
      const searchMatch = !query || item.indicator.toLowerCase().includes(query);
      return typeMatch && searchMatch;
    });
  }, [activeType, allItems, search]);

  const selectedItem = useMemo(() => {
    return allItems.find((item) => `${item.type}:${item.indicator}` === selectedKey) || filteredItems[0] || null;
  }, [allItems, filteredItems, selectedKey]);

  const mapItems = useMemo(
    () => (intel?.ip_intelligence || []).filter((item) => item.geolocation?.latitude != null && item.geolocation?.longitude != null),
    [intel]
  );

  const mapPoints = useMemo<InfrastructurePoint[]>(
    () => mapItems.map((item, index) => ({
      ip: maskSensitiveValue(item.indicator, maskingEnabled, "ip"),
      latitude: item.geolocation?.latitude as number,
      longitude: item.geolocation?.longitude as number,
      country: item.geolocation?.country,
      city: item.geolocation?.city,
      provider: item.geolocation?.organization || item.geolocation?.isp,
      asn: item.geolocation?.asn,
      role: item.role,
      earliest: Boolean(item.observed_in_received && index === 0),
    })),
    [mapItems, maskingEnabled]
  );

  const primaryIp = useMemo(
    () => (intel?.ip_intelligence || []).find((item) => item.public) || intel?.ip_intelligence?.[0] || null,
    [intel]
  );
  const senderSource = intel?.sender_source;
  const routeHops = analysis?.smtp_relay || [];

  const nav = (path: string) => {
    if (path !== "#") router.push(path);
  };

  if (!analysis) {
    return (
      <main className="min-h-screen bg-[#080c14] text-white">
        <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
          <div className="border-b border-slate-800 px-6 py-6">
            <div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
          </div>
          <nav className="flex-1 space-y-1 px-3 py-5">
            {sidebarItems.map((item) => (
              <button
                key={item.name}
                onClick={() => nav(item.path)}
                disabled={item.path === "#"}
                className="mb-1 flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm text-slate-400 hover:bg-white/5 hover:text-white disabled:cursor-default disabled:opacity-60"
              >
                <span className="w-5 text-center">{item.icon}</span>
                {item.name}
              </button>
            ))}
          </nav>
        </aside>
        <section className="ml-64 flex min-h-screen items-center justify-center px-8">
          <div className="max-w-lg rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-500/10 text-2xl">◈</div>
            <h1 className="mt-5 text-2xl font-bold">No active investigation</h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">Analyze an EML or MSG file first. The analysis result is then used to enrich the email&apos;s IPs, domains and URLs.</p>
            <button onClick={() => router.push("/analyze")} className="mt-6 rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold hover:bg-blue-500">Analyze Email →</button>
          </div>
        </section>
      </main>
    );
  }

  const summary = intel?.summary;

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-5">
          {sidebarItems.map((item) => {
            const active = item.name === "Geolocation";
            return (
              <button
                key={item.name}
                onClick={() => nav(item.path)}
                disabled={item.path === "#"}
                className={`mb-1 flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${active ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white"} disabled:cursor-default`}
              >
                <span className={`w-5 text-center ${active ? "text-blue-400" : "text-slate-500"}`}>{item.icon}</span>
                {item.name}
              </button>
            );
          })}
        </nav>
        <div className="border-t border-slate-800 p-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/15 text-xs font-semibold text-blue-400">MT</div>
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">Analyst</div>
                <div className="truncate text-xs text-slate-500">Security Operations</div>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <section className="ml-64 min-h-screen">
        <header className="sticky top-0 z-20 border-b border-slate-800 bg-[#080c14]/95 px-8 py-5 backdrop-blur">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <div className="text-xs uppercase tracking-[0.18em] text-blue-400">Geolocation</div>
              <h1 className="mt-1 text-2xl font-bold">Infrastructure & Indicator Intelligence</h1>
              <p className="mt-1 text-sm text-slate-500">Enrich evidence extracted from the active email investigation.</p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <button onClick={() => router.push(analysis?.investigation?.case_id ? `/investigations?case_id=${encodeURIComponent(analysis.investigation.case_id)}` : "/investigations")} className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-semibold text-slate-300 hover:border-slate-600 hover:text-white">View Forensic Case</button>
              <button onClick={() => router.push(analysis?.investigation?.case_id ? `/threat-graph?case_id=${encodeURIComponent(analysis.investigation.case_id)}` : "/threat-graph")} className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-semibold text-slate-300 hover:border-slate-600 hover:text-white">Threat Graph</button>
              <button onClick={() => analysis && runIntelligence(analysis)} disabled={loading} className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60">{loading ? "Enriching…" : "Refresh Intelligence"}</button>
            </div>
          </div>
        </header>

        <div className="space-y-6 p-8">
          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-blue-300">Active Investigation</span>
                  <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold text-emerald-300">{display(analysis.evidence?.evidence_id, "Evidence ID unavailable")}</span>
                </div>
                <h2 className="mt-4 truncate text-lg font-semibold">{display(analysis.email?.subject, "Untitled email")}</h2>
                <p className="mt-1 truncate text-sm text-slate-400">{display(analysis.email?.from, "Unknown sender")}</p>
                <p className="mt-3 text-xs text-slate-500">Classification: <span className="text-slate-300">{display(analysis.threat_detection?.classification)}</span> · Risk: <span className="text-slate-300">{display(analysis.threat_detection?.risk_score)}/100</span> · Confidence: <span className="text-slate-300">{display(analysis.threat_detection?.confidence)}</span></p>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <StatCard label="IPs" value={summary?.ip_count ?? analysis.indicators?.ips?.length ?? 0} subtitle="Network indicators" />
                <StatCard label="Domains" value={summary?.domain_count ?? 0} subtitle="Sender + URL hosts" />
                <StatCard label="URLs" value={summary?.url_count ?? analysis.indicators?.urls?.length ?? 0} subtitle="Extracted links" />
              </div>
            </div>
          </section>

          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-5 py-4">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 text-amber-300">⚠</div>
              <div>
                <p className="text-sm font-semibold text-amber-200">IP geolocation is infrastructure intelligence</p>
                <p className="mt-1 text-xs leading-5 text-amber-100/70">
                  A location shown for an IP describes the network or mail infrastructure associated with that address. A mail-provider, relay, VPN, proxy, or datacenter IP must not be interpreted as the physical location of the human sender.
                </p>
              </div>
            </div>
          </div>

          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-blue-400">Latest email network intelligence</p>
                <h2 className="mt-2 text-xl font-semibold">{display(analysis.email?.subject, "Untitled email")}</h2>
                <p className="mt-1 text-sm text-slate-400">{display(analysis.email?.from, "Unknown sender")}</p>
                <p className="mt-2 text-xs text-slate-500">Received: {display(analysis.email?.date, "Timestamp unavailable")}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-slate-300">Case: {display(analysis.investigation?.case_id)}</span>
                <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-slate-300">Threat: {display(analysis.threat_detection?.risk_level, "UNKNOWN")}</span>
              </div>
            </div>
            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-amber-500/25 bg-amber-500/5 p-4">
                <div className="flex items-center justify-between gap-3"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-amber-300">Sender source</p><span className="rounded-full border border-amber-500/30 px-2 py-1 text-[10px] font-semibold text-amber-200">NO SENDER IP</span></div>
                <p className="mt-3 text-sm font-semibold text-white">{senderSource?.available ? display(senderSource.ip) : "Unavailable from email transport evidence"}</p>
                <p className="mt-2 text-xs leading-5 text-amber-100/70">{display(senderSource?.reason, "No trustworthy public sender-origin IP was present in the preserved email headers.")}</p>
                {!!senderSource?.untrusted_metadata_ips?.length && <p className="mt-3 text-[11px] text-slate-500">Untrusted X-Originating-IP evidence: <span className="font-mono text-slate-400">{senderSource.untrusted_metadata_ips.join(", ")}</span></p>}
              </div>
              <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/5 p-4">
                <div className="flex items-center justify-between gap-3"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">Mail infrastructure</p><span className="rounded-full border border-cyan-500/30 px-2 py-1 text-[10px] font-semibold text-cyan-200">INFRASTRUCTURE ONLY</span></div>
                <p className="mt-3 text-sm font-semibold text-white">{primaryIp ? maskSensitiveValue(primaryIp.indicator, maskingEnabled, "ip") : "No public infrastructure IP"}</p>
                <p className="mt-1 text-xs text-cyan-100/70">Role: {display(primaryIp?.role, "UNKNOWN")} · {display([primaryIp?.geolocation?.city, primaryIp?.geolocation?.region, primaryIp?.geolocation?.country].filter(Boolean).join(", "), "Location unavailable")}</p>
                <p className="mt-2 text-[11px] text-slate-500">{display(primaryIp?.geolocation?.organization || primaryIp?.geolocation?.isp, "Provider unavailable")} · ASN {display(primaryIp?.geolocation?.asn, "unavailable")}</p>
              </div>
            </div>
            {primaryIp?.geolocation?.status === "ok" && <div className="mt-4 rounded-lg border border-blue-500/20 bg-blue-500/5 p-4 text-xs text-slate-400"><span className="font-semibold text-blue-300">Provider:</span> {display(primaryIp.geolocation.provider)} · <span className="font-semibold text-blue-300">Lookup:</span> {display(primaryIp.geolocation.lookup_timestamp, "Timestamp unavailable")} · <span className="font-semibold text-blue-300">Accuracy:</span> {display(primaryIp.geolocation.accuracy_radius, "Not supplied by provider")}</div>}
          </section>

          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-300">
              <div className="font-semibold">Threat Intelligence Error</div>
              <div className="mt-1 text-red-200/80">{error}</div>
            </div>
          )}

          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold">Infrastructure Location Map</h2>
                <p className="mt-1 text-sm text-slate-500">Observed network locations from available IP intelligence.</p>
              </div>
              <span className="text-[10px] uppercase tracking-[0.14em] text-amber-300">Not sender physical location</span>
            </div>
            {mapItems.length ? (
              <div className="mt-5 grid gap-5 lg:grid-cols-[1.3fr_1fr]">
                <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#09111d]"><InfrastructureMap points={mapPoints} /></div>
                <div className="space-y-2">
                  {mapItems.map((item) => <div key={item.indicator} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs text-white">{item.indicator}</span><span className="text-[10px] text-cyan-300">{display(item.role, "UNKNOWN")}</span></div><p className="mt-2 text-xs text-slate-400">{display([item.geolocation?.city, item.geolocation?.region, item.geolocation?.country].filter(Boolean).join(", "), "Location unavailable")}</p><p className="mt-1 text-[10px] text-slate-600">{display(item.geolocation?.organization || item.geolocation?.isp, "Provider unavailable")} · {display(item.geolocation?.asn, "ASN unavailable")}</p></div>)}
                </div>
              </div>
            ) : <div className="mt-5 rounded-xl border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">No geocoded infrastructure locations are available. The indicator tables below remain available as a fallback.</div>}
            <p className="mt-4 text-xs leading-5 text-amber-200/70">Infrastructure location does not prove the sender&apos;s physical location or identity.</p>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Email route</p><h2 className="mt-1 text-lg font-semibold">Received-header transport chain</h2><p className="mt-1 text-sm text-slate-500">Every hop is shown from preserved headers; a relay location is not treated as the sender&apos;s physical location.</p></div>
              <span className="text-xs text-slate-500">{routeHops.length} hop(s)</span>
            </div>
            {routeHops.length ? <div className="mt-5 space-y-3">{routeHops.map((hop, index) => { const hopIps = hop.ips || []; const enriched = hopIps.map((ip) => intel?.ip_intelligence?.find((item) => item.indicator === ip)).find(Boolean); return <div key={`${hop.hop || index}-${hop.raw || "hop"}`} className="relative rounded-xl border border-slate-800 bg-[#0a111c] p-4"><div className="flex flex-wrap items-center justify-between gap-3"><span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-300">Hop {hop.hop || index + 1}</span><span className="text-[11px] text-slate-500">{display(hop.protocol, "SMTP metadata unavailable")} {hop.tls ? "· TLS" : ""}</span></div><div className="mt-3 grid gap-3 sm:grid-cols-5"><div><p className="text-[11px] text-slate-500">IP</p><p className="mt-1 break-all font-mono text-xs text-white">{hopIps.length ? hopIps.join(", ") : "No IP extracted"}</p></div><div><p className="text-[11px] text-slate-500">Role</p><p className="mt-1 text-xs text-cyan-300">{display(enriched?.role, "UNKNOWN")}</p></div><div><p className="text-[11px] text-slate-500">Infrastructure location</p><p className="mt-1 text-xs text-slate-300">{display([enriched?.geolocation?.city, enriched?.geolocation?.region, enriched?.geolocation?.country].filter(Boolean).join(", "), "Unavailable")}</p></div><div><p className="text-[11px] text-slate-500">Network / ASN</p><p className="mt-1 text-xs text-slate-300">{display(enriched?.geolocation?.organization || enriched?.geolocation?.isp, "UNKNOWN")} · {display(enriched?.geolocation?.asn, "—")}</p></div><div><p className="text-[11px] text-slate-500">Header source</p><p className="mt-1 truncate text-xs text-slate-300">{display(hop.source_hostname, "Received header")}</p></div></div><details className="mt-3"><summary className="cursor-pointer text-[11px] text-blue-300">Show preserved Received header</summary><p className="mt-2 break-all whitespace-pre-wrap text-[11px] text-slate-500">{display(hop.raw)}</p></details></div>; })}</div> : <p className="mt-5 rounded-xl border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">No Received-header route was preserved for this email.</p>}
          </section>

          {loading && (
            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-8">
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 animate-pulse rounded-full bg-blue-500/20" />
                <div>
                  <p className="font-semibold">Enriching investigation indicators…</p>
                  <p className="mt-1 text-sm text-slate-500">Checking available geolocation, RDAP and configured reputation providers.</p>
                </div>
              </div>
            </section>
          )}

          {intel && !loading && (
            <>
              <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                  <div>
                    <h2 className="text-lg font-semibold">Indicator Workspace</h2>
                    <p className="mt-1 text-sm text-slate-500">Select an indicator to inspect its enrichment and forensic findings.</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(["ALL", "IP", "DOMAIN", "URL"] as const).map((type) => (
                      <button
                        key={type}
                        onClick={() => setActiveType(type)}
                        className={`rounded-lg px-3 py-2 text-xs font-semibold ${activeType === type ? "bg-blue-600 text-white" : "border border-slate-700 bg-slate-900 text-slate-400 hover:text-white"}`}
                      >
                        {type}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="mt-4">
                  <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IP, domain or URL…" className="w-full rounded-lg border border-slate-800 bg-[#0a111c] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-blue-500/50" />
                </div>
              </section>

              <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
                <section className="space-y-3">
                  {!filteredItems.length ? (
                    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-center">
                      <p className="font-semibold">No matching indicators</p>
                      <p className="mt-1 text-sm text-slate-500">Try another filter or search value.</p>
                    </div>
                  ) : (
                    filteredItems.map((item) => {
                      const key = `${item.type}:${item.indicator}`;
                      const selected = selectedItem ? `${selectedItem.type}:${selectedItem.indicator}` === key : false;

                      if (item.type === "IP") return <IpCard key={key} item={item} selected={selected} onSelect={() => setSelectedKey(key)} />;
                      if (item.type === "DOMAIN") return <DomainCard key={key} item={item} selected={selected} onSelect={() => setSelectedKey(key)} />;
                      return <UrlCard key={key} item={item} selected={selected} onSelect={() => setSelectedKey(key)} />;
                    })
                  )}
                </section>

                <aside className="h-fit rounded-2xl border border-slate-800 bg-[#0d1420] p-6 xl:sticky xl:top-28">
                  <div className="text-xs uppercase tracking-[0.18em] text-blue-400">Indicator Inspector</div>
                  {selectedItem ? (
                    <>
                      <div className="mt-3 break-all font-mono text-sm text-white">{maskSensitiveValue(selectedItem.indicator, maskingEnabled, selectedItem.type === "IP" ? "ip" : "text")}</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-400">{selectedItem.type}</span>
                        {selectedItem.scope && <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-400">{selectedItem.scope}</span>}
                      </div>

                      {selectedItem.type === "IP" && (
                        <div className="mt-6 space-y-4">
                          <div className="grid grid-cols-2 gap-3">
                            <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-[11px] text-slate-500">Infrastructure Country</p><p className="mt-1 text-sm text-slate-200">{display(selectedItem.geolocation?.country)}</p></div>
                            <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-[11px] text-slate-500">ASN</p><p className="mt-1 text-sm text-slate-200">{display(selectedItem.geolocation?.asn)}</p></div>
                          </div>
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Network</p><div className="mt-3 space-y-2 text-sm"><div className="flex justify-between gap-3"><span className="text-slate-500">Organization</span><span className="text-right text-slate-300">{display(selectedItem.geolocation?.organization)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">ISP</span><span className="text-right text-slate-300">{display(selectedItem.geolocation?.isp)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Reverse DNS</span><span className="text-right text-slate-300">{display(selectedItem.reverse_dns?.hostname)}</span></div></div></div>
                          <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
                            <p className="text-[11px] uppercase tracking-[0.14em] text-blue-400">Forensic Context</p>
                            <div className="mt-3 space-y-2 text-sm">
                              <div className="flex justify-between gap-3"><span className="text-slate-500">Observed Source</span><span className="text-right text-slate-300">{display(selectedItem.source)}</span></div>
                              <div className="flex justify-between gap-3"><span className="text-slate-500">Location Basis</span><span className="text-right text-slate-300">{display(selectedItem.location_basis, "Network infrastructure")}</span></div>
                            </div>
                            <p className="mt-3 text-[11px] leading-5 text-slate-500">{display(selectedItem.observation, "Observed from parsed email evidence.")}</p>
                          </div>

                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Reputation</p><div className="mt-3 space-y-2 text-sm"><div className="flex justify-between"><span className="text-slate-500">AbuseIPDB</span><span className={statusClass(selectedItem.abuseipdb?.status)}>{display(selectedItem.abuseipdb?.status)}</span></div><div className="flex justify-between"><span className="text-slate-500">Abuse score</span><span className="text-slate-300">{display(selectedItem.abuseipdb?.abuse_confidence_score, "Not configured")}</span></div><div className="flex justify-between"><span className="text-slate-500">VirusTotal</span><span className={statusClass(selectedItem.virustotal?.status)}>{display(selectedItem.virustotal?.status)}</span></div><div className="flex justify-between"><span className="text-slate-500">VT malicious</span><span className="text-slate-300">{display(selectedItem.virustotal?.malicious, "Not configured")}</span></div></div></div>
                        </div>
                      )}

                      {selectedItem.type === "DOMAIN" && (
                        <div className="mt-6 space-y-4">
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">RDAP Registration</p><div className="mt-3 space-y-2 text-sm"><div className="flex justify-between gap-3"><span className="text-slate-500">Status</span><span className={statusClass(selectedItem.rdap?.status)}>{display(selectedItem.rdap?.status)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Handle</span><span className="text-right text-slate-300">{display(selectedItem.rdap?.handle)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Created</span><span className="text-right text-slate-300">{display(selectedItem.rdap?.events?.registration)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Updated</span><span className="text-right text-slate-300">{display(selectedItem.rdap?.events?.last_changed)}</span></div></div></div>
                          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-cyan-300">DNS Intelligence</p><div className="mt-3 space-y-2 text-xs"><div><span className="text-slate-500">A Records</span><p className="mt-1 break-all text-slate-300">{selectedItem.dns?.a_records?.join(", ") || "Unavailable"}</p></div><div><span className="text-slate-500">AAAA Records</span><p className="mt-1 break-all text-slate-300">{selectedItem.dns?.aaaa_records?.join(", ") || "Unavailable"}</p></div><div><span className="text-slate-500">MX Records</span><p className="mt-1 break-all text-slate-300">{selectedItem.dns?.mx_records?.join(", ") || "Unavailable"}</p></div><div><span className="text-slate-500">NS Records</span><p className="mt-1 break-all text-slate-300">{selectedItem.dns?.ns_records?.join(", ") || "Unavailable"}</p></div><div><span className="text-slate-500">CNAME Records</span><p className="mt-1 break-all text-slate-300">{selectedItem.dns?.cname || "Unavailable"}</p></div></div><p className="mt-3 text-[10px] text-slate-600">{display(selectedItem.dns?.source, "Configured DNS resolver")} · {display(selectedItem.dns?.status, "unavailable")}</p></div>
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">VirusTotal</p><div className="mt-3 space-y-2 text-sm"><div className="flex justify-between"><span className="text-slate-500">Status</span><span className={statusClass(selectedItem.virustotal?.status)}>{display(selectedItem.virustotal?.status)}</span></div><div className="flex justify-between"><span className="text-slate-500">Malicious</span><span className="text-slate-300">{display(selectedItem.virustotal?.malicious, "Not configured")}</span></div><div className="flex justify-between"><span className="text-slate-500">Suspicious</span><span className="text-slate-300">{display(selectedItem.virustotal?.suspicious, "Not configured")}</span></div></div></div>
                        </div>
                      )}

                      {selectedItem.type === "URL" && (
                        <div className="mt-6 space-y-4">
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">URL Analysis</p><div className="mt-3"><FindingList findings={selectedItem.local_analysis?.findings} /></div></div>
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">VirusTotal</p><div className="mt-3 space-y-2 text-sm"><div className="flex justify-between"><span className="text-slate-500">Status</span><span className={statusClass(selectedItem.virustotal?.status)}>{display(selectedItem.virustotal?.status)}</span></div><div className="flex justify-between"><span className="text-slate-500">Malicious</span><span className="text-slate-300">{display(selectedItem.virustotal?.malicious, "Not configured")}</span></div><div className="flex justify-between"><span className="text-slate-500">Suspicious</span><span className="text-slate-300">{display(selectedItem.virustotal?.suspicious, "Not configured")}</span></div></div></div>
                        </div>
                      )}

                      <div className="mt-4"><FindingList findings={selectedItem.findings} /></div>
                      <p className="mt-4 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-[11px] leading-5 text-slate-500">{display(selectedItem.forensic_note || selectedItem.safety_note, "Provider results are indicators and should be interpreted in context.")}</p>
                    </>
                  ) : (
                    <p className="mt-5 text-sm text-slate-500">Select an indicator to inspect it.</p>
                  )}
                </aside>
              </div>

              <section className="grid gap-6 lg:grid-cols-2">
                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                  <p className="text-xs uppercase tracking-[0.18em] text-blue-400">Related activity</p>
                  <h3 className="mt-1 font-semibold">Historical IP correlation</h3>
                  <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">{[["Emails", history?.summary?.observed_emails ?? 0], ["Senders", history?.summary?.senders ?? 0], ["Domains", history?.summary?.sender_domains ?? 0], ["Recipients", history?.summary?.recipients ?? 0], ["Cases", history?.summary?.cases ?? 0]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-[11px] text-slate-500">{String(label)}</p><p className="mt-1 text-lg font-semibold text-white">{String(value)}</p></div>)}</div>
                  <p className="mt-4 text-xs text-slate-500">IP: <span className="font-mono text-slate-300">{primaryIp ? primaryIp.indicator : "Unavailable"}</span> · First seen: {display(history?.summary?.first_seen, "Unknown")} · Last seen: {display(history?.summary?.last_seen, "Unknown")}</p>
                  {history?.entries?.length ? <div className="mt-4 max-h-52 space-y-2 overflow-auto">{history.entries.slice(0, 8).map((entry) => <button key={entry.case_id} onClick={() => entry.case_id && router.push(`/investigations?case_id=${encodeURIComponent(entry.case_id)}`)} className="w-full rounded-lg border border-slate-800 bg-[#0a111c] p-3 text-left hover:border-blue-500/40"><div className="flex justify-between gap-3 text-xs"><span className="font-mono text-blue-300">{entry.case_id}</span><span className="text-slate-500">{display(entry.observed_at)}</span></div><p className="mt-1 truncate text-xs text-slate-300">{display(entry.subject, "Untitled email")}</p><p className="mt-1 text-[11px] text-slate-500">{display(entry.sender)} · {display(entry.classification)} · {display(entry.risk_level)}</p></button>)}</div> : <p className="mt-4 text-xs text-slate-500">No previous stored email observations for this public IP.</p>}
                </div>
                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                  <p className="text-xs uppercase tracking-[0.18em] text-blue-400">Evidence & provenance</p>
                  <h3 className="mt-1 font-semibold">Why am I seeing this location?</h3>
                  <div className="mt-4 space-y-2 text-xs"><div className="flex justify-between gap-3"><span className="text-slate-500">Email ID</span><span className="text-right text-slate-300">{display(analysis.evidence?.evidence_id)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Message-ID</span><span className="max-w-[65%] break-all text-right text-slate-300">{display(analysis.email?.message_id)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Sender-origin IP</span><span className="text-right font-mono text-slate-300">{display(senderSource?.ip, "Unavailable")}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Infrastructure evidence</span><span className="text-right font-mono text-slate-300">{display(primaryIp?.indicator, "Unavailable")}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Evidence source</span><span className="text-right text-slate-300">{display(primaryIp?.source, "Received header")}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Provider</span><span className="text-right text-slate-300">{display(primaryIp?.geolocation?.provider)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">Lookup timestamp</span><span className="text-right text-slate-300">{display(primaryIp?.geolocation?.lookup_timestamp)}</span></div><div className="flex justify-between gap-3"><span className="text-slate-500">SHA-256</span><span className="max-w-[65%] break-all text-right font-mono text-slate-500">{display(analysis.evidence?.sha256)}</span></div></div>
                  <p className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-[11px] leading-5 text-amber-100/70">IP geolocation identifies the approximate location associated with the IP/network. It does not establish the physical location or identity of the sender.</p>
                </div>
              </section>

              <section className="grid gap-6 lg:grid-cols-2">
                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                  <h3 className="font-semibold">Provider Status</h3>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    <ProviderBadge label="IP Geolocation" state={intel.providers?.ip_geolocation} />
                    <ProviderBadge label="RDAP" state={intel.providers?.rdap} />
                    <ProviderBadge label="AbuseIPDB" state={intel.providers?.abuseipdb} />
                    <ProviderBadge label="VirusTotal" state={intel.providers?.virustotal} />
                  </div>
                  {summary?.external_provider_enrichment ? (
                    <p className="mt-4 text-xs text-emerald-400">External reputation enrichment is enabled for this backend.</p>
                  ) : (
                    <p className="mt-4 text-xs text-slate-500">VirusTotal and AbuseIPDB require server-side API keys. Geolocation and RDAP work without those keys.</p>
                  )}
                </div>

                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                  <h3 className="font-semibold">Findings Summary</h3>
                  <div className="mt-4 grid grid-cols-3 gap-3">
                    <StatCard label="High" value={summary?.high_findings ?? 0} subtitle="High-severity findings" />
                    <StatCard label="Medium" value={summary?.medium_findings ?? 0} subtitle="Medium-severity findings" />
                    <StatCard label="Info" value={summary?.info_findings ?? 0} subtitle="Informational signals" />
                  </div>
                </div>
              </section>

              {intel.limitations?.length ? (
                <section className="rounded-xl border border-slate-800 bg-[#0d1420] p-5">
                  <h3 className="text-sm font-semibold">Forensic interpretation notes</h3>
                  <div className="mt-3 space-y-2 text-xs leading-5 text-slate-500">
                    {intel.limitations.map((note) => <p key={note}>• {note}</p>)}
                  </div>
                </section>
              ) : null}
            </>
          )}
        </div>
      </section>
    </main>
  );
}
