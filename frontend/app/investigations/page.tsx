"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
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
  sender_domain: string;
  reply_to_domain: string;
  return_path_domain: string;
  message_id: string;
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

type SharedIndicator = {
  type: string;
  values: string[];
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
  shared_indicators: SharedIndicator[];
  reasons: string[];
};

type CorrelationResponse = {
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
};

type InvestigationsResponse = {
  status: string;
  count: number;
  cases: CaseRecord[];
};

const navItems = [
  { name: "Dashboard", path: "/", icon: "▦" },
  { name: "Analyze Email", path: "/analyze", icon: "✉" },
  { name: "Investigations", path: "/investigations", icon: "⌕" },
  { name: "Threat Graph", path: "/threat-graph", icon: "◇" },
  { name: "Threat Intelligence", path: "/threat-intelligence", icon: "◈" },
  { name: "AI Investigator", path: "/ai-investigator", icon: "✦" },
  { name: "Reports", path: "/reports", icon: "▤" },
  { name: "Settings", path: "/settings", icon: "⚙" },
];

function display(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function formatDate(value: string) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value || "—";
  }
}

function riskClass(level?: string) {
  const value = (level || "LOW").toUpperCase();
  if (value === "CRITICAL") return "border-red-500/30 bg-red-500/10 text-red-300";
  if (value === "HIGH") return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  if (value === "MEDIUM") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

function classBadge(value?: string) {
  const normalized = (value || "UNKNOWN").toUpperCase();
  if (normalized === "MALWARE") return "border-red-500/30 bg-red-500/10 text-red-300";
  if (normalized === "BEC") return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  if (normalized === "PHISHING") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  if (normalized === "IMPERSONATION") return "border-purple-500/30 bg-purple-500/10 text-purple-300";
  if (normalized === "SUSPICIOUS") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

function matchClass(score: number) {
  if (score >= 70) return "border-red-500/30 bg-red-500/10 text-red-300";
  if (score >= 40) return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-slate-700 bg-slate-900 text-slate-300";
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

export default function InvestigationsPage() {
  const router = useRouter();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [classFilter, setClassFilter] = useState("ALL");
  const [selectedId, setSelectedId] = useState("");
  const [correlation, setCorrelation] = useState<CorrelationResponse | null>(null);
  const [correlationLoading, setCorrelationLoading] = useState(false);
  const maskingEnabled = useMaskingPreference();

  const loadCases = useCallback(async (preferredCaseId = "") => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/api/investigations?limit=200`, {
        cache: "no-store",
      });

      const data = (await response.json()) as InvestigationsResponse & { detail?: string };

      if (!response.ok) {
        throw new Error(data.detail || "Unable to load investigations.");
      }

      const loadedCases = Array.isArray(data.cases) ? data.cases : [];
      setCases(loadedCases);

      if (loadedCases.length) {
        const preferred = preferredCaseId
          ? loadedCases.find((item) => item.case_id === preferredCaseId)
          : null;

        setSelectedId(
          preferred?.case_id ||
            loadedCases[0].case_id
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect to MailTrace backend.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const preferredCaseId = params.get("case_id") || "";

    void Promise.resolve().then(() => loadCases(preferredCaseId));
  }, [loadCases]);

  const filteredCases = useMemo(() => {
    const query = search.trim().toLowerCase();

    return cases.filter((item) => {
      const riskMatch = riskFilter === "ALL" || item.risk_level === riskFilter;
      const classificationMatch = classFilter === "ALL" || item.classification === classFilter;

      const searchMatch =
        !query ||
        item.evidence_id.toLowerCase().includes(query) ||
        item.subject.toLowerCase().includes(query) ||
        item.sender.toLowerCase().includes(query) ||
        item.filename.toLowerCase().includes(query) ||
        item.sender_domain.toLowerCase().includes(query) ||
        item.ips.some((ip) => ip.toLowerCase().includes(query)) ||
        item.domains.some((domain) => domain.toLowerCase().includes(query));

      return riskMatch && classificationMatch && searchMatch;
    });
  }, [cases, search, riskFilter, classFilter]);

  const selectedCase = useMemo(
    () => cases.find((item) => item.case_id === selectedId) || filteredCases[0] || null,
    [cases, selectedId, filteredCases]
  );

  const loadCorrelation = useCallback(async (caseId: string) => {
    setCorrelationLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/api/correlation/${encodeURIComponent(caseId)}`, {
        cache: "no-store",
      });

      const data = (await response.json()) as CorrelationResponse & { detail?: string };

      if (!response.ok) {
        throw new Error(data.detail || "Unable to load correlation data.");
      }

      setCorrelation(data);
    } catch (err) {
      setCorrelation(null);
      setError(err instanceof Error ? err.message : "Unable to load correlation data.");
    } finally {
      setCorrelationLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedCase?.case_id) {
      void Promise.resolve().then(() => loadCorrelation(selectedCase.case_id));
    }
  }, [selectedCase?.case_id, loadCorrelation]);

  const stats = useMemo(() => {
    const highRisk = cases.filter((item) => item.risk_level === "HIGH" || item.risk_level === "CRITICAL").length;
    const suspicious = cases.filter((item) => item.classification && item.classification !== "LEGITIMATE").length;
    const linked = cases.filter((item) => item.ips.length || item.urls.length || item.domains.length).length;

    return {
      total: cases.length,
      highRisk,
      suspicious,
      linked,
    };
  }, [cases]);

  const navigate = (path: string) => {
    if (path !== "#") router.push(path);
  };

  const analysisHref = selectedCase?.case_id
    ? `/analyze?case_id=${encodeURIComponent(selectedCase.case_id)}`
    : "/analyze";

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>

        <nav className="flex-1 px-3 py-5">
          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Investigation</div>
          <div className="space-y-1">
            {navItems.map((item) => {
              const active = item.name === "Investigations";
              return (
                <button
                  key={item.name}
                  onClick={() => navigate(item.path)}
                  disabled={item.path === "#"}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${
                    active ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white"
                  } disabled:cursor-default disabled:opacity-50`}
                >
                  <span className="w-5 text-center">{item.icon}</span>
                  <span>{item.name}</span>
                </button>
              );
            })}
          </div>
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
              <div className="text-xs uppercase tracking-[0.18em] text-blue-400">Case Management</div>
              <h1 className="mt-1 text-2xl font-bold">Investigations</h1>
              <p className="mt-1 text-sm text-slate-500">Review stored email cases and inspect observable cross-case relationships.</p>
            </div>
            <div className="flex flex-wrap gap-3">
              <button onClick={() => void loadCases()} disabled={loading} className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white disabled:opacity-60">
                {loading ? "Refreshing…" : "Refresh Cases"}
              </button>
              <button onClick={() => router.push("/analyze")} className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500">
                New Investigation →
              </button>
            </div>
          </div>
        </header>

        <div className="space-y-6 p-8">
          <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 px-4 py-3 text-xs leading-5 text-slate-400">
            <span className="font-semibold text-blue-300">Live investigation workspace:</span>{" "}
            every email analyzed through <span className="text-white">Analyze Email</span> is stored
            as a local forensic case and appears here automatically.
          </div>

          <section className="grid gap-4 md:grid-cols-4">
            <StatCard label="Total Cases" value={stats.total} subtitle="Stored local investigations" />
            <StatCard label="High Risk" value={stats.highRisk} subtitle="HIGH + CRITICAL" />
            <StatCard label="Suspicious" value={stats.suspicious} subtitle="Non-legitimate classifications" />
            <StatCard label="Indicator Linked" value={stats.linked} subtitle="Cases with observable IOCs" />
          </section>

          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-300">
              <div className="font-semibold">Investigation Error</div>
              <div className="mt-1 text-red-200/80">{error}</div>
            </div>
          )}

          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <h2 className="text-lg font-semibold">Case Workspace</h2>
                <p className="mt-1 text-sm text-slate-500">Search by case ID, sender, subject, domain or IP.</p>
              </div>
              <div className="flex flex-wrap gap-2">
                {['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((value) => (
                  <button
                    key={value}
                    onClick={() => setRiskFilter(value)}
                    className={`rounded-lg px-3 py-2 text-xs font-semibold ${riskFilter === value ? 'bg-blue-600 text-white' : 'border border-slate-700 bg-slate-900 text-slate-400 hover:text-white'}`}
                  >
                    {value}
                  </button>
                ))}
              </div>
            </div>

            <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_220px]">
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search investigations…"
                className="w-full rounded-lg border border-slate-800 bg-[#0a111c] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-blue-500/50"
              />
              <select
                value={classFilter}
                onChange={(event) => setClassFilter(event.target.value)}
                className="rounded-lg border border-slate-800 bg-[#0a111c] px-4 py-3 text-sm text-slate-300 outline-none focus:border-blue-500/50"
              >
                <option value="ALL">All classifications</option>
                <option value="LEGITIMATE">LEGITIMATE</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="PHISHING">PHISHING</option>
                <option value="BEC">BEC</option>
                <option value="IMPERSONATION">IMPERSONATION</option>
                <option value="MALWARE">MALWARE</option>
              </select>
            </div>
          </section>

          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(380px,0.8fr)]">
            <section className="space-y-3">
              {loading ? (
                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-center text-sm text-slate-500">Loading investigations…</div>
              ) : !filteredCases.length ? (
                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-center">
                  <p className="font-semibold">No investigations found</p>
                  <p className="mt-1 text-sm text-slate-500">Analyze an email to create your first local forensic case.</p>
                  <button onClick={() => router.push('/analyze')} className="mt-5 rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold hover:bg-blue-500">Analyze Email →</button>
                </div>
              ) : (
                filteredCases.map((item) => {
                  const selected = selectedCase?.case_id === item.case_id;
                  return (
                    <button
                      key={item.case_id}
                      onClick={() => setSelectedId(item.case_id)}
                      className={`w-full rounded-xl border p-5 text-left transition ${selected ? 'border-blue-500/50 bg-blue-500/5' : 'border-slate-800 bg-[#0d1420] hover:border-slate-700'}`}
                    >
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-xs text-blue-300">{item.evidence_id}</span>
                            <span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${riskClass(item.risk_level)}`}>{item.risk_level}</span>
                            <span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${classBadge(item.classification)}`}>{display(item.classification, 'UNKNOWN')}</span>
                          </div>
                          <h3 className="mt-3 truncate font-semibold text-white">{display(item.subject, item.filename || 'Untitled Email')}</h3>
                          <p className="mt-1 truncate text-sm text-slate-400">{maskSensitiveValue(display(item.sender, 'Unknown sender'), maskingEnabled, 'email')}</p>
                          <p className="mt-2 text-xs text-slate-500">{formatDate(item.created_at)}</p>
                        </div>

                        <div className="grid grid-cols-3 gap-3 text-center text-xs lg:min-w-[300px]">
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="text-xl font-bold text-white">{item.risk_score}</div><div className="mt-1 text-slate-500">Risk</div></div>
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="text-xl font-bold text-white">{item.ips.length}</div><div className="mt-1 text-slate-500">IPs</div></div>
                          <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="text-xl font-bold text-white">{item.domains.length}</div><div className="mt-1 text-slate-500">Domains</div></div>
                        </div>
                      </div>
                    </button>
                  );
                })
              )}
            </section>

            <aside className="h-fit rounded-2xl border border-slate-800 bg-[#0d1420] p-6 xl:sticky xl:top-28">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs uppercase tracking-[0.18em] text-blue-400">Case Inspector</div>
                  <h2 className="mt-1 text-lg font-semibold">Investigation Details</h2>
                </div>
                {selectedCase && (
                  <a
                    href={analysisHref}
                    className="inline-flex items-center justify-center rounded-lg border border-slate-700 px-3 py-2 text-[11px] text-slate-400 hover:text-white"
                  >
                    Open Analysis
                  </a>
                )}
              </div>

              {!selectedCase ? (
                <p className="mt-6 text-sm text-slate-500">Select an investigation.</p>
              ) : (
                <div className="mt-5 space-y-5">
                  <div>
                    <div className="font-mono text-sm text-white">{selectedCase.evidence_id}</div>
                    <div className="mt-2 break-all text-xs text-slate-500">SHA-256: {display(selectedCase.sha256)}</div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="text-[11px] text-slate-500">Risk</div><div className="mt-1 text-sm font-semibold text-white">{selectedCase.risk_score}/100</div></div>
                    <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="text-[11px] text-slate-500">Confidence</div><div className="mt-1 text-sm font-semibold text-white">{display(selectedCase.confidence)}</div></div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4">
                    <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Message</div>
                    <div className="mt-3 space-y-2 text-sm">
                      <div className="flex justify-between gap-4"><span className="text-slate-500">Subject</span><span className="max-w-[220px] text-right text-slate-300">{display(selectedCase.subject)}</span></div>
                      <div className="flex justify-between gap-4"><span className="text-slate-500">From</span><span className="max-w-[220px] break-all text-right text-slate-300">{display(selectedCase.sender)}</span></div>
                      <div className="flex justify-between gap-4"><span className="text-slate-500">Recipient</span><span className="max-w-[220px] break-all text-right text-slate-300">{display(selectedCase.recipient)}</span></div>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4">
                    <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Observable Indicators</div>
                    <div className="mt-3 space-y-3 text-xs">
                      <div><div className="text-slate-500">IPs</div><div className="mt-1 break-all text-slate-300">{selectedCase.ips.length ? selectedCase.ips.map((ip) => maskSensitiveValue(ip, maskingEnabled, 'ip')).join(', ') : 'None'}</div></div>
                      <div><div className="text-slate-500">Domains</div><div className="mt-1 break-all text-slate-300">{selectedCase.domains.length ? selectedCase.domains.join(', ') : 'None'}</div></div>
                      <div><div className="text-slate-500">URLs</div><div className="mt-1 break-all text-slate-300">{selectedCase.urls.length ? selectedCase.urls.join(', ') : 'None'}</div></div>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0a111c] p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Cross-Case Correlation</div>
                      {correlationLoading && <span className="text-[10px] text-blue-400">Checking…</span>}
                    </div>

                    {correlationLoading ? (
                      <p className="mt-4 text-sm text-slate-500">Comparing observable indicators with previous investigations…</p>
                    ) : correlation?.correlation.related_case_count ? (
                      <div className="mt-4 space-y-3">
                        <div className="flex items-center justify-between"><span className="text-xs text-slate-500">Related cases</span><span className="text-sm font-semibold text-white">{correlation.correlation.related_case_count}</span></div>
                        <div className="flex items-center justify-between"><span className="text-xs text-slate-500">Best match</span><span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${matchClass(correlation.correlation.best_match_score)}`}>{correlation.correlation.best_match_score}/100</span></div>
                        <div className="space-y-2">
                          {correlation.correlation.related_cases.slice(0, 3).map((match) => (
                            <button key={match.case_id} onClick={() => setSelectedId(match.case_id)} className="w-full rounded-lg border border-slate-800 bg-slate-900/70 p-3 text-left hover:border-slate-700">
                              <div className="flex items-center justify-between gap-3"><span className="font-mono text-[11px] text-blue-300">{match.evidence_id}</span><span className={`rounded-full border px-2 py-1 text-[10px] font-semibold ${matchClass(match.similarity_score)}`}>{match.similarity_score}/100</span></div>
                              <div className="mt-2 truncate text-xs text-slate-300">{display(match.subject, match.filename)}</div>
                              <div className="mt-1 text-[11px] text-slate-500">{match.reasons.join(' • ')}</div>
                            </button>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4">
                        <p className="text-sm text-slate-400">No meaningful cross-case overlap found.</p>
                        <p className="mt-2 text-[11px] leading-5 text-slate-500">Correlation uses shared observable indicators. It is not proof that cases were created by the same actor.</p>
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <button onClick={() => router.push(selectedId ? `/threat-intelligence?case_id=${encodeURIComponent(selectedId)}` : "/threat-intelligence")} className="rounded-lg border border-slate-700 px-3 py-3 text-xs font-semibold text-slate-300 hover:text-white">Threat Intelligence</button>
                    <button onClick={() => router.push(selectedId ? `/threat-graph?case_id=${encodeURIComponent(selectedId)}` : "/threat-graph")} className="rounded-lg bg-blue-600 px-3 py-3 text-xs font-semibold text-white hover:bg-blue-500">Threat Graph</button>
                    <button onClick={() => router.push(selectedId ? `/ai-investigator?case_id=${encodeURIComponent(selectedId)}` : "/ai-investigator")} className="col-span-2 rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/10 px-3 py-3 text-xs font-semibold text-fuchsia-300 hover:bg-fuchsia-500/15">AI Investigator</button>
                    <button onClick={() => router.push(selectedId ? `/reports?case_id=${encodeURIComponent(selectedId)}` : "/reports")} className="col-span-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-3 text-xs font-semibold text-slate-300 hover:text-white">Forensic Report</button>
                  </div>
                </div>
              )}
            </aside>
          </div>
        </div>
      </section>
    </main>
  );
}
