"use client";

import { FormEvent, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { maskSensitiveValue, useMaskingPreference } from "../lib/masking";

type CaseRecord = {
  case_id: string;
  evidence_id?: string;
  created_at?: string;
  filename?: string;
  subject?: string;
  sender?: string;
  recipient?: string;
  classification?: string;
  risk_score?: number;
  risk_level?: string;
  confidence?: string;
  sha256?: string;
  ips?: string[];
  urls?: string[];
  domains?: string[];
};

type InvestigationsResponse = {
  status: string;
  count: number;
  cases: CaseRecord[];
};

type InvestigatorResponse = {
  status: string;
  mode?: string;
  case_id: string;
  question: string;
  answer: string;
  facts?: string[];
  evidence_refs?: string[];
  related_case_count?: number;
  guardrails?: string[];
};

type Message = {
  role: "user" | "assistant";
  text: string;
  facts?: string[];
  refs?: string[];
};

const API_BASE = "http://127.0.0.1:8000";

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

const quickQuestions = [
  "Why is this email risky?",
  "Show me the observable IOCs.",
  "What do SPF, DKIM and DMARC show?",
  "What is the earliest visible sending infrastructure?",
  "Are there related investigations or campaigns?",
];

function display(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function riskClass(level?: string) {
  const value = (level || "LOW").toUpperCase();
  if (value === "CRITICAL") return "border-red-500/30 bg-red-500/10 text-red-300";
  if (value === "HIGH") return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  if (value === "MEDIUM") return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

function formatDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function AIInvestigatorContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [question, setQuestion] = useState("");
  const [loadingCases, setLoadingCases] = useState(true);
  const [loadingAnswer, setLoadingAnswer] = useState(false);
  const [error, setError] = useState("");
  const maskingEnabled = useMaskingPreference();

  const queryCaseId = searchParams.get("case_id") || "";

  const loadCases = useCallback(async () => {
    setLoadingCases(true);
    setError("");
    try {
      const response = await fetch(`${API_BASE}/api/investigations?limit=200`, { cache: "no-store" });
      const data = (await response.json()) as InvestigationsResponse & { detail?: string };
      if (!response.ok) throw new Error(data.detail || "Unable to load investigations.");
      setCases(data.cases || []);
      const desired = queryCaseId || data.cases?.[0]?.case_id || "";
      setSelectedCaseId(current => current || desired);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load investigations.");
      setCases([]);
    } finally {
      setLoadingCases(false);
    }
  }, [queryCaseId]);

  useEffect(() => {
    void Promise.resolve().then(() => loadCases());
  }, [loadCases]);

  useEffect(() => {
    if (!selectedCaseId) return;
    void Promise.resolve().then(() => {
      setMessages([]);
      try {
        const current = JSON.parse(sessionStorage.getItem("mailtrace_investigator_messages") || "{}") as Record<string, Message[]>;
        if (Array.isArray(current[selectedCaseId])) setMessages(current[selectedCaseId]);
      } catch {
        // Ignore malformed optional UI cache.
      }
    });
  }, [selectedCaseId]);

  const selectedCase = useMemo(
    () => cases.find(item => item.case_id === selectedCaseId) || null,
    [cases, selectedCaseId]
  );

  const setCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    router.replace(`/ai-investigator?case_id=${encodeURIComponent(caseId)}`);
  };

  const askQuestion = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || !selectedCaseId || loadingAnswer) return;

    const userMessage: Message = { role: "user", text: trimmed };
    setMessages(current => [...current, userMessage]);
    setQuestion("");
    setLoadingAnswer(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/api/ai-investigator`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: selectedCaseId, question: trimmed }),
      });
      const data = (await response.json()) as InvestigatorResponse & { detail?: string };
      if (!response.ok) throw new Error(data.detail || "AI Investigator request failed.");

      const assistantMessage: Message = {
        role: "assistant",
        text: data.answer,
        facts: data.facts,
        refs: data.evidence_refs,
      };
      setMessages(current => {
        const next = [...current, assistantMessage];
        try {
          const cache = JSON.parse(sessionStorage.getItem("mailtrace_investigator_messages") || "{}") as Record<string, Message[]>;
          cache[selectedCaseId] = next;
          sessionStorage.setItem("mailtrace_investigator_messages", JSON.stringify(cache));
        } catch {
          // Optional UI cache only.
        }
        return next;
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to contact AI Investigator.";
      setError(message);
    } finally {
      setLoadingAnswer(false);
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await askQuestion(question);
  };

  const goToCase = (path: string) => {
    if (!selectedCaseId) {
      router.push(path);
      return;
    }
    router.push(`${path}?case_id=${encodeURIComponent(selectedCaseId)}`);
  };

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>
        <nav className="flex-1 px-3 py-5">
          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Workspace</div>
          <div className="space-y-1">
            {navItems.map(item => {
              const active = item.name === "AI Investigator";
              return (
                <button
                  key={item.name}
                  onClick={() => item.path !== "#" && router.push(item.path)}
                  disabled={item.path === "#"}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${active ? "bg-blue-600/15 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white"} disabled:cursor-default disabled:opacity-50`}
                >
                  <span className="w-5 text-center">{item.icon}</span>
                  {item.name}
                </button>
              );
            })}
          </div>
        </nav>
        <div className="border-t border-slate-800 px-5 py-4 text-[10px] leading-5 text-slate-600">
          AI Investigator grounds answers in stored case evidence and observable indicators.
        </div>
      </aside>

      <section className="ml-64 min-h-screen px-8 py-8">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="text-xs uppercase tracking-[0.2em] text-blue-400">Forensic reasoning</div>
              <h1 className="mt-2 text-3xl font-bold">AI Investigator</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                Ask evidence-grounded questions about a stored investigation, its indicators, authentication, relay path and cross-case relationships.
              </p>
            </div>
            <div className="flex gap-2">
              <button onClick={() => goToCase("/investigations")} disabled={!selectedCaseId} className="rounded-lg border border-slate-700 px-4 py-2.5 text-xs font-semibold text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40">Investigation</button>
              <button onClick={() => goToCase("/threat-graph")} disabled={!selectedCaseId} className="rounded-lg bg-blue-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-40">Threat Graph</button>
            </div>
          </div>

          {error && <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}

          <div className="mt-6 grid gap-6 lg:grid-cols-[300px_minmax(0,1fr)]">
            <aside className="rounded-2xl border border-slate-800 bg-[#0d1420] p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Case</p>
                  <p className="mt-1 text-sm font-semibold text-white">Select investigation</p>
                </div>
                <span className="rounded-full border border-slate-700 px-2 py-1 text-[10px] text-slate-500">{cases.length}</span>
              </div>

              {loadingCases ? (
                <div className="mt-5 space-y-2">{[1, 2, 3].map(n => <div key={n} className="h-20 animate-pulse rounded-xl bg-slate-800/60" />)}</div>
              ) : cases.length === 0 ? (
                <div className="mt-5 rounded-xl border border-dashed border-slate-700 p-5 text-center">
                  <p className="text-sm text-slate-400">No investigations stored.</p>
                  <button onClick={() => router.push("/analyze")} className="mt-4 rounded-lg bg-blue-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-500">Analyze Email →</button>
                </div>
              ) : (
                <div className="mt-4 space-y-2">
                  {cases.map(item => {
                    const active = item.case_id === selectedCaseId;
                    return (
                      <button key={item.case_id} onClick={() => setCase(item.case_id)} className={`w-full rounded-xl border p-3 text-left transition ${active ? "border-blue-500/50 bg-blue-500/10" : "border-slate-800 bg-slate-900/40 hover:border-slate-700"}`}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[10px] text-blue-300">{item.case_id}</span>
                          <span className={`rounded-full border px-2 py-1 text-[9px] font-semibold ${riskClass(item.risk_level)}`}>{display(item.risk_level, "LOW")}</span>
                        </div>
                        <p className="mt-2 truncate text-xs font-medium text-slate-200">{display(item.subject, item.filename || "Untitled email")}</p>
                        <p className="mt-1 text-[10px] text-slate-600">{formatDate(item.created_at)}</p>
                      </button>
                    );
                  })}
                </div>
              )}
            </aside>

            <section className="min-w-0">
              {!selectedCase ? (
                <div className="rounded-2xl border border-dashed border-slate-700 bg-[#0d1420] p-10 text-center">
                  <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-500/10 text-2xl">✦</div>
                  <h2 className="mt-5 text-xl font-semibold">Choose a stored investigation</h2>
                  <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-slate-500">AI Investigator uses the selected case as its evidence context.</p>
                </div>
              ) : (
                <>
                  <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs text-blue-300">{selectedCase.case_id}</span>
                          <span className={`rounded-full border px-2 py-1 text-[9px] font-semibold ${riskClass(selectedCase.risk_level)}`}>{display(selectedCase.risk_level, "LOW")}</span>
                        </div>
                        <h2 className="mt-3 truncate text-lg font-bold text-white">{display(selectedCase.subject, selectedCase.filename || "Untitled email")}</h2>
                        <p className="mt-1 truncate text-xs text-slate-500">{maskSensitiveValue(display(selectedCase.sender), maskingEnabled, "email")} → {maskSensitiveValue(display(selectedCase.recipient), maskingEnabled, "email")}</p>
                      </div>
                      <div className="grid grid-cols-3 gap-3 text-center">
                        <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-3"><p className="text-[9px] uppercase tracking-wider text-slate-600">Risk</p><p className="mt-1 text-lg font-bold text-white">{display(selectedCase.risk_score, "—")}</p></div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-3"><p className="text-[9px] uppercase tracking-wider text-slate-600">IPs</p><p className="mt-1 text-lg font-bold text-white">{selectedCase.ips?.length || 0}</p></div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-3"><p className="text-[9px] uppercase tracking-wider text-slate-600">Related</p><p className="mt-1 text-lg font-bold text-white">{cases.length > 1 ? "↗" : "—"}</p></div>
                      </div>
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {quickQuestions.map(item => (
                        <button key={item} onClick={() => void askQuestion(item)} disabled={loadingAnswer} className="rounded-full border border-slate-700 bg-slate-900/40 px-3 py-2 text-[10px] text-slate-400 hover:border-blue-500/40 hover:text-blue-300 disabled:opacity-50">{item}</button>
                      ))}
                    </div>
                  </div>

                  <div className="mt-5 rounded-2xl border border-slate-800 bg-[#0d1420]">
                    <div className="max-h-[520px] min-h-[320px] overflow-y-auto p-5">
                      {messages.length === 0 ? (
                        <div className="flex min-h-[290px] items-center justify-center text-center">
                          <div>
                            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-500/10 text-2xl">✦</div>
                            <h3 className="mt-4 font-semibold">Ask about this case</h3>
                            <p className="mt-2 max-w-md text-sm leading-6 text-slate-500">Questions are answered from the stored forensic analysis, not from an unrelated generic chat context.</p>
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-5">
                          {messages.map((message, index) => (
                            <div key={`${message.role}-${index}`} className={message.role === "user" ? "ml-auto max-w-2xl" : "mr-auto max-w-3xl"}>
                              <div className={`rounded-2xl border px-4 py-3 ${message.role === "user" ? "border-blue-500/20 bg-blue-500/10" : "border-slate-800 bg-slate-900/50"}`}>
                                <div className="mb-2 text-[9px] uppercase tracking-[0.16em] text-slate-600">{message.role === "user" ? "You" : "AI Investigator"}</div>
                                <p className="whitespace-pre-line text-sm leading-6 text-slate-300">{message.text}</p>
                                {message.facts?.length ? <div className="mt-3 space-y-1">{message.facts.slice(0, 8).map((fact, factIndex) => <div key={factIndex} className="rounded-md border border-slate-800 bg-[#0b101a] px-3 py-2 text-[11px] text-slate-500">{fact}</div>)}</div> : null}
                                {message.refs?.length ? <div className="mt-3 text-[10px] text-slate-600">Evidence: {message.refs.join(", ")}</div> : null}
                              </div>
                            </div>
                          ))}
                          {loadingAnswer && <div className="max-w-3xl rounded-2xl border border-slate-800 bg-slate-900/50 px-4 py-4 text-sm text-slate-500">Analyzing stored evidence…</div>}
                        </div>
                      )}
                    </div>

                    <form onSubmit={handleSubmit} className="border-t border-slate-800 p-4">
                      <div className="flex gap-3">
                        <input value={question} onChange={event => setQuestion(event.target.value)} placeholder="Ask a forensic question about this case…" disabled={loadingAnswer} className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-[#0b101a] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-blue-500/60" />
                        <button type="submit" disabled={!question.trim() || loadingAnswer} className="rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-600">Ask →</button>
                      </div>
                      <div className="mt-2 text-[10px] text-slate-600">Answers are evidence-grounded. Infrastructure location is not sender physical location, and correlation is not proof of a common actor.</div>
                    </form>
                  </div>
                </>
              )}
            </section>
          </div>
        </div>
      </section>
    </main>
  );
}

export default function AIInvestigatorPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#080c14]" />}>
      <AIInvestigatorContent />
    </Suspense>
  );
}
