"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const navigation: Array<[string, string, string]> = [
  ["Dashboard", "/", "▦"],
  ["Investigation", "/investigations", "⌕"],
  ["Threat Graph", "/threat-graph", "◇"],
  ["Geolocation", "/threat-intelligence", "◈"],
  ["AI Help", "/ai-investigator", "✦"],
  ["Reports", "/reports", "▤"],
  ["Help", "/help", "?"],
];

type CaseRecord = { case_id: string; subject: string; sender: string; risk_score: number; risk_level: string; classification: string };
type Analysis = {
  investigation?: { case_id?: string };
  email?: { subject?: string; from?: string; date?: string };
  threat_detection?: {
    classification?: string;
    risk_score?: number;
    risk_level?: string;
    confidence?: string;
    summary?: string;
    components?: Record<string, { score?: number; max_score?: number; findings?: string[] }>;
    evidence?: Array<{ id: string; severity: string; title: string; detail: string }>;
  };
  ml_analysis?: { ml_classification?: string; ml_confidence?: number; ml_model?: string };
};

function riskClass(level = "LOW") {
  const value = level.toUpperCase();
  return value === "CRITICAL" ? "text-red-300" : value === "HIGH" ? "text-orange-300" : value === "MEDIUM" ? "text-yellow-300" : "text-emerald-300";
}

export default function ScorecardPage() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const requestedCaseId = new URLSearchParams(window.location.search).get("case_id") || "";
    const loadCases = async () => {
      try {
        const response = await fetch(API_BASE + "/api/investigations?limit=200", { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data?.detail || "Unable to load analyzed emails.");
        const nextCases = data.cases || [];
        setCases(nextCases);
        setSelectedId((current) => current || requestedCaseId || nextCases[0]?.case_id || "");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load analyzed emails.");
      }
    };
    const task = window.setTimeout(() => void loadCases(), 0);
    return () => window.clearTimeout(task);
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    const loadAnalysis = async () => {
      setLoading(true);
      try {
        const response = await fetch(API_BASE + "/api/investigations/" + encodeURIComponent(selectedId) + "/analysis", { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data?.detail || "Unable to load scorecard details.");
        setAnalysis(data.analysis || null);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load scorecard details.");
      } finally {
        setLoading(false);
      }
    };
    void loadAnalysis();
  }, [selectedId]);

  const selectedCase = cases.find((item) => item.case_id === selectedId);
  const detection = analysis?.threat_detection;
  const score = detection?.risk_score ?? selectedCase?.risk_score ?? 0;
  const level = detection?.risk_level ?? selectedCase?.risk_level ?? "LOW";
  const components = Object.entries(detection?.components || {});

  return (
    <main className="min-h-screen bg-[#070b12] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0a101a]">
        <div className="border-b border-slate-800 px-6 py-7"><div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div><div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div></div>
        <nav className="flex-1 space-y-1 px-3 py-6">{navigation.map(([name, path, icon]) => <Link key={name} href={path} className={"flex items-center gap-3 rounded-lg px-3 py-3 text-sm " + (name === "Dashboard" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white")}><span className="w-5 text-center">{icon}</span>{name}</Link>)}</nav>
        <div className="border-t border-slate-800 p-4"><div className="rounded-xl border border-slate-800 bg-[#0d1420] px-4 py-3"><p className="text-sm font-semibold">Analyst</p><p className="mt-1 text-xs text-slate-500">Security Operations</p></div></div>
      </aside>

      <section className="ml-64 min-h-screen p-8"><div className="mx-auto max-w-7xl">
        <header className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-800 pb-6"><div><p className="text-xs uppercase tracking-[0.22em] text-blue-400">Email analysis details</p><h1 className="mt-2 text-3xl font-bold">Score Card</h1><p className="mt-2 text-sm text-slate-500">Detailed risk scoring for every analyzed email.</p></div><Link href={selectedId ? "/investigations?case_id=" + encodeURIComponent(selectedId) : "/investigations"} className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white">Investigation detail →</Link></header>
        {error && <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}
        <section className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-5"><label className="text-xs uppercase tracking-[0.16em] text-slate-500">Analyzed email</label><select value={selectedId} onChange={(event) => setSelectedId(event.target.value)} className="mt-3 w-full rounded-lg border border-slate-700 bg-[#0a111c] px-4 py-3 text-sm text-white outline-none focus:border-blue-500">{cases.map((item) => <option key={item.case_id} value={item.case_id}>{item.subject || item.case_id} · {item.case_id}</option>)}</select></section>
        {loading ? <div className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-sm text-slate-500">Loading scorecard details...</div> : analysis && <><section className="mt-6 grid gap-4 md:grid-cols-4"><div className="rounded-2xl border border-blue-500/30 bg-blue-500/10 p-5"><p className="text-xs uppercase text-blue-300">Risk score</p><p className={"mt-2 text-4xl font-bold " + riskClass(level)}>{score}<span className="text-lg text-slate-500">/100</span></p></div><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Risk level</p><p className={"mt-2 text-2xl font-bold " + riskClass(level)}>{level}</p></div><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Classification</p><p className="mt-2 text-2xl font-bold">{detection?.classification || selectedCase?.classification || "UNKNOWN"}</p></div><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Confidence</p><p className="mt-2 text-2xl font-bold">{detection?.confidence || "—"}</p></div></section>
          <section className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]"><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Score components</p><h2 className="mt-1 text-xl font-semibold">Why this score was assigned</h2><p className="mt-2 text-sm text-slate-500">{detection?.summary || "The score is calculated from the stored forensic analysis."}</p><div className="mt-6 space-y-4">{components.map(([name, item]) => <div key={name} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4"><div className="flex justify-between gap-4 text-sm"><span className="capitalize text-slate-200">{name.replaceAll("_", " ")}</span><span className="font-semibold text-blue-300">{item.score || 0}/{item.max_score || 0}</span></div><div className="mt-2 h-2 rounded-full bg-slate-800"><div className="h-2 rounded-full bg-blue-500" style={{ width: ((item.max_score ? (item.score || 0) / item.max_score : 0) * 100) + "%" }} /></div>{item.findings?.length ? <ul className="mt-3 space-y-1 text-xs text-slate-500">{item.findings.map((finding) => <li key={finding}>• {finding}</li>)}</ul> : null}</div>)}</div></div>
            <div className="space-y-6"><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Message</p><h2 className="mt-2 text-lg font-semibold">{analysis.email?.subject || selectedCase?.subject || "Analyzed email"}</h2><p className="mt-3 text-xs text-slate-500">{analysis.email?.from || selectedCase?.sender || "Unknown sender"}</p><p className="mt-2 text-xs text-slate-600">{analysis.email?.date || ""}</p></div><div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Evidence findings</p><div className="mt-4 space-y-3">{detection?.evidence?.length ? detection.evidence.map((item) => <div key={item.id} className="rounded-lg border border-orange-400/20 bg-orange-500/5 p-3"><p className="text-xs font-semibold text-orange-300">{item.severity} · {item.title}</p><p className="mt-1 text-xs text-slate-400">{item.detail}</p></div>) : <p className="text-sm text-slate-500">No high-severity findings were recorded.</p>}</div></div></div></section>
          <section className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Email-specific analysis</p><div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Link href={"/threat-graph?case_id=" + encodeURIComponent(selectedId)} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 hover:border-blue-500/50"><p className="font-semibold">Threat Graph</p><p className="mt-2 text-xs text-slate-500">Explore related indicators.</p></Link><Link href={"/threat-intelligence?case_id=" + encodeURIComponent(selectedId)} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 hover:border-blue-500/50"><p className="font-semibold">Geolocation</p><p className="mt-2 text-xs text-slate-500">Inspect IP and domain locations.</p></Link><Link href={"/ai-investigator?case_id=" + encodeURIComponent(selectedId)} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 hover:border-blue-500/50"><p className="font-semibold">AI Help</p><p className="mt-2 text-xs text-slate-500">Ask why this email is risky.</p></Link><Link href={"/reports?case_id=" + encodeURIComponent(selectedId)} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 hover:border-blue-500/50"><p className="font-semibold">Report</p><p className="mt-2 text-xs text-slate-500">Open the forensic report.</p></Link></div></section>
        </>}
      </div></section>
    </main>
  );
}
