"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { MASKING_EVENT, MASKING_STORAGE_KEY } from "../lib/masking";

const API_BASE = "http://127.0.0.1:8000";

type DatabaseStatus = { engine?: string; case_count?: number; alert_count?: number; audit_event_count?: number };
type Provider = { enabled?: boolean; requires_key?: boolean };
type IntelligenceStatus = { providers?: Record<string, Provider> };
type AiStatus = { status?: string; provider?: string; model?: string };

const nav = [["Dashboard", "/", "▦"], ["Analyze Email", "/analyze", "✉"], ["Investigations", "/investigations", "⌕"], ["Threat Graph", "/threat-graph", "◇"], ["Threat Intelligence", "/threat-intelligence", "◈"], ["AI Investigator", "/ai-investigator", "✦"], ["Reports", "/reports", "▤"], ["Settings", "/settings", "⚙"]];

export default function SettingsPage() {
  const [database, setDatabase] = useState<DatabaseStatus | null>(null);
  const [intel, setIntel] = useState<IntelligenceStatus | null>(null);
  const [ai, setAi] = useState<AiStatus | null>(null);
  const [maskSensitive, setMaskSensitive] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    queueMicrotask(() => setMaskSensitive(window.localStorage.getItem(MASKING_STORAGE_KEY) === "true"));
    const load = async () => {
      try {
        const [dbResponse, intelResponse, aiResponse] = await Promise.all([
          fetch(`${API_BASE}/api/database/status`, { cache: "no-store" }),
          fetch(`${API_BASE}/api/threat-intelligence/status`, { cache: "no-store" }),
          fetch(`${API_BASE}/api/ai-investigator/status`, { cache: "no-store" }),
        ]);
        const db = await dbResponse.json();
        if (!dbResponse.ok) throw new Error(db?.detail || "Database status unavailable.");
        setDatabase(db);
        setIntel(await intelResponse.json());
        setAi(await aiResponse.json());
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load system status.");
      }
    };
    void load();
  }, []);

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6"><div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div><div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div></div>
        <nav className="flex-1 space-y-1 px-3 py-5">{nav.map(([name, path, icon]) => <Link key={name} href={path} className={`flex items-center gap-3 rounded-lg px-3 py-3 text-sm ${name === "Settings" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white"}`}><span className="w-5 text-center">{icon}</span>{name}</Link>)}</nav>
      </aside>
      <section className="ml-64 min-h-screen p-8"><div className="mx-auto max-w-5xl"><p className="text-xs uppercase tracking-[0.2em] text-blue-400">System configuration</p><h1 className="mt-2 text-3xl font-bold">Settings</h1><p className="mt-2 text-sm text-slate-500">Runtime health, provider availability, and local forensic handling preferences.</p>
        {error && <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>}
        <div className="mt-8 grid gap-6 md:grid-cols-2">
          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><h2 className="font-semibold">Backend and Database</h2><div className="mt-5 space-y-4 text-sm"><div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Backend</span><span className={database ? "text-emerald-400" : "text-amber-300"}>{database ? "Connected" : "Unavailable"}</span></div><div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Database</span><span className="text-slate-300">{database?.engine || "SQLite"}</span></div><div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Stored investigations</span><span>{database?.case_count ?? "—"}</span></div><div className="flex justify-between"><span className="text-slate-500">Audit events / alerts</span><span>{database?.audit_event_count ?? "—"} / {database?.alert_count ?? "—"}</span></div></div></section>
          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><h2 className="font-semibold">AI Investigator</h2><div className="mt-5 space-y-3 text-sm"><div className="flex justify-between"><span className="text-slate-500">Mode</span><span className="text-slate-300">{ai?.status || "Unavailable"}</span></div><div className="flex justify-between"><span className="text-slate-500">Provider</span><span className="text-slate-300">{ai?.provider || "Deterministic fallback"}</span></div><div className="flex justify-between"><span className="text-slate-500">Model</span><span className="text-slate-300">{ai?.model || "Local rules"}</span></div></div></section>
          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6 md:col-span-2"><h2 className="font-semibold">Threat Intelligence Providers</h2><div className="mt-5 grid gap-3 sm:grid-cols-2">{Object.entries(intel?.providers || {}).map(([name, provider]) => <div key={name} className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0a111c] p-3 text-sm"><span className="text-slate-300">{name}</span><span className={provider.enabled ? "text-emerald-400" : "text-slate-500"}>{provider.enabled ? "Configured" : provider.requires_key ? "Key required" : "Available"}</span></div>)}</div></section>
          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6 md:col-span-2"><h2 className="font-semibold">Privacy and Retention</h2><label className="mt-5 flex max-w-md items-center justify-between gap-4 text-sm text-slate-300"><span>Mask displayed sensitive fields</span><input type="checkbox" checked={maskSensitive} onChange={(event) => { const next = event.target.checked; setMaskSensitive(next); window.localStorage.setItem(MASKING_STORAGE_KEY, String(next)); window.dispatchEvent(new Event(MASKING_EVENT)); }} /></label><p className="mt-3 text-xs leading-5 text-slate-500">Masking applies to presentation only and does not modify stored forensic evidence. Case IDs, evidence IDs, and SHA-256 values remain visible.</p></section>
        </div>
        <section className="mt-6 rounded-2xl border border-amber-500/20 bg-amber-500/5 p-6"><h2 className="font-semibold text-amber-200">Forensic operating notes</h2><ul className="mt-4 space-y-2 text-sm leading-6 text-slate-400"><li>SQLite is the source of truth; browser storage does not delete investigations.</li><li>Infrastructure location does not prove the sender&apos;s physical location or identity.</li><li>Correlation uses shared observable indicators and is not proof of a common actor.</li><li>Threat intelligence is enrichment, not proof.</li></ul></section>
      </div></section>
    </main>
  );
}
