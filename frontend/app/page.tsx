"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { maskSensitiveValue, useMaskingPreference } from "./lib/masking";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type CaseRecord = {
  case_id: string;
  created_at: string;
  subject: string;
  sender: string;
  classification: string;
  risk_score: number;
  risk_level: string;
  ips?: string[];
  urls?: string[];
  domains?: string[];
};
type AlertRecord = { alert_id: string; case_id: string; severity: string; title: string; message: string; created_at: string };
type Summary = {
  total_investigations: number;
  high_risk: number;
  suspicious_cases: number;
  unacknowledged_alerts: number;
  recent_alerts: AlertRecord[];
  risk_distribution: Record<string, number>;
  activity_last_7_days: Array<{ date: string; count: number }>;
  recent_cases: CaseRecord[];
};
type MailboxStatus = {
  ingestion?: {
    state?: string;
    provider?: string;
    provider_status?: { configured?: boolean; connected?: boolean; missing_config?: string[] };
    last_sync_at?: string;
    last_error?: string;
  };
};
type MailboxMessage = { email_id: string; risk_score?: number; risk_level?: string };

const navigation: Array<[string, string, string]> = [
  ["Dashboard", "/", "▦"],
  ["Investigation", "/investigations", "⌕"],
  ["Threat Graph", "/threat-graph", "◇"],
  ["Geolocation", "/threat-intelligence", "◈"],
  ["AI Help", "/ai-investigator", "✦"],
  ["Reports", "/reports", "▤"],
  ["Help", "/help", "?"],
];

function formatDate(value?: string) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function riskClass(level: string) {
  const value = level.toUpperCase();
  if (value === "CRITICAL") return "text-red-300";
  if (value === "HIGH") return "text-orange-300";
  if (value === "MEDIUM") return "text-yellow-300";
  return "text-emerald-300";
}
function riskBadgeClass(level: string) {
  const value = level.toUpperCase();
  if (value === "CRITICAL") return "border-red-400/30 bg-red-500/10 text-red-300";
  if (value === "HIGH") return "border-orange-400/30 bg-orange-500/10 text-orange-300";
  if (value === "MEDIUM") return "border-yellow-400/30 bg-yellow-500/10 text-yellow-300";
  return "border-emerald-400/30 bg-emerald-500/10 text-emerald-300";
}
function barClass(level: string) {
  const value = level.toUpperCase();
  if (value === "CRITICAL") return "bg-red-500";
  if (value === "HIGH") return "bg-orange-500";
  if (value === "MEDIUM") return "bg-yellow-500";
  return "bg-emerald-500";
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [mailbox, setMailbox] = useState<MailboxStatus | null>(null);
  const [mailboxMessages, setMailboxMessages] = useState<MailboxMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [mailboxBusy, setMailboxBusy] = useState(false);
  const [error, setError] = useState("");
  const [mailboxError, setMailboxError] = useState("");
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [openMenuCaseId, setOpenMenuCaseId] = useState<string | null>(null);
  const router = useRouter();
  const maskingEnabled = useMaskingPreference();

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(API_BASE + "/api/dashboard/summary", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || "Unable to load dashboard data.");
      const value = data as Summary;
      setSummary({
        ...value,
        recent_cases: (value.recent_cases || []).map((item) => ({
          ...item,
          subject: maskSensitiveValue(item.subject || item.case_id, maskingEnabled),
          sender: maskSensitiveValue(item.sender || "Unknown sender", maskingEnabled, "email"),
        })),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect to MailTrace backend.");
    } finally {
      setLoading(false);
    }
  }, [maskingEnabled]);

  const loadMailbox = useCallback(async () => {
    try {
      const [statusResponse, messagesResponse] = await Promise.all([
        fetch(API_BASE + "/api/mailbox/status", { cache: "no-store" }),
        fetch(API_BASE + "/api/mailbox/messages", { cache: "no-store" }),
      ]);
      const statusData = await statusResponse.json();
      const messagesData = await messagesResponse.json();
      if (!statusResponse.ok) throw new Error(statusData?.detail || "Mailbox status unavailable.");
      if (!messagesResponse.ok) throw new Error(messagesData?.detail || "Mailbox messages unavailable.");
      setMailbox(statusData as MailboxStatus);
      setMailboxMessages(messagesData.messages || []);
      setMailboxError("");
    } catch (err) {
      setMailboxError(err instanceof Error ? err.message : "Unable to load mailbox status.");
    }
  }, []);

  useEffect(() => {
    const initialLoad = window.setTimeout(() => {
      void loadSummary();
      void loadMailbox();
    }, 0);
    const timer = window.setInterval(() => {
      void loadSummary();
      void loadMailbox();
    }, 10000);
    let feed: EventSource | null = null;
    try {
      feed = new EventSource(API_BASE + "/api/mailbox/feed");
      feed.onmessage = () => {
        void loadSummary();
        void loadMailbox();
      };
    } catch {
      feed = null;
    }
    return () => {
      window.clearTimeout(initialLoad);
      window.clearInterval(timer);
      feed?.close();
    };
  }, [loadMailbox, loadSummary]);

  async function connectMailbox() {
    setMailboxBusy(true);
    setMailboxError("");
    try {
      const response = await fetch(API_BASE + "/api/mailbox/oauth/gmail/start", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || "Gmail OAuth is not configured.");
      if (!data.authorization_url) throw new Error("Gmail did not return an authorization URL.");
      window.location.assign(data.authorization_url);
    } catch (err) {
      setMailboxError(err instanceof Error ? err.message : "Unable to start Gmail connection.");
      setMailboxBusy(false);
    }
  }

  async function syncMailbox() {
    setMailboxBusy(true);
    setMailboxError("");
    try {
      const response = await fetch(API_BASE + "/api/mailbox/sync", { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || "Unable to sync mailbox.");
      await Promise.all([loadSummary(), loadMailbox()]);
    } catch (err) {
      setMailboxError(err instanceof Error ? err.message : "Unable to sync mailbox.");
    } finally {
      setMailboxBusy(false);
    }
  }

  const cases = summary?.recent_cases || [];
  const totalCases = summary?.total_investigations || 0;
  const maxActivity = Math.max(1, ...(summary?.activity_last_7_days || []).map((item) => item.count));
  const workerState = mailbox?.ingestion?.state || "STARTING";
  const provider = mailbox?.ingestion?.provider || "gmail";
  const connected = mailbox?.ingestion?.provider_status?.connected === true;
  const selectedCase = cases.find((item) => item.case_id === selectedCaseId) || cases[0] || null;
  const indicatorCount = cases.filter((item) => (item.ips?.length || 0) + (item.domains?.length || 0) + (item.urls?.length || 0) > 0).length;

  return (
    <main className="min-h-screen bg-[#070b12] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0a101a]">
        <div className="border-b border-slate-800 px-6 py-7">
          <div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-6">
          {navigation.map(([name, path, icon]) => (
            <Link key={name} href={path} className={"flex items-center gap-3 rounded-lg px-3 py-3 text-sm transition " + (name === "Dashboard" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white")}>
              <span className="w-5 text-center text-sm">{icon}</span>{name}
            </Link>
          ))}
        </nav>
        <div className="border-t border-slate-800 p-4"><div className="rounded-xl border border-slate-800 bg-[#0d1420] px-4 py-3"><p className="text-sm font-semibold">Analyst</p><p className="mt-1 text-xs text-slate-500">Security Operations</p></div></div>
      </aside>

      <section className="ml-64 min-h-screen p-8">
        <div className="mx-auto max-w-7xl">
          <header className="flex flex-col gap-5 border-b border-slate-800 pb-6 lg:flex-row lg:items-end lg:justify-between">
            <div><p className="text-xs uppercase tracking-[0.22em] text-blue-400">Security command center</p><h1 className="mt-2 text-3xl font-bold">Dashboard</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Monitor your mailbox, review risky messages, and move directly into a forensic investigation.</p></div>
            <div className="flex flex-wrap items-center gap-2"><button type="button" onClick={() => { void loadSummary(); void loadMailbox(); }} className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-300 hover:text-white">Refresh</button><Link href="/analyze" className="rounded-lg border border-blue-500/40 bg-blue-500/10 px-4 py-2 text-xs font-semibold text-blue-200 hover:bg-blue-500/20">Analyze email</Link><button type="button" disabled={mailboxBusy} onClick={() => void syncMailbox()} className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:border-blue-400 disabled:opacity-50">{mailboxBusy ? "Syncing..." : "Sync"}</button><button type="button" disabled={mailboxBusy} onClick={() => void connectMailbox()} className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50">{connected ? "Connect mailbox again" : "Connect mailbox"}</button></div>
          </header>
          {error && <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}

          <section className="mt-6 rounded-xl border border-slate-800 bg-[#0d1420] px-5 py-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div className="flex items-center gap-3"><span className="h-2.5 w-2.5 rounded-full bg-emerald-400" /><div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Mailbox monitor</p><p className="mt-1 text-sm text-slate-300">Automatic analysis is {connected ? "connected and watching" : "waiting for connection"} · {provider}</p></div></div><Link href="/mailbox" className="text-xs font-semibold text-blue-400 hover:text-blue-300">Open mailbox details →</Link></div>
            <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {[
                ["Worker state", workerState, connected ? "Connected and watching" : "Waiting for mailbox connection"],
                ["Provider", provider, mailbox?.ingestion?.provider_status?.configured ? "Credentials configured" : "Setup required"],
                ["Analyzed mail", mailboxMessages.length, "Messages in local evidence store"],
                ["Last sync", mailbox?.ingestion?.last_sync_at ? formatDate(mailbox.ingestion.last_sync_at) : "Not synced yet", "Automatic polling fallback enabled"],
              ].map(([label, value, detail]) => <div key={label} className="rounded-xl border border-slate-800 bg-[#0a111c]/80 p-4"><p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">{label}</p><p className="mt-2 truncate text-lg font-semibold">{loading && label !== "Provider" ? "—" : value}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></div>)}
            </div>
            {mailboxError && <p className="mt-4 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-300">{mailboxError}</p>}
          </section>

          <div className="hidden">
            {[["Recent investigations", totalCases, "Stored forensic cases"], ["High risk", summary?.high_risk ?? 0, "HIGH + CRITICAL"], ["Suspicious", summary?.suspicious_cases ?? 0, "Non-legitimate classifications"], ["Indicators linked", indicatorCount, "Cases with IP, domain, or URL"]].map(([label, value, detail]) => <div key={String(label)} className="rounded-xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase tracking-[0.14em] text-slate-500">{label}</p><p className="mt-3 text-3xl font-bold">{loading ? "—" : value}</p><p className="mt-2 text-[11px] text-slate-500">{detail}</p></div>)}
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
              <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Inbox activity</p><h2 className="mt-1 text-xl font-semibold">Recent emails</h2><p className="mt-1 text-sm text-slate-500">Click an email to open the complete mail and its security workspace.</p></div><Link href="/investigations" className="text-sm font-semibold text-blue-400 hover:text-blue-300">View all →</Link></div>
              <div className="mt-5 space-y-3">
                {!loading && cases.length === 0 && <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center"><p className="font-semibold text-slate-300">No analyzed emails yet</p><p className="mt-2 text-sm text-slate-500">Connect your mailbox or analyze a test email to create the first case.</p><div className="mt-5 flex justify-center gap-3"><button type="button" onClick={() => void connectMailbox()} className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold">Connect Gmail</button><Link href="/analyze" className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300">Analyze Email</Link></div></div>}
                {cases.map((item) => <div key={item.case_id} role="link" tabIndex={0} onClick={() => router.push("/investigations?case_id=" + encodeURIComponent(item.case_id))} onKeyDown={(event) => { if (event.key === "Enter") router.push("/investigations?case_id=" + encodeURIComponent(item.case_id)); }} className="relative block cursor-pointer rounded-xl border border-slate-800 bg-[#0a111c] p-4 transition hover:border-blue-500/50 hover:bg-[#0d1726]"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-blue-300">{item.case_id}</span><span className={"rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase " + riskBadgeClass(item.risk_level)}>{item.risk_level}</span><span className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] uppercase text-slate-400">{item.classification}</span></div><h3 className="mt-3 truncate text-sm font-semibold">{item.subject || item.case_id}</h3><p className="mt-1 truncate text-xs text-slate-500">{item.sender || "Unknown sender"} · {formatDate(item.created_at)}</p></div><div className="flex shrink-0 items-center gap-3 sm:text-right"><div><p className={"text-2xl font-bold " + riskClass(item.risk_level)}>{item.risk_score}</p><p className="text-[10px] uppercase text-slate-600">Score</p></div><button type="button" aria-label={"Open details for " + item.case_id} onClick={(event) => { event.stopPropagation(); setSelectedCaseId(item.case_id); setOpenMenuCaseId((current) => current === item.case_id ? null : item.case_id); }} className="rounded-lg border border-slate-700 px-3 py-2 text-xl leading-none text-slate-300 hover:border-blue-400 hover:text-white">⋮</button></div></div><p className="mt-3 text-xs font-semibold text-blue-400">Open complete mail →</p>{openMenuCaseId === item.case_id && <div onClick={(event) => event.stopPropagation()} className="absolute right-4 top-16 z-20 w-52 rounded-xl border border-slate-700 bg-[#111a29] p-2 shadow-2xl"><Link href={"/scorecard?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">Score Card</Link><Link href={"/threat-graph?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">Threat Graph</Link><Link href={"/threat-intelligence?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">Geolocation</Link><Link href={"/investigations?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">Investigation Detail</Link><Link href={"/ai-investigator?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">AI Help</Link><Link href={"/reports?case_id=" + encodeURIComponent(item.case_id)} className="block rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-white/10">Report</Link></div>}</div>)}
              </div>
            </section>

            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
              <div className="flex items-start justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Threat posture</p><h2 className="mt-1 text-xl font-semibold">Risk distribution</h2></div><span className="rounded-full border border-slate-700 px-2 py-1 text-[10px] uppercase text-slate-500">Live</span></div><p className="mt-2 text-sm text-slate-500">Risk scores from the local analysis engine.</p>
              <div className="mt-7 space-y-5">{["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => { const count = summary?.risk_distribution?.[level] || 0; const percent = totalCases ? Math.min(100, (count / totalCases) * 100) : 0; return <div key={level}><div className="flex justify-between text-xs"><span className={riskClass(level)}>{level}</span><span className="text-slate-400">{count}</span></div><div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800"><div className={"h-full rounded-full " + barClass(level)} style={{ width: percent + "%" }} /></div></div>; })}</div>
              <div className="mt-8 grid grid-cols-2 gap-3 border-t border-slate-800 pt-5"><div className="rounded-lg bg-[#0a111c] p-3"><p className="text-[10px] uppercase text-slate-500">Alerts</p><p className="mt-1 text-xl font-bold text-orange-300">{summary?.unacknowledged_alerts ?? 0}</p></div><div className="rounded-lg bg-[#0a111c] p-3"><p className="text-[10px] uppercase text-slate-500">7 day cases</p><p className="mt-1 text-xl font-bold text-blue-300">{(summary?.activity_last_7_days || []).reduce((total, day) => total + day.count, 0)}</p></div></div>
            </section>
          </div>

          <section className="mt-6 rounded-2xl border border-blue-500/20 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Selected email workspace</p><h2 className="mt-1 text-xl font-semibold">{selectedCase ? selectedCase.subject || selectedCase.case_id : "Select an email"}</h2><p className="mt-1 text-sm text-slate-500">{selectedCase ? "All security views below are specific to this email." : "Choose a recent email above to open its complete security workspace."}</p></div>
              {selectedCase && <span className={"rounded-full border px-3 py-1 text-xs font-semibold " + riskBadgeClass(selectedCase.risk_level)}>Score {selectedCase.risk_score}/100</span>}
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
              {[
                ["Investigation", "/investigations", "Case timeline and reasons"],
                ["Threat graph", "/threat-graph", "Connected indicators"],
                ["Geolocation", "/threat-intelligence", "IP and domain locations"],
                ["AI help", "/ai-investigator", "Why this email is risky"],
                ["Report", "/reports", "Export security findings"],
              ].map(([title, path, detail]) => <Link key={title} href={selectedCase ? path + "?case_id=" + encodeURIComponent(selectedCase.case_id) : path} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 transition hover:border-blue-500/50"><p className="font-semibold">{title}</p><p className="mt-2 text-xs text-slate-500">{detail}</p><p className="mt-4 text-xs font-semibold text-blue-400">Open →</p></Link>)}
            </div>
          </section>

          <section className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Security workflow</p><h2 className="mt-1 text-xl font-semibold">Continue the investigation</h2></div><p className="text-xs text-slate-500">All pages use the same mailbox evidence and live case data.</p></div>
            <div className="mt-5 grid gap-3 md:grid-cols-4">{[["Investigations", "Review cases, reasons, indicators, and forensic timelines.", "/investigations", "Open cases →"], ["Threat Graph", "Trace relationships between senders, IPs, domains, and URLs.", "/threat-graph", "Explore graph →"], ["Geolocation", "Inspect approximate locations for observed IPs and domains.", "/threat-intelligence", "View locations →"], ["AI Help", "Get a clear explanation of why a message is risky.", "/ai-investigator", "Ask AI Help →"]].map(([title, detail, path, action]) => <Link key={title} href={path} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4 transition hover:border-blue-500/50"><h3 className="font-semibold">{title}</h3><p className="mt-2 min-h-10 text-xs leading-5 text-slate-500">{detail}</p><p className="mt-4 text-xs font-semibold text-blue-400">{action}</p></Link>)}</div>
          </section>

          <section className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <div className="flex items-center justify-between"><div><p className="text-xs uppercase tracking-[0.18em] text-blue-400">Activity</p><h2 className="mt-1 text-lg font-semibold">Last seven days</h2></div><Link href="/reports" className="text-xs font-semibold text-blue-400">Open reports →</Link></div>
            <div className="mt-5 flex h-24 items-end gap-2">{(summary?.activity_last_7_days || []).map((day) => <div key={day.date} className="flex h-full flex-1 flex-col items-center justify-end gap-2"><div className="w-full rounded-t bg-blue-500/70" style={{ height: Math.max(5, (day.count / maxActivity) * 62) + "px" }} title={String(day.count) + " cases"} /><span className="text-[10px] text-slate-600">{day.date.slice(5)}</span></div>)}</div>
          </section>
        </div>
      </section>
    </main>
  );
}
