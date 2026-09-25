"use client";

import Link from "next/link";

const navigation = [
  ["Dashboard", "/", "▦"],
  ["Investigation", "/investigations", "⌕"],
  ["Threat Graph", "/threat-graph", "◇"],
  ["Geolocation", "/threat-intelligence", "◈"],
  ["AI Help", "/ai-investigator", "✦"],
  ["Reports", "/reports", "▤"],
  ["Help", "/help", "?"],
];

export default function HelpPage() {
  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-5">
          {navigation.map(([name, path, icon]) => (
            <Link key={name} href={path} className={`flex items-center gap-3 rounded-lg px-3 py-3 text-sm ${name === "Help" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white"}`}>
              <span className="w-5 text-center">{icon}</span>{name}
            </Link>
          ))}
        </nav>
      </aside>
      <section className="ml-64 min-h-screen p-8">
        <div className="mx-auto max-w-5xl">
          <p className="text-xs uppercase tracking-[0.2em] text-blue-400">MailTrace guidance</p>
          <h1 className="mt-2 text-3xl font-bold">Help</h1>
          <p className="mt-2 text-sm text-slate-500">Use the dashboard to connect your mailbox and follow analysis in real time.</p>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
              <h2 className="font-semibold">Mailbox monitoring</h2>
              <p className="mt-3 text-sm leading-6 text-slate-400">Use Connect Gmail and Sync Mail Now on the Dashboard. Authenticated messages are polled automatically, analyzed locally, and surfaced in investigations and alerts.</p>
              <Link href="/" className="mt-5 inline-block rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold">Open Dashboard</Link>
            </section>
            <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
              <h2 className="font-semibold">Investigate a result</h2>
              <p className="mt-3 text-sm leading-6 text-slate-400">Open Investigation for the full forensic record, Threat Graph for relationships, Geolocation for IP and domain context, and AI Help for evidence-grounded questions.</p>
              <Link href="/investigations" className="mt-5 inline-block rounded-lg border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-200">Open Investigation</Link>
            </section>
          </div>
          <section className="mt-4 rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
            <h2 className="font-semibold">Safety</h2>
            <p className="mt-3 text-sm leading-6 text-slate-400">Original email evidence is preserved and hashed. Attachments are never executed. Quarantine remains disabled unless explicitly enabled in the backend configuration.</p>
          </section>
        </div>
      </section>
    </main>
  );
}
