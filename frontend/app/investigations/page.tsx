"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import type { ReactNode } from "react";
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
  { name: "Investigation", path: "/investigations", icon: "⌕" },
  { name: "Threat Graph", path: "/threat-graph", icon: "◇" },
  { name: "Geolocation", path: "/threat-intelligence", icon: "◈" },
  { name: "AI Help", path: "/ai-investigator", icon: "✦" },
  { name: "Reports", path: "/reports", icon: "▤" },
  { name: "Help", path: "/help", icon: "?" },
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

type JsonObject = Record<string, unknown>;

function asRecord(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function asRecords(value: unknown): JsonObject[] {
  return Array.isArray(value) ? value.map(asRecord) : [];
}

function textValue(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.length ? value.join(", ") : fallback;
  return String(value);
}

function DetailSection({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
      <p className="text-xs uppercase tracking-[0.18em] text-blue-400">{title}</p>
      {subtitle && <p className="mt-2 text-sm text-slate-500">{subtitle}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

function FocusedInvestigation({ caseRecord, onBack }: { caseRecord: CaseRecord; onBack: () => void }) {
  const [payload, setPayload] = useState<{ analysis: JsonObject; audit: JsonObject } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const caseQuery = encodeURIComponent(caseRecord.case_id);

  useEffect(() => {
    const task = window.setTimeout(() => {
      void (async () => {
        try {
          const [analysisResponse, auditResponse] = await Promise.all([
            fetch(API_BASE + "/api/investigations/" + caseQuery + "/analysis", { cache: "no-store" }),
            fetch(API_BASE + "/api/investigations/" + caseQuery + "/audit", { cache: "no-store" }),
          ]);
          const analysisData = await analysisResponse.json();
          const auditData = await auditResponse.json();
          if (!analysisResponse.ok) throw new Error(analysisData?.detail || "Unable to load forensic analysis.");
          setPayload({ analysis: asRecord(analysisData.analysis), audit: asRecord(auditData) });
        } catch (err) {
          setError(err instanceof Error ? err.message : "Unable to load forensic analysis.");
        } finally {
          setLoading(false);
        }
      })();
    }, 0);
    return () => window.clearTimeout(task);
  }, [caseQuery]);

  const analysis = payload?.analysis || {};
  const email = asRecord(analysis.email);
  const threat = asRecord(analysis.threat_detection);
  const authentication = asRecord(analysis.authentication);
  const sender = asRecord(analysis.sender_analysis);
  const body = asRecord(analysis.body);
  const infrastructure = asRecord(analysis.sending_infrastructure);
  const candidate = asRecord(infrastructure.candidate);
  const indicators = asRecord(analysis.indicators);
  const attachmentAnalysis = asRecord(analysis.attachment_analysis);
  const correlation = asRecord(analysis.correlation);
  const ml = asRecord(analysis.ml_analysis);
  const components = Object.entries(asRecord(threat.components));
  const evidence = asRecords(threat.evidence);
  const headers = Object.entries(asRecord(analysis.headers));
  const hops = asRecords(analysis.smtp_relay);
  const attachments = asRecords(analysis.attachments);
  const relatedCases = asRecords(correlation.related_cases);
  const auditEvents = asRecords(payload?.audit.events);
  const graphNodes = asRecords(asRecord(analysis.threat_graph).nodes);
  const riskScore = textValue(threat.risk_score, String(caseRecord.risk_score));
  const riskLevel = textValue(threat.risk_level, caseRecord.risk_level);
  const classification = textValue(threat.classification, caseRecord.classification);

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6"><div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div><div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div></div>
        <nav className="flex-1 space-y-1 px-3 py-5">{navItems.map((item) => <Link key={item.name} href={item.path} className={"flex items-center gap-3 rounded-lg px-3 py-3 text-sm transition " + (item.name === "Investigation" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white")}><span className="w-5 text-center">{item.icon}</span>{item.name}</Link>)}</nav>
        <div className="border-t border-slate-800 p-4"><div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3"><div className="text-sm font-medium">Analyst</div><div className="text-xs text-slate-500">Security Operations</div></div></div>
      </aside>

      <section className="ml-64 min-h-screen p-8"><div className="mx-auto max-w-7xl">
        <header className="flex flex-col gap-4 border-b border-slate-800 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div><button onClick={onBack} className="text-xs font-semibold text-blue-400 hover:text-blue-300">← Back to investigation search</button><p className="mt-5 text-xs uppercase tracking-[0.2em] text-blue-400">Email threat detection & forensic investigation</p><h1 className="mt-2 text-3xl font-bold">Investigation Details</h1><p className="mt-2 text-sm text-slate-500">Focused evidence view for one selected email. Previous cases are hidden.</p></div>
          <div className="flex flex-wrap gap-2"><Link href={"/scorecard?case_id=" + caseQuery} className="rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-2 text-xs font-semibold text-blue-200">Score Card</Link><Link href={"/threat-graph?case_id=" + caseQuery} className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-300">Threat Graph</Link><Link href={"/ai-investigator?case_id=" + caseQuery} className="rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/10 px-3 py-2 text-xs font-semibold text-fuchsia-300">AI Help</Link><Link href={"/reports?case_id=" + caseQuery} className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-300">Report</Link></div>
        </header>
        {error && <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-300">{error}</div>}
        {loading ? <div className="mt-6 rounded-2xl border border-slate-800 bg-[#0d1420] p-10 text-center text-sm text-slate-500">Loading complete forensic evidence…</div> : <div className="mt-6 space-y-6">
          <DetailSection title="1. Case Overview" subtitle="The identity, verdict, and provenance of this investigation.">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[["Case ID", caseRecord.case_id], ["Evidence ID", caseRecord.evidence_id], ["Investigation status", "Analysis completed"], ["Source", "Direct mailbox connection"], ["Severity", riskLevel], ["Risk score", riskScore + "/100"], ["Confidence", textValue(threat.confidence, caseRecord.confidence)], ["Threat type", classification], ["Detection time", formatDate(caseRecord.created_at)], ["Affected mailbox", textValue(email.to)], ["Investigator", "MailTrace AI"], ["SHA-256", caseRecord.sha256]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-[11px] text-slate-500">{String(label)}</p><p className={"mt-1 break-all text-sm " + (label === "Risk score" || label === "Severity" ? "font-semibold text-orange-300" : "text-slate-200")}>{textValue(value)}</p></div>)}</div>
          </DetailSection>

          <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <DetailSection title="2. Threat Verdict" subtitle="Why the local detector classified this email.">
              <div className="flex flex-wrap gap-3"><span className={"rounded-full border px-3 py-2 text-sm font-semibold " + classBadge(classification)}>{classification}</span><span className={"rounded-full border px-3 py-2 text-sm font-semibold " + riskClass(riskLevel)}>{riskLevel} · {riskScore}/100</span><span className="rounded-full border border-slate-700 px-3 py-2 text-sm text-slate-300">{textValue(threat.confidence, caseRecord.confidence)} confidence</span></div><p className="mt-5 text-sm leading-6 text-slate-300">{textValue(threat.summary, "The score is based on observable email, authentication, content, infrastructure, and correlation evidence.")}</p><div className="mt-5 space-y-3">{evidence.length ? evidence.map((item, index) => <div key={textValue(item.id, String(index))} className="rounded-lg border border-orange-400/20 bg-orange-500/5 p-3"><p className="text-xs font-semibold text-orange-300">{textValue(item.severity)} · {textValue(item.title)}</p><p className="mt-1 text-sm text-slate-400">{textValue(item.detail)}</p></div>) : <p className="text-sm text-slate-500">No specific findings were returned.</p>}</div>
            </DetailSection>
            <DetailSection title="3. Score Evidence" subtitle="Transparent contribution of each detector.">
              <div className="space-y-4">{components.map(([name, item]) => { const value = asRecord(item); const score = Number(value.score || 0); const max = Number(value.max_score || 0); return <div key={String(name)}><div className="flex justify-between text-sm"><span className="capitalize text-slate-300">{String(name).replaceAll("_", " ")}</span><span className="text-blue-300">{score}/{max}</span></div><div className="mt-2 h-2 rounded-full bg-slate-800"><div className="h-2 rounded-full bg-blue-500" style={{ width: (max ? score / max * 100 : 0) + "%" }} /></div>{asRecords(value.findings).length ? <p className="mt-2 text-xs text-slate-500">{asRecords(value.findings).map((finding) => textValue(finding)).join(" · ")}</p> : Array.isArray(value.findings) && value.findings.length ? <p className="mt-2 text-xs text-slate-500">{value.findings.map((finding) => textValue(finding)).join(" · ")}</p> : null}</div>; })}</div><div className="mt-5 rounded-lg border border-slate-800 bg-[#0a111c] p-3 text-xs text-slate-500">Observed facts are separated from model inferences. A score alone is not treated as proof.</div>
            </DetailSection>
          </div>

          <DetailSection title="4. Email Information" subtitle="Who sent it, who received it, and what was delivered.">
            <div className="grid gap-3 md:grid-cols-2">{[["Subject", email.subject || caseRecord.subject], ["From", email.from || caseRecord.sender], ["To", email.to || caseRecord.recipient], ["Reply-To", email.reply_to || caseRecord.reply_to_domain], ["Return-Path", email.return_path || caseRecord.return_path_domain], ["Message-ID", email.message_id || caseRecord.message_id], ["Received time", email.date || caseRecord.created_at], ["Plain text length", textValue(body.plain_text_length)], ["HTML length", textValue(body.html_length)], ["Attachments", textValue(attachments.length, "0")]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs text-slate-500">{String(label)}</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(value)}</p></div>)}</div>
          </DetailSection>

          <div className="grid gap-6 xl:grid-cols-2">
            <DetailSection title="5. Header Forensics" subtitle="Original header values preserved from the evidence.">
              <div className="max-h-[420px] space-y-2 overflow-auto">{headers.length ? headers.map(([name, value]) => <div key={String(name)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs font-semibold text-blue-300">{String(name)}</p><p className="mt-1 break-all whitespace-pre-wrap text-xs leading-5 text-slate-400">{textValue(value)}</p></div>) : <p className="text-sm text-slate-500">No headers returned.</p>}</div>
            </DetailSection>
            <DetailSection title="6. Authentication & Sender Identity" subtitle="Authentication results and impersonation checks.">
              <div className="grid gap-3 sm:grid-cols-2">{[["SPF", authentication.spf], ["DKIM", authentication.dkim], ["DMARC", authentication.dmarc], ["ARC", authentication.arc], ["Sender domain", sender.sender_domain || caseRecord.sender_domain], ["Reply-To mismatch", sender.reply_to_mismatch], ["Return-Path mismatch", sender.return_path_mismatch], ["ML model", ml.ml_model]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs text-slate-500">{String(label)}</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(value)}</p></div>)}</div><p className="mt-4 text-xs leading-5 text-slate-500">Authentication passing does not prove that the content is safe; content and infrastructure evidence are evaluated separately.</p>
            </DetailSection>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <DetailSection title="7. Email Route & Infrastructure" subtitle="Delivery hops reconstructed from Received headers.">
              <div className="space-y-3">{hops.length ? hops.map((hop, index) => <div key={String(index)} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs font-semibold text-blue-300">Hop {index + 1}</p><p className="mt-1 whitespace-pre-wrap text-xs leading-5 text-slate-400">{textValue(hop.raw || hop.hostname || hop.ip)}</p><p className="mt-2 text-[11px] text-slate-500">IP: {textValue(hop.ips)} · Protocol/TLS evidence preserved in raw hop</p></div>) : <p className="text-sm text-slate-500">No relay hops were extracted.</p>}<div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-xs text-slate-400">Candidate infrastructure: <span className="text-white">{textValue(candidate.ip || indicators.ips)}</span> · confidence {textValue(candidate.confidence)}</div></div>
            </DetailSection>
            <DetailSection title="8. URLs, Domains & Attachments" subtitle="Indicators that support or weaken the verdict.">
              <div className="space-y-3"><div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs text-slate-500">IPs</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(indicators.ips)}</p><p className="mt-3 text-xs text-slate-500">Domains</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(indicators.domains || caseRecord.domains)}</p><p className="mt-3 text-xs text-slate-500">URLs</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(indicators.urls || caseRecord.urls)}</p></div><div className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs text-slate-500">Attachments</p><p className="mt-1 text-sm text-slate-200">{attachments.length ? attachments.map((item) => textValue(item.filename || item.name)).join(", ") : textValue(caseRecord.attachments, "None")}</p><p className="mt-3 text-xs text-slate-500">Attachment findings</p><p className="mt-1 text-sm text-slate-300">{textValue(attachmentAnalysis.findings, "No suspicious attachment findings returned.")}</p></div></div>
            </DetailSection>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <DetailSection title="9. Mailbox-Wide Correlation" subtitle="Related activity found in the connected mailbox.">
              <div className="flex flex-wrap gap-3"><span className="rounded-lg border border-slate-800 bg-[#0a111c] px-3 py-2 text-sm">Related cases: <b className="text-white">{textValue(correlation.related_case_count, "0")}</b></span><span className="rounded-lg border border-slate-800 bg-[#0a111c] px-3 py-2 text-sm">Best match: <b className="text-yellow-300">{textValue(correlation.best_match_score, "—")}</b></span></div><div className="mt-4 space-y-2">{relatedCases.slice(0, 5).map((item, index) => <div key={textValue(item.case_id, String(index))} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="font-mono text-xs text-blue-300">{textValue(item.case_id || item.evidence_id)}</p><p className="mt-1 truncate text-sm text-slate-200">{textValue(item.subject || item.filename)}</p><p className="mt-1 text-xs text-slate-500">{textValue(item.reasons)}</p></div>)}</div>
            </DetailSection>
            <DetailSection title="10. Threat Graph & IOC View" subtitle="Observable relationships, not unsupported attribution.">
              <div className="grid gap-3 sm:grid-cols-2">{graphNodes.map((node, index) => <div key={textValue(node.id, String(index))} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3"><p className="text-xs text-blue-300">{textValue(node.type)}</p><p className="mt-1 break-all text-sm text-slate-200">{textValue(node.value || node.label)}</p></div>)}</div><p className="mt-4 text-xs leading-5 text-slate-500">The graph shows links observed in the message evidence. It does not independently prove actor identity or physical location.</p>
            </DetailSection>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <DetailSection title="11. Forensic Timeline" subtitle="Recorded investigation events with timestamps and evidence IDs.">
              <div className="space-y-3">{auditEvents.length ? auditEvents.map((event, index) => <div key={textValue(event.event_id, String(index))} className="flex gap-3 rounded-lg border border-slate-800 bg-[#0a111c] p-3"><div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-blue-400" /><div><p className="text-xs font-semibold text-slate-200">{textValue(event.event_type)}</p><p className="mt-1 text-xs text-slate-500">{formatDate(textValue(event.timestamp, caseRecord.created_at))} · {textValue(event.description)}</p><p className="mt-1 break-all text-[11px] text-slate-600">Event ID: {textValue(event.event_id)} · Hash: {textValue(event.evidence_hash)}</p></div></div>) : <p className="text-sm text-slate-500">No timeline events returned.</p>}</div>
            </DetailSection>
            <DetailSection title="12. Evidence & Findings" subtitle="What is confirmed, what is suspected, and what remains unknown.">
              <div className="space-y-3"><div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4"><p className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-300">Confirmed / observed</p><p className="mt-2 text-sm leading-6 text-slate-300">The original message was preserved and hashed. The displayed headers, authentication results, extracted indicators, and detector findings above come from stored evidence.</p></div><div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-4"><p className="text-xs font-semibold uppercase tracking-[0.14em] text-yellow-300">Suspected / inferred</p><p className="mt-2 text-sm leading-6 text-slate-300">{textValue(threat.summary, "The threat classification is an evidence-based inference from the available signals.")}</p></div><div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4"><p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">Unknown / missing evidence</p><p className="mt-2 text-sm leading-6 text-slate-400">Endpoint telemetry, link-click telemetry, and attachment execution behavior are not assumed unless separately collected.</p></div></div>
            </DetailSection>
          </div>
        </div>}
      </div></section>
    </main>
  );
}

function InvestigationLanding() {
  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6"><div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div><div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div></div>
        <nav className="flex-1 space-y-1 px-3 py-5">{navItems.map((item) => <Link key={item.name} href={item.path} className={"flex items-center gap-3 rounded-lg px-3 py-3 text-sm transition " + (item.name === "Investigation" ? "bg-blue-500/10 text-blue-300" : "text-slate-400 hover:bg-white/5 hover:text-white")}><span className="w-5 text-center">{item.icon}</span>{item.name}</Link>)}</nav>
        <div className="border-t border-slate-800 p-4"><div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3"><div className="text-sm font-medium">Analyst</div><div className="text-xs text-slate-500">Security Operations</div></div></div>
      </aside>
      <section className="ml-64 min-h-screen p-8"><div className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-5xl items-center justify-center">
        <div className="w-full rounded-2xl border border-slate-800 bg-[#0d1420] p-10 text-center shadow-2xl">
          <p className="text-xs uppercase tracking-[0.2em] text-blue-400">Focused investigation workspace</p>
          <h1 className="mt-3 text-3xl font-bold">Choose an email to investigate</h1>
          <p className="mx-auto mt-4 max-w-xl text-sm leading-6 text-slate-400">Open an email on the Dashboard and use its three-dot menu → Investigation Detail. Only that email’s evidence, verdict, indicators, timeline, and findings will be shown here.</p>
          <Link href="/" className="mt-7 inline-flex rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold text-white hover:bg-blue-500">Go to Dashboard</Link>
        </div>
      </div></section>
    </main>
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
  const [focusedMode, setFocusedMode] = useState(false);
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

      const preferred = preferredCaseId
        ? loadedCases.find((item) => item.case_id === preferredCaseId)
        : null;
      setSelectedId(preferred?.case_id || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect to MailTrace backend.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const preferredCaseId = params.get("case_id") || "";
    const focusTask = window.setTimeout(() => setFocusedMode(Boolean(preferredCaseId)), 0);

    void Promise.resolve().then(() => loadCases(preferredCaseId));

    return () => window.clearTimeout(focusTask);
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
    () => cases.find((item) => item.case_id === selectedId) || null,
    [cases, selectedId]
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

  if (focusedMode && selectedCase) {
    return <FocusedInvestigation caseRecord={selectedCase} onBack={() => router.push("/investigations")} />;
  }

  if (!focusedMode) {
    return <InvestigationLanding />;
  }

  return (
    <main className="min-h-screen bg-[#080c14] text-white">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide">MailTrace <span className="text-blue-500">AI</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-5">
            {navItems.map((item) => {
              const active = item.name === "Investigation";
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
