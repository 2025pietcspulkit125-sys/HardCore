"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
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

type InvestigationListResponse = {
  status: string;
  count: number;
  cases: CaseRecord[];
  detail?: string;
};

type AnalysisPayload = {
  status?: string;
  file?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  email?: Record<string, unknown>;
  authentication?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  smtp_relay?: unknown[];
  sending_infrastructure?: Record<string, unknown>;
  indicators?: {
    ips?: string[];
    urls?: string[];
  };
  url_analysis?: unknown[];
  content_analysis?: {
    findings?: unknown[];
    urgency_matches?: string[];
    credential_matches?: string[];
    payment_matches?: string[];
  };
  attachments?: unknown[];
  attachment_analysis?: Record<string, unknown>;
  sender_analysis?: Record<string, unknown>;
  impersonation?: Record<string, unknown>;
  bec_analysis?: Record<string, unknown>;
  threat_detection?: {
    classification?: string;
    risk_score?: number;
    risk_level?: string;
    confidence?: string;
    summary?: string;
    components?: Record<string, unknown>;
    evidence?: unknown[];
    limitations?: string[];
  };
  correlation?: {
    related_cases?: unknown[];
    related_case_count?: number;
    best_match_score?: number;
    interpretation?: string;
  };
  ml_analysis?: {
    ml_classification?: string;
    ml_confidence?: number;
    ml_features_used?: string[];
    ml_disclaimer?: string;
  };
  attribution_support?: {
    items?: Array<{ indicator?: string; status?: string; evidence?: string; confidence?: string }>;
    disclaimer?: string;
  };
  compromised_account_indicator?: {
    status?: string;
    confidence?: string;
    reasons?: string[];
    note?: string;
  };
  chain_of_custody?: Array<{ event_type?: string; timestamp?: string; description?: string; evidence_hash?: string }>;
};

type AnalysisResponse = {
  status: string;
  analysis: AnalysisPayload;
  detail?: string;
};

type CorrelationResponse = {
  status: string;
  correlation: {
    related_cases?: Array<{
      case_id: string;
      evidence_id?: string;
      subject?: string;
      similarity_score?: number;
      reasons?: string[];
    }>;
    related_case_count?: number;
    best_match_score?: number;
    interpretation?: string;
  };
  detail?: string;
};

const NAV = [
  ["Dashboard", "/", "▦"],
  ["Investigation", "/investigations", "⌕"],
  ["Threat Graph", "/threat-graph", "◇"],
  ["Geolocation", "/threat-intelligence", "◈"],
  ["AI Help", "/ai-investigator", "✦"],
  ["Reports", "/reports", "▤"],
  ["Help", "/help", "?"],
];

function text(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function recordList(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"))
    : [];
}

function stringList(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
}

function authResult(value: unknown) {
  if (value && typeof value === "object") {
    const item = value as Record<string, unknown>;
    return text(item.result ?? item.status ?? item.value, "UNKNOWN").toUpperCase();
  }
  return text(value, "UNKNOWN").toUpperCase();
}

function dateText(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function riskClass(level?: string) {
  switch ((level || "").toUpperCase()) {
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

function ReportsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const requestedCaseId = searchParams.get("case_id") || "";

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedId, setSelectedId] = useState(requestedCaseId);
  const [analysis, setAnalysis] = useState<AnalysisPayload | null>(null);
  const [correlation, setCorrelation] = useState<CorrelationResponse["correlation"] | null>(null);

  const [, setLoadingCases] = useState(true);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const [loadingCorrelation, setLoadingCorrelation] = useState(false);
  const [error, setError] = useState("");
  const maskingEnabled = useMaskingPreference();

  const loadCases = useCallback(async () => {
    setLoadingCases(true);
    setError("");

    try {
      const response = await fetch(
        `${API_BASE}/api/investigations?limit=200`,
        { cache: "no-store" }
      );

      const data = (await response.json()) as InvestigationListResponse;

      if (!response.ok) {
        throw new Error(data.detail || "Unable to load stored investigations.");
      }

      const nextCases = Array.isArray(data.cases) ? data.cases : [];
      setCases(nextCases);

      setSelectedId((current) => {
        if (requestedCaseId && nextCases.some((item) => item.case_id === requestedCaseId)) {
          return requestedCaseId;
        }

        if (current && nextCases.some((item) => item.case_id === current)) {
          return current;
        }

        return "";
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load investigations.");
    } finally {
      setLoadingCases(false);
    }
  }, [requestedCaseId]);

  const loadCaseData = useCallback(async (caseId: string) => {
    if (!caseId) {
      setAnalysis(null);
      setCorrelation(null);
      return;
    }

    setLoadingAnalysis(true);
    setLoadingCorrelation(true);
    setError("");

    try {
      // IMPORTANT:
      // Reports no longer depend on /api/reports/{case_id}.
      // That route was the source of the "Not Found" screen when the
      // running backend was an older compatible version.
      const [analysisResponse, correlationResponse] = await Promise.all([
        fetch(
          `${API_BASE}/api/investigations/${encodeURIComponent(caseId)}/analysis`,
          { cache: "no-store" }
        ),
        fetch(
          `${API_BASE}/api/correlation/${encodeURIComponent(caseId)}`,
          { cache: "no-store" }
        ),
      ]);

      const analysisData =
        (await analysisResponse.json()) as AnalysisResponse;

      if (!analysisResponse.ok) {
        throw new Error(
          analysisData.detail || "Unable to load the stored case analysis."
        );
      }

      setAnalysis(analysisData.analysis || null);

      if (correlationResponse.ok) {
        const correlationData =
          (await correlationResponse.json()) as CorrelationResponse;
        setCorrelation(correlationData.correlation || null);
      } else {
        setCorrelation(null);
      }
    } catch (err) {
      setAnalysis(null);
      setCorrelation(null);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load the selected investigation."
      );
    } finally {
      setLoadingAnalysis(false);
      setLoadingCorrelation(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => loadCases());
  }, [loadCases]);

  useEffect(() => {
    if (!selectedId) return;
    void Promise.resolve().then(() => loadCaseData(selectedId));
  }, [selectedId, loadCaseData]);

  const selectedCase =
    cases.find((item) => item.case_id === selectedId) || null;

  const reportCase = analysis || {};

  const reportSubject =
    text(reportCase.email?.subject, "") ||
    selectedCase?.subject ||
    selectedCase?.filename ||
    "Untitled email";

  const reportSender =
    text(reportCase.email?.from, "") ||
    selectedCase?.sender ||
    "Unknown sender";

  const reportRecipient =
    text(reportCase.email?.to, "") ||
    selectedCase?.recipient ||
    "Unknown recipient";

  const reportClassification =
    text(reportCase.threat_detection?.classification, "") ||
    selectedCase?.classification ||
    "UNKNOWN";

  const reportRisk =
    reportCase.threat_detection?.risk_score ??
    selectedCase?.risk_score ??
    0;

  const reportRiskLevel =
    text(reportCase.threat_detection?.risk_level, "") ||
    selectedCase?.risk_level ||
    "LOW";

  const reportConfidence =
    text(reportCase.threat_detection?.confidence, "") ||
    selectedCase?.confidence ||
    "UNKNOWN";

  const reportEvidenceId =
    text(reportCase.evidence?.evidence_id, "") ||
    selectedCase?.evidence_id ||
    "—";

  const reportSha256 =
    text(reportCase.evidence?.sha256, "") ||
    selectedCase?.sha256 ||
    "—";

  const reportIps =
    reportCase.indicators?.ips?.length
      ? reportCase.indicators.ips
      : selectedCase?.ips || [];

  const reportUrls =
    reportCase.indicators?.urls?.length
      ? reportCase.indicators.urls
      : selectedCase?.urls || [];

  const reportAttachments =
    Array.isArray(reportCase.attachments) && reportCase.attachments.length
      ? reportCase.attachments
      : selectedCase?.attachments || [];

  const reportSummary =
    text(reportCase.threat_detection?.summary, "") ||
    "No stored executive summary is available for this case.";

  const reportEvidenceReasons = stringList(reportCase.threat_detection?.evidence);
  const contentFindings = recordList(reportCase.content_analysis?.findings);
  const senderFindings = recordList(reportCase.sender_analysis?.findings);
  const impersonationFindings = recordList(reportCase.impersonation?.findings);
  const urlFindings = reportCase.url_analysis?.flatMap((item) =>
    recordList((item as Record<string, unknown>)?.findings)
  ) || [];
  const attachmentFindings = recordList(reportCase.attachment_analysis?.findings);
  const conclusionReasons = Array.from(new Set([
    ...reportEvidenceReasons,
    ...contentFindings.map((item) => text(item.detail, text(item.type, "Content signal detected"))),
    ...senderFindings.map((item) => text(item.detail, text(item.type, "Sender relationship signal detected"))),
    ...urlFindings.map((item) => text(item.detail, text(item.type, "URL signal detected"))),
    ...attachmentFindings.map((item) => text(item.detail, text(item.type, "Attachment signal detected"))),
  ])).slice(0, 8);
  const auth = reportCase.authentication || {};
  const routeHops = Array.isArray(reportCase.smtp_relay) ? reportCase.smtp_relay : [];
  const threatClassification = reportClassification.toUpperCase();
  const conclusionTone = threatClassification === "LEGITIMATE" && reportRisk < 30
    ? "LOW CONCERN"
    : reportRisk >= 70 || ["MALWARE", "PHISHING", "BEC_FRAUD", "IMPERSONATION"].includes(threatClassification)
      ? "ACTION REQUIRED"
      : "REVIEW REQUIRED";
  const recommendedAction = conclusionTone === "LOW CONCERN"
    ? "No automatic blocking is recommended from this report alone. Continue normal mailbox monitoring."
    : reportRisk >= 70
      ? "Treat as high risk: preserve evidence, alert the analyst, and quarantine or block only according to the configured mailbox policy."
      : "Keep the original evidence, verify the sender through a trusted channel, and review links or attachments before any user action.";

  const openCase = (caseId: string) => {
    setSelectedId(caseId);
    router.replace(`/reports?case_id=${encodeURIComponent(caseId)}`);
  };

  const navigate = (path: string) => {
    router.push(path);
  };

  const downloadJson = () => {
    if (!selectedCase) return;

    const payload = {
      generated_at: new Date().toISOString(),
      report: {
        case: selectedCase,
        analysis: reportCase,
        correlation,
      },
    };

    const blob = new Blob(
      [JSON.stringify(payload, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `mailtrace-${selectedCase.case_id}-forensic-report.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
  };

  const printReport = () => {
    window.print();
  };

  return (
    <main className="min-h-screen bg-[#080c14] text-white print:bg-white print:text-black">
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a] print:hidden">
        <div className="border-b border-slate-800 px-6 py-6">
          <div className="text-xl font-bold tracking-wide">
            MailTrace <span className="text-blue-500">AI</span>
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">
            Email Forensics Platform
          </div>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-5">

          {NAV.map(([name, path, icon]) => {
            const active = name === "Reports";

            return (
              <button
                key={name}
                type="button"
                onClick={() => navigate(path)}
                className={`mb-1 flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm transition ${
                  active
                    ? "border border-blue-500/20 bg-blue-500/10 text-blue-300"
                    : "text-slate-400 hover:bg-white/5 hover:text-white"
                }`}
              >
                <span className="w-5 text-center">{icon}</span>
                {name}
              </button>
            );
          })}
        </nav>
      </aside>

      <section className="ml-64 min-h-screen px-8 py-8">
        <div className="mx-auto w-full max-w-[1600px]">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="text-xs uppercase tracking-[0.22em] text-blue-400">
                Forensic Reporting
              </div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight">
                Investigation Reports
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                Generate a persistent evidence-based report from any stored investigation.
              </p>
            </div>

            <button
              type="button"
              onClick={() => navigate("/analyze")}
              className="rounded-xl border border-slate-700 px-5 py-3 text-sm font-semibold text-slate-200 hover:border-blue-500/40 hover:text-white"
            >
              Analyze New Email
            </button>
          </div>

          {error && (
            <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-300">
              {error}
            </div>
          )}

          <div className="mt-8">
            <section className="min-w-0">
              {!selectedCase ? (
                <div className="flex min-h-[600px] items-center justify-center rounded-2xl border border-slate-800 bg-[#0d1420] p-8 text-center">
                  <div>
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-500/10 text-2xl">
                      ▤
                    </div>
                    <h2 className="mt-5 text-xl font-semibold">
                      No email report selected
                    </h2>
                    <p className="mt-2 text-sm text-slate-500">
                      Open Report from an email&apos;s three-dot menu on the Dashboard to view that email&apos;s complete forensic conclusion.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-6">
                  <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                    <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="font-mono text-xs text-blue-300">
                          {selectedCase.case_id}
                        </div>
                        <h2 className="mt-2 text-2xl font-bold leading-tight">
                          {reportSubject}
                        </h2>
                        <p className="mt-2 text-sm text-slate-500">
                          {maskSensitiveValue(reportSender, maskingEnabled, "email")} → {maskSensitiveValue(reportRecipient, maskingEnabled, "email")}
                        </p>
                      </div>

                      <div className="flex flex-wrap gap-2 print:hidden">
                        <button
                          type="button"
                          onClick={downloadJson}
                          className="rounded-lg border border-slate-700 px-4 py-2.5 text-xs font-semibold text-slate-300 hover:text-white"
                        >
                          Download JSON
                        </button>
                        <button
                          type="button"
                          onClick={printReport}
                          className="rounded-lg bg-blue-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-500"
                        >
                          Print / Save PDF
                        </button>
                      </div>
                    </div>

                    <div className="mt-6 grid gap-3 sm:grid-cols-4">
                      <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                        <p className="text-[10px] uppercase tracking-wider text-slate-600">
                          Classification
                        </p>
                        <p className="mt-2 text-sm font-semibold">
                          {reportClassification}
                        </p>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                        <p className="text-[10px] uppercase tracking-wider text-slate-600">
                          Risk
                        </p>
                        <p
                          className={`mt-2 inline-flex rounded-full border px-2 py-1 text-xs font-semibold ${riskClass(
                            reportRiskLevel
                          )}`}
                        >
                          {reportRiskLevel} · {reportRisk}/100
                        </p>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                        <p className="text-[10px] uppercase tracking-wider text-slate-600">
                          Confidence
                        </p>
                        <p className="mt-2 text-sm font-semibold">
                          {reportConfidence}
                        </p>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                        <p className="text-[10px] uppercase tracking-wider text-slate-600">
                          Created
                        </p>
                        <p className="mt-2 text-xs font-semibold text-slate-300">
                          {dateText(selectedCase.created_at)}
                        </p>
                      </div>
                    </div>
                  </section>

                  <section className="overflow-hidden rounded-2xl border border-blue-500/25 bg-gradient-to-br from-[#101d35] via-[#0d1420] to-[#0d1420]">
                    <div className="border-b border-blue-500/15 px-6 py-5 sm:px-8">
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-blue-300">Final forensic conclusion</p>
                          <h3 className="mt-2 text-2xl font-bold text-white">{conclusionTone}</h3>
                          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">{reportSummary}</p>
                        </div>
                        <div className={`rounded-xl border px-4 py-3 text-center ${riskClass(reportRiskLevel)}`}>
                          <p className="text-[10px] uppercase tracking-[0.16em]">Evidence-based risk</p>
                          <p className="mt-1 text-2xl font-bold">{reportRisk}/100</p>
                          <p className="text-[10px] uppercase">{reportRiskLevel} · {reportConfidence} confidence</p>
                        </div>
                      </div>
                    </div>

                    <div className="grid gap-4 px-6 py-6 sm:px-8 lg:grid-cols-3">
                      <div className="rounded-xl border border-slate-800 bg-[#0a111c]/80 p-4 lg:col-span-2">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">Why this email received this verdict</p>
                        {conclusionReasons.length ? (
                          <ol className="mt-4 space-y-3">
                            {conclusionReasons.map((reason, index) => <li key={`${reason}-${index}`} className="flex gap-3 text-sm leading-6 text-slate-300"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-blue-500/15 text-xs font-semibold text-blue-300">{index + 1}</span><span>{reason}</span></li>)}
                          </ol>
                        ) : (
                          <p className="mt-4 text-sm leading-6 text-slate-400">No specific finding was stored beyond the overall classification and score. Treat the result as limited evidence, not proof of safety.</p>
                        )}
                      </div>
                      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-amber-300">Recommended action</p>
                        <p className="mt-4 text-sm leading-6 text-amber-100/80">{recommendedAction}</p>
                        <p className="mt-4 text-[11px] leading-5 text-slate-500">The report supports analyst decisions. It does not claim that an email was opened, clicked, or that a person was physically located from an IP address.</p>
                      </div>
                    </div>

                    <div className="grid gap-3 border-t border-slate-800/80 px-6 py-5 sm:grid-cols-2 lg:grid-cols-4 sm:px-8">
                      <div><p className="text-[10px] uppercase tracking-wider text-slate-500">Sender</p><p className="mt-1 truncate text-sm text-slate-200">{maskSensitiveValue(reportSender, maskingEnabled, "email")}</p></div>
                      <div><p className="text-[10px] uppercase tracking-wider text-slate-500">Recipient</p><p className="mt-1 truncate text-sm text-slate-200">{maskSensitiveValue(reportRecipient, maskingEnabled, "email")}</p></div>
                      <div><p className="text-[10px] uppercase tracking-wider text-slate-500">Route evidence</p><p className="mt-1 text-sm text-slate-200">{routeHops.length} Received hop(s)</p></div>
                      <div><p className="text-[10px] uppercase tracking-wider text-slate-500">Indicators</p><p className="mt-1 text-sm text-slate-200">{reportIps.length} IP · {reportUrls.length} URL · {reportAttachments.length} file(s)</p></div>
                    </div>
                  </section>

                  {loadingAnalysis ? (
                    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6 text-sm text-slate-500">
                      Loading stored forensic evidence...
                    </div>
                  ) : (
                    <>
                      <div className="grid gap-6 lg:grid-cols-2">
                        <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <h3 className="font-semibold">Evidence Preservation</h3>

                          <dl className="mt-4 space-y-4 text-sm">
                            <div>
                              <dt className="text-xs text-slate-500">Evidence ID</dt>
                              <dd className="mt-2 break-all font-mono text-xs text-slate-300">
                                {reportEvidenceId}
                              </dd>
                            </div>

                            <div>
                              <dt className="text-xs text-slate-500">SHA-256</dt>
                              <dd className="mt-2 break-all font-mono text-[10px] leading-5 text-slate-300">
                                {reportSha256}
                              </dd>
                            </div>

                            <div>
                              <dt className="text-xs text-slate-500">Stored Case</dt>
                              <dd className="mt-2 font-mono text-xs text-blue-300">
                                {selectedCase.case_id}
                              </dd>
                            </div>
                          </dl>
                        </section>

                        <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <h3 className="font-semibold">Observable Indicators</h3>

                          <div className="mt-4 space-y-4 text-sm">
                            <div>
                              <p className="text-xs uppercase tracking-wider text-slate-600">
                                IP addresses
                              </p>
                              <p className="mt-2 break-all text-slate-300">
                                {reportIps.length ? reportIps.join(", ") : "None"}
                              </p>
                            </div>

                            <div>
                              <p className="text-xs uppercase tracking-wider text-slate-600">
                                URLs
                              </p>
                              <p className="mt-2 break-all text-slate-300">
                                {reportUrls.length ? reportUrls.join(", ") : "None"}
                              </p>
                            </div>

                            <div>
                              <p className="text-xs uppercase tracking-wider text-slate-600">
                                Attachments
                              </p>
                              <p className="mt-2 break-all text-slate-300">
                                {reportAttachments.length
                                  ? reportAttachments
                                      .map((item) =>
                                        typeof item === "string"
                                          ? item
                                          : text((item as Record<string, unknown>)?.filename)
                                      )
                                      .join(", ")
                                  : "None"}
                              </p>
                            </div>
                          </div>
                        </section>
                      </div>

                      <section className="grid gap-6 lg:grid-cols-2">
                        <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">Email facts</p>
                          <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                            <div><dt className="text-xs text-slate-500">Subject</dt><dd className="mt-1 text-slate-200">{reportSubject}</dd></div>
                            <div><dt className="text-xs text-slate-500">Received / Date</dt><dd className="mt-1 text-slate-200">{dateText(text(reportCase.email?.date, selectedCase.created_at))}</dd></div>
                            <div><dt className="text-xs text-slate-500">Reply-To</dt><dd className="mt-1 break-all text-slate-300">{text(reportCase.email?.reply_to, "Not available")}</dd></div>
                            <div><dt className="text-xs text-slate-500">Return-Path</dt><dd className="mt-1 break-all text-slate-300">{text(reportCase.email?.return_path, "Not available")}</dd></div>
                            <div><dt className="text-xs text-slate-500">Message-ID</dt><dd className="mt-1 break-all font-mono text-[11px] text-slate-400">{text(reportCase.email?.message_id, "Not available")}</dd></div>
                            <div><dt className="text-xs text-slate-500">Delivery route</dt><dd className="mt-1 text-slate-300">{routeHops.length ? `${routeHops.length} preserved Received header(s)` : "No Received headers stored"}</dd></div>
                          </dl>
                        </div>
                        <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">Authentication evidence</p>
                          <div className="mt-4 grid gap-3 sm:grid-cols-3">
                            {(["spf", "dkim", "dmarc"] as const).map((name) => <div key={name} className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"><p className="text-[10px] uppercase tracking-wider text-slate-500">{name}</p><p className={`mt-2 text-sm font-bold ${authResult(auth[name]) === "PASS" ? "text-emerald-300" : authResult(auth[name]) === "FAIL" || authResult(auth[name]) === "SOFTFAIL" ? "text-red-300" : "text-slate-200"}`}>{authResult(auth[name])}</p></div>)}
                          </div>
                          <p className="mt-4 text-[11px] leading-5 text-slate-500">Authentication results are copied from the preserved message evidence. A missing result is reported as unknown and is not treated as a pass.</p>
                        </div>
                      </section>

                      <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">Forensic evidence summary</p><h3 className="mt-1 font-semibold">What the system observed</h3></div><span className="text-xs text-slate-500">Raw evidence remains available in the selected case</span></div>
                        <div className="mt-5 grid gap-4 lg:grid-cols-3">
                          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"><p className="text-xs font-semibold text-slate-200">Headers & route</p><p className="mt-2 text-sm text-slate-400">{routeHops.length ? `${routeHops.length} Received hop(s) preserved for review.` : "No route headers were available."}</p><p className="mt-2 text-[11px] text-slate-600">Provider/relay locations are infrastructure evidence, not sender physical location.</p></div>
                          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"><p className="text-xs font-semibold text-slate-200">Content & identity</p><p className="mt-2 text-sm text-slate-400">{contentFindings.length + senderFindings.length} content or sender finding(s) recorded.</p><p className="mt-2 text-[11px] text-slate-600">{impersonationFindings.length ? text(impersonationFindings[0].detail, "Impersonation signal recorded.") : "No separate impersonation conclusion stored."}</p></div>
                          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"><p className="text-xs font-semibold text-slate-200">Files & links</p><p className="mt-2 text-sm text-slate-400">{reportUrls.length} URL(s), {reportAttachments.length} attachment(s), {urlFindings.length + attachmentFindings.length} related finding(s).</p><p className="mt-2 text-[11px] text-slate-600">Attachments were statically inspected; they were not executed.</p></div>
                        </div>
                      </section>

                      <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                        <h3 className="font-semibold">Executive Summary</h3>
                        <p className="mt-4 text-sm leading-7 text-slate-300">
                          {reportSummary}
                        </p>
                      </section>

                      <div className="grid gap-6 lg:grid-cols-2">
                        <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <h3 className="font-semibold">Local ML Triage</h3>
                          <p className="mt-3 text-sm text-slate-300">{text(reportCase.ml_analysis?.ml_classification, "Unavailable")} · {reportCase.ml_analysis?.ml_confidence != null ? `${Math.round(reportCase.ml_analysis.ml_confidence * 100)}% confidence` : "confidence unavailable"}</p>
                          <p className="mt-3 text-xs leading-5 text-slate-500">{text(reportCase.ml_analysis?.ml_disclaimer, "The local ML result is supplemental and does not replace deterministic forensic analysis.")}</p>
                        </section>
                        <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                          <h3 className="font-semibold">Attribution Support</h3>
                          <div className="mt-3 space-y-2">{(reportCase.attribution_support?.items || []).slice(0, 6).map((item, index) => <div key={`${item.indicator}-${index}`} className="flex items-start justify-between gap-3 text-xs"><span className="text-slate-400">{item.indicator}</span><span className="font-semibold text-slate-200">{item.status || "UNKNOWN"}</span></div>)}</div>
                          <p className="mt-4 text-[11px] leading-5 text-slate-500">{text(reportCase.attribution_support?.disclaimer, "Investigative support based on observable technical evidence; not actor attribution.")}</p>
                        </section>
                      </div>

                      <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                        <div className="flex items-center justify-between gap-3"><h3 className="font-semibold">Chain of Custody</h3><span className="text-xs text-slate-500">{reportCase.chain_of_custody?.length || 0} events</span></div>
                        <div className="mt-4 space-y-2">{(reportCase.chain_of_custody || []).map((event, index) => <div key={`${event.event_type}-${index}`} className="flex flex-col gap-1 border-l border-blue-500/30 pl-3 text-xs sm:flex-row sm:items-center sm:justify-between"><span className="font-semibold text-blue-300">{event.event_type}</span><span className="text-slate-400">{event.description}</span><span className="text-slate-600">{dateText(event.timestamp)}</span></div>)}</div>
                        <p className="mt-4 text-[11px] text-slate-500">Evidence hashes are retained where relevant; raw email bytes are not stored in the audit trail.</p>
                      </section>

                      <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <h3 className="font-semibold">Cross-Case Correlation</h3>
                            <p className="mt-1 text-xs text-slate-500">
                              Shared observable indicators across stored investigations.
                            </p>
                          </div>

                          <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400">
                            {correlation?.related_case_count || 0} related
                          </span>
                        </div>

                        {loadingCorrelation ? (
                          <p className="mt-5 text-sm text-slate-500">
                            Comparing observable indicators with previous investigations...
                          </p>
                        ) : (
                          <>
                            <div className="mt-5 grid gap-4 sm:grid-cols-3">
                              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                                <p className="text-[10px] uppercase tracking-wider text-slate-600">
                                  Best Match
                                </p>
                                <p className="mt-2 text-xl font-bold">
                                  {correlation?.best_match_score || 0}/100
                                </p>
                              </div>

                              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                                <p className="text-[10px] uppercase tracking-wider text-slate-600">
                                  Related Cases
                                </p>
                                <p className="mt-2 text-xl font-bold">
                                  {correlation?.related_case_count || 0}
                                </p>
                              </div>

                              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                                <p className="text-[10px] uppercase tracking-wider text-slate-600">
                                  Report Type
                                </p>
                                <p className="mt-2 text-sm font-semibold">
                                  Forensic Case Report
                                </p>
                              </div>
                            </div>

                            {correlation?.related_cases?.length ? (
                              <div className="mt-5 grid gap-2 sm:grid-cols-2">
                                {correlation.related_cases.slice(0, 6).map((match) => (
                                  <button
                                    key={match.case_id}
                                    type="button"
                                    onClick={() => openCase(match.case_id)}
                                    className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-3 text-left hover:border-slate-700"
                                  >
                                    <div className="flex items-center justify-between gap-3">
                                      <span className="font-mono text-[10px] text-blue-300">
                                        {match.case_id}
                                      </span>
                                      <span className="text-[10px] text-slate-500">
                                        {match.similarity_score || 0}/100
                                      </span>
                                    </div>
                                    <div className="mt-1 truncate text-xs text-slate-400">
                                      {match.subject || match.evidence_id || "Related case"}
                                    </div>
                                  </button>
                                ))}
                              </div>
                            ) : (
                              <p className="mt-5 text-sm text-slate-500">
                                No meaningful cross-case overlap was found.
                              </p>
                            )}

                            <p className="mt-5 text-[11px] leading-5 text-slate-500">
                              Correlation is based on shared observable indicators. It is not
                              proof that cases were created by the same actor. Infrastructure
                              location is not sender physical location.
                            </p>
                          </>
                        )}
                      </section>

                      <div className="flex flex-wrap gap-3 print:hidden">
                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/investigations?case_id=${encodeURIComponent(
                                selectedId
                              )}`
                            )
                          }
                          className="rounded-lg border border-slate-700 px-4 py-3 text-xs font-semibold text-slate-300 hover:text-white"
                        >
                          Open Investigation
                        </button>

                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/threat-graph?case_id=${encodeURIComponent(
                                selectedId
                              )}`
                            )
                          }
                          className="rounded-lg border border-slate-700 px-4 py-3 text-xs font-semibold text-slate-300 hover:text-white"
                        >
                          Threat Graph
                        </button>

                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/threat-intelligence?case_id=${encodeURIComponent(
                                selectedId
                              )}`
                            )
                          }
                          className="rounded-lg border border-slate-700 px-4 py-3 text-xs font-semibold text-slate-300 hover:text-white"
                        >
                          Threat Intelligence
                        </button>

                        <button
                          type="button"
                          onClick={() =>
                            navigate(
                              `/ai-investigator?case_id=${encodeURIComponent(
                                selectedId
                              )}`
                            )
                          }
                          className="rounded-lg bg-blue-600 px-4 py-3 text-xs font-semibold text-white hover:bg-blue-500"
                        >
                          AI Investigator
                        </button>
                      </div>
                    </>
                  )}
                </div>
              )}
            </section>
          </div>
        </div>
      </section>
    </main>
  );
}

export default function ReportsPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#080c14]" />}>
      <ReportsContent />
    </Suspense>
  );
}
