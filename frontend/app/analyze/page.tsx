"use client";

import { ChangeEvent, DragEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

/* ============================================================
   TYPES
   ============================================================ */

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;

interface EvidenceItem {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  detail: string;
}

interface ThreatComponent {
  score: number;
  max_score: number;
  findings: string[];
}

interface ThreatComponents {
  authentication: ThreatComponent;
  url_domain: ThreatComponent;
  content_social_engineering: ThreatComponent;
  infrastructure: ThreatComponent;
  attachments: ThreatComponent;
  correlation: ThreatComponent;
}

interface ThreatDetection {
  classification: string;
  risk_score: number;
  risk_level: string;
  confidence: string;
  summary: string;
  components: ThreatComponents;
  evidence: EvidenceItem[];
  limitations: string[];
}

interface AuthenticationData {
  authentication_results: string;
  spf: string;
  dkim: string;
  dmarc: string;
}

interface EmailData {
  subject: string;
  from: string;
  to: string;
  reply_to: string;
  return_path: string;
  message_id: string;
  date: string | null;
}

interface FileData {
  filename: string;
  content_type: string;
  size: number;
}

interface EvidenceData {
  evidence_id: string;
  sha256: string;
  size: number;
  captured_at: string;
  preservation: string;
}

interface IndicatorData {
  urls: string[];
  ips: string[];
}

interface Attachment {
  filename: string;
  content_type: string;
  size: number;
}

interface RelayHop {
  hop: number;
  raw: string;
  ips: string[];
}

interface AnalysisResult {
  status: string;
  file: FileData;
  evidence: EvidenceData;
  email: EmailData;
  authentication: AuthenticationData;
  headers: Record<string, string>;
  smtp_relay: RelayHop[];
  indicators: IndicatorData;
  url_analysis: unknown[];
  attachments: Attachment[];
  attachment_analysis: {
    high_risk_files: string[];
    macro_files: string[];
    archive_files: string[];
    findings: unknown[];
  };
  body: {
    plain_text_length: number;
    html_length: number;
  };
  sender_analysis: {
    sender_domain: string;
    reply_to_domain: string;
    return_path_domain: string;
    reply_to_mismatch: boolean;
    return_path_mismatch: boolean;
    findings: unknown[];
  };
  impersonation: {
    display_name: string;
    sender_address: string;
    matched_brand: string | null;
    findings: unknown[];
  };
  bec_analysis: {
    potential_bec: boolean;
    signal_count: number;
    signals: string[];
  };
  investigation?: {
    case_id: string;
    created_at: string;
    storage: string;
  };
  threat_detection: ThreatDetection;
}


/* ============================================================
   SIDEBAR
   ============================================================ */

const sidebarItems = [
  { name: "Dashboard", icon: "▣", path: "/" },
  { name: "Investigation", icon: "⌕", path: "/investigations" },
  { name: "Threat Graph", icon: "◎", path: "/threat-graph" },
  { name: "Geolocation", icon: "◈", path: "/threat-intelligence" },
  { name: "AI Help", icon: "✦", path: "/ai-investigator" },
  { name: "Reports", icon: "▤", path: "/reports" },
  { name: "Help", icon: "?", path: "/help" },
];


/* ============================================================
   MAIN COMPONENT
   ============================================================ */

export default function AnalyzeEmail() {
  const router = useRouter();

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);

  const [fileName, setFileName] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [dragging, setDragging] = useState(false);

  const [analysisResult, setAnalysisResult] =
    useState<AnalysisResult | null>(null);

  const [analyzing, setAnalyzing] = useState(false);

  const [error, setError] = useState("");

  /* ============================================================
     REOPEN A STORED INVESTIGATION
     ============================================================ */

  useEffect(() => {
    let cancelled = false;

    const reopenStoredCase = async () => {
      const params = new URLSearchParams(window.location.search);
      const caseId = params.get("case_id");

      if (!caseId) return;

      try {
        setError("");
        const response = await fetch(
          `${API_BASE}/api/investigations/${encodeURIComponent(caseId)}/analysis`,
          { cache: "no-store" }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.detail || "Unable to reopen this investigation.");
        }

        if (!cancelled && data?.analysis) {
          setAnalysisResult(data.analysis as AnalysisResult);
          try {
            sessionStorage.setItem("mailtrace_analysis", JSON.stringify(data.analysis));
            sessionStorage.setItem(
              "mailtrace_latest_evidence_id",
              String(data.analysis?.evidence?.evidence_id || "")
            );
            if (data.analysis?.investigation?.case_id) {
              sessionStorage.setItem(
                "mailtrace_latest_case_id",
                String(data.analysis.investigation.case_id)
              );
            }
          } catch {
            // Session storage is optional; the backend remains the source of truth.
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to reopen this investigation."
          );
        }
      }
    };

    void reopenStoredCase();

    return () => {
      cancelled = true;
    };
  }, []);

  /* ============================================================
     NAVIGATION
     ============================================================ */

  const handleNavigation = (path: string | null) => {
    if (path) {
      router.push(path);
    }
  };


  /* ============================================================
     FILE HANDLING
     ============================================================ */

  const handleFile = (file: File | undefined) => {
    if (!file) {
      return;
    }

    setError("");

    const extension = "." + file.name.split(".").pop()?.toLowerCase();

    if (extension !== ".eml" && extension !== ".msg") {
      setError("Please select a valid .eml or .msg email file.");
      return;
    }

    setSelectedFile(file);
    setFileName(file.name);

    // Clear previous analysis
    setAnalysisResult(null);
  };


  const handleInputChange = (
    event: ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];

    handleFile(file);
  };


  const handleDrop = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragging(false);

    const file = event.dataTransfer.files?.[0];

    handleFile(file);
  };


  const handleDragOver = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragging(true);
  };


  const handleDragLeave = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragging(false);
  };


  const removeFile = () => {
    setSelectedFile(null);
    setFileName("");
    setAnalysisResult(null);
    setError("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };


  /* ============================================================
     ANALYZE EMAIL
     ============================================================ */

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError("Please select an email file first.");
      return;
    }

    setAnalyzing(true);
    setError("");
    setAnalysisResult(null);

    try {
      const formData = new FormData();

      formData.append(
        "file",
        selectedFile
      );

      const response = await fetch(
        `${API_BASE}/api/analyze`,
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            "Email analysis failed."
        );
      }

      setAnalysisResult(data);

sessionStorage.setItem(
        "mailtrace_analysis",
        JSON.stringify(data)
      );

      if (data?.evidence?.evidence_id) {
        sessionStorage.setItem(
          "mailtrace_latest_evidence_id",
          String(data.evidence.evidence_id)
        );
      }

      if (data?.investigation?.case_id) {
        sessionStorage.setItem(
          "mailtrace_latest_case_id",
          String(data.investigation.case_id)
        );
      }
      console.log(
        "MailTrace AI analysis:",
        data
      );

      // Give React time to render the result before scrolling.
      setTimeout(() => {
        resultRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 150);

    } catch (err) {
      console.error(err);

      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to MailTrace AI backend."
      );
    } finally {
      setAnalyzing(false);
    }
  };


  /* ============================================================
     NEW ANALYSIS
     ============================================================ */

  const startNewAnalysis = () => {
    window.history.replaceState({}, "", "/analyze");
    setSelectedFile(null);
    setFileName("");
    setAnalysisResult(null);
    setError("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };


  return (
    <div className="min-h-screen bg-[#080c14] text-white">

      {/* ======================================================
          SIDEBAR
          ====================================================== */}

      <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">

        {/* Logo */}

        <div className="border-b border-slate-800 px-6 py-6">

          <div className="text-xl font-bold tracking-wide text-white">
            MailTrace <span className="text-blue-500">AI</span>
          </div>

          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">
            Email Forensics Platform
          </div>

        </div>


        {/* Navigation */}

        <nav className="flex-1 px-3 py-5">

          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
            Workspace
          </div>

          <div className="space-y-1">

            {sidebarItems.map((item) => {
              const active = item.name === "Analyze Email";
              const disabled = !item.path;

              return (
                <button
                  key={item.name}
                  onClick={() => handleNavigation(item.path)}
                  disabled={disabled}
                  className={`group flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left text-sm transition ${
                    active
                      ? "border border-blue-500/20 bg-blue-500/10 text-blue-400"
                      : disabled
                        ? "cursor-default text-slate-600"
                        : "text-slate-400 hover:bg-slate-800/70 hover:text-white"
                  }`}
                >
                  <span
                    className={`flex h-7 w-7 items-center justify-center rounded-md text-sm ${
                      active
                        ? "bg-blue-500/15 text-blue-400"
                        : "bg-slate-800 text-slate-400 group-hover:text-white"
                    }`}
                  >
                    {item.icon}
                  </span>
                  <span>{item.name}</span>
                </button>
              );
            })}

          </div>

        </nav>


        {/* Bottom sidebar */}

        <div className="border-t border-slate-800 p-4">

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">

            <div className="flex items-center gap-3">

              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-400">
                PA
              </div>

              <div className="min-w-0">

                <div className="truncate text-sm font-medium text-white">
                  Analyst
                </div>

                <div className="truncate text-xs text-slate-500">
                  Security Operations
                </div>

              </div>

            </div>

          </div>

        </div>

      </aside>


      {/* ======================================================
          MAIN CONTENT
          ====================================================== */}

      <main className="ml-64 min-h-screen">

        {/* Header */}

        <header className="sticky top-0 z-20 border-b border-slate-800 bg-[#080c14]/95 px-8 py-5 backdrop-blur">

          <div className="flex items-center justify-between">

            <div>

              <div className="text-xs uppercase tracking-[0.18em] text-blue-400">
                Forensic Analysis
              </div>

              <h1 className="mt-1 text-2xl font-bold text-white">
                Analyze Email
              </h1>

              <p className="mt-1 text-sm text-slate-500">
                Upload an email and perform automated
                forensic threat analysis.
              </p>

            </div>


            <div className="flex items-center gap-3">

              <div className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-400">
                ● Backend Online
              </div>

            </div>

          </div>

        </header>


        {/* Content */}

        <div className="space-y-6 p-8">

          {/* ==================================================
              UPLOAD CARD
              ================================================== */}

          <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-white">
                Email Evidence
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Supported formats: EML and MSG
              </p>

            </div>


            {/* Dropzone */}

            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() =>
                fileInputRef.current?.click()
              }
              className={`cursor-pointer rounded-2xl border-2 border-dashed p-10 text-center transition ${
                dragging
                  ? "border-blue-500 bg-blue-500/10"
                  : "border-slate-700 bg-slate-950/30 hover:border-slate-600 hover:bg-slate-900/40"
              }`}
            >

              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg,message/rfc822"
                onChange={handleInputChange}
                className="hidden"
              />


              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-blue-500/10 text-3xl text-blue-400">
                ✉
              </div>


              <h3 className="mt-5 text-base font-semibold text-white">
                Drop your email here
              </h3>


              <p className="mt-2 text-sm text-slate-500">
                or click to browse from your computer
              </p>


              <div className="mt-5 inline-flex rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs text-slate-300">
                Browse .EML / .MSG
              </div>

            </div>


            {/* Selected file */}

            {selectedFile && (

              <div className="mt-4 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/60 p-4">

                <div className="flex min-w-0 items-center gap-3">

                  <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400">
                    ✉
                  </div>

                  <div className="min-w-0">

                    <div className="truncate text-sm font-medium text-white">
                      {fileName}
                    </div>

                    <div className="mt-1 text-xs text-slate-500">
                      {(selectedFile.size / 1024).toFixed(2)} KB
                      {" • "}
                      {selectedFile.type || "Email file"}
                    </div>

                  </div>

                </div>


                <button
                  onClick={(event) => {
                    event.stopPropagation();
                    removeFile();
                  }}
                  className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-400 transition hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-400"
                >
                  Remove
                </button>

              </div>

            )}


            {/* Error */}

            {error && (

              <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/10 p-4">

                <div className="flex gap-3">

                  <span className="text-red-400">
                    ⚠
                  </span>

                  <div>

                    <div className="text-sm font-medium text-red-300">
                      Analysis Error
                    </div>

                    <div className="mt-1 text-xs leading-5 text-red-400/80">
                      {error}
                    </div>

                  </div>

                </div>

              </div>

            )}


            {/* Analyze button */}

            <div className="mt-5 flex justify-end">

              <button
                onClick={handleAnalyze}
                disabled={!selectedFile || analyzing}
                className="rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
              >

                {analyzing ? (
                  <span className="flex items-center gap-2">
                    <span className="animate-spin">
                      ◌
                    </span>
                    Analyzing Evidence...
                  </span>
                ) : (
                  "Analyze Email"
                )}

              </button>

            </div>

          </section>


          {/* ==================================================
              ANALYSIS RESULT
              ================================================== */}

          {analysisResult && (

            <div
              ref={resultRef}
              className="space-y-6"
            >

              {/* =================================================
                  THREAT DETECTION HERO
                  ================================================= */}

              <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">

                <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">

                  <div>

                    <div className="text-xs uppercase tracking-[0.18em] text-blue-400">
                      Automated Threat Detection
                    </div>

                    <h2 className="mt-2 text-2xl font-bold text-white">
                      {analysisResult.threat_detection.classification}
                    </h2>

                    <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                      {analysisResult.threat_detection.summary}
                    </p>

                  </div>


                  <div className="flex items-center gap-6">

                    {/* Risk score */}

                    <RiskScore
                      score={
                        analysisResult
                          .threat_detection
                          .risk_score
                      }
                    />


                    <div>

                      <div className="text-xs uppercase tracking-wider text-slate-500">
                        Risk Level
                      </div>

                      <RiskBadge
                        level={
                          analysisResult
                            .threat_detection
                            .risk_level
                        }
                      />

                      <div className="mt-4 text-xs uppercase tracking-wider text-slate-500">
                        Confidence
                      </div>

                      <ConfidenceBadge
                        confidence={
                          analysisResult
                            .threat_detection
                            .confidence
                        }
                      />

                    </div>

                  </div>

                </div>


                {/* Risk progress */}

                <div className="mt-7">

                  <div className="mb-2 flex items-center justify-between text-xs">

                    <span className="text-slate-500">
                      Threat Risk
                    </span>

                    <span className="font-medium text-slate-300">
                      {analysisResult.threat_detection.risk_score}
                      /100
                    </span>

                  </div>


                  <div className="h-3 overflow-hidden rounded-full bg-slate-800">

                    <div
                      className={`h-full rounded-full transition-all ${
                        getRiskBarColor(
                          analysisResult
                            .threat_detection
                            .risk_score
                        )
                      }`}
                      style={{
                        width: `${Math.min(
                          analysisResult
                            .threat_detection
                            .risk_score,
                          100
                        )}%`,
                      }}
                    />

                  </div>


                  <div className="mt-2 flex justify-between text-[10px] text-slate-600">
                    <span>LOW</span>
                    <span>MEDIUM</span>
                    <span>HIGH</span>
                    <span>CRITICAL</span>
                  </div>

                </div>

              </section>


              {/* =================================================
                  SCORE COMPONENTS
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Risk Score Breakdown"
                  subtitle="Explainable scoring based on forensic evidence"
                />


                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">

                  <ScoreCard
                    title="Authentication"
                    icon="✓"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .authentication
                    }
                  />

                  <ScoreCard
                    title="URL / Domain"
                    icon="⌁"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .url_domain
                    }
                  />

                  <ScoreCard
                    title="Content / Social Engineering"
                    icon="!"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .content_social_engineering
                    }
                  />

                  <ScoreCard
                    title="Infrastructure"
                    icon="◉"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .infrastructure
                    }
                  />

                  <ScoreCard
                    title="Attachments"
                    icon="▣"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .attachments
                    }
                  />

                  <ScoreCard
                    title="Campaign Correlation"
                    icon="◎"
                    component={
                      analysisResult
                        .threat_detection
                        .components
                        .correlation
                    }
                  />

                </div>

              </section>


              {/* =================================================
                  SECURITY EVIDENCE
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Security Evidence"
                  subtitle={`${analysisResult.threat_detection.evidence.length} evidence item(s) identified`}
                />


                <div className="overflow-hidden rounded-2xl border border-slate-800 bg-[#0d1420]">

                  {analysisResult.threat_detection.evidence.length === 0 ? (

                    <div className="p-8 text-center text-sm text-slate-500">
                      No strong security evidence was identified.
                    </div>

                  ) : (

                    <div className="divide-y divide-slate-800">

                      {analysisResult.threat_detection.evidence.map(
                        (item) => (

                          <EvidenceRow
                            key={item.id}
                            item={item}
                          />

                        )
                      )}

                    </div>

                  )}

                </div>

              </section>


              {/* =================================================
                  EMAIL INFORMATION
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Email Information"
                  subtitle="Parsed message metadata"
                />


                <div className="grid gap-4 lg:grid-cols-2">

                  <InfoCard
                    title="Message"
                    items={[
                      [
                        "Subject",
                        analysisResult.email.subject || "—",
                      ],
                      [
                        "From",
                        analysisResult.email.from || "—",
                      ],
                      [
                        "To",
                        analysisResult.email.to || "—",
                      ],
                      [
                        "Message ID",
                        analysisResult.email.message_id || "—",
                      ],
                    ]}
                  />


                  <InfoCard
                    title="Routing"
                    items={[
                      [
                        "Reply-To",
                        analysisResult.email.reply_to || "—",
                      ],
                      [
                        "Return-Path",
                        analysisResult.email.return_path || "—",
                      ],
                      [
                        "Sender Domain",
                        analysisResult.sender_analysis.sender_domain || "—",
                      ],
                      [
                        "Received Hops",
                        String(
                          analysisResult.smtp_relay.length
                        ),
                      ],
                    ]}
                  />

                </div>

              </section>


              {/* =================================================
                  AUTHENTICATION
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Email Authentication"
                  subtitle="SPF, DKIM and DMARC analysis"
                />


                <div className="grid gap-4 md:grid-cols-3">

                  <AuthenticationCard
                    name="SPF"
                    value={
                      analysisResult.authentication.spf
                    }
                  />

                  <AuthenticationCard
                    name="DKIM"
                    value={
                      analysisResult.authentication.dkim
                    }
                  />

                  <AuthenticationCard
                    name="DMARC"
                    value={
                      analysisResult.authentication.dmarc
                    }
                  />

                </div>

              </section>


              {/* =================================================
                  INDICATORS
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Indicators of Compromise"
                  subtitle="Extracted URLs and IP addresses"
                />


                <div className="grid gap-4 lg:grid-cols-2">

                  <IndicatorCard
                    title="URLs"
                    count={
                      analysisResult.indicators.urls.length
                    }
                    values={
                      analysisResult.indicators.urls
                    }
                  />

                  <IndicatorCard
                    title="IP Addresses"
                    count={
                      analysisResult.indicators.ips.length
                    }
                    values={
                      analysisResult.indicators.ips
                    }
                  />

                </div>

              </section>


              {/* =================================================
                  ATTACHMENTS
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Attachments"
                  subtitle="Attachment metadata and security indicators"
                />


                <div className="rounded-2xl border border-slate-800 bg-[#0d1420]">

                  {analysisResult.attachments.length === 0 ? (

                    <div className="p-7 text-center text-sm text-slate-500">
                      No attachments detected.
                    </div>

                  ) : (

                    <div className="divide-y divide-slate-800">

                      {analysisResult.attachments.map(
                        (attachment, index) => (

                          <div
                            key={`${attachment.filename}-${index}`}
                            className="flex items-center justify-between gap-4 p-5"
                          >

                            <div className="flex min-w-0 items-center gap-3">

                              <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-slate-800 text-slate-300">
                                ▣
                              </div>

                              <div className="min-w-0">

                                <div className="truncate text-sm font-medium text-white">
                                  {attachment.filename}
                                </div>

                                <div className="mt-1 text-xs text-slate-500">
                                  {attachment.content_type}
                                  {" • "}
                                  {formatBytes(
                                    attachment.size
                                  )}
                                </div>

                              </div>

                            </div>


                            <AttachmentRisk
                              filename={
                                attachment.filename
                              }
                            />

                          </div>

                        )
                      )}

                    </div>

                  )}

                </div>

              </section>


              {/* =================================================
                  SMTP RELAY
                  ================================================= */}

              <section>

                <SectionTitle
                  title="SMTP Relay Path"
                  subtitle="Received-header reconstruction"
                />


                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">

                  {analysisResult.smtp_relay.length === 0 ? (

                    <div className="py-6 text-center text-sm text-slate-500">
                      No Received headers were detected.
                    </div>

                  ) : (

                    <div className="space-y-3">

                      {analysisResult.smtp_relay.map(
                        (hop) => (

                          <div
                            key={hop.hop}
                            className="flex gap-4"
                          >

                            <div className="flex flex-col items-center">

                              <div className="flex h-9 w-9 items-center justify-center rounded-full border border-blue-500/20 bg-blue-500/10 text-xs font-semibold text-blue-400">
                                {hop.hop}
                              </div>

                              {hop.hop !==
                                analysisResult.smtp_relay.length && (
                                <div className="mt-2 h-full w-px bg-slate-800" />
                              )}

                            </div>


                            <div className="min-w-0 flex-1 rounded-xl border border-slate-800 bg-slate-950/40 p-4">

                              <div className="flex flex-wrap items-center gap-2">

                                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                                  Hop {hop.hop}
                                </span>

                                {hop.ips.map(
                                  (ip) => (
                                    <span
                                      key={ip}
                                      className="rounded-md bg-blue-500/10 px-2 py-1 font-mono text-xs text-blue-400"
                                    >
                                      {ip}
                                    </span>
                                  )
                                )}

                              </div>


                              <p className="mt-3 break-words text-xs leading-5 text-slate-500">
                                {hop.raw}
                              </p>

                            </div>

                          </div>

                        )
                      )}

                    </div>

                  )}

                </div>

              </section>


              {/* =================================================
                  FORENSIC EVIDENCE
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Evidence Preservation"
                  subtitle="Chain-of-custody foundation"
                />


                <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">

                  <div className="grid gap-5 md:grid-cols-2">

                    <EvidenceMetadata
                      label="Evidence ID"
                      value={
                        analysisResult.evidence.evidence_id
                      }
                    />

                    <EvidenceMetadata
                      label="Captured At"
                      value={
                        analysisResult.evidence.captured_at
                      }
                    />

                    <EvidenceMetadata
                      label="SHA-256"
                      value={
                        analysisResult.evidence.sha256
                      }
                      mono
                    />

                    <EvidenceMetadata
                      label="Original File Size"
                      value={
                        formatBytes(
                          analysisResult.evidence.size
                        )
                      }
                    />

                  </div>


                  <div className="mt-5 rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4">

                    <div className="flex gap-3">

                      <span className="text-emerald-400">
                        ✓
                      </span>

                      <div>

                        <div className="text-sm font-medium text-emerald-300">
                          Evidence preserved
                        </div>

                        <div className="mt-1 text-xs leading-5 text-slate-500">
                          {analysisResult.evidence.preservation}
                        </div>

                      </div>

                    </div>

                  </div>

                </div>

              </section>


              {/* =================================================
                  LIMITATIONS
                  ================================================= */}

              <section>

                <SectionTitle
                  title="Analysis Limitations"
                  subtitle="Important interpretation notes"
                />


                <div className="rounded-2xl border border-amber-500/10 bg-amber-500/5 p-5">

                  <div className="space-y-3">

                    {analysisResult.threat_detection.limitations.map(
                      (limitation, index) => (

                        <div
                          key={index}
                          className="flex gap-3 text-sm leading-6 text-slate-400"
                        >

                          <span className="text-amber-400">
                            •
                          </span>

                          <span>
                            {limitation}
                          </span>

                        </div>

                      )
                    )}

                  </div>

                </div>

              </section>


              {/* =================================================
                  ACTIONS
                  ================================================= */}

              <div className="flex flex-col gap-4 border-t border-slate-800 pt-6 pb-8 lg:flex-row lg:items-center lg:justify-between">

                <div className="flex flex-wrap gap-3">

                  <a
                    href={
                      analysisResult?.investigation?.case_id
                        ? `/investigations?case_id=${encodeURIComponent(analysisResult.investigation.case_id)}`
                        : "/investigations"
                    }
                    className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 px-5 py-3 text-sm font-semibold text-cyan-300 transition hover:bg-cyan-500/15"
                  >
                    Open Investigation
                  </a>

                  <a
                    href={analysisResult?.investigation?.case_id ? `/threat-graph?case_id=${encodeURIComponent(analysisResult.investigation.case_id)}` : "/threat-graph"}
                    className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/10 px-5 py-3 text-sm font-semibold text-violet-300 transition hover:bg-violet-500/15"
                  >
                    Threat Graph
                  </a>

                  <a
                    href={analysisResult?.investigation?.case_id ? `/threat-intelligence?case_id=${encodeURIComponent(analysisResult.investigation.case_id)}` : "/threat-intelligence"}
                    className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-5 py-3 text-sm font-semibold text-emerald-300 transition hover:bg-emerald-500/15"
                  >
                    Threat Intelligence
                  </a>

                  <a
                    href={analysisResult?.investigation?.case_id ? `/ai-investigator?case_id=${encodeURIComponent(analysisResult.investigation.case_id)}` : "/ai-investigator"}
                    className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-fuchsia-500/20 bg-fuchsia-500/10 px-5 py-3 text-sm font-semibold text-fuchsia-300 transition hover:bg-fuchsia-500/15"
                  >
                    AI Investigator
                  </a>

                  <a
                    href={analysisResult?.investigation?.case_id ? `/reports?case_id=${encodeURIComponent(analysisResult.investigation.case_id)}` : "/reports"}
                    className="inline-flex cursor-pointer items-center justify-center rounded-xl border border-slate-700 bg-slate-900 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:bg-slate-800 hover:text-white"
                  >
                    Forensic Report
                  </a>

                </div>

                <div className="flex flex-wrap gap-3">

                  <button
                    onClick={startNewAnalysis}
                    className="rounded-xl border border-slate-700 bg-slate-900 px-5 py-3 text-sm font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white"
                  >
                    + New Analysis
                  </button>

                  <button
                    onClick={() => window.print()}
                    className="rounded-xl border border-blue-500/20 bg-blue-500/10 px-5 py-3 text-sm font-medium text-blue-400 transition hover:bg-blue-500/15"
                  >
                    Print Report
                  </button>

                </div>

              </div>

            </div>

          )}


          {/* ==================================================
              EMPTY STATE / FEATURES
              ================================================== */}

          {!analysisResult && (

            <section className="grid gap-4 md:grid-cols-3">

              <FeatureCard
                icon="⌕"
                title="Header Forensics"
                description="Analyze Received, Return-Path, Message-ID, Reply-To and authentication headers."
              />

              <FeatureCard
                icon="◈"
                title="Threat Detection"
                description="Identify phishing, BEC, impersonation, suspicious URLs and risky attachments."
              />

              <FeatureCard
                icon="◎"
                title="Evidence Preservation"
                description="Generate a SHA-256 evidence hash and preserve the original email identity."
              />

            </section>

          )}

        </div>

      </main>

    </div>
  );
}


/* ============================================================
   RISK SCORE COMPONENT
   ============================================================ */

function RiskScore({
  score,
}: {
  score: number;
}) {

  return (
    <div className="relative flex h-28 w-28 items-center justify-center">

      <div
        className={`absolute inset-0 rounded-full bg-gradient-to-br ${getRiskGradient(
          score
        )} opacity-20 blur-xl`}
      />

      <div className="relative flex h-28 w-28 flex-col items-center justify-center rounded-full border border-slate-700 bg-slate-950">

        <div
          className={`text-3xl font-bold ${getRiskTextColor(
            score
          )}`}
        >
          {score}
        </div>

        <div className="text-[10px] uppercase tracking-wider text-slate-500">
          / 100
        </div>

      </div>

    </div>
  );
}


/* ============================================================
   RISK BADGE
   ============================================================ */

function RiskBadge({
  level,
}: {
  level: string;
}) {

  const normalized =
    level.toUpperCase();

  let classes =
    "border-slate-700 bg-slate-800 text-slate-300";

  if (normalized === "CRITICAL") {
    classes =
      "border-red-500/30 bg-red-500/10 text-red-400";
  } else if (normalized === "HIGH") {
    classes =
      "border-orange-500/30 bg-orange-500/10 text-orange-400";
  } else if (normalized === "MEDIUM") {
    classes =
      "border-amber-500/30 bg-amber-500/10 text-amber-400";
  } else if (normalized === "LOW") {
    classes =
      "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
  }

  return (
    <div
      className={`mt-1 inline-flex rounded-lg border px-3 py-1.5 text-xs font-semibold ${classes}`}
    >
      {normalized}
    </div>
  );
}


/* ============================================================
   CONFIDENCE BADGE
   ============================================================ */

function ConfidenceBadge({
  confidence,
}: {
  confidence: string;
}) {

  const normalized =
    confidence.toUpperCase();

  let classes =
    "border-slate-700 bg-slate-800 text-slate-300";

  if (normalized === "HIGH") {
    classes =
      "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
  } else if (normalized === "MEDIUM") {
    classes =
      "border-amber-500/30 bg-amber-500/10 text-amber-400";
  } else if (normalized === "LOW") {
    classes =
      "border-slate-600 bg-slate-800 text-slate-400";
  }

  return (
    <div
      className={`mt-1 inline-flex rounded-lg border px-3 py-1.5 text-xs font-semibold ${classes}`}
    >
      {normalized}
    </div>
  );
}


/* ============================================================
   SCORE CARD
   ============================================================ */

function ScoreCard({
  title,
  icon,
  component,
}: {
  title: string;
  icon: string;
  component: ThreatComponent;
}) {

  const percentage =
    component.max_score > 0
      ? (component.score /
          component.max_score) *
        100
      : 0;

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">

      <div className="flex items-center justify-between">

        <div className="flex items-center gap-3">

          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 text-slate-300">
            {icon}
          </div>

          <div className="text-sm font-medium text-white">
            {title}
          </div>

        </div>


        <div className="text-sm font-semibold text-slate-300">
          {component.score}
          <span className="text-slate-600">
            /{component.max_score}
          </span>
        </div>

      </div>


      <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-800">

        <div
          className={`h-full rounded-full ${getScoreColor(
            percentage
          )}`}
          style={{
            width: `${Math.min(
              percentage,
              100
            )}%`,
          }}
        />

      </div>


      {component.findings.length > 0 && (

        <div className="mt-4 space-y-2">

          {component.findings
            .slice(0, 3)
            .map((finding, index) => (

              <div
                key={index}
                className="text-xs leading-5 text-slate-500"
              >
                • {finding}
              </div>

            ))}

        </div>

      )}

    </div>
  );
}


/* ============================================================
   EVIDENCE ROW
   ============================================================ */

function EvidenceRow({
  item,
}: {
  item: EvidenceItem;
}) {

  return (
    <div className="p-5">

      <div className="flex items-start gap-4">

        <EvidenceSeverity
          severity={item.severity}
        />

        <div className="min-w-0 flex-1">

          <div className="flex flex-wrap items-center gap-2">

            <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[10px] text-slate-400">
              {item.id}
            </span>

            <span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-500">
              {item.type}
            </span>

          </div>


          <h3 className="mt-3 text-sm font-medium text-white">
            {item.title}
          </h3>


          <p className="mt-1 text-xs leading-5 text-slate-500">
            {item.detail}
          </p>

        </div>

      </div>

    </div>
  );
}


/* ============================================================
   EVIDENCE SEVERITY
   ============================================================ */

function EvidenceSeverity({
  severity,
}: {
  severity: string;
}) {

  const normalized =
    severity.toUpperCase();

  let classes =
    "border-slate-700 bg-slate-800 text-slate-400";

  if (
    normalized === "CRITICAL" ||
    normalized === "HIGH"
  ) {
    classes =
      "border-red-500/20 bg-red-500/10 text-red-400";
  } else if (normalized === "MEDIUM") {
    classes =
      "border-amber-500/20 bg-amber-500/10 text-amber-400";
  } else if (normalized === "LOW") {
    classes =
      "border-emerald-500/20 bg-emerald-500/10 text-emerald-400";
  }

  return (
    <div
      className={`mt-1 h-10 w-10 flex-shrink-0 rounded-lg border ${classes} flex items-center justify-center text-xs font-bold`}
    >
      !
    </div>
  );
}


/* ============================================================
   INFO CARD
   ============================================================ */

function InfoCard({
  title,
  items,
}: {
  title: string;
  items: [string, string][];
}) {

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">

      <div className="mb-4 text-sm font-semibold text-white">
        {title}
      </div>


      <div className="space-y-3">

        {items.map(([label, value]) => (

          <div
            key={label}
            className="grid grid-cols-[120px_1fr] gap-3 border-b border-slate-800/70 pb-3 last:border-0 last:pb-0"
          >

            <div className="text-xs text-slate-500">
              {label}
            </div>

            <div className="break-all text-xs text-slate-300">
              {value}
            </div>

          </div>

        ))}

      </div>

    </div>
  );
}


/* ============================================================
   AUTHENTICATION CARD
   ============================================================ */

function AuthenticationCard({
  name,
  value,
}: {
  name: string;
  value: string;
}) {

  const normalized =
    value.toUpperCase();

  const isPass =
    normalized === "PASS";

  const isFail =
    normalized === "FAIL";

  let classes =
    "border-slate-700 bg-slate-900/40 text-slate-400";

  let icon = "•";

  if (isPass) {
    classes =
      "border-emerald-500/20 bg-emerald-500/5 text-emerald-400";

    icon = "✓";
  } else if (isFail) {
    classes =
      "border-red-500/20 bg-red-500/5 text-red-400";

    icon = "!";
  }

  return (
    <div
      className={`rounded-2xl border p-5 ${classes}`}
    >

      <div className="flex items-center justify-between">

        <span className="text-sm font-semibold">
          {name}
        </span>

        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-black/10 text-xs font-bold">
          {icon}
        </span>

      </div>


      <div className="mt-4 text-2xl font-bold">
        {normalized}
      </div>

    </div>
  );
}


/* ============================================================
   INDICATOR CARD
   ============================================================ */

function IndicatorCard({
  title,
  count,
  values,
}: {
  title: string;
  count: number;
  values: string[];
}) {

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">

      <div className="flex items-center justify-between">

        <div className="text-sm font-semibold text-white">
          {title}
        </div>

        <div className="rounded-lg bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-400">
          {count}
        </div>

      </div>


      {values.length === 0 ? (

        <div className="mt-5 text-sm text-slate-600">
          No indicators detected.
        </div>

      ) : (

        <div className="mt-4 max-h-56 space-y-2 overflow-y-auto">

          {values.map((value) => (

            <div
              key={value}
              className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 font-mono text-xs text-slate-400"
            >
              {value}
            </div>

          ))}

        </div>

      )}

    </div>
  );
}


/* ============================================================
   ATTACHMENT RISK
   ============================================================ */

function AttachmentRisk({
  filename,
}: {
  filename: string;
}) {

  const extension =
    "." +
    filename.split(".").pop()?.toLowerCase();

  const dangerous = [
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".dll",
    ".com",
    ".hta",
    ".lnk",
  ];

  const macro = [
    ".docm",
    ".xlsm",
    ".pptm",
  ];

  const archive = [
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
  ];

  if (dangerous.includes(extension)) {

    return (
      <span className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400">
        High Risk Type
      </span>
    );
  }

  if (macro.includes(extension)) {

    return (
      <span className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-400">
        Macro Document
      </span>
    );
  }

  if (archive.includes(extension)) {

    return (
      <span className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-400">
        Archive
      </span>
    );
  }

  return (
    <span className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-500">
      Review
    </span>
  );
}


/* ============================================================
   EVIDENCE METADATA
   ============================================================ */

function EvidenceMetadata({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {

  return (
    <div>

      <div className="text-xs uppercase tracking-wider text-slate-600">
        {label}
      </div>

      <div
        className={`mt-2 break-all rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-300 ${
          mono ? "font-mono" : ""
        }`}
      >
        {value}
      </div>

    </div>
  );
}


/* ============================================================
   SECTION TITLE
   ============================================================ */

function SectionTitle({
  title,
  subtitle,
}: {
  title: string;
  subtitle: string;
}) {

  return (
    <div className="mb-4">

      <h2 className="text-lg font-semibold text-white">
        {title}
      </h2>

      <p className="mt-1 text-xs text-slate-500">
        {subtitle}
      </p>

    </div>
  );
}


/* ============================================================
   FEATURE CARD
   ============================================================ */

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {

  return (
    <div className="rounded-2xl border border-slate-800 bg-[#0d1420] p-5">

      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500/10 text-blue-400">
        {icon}
      </div>

      <h3 className="mt-4 text-sm font-semibold text-white">
        {title}
      </h3>

      <p className="mt-2 text-xs leading-5 text-slate-500">
        {description}
      </p>

    </div>
  );
}


/* ============================================================
   RISK COLOR HELPERS
   ============================================================ */

function getRiskTextColor(score: number) {

  if (score >= 75) {
    return "text-red-400";
  }

  if (score >= 50) {
    return "text-orange-400";
  }

  if (score >= 30) {
    return "text-amber-400";
  }

  return "text-emerald-400";
}


function getRiskGradient(score: number) {

  if (score >= 75) {
    return "from-red-500 to-red-700";
  }

  if (score >= 50) {
    return "from-orange-500 to-orange-700";
  }

  if (score >= 30) {
    return "from-amber-500 to-amber-700";
  }

  return "from-emerald-500 to-emerald-700";
}


function getRiskBarColor(score: number) {

  if (score >= 75) {
    return "bg-red-500";
  }

  if (score >= 50) {
    return "bg-orange-500";
  }

  if (score >= 30) {
    return "bg-amber-500";
  }

  return "bg-emerald-500";
}


function getScoreColor(percentage: number) {

  if (percentage >= 75) {
    return "bg-red-500";
  }

  if (percentage >= 50) {
    return "bg-orange-500";
  }

  if (percentage >= 30) {
    return "bg-amber-500";
  }

  return "bg-emerald-500";
}


/* ============================================================
   BYTE FORMATTER
   ============================================================ */

function formatBytes(bytes: number) {

  if (bytes === 0) {
    return "0 Bytes";
  }

  const units = [
    "Bytes",
    "KB",
    "MB",
    "GB",
  ];

  const index = Math.floor(
    Math.log(bytes) /
      Math.log(1024)
  );

  return (
    parseFloat(
      (
        bytes /
        Math.pow(1024, index)
      ).toFixed(2)
    )
    + " "
    + units[index]
  );
}
