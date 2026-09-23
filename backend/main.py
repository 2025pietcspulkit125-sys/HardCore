from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr

from urllib.parse import urlparse
from urllib.request import Request, urlopen

from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import re
import json
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

from ml_classifier import classify as classify_with_local_ml


# ============================================================
# APP CONFIGURATION
# ============================================================

app = FastAPI(
    title="MailTrace AI",
    description="AI-Powered Email Threat Detection and Forensic Intelligence Platform",
    version="3.0.0"
)


configured_origins = [
    origin.strip()
    for origin in os.getenv("FRONTEND_URLS", "").split(",")
    if origin.strip()
]
allowed_origins = list(dict.fromkeys([
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://frontend-seven-swart-94.vercel.app",
    "https://mailtraceai-rb5eij4yr-pulkitjoshi272006-8842.vercel.app",
    *configured_origins,
]))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "message": "MailTrace AI Backend is running",
        "status": "online",
        "version": "3.0.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ============================================================
# GENERAL HELPERS
# ============================================================

def unique_list(items):
    """
    Remove duplicate values while preserving order.
    """
    return list(dict.fromkeys(items))


def build_attribution_support(sender_analysis, impersonation, authentication, correlation, sending_infrastructure):
    reply_mismatch = bool(sender_analysis.get("reply_to_mismatch"))
    return_path_mismatch = bool(sender_analysis.get("return_path_mismatch"))
    impersonation_findings = impersonation.get("findings") or []
    related_count = int(correlation.get("related_case_count") or 0)
    candidate = sending_infrastructure.get("candidate") or {}
    auth_text = json.dumps(authentication, ensure_ascii=False).lower()

    def item(name, status, evidence, confidence):
        return {"indicator": name, "status": status, "evidence": evidence, "confidence": confidence}

    mismatch = reply_mismatch or return_path_mismatch
    return {
        "items": [
            item("Spoofed Domain Indicator", "YES" if mismatch else "UNKNOWN", "Reply-To or Return-Path differs from the sender domain." if mismatch else "No mismatch was observed in available headers.", "MEDIUM" if mismatch else "LOW"),
            item("Compromised Account Indicator", "YES" if mismatch and candidate else "UNKNOWN", "Identity mismatch combined with observed sending infrastructure requires review." if mismatch and candidate else "Insufficient direct evidence of account control.", "LOW"),
            item("Anonymized Infrastructure Indicator", "UNKNOWN", "VPN, Tor, or proxy status depends on provider intelligence.", "NONE"),
            item("Cloud Hosting Indicator", "UNKNOWN", "Hosting classification depends on provider security metadata.", "NONE"),
            item("Suspicious Relay Indicator", "YES" if candidate else "UNKNOWN", "An earliest visible infrastructure candidate was observed in Received headers." if candidate else "No public relay candidate was available.", "LOW"),
            item("Repeated Infrastructure Indicator", "YES" if related_count else "NO", f"{related_count} related case(s) share observable indicators." if related_count else "No related cases met the correlation threshold.", "LOW" if related_count else "MEDIUM"),
            item("Campaign Correlation Indicator", "YES" if related_count else "NO", "Correlation is based on shared observable indicators, not attribution.", "LOW" if related_count else "MEDIUM"),
        ],
        "disclaimer": "This assessment provides investigative support based on observable technical evidence. It does not independently establish the identity or physical location of an actor.",
    }


def build_compromised_account_indicator(sender_analysis, authentication, impersonation, correlation):
    reasons = []
    if sender_analysis.get("reply_to_mismatch"):
        reasons.append("Reply-To domain differs from the sender relationship.")
    if sender_analysis.get("return_path_mismatch"):
        reasons.append("Return-Path domain differs from the sender relationship.")
    if impersonation.get("findings"):
        reasons.append("Display-name or impersonation findings were recorded.")
    if correlation.get("related_case_count"):
        reasons.append("Observable overlap exists with historical investigations.")
    auth_text = json.dumps(authentication, ensure_ascii=False).lower()
    if any(term in auth_text for term in ("fail", "softfail", "none")):
        reasons.append("Available authentication results include a failure or missing result.")
    return {
        "status": "YES" if len(reasons) >= 2 else "UNKNOWN",
        "confidence": "LOW" if reasons else "NONE",
        "reasons": reasons,
        "note": "This is a heuristic investigative signal, not proof that an account was compromised.",
    }


def extract_ips(text: str):
    """
    Extract strictly valid IPv4 addresses from text.

    Leading-zero octets such as 09.16.02.13 are rejected because they
    are frequently dates, numeric fragments, or other non-IP header text.
    """

    if not text:
        return []

    pattern = r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
    candidates = re.findall(pattern, text)
    valid_ips = []

    for candidate in candidates:
        parts = candidate.split(".")
        if len(parts) != 4:
            continue

        # Reject octets with leading zeros (except the single octet '0').
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            continue

        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        if parsed.version == 4:
            valid_ips.append(candidate)

    return unique_list(valid_ips)


def extract_urls(text: str):
    """
    Extract HTTP/HTTPS URLs from email content.
    """

    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(pattern, text)

    cleaned_urls = []

    for url in urls:

        # Remove common trailing punctuation
        url = url.rstrip(".,;:!?)]}")

        cleaned_urls.append(url)

    return unique_list(cleaned_urls)


def extract_email_address(value: str):
    """
    Extract email address from:
    John Smith <john@example.com>
    """

    if not value:
        return ""

    _, address = parseaddr(value)

    return address.lower().strip()


def extract_email_domain(value: str):
    """
    Extract domain from an email address/header.
    """

    email_address = extract_email_address(value)

    if "@" not in email_address:
        return ""

    return email_address.split("@", 1)[1].lower()


def normalize_domain(domain: str):
    """
    Remove leading www.
    """

    if not domain:
        return ""

    return domain.lower().strip().removeprefix("www.")


def get_email_body(message):
    """
    Extract plain text and HTML body.
    """

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            disposition = str(
                part.get("Content-Disposition", "")
            )

            if "attachment" in disposition.lower():
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain" and not plain_text:
                plain_text = str(content)

            elif content_type == "text/html" and not html_text:
                html_text = str(content)

    else:

        try:

            content = message.get_content()

            if message.get_content_type() == "text/html":
                html_text = str(content)

            else:
                plain_text = str(content)

        except Exception:
            pass

    return plain_text, html_text


def extract_attachments(message):
    """
    Extract attachment metadata.
    """

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if not filename:
            continue

        payload = part.get_payload(decode=True)

        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload) if payload else 0
        })

    return attachments


def extract_received_headers(message):
    """
    Extract SMTP Received headers.
    """

    received_headers = message.get_all("Received", [])

    hops = []

    for index, header in enumerate(received_headers, start=1):

        ips = extract_ips(header)

        hops.append({
            "hop": index,
            "raw": header,
            "ips": ips
        })

    return hops


def analyze_smtp_sending_infrastructure(received_headers):
    """
    Assess the earliest externally routable IP visible in the SMTP
    Received-header chain.

    Received headers are normally added by each receiving mail server,
    so the top header is the newest hop and the bottom header is the
    oldest visible hop. We therefore inspect the headers from oldest to
    newest and select the first valid public IP we can substantiate.

    This is an infrastructure candidate, not proof of the sender's
    device, physical location, or identity.
    """

    if not isinstance(received_headers, list) or not received_headers:
        return {
            "status": "not_available",
            "candidate": None,
            "public_ip_candidates": [],
            "total_received_hops": 0,
            "basis": "No SMTP Received headers were available in the parsed email.",
            "interpretation": "No earliest public sending-infrastructure candidate could be established from the available headers."
        }

    ordered_candidates = []

    # message.get_all('Received') preserves the header order as present
    # in the message; the oldest visible hop is normally the last item.
    for hop in reversed(received_headers):
        if not isinstance(hop, dict):
            continue

        hop_number = hop.get("hop")
        raw_header = str(hop.get("raw") or "")
        raw_ips = hop.get("ips") or []

        valid_public_ips = []
        for raw_ip in raw_ips:
            if not isinstance(raw_ip, str):
                continue
            ip = raw_ip.strip()
            if not _is_valid_ip(ip) or not _is_public_ip(ip):
                continue
            if ip not in valid_public_ips:
                valid_public_ips.append(ip)

        for ip in valid_public_ips:
            ordered_candidates.append({
                "ip": ip,
                "hop": hop_number,
                "raw_header": raw_header,
            })

    if not ordered_candidates:
        return {
            "status": "not_available",
            "candidate": None,
            "public_ip_candidates": [],
            "total_received_hops": len(received_headers),
            "basis": "Received headers were present, but no valid public IP was visible in the chain.",
            "interpretation": "The available email headers do not expose an externally routable sending-infrastructure IP."
        }

    selected = ordered_candidates[0]

    return {
        "status": "candidate_identified",
        "candidate": {
            "ip": selected["ip"],
            "hop": selected["hop"],
            "source": "SMTP Received header",
            "role": "earliest_visible_public_infrastructure",
            "confidence": "medium",
        },
        "public_ip_candidates": ordered_candidates,
        "total_received_hops": len(received_headers),
        "basis": (
            "Selected the first valid public IP encountered while traversing "
            "the available Received headers from the oldest visible hop toward the newest hop."
        ),
        "interpretation": (
            "This is the earliest externally routable infrastructure address visible "
            "in the email's delivery path. It may belong to a mail relay or provider "
            "rather than the sender's endpoint."
        ),
        "limitations": [
            "Mail providers can omit or replace originating client IP information.",
            "The selected address may identify provider or relay infrastructure rather than the sender's device.",
            "An IP address and its geolocation do not establish the sender's physical location or identity."
        ]
    }


def extract_all_header_text(message):
    """
    Convert all email headers into searchable text.
    """

    return "\n".join(
        f"{key}: {value}"
        for key, value in message.items()
    )


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def parse_authentication_results(message):
    """
    Parse SPF, DKIM and DMARC results from Authentication-Results.

    Example:
    spf=pass
    dkim=pass
    dmarc=fail
    """

    authentication_results = message.get(
        "Authentication-Results",
        ""
    )

    received_spf = message.get(
        "Received-SPF",
        ""
    )

    dkim_signature = message.get(
        "DKIM-Signature",
        ""
    )

    combined = (
        str(authentication_results)
        + " "
        + str(received_spf)
    ).lower()

    result = {
        "authentication_results": str(authentication_results),
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    spf_match = re.search(
        r'\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b',
        combined
    )

    if spf_match:

        result["spf"] = spf_match.group(1)

    elif received_spf:

        first_word = str(received_spf).strip().split()

        if first_word:

            possible_spf = first_word[0].lower()

            if possible_spf in [
                "pass",
                "fail",
                "softfail",
                "neutral",
                "none",
                "temperror",
                "permerror"
            ]:

                result["spf"] = possible_spf

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    dkim_match = re.search(
        r'\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b',
        combined
    )

    if dkim_match:

        result["dkim"] = dkim_match.group(1)

    elif dkim_signature:

        # Signature exists, but existence does NOT prove validity.
        result["dkim"] = "present-not-verified"

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    dmarc_match = re.search(
        r'\bdmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)\b',
        combined
    )

    if dmarc_match:

        result["dmarc"] = dmarc_match.group(1)

    return result


# ============================================================
# URL ANALYSIS
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at"
}


SUSPICIOUS_URL_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "update",
    "confirm",
    "billing",
    "payment",
    "invoice",
    "wallet",
    "credential",
    "authenticate",
    "unlock",
    "suspended",
    "security"
}


def analyze_single_url(url: str):
    """
    Analyze URL characteristics.

    These are indicators, NOT proof that the URL is malicious.
    """

    findings = []

    try:

        parsed = urlparse(url)

        hostname = (parsed.hostname or "").lower()

        path = (parsed.path or "").lower()

        query = (parsed.query or "").lower()

        full_target = (
            hostname
            + " "
            + path
            + " "
            + query
        )

        # ----------------------------------------------------
        # IP address used as hostname
        # ----------------------------------------------------

        hostname_is_ip = bool(
            re.fullmatch(
                r'(?:\d{1,3}\.){3}\d{1,3}',
                hostname
            )
        )

        if hostname_is_ip:

            findings.append({
                "type": "ip-host",
                "severity": "high",
                "detail": "URL uses an IPv4 address instead of a normal domain."
            })

        # ----------------------------------------------------
        # URL shortener
        # ----------------------------------------------------

        normalized_hostname = normalize_domain(hostname)

        if normalized_hostname in URL_SHORTENERS:

            findings.append({
                "type": "shortener",
                "severity": "medium",
                "detail": "URL uses a known URL-shortening service."
            })

        # ----------------------------------------------------
        # Punycode
        # ----------------------------------------------------

        if "xn--" in hostname:

            findings.append({
                "type": "punycode",
                "severity": "high",
                "detail": "Domain contains punycode and requires additional lookalike-domain review."
            })

        # ----------------------------------------------------
        # Suspicious words
        # ----------------------------------------------------

        matched_words = []

        for word in SUSPICIOUS_URL_WORDS:

            if word in full_target:
                matched_words.append(word)

        if matched_words:

            findings.append({
                "type": "suspicious-keywords",
                "severity": "medium",
                "detail": (
                    "URL contains security/account/payment-related "
                    "keywords: "
                    + ", ".join(sorted(matched_words))
                )
            })

        # ----------------------------------------------------
        # Non-standard port
        # ----------------------------------------------------

        if parsed.port:

            if parsed.port not in [80, 443]:

                findings.append({
                    "type": "non-standard-port",
                    "severity": "medium",
                    "detail": f"URL uses non-standard port {parsed.port}."
                })

        # ----------------------------------------------------
        # Excessive subdomains
        # ----------------------------------------------------

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:

            findings.append({
                "type": "deep-subdomain",
                "severity": "medium",
                "detail": "URL contains an unusually deep subdomain structure."
            })

        # ----------------------------------------------------
        # Username in URL
        # ----------------------------------------------------

        if parsed.username:

            findings.append({
                "type": "embedded-username",
                "severity": "medium",
                "detail": "URL contains an embedded username component."
            })

        return {
            "url": url,
            "hostname": hostname,
            "findings": findings
        }

    except Exception:

        return {
            "url": url,
            "hostname": "",
            "findings": []
        }


def analyze_urls(urls):
    """
    Analyze every extracted URL.
    """

    analyzed = []

    for url in urls:

        analyzed.append(
            analyze_single_url(url)
        )

    return analyzed


# ============================================================
# CONTENT / SOCIAL ENGINEERING ANALYSIS
# ============================================================

URGENCY_PHRASES = [
    "urgent",
    "urgently",
    "immediately",
    "right away",
    "as soon as possible",
    "action required",
    "act now",
    "final notice",
    "last warning",
    "within 24 hours",
    "within 48 hours"
]


CREDENTIAL_PHRASES = [
    "verify your account",
    "verify account",
    "confirm your account",
    "confirm your identity",
    "verify your identity",
    "reset your password",
    "password expired",
    "login",
    "sign in",
    "credentials",
    "username and password",
    "security verification",
    "account suspended",
    "account locked"
]


PAYMENT_PHRASES = [
    "wire transfer",
    "bank transfer",
    "payment",
    "invoice",
    "gift card",
    "purchase order",
    "vendor",
    "payroll",
    "bank account",
    "account number",
    "payment due",
    "transfer funds"
]


def find_phrases(text: str, phrases):
    """
    Find phrases without case sensitivity.
    """

    text_lower = text.lower()

    matches = []

    for phrase in phrases:

        if phrase.lower() in text_lower:
            matches.append(phrase)

    return unique_list(matches)


def analyze_content(text: str):
    """
    Detect common social-engineering indicators.
    """

    urgency = find_phrases(
        text,
        URGENCY_PHRASES
    )

    credentials = find_phrases(
        text,
        CREDENTIAL_PHRASES
    )

    payment = find_phrases(
        text,
        PAYMENT_PHRASES
    )

    findings = []

    if urgency:

        findings.append({
            "type": "urgency",
            "severity": "medium",
            "detail": (
                "Urgency language detected: "
                + ", ".join(urgency)
            )
        })

    if credentials:

        findings.append({
            "type": "credential-request",
            "severity": "high",
            "detail": (
                "Credential/account-verification language detected: "
                + ", ".join(credentials)
            )
        })

    if payment:

        findings.append({
            "type": "payment-request",
            "severity": "high",
            "detail": (
                "Payment or financial-action language detected: "
                + ", ".join(payment)
            )
        })

    return {
        "urgency_matches": urgency,
        "credential_matches": credentials,
        "payment_matches": payment,
        "findings": findings
    }


# ============================================================
# SENDER / REPLY-TO ANALYSIS
# ============================================================

def analyze_sender_relationship(
    sender: str,
    reply_to: str,
    return_path: str
):

    sender_domain = normalize_domain(
        extract_email_domain(sender)
    )

    reply_domain = normalize_domain(
        extract_email_domain(reply_to)
    )

    return_path_domain = normalize_domain(
        extract_email_domain(return_path)
    )

    findings = []

    reply_to_mismatch = False
    return_path_mismatch = False

    # --------------------------------------------------------
    # Reply-To mismatch
    # --------------------------------------------------------

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:

            reply_to_mismatch = True

            findings.append({
                "type": "reply-to-mismatch",
                "severity": "high",
                "detail": (
                    f"From domain '{sender_domain}' differs "
                    f"from Reply-To domain '{reply_domain}'."
                )
            })

    # --------------------------------------------------------
    # Return-Path mismatch
    # --------------------------------------------------------

    if sender_domain and return_path_domain:

        if sender_domain != return_path_domain:

            return_path_mismatch = True

            findings.append({
                "type": "return-path-mismatch",
                "severity": "medium",
                "detail": (
                    f"From domain '{sender_domain}' differs "
                    f"from Return-Path domain '{return_path_domain}'."
                )
            })

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "findings": findings
    }


# ============================================================
# IMPERSONATION ANALYSIS
# ============================================================

BRAND_DOMAINS = {
    "microsoft": [
        "microsoft.com",
        "microsoftonline.com",
        "office.com"
    ],
    "google": [
        "google.com",
        "googlemail.com"
    ],
    "apple": [
        "apple.com",
        "icloud.com"
    ],
    "amazon": [
        "amazon.com",
        "amazon.in"
    ],
    "paypal": [
        "paypal.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "riot games": [
        "riotgames.com",
        "riotgames.com"
    ]
}


def analyze_impersonation(sender: str):

    display_name, sender_address = parseaddr(sender)

    display_name_lower = (
        display_name or ""
    ).lower()

    sender_domain = normalize_domain(
        extract_email_domain(sender)
    )

    findings = []

    matched_brand = None

    for brand, allowed_domains in BRAND_DOMAINS.items():

        if brand in display_name_lower:

            matched_brand = brand

            domain_matches = False

            for allowed_domain in allowed_domains:

                if (
                    sender_domain == allowed_domain
                    or sender_domain.endswith(
                        "." + allowed_domain
                    )
                ):
                    domain_matches = True
                    break

            if not domain_matches:

                findings.append({
                    "type": "possible-brand-impersonation",
                    "severity": "high",
                    "detail": (
                        f"Display name references '{brand}', "
                        f"but sender domain is '{sender_domain}'. "
                        "This is an impersonation indicator and "
                        "requires further verification."
                    )
                })

            break

    return {
        "display_name": display_name,
        "sender_address": sender_address,
        "matched_brand": matched_brand,
        "findings": findings
    }


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

HIGH_RISK_EXTENSIONS = {
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
    ".lnk"
}


MACRO_DOCUMENT_EXTENSIONS = {
    ".docm",
    ".xlsm",
    ".pptm"
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img"
}


def analyze_attachments(attachments):

    findings = []

    high_risk = []
    macro_files = []
    archives = []

    for attachment in attachments:

        filename = attachment.get(
            "filename",
            ""
        )

        extension = ""

        if "." in filename:

            extension = (
                "."
                + filename.rsplit(".", 1)[1].lower()
            )

        if extension in HIGH_RISK_EXTENSIONS:

            high_risk.append(filename)

            findings.append({
                "type": "executable-attachment",
                "severity": "high",
                "detail": (
                    f"Potentially dangerous executable/script "
                    f"attachment type detected: {filename}"
                )
            })

        elif extension in MACRO_DOCUMENT_EXTENSIONS:

            macro_files.append(filename)

            findings.append({
                "type": "macro-document",
                "severity": "medium",
                "detail": (
                    f"Macro-enabled document detected: {filename}"
                )
            })

        elif extension in ARCHIVE_EXTENSIONS:

            archives.append(filename)

            findings.append({
                "type": "archive-attachment",
                "severity": "medium",
                "detail": (
                    f"Archive/disk-image attachment detected: {filename}. "
                    "Its contents require further inspection."
                )
            })

    return {
        "high_risk_files": high_risk,
        "macro_files": macro_files,
        "archive_files": archives,
        "findings": findings
    }


# ============================================================
# BEC ANALYSIS
# ============================================================

def analyze_bec(
    sender_analysis,
    content_analysis,
    sender_domain
):

    payment_signals = len(
        content_analysis["payment_matches"]
    )

    urgency_signals = len(
        content_analysis["urgency_matches"]
    )

    mismatch_signals = 0

    if sender_analysis["reply_to_mismatch"]:
        mismatch_signals += 1

    if sender_analysis["return_path_mismatch"]:
        mismatch_signals += 1

    external_sender = False

    if sender_domain:

        common_free_domains = {
            "gmail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com",
            "proton.me",
            "protonmail.com"
        }

        if sender_domain in common_free_domains:
            external_sender = True

    bec_score = (
        payment_signals
        + urgency_signals
        + mismatch_signals
    )

    signals = []

    if payment_signals:
        signals.append("financial/payment language")

    if urgency_signals:
        signals.append("urgency language")

    if mismatch_signals:
        signals.append("identity/routing mismatch")

    if external_sender:
        signals.append("consumer/free-mail sender domain")

    return {
        "potential_bec": bec_score >= 3,
        "signal_count": bec_score,
        "signals": signals
    }


# ============================================================
# EVIDENCE BUILDER
# ============================================================

def build_evidence(
    authentication,
    url_analysis,
    content_analysis,
    sender_analysis,
    impersonation,
    attachment_analysis,
    bec_analysis
):

    evidence = []

    counter = 1

    def add_evidence(
        evidence_type,
        severity,
        title,
        detail
    ):

        nonlocal counter

        evidence.append({
            "id": f"E{counter:03d}",
            "type": evidence_type,
            "severity": severity,
            "title": title,
            "detail": detail
        })

        counter += 1

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if authentication["spf"] == "fail":

        add_evidence(
            "AUTHENTICATION",
            "HIGH",
            "SPF validation failed",
            "The available authentication result reports SPF failure."
        )

    if authentication["dkim"] == "fail":

        add_evidence(
            "AUTHENTICATION",
            "HIGH",
            "DKIM validation failed",
            "The available authentication result reports DKIM failure."
        )

    if authentication["dmarc"] == "fail":

        add_evidence(
            "AUTHENTICATION",
            "HIGH",
            "DMARC validation failed",
            "The available authentication result reports DMARC failure."
        )

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    for result in url_analysis:

        for finding in result["findings"]:

            add_evidence(
                "URL",
                finding["severity"].upper(),
                "Suspicious URL indicator",
                (
                    finding["detail"]
                    + " URL: "
                    + result["url"]
                )
            )

    # --------------------------------------------------------
    # Content
    # --------------------------------------------------------

    for finding in content_analysis["findings"]:

        add_evidence(
            "CONTENT",
            finding["severity"].upper(),
            "Social-engineering indicator",
            finding["detail"]
        )

    # --------------------------------------------------------
    # Sender
    # --------------------------------------------------------

    for finding in sender_analysis["findings"]:

        add_evidence(
            "IDENTITY",
            finding["severity"].upper(),
            "Sender identity/routing mismatch",
            finding["detail"]
        )

    # --------------------------------------------------------
    # Impersonation
    # --------------------------------------------------------

    for finding in impersonation["findings"]:

        add_evidence(
            "IMPERSONATION",
            finding["severity"].upper(),
            "Possible brand impersonation",
            finding["detail"]
        )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    for finding in attachment_analysis["findings"]:

        add_evidence(
            "ATTACHMENT",
            finding["severity"].upper(),
            "Attachment security indicator",
            finding["detail"]
        )

    # --------------------------------------------------------
    # BEC
    # --------------------------------------------------------

    if bec_analysis["potential_bec"]:

        add_evidence(
            "BEC",
            "HIGH",
            "Potential business email compromise pattern",
            (
                "Multiple signals associated with payment, urgency, "
                "or sender-routing manipulation were detected."
            )
        )

    return evidence


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    authentication,
    url_analysis,
    content_analysis,
    sender_analysis,
    attachment_analysis,
    impersonation,
    bec_analysis
):

    # ========================================================
    # 1. AUTHENTICATION Ã¢â‚¬â€ MAX 25
    # ========================================================

    authentication_score = 0
    authentication_findings = []

    if authentication["spf"] == "fail":

        authentication_score += 10

        authentication_findings.append(
            "SPF failed"
        )

    if authentication["dkim"] == "fail":

        authentication_score += 8

        authentication_findings.append(
            "DKIM failed"
        )

    if authentication["dmarc"] == "fail":

        authentication_score += 7

        authentication_findings.append(
            "DMARC failed"
        )

    authentication_score = min(
        authentication_score,
        25
    )

    # ========================================================
    # 2. URL / DOMAIN Ã¢â‚¬â€ MAX 20
    # ========================================================

    url_score = 0
    url_findings = []

    for result in url_analysis:

        for finding in result["findings"]:

            finding_type = finding["type"]

            if finding_type == "ip-host":
                url_score += 10

            elif finding_type == "punycode":
                url_score += 5

            elif finding_type == "shortener":
                url_score += 5

            elif finding_type == "suspicious-keywords":
                url_score += 3

            elif finding_type == "non-standard-port":
                url_score += 3

            elif finding_type == "deep-subdomain":
                url_score += 2

            elif finding_type == "embedded-username":
                url_score += 2

            url_findings.append(
                finding["detail"]
            )

    url_score = min(
        url_score,
        20
    )

    # ========================================================
    # 3. CONTENT / SOCIAL ENGINEERING Ã¢â‚¬â€ MAX 20
    # ========================================================

    content_score = 0
    content_findings = []

    urgency_count = len(
        content_analysis["urgency_matches"]
    )

    credential_count = len(
        content_analysis["credential_matches"]
    )

    payment_count = len(
        content_analysis["payment_matches"]
    )

    if urgency_count:

        content_score += min(
            urgency_count * 2,
            6
        )

        content_findings.append(
            "Urgency language detected"
        )

    if credential_count:

        content_score += min(
            credential_count * 3,
            8
        )

        content_findings.append(
            "Credential/account-verification language detected"
        )

    if payment_count:

        content_score += min(
            payment_count * 2,
            6
        )

        content_findings.append(
            "Payment/financial language detected"
        )

    if bec_analysis["potential_bec"]:

        content_score += 4

        content_findings.append(
            "Potential BEC pattern detected"
        )

    content_score = min(
        content_score,
        20
    )

    # ========================================================
    # 4. INFRASTRUCTURE Ã¢â‚¬â€ MAX 15
    # ========================================================

    infrastructure_score = 0
    infrastructure_findings = []

    # We do NOT call an IP malicious without reputation
    # enrichment.

    # A direct IP URL is already scored under URL analysis.

    if url_analysis:

        direct_ip_urls = sum(
            1
            for result in url_analysis
            for finding in result["findings"]
            if finding["type"] == "ip-host"
        )

        if direct_ip_urls:

            infrastructure_score += min(
                direct_ip_urls * 5,
                10
            )

            infrastructure_findings.append(
                "Direct IP-based URL infrastructure observed"
            )

    infrastructure_score = min(
        infrastructure_score,
        15
    )

    # ========================================================
    # 5. ATTACHMENTS Ã¢â‚¬â€ MAX 10
    # ========================================================

    attachment_score = 0
    attachment_findings = []

    if attachment_analysis["high_risk_files"]:

        attachment_score += 10

        attachment_findings.append(
            "Potentially dangerous executable/script attachment"
        )

    elif attachment_analysis["macro_files"]:

        attachment_score += 7

        attachment_findings.append(
            "Macro-enabled document detected"
        )

    elif attachment_analysis["archive_files"]:

        attachment_score += 4

        attachment_findings.append(
            "Archive/disk-image attachment detected"
        )

    attachment_score = min(
        attachment_score,
        10
    )

    # ========================================================
    # 6. CORRELATION Ã¢â‚¬â€ MAX 10
    # ========================================================

    # Historical campaign correlation will be connected
    # after the database/correlation module is implemented.

    correlation_score = 0

    correlation_findings = [
        "Historical campaign correlation not yet available"
    ]

    # ========================================================
    # TOTAL
    # ========================================================

    total_score = (
        authentication_score
        + url_score
        + content_score
        + infrastructure_score
        + attachment_score
        + correlation_score
    )

    total_score = max(
        0,
        min(total_score, 100)
    )

    return {
        "risk_score": total_score,

        "components": {

            "authentication": {
                "score": authentication_score,
                "max_score": 25,
                "findings": authentication_findings
            },

            "url_domain": {
                "score": url_score,
                "max_score": 20,
                "findings": url_findings
            },

            "content_social_engineering": {
                "score": content_score,
                "max_score": 20,
                "findings": content_findings
            },

            "infrastructure": {
                "score": infrastructure_score,
                "max_score": 15,
                "findings": infrastructure_findings
            },

            "attachments": {
                "score": attachment_score,
                "max_score": 10,
                "findings": attachment_findings
            },

            "correlation": {
                "score": correlation_score,
                "max_score": 10,
                "findings": correlation_findings
            }
        }
    }


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int):

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

def classify_threat(
    score,
    content_analysis,
    attachment_analysis,
    impersonation,
    bec_analysis,
    url_analysis
):

    # --------------------------------------------------------
    # Malware
    # --------------------------------------------------------

    if attachment_analysis["high_risk_files"]:

        return "MALWARE"

    # --------------------------------------------------------
    # BEC / Fraud
    # --------------------------------------------------------

    if bec_analysis["potential_bec"]:

        return "BEC"

    # --------------------------------------------------------
    # Impersonation
    # --------------------------------------------------------

    if impersonation["findings"]:

        return "IMPERSONATION"

    # --------------------------------------------------------
    # Phishing
    # --------------------------------------------------------

    credential_signals = len(
        content_analysis["credential_matches"]
    )

    suspicious_urls = sum(
        len(result["findings"])
        for result in url_analysis
    )

    if credential_signals > 0 or suspicious_urls > 0:

        return "PHISHING"

    # --------------------------------------------------------
    # Suspicious
    # --------------------------------------------------------

    if score >= 30:

        return "SUSPICIOUS"

    # --------------------------------------------------------
    # Legitimate
    # --------------------------------------------------------

    return "LEGITIMATE"


# ============================================================
# CONFIDENCE
# ============================================================

def calculate_confidence(
    evidence,
    authentication,
    attachment_analysis
):

    evidence_count = len(evidence)

    strong_evidence = 0

    for item in evidence:

        if item["severity"] == "HIGH":

            strong_evidence += 1

    if (
        strong_evidence >= 2
        or evidence_count >= 5
    ):

        return "HIGH"

    if evidence_count >= 2:

        return "MEDIUM"

    return "LOW"


# ============================================================
# THREAT SUMMARY
# ============================================================

def generate_summary(
    classification,
    risk_score,
    risk_level,
    evidence,
    authentication
):

    if classification == "LEGITIMATE":

        return (
            "No strong malicious indicators were identified "
            "by the current deterministic analysis rules. "
            "This does not guarantee that the email is safe."
        )

    if classification == "MALWARE":

        return (
            f"The email received a {risk_score}/100 risk score "
            f"({risk_level}). Potentially dangerous attachment "
            "types were identified and require further sandbox "
            "or malware analysis."
        )

    if classification == "BEC":

        return (
            f"The email received a {risk_score}/100 risk score "
            f"({risk_level}) and contains multiple indicators "
            "associated with business email compromise or "
            "financial-request scenarios."
        )

    if classification == "IMPERSONATION":

        return (
            f"The email received a {risk_score}/100 risk score "
            f"({risk_level}). The sender identity contains "
            "possible brand/domain impersonation indicators."
        )

    if classification == "PHISHING":

        return (
            f"The email received a {risk_score}/100 risk score "
            f"({risk_level}) with indicators associated with "
            "credential theft, suspicious URLs, or social engineering."
        )

    return (
        f"The email received a {risk_score}/100 risk score "
        f"({risk_level}) and contains security indicators "
        "requiring further investigation."
    )



# ============================================================
# THREAT GRAPH BUILDER
# ============================================================

def build_threat_graph(email, indicators, smtp_relay, attachments, evidence_id):
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id, node_type, label, value, properties=None):
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": label,
            "value": value,
            "properties": properties or {}
        })

    def add_edge(source, target, relationship, supporting_evidence=None):
        edges.append({
            "source": source,
            "target": target,
            "relationship": relationship,
            "evidence_id": supporting_evidence
        })

    message_id = email.get("message_id") or "unknown-message"
    email_id = "email:" + message_id

    add_node(
        email_id,
        "EMAIL",
        "Email",
        message_id,
        {
            "subject": email.get("subject", ""),
            "from": email.get("from", ""),
            "to": email.get("to", ""),
            "date": email.get("date"),
            "evidence_id": evidence_id
        }
    )

    sender_domain = normalize_domain(
        extract_email_domain(email.get("from", ""))
    )
    if sender_domain:
        domain_id = "domain:" + sender_domain
        add_node(
            domain_id,
            "DOMAIN",
            "Sender Domain",
            sender_domain,
            {"source": "From header"}
        )
        add_edge(email_id, domain_id, "SENT_FROM")

    reply_domain = normalize_domain(
        extract_email_domain(email.get("reply_to", ""))
    )
    if reply_domain:
        domain_id = "domain:" + reply_domain
        add_node(
            domain_id,
            "DOMAIN",
            "Reply-To Domain",
            reply_domain,
            {"source": "Reply-To header"}
        )
        add_edge(email_id, domain_id, "REPLIES_TO")

    return_domain = normalize_domain(
        extract_email_domain(email.get("return_path", ""))
    )
    if return_domain:
        domain_id = "domain:" + return_domain
        add_node(
            domain_id,
            "DOMAIN",
            "Return-Path Domain",
            return_domain,
            {"source": "Return-Path header"}
        )
        add_edge(email_id, domain_id, "RETURN_PATH")

    for index, url in enumerate(indicators.get("urls", []), 1):
        url_id = f"url:{index}"
        add_node(url_id, "URL", "URL", url)

        add_edge(
            email_id,
            url_id,
            "CONTAINS_URL"
        )

        try:
            hostname = normalize_domain(
                urlparse(url).hostname or ""
            )
        except Exception:
            hostname = ""

        if hostname:
            domain_id = "domain:" + hostname
            add_node(
                domain_id,
                "DOMAIN",
                "URL Domain",
                hostname,
                {"source": "URL hostname"}
            )
            add_edge(
                url_id,
                domain_id,
                "HOSTED_ON"
            )

    for ip in indicators.get("ips", []):
        ip_id = "ip:" + ip

        add_node(
            ip_id,
            "IP",
            "IP Address",
            ip,
            {"source": "Email headers/content"}
        )

        add_edge(
            email_id,
            ip_id,
            "REFERENCES_IP"
        )

    previous_node = email_id

    for hop in smtp_relay:
        hop_number = hop.get("hop", 0)

        for ip in hop.get("ips", []):
            ip_id = "ip:" + ip

            add_node(
                ip_id,
                "IP",
                "SMTP Relay IP",
                ip,
                {
                    "source": "Received header",
                    "hop": hop_number
                }
            )

            add_edge(
                previous_node,
                ip_id,
                "RELAYED_THROUGH",
                f"E-HOP-{hop_number}"
            )

            previous_node = ip_id

    for index, attachment in enumerate(attachments, 1):
        attachment_id = f"attachment:{index}"

        add_node(
            attachment_id,
            "ATTACHMENT",
            "Attachment",
            attachment.get(
                "filename",
                f"attachment-{index}"
            ),
            {
                "content_type": attachment.get(
                    "content_type", ""
                ),
                "size": attachment.get(
                    "size", 0
                )
            }
        )

        add_edge(
            email_id,
            attachment_id,
            "HAS_ATTACHMENT"
        )

    campaign_id = "campaign:pending-correlation"

    add_node(
        campaign_id,
        "CAMPAIGN",
        "Campaign",
        "Pending historical correlation",
        {"status": "not_yet_correlated"}
    )

    add_edge(
        email_id,
        campaign_id,
        "POTENTIAL_CAMPAIGN"
    )

    node_counts = {}
    relationship_counts = {}

    for node in nodes:
        node_type = node["type"]
        node_counts[node_type] = (
            node_counts.get(node_type, 0) + 1
        )

    for edge in edges:
        relation = edge["relationship"]
        relationship_counts[relation] = (
            relationship_counts.get(relation, 0) + 1
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": node_counts,
            "relationships": relationship_counts
        },
        "graph_metadata": {
            "evidence_id": evidence_id,
            "description": (
                "Evidence relationship graph generated "
                "from the analyzed email."
            )
        }
    }


# ============================================================
# MAIN ANALYSIS ROUTE
# ============================================================

@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile = File(...)
):

    # ========================================================
    # FILE VALIDATION
    # ========================================================

    filename = file.filename or "unknown"

    extension = ""

    if "." in filename:

        extension = (
            "."
            + filename.rsplit(".", 1)[1].lower()
        )

    if extension not in [".eml", ".msg"]:

        raise HTTPException(
            status_code=400,
            detail="Only .eml and .msg email files are supported."
        )

    # ========================================================
    # READ FILE
    # ========================================================

    contents = await file.read()

    if not contents:

        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty."
        )

    # ========================================================
    # SHA-256 EVIDENCE HASH
    # ========================================================

    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    evidence_id = (
        "MT-"
        + sha256_hash[:12].upper()
    )

    captured_at = datetime.now(
        timezone.utc
    ).isoformat()

    # ========================================================
    # PARSE EMAIL
    # ========================================================

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(contents)

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=f"Unable to parse email: {str(error)}"
        )

    # ========================================================
    # BODY
    # ========================================================

    plain_text, html_text = get_email_body(
        message
    )

    combined_text = (
        plain_text
        + "\n"
        + html_text
    )

    # ========================================================
    # BASIC EMAIL INFORMATION
    # ========================================================

    subject = message.get(
        "Subject",
        ""
    )

    sender = message.get(
        "From",
        ""
    )

    recipient = message.get(
        "To",
        ""
    )

    reply_to = message.get(
        "Reply-To",
        ""
    )

    return_path = message.get(
        "Return-Path",
        ""
    )

    message_id = message.get(
        "Message-ID",
        ""
    )

    date_header = message.get(
        "Date",
        ""
    )

    parsed_date = None

    if date_header:

        try:

            parsed_date = parsedate_to_datetime(
                date_header
            ).isoformat()

        except Exception:

            parsed_date = str(
                date_header
            )

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    authentication = parse_authentication_results(
        message
    )

    # ========================================================
    # HEADERS
    # ========================================================

    received_headers = extract_received_headers(
        message
    )

    sending_infrastructure = analyze_smtp_sending_infrastructure(
        received_headers
    )

    all_header_text = extract_all_header_text(
        message
    )

    # ========================================================
    # IOCs
    # ========================================================

    urls = extract_urls(
        combined_text
    )

    ips = extract_ips(
        all_header_text
        + "\n"
        + combined_text
    )

    # ========================================================
    # ATTACHMENTS
    # ========================================================

    attachments = extract_attachments(
        message
    )

    # ========================================================
    # HEADER DICTIONARY
    # ========================================================

    headers = {}

    for key, value in message.items():

        headers[key] = str(value)

    # ========================================================
    # THREAT ANALYSIS
    # ========================================================

    url_analysis = analyze_urls(
        urls
    )

    content_analysis = analyze_content(
        combined_text
    )

    sender_analysis = analyze_sender_relationship(
        sender,
        reply_to,
        return_path
    )

    impersonation = analyze_impersonation(
        sender
    )

    attachment_analysis = analyze_attachments(
        attachments
    )

    sender_domain = normalize_domain(
        extract_email_domain(sender)
    )

    bec_analysis = analyze_bec(
        sender_analysis,
        content_analysis,
        sender_domain
    )

    ml_analysis = classify_with_local_ml(
        subject,
        combined_text,
        sender,
        urls,
        [item.get("filename", "") for item in attachments if isinstance(item, dict)],
    )

    # ========================================================
    # EVIDENCE
    # ========================================================

    evidence = build_evidence(
        authentication,
        url_analysis,
        content_analysis,
        sender_analysis,
        impersonation,
        attachment_analysis,
        bec_analysis
    )

    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_data = calculate_risk_score(
        authentication,
        url_analysis,
        content_analysis,
        sender_analysis,
        attachment_analysis,
        impersonation,
        bec_analysis
    )

    ml_label = ml_analysis.get("ml_classification")
    ml_confidence = float(ml_analysis.get("ml_confidence") or 0)
    if ml_label not in {"LEGITIMATE", ""} and ml_confidence >= 0.65:
        risk_data["risk_score"] = min(100, int(risk_data["risk_score"] + round(8 * ml_confidence)))
        risk_data.setdefault("components", {})["local_ml"] = {
            "score": round(8 * ml_confidence),
            "max_score": 8,
            "findings": [f"Local ML classifier supports {ml_label} with {ml_confidence:.0%} confidence."],
        }

    # Every analysis gets its own investigation/case identifier.
    # evidence_id remains the SHA-256-derived evidence identifier, while
    # case_id uniquely represents this analysis event. This means analyzing
    # the same email again still creates a separate historical investigation.
    case_id = "INV-" + uuid4().hex[:12].upper()

    # Cross-case correlation is calculated before the final classification.
    # It compares the current email's observable indicators with previously
    # analyzed cases stored locally in SQLite.
    current_case = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "filename": filename,
        "subject": subject,
        "from": sender,
        "to": recipient,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "date": parsed_date,
        "sender_domain": sender_analysis.get("sender_domain", ""),
        "reply_to_domain": sender_analysis.get("reply_to_domain", ""),
        "return_path_domain": sender_analysis.get("return_path_domain", ""),
        "ips": ips,
        "urls": urls,
        "domains": unique_list(
            [
                sender_analysis.get("sender_domain", ""),
                sender_analysis.get("reply_to_domain", ""),
                sender_analysis.get("return_path_domain", ""),
            ] + [_domain_from_url_value(url) for url in urls]
        ),
        "attachments": [a.get("filename", "") for a in attachments if isinstance(a, dict)],
        "classification": classification if "classification" in locals() else "",
        "risk_score": risk_data["risk_score"],
        "risk_level": get_risk_level(risk_data["risk_score"]),
        "confidence": "",
    }

    correlation = correlate_case(current_case)
    correlation_points = min(10, int(round((correlation.get("best_match_score", 0) or 0) / 10)))

    risk_score = min(100, risk_data["risk_score"] + correlation_points)

    risk_data["risk_score"] = risk_score
    risk_data["components"]["correlation"] = {
        "score": correlation_points,
        "max_score": 10,
        "findings": correlation.get("risk_findings", [])
            or (["No meaningful cross-case match found"] if not correlation.get("related_cases") else [])
    }

    risk_level = get_risk_level(
        risk_score
    )

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    classification = classify_threat(
        risk_score,
        content_analysis,
        attachment_analysis,
        impersonation,
        bec_analysis,
        url_analysis
    )

    if classification == "LEGITIMATE" and ml_label not in {"LEGITIMATE", ""} and ml_confidence >= 0.8:
        classification = ml_label

    # ========================================================
    # CONFIDENCE
    # ========================================================

    confidence = calculate_confidence(
        evidence,
        authentication,
        attachment_analysis
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    summary = generate_summary(
        classification,
        risk_score,
        risk_level,
        evidence,
        authentication
    )

    attribution_support = build_attribution_support(
        sender_analysis,
        impersonation,
        authentication,
        correlation,
        sending_infrastructure,
    )
    compromised_account_indicator = build_compromised_account_indicator(
        sender_analysis,
        authentication,
        impersonation,
        correlation,
    )

    # ========================================================
    # THREAT EVIDENCE GRAPH
    # ========================================================

    threat_graph = build_threat_graph(
        email={
            "subject": subject,
            "from": sender,
            "to": recipient,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": message_id,
            "date": parsed_date
        },
        indicators={
            "urls": urls,
            "ips": ips
        },
        smtp_relay=received_headers,
        attachments=attachments,
        evidence_id=evidence_id
    )
    # ========================================================
    # LIMITATIONS
    # ========================================================

    limitations = [
        "This prototype uses deterministic forensic rules; it is not a substitute for a full malware sandbox or enterprise threat-intelligence platform.",
        "IP addresses and geolocation indicators do not by themselves prove attacker identity or physical location.",
        "URL and domain characteristics are indicators and do not by themselves prove that a URL or domain is malicious.",
        "Historical campaign correlation and external reputation enrichment will be added in the threat-intelligence and case-correlation modules.",
        "DKIM signature presence does not prove that DKIM validation passed."
    ]

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    analysis_result = {

        "status": "success",

        # ----------------------------------------------------
        # File
        # ----------------------------------------------------

        "file": {

            "filename": filename,

            "content_type": file.content_type,

            "size": len(contents)

        },

        # ----------------------------------------------------
        # Evidence Preservation
        # ----------------------------------------------------

        "evidence": {

            "evidence_id": evidence_id,

            "sha256": sha256_hash,

            "size": len(contents),

            "captured_at": captured_at,

            "preservation": (
                "Original uploaded bytes were hashed at ingestion."
            )

        },

        # ----------------------------------------------------
        # Email
        # ----------------------------------------------------

        "email": {

            "subject": subject,

            "from": sender,

            "to": recipient,

            "reply_to": reply_to,

            "return_path": return_path,

            "message_id": message_id,

            "date": parsed_date

        },

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "authentication": authentication,

        # ----------------------------------------------------
        # Headers
        # ----------------------------------------------------

        "headers": headers,

        # ----------------------------------------------------
        # SMTP Relay
        # ----------------------------------------------------

        "smtp_relay": received_headers,

        # ----------------------------------------------------
        # SMTP Sending Infrastructure Assessment
        # ----------------------------------------------------

        "sending_infrastructure": sending_infrastructure,

        # ----------------------------------------------------
        # Indicators
        # ----------------------------------------------------

        "indicators": {

            "urls": urls,

            "ips": ips

        },

        # ----------------------------------------------------
        # URL Intelligence
        # ----------------------------------------------------

        "url_analysis": url_analysis,

        # ----------------------------------------------------
        # Attachments
        # ----------------------------------------------------

        "attachments": attachments,

        "attachment_analysis": attachment_analysis,

        # ----------------------------------------------------
        # Body
        # ----------------------------------------------------

        "body": {

            "plain_text_length": len(
                plain_text
            ),

            "html_length": len(
                html_text
            )

        },

        # ----------------------------------------------------
        # Sender Analysis
        # ----------------------------------------------------

        "sender_analysis": sender_analysis,

        # ----------------------------------------------------
        # Impersonation
        # ----------------------------------------------------

        "impersonation": impersonation,

        # ----------------------------------------------------
        # BEC
        # ----------------------------------------------------

        "bec_analysis": bec_analysis,

        "ml_analysis": ml_analysis,

        "attribution_support": attribution_support,

        "compromised_account_indicator": compromised_account_indicator,

        # ----------------------------------------------------
        # Threat Detection
        # ----------------------------------------------------

        "threat_detection": {

            "classification": classification,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "confidence": confidence,

            "summary": summary,

            "components": risk_data["components"],

            "evidence": evidence,

            "limitations": limitations

        },

        "investigation": {
            "case_id": case_id,
            "created_at": captured_at,
            "storage": "Local SQLite forensic case store"
        },

        "threat_graph": threat_graph,

        "correlation": correlation

    }

    analysis_result["correlation"] = persist_case_and_recalculate_correlation(
        analysis_result
    )
    return analysis_result

# ============================================================
# CROSS-CASE CORRELATION / INVESTIGATION STORE
# ============================================================
# MailTrace keeps a lightweight local SQLite case index. It stores the
# structured forensic result for each investigation, but NOT the original
# uploaded email bytes. case_id is unique for every analysis event.

CASE_DB_PATH = Path(os.getenv("MAILTRACE_DB_PATH", str(Path(__file__).resolve().parent / "mailtrace_cases.db"))).resolve()


def get_db_connection():
    """Return a configured SQLite connection used by the entire application."""
    CASE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(CASE_DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def _domain_from_url_value(url_value):
    try:
        return normalize_domain(urlparse(url_value).hostname or "")
    except Exception:
        return ""


def _safe_json_list(value):
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _new_case_id():
    return "INV-" + uuid4().hex[:12].upper()


def init_case_store():
    CASE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = get_db_connection()
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cases'"
        ).fetchone()

        if not table:
            connection.execute(
                """
                CREATE TABLE cases (
                    case_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    filename TEXT,
                    subject TEXT,
                    sender TEXT,
                    recipient TEXT,
                    sender_domain TEXT,
                    reply_to_domain TEXT,
                    return_path_domain TEXT,
                    message_id TEXT,
                    classification TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    confidence TEXT,
                    sha256 TEXT,
                    ips_json TEXT NOT NULL,
                    urls_json TEXT NOT NULL,
                    domains_json TEXT NOT NULL,
                    attachments_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
        else:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(cases)").fetchall()]

            # Migrate the older v5 schema where evidence_id was the primary key.
            if "case_id" not in columns:
                connection.execute("ALTER TABLE cases RENAME TO cases_legacy_v5")
                connection.execute(
                    """
                    CREATE TABLE cases (
                        case_id TEXT PRIMARY KEY,
                        evidence_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        filename TEXT,
                        subject TEXT,
                        sender TEXT,
                        recipient TEXT,
                        sender_domain TEXT,
                        reply_to_domain TEXT,
                        return_path_domain TEXT,
                        message_id TEXT,
                        classification TEXT,
                        risk_score INTEGER,
                        risk_level TEXT,
                        confidence TEXT,
                        sha256 TEXT,
                        ips_json TEXT NOT NULL,
                        urls_json TEXT NOT NULL,
                        domains_json TEXT NOT NULL,
                        attachments_json TEXT NOT NULL,
                        analysis_json TEXT NOT NULL DEFAULT '{}'
                    )
                    """
                )
                legacy_rows = connection.execute(
                    """
                    SELECT evidence_id, created_at, filename, subject, sender, recipient,
                           sender_domain, reply_to_domain, return_path_domain, message_id,
                           classification, risk_score, risk_level, confidence, sha256,
                           ips_json, urls_json, domains_json, attachments_json
                    FROM cases_legacy_v5
                    ORDER BY created_at ASC
                    """
                ).fetchall()

                for row in legacy_rows:
                    connection.execute(
                        """
                        INSERT INTO cases (
                            case_id, evidence_id, created_at, filename, subject, sender, recipient,
                            sender_domain, reply_to_domain, return_path_domain, message_id,
                            classification, risk_score, risk_level, confidence, sha256,
                            ips_json, urls_json, domains_json, attachments_json, analysis_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (_new_case_id(), *row, "{}"),
                    )

                connection.execute("DROP TABLE cases_legacy_v5")
            elif "analysis_json" not in columns:
                connection.execute(
                    "ALTER TABLE cases ADD COLUMN analysis_json TEXT NOT NULL DEFAULT '{}'"
                )

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_evidence_id ON cases(evidence_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_sender_domain ON cases(sender_domain)"
        )
        # AI Investigator conversation history is persisted per case.
        # Only questions/answers are stored; raw email bytes are never stored here.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_messages (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                message_text TEXT NOT NULL,
                facts_json TEXT NOT NULL DEFAULT '[]',
                evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_hash TEXT,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_events(case_id)")

        connection.commit()
    finally:
        connection.close()


def _case_row_to_dict(row):
    return {
        "case_id": row[0],
        "evidence_id": row[1],
        "created_at": row[2],
        "filename": row[3] or "",
        "subject": row[4] or "",
        "sender": row[5] or "",
        "recipient": row[6] or "",
        "sender_domain": row[7] or "",
        "reply_to_domain": row[8] or "",
        "return_path_domain": row[9] or "",
        "message_id": row[10] or "",
        "classification": row[11] or "",
        "risk_score": row[12] or 0,
        "risk_level": row[13] or "LOW",
        "confidence": row[14] or "LOW",
        "sha256": row[15] or "",
        "ips": json.loads(row[16] or "[]"),
        "urls": json.loads(row[17] or "[]"),
        "domains": json.loads(row[18] or "[]"),
        "attachments": json.loads(row[19] or "[]"),
    }


def _load_case_records(limit=200, exclude_case_id=None):
    connection = get_db_connection()
    try:
        sql = """
            SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                   sender_domain, reply_to_domain, return_path_domain, message_id,
                   classification, risk_score, risk_level, confidence, sha256,
                   ips_json, urls_json, domains_json, attachments_json
            FROM cases
        """
        params = []
        if exclude_case_id:
            sql += " WHERE case_id != ?"
            params.append(exclude_case_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(int(limit))
        rows = connection.execute(sql, tuple(params)).fetchall()
        return [_case_row_to_dict(row) for row in rows]
    finally:
        connection.close()


def _case_feature_sets(case):
    return {
        "ips": set(_safe_json_list(case.get("ips"))),
        "urls": set(_safe_json_list(case.get("urls"))),
        "domains": set(_safe_json_list(case.get("domains"))),
        "attachments": set(_safe_json_list(case.get("attachments"))),
        "sender_domain": str(case.get("sender_domain") or "").lower(),
        "reply_to_domain": str(case.get("reply_to_domain") or "").lower(),
        "return_path_domain": str(case.get("return_path_domain") or "").lower(),
    }


def score_case_similarity(current_case, candidate_case):
    current = _case_feature_sets(current_case)
    candidate = _case_feature_sets(candidate_case)

    score = 0
    shared = []
    reasons = []

    shared_ips = sorted(current["ips"] & candidate["ips"])
    shared_urls = sorted(current["urls"] & candidate["urls"])
    shared_domains = sorted(current["domains"] & candidate["domains"])
    shared_attachments = sorted(current["attachments"] & candidate["attachments"])

    if shared_ips:
        score += min(30, 20 + 5 * len(shared_ips))
        shared.append({"type": "IP", "values": shared_ips[:10]})
        reasons.append("Shared network indicator(s)")

    if shared_urls:
        score += min(35, 25 + 10 * len(shared_urls))
        shared.append({"type": "URL", "values": shared_urls[:10]})
        reasons.append("Shared exact URL indicator(s)")

    if shared_domains:
        score += min(25, 15 + 5 * len(shared_domains))
        shared.append({"type": "DOMAIN", "values": shared_domains[:10]})
        reasons.append("Shared domain indicator(s)")

    if current["sender_domain"] and current["sender_domain"] == candidate["sender_domain"]:
        score += 15
        shared.append({"type": "SENDER_DOMAIN", "values": [current["sender_domain"]]})
        reasons.append("Same sender domain")

    if current["reply_to_domain"] and current["reply_to_domain"] == candidate["reply_to_domain"]:
        score += 10
        shared.append({"type": "REPLY_TO_DOMAIN", "values": [current["reply_to_domain"]]})
        reasons.append("Same Reply-To domain")

    if current["return_path_domain"] and current["return_path_domain"] == candidate["return_path_domain"]:
        score += 8
        shared.append({"type": "RETURN_PATH_DOMAIN", "values": [current["return_path_domain"]]})
        reasons.append("Same Return-Path domain")

    if shared_attachments:
        score += min(10, 5 * len(shared_attachments))
        shared.append({"type": "ATTACHMENT", "values": shared_attachments[:10]})
        reasons.append("Shared attachment name(s)")

    score = min(100, score)

    if score >= 70:
        confidence = "HIGH"
    elif score >= 40:
        confidence = "MEDIUM"
    elif score >= 20:
        confidence = "LOW"
    else:
        confidence = "NONE"

    return {
        "score": score,
        "confidence": confidence,
        "shared_indicators": shared,
        "reasons": reasons,
    }


def correlate_case(current_case, limit=5, minimum_score=20):
    candidates = _load_case_records(
        limit=200,
        exclude_case_id=current_case.get("case_id"),
    )

    matches = []
    for candidate in candidates:
        similarity = score_case_similarity(current_case, candidate)
        if similarity["score"] < minimum_score:
            continue
        matches.append({
            "case_id": candidate["case_id"],
            "evidence_id": candidate["evidence_id"],
            "created_at": candidate["created_at"],
            "filename": candidate["filename"],
            "subject": candidate["subject"],
            "sender": candidate["sender"],
            "classification": candidate["classification"],
            "risk_score": candidate["risk_score"],
            "risk_level": candidate["risk_level"],
            "confidence": candidate["confidence"],
            "similarity_score": similarity["score"],
            "match_confidence": similarity["confidence"],
            "shared_indicators": similarity["shared_indicators"],
            "reasons": similarity["reasons"],
        })

    matches.sort(
        key=lambda item: (item["similarity_score"], item["created_at"]),
        reverse=True,
    )

    best_score = matches[0]["similarity_score"] if matches else 0

    risk_findings = []
    if best_score >= 70:
        risk_findings.append("Strong cross-case infrastructure/indicator overlap detected")
    elif best_score >= 40:
        risk_findings.append("Moderate cross-case indicator overlap detected")
    elif best_score >= 20:
        risk_findings.append("Low-level cross-case overlap detected")

    return {
        "status": "matched" if matches else "no_match",
        "related_cases": matches[:limit],
        "related_case_count": len(matches),
        "best_match_score": best_score,
        "risk_findings": risk_findings,
        "interpretation": (
            "Related-case similarity is based on shared observable indicators. "
            "It is a correlation signal, not proof that the cases were created by the same actor."
        ),
    }


def persist_case(analysis_result):
    investigation = analysis_result.get("investigation") or {}
    evidence = analysis_result.get("evidence") or {}
    email = analysis_result.get("email") or {}
    sender_analysis = analysis_result.get("sender_analysis") or {}
    indicators = analysis_result.get("indicators") or {}
    attachments = analysis_result.get("attachments") or []
    threat_detection = analysis_result.get("threat_detection") or {}

    case_id = str(investigation.get("case_id") or _new_case_id())
    evidence_id = str(evidence.get("evidence_id") or "")
    if not evidence_id:
        return case_id

    ips = _safe_json_list(indicators.get("ips"))
    urls = _safe_json_list(indicators.get("urls"))
    domains = unique_list(
        [
            str(sender_analysis.get("sender_domain") or ""),
            str(sender_analysis.get("reply_to_domain") or ""),
            str(sender_analysis.get("return_path_domain") or ""),
        ]
        + [_domain_from_url_value(url) for url in urls]
    )
    domains = [domain for domain in domains if domain]
    attachment_names = [
        str(item.get("filename"))
        for item in attachments
        if isinstance(item, dict) and item.get("filename")
    ]

    # Persist the structured forensic analysis so a previous investigation can
    # be reopened later from the Investigations page.
    analysis_json = json.dumps(analysis_result, ensure_ascii=False, separators=(",", ":"))

    connection = get_db_connection()
    try:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, evidence_id, created_at, filename, subject, sender, recipient,
                sender_domain, reply_to_domain, return_path_domain, message_id,
                classification, risk_score, risk_level, confidence, sha256,
                ips_json, urls_json, domains_json, attachments_json, analysis_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_id,
                str((investigation.get("created_at") or evidence.get("captured_at") or datetime.now(timezone.utc).isoformat())),
                str((analysis_result.get("file") or {}).get("filename") or ""),
                str(email.get("subject") or ""),
                str(email.get("from") or ""),
                str(email.get("to") or ""),
                str(sender_analysis.get("sender_domain") or ""),
                str(sender_analysis.get("reply_to_domain") or ""),
                str(sender_analysis.get("return_path_domain") or ""),
                str(email.get("message_id") or ""),
                str(threat_detection.get("classification") or ""),
                int(threat_detection.get("risk_score") or 0),
                str(threat_detection.get("risk_level") or "LOW"),
                str(threat_detection.get("confidence") or "LOW"),
                str(evidence.get("sha256") or ""),
                json.dumps(ips),
                json.dumps(urls),
                json.dumps(domains),
                json.dumps(attachment_names),
                analysis_json,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return case_id


def persist_case_and_recalculate_correlation(analysis_result):
    # The current case is correlated against older records before it is
    # inserted. That prevents self-matching while still preserving every run.
    case_id = persist_case(analysis_result)
    evidence = analysis_result.get("evidence") or {}
    risk = analysis_result.get("threat_detection") or {}
    add_audit_event(case_id, "ANALYSIS_COMPLETED", "Structured forensic analysis completed.", evidence.get("sha256"))
    add_audit_event(case_id, "CASE_CREATED", "Persistent investigation case created.", evidence.get("sha256"))
    threshold = int(os.getenv("MAILTRACE_ALERT_THRESHOLD", "80"))
    if int(risk.get("risk_score") or 0) >= threshold:
        create_alert(
            case_id,
            str(risk.get("risk_level") or "HIGH"),
            "High-risk email investigation",
            f"Case {case_id} reached risk score {risk.get('risk_score')}/100.",
        )
    return analysis_result.get("correlation") or {}


def add_audit_event(case_id, event_type, description, evidence_hash=None):
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT INTO audit_events (event_id, case_id, event_type, timestamp, description, evidence_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (f"EVT-{uuid4().hex[:16].upper()}", case_id, event_type, datetime.now(timezone.utc).isoformat(), description, evidence_hash or None),
        )
        connection.commit()
    finally:
        connection.close()


def create_alert(case_id, severity, title, message):
    connection = get_db_connection()
    try:
        alert_id = f"ALT-{uuid4().hex[:12].upper()}"
        connection.execute(
            "INSERT INTO alerts (alert_id, case_id, severity, title, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (alert_id, case_id, severity, title, message, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    add_audit_event(case_id, "ALERT_CREATED", "A local high-risk alert was created.")
    return alert_id


@app.get("/api/investigations")
def list_investigations(limit: int = 50):
    limit = max(1, min(int(limit), 200))
    cases = _load_case_records(limit=limit)
    return {
        "status": "success",
        "count": len(cases),
        "cases": cases,
    }


@app.get("/api/investigations/{case_id}/analysis")
def get_investigation_analysis(case_id: str):
    connection = get_db_connection()
    try:
        row = connection.execute(
            "SELECT analysis_json FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if not row:
            # Backward-compatible lookup by evidence_id.
            row = connection.execute(
                "SELECT analysis_json FROM cases WHERE evidence_id = ? ORDER BY created_at DESC LIMIT 1",
                (case_id,),
            ).fetchone()
    finally:
        connection.close()

    if not row:
        raise HTTPException(status_code=404, detail="Investigation analysis not found.")

    try:
        payload = json.loads(row[0] or "{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Stored investigation data is invalid.")

    canonical_case_id = ((payload.get("investigation") or {}).get("case_id") or case_id)
    add_audit_event(canonical_case_id, "CASE_VIEWED", "Stored investigation analysis was viewed.")

    return {
        "status": "success",
        "analysis": payload,
    }


@app.get("/api/correlation/{case_id}")
def get_case_correlation(case_id: str):
    connection = get_db_connection()
    try:
        row = connection.execute(
            """
            SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                   sender_domain, reply_to_domain, return_path_domain, message_id,
                   classification, risk_score, risk_level, confidence, sha256,
                   ips_json, urls_json, domains_json, attachments_json
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if not row:
            row = connection.execute(
                """
                SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                       sender_domain, reply_to_domain, return_path_domain, message_id,
                       classification, risk_score, risk_level, confidence, sha256,
                       ips_json, urls_json, domains_json, attachments_json
                FROM cases
                WHERE evidence_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()
    finally:
        connection.close()

    if not row:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    case = _case_row_to_dict(row)
    correlation = correlate_case(case)
    return {
        "status": "success",
        "case": case,
        "correlation": correlation,
    }


# Initialize the local investigation store on backend startup.
init_case_store()


@app.get("/api/database/status")
def database_status():
    """Return the health and basic size of the MailTrace SQLite store."""
    connection = get_db_connection()
    try:
        total = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        latest = connection.execute(
            "SELECT created_at FROM cases ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return {
            "status": "connected",
            "database": str(CASE_DB_PATH),
            "engine": "SQLite",
            "case_count": int(total),
            "latest_case_created_at": latest[0] if latest else None,
            "alert_count": int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]),
            "audit_event_count": int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]),
        }
    finally:
        connection.close()


@app.get("/api/dashboard/summary")
def dashboard_summary():
    """Return dashboard KPIs directly from the persistent case database."""
    connection = get_db_connection()
    try:
        total = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        high_risk = connection.execute(
            "SELECT COUNT(*) FROM cases WHERE UPPER(COALESCE(risk_level, 'LOW')) IN ('HIGH','CRITICAL')"
        ).fetchone()[0]
        suspicious = connection.execute(
            "SELECT COUNT(*) FROM cases WHERE UPPER(COALESCE(classification, '')) <> '' AND UPPER(COALESCE(classification, '')) <> 'LEGITIMATE'"
        ).fetchone()[0]
        unacknowledged_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
        ).fetchone()[0]
        recent_alerts = connection.execute(
            "SELECT alert_id, case_id, severity, title, message, created_at, acknowledged FROM alerts ORDER BY created_at DESC LIMIT 10"
        ).fetchall()

        recent = connection.execute(
            """
            SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                 sender_domain, reply_to_domain, return_path_domain, message_id,
                 classification, risk_score, risk_level, confidence, sha256,
                   ips_json, urls_json, domains_json, attachments_json
            FROM cases
            ORDER BY created_at DESC
            LIMIT 10
            """
        ).fetchall()

        recent_cases = [_case_row_to_dict(tuple(row)) for row in recent]

        risk_rows = connection.execute(
            "SELECT UPPER(COALESCE(risk_level,'LOW')) AS level, COUNT(*) AS count FROM cases GROUP BY UPPER(COALESCE(risk_level,'LOW'))"
        ).fetchall()
        risk_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for row in risk_rows:
            level = str(row[0] or "LOW")
            risk_distribution[level] = int(row[1])

        # Seven-day activity is calculated in the database so the Dashboard
        # does not need to download every historical case just to draw a chart.
        now_utc = datetime.now(timezone.utc)
        day_keys = []
        for offset in range(6, -1, -1):
            day = (now_utc.date() - timedelta(days=offset))
            day_keys.append(day.isoformat())

        activity_rows = connection.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count
            FROM cases
            WHERE substr(created_at, 1, 10) >= ?
            GROUP BY substr(created_at, 1, 10)
            ORDER BY day
            """,
            (day_keys[0],),
        ).fetchall()

        activity_counts = {str(row[0]): int(row[1]) for row in activity_rows}
        activity_last_7_days = [
            {
                "date": day_key,
                "count": activity_counts.get(day_key, 0),
            }
            for day_key in day_keys
        ]

        return {
            "status": "success",
            "database": "SQLite",
            "total_investigations": int(total),
            "high_risk": int(high_risk),
            "suspicious_cases": int(suspicious),
            "unacknowledged_alerts": int(unacknowledged_alerts),
            "recent_alerts": [dict(row) for row in recent_alerts],
            "risk_distribution": risk_distribution,
            "activity_last_7_days": activity_last_7_days,
            "recent_cases": recent_cases,
        }
    finally:
        connection.close()


@app.get("/api/alerts")
def list_alerts(limit: int = 50, unacknowledged_only: bool = False):
    limit = max(1, min(int(limit), 200))
    connection = get_db_connection()
    try:
        query = "SELECT alert_id, case_id, severity, title, message, created_at, acknowledged FROM alerts"
        if unacknowledged_only:
            query += " WHERE acknowledged = 0"
        query += " ORDER BY created_at DESC LIMIT ?"
        rows = connection.execute(query, (limit,)).fetchall()
        return {"status": "success", "count": len(rows), "alerts": [dict(row) for row in rows]}
    finally:
        connection.close()


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT case_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found.")
        connection.execute("UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?", (alert_id,))
        connection.commit()
        add_audit_event(row[0], "ALERT_ACKNOWLEDGED", "High-risk alert was acknowledged.")
        return {"status": "success", "alert_id": alert_id, "acknowledged": True}
    finally:
        connection.close()


@app.get("/api/investigations/{case_id}/audit")
def get_case_audit(case_id: str, limit: int = 200):
    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    canonical_case_id = loaded[0].get("case_id")
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT event_id, case_id, event_type, timestamp, description, evidence_hash FROM audit_events WHERE case_id = ? ORDER BY timestamp ASC LIMIT ?",
            (canonical_case_id, max(1, min(int(limit), 500))),
        ).fetchall()
        return {"status": "success", "case_id": canonical_case_id, "events": [dict(row) for row in rows]}
    finally:
        connection.close()


# ============================================================
# CROSS-CASE THREAT GRAPH
# ============================================================
# This graph is built from the persisted structured investigations.
# It keeps email/case nodes unique while merging exact observable
# indicators (IPs, domains, URLs) across related cases so shared
# infrastructure becomes visually obvious.


def _safe_json(value, fallback):
    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def _load_case_by_id(case_id):
    """Load one persisted case by case_id, with evidence_id fallback."""
    connection = get_db_connection()
    try:
        row = connection.execute(
            """
            SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                   sender_domain, reply_to_domain, return_path_domain, message_id,
                   classification, risk_score, risk_level, confidence, sha256,
                   ips_json, urls_json, domains_json, attachments_json, analysis_json
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if not row:
            row = connection.execute(
                """
                SELECT case_id, evidence_id, created_at, filename, subject, sender, recipient,
                       sender_domain, reply_to_domain, return_path_domain, message_id,
                       classification, risk_score, risk_level, confidence, sha256,
                       ips_json, urls_json, domains_json, attachments_json, analysis_json
                FROM cases
                WHERE evidence_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()
    finally:
        connection.close()

    if not row:
        return None

    case = _case_row_to_dict(row[:20])
    analysis = _safe_json(row[20], {})
    return case, analysis


def _global_indicator_id(kind, value):
    return f"indicator:{kind.lower()}:{value}"


def _add_graph_node(nodes, node_map, node_id, node_type, label, value, properties=None):
    if node_id in node_map:
        # Merge provenance without duplicating the node.
        existing = node_map[node_id]
        if properties:
            existing_props = existing.setdefault("properties", {})
            for key, prop_value in properties.items():
                if key == "case_ids":
                    current = existing_props.setdefault("case_ids", [])
                    for case_id in prop_value if isinstance(prop_value, list) else [prop_value]:
                        if case_id not in current:
                            current.append(case_id)
                elif key not in existing_props or existing_props.get(key) in (None, "", []):
                    existing_props[key] = prop_value
        return

    node = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "value": value,
        "properties": properties or {},
    }
    nodes.append(node)
    node_map[node_id] = node


def _append_graph_edge(edges, edge_keys, source, target, relationship, evidence_id=None, properties=None):
    key = (source, target, relationship)
    if key in edge_keys:
        return
    edge_keys.add(key)
    edges.append({
        "source": source,
        "target": target,
        "relationship": relationship,
        "evidence_id": evidence_id,
        "properties": properties or {},
    })


def _analysis_domains(analysis):
    sender_analysis = analysis.get("sender_analysis") or {}
    indicators = analysis.get("indicators") or {}
    urls = indicators.get("urls") if isinstance(indicators.get("urls"), list) else []

    domains = []
    for value in (
        sender_analysis.get("sender_domain", ""),
        sender_analysis.get("reply_to_domain", ""),
        sender_analysis.get("return_path_domain", ""),
    ):
        domain = normalize_domain(str(value or ""))
        if domain:
            domains.append(domain)

    for url in urls:
        domain = _domain_from_url_value(str(url))
        if domain:
            domains.append(domain)

    return unique_list(domains)


def _build_cross_case_threat_graph(selected_case, selected_analysis, related_cases):
    """Build a merged graph for the selected case and correlated cases."""
    nodes = []
    edges = []
    node_map = {}
    edge_keys = set()

    all_cases = [(selected_case, selected_analysis, True)]
    selected_case_id = selected_case.get("case_id")

    # Load the stored analyses for related cases. Only cases returned by the
    # correlation engine are included, which keeps the graph useful and scoped.
    for related in related_cases:
        case_id = related.get("case_id")
        if not case_id or case_id == selected_case_id:
            continue
        loaded = _load_case_by_id(case_id)
        if not loaded:
            continue
        case_record, analysis = loaded
        all_cases.append((case_record, analysis, False))

    email_node_ids = {}

    for case_record, analysis, is_current in all_cases:
        case_id = case_record.get("case_id") or "unknown-case"
        email_key = f"case:{case_id}:email"
        email_node_ids[case_id] = email_key

        _add_graph_node(
            nodes,
            node_map,
            email_key,
            "EMAIL",
            "Current Investigation" if is_current else "Related Investigation",
            case_id,
            {
                "case_id": case_id,
                "evidence_id": case_record.get("evidence_id", ""),
                "subject": case_record.get("subject", ""),
                "from": case_record.get("sender", ""),
                "to": case_record.get("recipient", ""),
                "classification": case_record.get("classification", ""),
                "risk_score": case_record.get("risk_score", 0),
                "risk_level": case_record.get("risk_level", "LOW"),
                "confidence": case_record.get("confidence", "LOW"),
                "created_at": case_record.get("created_at", ""),
                "current_case": is_current,
                "case_ids": [case_id],
            },
        )

        email_data = analysis.get("email") or {}
        indicators = analysis.get("indicators") or {}
        urls = indicators.get("urls") if isinstance(indicators.get("urls"), list) else []
        ips = indicators.get("ips") if isinstance(indicators.get("ips"), list) else []
        sender_analysis = analysis.get("sender_analysis") or {}

        # Sender / reply / return-path domains are merged globally.
        domain_roles = [
            (sender_analysis.get("sender_domain", ""), "SENT_FROM"),
            (sender_analysis.get("reply_to_domain", ""), "REPLIES_TO"),
            (sender_analysis.get("return_path_domain", ""), "RETURN_PATH"),
        ]

        for raw_domain, relation in domain_roles:
            domain = normalize_domain(str(raw_domain or ""))
            if not domain:
                continue
            domain_id = _global_indicator_id("domain", domain)
            _add_graph_node(
                nodes,
                node_map,
                domain_id,
                "DOMAIN",
                "Shared Domain",
                domain,
                {"source": "Email header", "case_ids": [case_id]},
            )
            _append_graph_edge(edges, edge_keys, email_key, domain_id, relation, case_record.get("evidence_id"))

        for url in unique_list([str(value) for value in urls if str(value).strip()]):
            url_id = _global_indicator_id("url", url)
            _add_graph_node(
                nodes,
                node_map,
                url_id,
                "URL",
                "Observed URL",
                url,
                {"case_ids": [case_id]},
            )
            _append_graph_edge(edges, edge_keys, email_key, url_id, "CONTAINS_URL", case_record.get("evidence_id"))

            hostname = _domain_from_url_value(url)
            if hostname:
                domain_id = _global_indicator_id("domain", hostname)
                _add_graph_node(
                    nodes,
                    node_map,
                    domain_id,
                    "DOMAIN",
                    "URL Domain",
                    hostname,
                    {"source": "URL hostname", "case_ids": [case_id]},
                )
                _append_graph_edge(edges, edge_keys, url_id, domain_id, "HOSTED_ON", case_record.get("evidence_id"))

        for ip in unique_list([str(value).strip() for value in ips if str(value).strip()]):
            ip_id = _global_indicator_id("ip", ip)
            _add_graph_node(
                nodes,
                node_map,
                ip_id,
                "IP",
                "Shared IP",
                ip,
                {"source": "Email headers/content", "case_ids": [case_id]},
            )
            _append_graph_edge(edges, edge_keys, email_key, ip_id, "REFERENCES_IP", case_record.get("evidence_id"))

        # Preserve the visible SMTP relay sequence for each case, but scope
        # the edge to that case's unique email node.
        relay = analysis.get("smtp_relay") or []
        if not isinstance(relay, list):
            relay = []
        previous = email_key
        for hop in relay:
            if not isinstance(hop, dict):
                continue
            hop_number = hop.get("hop", 0)
            hop_ips = hop.get("ips") if isinstance(hop.get("ips"), list) else []
            for hop_ip in hop_ips:
                ip = str(hop_ip).strip()
                if not ip:
                    continue
                ip_id = _global_indicator_id("ip", ip)
                _add_graph_node(
                    nodes,
                    node_map,
                    ip_id,
                    "IP",
                    "SMTP Relay IP",
                    ip,
                    {"source": "Received header", "hop": hop_number, "case_ids": [case_id]},
                )
                _append_graph_edge(
                    edges,
                    edge_keys,
                    previous,
                    ip_id,
                    "RELAYED_THROUGH",
                    case_record.get("evidence_id"),
                    {"hop": hop_number, "case_id": case_id},
                )
                previous = ip_id

        attachments = analysis.get("attachments") or []
        if isinstance(attachments, list):
            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue
                filename = str(attachment.get("filename") or "").strip()
                if not filename:
                    continue
                # Attachment nodes stay case-scoped to avoid treating identical
                # filenames as proof of shared malware.
                attachment_id = f"case:{case_id}:attachment:{filename}"
                _add_graph_node(
                    nodes,
                    node_map,
                    attachment_id,
                    "ATTACHMENT",
                    "Attachment",
                    filename,
                    {
                        "case_id": case_id,
                        "content_type": attachment.get("content_type", ""),
                        "size": attachment.get("size", 0),
                    },
                )
                _append_graph_edge(edges, edge_keys, email_key, attachment_id, "HAS_ATTACHMENT", case_record.get("evidence_id"))

    # Explicit correlation edges make the cross-case relationship visible even
    # when there is only one shared indicator node.
    correlation_cache = correlate_case(selected_case, limit=max(20, len(related_cases) + 5), minimum_score=20)
    related_by_id = {item.get("case_id"): item for item in correlation_cache.get("related_cases", [])}

    campaign_node_id = f"campaign:cluster:{selected_case_id}"
    if related_by_id:
        _add_graph_node(
            nodes,
            node_map,
            campaign_node_id,
            "CAMPAIGN",
            "Potential Campaign Cluster",
            f"Cluster around {selected_case_id}",
            {
                "case_id": selected_case_id,
                "related_case_count": len(related_by_id),
                "interpretation": "Correlation based on shared observable indicators; not proof of same actor.",
                "case_ids": [selected_case_id] + list(related_by_id.keys()),
            },
        )
        _append_graph_edge(
            edges,
            edge_keys,
            email_node_ids[selected_case_id],
            campaign_node_id,
            "POTENTIAL_CAMPAIGN",
            selected_case.get("evidence_id"),
        )

        for related_id, match in related_by_id.items():
            if related_id not in email_node_ids:
                continue
            _append_graph_edge(
                edges,
                edge_keys,
                email_node_ids[selected_case_id],
                email_node_ids[related_id],
                "CORRELATED_WITH",
                selected_case.get("evidence_id"),
                {
                    "similarity_score": match.get("similarity_score", 0),
                    "match_confidence": match.get("match_confidence", "NONE"),
                    "reasons": match.get("reasons", []),
                },
            )
            _append_graph_edge(
                edges,
                edge_keys,
                email_node_ids[related_id],
                campaign_node_id,
                "POTENTIAL_CAMPAIGN",
                match.get("evidence_id"),
            )

    # Compute statistics.
    node_counts = {}
    relationship_counts = {}
    for node in nodes:
        node_type = node.get("type", "UNKNOWN")
        node_counts[node_type] = node_counts.get(node_type, 0) + 1
    for edge in edges:
        relationship = edge.get("relationship", "UNKNOWN")
        relationship_counts[relationship] = relationship_counts.get(relationship, 0) + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": node_counts,
            "relationships": relationship_counts,
        },
        "graph_metadata": {
            "case_id": selected_case_id,
            "evidence_id": selected_case.get("evidence_id", ""),
            "description": "Cross-case forensic evidence graph using the selected investigation and observable-indicator-correlated cases.",
            "scope": "selected_case_and_correlated_cases",
            "related_case_count": len(related_by_id),
            "limitations": [
                "Shared indicators are correlation signals, not proof that the same actor created the cases.",
                "Infrastructure location is not sender physical location or identity attribution.",
            ],
        },
    }


@app.get("/api/threat-graph/{case_id}")
def get_threat_graph(case_id: str):
    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    case, analysis = loaded
    correlation = correlate_case(case, limit=8, minimum_score=20)
    graph = _build_cross_case_threat_graph(
        case,
        analysis,
        correlation.get("related_cases", []),
    )

    return {
        "status": "success",
        "case": case,
        "correlation": correlation,
        "threat_graph": graph,
    }


# ============================================================
# AI INVESTIGATOR (EXPLAINABLE CASE Q&A)
# ============================================================

def _ai_investigator_answer(case_id: str, question: str):
    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    case, analysis = loaded
    correlation = correlate_case(case, limit=8, minimum_score=20)
    threat = analysis.get("threat_detection") or {}
    authentication = analysis.get("authentication") or {}
    email = analysis.get("email") or {}
    indicators = analysis.get("indicators") or {}
    sending = analysis.get("sending_infrastructure") or {}
    smtp_relay = analysis.get("smtp_relay") or []
    impersonation = analysis.get("impersonation") or {}
    bec = analysis.get("bec_analysis") or {}
    attachments = analysis.get("attachments") or []
    url_analysis = analysis.get("url_analysis") or []

    q = (question or "").strip().lower()
    if not q:
        raise HTTPException(status_code=400, detail="Question is required.")

    evidence_refs = [case.get("evidence_id", "")]
    facts = []
    answer = ""

    risk_score = threat.get("risk_score")
    risk_level = threat.get("risk_level")
    classification = threat.get("classification")
    confidence = threat.get("confidence")

    if any(term in q for term in ["why", "risk", "danger", "suspicious", "malicious", "threat"]):
        reasons = []
        components = threat.get("components") or []
        for item in components:
            if isinstance(item, dict):
                label = item.get("name") or item.get("label") or item.get("component")
                points = item.get("points")
                if label and points not in (None, 0):
                    reasons.append(f"{label}: {points} points")
        if not reasons:
            reasons = list(threat.get("evidence") or [])[:6]
        answer = (
            f"Case {case_id} is classified as {classification or 'UNKNOWN'} with a {risk_level or 'UNKNOWN'} risk level, "
            f"score {risk_score if risk_score is not None else 'Ã¢â‚¬â€'}/100 and {confidence or 'UNKNOWN'} confidence. "
            + ("The main recorded signals are " + "; ".join(map(str, reasons[:6])) + "." if reasons else "No detailed risk components were stored.")
        )
        facts = reasons[:8]

    elif any(term in q for term in ["ioc", "indicator", "ip", "url", "domain"]):
        ips = indicators.get("ips") or []
        urls = indicators.get("urls") or []
        domains = sorted(set(
            [normalize_domain(urlparse(u).hostname or "") for u in urls if isinstance(u, str)]
            + ([extract_email_domain(email.get("from", ""))] if email.get("from") else [])
        ))
        facts = []
        if ips:
            facts.append("IPs: " + ", ".join(ips))
        if domains:
            facts.append("Domains: " + ", ".join([d for d in domains if d]))
        if urls:
            facts.append("URLs: " + ", ".join(urls[:8]))
        answer = "Observable indicators for this case: " + (" | ".join(facts) if facts else "No IPs, domains, or URLs were extracted.")

    elif any(term in q for term in ["authentication", "spf", "dkim", "dmarc"]):
        auth_lines = []
        for key in ("spf", "dkim", "dmarc"):
            value = authentication.get(key)
            if isinstance(value, dict):
                result = value.get("result") or value.get("status") or value.get("value") or "unknown"
                auth_lines.append(f"{key.upper()}: {result}")
            elif value is not None:
                auth_lines.append(f"{key.upper()}: {value}")
        answer = "Authentication findings: " + ("; ".join(auth_lines) if auth_lines else "Authentication details were not available in the stored analysis.")
        facts = auth_lines

    elif any(term in q for term in ["sender", "from", "reply-to", "return-path", "impersonat"]):
        answer = (
            f"From: {email.get('from') or 'Ã¢â‚¬â€'}. Reply-To: {email.get('reply_to') or 'Ã¢â‚¬â€'}. "
            f"Return-Path: {email.get('return_path') or 'Ã¢â‚¬â€'}. "
            f"Impersonation assessment: {json.dumps(impersonation, ensure_ascii=False)}"
        )
        facts = [email.get("from"), email.get("reply_to"), email.get("return_path")]

    elif any(term in q for term in ["relay", "received", "smtp", "infrastructure", "sending"]):
        candidate = sending.get("candidate") or {}
        answer = (
            f"The earliest visible sending-infrastructure candidate is {candidate.get('ip') or 'not available'} "
            f"from {candidate.get('source') or 'the analyzed headers'}. "
            f"There are {len(smtp_relay)} parsed SMTP/Received hops. "
            "This identifies observed email infrastructure, not the sender's physical location or identity."
        )
        facts = [f"Received hops: {len(smtp_relay)}", f"Candidate IP: {candidate.get('ip') or 'Ã¢â‚¬â€'}"]

    elif any(term in q for term in ["attachment", "file"]):
        names = [a.get("filename") for a in attachments if isinstance(a, dict) and a.get("filename")]
        answer = "Attachments: " + (", ".join(names) if names else "No stored attachment filenames were found.")
        facts = names

    elif any(term in q for term in ["campaign", "related", "similar", "correlation", "case"]):
        related = correlation.get("related_cases") or []
        if related:
            lines = []
            for match in related[:5]:
                lines.append(f"{match.get('case_id')}: {match.get('similarity_score', 0)}/100 Ã¢â‚¬â€ {', '.join(match.get('reasons') or [])}")
            answer = "Related investigations based on shared observable indicators:\n" + "\n".join(lines)
            facts = [x.get("case_id") for x in related[:5]]
        else:
            answer = "No meaningful related investigations were found using the current observable-indicator correlation rules."

    elif any(term in q for term in ["summary", "overview", "what happened", "explain this email"]):
        answer = (
            f"{threat.get('summary') or 'No summary was stored.'} "
            f"The message subject is '{email.get('subject') or 'Ã¢â‚¬â€'}'. "
            f"Observed indicators include {len(indicators.get('ips') or [])} IP(s) and {len(indicators.get('urls') or [])} URL(s), "
            f"with {len(smtp_relay)} SMTP/Received hop(s) and {len(attachments)} attachment(s)."
        )

    else:
        answer = (
            f"I reviewed case {case_id}. It is {classification or 'UNKNOWN'} / {risk_level or 'UNKNOWN'} "
            f"with score {risk_score if risk_score is not None else 'Ã¢â‚¬â€'}/100 and {confidence or 'UNKNOWN'} confidence. "
            "Try asking about risk, IOCs, authentication, sender identity signals, SMTP relay, attachments, or related cases."
        )

    return {
        "status": "success",
        "mode": "explainable-case-investigator",
        "case_id": case_id,
        "question": question,
        "answer": answer,
        "facts": [str(x) for x in facts if x not in (None, "")],
        "evidence_refs": evidence_refs,
        "related_case_count": len(correlation.get("related_cases") or []),
        "guardrails": [
            "Answers are grounded in the stored case analysis and observable indicators.",
            "Infrastructure geolocation is not sender physical location or identity attribution.",
            "Shared indicators are correlation signals, not proof of the same actor.",
        ],
    }


def _try_llm_investigator(case_id: str, question: str):
    """Ask an optional OpenAI-compatible provider using structured case evidence only."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None

    loaded = _load_case_by_id(case_id)
    if not loaded:
        return None

    case, analysis = loaded
    correlation = correlate_case(case, limit=8, minimum_score=20)
    evidence = {
        "case": case,
        "analysis": analysis,
        "correlation": correlation,
    }
    prompt = (
        "You are a digital email forensics assistant. Use only the supplied case evidence. "
        "Do not invent facts. Do not infer physical location from IP geolocation. Do not claim actor identity. "
        "Clearly distinguish observed evidence, inference, and uncertainty. If evidence is insufficient, say so.\n\n"
        f"Question: {question}\n\nStructured case evidence:\n"
        + json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    )
    payload = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": "Answer only from supplied digital-forensic evidence."},
            {"role": "user", "content": prompt},
        ],
    }

    try:
        request = Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
        answer = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not isinstance(answer, str) or not answer.strip():
            return None
        return {
            "status": "success",
            "mode": "openai-evidence-grounded",
            "case_id": case_id,
            "question": question,
            "answer": answer.strip(),
            "facts": [],
            "evidence_refs": [case.get("evidence_id", "")],
            "related_case_count": len(correlation.get("related_cases") or []),
            "guardrails": [
                "The provider received structured stored case evidence only.",
                "Infrastructure geolocation is not sender physical location or identity attribution.",
                "Shared indicators are correlation signals, not proof of the same actor.",
            ],
        }
    except Exception:
        # A provider outage must never make the core investigator unusable.
        return None


@app.get("/api/ai-investigator/status")
def ai_investigator_status():
    return {
        "status": "configured" if os.getenv("OPENAI_API_KEY", "").strip() else "fallback",
        "provider": "OpenAI-compatible",
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "fallback": "deterministic evidence-grounded investigator",
    }


def _save_ai_message(case_id: str, role: str, message_text: str, facts=None, evidence_refs=None):
    if role not in {"user", "assistant"}:
        raise ValueError("Invalid AI message role")

    connection = get_db_connection()
    try:
        # Resolve evidence_id inputs to the canonical case_id.
        row = connection.execute(
            "SELECT case_id FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if not row:
            row = connection.execute(
                "SELECT case_id FROM cases WHERE evidence_id = ? ORDER BY created_at DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        if not row:
            return None

        canonical_case_id = row[0]
        cursor = connection.execute(
            """
            INSERT INTO ai_messages (
                case_id, created_at, role, message_text, facts_json, evidence_refs_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                canonical_case_id,
                datetime.now(timezone.utc).isoformat(),
                role,
                str(message_text or ""),
                json.dumps(facts or [], ensure_ascii=False),
                json.dumps(evidence_refs or [], ensure_ascii=False),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


@app.get("/api/ai-investigator/{case_id}/history")
def get_ai_investigator_history(case_id: str, limit: int = 100):
    limit = max(1, min(int(limit), 500))
    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    canonical_case_id = loaded[0].get("case_id")
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT message_id, created_at, role, message_text, facts_json, evidence_refs_json
            FROM ai_messages
            WHERE case_id = ?
            ORDER BY message_id ASC
            LIMIT ?
            """,
            (canonical_case_id, limit),
        ).fetchall()
    finally:
        connection.close()

    messages = []
    for row in rows:
        try:
            facts = json.loads(row[4] or "[]")
        except Exception:
            facts = []
        try:
            refs = json.loads(row[5] or "[]")
        except Exception:
            refs = []

        messages.append({
            "message_id": row[0],
            "created_at": row[1],
            "role": row[2],
            "text": row[3],
            "facts": facts if isinstance(facts, list) else [],
            "refs": refs if isinstance(refs, list) else [],
        })

    return {
        "status": "success",
        "case_id": canonical_case_id,
        "count": len(messages),
        "messages": messages,
    }


@app.delete("/api/ai-investigator/{case_id}/history")
def clear_ai_investigator_history(case_id: str):
    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    canonical_case_id = loaded[0].get("case_id")
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "DELETE FROM ai_messages WHERE case_id = ?",
            (canonical_case_id,),
        )
        connection.commit()
        return {
            "status": "success",
            "case_id": canonical_case_id,
            "deleted": int(cursor.rowcount),
        }
    finally:
        connection.close()


@app.post("/api/ai-investigator")
def ai_investigator(payload: dict):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required.")

    case_id = str(payload.get("case_id") or payload.get("evidence_id") or "").strip()
    question = str(payload.get("question") or "").strip()

    if not case_id:
        raise HTTPException(status_code=400, detail="case_id is required.")
    if not question:
        raise HTTPException(status_code=400, detail="question is required.")

    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    answer_payload = _try_llm_investigator(case_id, question) or _ai_investigator_answer(case_id, question)

    # Persist the user question and evidence-grounded answer in SQLite.
    _save_ai_message(case_id, "user", question)
    _save_ai_message(
        case_id,
        "assistant",
        answer_payload.get("answer", ""),
        answer_payload.get("facts") or [],
        answer_payload.get("evidence_refs") or [],
    )

    return answer_payload


# ============================================================
# FORENSIC REPORTS
# ============================================================

@app.get("/api/reports/{case_id}")
def get_forensic_report(case_id: str):
    """Return a structured report payload for a stored investigation."""

    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    case, analysis = loaded
    correlation = correlate_case(case, limit=8, minimum_score=20)
    threat = analysis.get("threat_detection") or {}
    email = analysis.get("email") or {}
    evidence = analysis.get("evidence") or {}
    authentication = analysis.get("authentication") or {}
    indicators = analysis.get("indicators") or {}
    sending = analysis.get("sending_infrastructure") or {}
    relay = analysis.get("smtp_relay") or []
    attachments = analysis.get("attachments") or []
    impersonation = analysis.get("impersonation") or {}
    add_audit_event(case_id, "REPORT_GENERATED", "Structured forensic report was generated.", evidence.get("sha256"))
    audit = get_case_audit(case_id)

    return {
        "status": "success",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report": {
            "title": "MailTrace AI Forensic Investigation Report",
            "case": case,
            "evidence": evidence,
            "email": email,
            "threat_detection": threat,
            "authentication": authentication,
            "indicators": indicators,
            "sending_infrastructure": sending,
            "smtp_relay": relay,
            "attachments": attachments,
            "impersonation": impersonation,
            "ml_analysis": analysis.get("ml_analysis") or {},
            "attribution_support": analysis.get("attribution_support") or {},
            "compromised_account_indicator": analysis.get("compromised_account_indicator") or {},
            "alerts": [item for item in list_alerts(limit=200).get("alerts", []) if item.get("case_id") == case.get("case_id")],
            "chain_of_custody": audit.get("events", []),
            "correlation": correlation,
            "limitations": analysis.get("threat_detection", {}).get("limitations", []),
        },
    }


@app.get("/api/reports/{case_id}/pdf")
def download_forensic_report_pdf(case_id: str):
    """Generate a compact, printable PDF report for the stored case."""

    loaded = _load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    case, analysis = loaded
    correlation = correlate_case(case, limit=8, minimum_score=20)
    threat = analysis.get("threat_detection") or {}
    email = analysis.get("email") or {}
    evidence = analysis.get("evidence") or {}
    authentication = analysis.get("authentication") or {}
    indicators = analysis.get("indicators") or {}
    sending = analysis.get("sending_infrastructure") or {}
    relay = analysis.get("smtp_relay") or []
    attachments = analysis.get("attachments") or []

    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="PDF generation requires reportlab. Install it with: pip install reportlab",
        ) from exc

    def safe(value):
        if value is None or value == "":
            return "Ã¢â‚¬â€"
        return str(value)

    def multiline(items):
        if not items:
            return "Ã¢â‚¬â€"
        return "<br/>".join(safe(item) for item in items[:20])

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"MailTrace AI - {case.get('case_id', case_id)}",
        author="MailTrace AI",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8.5, leading=11))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], spaceBefore=8, spaceAfter=5))

    story = [
        Paragraph("MailTrace AI Forensic Investigation Report", styles["Title"]),
        Paragraph(f"Case ID: {safe(case.get('case_id'))}", styles["Heading3"]),
        Spacer(1, 6),
    ]

    def add_table(rows):
        table = Table(rows, colWidths=[45 * mm, 125 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9aa4b2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f8")]),
        ]))
        story.append(table)
        story.append(Spacer(1, 7))

    story.append(Paragraph("Case & Threat Assessment", styles["Section"]))
    add_table([
        ["Field", "Value"],
        ["Classification", safe(threat.get("classification"))],
        ["Risk Score", safe(threat.get("risk_score")) + "/100"],
        ["Risk Level", safe(threat.get("risk_level"))],
        ["Confidence", safe(threat.get("confidence"))],
        ["Evidence ID", safe(evidence.get("evidence_id"))],
        ["SHA-256", safe(evidence.get("sha256"))],
    ])

    story.append(Paragraph("Email Metadata", styles["Section"]))
    add_table([
        ["Field", "Value"],
        ["Subject", safe(email.get("subject"))],
        ["From", safe(email.get("from"))],
        ["To", safe(email.get("to"))],
        ["Reply-To", safe(email.get("reply_to"))],
        ["Return-Path", safe(email.get("return_path"))],
        ["Message-ID", safe(email.get("message_id"))],
    ])

    story.append(Paragraph("Authentication", styles["Section"]))
    auth_rows = [["Protocol", "Recorded Result"]]
    for key in ("spf", "dkim", "dmarc"):
        value = authentication.get(key)
        if isinstance(value, dict):
            result = value.get("result") or value.get("status") or value.get("value") or "unknown"
        else:
            result = value if value is not None else "unknown"
        auth_rows.append([key.upper(), safe(result)])
    add_table(auth_rows)

    story.append(Paragraph("Observable Indicators", styles["Section"]))
    add_table([
        ["Indicator", "Observed values"],
        ["IPs", multiline(indicators.get("ips") or [])],
        ["URLs", multiline(indicators.get("urls") or [])],
    ])

    candidate = sending.get("candidate") or {}
    story.append(Paragraph("Sending Infrastructure & SMTP Path", styles["Section"]))
    add_table([
        ["Field", "Value"],
        ["Earliest Visible Candidate", safe(candidate.get("ip"))],
        ["Candidate Source", safe(candidate.get("source"))],
        ["SMTP/Received Hops", safe(len(relay))],
    ])
    story.append(Paragraph(
        "Infrastructure location is not sender physical location or identity attribution. "
        "Observed relay information is an evidence indicator, not proof of the sender's identity.",
        styles["Small"],
    ))

    story.append(Paragraph("Attachments", styles["Section"]))
    add_table([["Attachment", "Metadata"]] + [
        [safe(item.get("filename")), safe(item.get("content_type")) + "; " + safe(item.get("size")) + " bytes"]
        for item in attachments[:20] if isinstance(item, dict)
    ] or [["Attachment", "None recorded"]])

    story.append(Paragraph("Cross-Case Correlation", styles["Section"]))
    add_table([
        ["Field", "Value"],
        ["Related Cases", safe(correlation.get("related_case_count"))],
        ["Best Match Score", safe(correlation.get("best_match_score")) + "/100"],
        ["Findings", multiline(correlation.get("risk_findings") or [])],
    ])
    story.append(Paragraph(
        "Correlation is based on shared observable indicators and is not proof that the cases were created by the same actor.",
        styles["Small"],
    ))

    story.append(PageBreak())
    story.append(Paragraph("Executive Summary", styles["Section"]))
    story.append(Paragraph(safe(threat.get("summary")), styles["BodyText"]))

    limitations = analysis.get("threat_detection", {}).get("limitations") or []
    story.append(Paragraph("Forensic Limitations", styles["Section"]))
    for item in limitations:
        story.append(Paragraph("Ã¢â‚¬Â¢ " + safe(item), styles["Small"]))

    document.build(story)
    buffer.seek(0)

    from fastapi.responses import StreamingResponse
    filename = f"mailtrace-{case.get('case_id', case_id)}-forensic-report.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ============================================================
# THREAT INTELLIGENCE ENRICHMENT
# ============================================================
# This module is intentionally self-contained and uses only the
# Python standard library. External enrichments are optional:
# - ipwho.is: public IP geolocation / ASN data, no API key required
# - RDAP.org: domain/IP registration data bootstrap service
# - AbuseIPDB: optional IP reputation when ABUSEIPDB_API_KEY is set
# - VirusTotal: optional IP/domain/URL reputation when VT_API_KEY is set
#
# IMPORTANT:
# External intelligence is evidence enrichment, not proof of attacker
# identity or physical location. The email indicator is sent to the
# provider only when that provider is enabled by configuration.

import asyncio
import ipaddress
import json
import os
import socket
import time
import dns.resolver
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


THREAT_INTEL_CACHE = {}
THREAT_INTEL_CACHE_TTL_SECONDS = 15 * 60
THREAT_INTEL_MAX_IPS = 12
THREAT_INTEL_MAX_DOMAINS = 12
THREAT_INTEL_MAX_URLS = 10
THREAT_INTEL_HTTP_TIMEOUT = 5


def _cache_get(cache_key):
    item = THREAT_INTEL_CACHE.get(cache_key)
    if not item:
        return None

    created_at, value = item
    if time.time() - created_at > THREAT_INTEL_CACHE_TTL_SECONDS:
        THREAT_INTEL_CACHE.pop(cache_key, None)
        return None

    return value


def _cache_set(cache_key, value):
    THREAT_INTEL_CACHE[cache_key] = (time.time(), value)


def _http_json(url, headers=None, timeout=THREAT_INTEL_HTTP_TIMEOUT):
    request_headers = {
        "User-Agent": "MailTrace-AI/1.0",
        "Accept": "application/json",
    }

    if headers:
        request_headers.update(headers)

    request = Request(url, headers=request_headers, method="GET")

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return {
                "ok": True,
                "status_code": getattr(response, "status", 200),
                "data": json.loads(raw.decode("utf-8")),
            }
    except HTTPError as error:
        try:
            body = error.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body else None
        except Exception:
            parsed = None

        return {
            "ok": False,
            "status_code": error.code,
            "error": parsed or str(error),
        }
    except (URLError, TimeoutError, socket.timeout) as error:
        return {
            "ok": False,
            "status_code": None,
            "error": str(error),
        }
    except Exception as error:
        return {
            "ok": False,
            "status_code": None,
            "error": str(error),
        }


def _is_valid_ip(value):
    try:
        parsed = ipaddress.ip_address(value)
        return parsed.version in (4, 6)
    except ValueError:
        return False


def _is_public_ip(value):
    try:
        parsed = ipaddress.ip_address(value)
        return parsed.version in (4, 6) and parsed.is_global
    except ValueError:
        return False


def _ip_scope(value):
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"

    if parsed.is_loopback:
        return "loopback"
    if parsed.is_private:
        return "private"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_reserved:
        return "reserved"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_global:
        return "public"
    return "special"


def _reverse_dns(ip):
    try:
        host, aliases, _addresses = socket.gethostbyaddr(ip)
        return {
            "hostname": host,
            "aliases": aliases or [],
        }
    except Exception:
        return {
            "hostname": None,
            "aliases": [],
        }


def _ipwhois_lookup(ip):
    cache_key = f"ipwhois:{ip}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    result = _http_json(
        f"https://ipwho.is/{quote(ip, safe=':')}",
        timeout=THREAT_INTEL_HTTP_TIMEOUT,
    )

    if not result["ok"]:
        value = {
            "provider": "ipwho.is",
            "status": "error",
            "error": result.get("error"),
        }
        _cache_set(cache_key, value)
        return value

    data = result.get("data") or {}

    if data.get("success") is False:
        value = {
            "provider": "ipwho.is",
            "status": "error",
            "error": data.get("message", "Lookup failed"),
        }
        _cache_set(cache_key, value)
        return value

    connection = data.get("connection") or {}
    security = data.get("security") or {}

    value = {
        "provider": "ipwho.is",
        "status": "ok",
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "asn": connection.get("asn"),
        "organization": connection.get("org"),
        "isp": connection.get("isp"),
        "network_domain": connection.get("domain"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "security": {
            "anonymous": security.get("anonymous"),
            "proxy": security.get("proxy"),
            "vpn": security.get("vpn"),
            "tor": security.get("tor"),
            "hosting": security.get("hosting"),
            "relay": security.get("relay"),
        },
        "source_note": "Approximate IP-associated location and network data.",
    }

    _cache_set(cache_key, value)
    return value


def _rdap_lookup(resource_type, value):
    cache_key = f"rdap:{resource_type}:{value.lower()}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = f"https://rdap.org/{resource_type}/{quote(value, safe=':.') }"
    result = _http_json(endpoint, timeout=THREAT_INTEL_HTTP_TIMEOUT)

    if not result["ok"]:
        value_result = {
            "provider": "RDAP.org",
            "status": "error",
            "error": result.get("error"),
        }
        _cache_set(cache_key, value_result)
        return value_result

    data = result.get("data") or {}
    events = data.get("events") or []
    nameservers = data.get("nameservers") or []

    event_map = {}
    for event in events:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            event_map[action] = date

    value_result = {
        "provider": "RDAP.org",
        "status": "ok",
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName") or data.get("name"),
        "port43": data.get("port43"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "country": data.get("country"),
        "events": event_map,
        "nameservers": [
            ns.get("ldhName") or ns.get("unicodeName")
            for ns in nameservers
            if isinstance(ns, dict)
        ][:10],
        "status_codes": data.get("status", [])[:10]
        if isinstance(data.get("status"), list)
        else [],
    }

    _cache_set(cache_key, value_result)
    return value_result


def _dns_lookup(domain):
    """Resolve common DNS records with bounded dnspython timeouts."""
    result = {
        "domain": domain,
        "status": "unavailable",
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "cname": None,
        "source": "configured system DNS resolver",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    try:
        queries = (("A", "a_records"), ("AAAA", "aaaa_records"), ("MX", "mx_records"), ("NS", "ns_records"), ("CNAME", "cname"))
        errors = []
        for record_type, key in queries:
            try:
                answers = resolver.resolve(domain, record_type)
                if record_type == "MX":
                    result[key] = sorted([str(answer.exchange).rstrip(".") for answer in answers])
                elif record_type == "CNAME":
                    result[key] = str(answers[0].target).rstrip(".") if answers else None
                else:
                    result[key] = sorted({str(answer).rstrip(".") for answer in answers})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as error:
                errors.append(type(error).__name__)
        if any(result[key] for key in ("a_records", "aaaa_records", "mx_records", "ns_records", "cname")):
            result["status"] = "ok"
        if errors:
            result["partial_errors"] = sorted(set(errors))
    except Exception as error:
        result["error"] = str(error)
    result["note"] = "DNS records come from the configured resolver; unavailable records are not inferred."
    return result


def _classify_infrastructure(geo, abuse, vt):
    security = geo.get("security") if isinstance(geo, dict) else {}
    security = security if isinstance(security, dict) else {}
    findings = []

    def finding(kind, source, evidence, confidence):
        findings.append({"type": kind, "source": source, "evidence": evidence, "confidence": confidence})

    if security.get("tor") is True:
        finding("TOR_EXIT_NODE", "ipwho.is", "Provider security metadata marks this address as Tor-associated.", "MEDIUM")
    if security.get("vpn") is True:
        finding("VPN", "ipwho.is", "Provider security metadata marks this address as VPN-associated.", "MEDIUM")
    if security.get("proxy") is True:
        finding("PROXY", "ipwho.is", "Provider security metadata marks this address as proxy-associated.", "MEDIUM")
    if security.get("hosting") is True:
        finding("CLOUD_HOSTING", "ipwho.is", "Provider security metadata marks this address as hosting infrastructure.", "MEDIUM")
    if isinstance(abuse, dict) and (abuse.get("abuse_confidence_score") or 0) >= 80:
        finding("KNOWN_ABUSE", "AbuseIPDB", "Abuse confidence score is at least 80/100.", "MEDIUM")
    if isinstance(vt, dict) and (vt.get("stats") or {}).get("malicious", 0) > 0:
        finding("KNOWN_ABUSE", "VirusTotal", "At least one engine reported a malicious verdict.", "LOW")
    return {
        "type": findings[0]["type"] if findings else "UNKNOWN",
        "findings": findings,
        "note": "Infrastructure categories are indicators, not proof of maliciousness or actor identity.",
    }


def _virustotal_lookup(kind, value):
    api_key = os.getenv("VT_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": "VirusTotal",
            "status": "not_configured",
            "message": "Set VT_API_KEY in the backend environment to enable VirusTotal enrichment.",
        }

    encoded = value
    if kind == "url":
        import base64
        encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    elif kind == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{quote(value, safe='.-') }"
    elif kind == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(value, safe=':') }"
    else:
        return {
            "provider": "VirusTotal",
            "status": "unsupported",
        }

    cache_key = f"vt:{kind}:{value}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    result = _http_json(
        endpoint,
        headers={"x-apikey": api_key},
        timeout=THREAT_INTEL_HTTP_TIMEOUT,
    )

    if not result["ok"]:
        value_result = {
            "provider": "VirusTotal",
            "status": "error",
            "status_code": result.get("status_code"),
            "error": result.get("error"),
        }
        _cache_set(cache_key, value_result)
        return value_result

    data = result.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    harmless = stats.get("harmless", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = harmless + malicious + suspicious + undetected

    value_result = {
        "provider": "VirusTotal",
        "status": "ok",
        "id": data.get("id"),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_counted": total,
        },
        "whois": attributes.get("whois"),
        "categories": attributes.get("categories"),
    }

    _cache_set(cache_key, value_result)
    return value_result


def _abuseipdb_lookup(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": "AbuseIPDB",
            "status": "not_configured",
            "message": "Set ABUSEIPDB_API_KEY in the backend environment to enable AbuseIPDB enrichment.",
        }

    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = (
        "https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress={quote(ip, safe=':')}"
        "&maxAgeInDays=90"
    )

    result = _http_json(
        endpoint,
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
        timeout=THREAT_INTEL_HTTP_TIMEOUT,
    )

    if not result["ok"]:
        value_result = {
            "provider": "AbuseIPDB",
            "status": "error",
            "status_code": result.get("status_code"),
            "error": result.get("error"),
        }
        _cache_set(cache_key, value_result)
        return value_result

    data = (result.get("data") or {}).get("data") or {}

    value_result = {
        "provider": "AbuseIPDB",
        "status": "ok",
        "ip_address": data.get("ipAddress"),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "is_whitelisted": data.get("isWhitelisted"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames", [])[:10]
        if isinstance(data.get("hostnames"), list)
        else [],
    }

    _cache_set(cache_key, value_result)
    return value_result


def _extract_domains_from_urls(urls):
    domains = []

    for url in urls:
        try:
            hostname = urlsplit(url).hostname or ""
        except Exception:
            hostname = ""

        hostname = normalize_domain(hostname)
        if hostname:
            domains.append(hostname)

    return unique_list(domains)


def _extract_domains_from_email_fields(email_data):
    domains = []

    for field_name in ("from", "reply_to", "return_path"):
        value = email_data.get(field_name, "") if isinstance(email_data, dict) else ""
        domain = normalize_domain(extract_email_domain(value))
        if domain:
            domains.append(domain)

    return domains


def _build_ip_findings(scope, geo, abuse, vt):
    findings = []

    if scope in {"private", "loopback", "link-local", "reserved", "multicast", "unspecified", "special"}:
        findings.append({
            "severity": "info",
            "type": "non-public-ip",
            "detail": f"IP address is classified as {scope} and is not treated as public Internet infrastructure."
        })

    if isinstance(abuse, dict) and abuse.get("status") == "ok":
        score = abuse.get("abuse_confidence_score")
        if isinstance(score, (int, float)):
            if score >= 80:
                findings.append({
                    "severity": "high",
                    "type": "abuseipdb-high",
                    "detail": f"AbuseIPDB abuse confidence score is {score}/100."
                })
            elif score >= 40:
                findings.append({
                    "severity": "medium",
                    "type": "abuseipdb-medium",
                    "detail": f"AbuseIPDB abuse confidence score is {score}/100."
                })

    if isinstance(vt, dict) and vt.get("status") == "ok":
        malicious = (vt.get("stats") or {}).get("malicious", 0)
        suspicious = (vt.get("stats") or {}).get("suspicious", 0)
        if malicious:
            findings.append({
                "severity": "high",
                "type": "virustotal-malicious",
                "detail": f"VirusTotal reports {malicious} malicious engine verdict(s)."
            })
        elif suspicious:
            findings.append({
                "severity": "medium",
                "type": "virustotal-suspicious",
                "detail": f"VirusTotal reports {suspicious} suspicious engine verdict(s)."
            })

    if isinstance(geo, dict) and geo.get("status") == "ok" and geo.get("security"):
        security = geo.get("security") or {}
        if security.get("tor"):
            findings.append({
                "severity": "medium",
                "type": "tor-exit-indicator",
                "detail": "The IP intelligence provider marks the address as associated with Tor."
            })
        if security.get("vpn") or security.get("proxy"):
            findings.append({
                "severity": "medium",
                "type": "proxy-vpn-indicator",
                "detail": "The IP intelligence provider marks the address as associated with a VPN or proxy."
            })
        if security.get("hosting"):
            findings.append({
                "severity": "info",
                "type": "hosting-indicator",
                "detail": "The IP intelligence provider marks the address as hosting infrastructure."
            })

    return findings


def _provider_status():
    return {
        "ip_geolocation": {
            "provider": "ipwho.is",
            "enabled": True,
            "requires_key": False,
            "note": "Public IP geolocation/ASN enrichment."
        },
        "rdap": {
            "provider": "RDAP.org",
            "enabled": True,
            "requires_key": False,
            "note": "Registration and allocation data."
        },
        "abuseipdb": {
            "provider": "AbuseIPDB",
            "enabled": bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()),
            "requires_key": True,
        },
        "virustotal": {
            "provider": "VirusTotal",
            "enabled": bool(os.getenv("VT_API_KEY", "").strip()),
            "requires_key": True,
        },
    }


async def _enrich_ip(ip, observed_in_received=False):
    scope = _ip_scope(ip)

    if scope == "invalid":
        return {
            "indicator": ip,
            "type": "IP",
            "scope": scope,
            "status": "invalid",
            "findings": [],
        }

    # Public IPs are the only IPs sent to geolocation/reputation services.
    is_public = _is_public_ip(ip)

    if is_public:
        geo_task = asyncio.to_thread(_ipwhois_lookup, ip)
        abuse_task = asyncio.to_thread(_abuseipdb_lookup, ip)
        vt_task = asyncio.to_thread(_virustotal_lookup, "ip", ip)
        geo, abuse, vt = await asyncio.gather(geo_task, abuse_task, vt_task)
    else:
        geo = {
            "provider": "ipwho.is",
            "status": "skipped",
            "message": "Private/special-use IP was not sent to a public geolocation service."
        }
        abuse = {
            "provider": "AbuseIPDB",
            "status": "skipped",
            "message": "Private/special-use IP was not sent to an abuse reputation service."
        }
        vt = {
            "provider": "VirusTotal",
            "status": "skipped",
            "message": "Private/special-use IP was not sent to external reputation services."
        }

    reverse_dns = await asyncio.to_thread(_reverse_dns, ip) if is_public else {
        "hostname": None,
        "aliases": [],
    }

    findings = _build_ip_findings(scope, geo, abuse, vt)
    infrastructure = _classify_infrastructure(geo, abuse, vt)

    if observed_in_received:
        source = "Received header / SMTP relay"
        observation = "Observed in the email's SMTP Received path."
    else:
        source = "Email headers or content"
        observation = "Observed in parsed email headers/content; not necessarily the sender's endpoint."

    if is_public:
        location_basis = "Network infrastructure location"
    else:
        location_basis = "No public geolocation applied"

    if isinstance(geo, dict):
        geo = {
            **geo,
            "location_type": "network_infrastructure" if is_public else "not_applicable",
            "location_label": "Infrastructure Location",
        }

    return {
        "indicator": ip,
        "type": "IP",
        "scope": scope,
        "public": is_public,
        "source": source,
        "observation": observation,
        "location_basis": location_basis,
        "observed_in_received": observed_in_received,
        "reverse_dns": reverse_dns,
        "geolocation": geo,
        "abuseipdb": abuse,
        "virustotal": vt,
        "findings": findings,
        "infrastructure_classification": infrastructure,
        "forensic_note": "Infrastructure geolocation is an approximate network-associated location. It does not identify the sender's physical location or prove who controlled the IP address.",
    }


async def _enrich_domain(domain):
    rdap_task = asyncio.to_thread(_rdap_lookup, "domain", domain)
    vt_task = asyncio.to_thread(_virustotal_lookup, "domain", domain)
    dns_task = asyncio.to_thread(_dns_lookup, domain)
    rdap, vt, dns = await asyncio.gather(rdap_task, vt_task, dns_task)

    rdap_events = rdap.get("events", {}) if isinstance(rdap, dict) else {}
    created = rdap_events.get("registration") or rdap_events.get("last changed")
    expires = rdap_events.get("expiration")

    findings = []

    if isinstance(vt, dict) and vt.get("status") == "ok":
        malicious = (vt.get("stats") or {}).get("malicious", 0)
        suspicious = (vt.get("stats") or {}).get("suspicious", 0)
        if malicious:
            findings.append({
                "severity": "high",
                "type": "virustotal-malicious-domain",
                "detail": f"VirusTotal reports {malicious} malicious engine verdict(s) for this domain."
            })
        elif suspicious:
            findings.append({
                "severity": "medium",
                "type": "virustotal-suspicious-domain",
                "detail": f"VirusTotal reports {suspicious} suspicious engine verdict(s) for this domain."
            })

    return {
        "indicator": domain,
        "type": "DOMAIN",
        "rdap": rdap,
        "dns": dns,
        "domain_intelligence": {
            "domain": domain,
            "registrar": None,
            "created": created,
            "expires": expires,
            "age_days": None,
            "nameservers": rdap.get("nameservers", []) if isinstance(rdap, dict) else [],
            "a_records": dns.get("a_records", []),
            "aaaa_records": dns.get("aaaa_records", []),
            "mx_records": dns.get("mx_records", []),
            "ns_records": dns.get("ns_records", []),
            "cname": dns.get("cname"),
            "hosting_provider": None,
            "source": "RDAP.org + local system resolver",
            "status": "ok" if (rdap.get("status") == "ok" or dns.get("status") == "ok") else "unavailable",
        },
        "virustotal": vt,
        "findings": findings,
    }


async def _enrich_url(url, local_analysis=None):
    vt = await asyncio.to_thread(_virustotal_lookup, "url", url)
    findings = list(local_analysis.get("findings", [])) if isinstance(local_analysis, dict) else []

    if isinstance(vt, dict) and vt.get("status") == "ok":
        malicious = (vt.get("stats") or {}).get("malicious", 0)
        suspicious = (vt.get("stats") or {}).get("suspicious", 0)
        if malicious:
            findings.append({
                "type": "virustotal-malicious-url",
                "severity": "high",
                "detail": f"VirusTotal reports {malicious} malicious engine verdict(s) for this URL."
            })
        elif suspicious:
            findings.append({
                "type": "virustotal-suspicious-url",
                "severity": "medium",
                "detail": f"VirusTotal reports {suspicious} suspicious engine verdict(s) for this URL."
            })

    return {
        "indicator": url,
        "type": "URL",
        "local_analysis": local_analysis or {"url": url, "findings": []},
        "virustotal": vt,
        "findings": findings,
        "safety_note": "URL characteristics and reputation are indicators; they are not by themselves proof of maliciousness."
    }


@app.get("/api/threat-intelligence/status")
def threat_intelligence_status():
    return {
        "status": "online",
        "providers": _provider_status(),
        "limits": {
            "max_ips": THREAT_INTEL_MAX_IPS,
            "max_domains": THREAT_INTEL_MAX_DOMAINS,
            "max_urls": THREAT_INTEL_MAX_URLS,
            "cache_ttl_seconds": THREAT_INTEL_CACHE_TTL_SECONDS,
        }
    }


@app.post("/api/threat-intelligence")
async def threat_intelligence(payload: dict):
    """
    Enrich indicators already extracted by /api/analyze.

    Expected payload can be either the complete /api/analyze result or
    this smaller shape:

    {
      "evidence_id": "MT-...",
      "email": {...},
      "indicators": {"ips": [...], "urls": [...]},
      "url_analysis": [...]
    }

    The endpoint is designed to degrade gracefully when optional API
    keys are not configured or when external providers are unavailable.
    """

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="Threat intelligence payload must be a JSON object."
        )

    indicators = payload.get("indicators") or {}
    if not isinstance(indicators, dict):
        raise HTTPException(
            status_code=400,
            detail="The 'indicators' field must be an object."
        )

    raw_ips = indicators.get("ips") or []
    raw_urls = indicators.get("urls") or []
    email_data = payload.get("email") or {}
    url_analysis = payload.get("url_analysis") or []

    if not isinstance(raw_ips, list):
        raw_ips = []
    if not isinstance(raw_urls, list):
        raw_urls = []
    if not isinstance(email_data, dict):
        email_data = {}
    if not isinstance(url_analysis, list):
        url_analysis = []

    # Keep only valid IP literals. This removes malformed values such as
    # 09.16.02.13 before any external lookup is attempted.
    ips = unique_list(
        str(ip).strip()
        for ip in raw_ips
        if isinstance(ip, str)
        and ip.strip()
        and _is_valid_ip(str(ip).strip())
    )[:THREAT_INTEL_MAX_IPS]

    urls = unique_list(
        str(url).strip()
        for url in raw_urls
        if isinstance(url, str) and url.strip()
    )[:THREAT_INTEL_MAX_URLS]

    domains = unique_list(
        _extract_domains_from_email_fields(email_data)
        + _extract_domains_from_urls(urls)
    )[:THREAT_INTEL_MAX_DOMAINS]

    received_ip_set = set()
    raw_relay = payload.get("smtp_relay") or []
    if not isinstance(raw_relay, list):
        raw_relay = []

    for hop in raw_relay:
        if not isinstance(hop, dict):
            continue
        hop_ips = hop.get("ips") or []
        if isinstance(hop_ips, list):
            for hop_ip in hop_ips:
                if isinstance(hop_ip, str) and _is_valid_ip(hop_ip.strip()):
                    received_ip_set.add(hop_ip.strip())

    sending_infrastructure = analyze_smtp_sending_infrastructure(raw_relay)

    url_analysis_map = {}
    for item in url_analysis:
        if not isinstance(item, dict):
            continue
        url_value = item.get("url")
        if isinstance(url_value, str) and url_value:
            url_analysis_map[url_value] = item

    ip_results = await asyncio.gather(
        *[_enrich_ip(ip, ip in received_ip_set) for ip in ips]
    ) if ips else []

    domain_results = await asyncio.gather(
        *[_enrich_domain(domain) for domain in domains]
    ) if domains else []

    url_results = await asyncio.gather(
        *[
            _enrich_url(url, url_analysis_map.get(url))
            for url in urls
        ]
    ) if urls else []

    high_findings = 0
    medium_findings = 0
    info_findings = 0

    for collection in (ip_results, domain_results, url_results):
        for item in collection:
            for finding in item.get("findings", []):
                severity = str(finding.get("severity", "info")).lower()
                if severity == "high":
                    high_findings += 1
                elif severity == "medium":
                    medium_findings += 1
                else:
                    info_findings += 1

    evidence_id = payload.get("evidence_id")
    if not evidence_id:
        evidence = payload.get("evidence") or {}
        if isinstance(evidence, dict):
            evidence_id = evidence.get("evidence_id")

    return {
        "status": "success",
        "evidence_id": evidence_id,
        "requested_indicators": {
            "ips": ips,
            "domains": domains,
            "urls": urls,
        },
        "summary": {
            "ip_count": len(ip_results),
            "domain_count": len(domain_results),
            "url_count": len(url_results),
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "info_findings": info_findings,
            "external_provider_enrichment": bool(
                os.getenv("VT_API_KEY", "").strip()
                or os.getenv("ABUSEIPDB_API_KEY", "").strip()
            ),
        },
        "ip_intelligence": ip_results,
        "domain_intelligence": domain_results,
        "url_intelligence": url_results,
        "sending_infrastructure": sending_infrastructure,
        "smtp_relay_chain": raw_relay,
        "providers": _provider_status(),
        "limitations": [
            "IP geolocation represents an approximate network-associated location and must not be interpreted as the sender's physical location.",
            "When an IP appears in a Received header, it may identify a mail relay or hosting provider rather than the sender endpoint.",
            "Reputation provider verdicts are third-party intelligence signals and should be interpreted with their source context and timestamps.",
            "No external lookup result alone proves who sent the email or controls an infrastructure address.",
            "VirusTotal and AbuseIPDB enrichments are optional and require server-side API keys.",
            "External services may rate-limit or temporarily fail; MailTrace AI returns provider status instead of treating failure as a malicious verdict."
        ]
    }
