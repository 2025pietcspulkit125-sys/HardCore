"""Mailbox provider adapters used by the local-first ingestion worker.

The adapters intentionally return one normalized message shape. OAuth secrets and
access tokens are read from the server environment only and are never returned
by the API or written to the forensic database.
"""

from __future__ import annotations

import base64
import email
import imaplib
import json
import os
import secrets
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class NormalizedEmailMessage:
    provider: str
    provider_message_id: str
    raw_bytes: bytes
    received_at: str
    thread_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("raw_bytes", None)
        data["size"] = len(self.raw_bytes)
        return data


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


def _redirect_uri(provider: str) -> str:
    configured = _first_env("MAILBOX_REDIRECT_URI")
    if not configured:
        configured = _first_env("GOOGLE_REDIRECT_URI" if provider == "gmail" else "MICROSOFT_REDIRECT_URI")
    if not configured:
        configured = "http://127.0.0.1:8000/api/mailbox/oauth/{provider}/callback"
    return configured.replace("{provider}", provider)


def _json_request(url: str, *, method: str = "GET", token: str = "", body: dict[str, Any] | None = None, timeout: float = 12) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _form_request(url: str, values: dict[str, str], timeout: float = 12) -> dict[str, Any]:
    request = urllib.request.Request(url, data=urllib.parse.urlencode(values).encode("utf-8"), headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class MailboxProvider:
    name = "base"

    def status(self) -> dict[str, Any]:
        return {"provider": self.name, "configured": False, "connected": False, "capabilities": []}

    def fetch_since(self, cursor: str | None = None) -> tuple[list[NormalizedEmailMessage], str | None]:
        raise NotImplementedError

    def quarantine(self, provider_message_id: str) -> dict[str, Any]:
        return {"status": "unsupported", "provider": self.name, "provider_message_id": provider_message_id}


class GmailProvider(MailboxProvider):
    name = "gmail"

    def __init__(self, access_token: str | None = None):
        self.access_token = access_token or os.getenv("GMAIL_ACCESS_TOKEN", "")

    def status(self) -> dict[str, Any]:
        client_id = _first_env("GMAIL_CLIENT_ID", "GOOGLE_CLIENT_ID")
        client_secret = _first_env("GMAIL_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET")
        missing = [name for name, value in (("GMAIL_CLIENT_ID", client_id), ("GMAIL_CLIENT_SECRET", client_secret)) if not value]
        return {"provider": self.name, "configured": not missing, "connected": bool(self.access_token), "missing_config": missing, "capabilities": ["oauth", "poll", "quarantine-label"]}

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": _first_env("GMAIL_CLIENT_ID", "GOOGLE_CLIENT_ID"),
            "redirect_uri": _redirect_uri(self.name),
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/gmail.modify",
            "access_type": "offline",
            "state": state,
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)

    def exchange_oauth_code(self, code: str) -> dict[str, Any]:
        return _form_request("https://oauth2.googleapis.com/token", {"code": code, "client_id": _first_env("GMAIL_CLIENT_ID", "GOOGLE_CLIENT_ID"), "client_secret": _first_env("GMAIL_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET"), "redirect_uri": _redirect_uri(self.name), "grant_type": "authorization_code"})

    def fetch_since(self, cursor: str | None = None) -> tuple[list[NormalizedEmailMessage], str | None]:
        if not self.access_token:
            return [], cursor
        query = urllib.parse.urlencode({"labelIds": "INBOX", "q": "newer_than:2d", "maxResults": "25"})
        listing = _json_request(f"https://gmail.googleapis.com/gmail/v1/users/me/messages?{query}", token=self.access_token)
        messages: list[NormalizedEmailMessage] = []
        for item in listing.get("messages", []):
            message_id = str(item.get("id", ""))
            if not message_id or message_id == cursor:
                continue
            raw = _json_request(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=self.access_token)
            encoded = str(raw.get("raw", ""))
            try:
                payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            except (ValueError, base64.binascii.Error):
                continue
            messages.append(NormalizedEmailMessage(self.name, message_id, payload, _now(), str(raw.get("threadId", "")), {"label_ids": raw.get("labelIds", [])}))
        return messages, (messages[0].provider_message_id if messages else cursor)

    def quarantine(self, provider_message_id: str) -> dict[str, Any]:
        if not self.access_token:
            return {"status": "not_configured", "provider": self.name, "provider_message_id": provider_message_id}
        payload = _json_request(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{urllib.parse.quote(provider_message_id)}/modify",
            method="POST", token=self.access_token, body={"removeLabelIds": ["INBOX"], "addLabelIds": ["SPAM"]},
        )
        return {"status": "quarantined", "provider": self.name, "provider_message_id": provider_message_id, "provider_response": {"id": payload.get("id"), "labelIds": payload.get("labelIds", [])}}


class MicrosoftGraphProvider(MailboxProvider):
    name = "microsoft_graph"

    def __init__(self, access_token: str | None = None):
        self.access_token = access_token or os.getenv("MICROSOFT_ACCESS_TOKEN", "")

    def status(self) -> dict[str, Any]:
        missing = [name for name in ("MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET") if not os.getenv(name, "").strip()]
        return {"provider": self.name, "configured": not missing, "connected": bool(self.access_token), "missing_config": missing, "capabilities": ["oauth", "poll", "move"]}

    def authorization_url(self, state: str) -> str:
        params = {
            "client_id": os.getenv("MICROSOFT_CLIENT_ID", ""),
            "response_type": "code",
            "redirect_uri": _redirect_uri(self.name),
            "response_mode": "query",
            "scope": "offline_access Mail.ReadWrite",
            "state": state,
        }
        tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params)

    def exchange_oauth_code(self, code: str) -> dict[str, Any]:
        tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
        return _form_request(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", {"code": code, "client_id": os.getenv("MICROSOFT_CLIENT_ID", ""), "client_secret": os.getenv("MICROSOFT_CLIENT_SECRET", ""), "redirect_uri": _redirect_uri(self.name), "grant_type": "authorization_code", "scope": "offline_access Mail.ReadWrite"})

    def fetch_since(self, cursor: str | None = None) -> tuple[list[NormalizedEmailMessage], str | None]:
        if not self.access_token:
            return [], cursor
        data = _json_request("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=25&$select=id,internetMessageId,parentFolderId,receivedDateTime", token=self.access_token)
        messages: list[NormalizedEmailMessage] = []
        for item in data.get("value", []):
            message_id = str(item.get("id", ""))
            if not message_id or message_id == cursor:
                continue
            raw = urllib.request.Request(f"https://graph.microsoft.com/v1.0/me/messages/{urllib.parse.quote(message_id)}/$value", headers={"Authorization": f"Bearer {self.access_token}"})
            try:
                with urllib.request.urlopen(raw, timeout=12) as response:
                    payload = response.read()
            except OSError:
                continue
            messages.append(NormalizedEmailMessage(self.name, message_id, payload, str(item.get("receivedDateTime") or _now()), metadata={"internet_message_id": item.get("internetMessageId", "")}))
        return messages, (messages[0].provider_message_id if messages else cursor)

    def quarantine(self, provider_message_id: str) -> dict[str, Any]:
        if not self.access_token:
            return {"status": "not_configured", "provider": self.name, "provider_message_id": provider_message_id}
        payload = _json_request(f"https://graph.microsoft.com/v1.0/me/messages/{urllib.parse.quote(provider_message_id)}/move", method="POST", token=self.access_token, body={"destinationId": os.getenv("MICROSOFT_QUARANTINE_FOLDER_ID", "junkemail")})
        return {"status": "quarantined", "provider": self.name, "provider_message_id": provider_message_id, "provider_response": {"id": payload.get("id"), "parentFolderId": payload.get("parentFolderId")}}


class GenericIMAPProvider(MailboxProvider):
    name="imap"
    def __init__(self, config: dict[str, Any] | None = None):
        config=config or {}
        self.host=str(config.get("host") or os.getenv("IMAP_HOST","")).strip()
        self.port=int(config.get("port") or os.getenv("IMAP_PORT","993"))
        self.username=str(config.get("username") or os.getenv("IMAP_USERNAME","")).strip()
        self.password=str(config.get("password") or os.getenv("IMAP_PASSWORD",""))
        self.tls=bool(config.get("tls",os.getenv("IMAP_TLS","true").lower() not in {"0","false","no"}))
        self.folder=str(config.get("folder") or os.getenv("IMAP_FOLDER","INBOX"))
        self.quarantine_folder=str(config.get("quarantine_folder") or os.getenv("IMAP_QUARANTINE_FOLDER","Quarantine"))
    def status(self):
        configured=bool(self.host and self.username and self.password)
        return {"provider":self.name,"configured":configured,"connected":configured,"capabilities":["imap-idle","poll","quarantine-folder"],"host":self.host,"port":self.port,"tls":self.tls,"username":self.username}
    def _client(self):
        return imaplib.IMAP4_SSL(self.host,self.port) if self.tls else imaplib.IMAP4(self.host,self.port)
    def test_connection(self):
        if not self.status()["configured"]: raise ValueError("IMAP host, username, and password are required.")
        c=self._client()
        try:
            typ,_=c.login(self.username,self.password)
            if typ!="OK": raise ValueError("IMAP login failed.")
            typ,boxes=c.list()
            return {"status":"connected","imap_login":typ=="OK","mailboxes_visible":len(boxes or [])}
        finally:
            try: c.logout()
            except Exception: pass
    def fetch_since(self,cursor=None):
        if not self.status()["configured"]: return [],cursor
        c=self._client()
        try:
            c.login(self.username,self.password); c.select(self.folder,readonly=True)
            status,data=c.uid("search",None,"ALL")
            if status!="OK": return [],cursor
            messages=[]
            for uid in (data[0] or b"").split()[-25:]:
                pid=uid.decode("ascii",errors="ignore")
                if pid==cursor: continue
                status,fetched=c.uid("fetch",uid,"(RFC822)")
                if status!="OK": continue
                payload=next((part[1] for part in fetched if isinstance(part,tuple) and isinstance(part[1],bytes)),b"")
                if payload: messages.append(NormalizedEmailMessage(self.name,pid,payload,_now(),metadata={"folder":self.folder}))
            return messages,(messages[-1].provider_message_id if messages else cursor)
        finally:
            try: c.logout()
            except Exception: pass
    def quarantine(self,provider_message_id):
        if not self.status()["configured"]: return {"status":"not_configured","provider":self.name,"provider_message_id":provider_message_id}
        c=self._client()
        try:
            c.login(self.username,self.password); c.select(self.folder)
            status,_=c.uid("COPY",provider_message_id.encode(),self.quarantine_folder)
            return {"status":"quarantined_copy" if status=="OK" else "error","provider":self.name,"provider_message_id":provider_message_id,"provider_response":{"imap_status":status,"original_preserved":True}}
        finally:
            try: c.logout()
            except Exception: pass

def provider_for(name: str | None, access_token: str | None = None, config: dict[str, Any] | None = None) -> MailboxProvider:
    normalized=(name or os.getenv("MAILBOX_PROVIDER","imap")).lower()
    if normalized in {"gmail","google"}: return GmailProvider(access_token)
    if normalized in {"microsoft","microsoft_graph","outlook","graph"}: return MicrosoftGraphProvider(access_token)
    return GenericIMAPProvider(config)

def oauth_state() -> str:
    return secrets.token_urlsafe(24)
