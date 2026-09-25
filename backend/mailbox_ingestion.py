"""Near-real-time mailbox ingestion with deduplication and backoff."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from mailbox_connectors import NormalizedEmailMessage, provider_for


ProcessCallback = Callable[[NormalizedEmailMessage], Awaitable[dict[str, Any]]]


class IngestionManager:
    def __init__(self, process_callback: ProcessCallback):
        self.process_callback = process_callback
        self.state = "PAUSED"
        self.provider_name = os.getenv("MAILBOX_PROVIDER", "imap")
        self.provider = provider_for(self.provider_name)
        self.cursor: str | None = None
        self.last_error = ""
        self.last_sync_at: str | None = None
        self.interval = max(10, int(os.getenv("MAILBOX_POLL_INTERVAL_SECONDS", "30")))
        self._task: asyncio.Task[Any] | None = None
        self._stop = asyncio.Event()
        self._sync_lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._seen: deque[str] = deque(maxlen=5000)

    def configure_provider(self,provider_name: str,*,access_token: str|None=None,config: dict[str,Any]|None=None):
        self.provider_name=provider_name
        self.provider=provider_for(provider_name,access_token,config=config)
        self.cursor=None
        self.last_error=""
        self.state="CONNECTED" if self.provider.status().get("configured") else "CONFIGURED"
        return self.public_status()

    def public_status(self) -> dict[str, Any]:
        return {"state": self.state, "provider": self.provider_name, "provider_status": self.provider.status(), "cursor": self.cursor, "last_sync_at": self.last_sync_at, "last_error": self.last_error, "poll_interval_seconds": self.interval}

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        if os.getenv("MAILBOX_INGESTION_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
            self.state = "PAUSED"
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="mailtrace-mailbox-ingestion")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
        self.state = "PAUSED"

    async def _run(self) -> None:
        delay = 1
        while not self._stop.is_set():
            try:
                await self.sync_now()
                delay = 1
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                continue
            except Exception as error:  # provider failures must not stop the worker
                self.state = "ERROR"
                self.last_error = str(error)[:500]
                await self._publish({"type": "MAILBOX_SYNC_ERROR", "error": self.last_error})
                await asyncio.wait_for(self._stop.wait(), timeout=min(300, delay)) if not self._stop.is_set() else None
                delay = min(300, delay * 2)

    async def sync_now(self) -> dict[str, Any]:
        """Fetch and analyze one mailbox batch immediately."""
        async with self._sync_lock:
            self.state = "SYNCING"
            try:
                messages, cursor = await asyncio.to_thread(self.provider.fetch_since, self.cursor)
                processed = 0
                for message in messages:
                    result = await self.ingest(message)
                    if result.get("status") != "duplicate":
                        processed += 1
                self.cursor = cursor
                self.last_sync_at = datetime.now(timezone.utc).isoformat()
                self.state = "CONNECTED"
                self.last_error = ""
                return {"fetched": len(messages), "processed": processed, "cursor": self.cursor, "synced_at": self.last_sync_at}
            except Exception as error:
                self.state = "ERROR"
                self.last_error = str(error)[:500]
                await self._publish({"type": "MAILBOX_SYNC_ERROR", "error": self.last_error})
                raise

    async def ingest(self, message: NormalizedEmailMessage) -> dict[str, Any]:
        dedupe_key = f"{message.provider}:{message.provider_message_id}:{hashlib.sha256(message.raw_bytes).hexdigest()}"
        if dedupe_key in self._seen:
            return {"status": "duplicate", "provider_message_id": message.provider_message_id}
        self._seen.append(dedupe_key)
        await self._publish({"type": "EMAIL_RECEIVED", "message": message.to_public_dict()})
        result = await self.process_callback(message)
        await self._publish({"type": "EMAIL_ANALYSIS_COMPLETED", "result": result, "message": message.to_public_dict()})
        return result

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    async def _publish(self, event: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass

