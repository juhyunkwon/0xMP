"""Push notification dispatch (spec: offline delivery).

The protocol server never sends message plaintext to push providers:
payloads contain only identifiers (type, conversation_id, message_id),
which is mandatory for E2E conversations and good hygiene for all.

Providers:
  * RecordingPushProvider - tests/diagnostics; keeps every event in memory.
  * WebhookPushProvider   - POSTs the JSON event to a configured URL; a
    deployment can bridge this to FCM/APNs. Direct FCM/APNs providers can
    implement the same `send` interface without touching the server core.
"""
from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass, field


@dataclass
class PushEvent:
    push_token: str
    conversation_id: str  # hex
    message_id: str       # hex
    kind: str = "message"


@dataclass
class RecordingPushProvider:
    name: str = "recording"
    events: list[PushEvent] = field(default_factory=list)

    async def send(self, event: PushEvent) -> None:
        self.events.append(event)


@dataclass
class WebhookPushProvider:
    url: str
    name: str = "webhook"

    async def send(self, event: PushEvent) -> None:
        body = json.dumps({
            "token": event.push_token, "type": event.kind,
            "conversation_id": event.conversation_id,
            "message_id": event.message_id,
        }).encode()
        request = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"})
        await asyncio.to_thread(urllib.request.urlopen, request, timeout=5)
