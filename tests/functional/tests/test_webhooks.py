from __future__ import annotations

import hmac
import json
import time
from hashlib import sha256

import pytest


def _compute_signature(secret: str, timestamp: str, body: dict) -> str:
    payload = f"{timestamp}.{json.dumps(body, separators=(',', ':'))}"
    digest = hmac.new(secret.encode(), payload.encode(), sha256).hexdigest()
    return f"sha256={digest}"


@pytest.mark.functional
@pytest.mark.asyncio
async def test_webhook_trigger_flow(async_http_client):
    create_resp = await async_http_client.post(
        "/api/v1/webhook-triggers",
        json={
            "name": "functional-webhook",
            "target": "test.reasoner",
            "mode": "remap",
            "field_mappings": {"id": "/id"},
            "event_id_pointer": "/id",
            "async_execution": True,
        },
        timeout=10.0,
    )
    assert create_resp.status_code == 200, create_resp.text
    payload = create_resp.json()
    trigger_id = payload["trigger_id"]
    secret = payload["secret"]

    body = {"id": "evt-functional", "message": "hello"}
    timestamp = str(int(time.time()))
    signature = _compute_signature(secret, timestamp, body)

    resp = await async_http_client.post(
        f"/api/v1/webhooks/{trigger_id}",
        json=body,
        headers={
            "X-AF-Timestamp": timestamp,
            "X-AF-Signature": signature,
        },
        timeout=10.0,
    )
    assert resp.status_code in (200, 202), resp.text

    # Duplicate delivery should be detected.
    dup_resp = await async_http_client.post(
        f"/api/v1/webhooks/{trigger_id}",
        json=body,
        headers={
            "X-AF-Timestamp": timestamp,
            "X-AF-Signature": signature,
        },
        timeout=10.0,
    )
    assert dup_resp.status_code in (200, 202)
    dup_body = dup_resp.json()
    assert dup_body["status"] in ("duplicate", "accepted")

    # Delivery listing should include at least one record.
    deliveries_resp = await async_http_client.get(
        f"/api/v1/webhook-triggers/{trigger_id}/deliveries",
        timeout=10.0,
    )
    assert deliveries_resp.status_code == 200, deliveries_resp.text
    deliveries = deliveries_resp.json().get("deliveries", [])
    assert len(deliveries) >= 1
