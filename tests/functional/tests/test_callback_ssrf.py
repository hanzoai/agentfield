import asyncio
import os

import pytest

from utils import unique_node_id


@pytest.mark.functional
@pytest.mark.asyncio
async def test_node_registration_does_not_probe_callback(async_http_client):
    """
    Registration should not reach out to the provided callback URL (prevents SSRF).
    """
    hits = 0

    async def handle(reader, writer):
        nonlocal hits
        hits += 1
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nOK")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host="0.0.0.0", port=0)
    port = server.sockets[0].getsockname()[1]
    callback_host = os.environ.get("TEST_AGENT_CALLBACK_HOST", "test-runner")
    base_url = f"http://{callback_host}:{port}"
    node_id = unique_node_id("ssrf")

    try:
        resp = await async_http_client.post(
            "/api/v1/nodes",
            json={"id": node_id, "base_url": base_url},
            timeout=10.0,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["success"] is True
        assert body.get("resolved_base_url") == base_url

        # Allow a brief window for any unexpected probes to surface
        await asyncio.sleep(0.5)
        assert hits == 0, f"control plane probed callback URL during registration ({hits} requests)"
    finally:
        server.close()
        await server.wait_closed()
