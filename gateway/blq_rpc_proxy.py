#!/usr/bin/env python3
"""Small public JSON-RPC edge for BLQ.

The full node keeps its private RPC on Tailscale. This process exposes only
public methods and forwards requests to that private endpoint.
"""

import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

UPSTREAM = os.environ.get("BLQ_UPSTREAM", "http://192.0.2.39:8545")
UPSTREAMS = tuple(
    value.strip()
    for value in os.environ.get("BLQ_UPSTREAMS", UPSTREAM).split(",")
    if value.strip()
)
MINING_UPSTREAMS = tuple(
    value.strip()
    for value in os.environ.get("BLQ_MINING_UPSTREAMS", UPSTREAM).split(",")
    if value.strip()
)
TRANSACTION_UPSTREAMS = tuple(
    value.strip()
    for value in os.environ.get("BLQ_TRANSACTION_UPSTREAMS", ",".join(MINING_UPSTREAMS)).split(",")
    if value.strip()
)
TRANSACTION_RELAY_UPSTREAMS = tuple(
    value.strip()
    for value in os.environ.get("BLQ_TRANSACTION_RELAY_UPSTREAMS", "").split(",")
    if value.strip()
)
LISTEN = os.environ.get("BLQ_LISTEN", "127.0.0.1:18545")
MAX_BODY = 256 * 1024
MAX_INFLIGHT = int(os.environ.get("BLQ_MAX_INFLIGHT", "32"))
READ_MAX_INFLIGHT = int(os.environ.get("BLQ_READ_MAX_INFLIGHT", "24"))
TRANSACTION_MAX_INFLIGHT = int(os.environ.get("BLQ_TRANSACTION_MAX_INFLIGHT", "4"))
MINING_MAX_INFLIGHT = int(os.environ.get("BLQ_MINING_MAX_INFLIGHT", "2"))
TELEMETRY_MAX_INFLIGHT = int(os.environ.get("BLQ_TELEMETRY_MAX_INFLIGHT", "4"))
RATE = 10.0
BURST = 20.0
UPSTREAM_TIMEOUT_SECONDS = float(os.environ.get("BLQ_UPSTREAM_TIMEOUT_SECONDS", "4"))
MINING_UPSTREAM_TIMEOUT_SECONDS = float(os.environ.get("BLQ_MINING_UPSTREAM_TIMEOUT_SECONDS", "10"))
UPSTREAM_COOLDOWN_SECONDS = float(os.environ.get("BLQ_UPSTREAM_COOLDOWN_SECONDS", "15"))
UPSTREAM_IDENTITY_TTL_SECONDS = float(os.environ.get("BLQ_UPSTREAM_IDENTITY_TTL_SECONDS", "60"))
EXPECTED_CHAIN_ID = int(os.environ.get("BLQ_EXPECTED_CHAIN_ID", "707070"))
EXPECTED_GENESIS_HASH = os.environ.get("BLQ_EXPECTED_GENESIS_HASH", "").lower()
EXPECTED_CONSENSUS_PROFILE = os.environ.get("BLQ_EXPECTED_CONSENSUS_PROFILE", "")

PUBLIC_METHODS = {
    "eth_chainId",
    "net_version",
    "web3_clientVersion",
    "eth_blockNumber",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_syncing",
    "eth_mining",
    "eth_hashrate",
    "eth_coinbase",
    "eth_feeHistory",
    "eth_getBalance",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getBlockReceipts",
    "eth_getTransactionCount",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_sendRawTransaction",
    "eth_call",
    "eth_estimateGas",
    "eth_getLogs",
    "blq_chainInfo",
    "blq_health",
    "blq_nodeInfo",
    "blq_pendingTransactions",
    "blq_powSpec",
}
MINING_METHODS = {"blq_getBlockTemplate", "blq_submitBlock"}
TRANSACTION_METHODS = {"eth_sendRawTransaction"}
TELEMETRY_METHODS = {"blq_reportHashrate"}
# Mining is permissionless at the public edge.  The node still performs full
# PoW/block validation; this gateway only bounds request volume and size.
# Keep accepting the legacy header so private deployments can migrate without
# changing miner launch commands.
MINING_TOKEN = os.environ.get("BLQ_MINING_TOKEN", "")
PUBLIC_WEBSOCKET_ENDPOINT = os.environ.get("BLQ_PUBLIC_WEBSOCKET_ENDPOINT", "")

_lock = threading.Lock()
_buckets = {}
_inflight = threading.BoundedSemaphore(MAX_INFLIGHT)
_read_inflight = threading.BoundedSemaphore(READ_MAX_INFLIGHT)
_transaction_inflight = threading.BoundedSemaphore(TRANSACTION_MAX_INFLIGHT)
_mining_inflight = threading.BoundedSemaphore(MINING_MAX_INFLIGHT)
_telemetry_inflight = threading.BoundedSemaphore(TELEMETRY_MAX_INFLIGHT)
HTTP_SOCKET_TIMEOUT_SECONDS = float(os.environ.get("BLQ_HTTP_SOCKET_TIMEOUT_SECONDS", "15"))
RELAY_QUEUE_SIZE = int(os.environ.get("BLQ_RELAY_QUEUE_SIZE", "128"))
RELAY_WORKERS = int(os.environ.get("BLQ_RELAY_WORKERS", "2"))
_relay_queue = queue.Queue(maxsize=RELAY_QUEUE_SIZE)
_upstream_cooldowns = {}
_verified_upstreams = {}
_transaction_metrics = {
    "submissionsReceived": 0,
    "acceptedByMiningUpstream": 0,
    "alreadyKnown": 0,
    "rejected": 0,
    "relaySuccesses": 0,
    "relayFailures": 0,
    "upstreamTimeouts": 0,
}
MAX_RATE_BUCKETS = 10_000
PUBLIC_NODE_INFO_FIELDS = (
    "chainId",
    "genesisHash",
    "consensusProfile",
    "blockTimeV2ActivationHeight",
    "blockTimeTargetSeconds",
    "blockTimeV2TargetSeconds",
    "blockTimeV2Window",
    "blockTimeV2FastMedianSeconds",
    "blockTimeV2SlowIntervalSeconds",
    "nodeMode",
    "miningEnabled",
    "templateServing",
    "currentHeight",
    "networkHeight",
    "syncState",
    "status",
    "isSyncing",
    "isMining",
    "lastCanonicalBlockAt",
    "blockAgeSeconds",
    "liveness",
    "websocketEndpoint",
)


def error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def method_allowed(method, mining_token):
    if method in PUBLIC_METHODS or method in MINING_METHODS or method in TELEMETRY_METHODS:
        return True
    return False


def valid_envelope(item):
    return (
        isinstance(item, dict)
        and item.get("jsonrpc") == "2.0"
        and isinstance(item.get("method"), str)
    )


def allowed(client):
    now = time.monotonic()
    with _lock:
        if client not in _buckets and len(_buckets) >= MAX_RATE_BUCKETS:
            cutoff = now - 3600
            for key, (_, seen) in list(_buckets.items()):
                if seen < cutoff:
                    _buckets.pop(key, None)
            if len(_buckets) >= MAX_RATE_BUCKETS:
                return False
        tokens, last = _buckets.get(client, (BURST, now))
        tokens = min(BURST, tokens + (now - last) * RATE)
        if tokens < 1:
            _buckets[client] = (tokens, now)
            return False
        _buckets[client] = (tokens - 1, now)
        if len(_buckets) >= MAX_RATE_BUCKETS:
            cutoff = now - 3600
            for key, (_, seen) in list(_buckets.items()):
                if seen < cutoff:
                    _buckets.pop(key, None)
        return True


def eligible_upstreams(now=None, upstreams=None):
    """Return healthy upstreams first without permanently excluding any peer."""
    now = time.monotonic() if now is None else now
    with _lock:
        candidates = UPSTREAMS if upstreams is None else tuple(upstreams)
        healthy = [url for url in candidates if _upstream_cooldowns.get(url, 0) <= now]
        if healthy:
            return tuple(healthy)
        # Every provider is cooling down. Probe only the one that is due back
        # first so a complete outage does not fan out into a request storm.
        return (min(candidates, key=lambda url: _upstream_cooldowns.get(url, 0)),) if candidates else ()


def record_upstream_failure(upstream_url, now=None):
    now = time.monotonic() if now is None else now
    with _lock:
        _upstream_cooldowns[upstream_url] = now + UPSTREAM_COOLDOWN_SECONDS
        _verified_upstreams.pop(upstream_url, None)


def record_upstream_success(upstream_url):
    with _lock:
        _upstream_cooldowns.pop(upstream_url, None)


def transaction_metrics():
    with _lock:
        return dict(_transaction_metrics)


def record_transaction_metric(name, amount=1):
    with _lock:
        _transaction_metrics[name] = _transaction_metrics.get(name, 0) + amount


def identity_matches(result):
    """Require an upstream to prove that it serves this exact BLQ network."""
    if not isinstance(result, dict) or result.get("chainId") != EXPECTED_CHAIN_ID:
        return False
    if EXPECTED_GENESIS_HASH and str(result.get("genesisHash", "")).lower() != EXPECTED_GENESIS_HASH:
        return False
    if EXPECTED_CONSENSUS_PROFILE and result.get("consensusProfile") != EXPECTED_CONSENSUS_PROFILE:
        return False
    return True


def storage_available(result):
    """Reject only upstreams that cannot safely persist the next request."""
    if not isinstance(result, dict):
        return False
    storage = result.get("storage")
    if not isinstance(storage, dict):
        # Older compatible nodes do not publish storage telemetry. Keep them
        # eligible; transport and normal RPC failures still quarantine them.
        return True
    if storage.get("diskPressure") == "blocked":
        return False
    free = storage.get("filesystemFreeBytes")
    reserve = storage.get("filesystemReserveBytes")
    try:
        return free is None or reserve is None or int(free) >= int(reserve)
    except (TypeError, ValueError):
        return False


def response_is_storage_blocked(body):
    """Identify a node-local reserve failure without trusting free-form logs."""
    try:
        payload = json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError):
        return False
    items = payload if isinstance(payload, list) else [payload]
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("error"), dict):
            continue
        message = str(item["error"].get("message", "")).lower()
        if "storage blocked" in message or "filesystem reserve unavailable" in message:
            return True
    return False
def verified_upstream(upstream_url, now=None):
    """Return true only after a fresh or cached compatible node-info probe."""
    now = time.monotonic() if now is None else now
    with _lock:
        if _verified_upstreams.get(upstream_url, 0) > now:
            return True
    request_body = json.dumps(
        {"jsonrpc": "2.0", "id": "gateway-identity", "method": "blq_nodeInfo", "params": []},
        separators=(",", ":"),
    ).encode()
    probe = Request(
        upstream_url,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(probe, timeout=UPSTREAM_TIMEOUT_SECONDS) as response:
            raw_payload = response.read(MAX_BODY + 1)
        if len(raw_payload) > MAX_BODY:
            raise ValueError("public RPC upstream identity response is too large")
        payload = json.loads(raw_payload)
    except (OSError, TimeoutError, ValueError):
        record_upstream_failure(upstream_url, now)
        return False
    result = payload.get("result") if isinstance(payload, dict) else None
    if not identity_matches(result) or not storage_available(result):
        record_upstream_failure(upstream_url, now)
        return False
    with _lock:
        _verified_upstreams[upstream_url] = now + UPSTREAM_IDENTITY_TTL_SECONDS
    record_upstream_success(upstream_url)
    return True


def forward_json_rpc(request, mining=False, transaction=False, upstreams=None):
    """Forward one approved JSON-RPC payload through the configured failover set."""
    body = None
    last_error = None
    encoded = json.dumps(request, separators=(",", ":")).encode()
    candidates = upstreams or (MINING_UPSTREAMS if mining else TRANSACTION_UPSTREAMS if transaction else UPSTREAMS)
    timeout = MINING_UPSTREAM_TIMEOUT_SECONDS if mining else UPSTREAM_TIMEOUT_SECONDS
    for upstream_url in eligible_upstreams(upstreams=candidates):
        if not verified_upstream(upstream_url):
            last_error = OSError("upstream identity is incompatible")
            continue
        upstream = Request(
            upstream_url,
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(upstream, timeout=timeout) as response:
                body = response.read(MAX_BODY + 1)
            if response_is_storage_blocked(body):
                last_error = OSError("upstream storage reserve unavailable")
                record_upstream_failure(upstream_url)
                continue
            record_upstream_success(upstream_url)
            break
        except (OSError, TimeoutError) as upstream_error:
            last_error = upstream_error
            if transaction:
                record_transaction_metric("upstreamTimeouts")
            record_upstream_failure(upstream_url)
    if body is None:
        raise last_error or OSError("no public RPC upstreams configured")
    if len(body) > MAX_BODY:
        raise OSError("public RPC upstream response is too large")
    return body


def transaction_was_accepted(body):
    try:
        payload = json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError):
        return False
    items = payload if isinstance(payload, list) else [payload]
    accepted = False
    for item in items:
        if not isinstance(item, dict):
            continue
        result = item.get("result")
        message = str(item.get("error", {}).get("message", "")).lower()
        if isinstance(result, str) and result:
            accepted = True
        if "already known" in message or "known transaction" in message or "already in mempool" in message:
            record_transaction_metric("alreadyKnown")
            accepted = True
        elif item.get("error"):
            record_transaction_metric("rejected")
    return accepted


def relay_transaction(request):
    if not TRANSACTION_RELAY_UPSTREAMS:
        return
    try:
        body = forward_json_rpc(request, transaction=True, upstreams=TRANSACTION_RELAY_UPSTREAMS)
        if transaction_was_accepted(body):
            record_transaction_metric("relaySuccesses")
        else:
            record_transaction_metric("relayFailures")
    except (OSError, TimeoutError, ValueError):
        record_transaction_metric("relayFailures")


def relay_worker():
    while True:
        request = _relay_queue.get()
        try:
            relay_transaction(request)
        finally:
            _relay_queue.task_done()


def enqueue_relay(request):
    try:
        _relay_queue.put_nowait(request)
    except queue.Full:
        record_transaction_metric("relayFailures")


for _ in range(RELAY_WORKERS):
    threading.Thread(target=relay_worker, name="rpc-relay", daemon=True).start()


def public_status_payload(response):
    """Return only the public status results from the fixed status batch."""
    if not isinstance(response, list):
        raise ValueError("unexpected public status response")
    results = {item.get("id"): item.get("result") for item in response if isinstance(item, dict)}
    health = results.get("health")
    if not isinstance(health, dict):
        raise ValueError("missing public health result")
    return {
        "service": "BLQ public RPC",
        "status": "online",
        "rpc": "/rpc",
        "chain": results.get("chain"),
        "transactionMetrics": transaction_metrics(),
        "health": {
            key: health.get(key)
            for key in (
                "chainId",
                "genesisHash",
                "consensusProfile",
                "nodeMode",
                "currentHeight",
                "networkHeight",
                "verifiedNetworkHeight",
                "syncState",
                "status",
                "activity",
                "isSyncing",
                "isMining",
                "templateServing",
                "miningMode",
                "peerCount",
                "hashrate",
                "hashrateUnit",
                "activeMinerCount",
                "hashrateStatus",
                "lastCanonicalBlockAt",
                "blockAgeSeconds",
                "liveness",
            )
        },
    }


def public_node_info_payload(result):
    """Project node identity onto fields that are safe for public callers."""
    if not isinstance(result, dict):
        raise ValueError("unexpected public node-info result")
    payload = {key: result.get(key) for key in PUBLIC_NODE_INFO_FIELDS}
    # Never relay an upstream-advertised private address.  The public route is
    # configured explicitly by the operator and may be omitted for polling-only
    # deployments.
    payload["websocketEndpoint"] = PUBLIC_WEBSOCKET_ENDPOINT or None
    return payload


def sanitize_public_rpc_response(request, response):
    """Remove route, peer, and recovery internals from approved node-info calls."""
    requests = request if isinstance(request, list) else [request]
    node_info_ids = {
        item.get("id")
        for item in requests
        if isinstance(item, dict) and item.get("method") == "blq_nodeInfo"
    }
    responses = response if isinstance(response, list) else [response]
    sanitized = []
    for item in responses:
        if not isinstance(item, dict) or item.get("id") not in node_info_ids or "result" not in item:
            sanitized.append(item)
            continue
        copy = dict(item)
        copy["result"] = public_node_info_payload(item["result"])
        sanitized.append(copy)
    return sanitized if isinstance(response, list) else sanitized[0]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(HTTP_SOCKET_TIMEOUT_SECONDS)
        self.close_connection = True

    def send_json(self, value, status=200):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The client may abandon a timed-out request while the edge is
            # producing its bounded error response.  The connection is
            # already unusable; do not turn that normal race into a traceback.
            pass
        self.close_connection = True

    def do_POST(self):
        if not _inflight.acquire(blocking=False):
            self.send_json(error(None, -32005, "public RPC is busy"), 503)
            return
        mining_slot = False
        read_slot = False
        transaction_slot = False
        telemetry_slot = False
        try:
            client = self.headers.get("X-Real-IP", self.client_address[0])
            if not allowed(client):
                self.send_json(error(None, -32005, "public RPC rate limit exceeded"), 429)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self.send_json(error(None, -32600, "request body is missing or too large"), 413)
                return
            try:
                request = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(error(None, -32700, "parse error"), 400)
                return
            requests = request if isinstance(request, list) else [request]
            if not requests or len(requests) > 20:
                self.send_json(error(None, -32600, "invalid batch size"), 400)
                return
            for item in requests:
                if not valid_envelope(item):
                    response = error(item.get("id") if isinstance(item, dict) else None, -32600, "invalid request")
                    self.send_json(response)
                    return
                method = item.get("method") if isinstance(item, dict) else None
                if not method_allowed(method, self.headers.get("X-BLQ-Mining-Token", "")):
                    response = error(item.get("id") if isinstance(item, dict) else None, -32601, "method not available on public RPC")
                    self.send_json(response)
                    return
            if any(item.get("method") in MINING_METHODS for item in requests):
                if not _mining_inflight.acquire(blocking=False):
                    self.send_json(error(None, -32005, "public mining RPC is busy"), 503)
                    return
                mining_slot = True
            transaction_request = any(item.get("method") in TRANSACTION_METHODS for item in requests)
            telemetry_request = any(item.get("method") in TELEMETRY_METHODS for item in requests)
            if telemetry_request and len(requests) != 1:
                self.send_json(error(None, -32600, "hashrate telemetry must be sent alone"), 400)
                return
            if telemetry_request:
                if not _telemetry_inflight.acquire(blocking=False):
                    self.send_json(error(None, -32005, "public telemetry RPC is busy"), 503)
                    return
                telemetry_slot = True
            if not transaction_request and not telemetry_request and not any(item.get("method") in MINING_METHODS for item in requests):
                if not _read_inflight.acquire(blocking=False):
                    self.send_json(error(None, -32005, "public RPC read capacity is busy"), 503)
                    return
                read_slot = True
            if transaction_request:
                if not _transaction_inflight.acquire(blocking=False):
                    self.send_json(error(None, -32005, "public transaction RPC is busy"), 503)
                    return
                transaction_slot = True
            if transaction_request:
                record_transaction_metric("submissionsReceived")
            body = forward_json_rpc(
                request,
                mining=any(item.get("method") in MINING_METHODS for item in requests),
                transaction=transaction_request,
                upstreams=MINING_UPSTREAMS if telemetry_request else None,
            )
            if not body:
                self.send_response(204)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            value = sanitize_public_rpc_response(request, json.loads(body))
            self.send_json(value)
            if transaction_request and transaction_was_accepted(body):
                record_transaction_metric("acceptedByMiningUpstream")
                enqueue_relay(request)
        except Exception:
            self.send_json(error(None, -32000, "upstream RPC unavailable; retry shortly"), 503)
        finally:
            if mining_slot:
                _mining_inflight.release()
            if transaction_slot:
                _transaction_inflight.release()
            if telemetry_slot:
                _telemetry_inflight.release()
            if read_slot:
                _read_inflight.release()
            _inflight.release()

    def do_GET(self):
        if self.path not in ("/", "/healthz"):
            self.send_json(error(None, -32601, "JSON-RPC POST required"), 405)
            return
        if not _inflight.acquire(blocking=False):
            self.send_json({"service": "BLQ public RPC", "status": "busy"}, 503)
            return
        try:
            client = self.headers.get("X-Real-IP", self.client_address[0])
            if not allowed(client):
                self.send_json({"service": "BLQ public RPC", "status": "rate-limited"}, 429)
                return
            request = [
                {"jsonrpc": "2.0", "id": "chain", "method": "blq_chainInfo", "params": []},
                {"jsonrpc": "2.0", "id": "health", "method": "blq_health", "params": []},
            ]
            response = json.loads(forward_json_rpc(request))
            self.send_json(public_status_payload(response))
        except Exception:
            self.send_json({"service": "BLQ public RPC", "status": "upstream-unavailable"}, 503)
        finally:
            _inflight.release()

    def log_message(self, format, *args):
        return


def main():
    host, port = LISTEN.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
