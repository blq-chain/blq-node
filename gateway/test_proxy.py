import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("BLQ_MINING_TOKEN", "test-mining-token")

import blq_rpc_proxy as proxy

from blq_rpc_proxy import (
    UPSTREAMS,
    _upstream_cooldowns,
    _verified_upstreams,
    eligible_upstreams,
    identity_matches,
    method_allowed,
    public_status_payload,
    record_upstream_failure,
    record_upstream_success,
    sanitize_public_rpc_response,
    storage_available,
    response_is_storage_blocked,
    valid_envelope,
    verified_upstream,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit):
        return self.payload


class PublicRpcPolicyTests(unittest.TestCase):
    def test_read_only_method_is_public(self):
        self.assertTrue(method_allowed("eth_blockNumber", ""))

    def test_node_identity_method_is_public(self):
        self.assertTrue(method_allowed("blq_nodeInfo", ""))

    def test_bounded_pending_transactions_view_is_public(self):
        self.assertTrue(method_allowed("blq_pendingTransactions", ""))

    def test_hashrate_telemetry_is_public(self):
        self.assertTrue(method_allowed("blq_reportHashrate", ""))

    def test_node_info_hides_peer_routes_and_recovery_details(self):
        response = sanitize_public_rpc_response(
            {"jsonrpc": "2.0", "id": 9, "method": "blq_nodeInfo", "params": []},
            {
                "jsonrpc": "2.0",
                "id": 9,
                "result": {
                    "chainId": 707070,
                    "genesisHash": "test-genesis",
                    "consensusProfile": "BLQ-RX/2",
                    "blockTimeV2ActivationHeight": 14100,
                    "blockTimeTargetSeconds": 15,
                    "currentHeight": 12,
                    "rpcEndpoint": "http://192.0.2.39:8545",
                    "p2pEndpoint": "192.0.2.39:30334",
                    "stalePeerTargets": [{"peer": "internal"}],
                    "recoveryProvider": "internal-provider",
                },
            },
        )
        self.assertEqual(response["result"]["chainId"], 707070)
        self.assertEqual(response["result"]["blockTimeV2ActivationHeight"], 14100)
        self.assertEqual(response["result"]["blockTimeTargetSeconds"], 15)
        self.assertNotIn("rpcEndpoint", response["result"])
        self.assertNotIn("p2pEndpoint", response["result"])
        self.assertNotIn("stalePeerTargets", response["result"])
        self.assertNotIn("recoveryProvider", response["result"])

    def test_admin_method_is_private(self):
        self.assertFalse(method_allowed("blq_sendTransaction", "test-mining-token"))

    def test_mining_methods_are_public(self):
        self.assertTrue(method_allowed("blq_getBlockTemplate", ""))
        self.assertTrue(method_allowed("blq_submitBlock", ""))
        self.assertTrue(method_allowed("blq_submitBlock", "legacy-token"))

    def test_template_and_submission_capacity_are_bounded_separately(self):
        template = proxy._template_inflight.acquire(blocking=False)
        submit = proxy._submit_inflight.acquire(blocking=False)
        self.assertTrue(template)
        self.assertTrue(submit)
        try:
            self.assertGreaterEqual(proxy.TEMPLATE_MAX_INFLIGHT, 1)
            self.assertGreaterEqual(proxy.SUBMIT_MAX_INFLIGHT, 1)
        finally:
            if template:
                proxy._template_inflight.release()
            if submit:
                proxy._submit_inflight.release()

    def test_hashrate_telemetry_capacity_is_bounded_separately(self):
        first = proxy._telemetry_inflight.acquire(blocking=False)
        self.assertTrue(first)
        try:
            self.assertGreaterEqual(proxy.TELEMETRY_MAX_INFLIGHT, 1)
        finally:
            if first:
                proxy._telemetry_inflight.release()

    def test_json_rpc_envelope_requires_version_and_method(self):
        self.assertTrue(valid_envelope({"jsonrpc": "2.0", "method": "eth_chainId"}))
        self.assertFalse(valid_envelope({"jsonrpc": "1.0", "method": "eth_chainId"}))
        self.assertFalse(valid_envelope({"jsonrpc": "2.0", "method": 7}))

    def test_default_upstream_is_available(self):
        self.assertTrue(UPSTREAMS)

    def test_failed_upstream_is_temporarily_skipped_then_rejoins(self):
        original = proxy.UPSTREAMS
        try:
            proxy.UPSTREAMS = ("http://first", "http://second")
            _upstream_cooldowns.clear()
            first, second = proxy.UPSTREAMS
            record_upstream_failure(first, now=100)
            self.assertEqual(eligible_upstreams(now=101), (second,))
            record_upstream_success(first)
            self.assertIn(first, eligible_upstreams(now=101))
        finally:
            proxy.UPSTREAMS = original
            _upstream_cooldowns.clear()

    def test_identity_rejects_wrong_genesis_and_profile(self):
        original_genesis = proxy.EXPECTED_GENESIS_HASH
        original_profile = proxy.EXPECTED_CONSENSUS_PROFILE
        try:
            proxy.EXPECTED_GENESIS_HASH = "expected-genesis"
            proxy.EXPECTED_CONSENSUS_PROFILE = "expected-profile"
            self.assertTrue(identity_matches({"chainId": 707070, "genesisHash": "expected-genesis", "consensusProfile": "expected-profile"}))
            self.assertFalse(identity_matches({"chainId": 707070, "genesisHash": "wrong-genesis", "consensusProfile": "expected-profile"}))
            self.assertFalse(identity_matches({"chainId": 707070, "genesisHash": "expected-genesis", "consensusProfile": "wrong-profile"}))
        finally:
            proxy.EXPECTED_GENESIS_HASH = original_genesis
            proxy.EXPECTED_CONSENSUS_PROFILE = original_profile

    def test_verified_upstream_quarantines_incompatible_identity(self):
        original_genesis = proxy.EXPECTED_GENESIS_HASH
        try:
            proxy.EXPECTED_GENESIS_HASH = "expected-genesis"
            _upstream_cooldowns.clear()
            _verified_upstreams.clear()
            response = FakeResponse(json.dumps({
                "jsonrpc": "2.0",
                "id": "gateway-identity",
                "result": {"chainId": 707070, "genesisHash": "wrong-genesis"},
            }).encode())
            with patch("blq_rpc_proxy.urlopen", return_value=response):
                self.assertFalse(verified_upstream("http://wrong", now=10))
            self.assertGreater(_upstream_cooldowns["http://wrong"], 10)
        finally:
            proxy.EXPECTED_GENESIS_HASH = original_genesis
            _upstream_cooldowns.clear()
            _verified_upstreams.clear()

    def test_storage_guard_excludes_blocked_upstream(self):
        self.assertFalse(storage_available({
            "storage": {
                "diskPressure": "blocked",
                "filesystemFreeBytes": 400,
                "filesystemReserveBytes": 500,
            }
        }))
        self.assertFalse(storage_available({
            "storage": {
                "diskPressure": "normal",
                "filesystemFreeBytes": 400,
                "filesystemReserveBytes": 500,
            }
        }))
        self.assertTrue(storage_available({
            "storage": {
                "diskPressure": "normal",
                "filesystemFreeBytes": 600,
                "filesystemReserveBytes": 500,
            }
        }))

    def test_storage_blocked_rpc_error_is_failover_signal(self):
        blocked = json.dumps({"error": {"code": -32000, "message": "filesystem reserve unavailable: node is storage-blocked"}}).encode()
        healthy = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "ok"}).encode()
        self.assertTrue(response_is_storage_blocked(blocked))
        self.assertFalse(response_is_storage_blocked(healthy))

    def test_verified_upstream_caches_a_compatible_identity_probe(self):
        original_genesis = proxy.EXPECTED_GENESIS_HASH
        original_profile = proxy.EXPECTED_CONSENSUS_PROFILE
        try:
            proxy.EXPECTED_GENESIS_HASH = "expected-genesis"
            proxy.EXPECTED_CONSENSUS_PROFILE = "expected-profile"
            _upstream_cooldowns.clear()
            _verified_upstreams.clear()
            response = FakeResponse(json.dumps({
                "jsonrpc": "2.0",
                "id": "gateway-identity",
                "result": {
                    "chainId": 707070,
                    "genesisHash": "expected-genesis",
                    "consensusProfile": "expected-profile",
                },
            }).encode())
            with patch("blq_rpc_proxy.urlopen", return_value=response) as mocked_urlopen:
                self.assertTrue(verified_upstream("http://compatible", now=10))
                self.assertTrue(verified_upstream("http://compatible", now=11))
            self.assertEqual(mocked_urlopen.call_count, 1)
        finally:
            proxy.EXPECTED_GENESIS_HASH = original_genesis
            proxy.EXPECTED_CONSENSUS_PROFILE = original_profile
            _upstream_cooldowns.clear()
            _verified_upstreams.clear()

    def test_public_status_contains_only_status_results(self):
        payload = public_status_payload([
            {"jsonrpc": "2.0", "id": "chain", "result": {"chainId": 707070}},
            {
                "jsonrpc": "2.0",
                "id": "health",
                "result": {
                    "status": "synced",
                    "liveness": "healthy",
                    "blockAgeSeconds": 12,
                    "templateServing": True,
                },
            },
        ])
        self.assertEqual(payload["service"], "BLQ public RPC")
        self.assertEqual(payload["chain"]["chainId"], 707070)
        self.assertEqual(payload["health"]["status"], "synced")
        self.assertEqual(payload["health"]["liveness"], "healthy")
        self.assertEqual(payload["health"]["blockAgeSeconds"], 12)
        self.assertTrue(payload["health"]["templateServing"])

    def test_public_status_omits_internal_endpoints_and_peer_details(self):
        payload = public_status_payload([
            {"jsonrpc": "2.0", "id": "chain", "result": {}},
            {
                "jsonrpc": "2.0",
                "id": "health",
                "result": {
                    "status": "synced",
                    "rpcEndpoint": "http://192.0.2.39:8545",
                    "activePeer": "internal-peer",
                },
            },
        ])
        self.assertEqual(payload["health"]["status"], "synced")
        self.assertNotIn("rpcEndpoint", payload["health"])
        self.assertNotIn("activePeer", payload["health"])


if __name__ == "__main__":
    unittest.main()
