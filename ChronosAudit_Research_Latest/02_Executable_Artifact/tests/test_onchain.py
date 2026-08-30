import hashlib
from pathlib import Path
import urllib.error

import pytest

from chronosaudit_stage2.onchain import (
    JsonRpcProvider,
    ProviderObservation,
    block_tag,
    is_eip1167_minimal_proxy,
    provider_consensus,
    storage_word_to_address,
    strip_solidity_metadata,
)


def test_raw_response_is_committed_without_in_place_final_path_write(monkeypatch, tmp_path):
    raw = b'{"jsonrpc":"2.0","id":1,"result":"0x"}'
    response_sha256 = hashlib.sha256(raw).hexdigest()
    final_name = f"{response_sha256}.json"
    original_write_bytes = Path.write_bytes

    def guarded_write_bytes(path, payload):
        if path.name == final_name:
            raise AssertionError("content-addressed final receipt must not be written in place")
        return original_write_bytes(path, payload)

    monkeypatch.setattr(Path, "write_bytes", guarded_write_bytes)
    provider = JsonRpcProvider(
        "provider-a",
        "https://rpc.example.invalid/v1/redacted",
        artifact_root=tmp_path,
    )

    observed_sha256, raw_path = provider._persist_raw_response(raw)

    assert observed_sha256 == response_sha256
    assert raw_path is not None
    assert Path(raw_path).read_bytes() == raw


@pytest.mark.parametrize("error_message", ["Internal error", "precondition failure"])
def test_json_rpc_provider_retries_receipt_bound_provider_error(monkeypatch, tmp_path, error_message):
    calls = {"count": 0}

    class Response:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return self.payload

    def urlopen(_request, timeout):
        assert timeout == 1
        calls["count"] += 1
        if calls["count"] == 1:
            payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": error_message}}
            import json

            return Response(json.dumps(payload).encode("utf-8"))
        return Response(b'{"jsonrpc":"2.0","id":1,"result":"0x6000"}')

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = JsonRpcProvider(
        "provider-a",
        "https://rpc.example.invalid/v1/redacted",
        timeout=1,
        max_retries=1,
        backoff_seconds=0,
        provider_family="family-one",
        artifact_root=tmp_path,
    )

    observation = provider.call("eth_getCode", ["0x" + "11" * 20, "0x10"])

    assert calls["count"] == 2
    assert observation.error is None
    assert observation.result == "0x6000"
    assert observation.attempt == 2
    assert observation.response_sha256 is not None
    assert observation.raw_response_path is not None


def test_json_rpc_provider_retries_http_request_timeout(monkeypatch, tmp_path):
    calls = {"count": 0}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"jsonrpc":"2.0","id":1,"result":"0x6000"}'

    def urlopen(request, timeout):
        assert timeout == 1
        calls["count"] += 1
        if calls["count"] == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                408,
                "Request Timeout",
                hdrs=None,
                fp=None,
            )
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = JsonRpcProvider(
        "provider-a",
        "https://rpc.example.invalid/v1/redacted",
        timeout=1,
        max_retries=1,
        backoff_seconds=0,
        provider_family="family-one",
        artifact_root=tmp_path,
    )

    observation = provider.call("eth_getCode", ["0x" + "11" * 20, "0x10"])

    assert calls["count"] == 2
    assert observation.error is None
    assert observation.result == "0x6000"
    assert observation.attempt == 2


class FakeProvider:
    def __init__(self, provider_id, result=None, error=None):
        self.provider_id = provider_id
        self.result = result
        self.error = error

    def call(self, method, params):
        return ProviderObservation(self.provider_id, method, params, self.result, 1, self.error)


def test_provider_consensus_requires_two():
    result = provider_consensus(
        [FakeProvider("a", "0x6000"), FakeProvider("b", "0x6000"), FakeProvider("c", "0x6001")],
        "eth_getCode",
        ["0x" + "11" * 20, "0x1"],
    )
    assert result["status"] == "consensus"
    assert result["value"] == "0x6000"
    assert result["agreement_count"] == 2


def test_storage_address_and_minimal_proxy():
    target = "1234567890abcdef1234567890abcdef12345678"
    word = "0x" + "00" * 12 + target
    assert storage_word_to_address(word) == "0x" + target
    code = "0x363d3d373d3d3d363d73" + target + "5af43d82803e903d91602b57fd5bf3"
    assert is_eip1167_minimal_proxy(code) == "0x" + target


def test_metadata_stripping_is_conservative():
    # Tiny CBOR map a0 plus length trailer 0001.
    normalized, status = strip_solidity_metadata("0x6000a00001")
    assert normalized == "0x6000"
    assert status == "metadata_stripped"
    unchanged, status2 = strip_solidity_metadata("0x6000")
    assert unchanged == "0x6000"
    assert status2 != "metadata_stripped"


def test_block_tag():
    assert block_tag(16) == "0x10"


def test_eip1898_block_selector_and_historical_snapshot():
    from chronosaudit_stage2.onchain import canonical_block_selector, historical_identity_snapshot, EIP1967_IMPLEMENTATION_SLOT, EIP1967_BEACON_SLOT, EIP1967_ADMIN_SLOT

    block_hash = '0x' + 'ab' * 32
    address = '0x' + '11' * 20
    impl = '0x' + '22' * 20
    zero = '0x' + '00' * 32
    impl_word = '0x' + '00' * 12 + impl[2:]

    class RoutingProvider:
        def __init__(self, provider_id): self.provider_id = provider_id
        def call(self, method, params):
            if method == 'eth_getBlockByNumber': result = {'hash': block_hash, 'number': '0x10'}
            elif method == 'eth_getCode': result = '0x6000'
            elif method == 'eth_getStorageAt' and params[1] == EIP1967_IMPLEMENTATION_SLOT: result = impl_word
            elif method == 'eth_getStorageAt' and params[1] in {EIP1967_BEACON_SLOT, EIP1967_ADMIN_SLOT}: result = zero
            else: result = None
            return ProviderObservation(self.provider_id, method, params, result, 1)

    selector = canonical_block_selector(block_hash)
    assert selector == {'blockHash': block_hash, 'requireCanonical': True}
    result = historical_identity_snapshot(address, 16, [RoutingProvider('a'), RoutingProvider('b')])
    assert result['status'] == 'complete'
    assert result['eip1898_pinned'] is True
    assert result['canonical_block_hash'] == block_hash
    assert result['implementation']['value'] == impl
    assert result['runtime_bytecode_sha256'] is not None
