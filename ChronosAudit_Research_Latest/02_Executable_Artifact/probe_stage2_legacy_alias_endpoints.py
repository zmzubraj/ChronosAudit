#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import ssl
from urllib import request


ENDPOINTS = {
    "base": ("https://base.merkle.io", "0x2105"),
    "bsc": ("https://bsc.merkle.io", "0x38"),
    "ethereum": ("https://eth.merkle.io", "0x1"),
}


def canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def probe(chain: str, endpoint: str, expected_chain_id: str) -> dict[str, object]:
    host = endpoint.removeprefix("https://")
    addresses = sorted(
        {row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    )
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secure:
            certificate = secure.getpeercert()
            tls_version = secure.version()
            cipher = secure.cipher()
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        separators=(",", ":"),
    ).encode()
    rpc_request = request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(rpc_request, timeout=30) as response:
        response_body = response.read()
        status = response.status
        content_type = response.headers.get("Content-Type")
    rpc = json.loads(response_body)
    result = str(rpc.get("result", "")).lower()
    return {
        "chain": chain,
        "endpoint": endpoint,
        "registrable_domain": "merkle.io",
        "hostname": host,
        "dns_addresses": addresses,
        "tls_hostname_verified": True,
        "tls_version": tls_version,
        "tls_cipher": list(cipher) if cipher else None,
        "certificate_subject": certificate.get("subject"),
        "certificate_issuer": certificate.get("issuer"),
        "certificate_not_before": certificate.get("notBefore"),
        "certificate_not_after": certificate.get("notAfter"),
        "https_status": status,
        "https_content_type": content_type,
        "rpc_method": "eth_chainId",
        "rpc_result": result,
        "expected_chain_id": expected_chain_id,
        "chain_id_matches": result == expected_chain_id,
        "complete": bool(addresses) and status == 200 and result == expected_chain_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload: dict[str, object] = {
        "schema_version": "chronosaudit.legacy_alias_live_endpoint_probe.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "LOCAL_TEST_ONLY",
        "probes": [probe(chain, *ENDPOINTS[chain]) for chain in sorted(ENDPOINTS)],
        "provider_identity_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    payload["probe_sha256"] = canonical_sha(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
