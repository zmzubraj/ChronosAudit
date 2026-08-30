from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.historical_snapshot_run import (
    build_snapshot_run_plan,
    canonical_normalized_incident_row_sha256,
    freeze_incident_metadata_bytes,
    load_canonical_snapshot_population,
    match_incident_metadata,
)


ROOT = Path(__file__).resolve().parents[1]
QUEUE_PATH = (
    ROOT
    / "processed"
    / "public_acquisition"
    / "2026-08-08"
    / "public-acquisition-20260808T122104Z-2942b2819e08"
    / "case_queue.csv"
)
TEMPORAL_PATH = ROOT / "processed" / "stage2a_temporal_provenance.csv"
CANONICAL_QUEUE_PATH = ROOT / "processed" / "stage2b_onchain_query_queue.csv"
POLICY_PATH = ROOT / "config" / "public_acquisition_policy.yaml"
TEMPLATE_PATH = ROOT / "config" / "managed_archive_provider_templates.yaml"


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _portable(path: Path, *, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _copy_inputs(tmp_path: Path) -> tuple[Path, Path]:
    queue_copy = tmp_path / "case_queue.csv"
    temporal_copy = tmp_path / "stage2a_temporal_provenance.csv"
    shutil.copyfile(QUEUE_PATH, queue_copy)
    shutil.copyfile(TEMPORAL_PATH, temporal_copy)
    return queue_copy, temporal_copy


def test_load_canonical_snapshot_population_freezes_exact_417_cases() -> None:
    population = load_canonical_snapshot_population(QUEUE_PATH, TEMPORAL_PATH)

    assert len(population) == 417
    assert population["chain"].value_counts().sort_index().to_dict() == {
        "arbitrum": 1,
        "base": 9,
        "bsc": 226,
        "ethereum": 181,
    }
    assert population["case_id"].is_unique
    assert population["input_row_sha256"].is_unique
    assert population["input_row_sha256"].str.fullmatch(r"[0-9a-f]{64}").all()

    rerun = load_canonical_snapshot_population(QUEUE_PATH, TEMPORAL_PATH)
    pd.testing.assert_frame_equal(population, rerun, check_like=False)


def test_load_canonical_snapshot_population_accepts_stage2b_queue_schema() -> None:
    population = load_canonical_snapshot_population(CANONICAL_QUEUE_PATH, TEMPORAL_PATH)

    assert len(population) == 417
    assert population["case_id"].is_unique
    assert population["address"].str.fullmatch(r"0x[0-9a-f]{40}").all()
    assert population["incident_block"].map(lambda value: isinstance(value, int)).all()


def test_load_canonical_snapshot_population_rejects_conflicting_queue_aliases(tmp_path: Path) -> None:
    queue_copy, temporal_copy = _copy_inputs(tmp_path)
    queue = pd.read_csv(queue_copy)
    queue["target_contract_address"] = queue["address"]
    queue["fork_block_number"] = queue["incident_block"]
    queue.loc[0, "target_contract_address"] = "0x" + "ff" * 20
    queue.to_csv(queue_copy, index=False)

    with pytest.raises(ValueError, match="conflicting queue alias columns: address!=target_contract_address"):
        load_canonical_snapshot_population(queue_copy, temporal_copy)


def test_load_canonical_snapshot_population_rejects_truncated_population(tmp_path: Path) -> None:
    queue_copy, temporal_copy = _copy_inputs(tmp_path)
    pd.read_csv(queue_copy).iloc[:-1].to_csv(queue_copy, index=False)

    with pytest.raises(ValueError, match="expected 417 canonical cases"):
        load_canonical_snapshot_population(queue_copy, temporal_copy)


def test_load_canonical_snapshot_population_rejects_duplicate_case_ids(tmp_path: Path) -> None:
    queue_copy, temporal_copy = _copy_inputs(tmp_path)
    queue = pd.read_csv(queue_copy)
    queue.loc[1, "case_id"] = queue.loc[0, "case_id"]
    queue.to_csv(queue_copy, index=False)

    with pytest.raises(ValueError, match="duplicate case_id"):
        load_canonical_snapshot_population(queue_copy, temporal_copy)


def test_load_canonical_snapshot_population_rejects_queue_temporal_mismatch(tmp_path: Path) -> None:
    queue_copy, temporal_copy = _copy_inputs(tmp_path)
    temporal = pd.read_csv(temporal_copy)
    temporal.loc[0, "chain"] = "base"
    temporal.to_csv(temporal_copy, index=False)

    with pytest.raises(ValueError, match="queue/temporal mismatch"):
        load_canonical_snapshot_population(queue_copy, temporal_copy)


def test_build_snapshot_run_plan_keeps_full_target_when_selection_is_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unexpected_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("build_snapshot_run_plan must not perform network access")

    monkeypatch.setattr("urllib.request.urlopen", _unexpected_network)

    plan = build_snapshot_run_plan(
        QUEUE_PATH,
        TEMPORAL_PATH,
        policy_path=POLICY_PATH,
        provider_template_path=TEMPLATE_PATH,
        selected_cases=["bancor", "opyn", "uranium"],
        max_cases=2,
    )

    assert plan["population"]["target_case_count"] == 417
    assert plan["population"]["chain_case_counts"] == {
        "arbitrum": 1,
        "base": 9,
        "bsc": 226,
        "ethereum": 181,
    }
    assert plan["selected"]["requested_case_names"] == ["bancor", "opyn", "uranium"]
    assert plan["selected"]["selected_case_names"] == ["bancor", "opyn"]
    assert plan["selected"]["selected_case_count"] == 2
    assert plan["hashes"]["queue_sha256"] == _sha256_bytes(QUEUE_PATH.read_bytes())
    assert plan["hashes"]["temporal_sha256"] == _sha256_bytes(TEMPORAL_PATH.read_bytes())
    assert plan["hashes"]["policy_sha256"] == _sha256_bytes(POLICY_PATH.read_bytes())
    assert plan["hashes"]["provider_template_sha256"] == _sha256_bytes(TEMPLATE_PATH.read_bytes())


def test_build_snapshot_run_plan_hash_is_independent_of_host_paths(tmp_path: Path) -> None:
    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b" / "deeper"
    root_a.mkdir(parents=True)
    root_b.mkdir(parents=True)

    queue_a, temporal_a = _copy_inputs(root_a)
    queue_b, temporal_b = _copy_inputs(root_b)
    policy_a = root_a / "policy.yaml"
    policy_b = root_b / "policy.yaml"
    template_a = root_a / "templates.yaml"
    template_b = root_b / "templates.yaml"
    shutil.copyfile(POLICY_PATH, policy_a)
    shutil.copyfile(POLICY_PATH, policy_b)
    shutil.copyfile(TEMPLATE_PATH, template_a)
    shutil.copyfile(TEMPLATE_PATH, template_b)

    plan_a = build_snapshot_run_plan(
        queue_a,
        temporal_a,
        policy_path=policy_a,
        provider_template_path=template_a,
        selected_cases=["bancor", "opyn"],
        max_cases=1,
    )
    plan_b = build_snapshot_run_plan(
        queue_b,
        temporal_b,
        policy_path=policy_b,
        provider_template_path=template_b,
        selected_cases=["bancor", "opyn"],
        max_cases=1,
    )

    assert plan_a["plan_sha256"] == plan_b["plan_sha256"]
    assert plan_a["inputs"]["runtime_paths"] != plan_b["inputs"]["runtime_paths"]


def test_freeze_incident_metadata_bytes_writes_content_addressed_raw_and_manifest(tmp_path: Path) -> None:
    raw_bytes = (
        b"### 20260102 Example Protocol - Reentrancy\n"
        b"- reference https://etherscan.io/address/0x1111111111111111111111111111111111111111\n"
        b"- reference https://etherscan.io/tx/0x2222222222222222222222222222222222222222222222222222222222222222\n"
        b"### Lost: $1234\n"
        b"[Example](src/test/2026-01/Example_exp.sol)\n"
    )
    response_metadata = {
        "status": 200,
        "headers": {"content-type": "text/markdown; charset=utf-8"},
        "elapsed_seconds": 0.125,
        "authorization": "should-not-leak",
        "request_headers": {"Authorization": "Bearer top-secret", "X-Trace": "ok"},
        "request": {
            "api_key": "super-secret-key",
            "query": {"token": "nested-token", "page": 1},
        },
        "response": {
            "response_headers": {"Set-Cookie": "session=secret", "content-length": "123"},
            "notes": ["safe", {"password": "nope"}],
        },
    }
    retrieval_utc = "2026-08-08T12:34:56Z"

    result = freeze_incident_metadata_bytes(
        raw_bytes,
        source_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2026/README.md",
        response_metadata=response_metadata,
        output_root=tmp_path,
        retrieval_utc=retrieval_utc,
    )

    raw_sha = _sha256_bytes(raw_bytes)
    raw_path = tmp_path / result["raw_artifact_path"]
    sidecar_path = tmp_path / result["raw_metadata_path"]
    normalized_path = tmp_path / result["normalized_csv_path"]
    manifest_path = tmp_path / result["manifest_path"]

    assert raw_path.read_bytes() == raw_bytes
    assert raw_path.name == f"{raw_sha}.bin"
    assert raw_path.parent.name == raw_sha[:2]
    assert _portable(raw_path, root=tmp_path) == result["raw_artifact_path"]
    assert _portable(sidecar_path, root=tmp_path) == result["raw_metadata_path"]
    assert _portable(normalized_path, root=tmp_path) == result["normalized_csv_path"]
    assert _portable(manifest_path, root=tmp_path) == result["manifest_path"]

    normalized = pd.read_csv(normalized_path)
    assert len(normalized) == 1
    row = normalized.iloc[0]
    assert row["incident_name"] == "Example Protocol"
    assert row["incident_date"] == "2026-01-02"
    assert row["incident_chain"] == "ethereum"
    assert row["incident_type"] == "Reentrancy"
    assert row["incident_loss_text"] == "$1234"
    assert row["incident_contract_path"] == "src/test/2026-01/Example_exp.sol"
    assert row["incident_address"] == "0x1111111111111111111111111111111111111111"
    assert row["source_role"] == "incident_metadata_only"
    assert row["source_status"] == "frozen_public_source_hashed"
    assert row["raw_sha256"] == raw_sha
    assert isinstance(row["source_block_sha256"], str) and len(row["source_block_sha256"]) == 64
    expected_row_sha = canonical_normalized_incident_row_sha256(row)
    assert row["normalized_row_sha256"] == expected_row_sha

    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert sidecar["sha256"] == raw_sha
    assert sidecar["source_url"] == "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2026/README.md"
    assert sidecar["retrieval_utc"] == retrieval_utc
    serialized_sidecar = json.dumps(sidecar, sort_keys=True).lower()
    assert "authorization" not in serialized_sidecar
    assert "bearer top-secret" not in serialized_sidecar
    assert "super-secret-key" not in serialized_sidecar
    assert "nested-token" not in serialized_sidecar
    assert "session=secret" not in serialized_sidecar
    assert "nope" not in serialized_sidecar
    assert sidecar["response_metadata"]["status"] == 200
    assert sidecar["response_metadata"]["headers"]["content-type"] == "text/markdown; charset=utf-8"
    assert sidecar["response_metadata"]["request_headers"]["X-Trace"] == "ok"
    assert sidecar["response_metadata"]["request"]["query"]["page"] == 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["raw_sha256"] == raw_sha
    assert manifest["retrieval_utc"] == retrieval_utc
    assert manifest["normalized_row_count"] == 1
    assert manifest["normalized_row_sha256"] == [row["normalized_row_sha256"]]
    manifest_hash = manifest.pop("manifest_sha256")
    assert manifest_hash == hashlib.sha256(_canonical_json(manifest).encode("utf-8")).hexdigest()
    serialized_manifest = json.dumps(manifest, sort_keys=True).lower()
    assert "top-secret" not in serialized_manifest
    assert "super-secret-key" not in serialized_manifest

    tampered = row.copy()
    tampered["incident_type"] = "Price Oracle Manipulation"
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]
    tampered["incident_type"] = row["incident_type"]
    tampered["incident_tx_hashes"] = "[]"
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]
    tampered["incident_tx_hashes"] = row["incident_tx_hashes"]
    tampered["incident_reference_urls"] = "[]"
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]
    tampered["incident_reference_urls"] = row["incident_reference_urls"]
    tampered["raw_sha256"] = "0" * 64
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]
    tampered["raw_sha256"] = row["raw_sha256"]
    tampered["source_status"] = "tampered_status"
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]
    tampered["source_status"] = row["source_status"]
    tampered["source_block_sha256"] = "f" * 64
    assert canonical_normalized_incident_row_sha256(tampered) != row["normalized_row_sha256"]

    repeated = freeze_incident_metadata_bytes(
        raw_bytes,
        source_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2026/README.md",
        response_metadata=response_metadata,
        output_root=tmp_path,
        retrieval_utc=retrieval_utc,
    )
    assert repeated["raw_artifact_path"] == result["raw_artifact_path"]


@pytest.mark.parametrize(
    ("column", "value", "pattern"),
    [
        ("address", "0x1234", "invalid address"),
        ("address", "0xgg11111111111111111111111111111111111111", "invalid address"),
        ("incident_block", 123.5, "invalid incident block"),
        ("incident_block", -1, "invalid incident block"),
        ("incident_block", "NaN", "invalid incident block"),
    ],
)
def test_load_canonical_snapshot_population_rejects_invalid_address_and_block_shapes(
    tmp_path: Path,
    column: str,
    value: object,
    pattern: str,
) -> None:
    queue_copy, temporal_copy = _copy_inputs(tmp_path)
    queue = pd.read_csv(queue_copy)
    queue[column] = queue[column].astype(object)
    queue.loc[0, column] = value
    queue.to_csv(queue_copy, index=False)

    with pytest.raises(ValueError, match=pattern):
        load_canonical_snapshot_population(queue_copy, temporal_copy)


def test_match_incident_metadata_is_exact_only_and_fail_closed() -> None:
    canonical = pd.DataFrame(
        [
            {
                "case_id": "ca2-alpha",
                "case_name": "alpha",
                "chain": "ethereum",
                "address": "0x1111111111111111111111111111111111111111",
                "incident_block": 100,
            },
            {
                "case_id": "ca2-beta",
                "case_name": "beta",
                "chain": "bsc",
                "address": "0x2222222222222222222222222222222222222222",
                "incident_block": 200,
            },
            {
                "case_id": "ca2-gamma",
                "case_name": "gamma",
                "chain": "base",
                "address": "0x3333333333333333333333333333333333333333",
                "incident_block": 300,
            },
            {
                "case_id": "ca2-delta",
                "case_name": "delta",
                "chain": "arbitrum",
                "address": "0x4444444444444444444444444444444444444444",
                "incident_block": 400,
            },
        ]
    )
    normalized = pd.DataFrame(
        [
            {
                "incident_key": "alpha",
                "incident_name": "Alpha",
                "incident_chain": "ethereum",
                "incident_address": "0x1111111111111111111111111111111111111111",
                "normalized_row_sha256": "a" * 64,
            },
            {
                "incident_key": "beta",
                "incident_name": "Beta first",
                "incident_chain": "bsc",
                "incident_address": "0x2222222222222222222222222222222222222222",
                "normalized_row_sha256": "b" * 64,
            },
            {
                "incident_key": "beta",
                "incident_name": "Beta second",
                "incident_chain": "bsc",
                "incident_address": "0x2222222222222222222222222222222222222222",
                "normalized_row_sha256": "c" * 64,
            },
            {
                "incident_key": "delta",
                "incident_name": "Delta",
                "incident_chain": "ethereum",
                "incident_address": "0x9999999999999999999999999999999999999999",
                "normalized_row_sha256": "d" * 64,
            },
        ]
    )

    matched = match_incident_metadata(canonical, normalized)
    statuses = dict(zip(matched["case_name"], matched["incident_match_status"], strict=True))

    assert statuses == {
        "alpha": "exact_unique",
        "beta": "multiple",
        "gamma": "missing",
        "delta": "conflict",
    }
    assert matched.loc[matched["case_name"] == "alpha", "normalized_row_sha256"].item() == "a" * 64
    assert matched.loc[matched["case_name"] == "delta", "chain"].item() == "arbitrum"
    assert matched.loc[matched["case_name"] == "delta", "address"].item() == "0x4444444444444444444444444444444444444444"
    assert matched.loc[matched["case_name"] == "delta", "incident_chain"].item() == "ethereum"
    assert matched.loc[matched["case_name"] == "delta", "incident_address"].item() == "0x9999999999999999999999999999999999999999"
    assert "alp" not in matched["case_name"].tolist()
