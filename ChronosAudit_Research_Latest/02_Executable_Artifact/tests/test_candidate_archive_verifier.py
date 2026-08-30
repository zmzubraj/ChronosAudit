from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/chronosaudit_stage2/public_acquisition/candidate_archive_verifier.py"
CLI_PATH = ROOT / "verify_candidate_archive_qualification.py"
AUTHORITATIVE_RUN_ROOT = (
    ROOT
    / "raw/candidate_archive_qualification/2026-08-10/defihacklabs-temporal-replacements-v4-authoritative"
)
SEALED_REVISION_ROOT = ROOT / "raw/cohort_revisions/2026-08-10/defihacklabs-temporal-replacements-v1"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _verifier_module():
    return _load_module("candidate_archive_verifier_module", MODULE_PATH)


def _cli_module():
    return _load_module("candidate_archive_verifier_cli_module", CLI_PATH)


def _qualification_module():
    return _load_module(
        "candidate_archive_qualification_module_for_verifier_tests",
        ROOT / "src/chronosaudit_stage2/public_acquisition/candidate_archive_qualification.py",
    )


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    run_root = tmp_path / "run"
    revision_root = tmp_path / "revision"
    output_dir = tmp_path / "output"
    shutil.copytree(AUTHORITATIVE_RUN_ROOT, run_root)
    shutil.copytree(SEALED_REVISION_ROOT, revision_root)
    _rebase_copied_run_paths(run_root)
    return run_root, revision_root, output_dir


def _replace_path_prefix(value: Any, *, old: str, new: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_path_prefix(item, old=old, new=new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_path_prefix(item, old=old, new=new) for item in value]
    if isinstance(value, str) and value.startswith(old):
        return new + value[len(old) :]
    return value


def _rebase_copied_run_paths(run_root: Path) -> None:
    """Keep mutation tests isolated from the sealed authoritative run."""
    qualification = _qualification_module()
    historical_run = _load_module(
        "historical_snapshot_run_for_candidate_verifier_fixture",
        ROOT / "src/chronosaudit_stage2/public_acquisition/historical_snapshot_run.py",
    )
    strict_snapshot = _load_module(
        "strict_snapshot_for_candidate_verifier_fixture",
        ROOT / "src/chronosaudit_stage2/public_acquisition/strict_snapshot.py",
    )
    old = str(AUTHORITATIVE_RUN_ROOT.resolve())
    new = str(run_root.resolve())
    result = _read_json(run_root / "qualification_result.json")
    result["run_root"] = new
    rewritten_cases: dict[str, dict[str, Any]] = {}
    for item in result["cases"]:
        candidate_id = str(item["candidate_id"])
        historical_path = _historical_case_path(run_root, candidate_id)
        historical: dict[str, Any] | None = None
        if historical_path.is_file():
            historical = _replace_path_prefix(_read_json(historical_path), old=old, new=new)
            strict = dict(historical.get("strict_snapshot") or {})
            if strict.get("artifact_sha256"):
                strict = strict_snapshot._attach_self_hashes(strict)
                historical["strict_snapshot"] = strict
                historical["strict_snapshot_sha256"] = strict.get("artifact_sha256")
            historical = historical_run._seal_snapshot_case_envelope(historical)
            _write_json(historical_path, historical)
        case_payload = _replace_path_prefix(_read_json(_case_path(run_root, candidate_id)), old=old, new=new)
        receipt_summary = dict(case_payload.get("receipt_summary") or {})
        if receipt_summary:
            normalized = []
            for observation in receipt_summary["observations"]:
                receipt = _read_json(Path(observation["receipt_raw_response_path"]))["result"]
                header = _read_json(Path(observation["header_raw_response_path"]))["result"]
                normalized.append(
                    (
                        int(receipt["blockNumber"], 16),
                        receipt["blockHash"].lower(),
                        int(receipt["status"], 16),
                        int(header["number"], 16),
                        header["hash"].lower(),
                    )
                )
            receipt_summary["proof_sha256"] = qualification._sha256_json(
                {"normalized": normalized, "observations": receipt_summary["observations"]}
            )
            case_payload["receipt_summary"] = receipt_summary
        if historical is not None:
            runtime_result = dict(historical)
            runtime_result.update(
                {"resumed": False, "quarantined": False, "quarantine_reason": None}
            )
            case_payload["historical_case_sha256"] = qualification._sha256_json(runtime_result)
        sealed = qualification._seal_case_envelope(case_payload)
        _write_json(_case_path(run_root, candidate_id), sealed)
        rewritten_cases[candidate_id] = sealed
    result["cases"] = [rewritten_cases[str(item["candidate_id"])] for item in result["cases"]]
    _write_json(run_root / "qualification_result.json", result)


def _qualification_result(run_root: Path) -> dict[str, Any]:
    return _read_json(run_root / "qualification_result.json")


def _write_manifest(run_root: Path, payload: dict[str, Any]) -> None:
    qualification = _qualification_module()
    body = dict(payload)
    body["binding_sha256"] = qualification._sha256_json(
        {key: value for key, value in body.items() if key != "binding_sha256"}
    )
    _write_json(run_root / "run_manifest.json", body)


def _case_path(run_root: Path, candidate_id: str) -> Path:
    return run_root / "cases" / f"{candidate_id}.json"


def _historical_case_path(run_root: Path, candidate_id: str) -> Path:
    return run_root / "historical_cases" / candidate_id / f"{candidate_id}.json"


def _rewrite_case(run_root: Path, candidate_id: str, mutate) -> None:
    qualification = _qualification_module()
    case_path = _case_path(run_root, candidate_id)
    case_payload = _read_json(case_path)
    mutate(case_payload)
    sealed = qualification._seal_case_envelope(case_payload)
    _write_json(case_path, sealed)

    result = _qualification_result(run_root)
    for index, item in enumerate(result["cases"]):
        if item["candidate_id"] == candidate_id:
            result["cases"][index] = sealed
            break
    else:
        raise AssertionError(f"candidate_id not found: {candidate_id}")
    _write_json(run_root / "qualification_result.json", result)


def _rewrite_historical_case(run_root: Path, candidate_id: str, mutate) -> None:
    qualification = _qualification_module()
    historical_run = _load_module(
        "historical_snapshot_run_for_candidate_verifier_mutation",
        ROOT / "src/chronosaudit_stage2/public_acquisition/historical_snapshot_run.py",
    )
    historical_path = _historical_case_path(run_root, candidate_id)
    historical = _read_json(historical_path)
    mutate(historical)
    sealed_historical = historical_run._seal_snapshot_case_envelope(historical)
    _write_json(historical_path, sealed_historical)

    runtime_result = dict(sealed_historical)
    runtime_result.update({"resumed": False, "quarantined": False, "quarantine_reason": None})

    def rewrite_case(case_payload: dict[str, Any]) -> None:
        case_payload["historical_case_sha256"] = qualification._sha256_json(runtime_result)

    _rewrite_case(run_root, candidate_id, rewrite_case)


def _rewrite_raw_response(
    run_root: Path,
    candidate_id: str,
    *,
    observation_key: str,
    mutate_result,
) -> None:
    case_payload = _read_json(_case_path(run_root, candidate_id))
    observation = dict(case_payload["receipt_summary"]["observations"][0])
    response_path = Path(observation[observation_key])
    response_payload = _read_json(response_path)
    mutate_result(response_payload["result"])
    response_bytes = json.dumps(
        response_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    new_sha = _sha256_bytes(response_bytes)
    new_path = response_path.parent.parent / new_sha[:2] / f"{new_sha}.json"
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_bytes(response_bytes)

    def rewrite_case(case_payload: dict[str, Any]) -> None:
        updated_observation = case_payload["receipt_summary"]["observations"][0]
        if "receipt" in observation_key:
            updated_observation["receipt_response_sha256"] = new_sha
            updated_observation["receipt_raw_response_path"] = str(new_path)
        else:
            updated_observation["header_response_sha256"] = new_sha
            updated_observation["header_raw_response_path"] = str(new_path)

    _rewrite_case(run_root, candidate_id, rewrite_case)


def _first_partial_with_receipts(run_root: Path) -> str:
    result = _qualification_result(run_root)
    for item in result["cases"]:
        historical_case = _historical_case_path(run_root, item["candidate_id"])
        if not item["qualified"] and item.get("receipt_summary") and historical_case.is_file():
            return str(item["candidate_id"])
    raise AssertionError("no partial candidate with receipt summary found")


def _first_qualified(run_root: Path) -> str:
    result = _qualification_result(run_root)
    for item in result["cases"]:
        if item["qualified"]:
            return str(item["candidate_id"])
    raise AssertionError("no qualified candidate found")


def _row(report: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    for row in report["rows"]:
        if row["candidate_id"] == candidate_id:
            return row
    raise AssertionError(f"candidate row not found: {candidate_id}")


def _scientific_blockers(report: dict[str, Any], candidate_id: str) -> list[str]:
    return list(_row(report, candidate_id)["scientific_blockers"])


def _integration_verify(module, run_root: Path, revision_root: Path, output_dir: Path) -> dict[str, Any]:
    return module.verify_candidate_archive_run(
        run_root=run_root,
        revision_root=revision_root,
        output_dir=output_dir,
    )


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("authorization_basis", False),
        ("credential_kind", False),
        ("cookie_policy", False),
        ("auth_token_sha256", False),
        ("api_key", True),
        ("access_token", True),
        ("client_secret", True),
        ("client_secret_id", True),
        ("private_key", True),
        ("authorization_header", True),
        ("authorization_header_url", True),
        ("api_key_policy", True),
        ("session_cookie_kind", True),
        ("credentials", True),
    ],
)
def test_key_looks_secret_like_classifies_safe_metadata_and_secret_containers(
    key: str,
    expected: bool,
) -> None:
    module = _verifier_module()

    assert module._key_looks_secret_like(key) is expected


def test_verify_candidate_archive_run_authoritative_counts_and_outputs(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)

    report = _integration_verify(module, run_root, revision_root, output_dir)
    projection_rows = _read_csv_rows(output_dir / "candidate_archive_verified_projection.csv")
    checksum_lines = (output_dir / "SHA256SUMS.txt").read_text(encoding="utf-8").strip().splitlines()

    assert report["candidate_count"] == 145
    assert report["eligible_count"] == 116
    assert report["eligible_chain_counts"] == {"base": 11, "bsc": 49, "ethereum": 56}
    assert report["counter_authority"] is True
    assert report["integrity_errors"] == []
    assert len(report["rows"]) == 145
    assert len(projection_rows) == 145
    assert len(checksum_lines) == 3
    assert (output_dir / "candidate_archive_verification_report.json").is_file()
    assert (output_dir / "candidate_archive_verified_projection.csv").is_file()


def test_verify_candidate_archive_run_tampered_manifest_hash_closes_counter_authority(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    manifest_path = run_root / "run_manifest.json"
    manifest = _read_json(manifest_path)
    manifest["binding_sha256"] = "0" * 64
    _write_json(manifest_path, manifest)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "run_manifest_binding_hash_mismatch" in report["integrity_errors"]


def test_verify_candidate_archive_run_receipt_path_escape_is_integrity_error(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_partial_with_receipts(run_root)

    def mutate(case_payload: dict[str, Any]) -> None:
        case_payload["receipt_summary"]["observations"][0]["receipt_raw_response_path"] = str(
            run_root.parent / "escape.json"
        )

    _rewrite_case(run_root, candidate_id, mutate)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "receipt_path_escape" in report["integrity_errors"]


def test_verify_candidate_archive_run_receipt_symlink_is_integrity_error(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_partial_with_receipts(run_root)
    case_payload = _read_json(_case_path(run_root, candidate_id))
    receipt_path = Path(case_payload["receipt_summary"]["observations"][0]["receipt_raw_response_path"])
    original = receipt_path.read_bytes()
    receipt_path.unlink()
    receipt_path.symlink_to(run_root / "qualification_result.json")
    assert receipt_path.is_symlink()

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert original
    assert report["counter_authority"] is False
    assert "receipt_path_invalid" in report["integrity_errors"]


def test_verify_candidate_archive_run_raw_response_hash_mismatch_is_integrity_error(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_partial_with_receipts(run_root)
    case_payload = _read_json(_case_path(run_root, candidate_id))
    receipt_path = Path(case_payload["receipt_summary"]["observations"][0]["receipt_raw_response_path"])
    receipt_path.write_text('{"result":{"tampered":true}}\n', encoding="utf-8")

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "receipt_hash_mismatch" in report["integrity_errors"]


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("provider_family", "same_family"),
        ("public_endpoint_id", "same_endpoint_identity"),
    ],
)
def test_verify_candidate_archive_run_receipt_identity_failures_are_row_blockers(
    tmp_path: Path,
    field: str,
    code: str,
) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_partial_with_receipts(run_root)

    def mutate(case_payload: dict[str, Any]) -> None:
        observations = case_payload["receipt_summary"]["observations"]
        observations[1][field] = observations[0][field]

    _rewrite_case(run_root, candidate_id, mutate)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is True
    assert report["integrity_errors"] == []
    assert code in _scientific_blockers(report, candidate_id)


def test_verify_candidate_archive_run_receipt_disagreement_is_row_blocker(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_partial_with_receipts(run_root)
    case_payload = _read_json(_case_path(run_root, candidate_id))
    header_path = Path(case_payload["receipt_summary"]["observations"][0]["header_raw_response_path"])
    header_payload = _read_json(header_path)
    header_payload["result"]["hash"] = "0x" + "99" * 32
    header_bytes = json.dumps(header_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    new_sha = _sha256_bytes(header_bytes)
    new_path = header_path.parent.parent / new_sha[:2] / f"{new_sha}.json"
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_bytes(header_bytes)

    def mutate(case_payload: dict[str, Any]) -> None:
        observation = case_payload["receipt_summary"]["observations"][0]
        observation["header_response_sha256"] = new_sha
        observation["header_raw_response_path"] = str(new_path)

    _rewrite_case(run_root, candidate_id, mutate)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is True
    assert report["integrity_errors"] == []
    assert "receipt_header_disagreement" in _scientific_blockers(report, candidate_id)


def test_verify_candidate_archive_run_strict_historical_artifact_tamper_closes_counter_authority(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)
    historical_path = _historical_case_path(run_root, candidate_id)
    historical = _read_json(historical_path)
    historical["strict_snapshot"]["snapshot"]["status"] = "tampered"
    _write_json(historical_path, historical)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "historical_case_hash_mismatch" in report["integrity_errors"]


def test_verify_candidate_archive_run_missing_historical_case_is_integrity_error(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)
    historical_path = _historical_case_path(run_root, candidate_id)
    historical_path.unlink()

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "historical_case_path_invalid" in report["integrity_errors"]


def test_verify_candidate_archive_run_historical_case_symlink_is_integrity_error(tmp_path: Path) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)
    historical_path = _historical_case_path(run_root, candidate_id)
    original = historical_path.read_bytes()
    historical_path.unlink()
    historical_path.symlink_to(run_root / "qualification_result.json")
    assert historical_path.is_symlink()

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert original
    assert report["counter_authority"] is False
    assert "historical_case_path_invalid" in report["integrity_errors"]


@pytest.mark.parametrize(
    ("surface", "secret_key"),
    [
        ("manifest", "api_token"),
        ("qualification_result", "password"),
        ("candidate_case", "private_key"),
        ("receipt_json", "authorization_header"),
        ("header_json", "session_cookie"),
        ("historical_json", "client_secret"),
    ],
)
def test_verify_candidate_archive_run_secret_like_persisted_fields_are_integrity_errors(
    tmp_path: Path,
    surface: str,
    secret_key: str,
) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)

    if surface == "manifest":
        manifest = _read_json(run_root / "run_manifest.json")
        manifest[secret_key] = "redacted"
        _write_manifest(run_root, manifest)
    elif surface == "qualification_result":
        result = _qualification_result(run_root)
        result[secret_key] = "redacted"
        _write_json(run_root / "qualification_result.json", result)
    elif surface == "candidate_case":
        _rewrite_case(run_root, candidate_id, lambda case_payload: case_payload.__setitem__(secret_key, "redacted"))
    elif surface == "receipt_json":
        _rewrite_raw_response(
            run_root,
            candidate_id,
            observation_key="receipt_raw_response_path",
            mutate_result=lambda result_payload: result_payload.__setitem__(secret_key, "redacted"),
        )
    elif surface == "header_json":
        _rewrite_raw_response(
            run_root,
            candidate_id,
            observation_key="header_raw_response_path",
            mutate_result=lambda result_payload: result_payload.__setitem__(secret_key, "redacted"),
        )
    elif surface == "historical_json":
        _rewrite_historical_case(
            run_root,
            candidate_id,
            lambda historical_payload: historical_payload.__setitem__(secret_key, "redacted"),
        )
    else:
        raise AssertionError(f"unsupported surface: {surface}")

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "secret_like_persisted_field" in report["integrity_errors"]


@pytest.mark.parametrize(
    "safe_key",
    [
        "authorization_basis",
        "credential_kind",
        "cookie_policy",
        "auth_token_sha256",
    ],
)
def test_verify_candidate_archive_run_allows_safe_descriptive_candidate_envelope_keys(
    tmp_path: Path,
    safe_key: str,
) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)

    _rewrite_case(run_root, candidate_id, lambda case_payload: case_payload.__setitem__(safe_key, "public-metadata"))

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is True
    assert report["integrity_errors"] == []
    assert _row(report, candidate_id)["eligible"] is True


@pytest.mark.parametrize(
    "secret_key",
    [
        "api_key",
        "access_token",
        "client_secret",
        "client_secret_id",
        "private_key",
        "authorization_header",
        "authorization_header_url",
        "api_key_policy",
        "session_cookie_kind",
        "credentials",
    ],
)
def test_verify_candidate_archive_run_rejects_secret_container_candidate_envelope_keys(
    tmp_path: Path,
    secret_key: str,
) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    candidate_id = _first_qualified(run_root)

    _rewrite_case(run_root, candidate_id, lambda case_payload: case_payload.__setitem__(secret_key, "redacted"))

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "secret_like_persisted_field" in report["integrity_errors"]


@pytest.mark.parametrize("mode", ["missing", "duplicate", "extra"])
def test_verify_candidate_archive_run_result_population_drift_is_integrity_error(
    tmp_path: Path,
    mode: str,
) -> None:
    module = _verifier_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)
    result = _qualification_result(run_root)
    if mode == "missing":
        result["cases"] = result["cases"][:-1]
        result["candidate_count"] = len(result["cases"])
    elif mode == "duplicate":
        result["cases"].append(dict(result["cases"][0]))
        result["candidate_count"] = len(result["cases"])
    else:
        extra = dict(result["cases"][0])
        extra["candidate_id"] = "ca2r-extra0000000000000000"
        extra["candidate_input"] = dict(extra["candidate_input"])
        extra["candidate_input"]["candidate_id"] = extra["candidate_id"]
        result["cases"].append(extra)
        result["candidate_count"] = len(result["cases"])
    _write_json(run_root / "qualification_result.json", result)

    report = _integration_verify(module, run_root, revision_root, output_dir)

    assert report["counter_authority"] is False
    assert "candidate_population_mismatch" in report["integrity_errors"]


def test_verify_candidate_archive_run_cli_prints_secret_safe_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli = _cli_module()
    run_root, revision_root, output_dir = _fixture_roots(tmp_path)

    exit_code = cli.main(
        [
            "--run-root",
            str(run_root),
            "--revision-root",
            str(revision_root),
            "--output-dir",
            str(output_dir),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["candidate_count"] == 145
    assert payload["eligible_count"] == 116
    assert "secret" not in json.dumps(payload).lower()
