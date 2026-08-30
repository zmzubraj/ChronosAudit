from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

import chronosaudit_stage2.public_acquisition.historical_snapshot_run as snapshot_run_module


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "run_historical_snapshots_417.py"
QUEUE_PATH = (
    ROOT
    / "processed"
    / "public_acquisition"
    / "2026-08-08"
    / "public-acquisition-20260808T122104Z-2942b2819e08"
    / "case_queue.csv"
)
TEMPORAL_PATH = ROOT / "processed" / "stage2a_temporal_provenance.csv"
POLICY_PATH = ROOT / "config" / "public_acquisition_policy.yaml"
TEMPLATE_PATH = ROOT / "config" / "managed_archive_provider_templates.yaml"


def _load_runner_module():
    spec = importlib.util.spec_from_file_location("historical_snapshot_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _copy_preparation_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    queue_copy = tmp_path / "case_queue.csv"
    temporal_copy = tmp_path / "stage2a_temporal_provenance.csv"
    policy_copy = tmp_path / "public_acquisition_policy.yaml"
    template_copy = tmp_path / "managed_archive_provider_templates.yaml"
    shutil.copyfile(QUEUE_PATH, queue_copy)
    shutil.copyfile(TEMPORAL_PATH, temporal_copy)
    shutil.copyfile(POLICY_PATH, policy_copy)
    shutil.copyfile(TEMPLATE_PATH, template_copy)
    return queue_copy, temporal_copy, policy_copy, template_copy


def _incident_input(tmp_path: Path) -> Path:
    path = tmp_path / "incident-super-secret-token.md"
    path.write_text(
        "\n".join(
            [
                "### 20260102 Example Protocol - Reentrancy",
                "- reference https://secret.example.invalid/full-url?api_key=top-secret",
                "- note super-secret-token",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _append_resume_drift(path: Path, *, name: str) -> None:
    if path.suffix == ".csv":
        path.write_bytes(path.read_bytes() + b"\n")
        return
    if path.suffix in {".yaml", ".yml"}:
        path.write_text(path.read_text(encoding="utf-8") + f"\n# {name}-resume-drift\n", encoding="utf-8")
        return
    path.write_text(path.read_text(encoding="utf-8") + f"\n{name}-resume-drift\n", encoding="utf-8")


def _snapshot_tree(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    if not root.exists():
        return snapshot
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        snapshot[path.relative_to(root).as_posix()] = _sha256_bytes(path.read_bytes())
    return snapshot


def test_prepare_resolves_relative_output_root_for_receipt_portability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, temporal, policy, template = _copy_preparation_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)

    prepared = snapshot_run_module.prepare_historical_snapshot_run(
        queue,
        temporal,
        policy_path=policy,
        provider_template_path=template,
        output_root=Path("relative-output"),
        revision="2026-08-09",
        run_id="relative-run",
        selected_cases=["bancor"],
    )

    assert Path(prepared["run_root"]).is_absolute()
    assert Path(prepared["run_root"]) == tmp_path / "relative-output" / "2026-08-09" / "relative-run"


def test_runner_import_and_plan_do_not_create_run_root_and_do_not_resolve_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_root = tmp_path / "plan-output"
    assert not output_root.exists()

    runner = _load_runner_module()
    assert not output_root.exists()

    def _unexpected_provider_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("plan must not resolve providers")

    def _unexpected_env_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("plan must not read .env")

    def _unexpected_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("plan must not perform network access")

    monkeypatch.setattr(runner, "load_dotenv", _unexpected_env_read, raising=False)
    monkeypatch.setattr(runner, "resolve_managed_providers_for_chain", _unexpected_provider_resolution, raising=False)
    monkeypatch.setattr("urllib.request.urlopen", _unexpected_network)

    exit_code = runner.main(
        [
            "plan",
            "--queue",
            str(QUEUE_PATH),
            "--temporal",
            str(TEMPORAL_PATH),
            "--policy",
            str(POLICY_PATH),
            "--provider-template",
            str(TEMPLATE_PATH),
            "--output-root",
            str(output_root),
            "--revision",
            "2026-08-08-historical-snapshots-plan",
            "--run-id",
            "historical-snapshots-plan",
            "--case",
            "bancor",
            "--case",
            "opyn",
            "--max-cases",
            "1",
        ]
    )

    assert exit_code == 0
    assert not output_root.exists()

    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "plan"
    assert payload["population"]["target_case_count"] == 417
    assert payload["population"]["chain_case_counts"] == {
        "arbitrum": 1,
        "base": 9,
        "bsc": 226,
        "ethereum": 181,
    }
    assert payload["selected"]["requested_case_names"] == ["bancor", "opyn"]
    assert payload["selected"]["selected_case_names"] == ["bancor"]
    assert payload["selected"]["selected_case_count"] == 1


def test_prepare_historical_snapshot_run_freezes_exact_bytes_hashes_and_accepts_same_run_resume(
    tmp_path: Path,
) -> None:
    queue_copy, temporal_copy, policy_copy, template_copy = _copy_preparation_inputs(tmp_path)

    prepared = snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        output_root=tmp_path / "runner-output",
        revision="2026-08-08-historical-snapshots-freeze",
        run_id="historical-snapshots-freeze",
        selected_cases=["bancor", "opyn"],
        max_cases=1,
    )
    rerun = snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        output_root=tmp_path / "runner-output",
        revision="2026-08-08-historical-snapshots-freeze",
        run_id="historical-snapshots-freeze",
        selected_cases=["bancor", "opyn"],
        max_cases=1,
    )

    run_root = Path(prepared["run_root"])
    frozen_manifest = json.loads((run_root / "frozen_inputs" / "manifest.json").read_text(encoding="utf-8"))
    run_manifest = json.loads((run_root / "run_manifest.json").read_text(encoding="utf-8"))
    frozen_entries = {entry["name"]: entry for entry in frozen_manifest["entries"]}

    assert prepared["binding"] == rerun["binding"]
    assert prepared["frozen_inputs"]["entries"] == rerun["frozen_inputs"]["entries"]
    assert prepared["binding"]["selected"]["selected_case_count"] == 1
    assert run_manifest["binding"] == prepared["binding"]
    assert run_manifest["binding_sha256"] == snapshot_run_module._sha256_json(prepared["binding"])
    assert frozen_manifest["entries_sha256"] == prepared["frozen_inputs"]["entries_sha256"]

    for name, source_path in {
        "queue": queue_copy,
        "temporal": temporal_copy,
        "policy": policy_copy,
        "provider_template": template_copy,
    }.items():
        entry = frozen_entries[name]
        frozen_path = run_root / entry["frozen_path"]
        source_bytes = source_path.read_bytes()
        assert entry["available"] is True
        assert frozen_path.read_bytes() == source_bytes
        assert entry["bytes"] == len(source_bytes)
        assert entry["sha256"] == _sha256_bytes(source_bytes)

    assert frozen_entries["incident_input"] == {
        "name": "incident_input",
        "available": False,
        "blocker": "incident_input_unavailable",
    }
    assert prepared["preparation_blockers"] == ["incident_input_unavailable"]
    assert _snapshot_tree(run_root) == _snapshot_tree(Path(rerun["run_root"]))


def test_prepare_historical_snapshot_run_sanitizes_persisted_manifest_with_incident_input(
    tmp_path: Path,
) -> None:
    queue_copy, temporal_copy, policy_copy, template_copy = _copy_preparation_inputs(tmp_path)
    incident_input = _incident_input(tmp_path)

    prepared = snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        incident_input_path=incident_input,
        output_root=tmp_path / "runner-output",
        revision="2026-08-08-historical-snapshots-sanitized",
        run_id="historical-snapshots-sanitized",
    )

    run_root = Path(prepared["run_root"])
    frozen_manifest_text = (run_root / "frozen_inputs" / "manifest.json").read_text(encoding="utf-8")
    run_manifest_text = (run_root / "run_manifest.json").read_text(encoding="utf-8")
    incident_entry = next(
        entry for entry in prepared["frozen_inputs"]["entries"] if entry["name"] == "incident_input"
    )

    assert incident_entry["available"] is True
    assert incident_entry["sha256"] == _sha256_bytes(incident_input.read_bytes())
    assert (run_root / incident_entry["frozen_path"]).read_bytes() == incident_input.read_bytes()
    assert "super-secret-token" not in frozen_manifest_text
    assert "super-secret-token" not in run_manifest_text
    assert "https://secret.example.invalid/full-url?api_key=top-secret" not in frozen_manifest_text
    assert "https://secret.example.invalid/full-url?api_key=top-secret" not in run_manifest_text
    assert '"source_path"' not in frozen_manifest_text
    assert '"source_path"' not in run_manifest_text


@pytest.mark.parametrize(
    ("label", "target_name"),
    [
        ("queue", "queue"),
        ("temporal", "temporal"),
        ("policy", "policy"),
        ("provider_template", "provider_template"),
        ("incident_input", "incident_input"),
    ],
)
def test_prepare_historical_snapshot_run_refuses_changed_input_bytes_on_resume(
    tmp_path: Path,
    label: str,
    target_name: str,
) -> None:
    queue_copy, temporal_copy, policy_copy, template_copy = _copy_preparation_inputs(tmp_path)
    incident_input = _incident_input(tmp_path)
    paths = {
        "queue": queue_copy,
        "temporal": temporal_copy,
        "policy": policy_copy,
        "provider_template": template_copy,
        "incident_input": incident_input,
    }

    prepared = snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        incident_input_path=incident_input,
        output_root=tmp_path / "runner-output",
        revision=f"2026-08-08-historical-snapshots-{label}",
        run_id=f"historical-snapshots-{label}",
    )
    run_root = Path(prepared["run_root"])
    before_snapshot = _snapshot_tree(run_root)

    _append_resume_drift(paths[target_name], name=target_name)

    with pytest.raises(ValueError, match="resume input mismatch"):
        snapshot_run_module.prepare_historical_snapshot_run(
            queue_copy,
            temporal_copy,
            policy_path=policy_copy,
            provider_template_path=template_copy,
            incident_input_path=incident_input,
            output_root=tmp_path / "runner-output",
            revision=f"2026-08-08-historical-snapshots-{label}",
            run_id=f"historical-snapshots-{label}",
        )
    assert _snapshot_tree(run_root) == before_snapshot


@pytest.mark.parametrize("mutation", ["tampered", "deleted"])
def test_prepare_historical_snapshot_run_rejects_tampered_or_deleted_frozen_file_without_repair(
    tmp_path: Path,
    mutation: str,
) -> None:
    queue_copy, temporal_copy, policy_copy, template_copy = _copy_preparation_inputs(tmp_path)
    incident_input = _incident_input(tmp_path)

    prepared = snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        incident_input_path=incident_input,
        output_root=tmp_path / "runner-output",
        revision=f"2026-08-08-historical-snapshots-{mutation}",
        run_id=f"historical-snapshots-{mutation}",
    )

    run_root = Path(prepared["run_root"])
    before_snapshot = _snapshot_tree(run_root)
    frozen_manifest_path = run_root / "frozen_inputs" / "manifest.json"
    run_manifest_path = run_root / "run_manifest.json"
    frozen_manifest_text = frozen_manifest_path.read_text(encoding="utf-8")
    run_manifest_text = run_manifest_path.read_text(encoding="utf-8")

    queue_entry = next(
        entry for entry in prepared["frozen_inputs"]["entries"] if entry["name"] == "queue"
    )
    queue_frozen_path = run_root / queue_entry["frozen_path"]
    original_queue_sha = _sha256_bytes(queue_frozen_path.read_bytes())

    if mutation == "tampered":
        queue_frozen_path.write_bytes(queue_frozen_path.read_bytes() + b"\ntampered\n")
    else:
        queue_frozen_path.unlink()

    with pytest.raises(ValueError, match="frozen input (hash mismatch|is missing): queue"):
        snapshot_run_module.prepare_historical_snapshot_run(
            queue_copy,
            temporal_copy,
            policy_path=policy_copy,
            provider_template_path=template_copy,
            incident_input_path=incident_input,
            output_root=tmp_path / "runner-output",
            revision=f"2026-08-08-historical-snapshots-{mutation}",
            run_id=f"historical-snapshots-{mutation}",
        )

    assert frozen_manifest_path.read_text(encoding="utf-8") == frozen_manifest_text
    assert run_manifest_path.read_text(encoding="utf-8") == run_manifest_text
    if mutation == "tampered":
        assert queue_frozen_path.is_file()
        assert _sha256_bytes(queue_frozen_path.read_bytes()) != original_queue_sha
    else:
        assert not queue_frozen_path.exists()
    after_snapshot = _snapshot_tree(run_root)
    if mutation == "tampered":
        assert after_snapshot == {
            **before_snapshot,
            queue_entry["frozen_path"]: _sha256_bytes(queue_frozen_path.read_bytes()),
        }
    else:
        expected = dict(before_snapshot)
        expected.pop(queue_entry["frozen_path"])
        assert after_snapshot == expected
