from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import run_stage2_control_cutoff_boundary_resolution as runner


def _activation(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "range_scopes": [
                    {
                        "provider_id": "provider-a",
                        "operator_family": "family-a",
                    },
                    {
                        "provider_id": "provider-b",
                        "operator_family": "family-b",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


class _Record:
    def __init__(
        self,
        provider_id: str,
        family: str,
        *,
        verified: bool = True,
        tracking: bool = True,
    ) -> None:
        self.provider_id = provider_id
        self.operator_family = family
        self.operator_verified = verified
        self.tracking_enabled = tracking
        self.public_endpoint = "https://example.invalid/{api_key}"
        self.public_endpoint_id = provider_id + "-endpoint"

    def resolved_endpoint(self) -> str:
        return f"https://rpc.example.invalid/private/{self.provider_id}"


def test_build_runtime_providers_uses_exact_verified_activation_set(
    monkeypatch: pytest.MonkeyPatch,
):
    records = [
        _Record("provider-a", "family-a"),
        _Record("provider-b", "family-b"),
        _Record("not-activated", "family-c"),
    ]
    monkeypatch.setattr(
        runner.ProviderRegistry,
        "from_path",
        lambda path: SimpleNamespace(providers=records),
    )
    constructed: list[dict[str, object]] = []

    class _RuntimeProvider:
        def __init__(self, **kwargs: object) -> None:
            constructed.append(kwargs)
            self.provider_id = kwargs["provider_id"]
            self.provider_family = kwargs["provider_family"]

    monkeypatch.setattr(runner, "JsonRpcProvider", _RuntimeProvider)
    activation = {
        "range_scopes": [
            {"provider_id": "provider-a"},
            {"provider_id": "provider-b"},
            {"provider_id": "provider-a"},
        ]
    }

    providers = runner.build_runtime_providers(
        activation=activation,
        provider_registry_path=Path("registry.yaml"),
        timeout_seconds=45,
    )

    assert set(providers) == {"provider-a", "provider-b"}
    assert {str(row["provider_id"]) for row in constructed} == {
        "provider-a",
        "provider-b",
    }
    assert all(row["timeout"] == 45 for row in constructed)
    assert not any(row["provider_id"] == "not-activated" for row in constructed)


def test_build_runtime_providers_rejects_unverified_activation_provider(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        runner.ProviderRegistry,
        "from_path",
        lambda path: SimpleNamespace(
            providers=[
                _Record("provider-a", "family-a"),
                _Record("provider-b", "family-b", verified=False),
            ]
        ),
    )

    with pytest.raises(ValueError, match="activation_provider_absent_or_unverified"):
        runner.build_runtime_providers(
            activation={
                "range_scopes": [
                    {"provider_id": "provider-a"},
                    {"provider_id": "provider-b"},
                ]
            },
            provider_registry_path=Path("registry.yaml"),
            timeout_seconds=45,
        )


def test_main_routes_resume_and_never_prints_provider_endpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    activation_path = tmp_path / "activation.json"
    _activation(activation_path)
    requirements_path = tmp_path / "requirements.json"
    requirements_path.write_text("{}", encoding="utf-8")
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text("providers: []\n", encoding="utf-8")
    output_root = tmp_path / "output"
    providers = {
        "provider-a": object(),
        "provider-b": object(),
    }
    monkeypatch.setattr(runner, "build_runtime_providers", lambda **kwargs: providers)
    calls: list[dict[str, object]] = []

    def fake_resume(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "status": "IN_PROGRESS_NON_AUTHORIZING",
            "processed_target_count": 3,
            "completed_target_count": 3,
            "counter_authority": False,
            "selection_authorized": False,
        }

    monkeypatch.setattr(runner, "resume_cutoff_boundary_batch", fake_resume)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_stage2_control_cutoff_boundary_resolution.py",
            "--activation-verification",
            str(activation_path),
            "--requirements",
            str(requirements_path),
            "--provider-registry",
            str(registry_path),
            "--output-root",
            str(output_root),
            "--now-utc",
            "2026-08-21T01:00:00Z",
            "--max-targets",
            "3",
            "--provider-min-interval",
            "provider-b=0.5",
            "--resume",
        ],
    )

    assert runner.main() == 3
    assert len(calls) == 1
    assert calls[0]["providers_by_id"] is providers
    assert calls[0]["max_targets"] == 3
    assert calls[0]["provider_min_intervals"] == {"provider-b": 0.5}
    output = capsys.readouterr().out
    assert "IN_PROGRESS_NON_AUTHORIZING" in output
    assert "rpc.example.invalid" not in output
    assert '"counter_authority": false' in output
    assert '"selection_authorized": false' in output
