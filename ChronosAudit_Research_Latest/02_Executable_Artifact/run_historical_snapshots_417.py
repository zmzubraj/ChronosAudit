from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from chronosaudit_stage2.public_acquisition.historical_snapshot_run import (
    build_snapshot_run_plan,
    execute_historical_snapshot_cases,
    execute_snapshot_case,
    prepare_historical_snapshot_run,
)
from chronosaudit_stage2.public_acquisition.managed_providers import (
    ManagedProviderConfigurationError,
    load_managed_provider_templates,
    providers_for_chain_from_managed_env,
)


_URL_RE = re.compile(r"https?://\S+")
_KNOWN_COMMANDS = {"plan", "execute"}


def _json_dumps(payload: Mapping[str, Any] | dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _selected_cases_argument(args: argparse.Namespace) -> list[str] | None:
    return args.case if args.case else None


def command_plan(args: argparse.Namespace) -> dict[str, Any]:
    _validate_input_paths(args)
    return {
        "command": "plan",
        **build_snapshot_run_plan(
            args.queue,
            args.temporal,
            policy_path=args.policy,
            provider_template_path=args.provider_template,
            selected_cases=_selected_cases_argument(args),
            max_cases=args.max_cases,
        ),
    }


def _parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        normalized_key = key.strip()
        if not normalized_key:
            continue
        normalized_value = value.strip()
        if normalized_value and normalized_value[0] == normalized_value[-1] and normalized_value[0] in {"'", '"'}:
            normalized_value = normalized_value[1:-1]
        values[normalized_key] = normalized_value
    return values


def _load_execute_env() -> dict[str, str]:
    env = dict(os.environ)
    for key, value in _parse_dotenv(ROOT / ".env").items():
        env.setdefault(key, value)
    return env


def _prepared_frozen_input_path(prepared_run: Mapping[str, Any], *, name: str) -> Path:
    run_root = Path(str(prepared_run["run_root"]))
    frozen_inputs = dict(prepared_run.get("frozen_inputs") or {})
    entries = list(frozen_inputs.get("entries") or [])
    for entry in entries:
        if str(entry.get("name", "")).strip() == name:
            if not entry.get("available"):
                raise FileNotFoundError(f"frozen input unavailable: {name}")
            frozen_path = str(entry.get("frozen_path", "")).strip()
            if not frozen_path:
                raise FileNotFoundError(f"frozen input unavailable: {name}")
            return run_root / frozen_path
    raise FileNotFoundError(f"frozen input unavailable: {name}")


def _build_provider_resolver(prepared_run: Mapping[str, Any]) -> Any:
    template_path = _prepared_frozen_input_path(prepared_run, name="provider_template")
    templates = load_managed_provider_templates(template_path)
    env = _load_execute_env()

    def provider_resolver(chain: str, receipt_root: Path) -> list[Any]:
        return providers_for_chain_from_managed_env(
            chain,
            templates=templates,
            env=env,
            artifact_root=receipt_root,
            timeout=30,
            retries=3,
            backoff_seconds=0.25,
        )

    return provider_resolver


def _artifact_paths(prepared_run: Mapping[str, Any], execute_result: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    run_root = Path(str(prepared_run["run_root"])).resolve()
    artifact_paths: dict[str, dict[str, str]] = {
        "run_root": {"relative": ".", "absolute": str(run_root)},
        "run_manifest": {
            "relative": "run_manifest.json",
            "absolute": str(Path(str(prepared_run["run_manifest_path"])).resolve()),
        },
    }
    aggregate_artifacts = dict(execute_result.get("aggregate_artifacts") or {})
    for name, relpath in dict(aggregate_artifacts.get("paths") or {}).items():
        artifact_paths[str(name)] = {
            "relative": str(relpath),
            "absolute": str((run_root / str(relpath)).resolve()),
        }
    return artifact_paths


def _blocker_counts_by_code(blocker_rows: list[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in blocker_rows:
        code = str(row.get("code", "")).strip()
        if not code:
            continue
        counts[code] = counts.get(code, 0) + 1
    return {code: counts[code] for code in sorted(counts)}


def command_execute(args: argparse.Namespace) -> dict[str, Any]:
    if args.max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    _validate_input_paths(args)
    prepared_run = prepare_historical_snapshot_run(
        args.queue,
        args.temporal,
        policy_path=args.policy,
        provider_template_path=args.provider_template,
        incident_input_path=args.incident_input,
        output_root=args.output_root,
        revision=args.revision,
        run_id=args.run_id,
        selected_cases=_selected_cases_argument(args),
        max_cases=args.max_cases,
    )
    execute_kwargs = {
        "provider_resolver": _build_provider_resolver(prepared_run),
        "case_executor": execute_snapshot_case,
        "max_workers": args.max_workers,
        "resume": args.resume,
    }
    if getattr(args, "retry_partial", False):
        execute_kwargs["retry_partial"] = True
    execute_result = execute_historical_snapshot_cases(prepared_run, **execute_kwargs)
    summary = dict(execute_result.get("summary") or {})
    blocker_rows = list(execute_result.get("blocker_rows") or [])
    return {
        "command": "execute",
        "status": "ok",
        "revision": str(prepared_run["revision"]),
        "run_id": str(prepared_run["run_id"]),
        "selected_case_count": int(summary.get("selected_case_count", 0)),
        "processed_case_count": int(summary.get("processed_case_count", 0)),
        "candidate_closed_count": int(summary.get("candidate_closed_count", 0)),
        "reused_case_count": int(summary.get("reused_case_count", 0)),
        "quarantined_case_count": int(summary.get("quarantined_case_count", 0)),
        "retried_case_count": int(summary.get("retried_case_count", 0)),
        "blocker_count": len(blocker_rows),
        "blocker_counts_by_code": _blocker_counts_by_code(blocker_rows),
        "artifact_paths": _artifact_paths(prepared_run, execute_result),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resumable ChronosAudit historical snapshot runner.",
        exit_on_error=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_flags(command: argparse.ArgumentParser) -> None:
        command.add_argument("--queue", type=Path, required=True)
        command.add_argument("--temporal", type=Path, required=True)
        command.add_argument("--policy", type=Path, required=True)
        command.add_argument("--provider-template", type=Path, required=True)
        command.add_argument("--incident-input", type=Path, default=None)
        command.add_argument("--output-root", type=Path, required=True)
        command.add_argument("--revision", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--case", action="append", default=[])
        command.add_argument("--max-cases", type=int, default=None)

    plan = subparsers.add_parser("plan", help="Prepare an offline historical snapshot plan.")
    add_common_flags(plan)
    plan.set_defaults(func=command_plan)

    execute = subparsers.add_parser("execute", help="Execute selected historical snapshot cases.")
    add_common_flags(execute)
    execute.add_argument("--max-workers", type=int, default=1)
    execute.add_argument("--resume", dest="resume", action="store_true", default=True)
    execute.add_argument("--no-resume", dest="resume", action="store_false")
    execute.add_argument(
        "--retry-partial",
        action="store_true",
        help="Preserve and retry only valid PARTIAL case envelopes; reuse strict closures.",
    )
    execute.set_defaults(func=command_execute)
    return parser


def _safe_message(value: str) -> str:
    return _URL_RE.sub("<redacted-url>", value)


def _command_from_argv(argv: list[str] | None) -> str:
    if not argv:
        return "unknown"
    candidate = str(argv[0]).strip()
    return candidate if candidate in _KNOWN_COMMANDS else "unknown"


def _error_payload(*, command: str, error_code: str, message: str) -> dict[str, str]:
    return {
        "command": command,
        "status": "error",
        "error_code": error_code,
        "message": _safe_message(message),
    }


def _validate_input_paths(args: argparse.Namespace) -> None:
    required_inputs = {
        "--queue": args.queue,
        "--temporal": args.temporal,
        "--policy": args.policy,
        "--provider-template": args.provider_template,
    }
    if getattr(args, "incident_input", None) is not None:
        required_inputs["--incident-input"] = args.incident_input
    for flag, path_value in required_inputs.items():
        path = Path(path_value)
        if not path.is_file():
            raise FileNotFoundError(f"required input path missing for {flag}")


def _value_error_payload(command: str, exc: ValueError) -> dict[str, str]:
    message = str(exc)
    if message == "max_workers must be >= 1":
        return _error_payload(command=command, error_code="invalid_cli_argument", message=message)
    if message.startswith("unknown selected case:"):
        return _error_payload(command=command, error_code="invalid_cli_argument", message=message)
    return _error_payload(
        command=command,
        error_code="invalid_cli_argument",
        message="invalid command line arguments",
    )


def _file_not_found_payload(command: str, exc: FileNotFoundError) -> dict[str, str]:
    message = str(exc)
    if message.startswith("required input path missing for "):
        safe_message = message
    elif message.startswith("frozen input unavailable:"):
        safe_message = "required prepared input missing"
    else:
        safe_message = "required input path missing"
    return _error_payload(command=command, error_code="input_not_found", message=safe_message)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    command = _command_from_argv(argv)
    try:
        args = parser.parse_args(argv)
        command = getattr(args, "command", command)
        result = args.func(args)
        print(_json_dumps(result))
        return 0
    except argparse.ArgumentError as exc:
        payload = _error_payload(
            command=command,
            error_code="invalid_cli_argument",
            message="invalid command line arguments",
        )
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1
    except SystemExit:
        payload = _error_payload(
            command=command,
            error_code="invalid_cli_argument",
            message="invalid command line arguments",
        )
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1
    except ManagedProviderConfigurationError as exc:
        payload = _error_payload(
            command=command,
            error_code=str(getattr(exc, "code", "managed_provider_configuration_failed")).strip() or "managed_provider_configuration_failed",
            message="managed provider configuration failed",
        )
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        payload = _file_not_found_payload(command, exc)
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1
    except ValueError as exc:
        payload = _value_error_payload(command, exc)
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1
    except Exception:
        payload = _error_payload(
            command=command,
            error_code="historical_snapshot_runner_failed",
            message="historical snapshot runner failed",
        )
        print(_json_dumps(payload))
        print(payload["message"], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
