from __future__ import annotations

import json
import os
from pathlib import Path

from jsonschema import Draft202012Validator

from .model import (
    AcquisitionEvent,
    AcquisitionStatus,
    ZERO_SHA256,
    canonical_json,
    validate_status_transition,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


class AppendOnlyLedger:
    def __init__(self, path: str | Path, schema_path: str | Path | None = None):
        self.path = Path(path)
        self.schema_path = Path(schema_path) if schema_path is not None else _project_root() / "schemas" / "public_acquisition_event.schema.json"
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self.validator = Draft202012Validator(schema)

    def append(self, event: AcquisitionEvent) -> AcquisitionEvent:
        events = self._read_events()
        previous_sha = events[-1].event_sha256 if events else ZERO_SHA256
        latest_by_cell: dict[str, AcquisitionStatus] = {}
        for existing in events:
            latest_by_cell[existing.cell_id] = existing.status
        validate_status_transition(latest_by_cell.get(event.cell_id), event.status)
        bound_event = event.bind_previous(previous_sha)
        payload = bound_event.to_dict()
        errors = list(self.validator.iter_errors(payload))
        if errors:
            raise ValueError(f"event schema validation failed: {errors[0].message}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = canonical_json(payload) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return bound_event

    def resume_index(self) -> dict[str, AcquisitionStatus]:
        state: dict[str, AcquisitionStatus] = {}
        for event in self._read_events():
            state[event.cell_id] = event.status
        return state

    def events(self) -> list[AcquisitionEvent]:
        return self._read_events()

    def _read_events(self) -> list[AcquisitionEvent]:
        if not self.path.exists():
            return []
        events: list[AcquisitionEvent] = []
        previous_sha = ZERO_SHA256
        latest_by_cell: dict[str, AcquisitionStatus] = {}
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                if not line:
                    raise ValueError(f"ledger line {line_number} is blank or truncated")
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"ledger line {line_number} is malformed JSON") from exc
                errors = list(self.validator.iter_errors(payload))
                if errors:
                    raise ValueError(f"ledger line {line_number} failed schema validation: {errors[0].message}")
                event = AcquisitionEvent.from_dict(payload)
                if event.previous_event_sha256 != previous_sha:
                    raise ValueError(f"ledger line {line_number} breaks append-only hash chain")
                try:
                    validate_status_transition(latest_by_cell.get(event.cell_id), event.status)
                except ValueError as exc:
                    raise ValueError(str(exc)) from exc
                events.append(event)
                previous_sha = event.event_sha256
                latest_by_cell[event.cell_id] = event.status
        return events
