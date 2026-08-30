from __future__ import annotations

from chronosaudit_stage2.public_acquisition.control_block_window_resolution import (
    ControlBlockWindowResolutionError,
    _rpc_quantity,
    first_accessible_block_anchor,
    first_block_at_or_after_timestamp_interpolated,
    last_block_at_or_before,
)


class _Observation:
    def __init__(self, *, block: int, timestamp: int | None, error: object = None) -> None:
        self.error = error
        self.result = (
            None
            if timestamp is None
            else {
                "number": hex(block),
                "hash": "0x" + f"{block:064x}",
                "timestamp": hex(timestamp),
            }
        )
        self.response_sha256 = f"{block:064x}"


class _PrunedProvider:
    def __init__(self, first_available: int) -> None:
        self.first_available = first_available

    def call(self, method: str, params: list[object]) -> _Observation:
        assert method == "eth_getBlockByNumber"
        block = int(str(params[0]), 16)
        if block < self.first_available:
            return _Observation(block=block, timestamp=None, error={"code": 4444})
        return _Observation(block=block, timestamp=1_000 + block)


class _LinearProvider:
    def call(self, method: str, params: list[object]) -> _Observation:
        assert method == "eth_getBlockByNumber"
        block = int(str(params[0]), 16)
        return _Observation(block=block, timestamp=1_000 + block * 2)


def test_last_block_at_or_before_uses_exact_or_previous_boundary() -> None:
    exact = {
        "target_timestamp": 100,
        "previous_block": {"number": 9, "timestamp": 99},
        "cutoff_block": {"number": 10, "timestamp": 100},
    }
    between = {
        "target_timestamp": 100,
        "previous_block": {"number": 9, "timestamp": 99},
        "cutoff_block": {"number": 10, "timestamp": 101},
    }

    assert last_block_at_or_before(exact) == 10
    assert last_block_at_or_before(between) == 9


def test_first_accessible_block_anchor_handles_pruned_genesis() -> None:
    anchor = first_accessible_block_anchor(
        _PrunedProvider(first_available=37),
        upper_block=100,
        earliest_target_timestamp=1_100,
    )

    assert anchor["number"] == 37
    assert anchor["timestamp"] == 1_037
    assert anchor["response_sha256"] == f"{37:064x}"


def test_first_accessible_block_anchor_rejects_anchor_after_target() -> None:
    try:
        first_accessible_block_anchor(
            _PrunedProvider(first_available=37),
            upper_block=100,
            earliest_target_timestamp=1_020,
        )
    except ValueError as exc:
        assert str(exc) == "first accessible block is not before the earliest target"
    else:
        raise AssertionError("expected insufficient historical coverage")


def test_rpc_quantity_rejects_embedded_application_error() -> None:
    try:
        _rpc_quantity({"code": 503, "message": "server unavailable"}, "head")
    except ControlBlockWindowResolutionError as exc:
        assert str(exc) == "provider_head_invalid"
    else:
        raise AssertionError("expected malformed JSON-RPC quantity rejection")


def test_interpolated_timestamp_search_preserves_exact_bracket() -> None:
    result = first_block_at_or_after_timestamp_interpolated(
        _LinearProvider(),
        target_timestamp=1_075,
        lower_block=0,
        upper_block=100,
    )

    assert result["previous_block"]["number"] == 37
    assert result["previous_block"]["timestamp"] == 1_074
    assert result["cutoff_block"]["number"] == 38
    assert result["cutoff_block"]["timestamp"] == 1_076
