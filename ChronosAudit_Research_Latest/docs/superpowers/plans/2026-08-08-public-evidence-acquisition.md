# ChronosAudit Public-Evidence Acquisition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and execute an auditable public-data acquisition system that queues all 417 ChronosAudit cases, preserves a fixed 10-case evidence-grade pilot, attempts a 20,000-deployment denominator, prepares external-review packets, and derives every scientific counter fail-closed from row-level evidence.

**Architecture:** Add a focused `chronosaudit_stage2.public_acquisition` package around the existing on-chain, source-history, control-matching, review, and release modules. The package owns source inventories, provider identities, append-only acquisition events, deterministic queues, bulk deployment ingestion, strict counter projection, and a resumable CLI. Network acquisition and offline qualification are separate commands; public-source failures remain preserved observations rather than being hidden or promoted.

**Tech Stack:** Python 3.10+, standard library HTTP/JSON/XML/SQLite, pandas, PyYAML, jsonschema, PyArrow for pinned Parquet inputs, pytest, uv lockfile, existing ChronosAudit Stage-2 modules.

## Global Constraints

- Public data and public RPC only. Paid APIs, private archive services, authenticated browser sessions, and proprietary databases are outside this plan.
- Queue all 417 canonical cases on the first live run. The fixed pilot allocation is exactly 3 Ethereum, 3 BNB Smart Chain, 2 Base, and 2 Arbitrum cases.
- Use seed `chronosaudit-public-pilot-v1-20260808` for pilot and denominator deterministic ranking.
- Target exactly 5,000 unique deployment records per chain and 20,000 total. Do not reallocate a chain shortfall.
- The canonical outcome-independent cutoff is 24 hours after deployment with a minimum one-hour lead before incident, as specified in `config/stage2_policy.yaml`. The incident block/time only determines eligibility; it must never move the cutoff. Missing deployment evidence leaves the case `PARTIAL`.
- Strict historical closure requires two independently evidenced provider families, canonical block-hash agreement, and EIP-1898 block-hash-pinned code and proxy-state agreement. Multiple URLs from one operator count as one family.
- Chainlist is discovery-only. An endpoint is not archive-qualified from listing or operator claims.
- Preserve raw response bytes or byte-exact artifacts, SHA-256 digests, normalized requests, UTC timestamps, endpoint pseudonyms, retries, and errors. Never persist credentials or unredacted secret-bearing URLs.
- Use only these acquisition states: `NOT_QUEUED`, `QUEUED`, `ATTEMPTED`, `PARTIAL`, `VERIFIED`, `DISPUTED`, `UNAVAILABLE`, `POLICY_EXCLUDED`, `WAITING_EXTERNAL`, `STALE`.
- Independent adjudication remains `WAITING_EXTERNAL` until distinct accountable human reviewers participate. AI-generated, public benchmark, and same-owner labels never increment it.
- Control candidates never increment qualified controls without cutoff-safe risk-set membership, frozen follow-up/censoring evidence, investigated-negative evidence, and independent outcome review.
- Independent R5 blocks and release-eligible cases remain zero until their complete adjudication, lineage, censoring, and leakage predicates pass.
- Every summary counter must be reproducible from validated row-level artifacts. No prose, configuration variable, or manually supplied numerator can assign a counter.
- Acquisition must be bounded: explicit concurrency, timeout, response-size, retry, elapsed-time, and disk budgets; exponential backoff with jitter; per-case x provider x method resumability.
- Existing authoritative artifacts must not be silently overwritten. New outputs use revisioned directories and manifests with derivation hashes.
- A successful acquisition run must not automatically promote the research phase.

---

### Task 1: Acquisition evidence model, provider registry, and append-only ledger

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/__init__.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/model.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/ledger.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/providers.py`
- Create: `02_Executable_Artifact/config/public_acquisition_policy.yaml`
- Create: `02_Executable_Artifact/config/public_provider_registry.yaml`
- Create: `02_Executable_Artifact/schemas/public_acquisition_event.schema.json`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_model.py`
- Modify: `02_Executable_Artifact/pyproject.toml`
- Create: `02_Executable_Artifact/uv.lock`

**Interfaces:**
- Produces: `AcquisitionStatus`, `AcquisitionEvent`, `ProviderRecord`, `ProviderRegistry`, `AppendOnlyLedger`, `redact_endpoint()`, `endpoint_id()`, `canonical_json_sha256()`.
- Consumes: existing `archive_provider_catalog.yaml` semantics and JSON Schema validation.
- Later tasks rely on: `AppendOnlyLedger.append(event)`, `AppendOnlyLedger.resume_index()`, and `ProviderRegistry.providers_for_chain(chain, verified_only=False)`.

- [ ] **Step 1: Write failing model, redaction, independence, and ledger tests**

```python
def test_secret_bearing_endpoint_is_redacted_and_stably_identified():
    raw = "https://rpc.example/v3/SECRET?apikey=TOPSECRET&x=1"
    assert redact_endpoint(raw) == "https://rpc.example/v3/<redacted>?apikey=<redacted>&x=1"
    assert endpoint_id(raw) == endpoint_id(raw)
    assert "SECRET" not in endpoint_id(raw)

def test_registry_requires_distinct_verified_operator_families(tmp_path):
    registry = ProviderRegistry.from_mapping({"providers": [
        {"provider_id": "a1", "chain": "ethereum", "operator_family": "operator-a", "endpoint": "https://a/1", "operator_evidence_url": "https://a/about", "operator_evidence_sha256": "a" * 64},
        {"provider_id": "a2", "chain": "ethereum", "operator_family": "operator-a", "endpoint": "https://a/2", "operator_evidence_url": "https://a/about", "operator_evidence_sha256": "a" * 64},
    ]})
    assert registry.independent_family_count("ethereum") == 1

def test_ledger_is_append_only_and_resumes_per_cell(tmp_path):
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    event = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    ledger.append(event)
    ledger.append(event.transition(AcquisitionStatus.ATTEMPTED))
    assert ledger.resume_index()[event.cell_id] == AcquisitionStatus.ATTEMPTED
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 2
```

- [ ] **Step 2: Run tests and confirm the new package is absent**

Run: `uv run pytest -q tests/test_public_acquisition_model.py` from `02_Executable_Artifact/`  
Expected: collection failure because `chronosaudit_stage2.public_acquisition` does not exist.

- [ ] **Step 3: Implement the evidence types and endpoint protection**

```python
class AcquisitionStatus(str, Enum):
    NOT_QUEUED = "NOT_QUEUED"
    QUEUED = "QUEUED"
    ATTEMPTED = "ATTEMPTED"
    PARTIAL = "PARTIAL"
    VERIFIED = "VERIFIED"
    DISPUTED = "DISPUTED"
    UNAVAILABLE = "UNAVAILABLE"
    POLICY_EXCLUDED = "POLICY_EXCLUDED"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    STALE = "STALE"

@dataclass(frozen=True)
class AcquisitionEvent:
    event_id: str
    cell_id: str
    case_id: str | None
    chain: str
    provider_id: str | None
    method: str
    block_selector: str | None
    status: AcquisitionStatus
    observed_at_utc: str
    request_sha256: str | None
    response_sha256: str | None
    raw_artifact_path: str | None
    error_class: str | None
    error_detail: str | None
    previous_event_sha256: str
    event_sha256: str
```

Implement allowed state transitions, canonical hashing, fsync-backed JSONL append, chain validation, and a resume index that selects the latest valid event per cell without erasing history. Reject malformed/truncated ledger lines rather than skipping them.

- [ ] **Step 4: Add provider registry and exact configuration**

`public_acquisition_policy.yaml` must contain:

```yaml
version: 1.0.0
seed: chronosaudit-public-pilot-v1-20260808
pilot_allocation: {ethereum: 3, bsc: 3, base: 2, arbitrum: 2}
denominator_per_chain: 5000
full_case_target: 417
timeout_seconds: 20
max_retries: 3
max_response_bytes: 10485760
global_concurrency: 4
per_provider_concurrency: 1
backoff_base_seconds: 0.5
backoff_max_seconds: 30
require_eip1898_for_strict_snapshot: true
```

Registry records must include provider ID, chain, endpoint, operator family, discovery source, tracking flag, operator-evidence URL/hash, and `operator_verified`. Seed only publicly documented PublicNode and 1RPC candidates, marked `operator_verified: false` until their operator evidence is captured and hashed by the live inventory command.

- [ ] **Step 5: Lock dependencies and run the task tests**

Add `pyarrow>=22.0.0,<23.0.0` to `pyproject.toml`, run `uv lock`, then run:

```bash
uv sync --locked
uv run pytest -q tests/test_public_acquisition_model.py
```

Expected: all task tests pass.

- [ ] **Step 6: Commit**

```bash
git add 02_Executable_Artifact/pyproject.toml 02_Executable_Artifact/uv.lock \
  02_Executable_Artifact/config/public_acquisition_policy.yaml \
  02_Executable_Artifact/config/public_provider_registry.yaml \
  02_Executable_Artifact/schemas/public_acquisition_event.schema.json \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition \
  02_Executable_Artifact/tests/test_public_acquisition_model.py
git commit -m "feat: add public acquisition evidence foundation"
```

---

### Task 2: Deterministic pilot/full queue and strict RPC acquisition

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/queue.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/rpc.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_queue.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_rpc.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/onchain.py`
- Modify: `02_Executable_Artifact/run_live_stage2_evidence.py`

**Interfaces:**
- Consumes: Task 1 `ProviderRegistry`, `AppendOnlyLedger`, `AcquisitionEvent`; canonical case CSV `processed/stage2b_onchain_query_queue.csv`; existing `historical_identity_snapshot()`.
- Produces: `build_case_queue(cases, policy) -> tuple[pd.DataFrame, pd.DataFrame]`, `PublicRpcClient`, `acquire_case_snapshot()`, `acquire_queue()`.
- Later tasks rely on: queue columns `case_id`, `case_name`, `chain`, `address`, `incident_block`, `pilot_member`, `priority`, `queue_sha256`, `cutoff_status`, and `prediction_cutoff_block`.

- [ ] **Step 1: Write failing deterministic-queue and provider-object regression tests**

```python
def test_queue_contains_all_cases_and_frozen_allocation(canonical_cases):
    full, pilot = build_case_queue(canonical_cases, policy())
    assert len(full) == 417
    assert pilot.chain.value_counts().to_dict() == {"ethereum": 3, "bsc": 3, "base": 2, "arbitrum": 2}
    assert len(pilot) == 10
    assert full.loc[full.pilot_member, "priority"].eq(0).all()
    assert full.loc[~full.pilot_member, "priority"].eq(1).all()

def test_public_provider_fallback_constructs_provider_objects():
    providers = public_provider_objects("ethereum", ProviderRegistry.load(CONFIG))
    assert len(providers) >= 2
    assert all(hasattr(provider, "call") for provider in providers)

def test_same_family_responses_cannot_close_snapshot(fake_snapshot_inputs):
    result = acquire_case_snapshot(fake_snapshot_inputs, providers=[same_family_a, same_family_b])
    assert result["status"] != "VERIFIED"
    assert result["blocked_reason"] == "insufficient_independent_provider_families"
```

- [ ] **Step 2: Run task tests and verify red state**

Run: `uv run pytest -q tests/test_public_acquisition_queue.py tests/test_public_acquisition_rpc.py`  
Expected: import failures for missing queue/RPC modules.

- [ ] **Step 3: Implement deterministic two-lane queue generation**

Normalize chain aliases `mainnet -> ethereum` and `arbi -> arbitrum`. Select the pilot before any network result is read. Within each chain, create deterministic age strata from incident block quantiles and a pre-network proxy-hint stratum only when that hint is already present in the canonical input. Rank rows by:

```python
hashlib.sha256(f"{seed}|pilot|{chain}|{case_name}".encode()).hexdigest()
```

Bind full and pilot manifests to the input file SHA-256, policy SHA-256, seed, and selection-code version. Refuse duplicate case IDs or a case count other than 417.

- [ ] **Step 4: Strengthen provider-family consensus and raw receipts**

Modify `ProviderObservation` to include `provider_family`, `request_sha256`, `raw_response_path`, `http_status`, `attempt`, and a UTC timestamp while retaining backward-compatible defaults. Modify `provider_consensus()` so strict mode counts distinct verified provider families, not merely response count. Persist raw response bytes using a content-addressed path before returning the normalized observation.

Environment provider syntax becomes:

```text
CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS=https://one,https://two
CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES=operator-one,operator-two
```

Mismatched list lengths or unverified families yield configuration errors and cannot close strict consensus.

- [ ] **Step 5: Implement bounded queue acquisition**

For every case, always record a capability observation at its existing historical anchor. Attempt a strict prediction-cutoff snapshot only when deployment evidence permits the canonical 24-hour landmark and its block has been independently resolved. Keep cells separate for block, code, each EIP-1967 slot, beacon call, implementation code, source locator, and creation locator.

Use bounded worker execution with global concurrency 4 and per-provider concurrency 1. Retry only transient classes, preserve jittered backoff, and use the ledger resume index. Terminal `VERIFIED`, `DISPUTED`, `POLICY_EXCLUDED`, and `WAITING_EXTERNAL` cells are not reissued unless `--retry-terminal` is explicitly passed.

- [ ] **Step 6: Replace the broken legacy public-provider path with a compatibility wrapper**

`run_live_stage2_evidence.py` must construct `JsonRpcProvider` objects through the registry and delegate to the new acquisition API. Keep dry-run default and require `--execute` for network calls. Preserve the legacy output location through an explicit `--legacy-output` option rather than writing it by default.

- [ ] **Step 7: Run focused and regression tests**

```bash
uv run pytest -q tests/test_onchain.py tests/test_deployment_stream_full.py \
  tests/test_public_acquisition_queue.py tests/test_public_acquisition_rpc.py
```

Expected: all tests pass, including the URL-string regression and provider-family fail-closed cases.

- [ ] **Step 8: Commit**

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/onchain.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/queue.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/rpc.py \
  02_Executable_Artifact/run_live_stage2_evidence.py \
  02_Executable_Artifact/tests/test_public_acquisition_queue.py \
  02_Executable_Artifact/tests/test_public_acquisition_rpc.py
git commit -m "feat: add bounded full-case RPC acquisition"
```

---

### Task 3: Public inventory capture and 20,000-deployment denominator

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/inventory.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/denominator.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_inventory.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_denominator.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/source_history.py`

**Interfaces:**
- Consumes: Task 1 hashing/ledger and fixed policy; public Chainlist, AWS S3 inventory, and Sourcify v2 listing formats.
- Produces: `capture_chainlist_inventory()`, `capture_s3_inventory()`, `capture_sourcify_inventory()`, `normalize_deployment_batch()`, `select_denominator()`, `validate_denominator()`.
- Later tasks rely on denominator columns: `deployment_id`, `chain`, `chain_id`, `contract_address`, `creation_tx_hash`, `creation_type`, `deployment_block`, `deployment_block_hash`, `deployment_time`, `creator_address`, `runtime_code_sha256`, `source_provider`, `source_object_key`, `source_object_etag`, `source_record_sha256`, `duplicate_group_id`, `admissibility_status`, `exclusion_reason`, `selection_rank_sha256`.

- [ ] **Step 1: Write failing inventory, normalization, and deterministic selection tests**

```python
def test_chainlist_inventory_excludes_secret_and_tracking_endpoints(fixture_xml_json):
    result = capture_chainlist_inventory(fixture_xml_json, output_dir)
    assert result["raw_sha256"]
    assert all("${" not in row["endpoint"] for row in result["eligible_endpoints"])
    assert all(row["tracking"] is False for row in result["eligible_endpoints"])

def test_denominator_requires_creation_proof_and_deduplicates():
    normalized = normalize_deployment_batch(rows_with_duplicate_and_current_code_only)
    assert normalized.admissibility_status.tolist().count("VERIFIED") == 1
    assert "missing_creation_proof" in set(normalized.exclusion_reason)

def test_no_chain_shortfall_reallocation(valid_deployments):
    selected, audit = select_denominator(valid_deployments, per_chain=5000, seed=SEED)
    assert audit.set_index("chain").loc["base", "selected"] == audit.set_index("chain").loc["base", "available"]
    assert len(selected[selected.chain == "ethereum"]) == 5000
    assert audit.loc[audit.chain == "base", "shortfall"].iloc[0] > 0
```

- [ ] **Step 2: Run tests and verify red state**

Run: `uv run pytest -q tests/test_public_acquisition_inventory.py tests/test_public_acquisition_denominator.py`  
Expected: missing-module failures.

- [ ] **Step 3: Implement immutable public inventory capture**

Use bounded `urllib.request` downloads and `xml.etree.ElementTree` parsing. Capture:

- Chainlist raw JSON plus response headers and SHA-256;
- AWS `ListObjectsV2` XML pages for each configured chain prefix, with pagination token, key, size, ETag, and last modified;
- Sourcify v2 bucket XML pages for `contract_deployments`, `contracts`, `code`, and `verified_contracts`.

Store every raw inventory page content-addressably and emit a normalized CSV plus JSON manifest. Enforce maximum pages, objects, response bytes, and elapsed time from configuration.

- [ ] **Step 4: Implement PyArrow batch extraction and schema adapters**

Read downloaded Parquet objects in record batches. Chain-specific field mappings must be configuration-driven and validated before rows are emitted. Preserve rejected rows with explicit reasons. Include top-level and internal creation events only when transaction/trace creation proof exists. Extend the existing Sourcify deployment adapter without changing its fail-closed semantics.

- [ ] **Step 5: Implement the 5,000-per-chain selector and 200-row cross-check manifest**

Rank verified rows by:

```python
hashlib.sha256(f"{seed}|denominator|{chain}|{deployment_id}".encode()).hexdigest()
```

Select exactly 5,000 per chain when available. Emit a per-chain audit with inventory rows, parsed rows, verified rows, duplicates, exclusions, selected rows, and shortfall. Select 50 rows per chain for independent RPC/Sourcify cross-check; cross-check failures mark rows `PARTIAL` or `DISPUTED` and trigger deterministic replacement only before the denominator is frozen, with every replacement logged.

- [ ] **Step 6: Run task and existing source-history tests**

```bash
uv run pytest -q tests/test_source_history_adapters.py tests/test_public_evidence.py \
  tests/test_public_acquisition_inventory.py tests/test_public_acquisition_denominator.py
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/source_history.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/inventory.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/denominator.py \
  02_Executable_Artifact/tests/test_public_acquisition_inventory.py \
  02_Executable_Artifact/tests/test_public_acquisition_denominator.py
git commit -m "feat: add public deployment denominator ingestion"
```

---

### Task 4: Control candidates, external-review packets, and strict counter projection

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/qualification.py`
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/counters.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_qualification.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_counters.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/review_workflow.py`
- Modify: `02_Executable_Artifact/production_qualification.py`

**Interfaces:**
- Consumes: validated historical manifests, denominator, existing `deterministic_matched_controls()`, blinded reviewer workflow, strict R0–R5 certification inputs.
- Produces: `build_control_candidates()`, `build_review_bundle()`, `qualify_control_rows()`, `project_counters()`, `verify_release_eligibility()`.
- Counter output keys are exactly: `historical_snapshots`, `independent_adjudications`, `deployment_denominator`, `control_candidates`, `qualified_controls`, `independent_r5_blocks`, `release_eligible_cases`.

- [ ] **Step 1: Write failing fail-closed counter tests**

```python
def test_packets_do_not_increment_independent_adjudications(evidence_fixture):
    result = project_counters(evidence_fixture.with_review_packets(10, 100))
    assert result["independent_adjudications"]["observed"] == 0
    assert result["positive_case_review_packets"]["observed"] == 10

def test_candidates_do_not_increment_qualified_controls(evidence_fixture):
    result = project_counters(evidence_fixture.with_control_candidates(100))
    assert result["control_candidates"]["observed"] == 100
    assert result["qualified_controls"]["observed"] == 0

def test_any_missing_gate_yields_zero_release(evidence_fixture):
    for missing in evidence_fixture.mandatory_gate_names:
        result = verify_release_eligibility(evidence_fixture.with_gate_missing(missing))
        assert result["release_eligible_cases"] == 0
```

- [ ] **Step 2: Run tests and verify red state**

Run: `uv run pytest -q tests/test_public_acquisition_qualification.py tests/test_public_acquisition_counters.py`  
Expected: missing-module failures.

- [ ] **Step 3: Build 10:1 candidate matching without qualification inflation**

Use the existing matcher only after converting positives and denominator rows into its cutoff-safe input schema. Exclude all known positive addresses and any currently detected identity/clone/proxy/protocol linkage. Preserve underfilled match sets. Add `candidate_status`, `follow_up_start`, `follow_up_horizon`, `censoring_status`, `investigated_negative_status`, and `independent_outcome_review_status`. Only the full conjunction may produce `QUALIFIED_CONTROL`.

- [ ] **Step 4: Generate immutable blinded review bundles**

Produce separate positive-case and control packets with packet IDs, source-manifest hash, visible-field list, blinding seed/hash, assignment placeholder, and packet SHA-256. Keep `positive_case_review_packets`, `control_review_packets`, and `finalized_positive_adjudications` separate. Extend the independence gate so same-case completion requires reviewer metadata, conflict declarations, confidence threshold, agreement/adjudicator evidence, and final-decision hashes.

- [ ] **Step 5: Implement central counter and release projection**

Derive counters only from schema-valid, hash-bound rows. Historical snapshots require strict status and two distinct verified families. Independent adjudications require finalized same-case human decisions. R5 requires finalized mechanism/lineage graph components and the policy thresholds. Release eligibility is the conjunction of all case-level gates and must preserve zero rows until everything closes.

Replace `production_qualification.py` environment/count shortcuts with validation of the new canonical counter artifact and its input manifest. Keep exit code 3 when unqualified.

- [ ] **Step 6: Run focused and release-gate tests**

```bash
uv run pytest -q tests/test_control_matching.py tests/test_stage2_upgrade.py \
  tests/test_split_audit.py tests/test_public_acquisition_qualification.py \
  tests/test_public_acquisition_counters.py
```

Expected: all tests pass and every negative fixture keeps release at zero.

- [ ] **Step 7: Commit**

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/review_workflow.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/qualification.py \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/counters.py \
  02_Executable_Artifact/production_qualification.py \
  02_Executable_Artifact/tests/test_public_acquisition_qualification.py \
  02_Executable_Artifact/tests/test_public_acquisition_counters.py
git commit -m "feat: derive acquisition counters fail closed"
```

---

### Task 5: Resumable CLI, verifier, runbook, and offline integration

**Files:**
- Create: `02_Executable_Artifact/run_public_evidence_acquisition.py`
- Create: `02_Executable_Artifact/verify_public_evidence_acquisition.py`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_cli.py`
- Create: `02_Executable_Artifact/PUBLIC_ACQUISITION_RUNBOOK.md`
- Modify: `02_Executable_Artifact/README.md`
- Modify: `02_Executable_Artifact/verify_stage2.py`

**Interfaces:**
- Consumes: Tasks 1–4 modules.
- Produces CLI subcommands: `plan`, `inventory`, `rpc`, `denominator`, `controls`, `review-packets`, `project`, `verify`, and `run-public`.
- Produces revisioned directories under `raw/public_acquisition/`, `processed/public_acquisition/`, and `reports/public_acquisition/`.

- [ ] **Step 1: Write failing CLI dry-run, resume, and fail-closed integration tests**

```python
def test_plan_is_offline_and_writes_417_case_manifest(cli_runner, tmp_path):
    result = cli_runner("plan", "--output-root", str(tmp_path))
    assert result.exit_code == 0
    assert read_csv(tmp_path / "processed/case_queue.csv").shape[0] == 417

def test_network_commands_require_execute(cli_runner, tmp_path):
    result = cli_runner("rpc", "--output-root", str(tmp_path))
    assert result.exit_code == 0
    assert "plan_only" in result.stdout

def test_verifier_rejects_tampered_ledger(cli_runner, completed_fixture):
    tamper(completed_fixture / "raw/acquisition_events.jsonl")
    result = cli_runner("verify", "--output-root", str(completed_fixture))
    assert result.exit_code != 0
```

- [ ] **Step 2: Run tests and verify red state**

Run: `uv run pytest -q tests/test_public_acquisition_cli.py`  
Expected: missing CLI failure.

- [ ] **Step 3: Implement dry-run-by-default command orchestration**

All network commands require `--execute`. `run-public --execute` performs inventory capture, queues all 417 cases, runs bounded RPC acquisition, attempts denominator materialization, prepares control candidates/reviewer packets, projects counters, and verifies the output. Every subcommand is independently resumable and accepts `--revision`, `--max-cases`, `--max-pages`, `--max-bytes`, and `--deadline-seconds` where relevant.

Use revision path format:

```python
run_id = f"public-acquisition-{utc_timestamp_compact}-{input_sha256[:12]}"
```

Write `run-state.json` after each cell with atomic replace, while the scientific evidence ledger remains append-only.

- [ ] **Step 4: Implement the independent verifier**

Verify schemas, hashes, ledger continuity, manifest closure, 417-case queue, pilot allocation, per-chain denominator counts, shortfalls, duplicate identities, request/response artifacts, counter derivation, qualified-control predicates, reviewer independence artifacts, R0–R5 prerequisites, and release rows. Emit machine-readable JSON and a Markdown report. A structurally valid but scientifically incomplete run exits 0 with `structure_valid: true` and `scientifically_complete: false`; integrity/schema/tamper failures exit nonzero.

- [ ] **Step 5: Document exact safe commands and interpretations**

The runbook must show:

```bash
uv sync --locked
uv run python run_public_evidence_acquisition.py plan
uv run python run_public_evidence_acquisition.py run-public --execute \
  --max-cases 417 --deadline-seconds 21600
uv run python verify_public_evidence_acquisition.py --latest
```

Document that attempted coverage, packet preparation, and control candidates do not increment scientific counters. Document resume commands, endpoint removal, rate-limit handling, disk budgets, and external-review handoff.

- [ ] **Step 6: Run focused CLI and full unit suite**

```bash
uv run pytest -q tests/test_public_acquisition_cli.py
uv run pytest -q
uv run python verify_stage2.py
```

Expected: all pytest tests pass; the existing Stage-2 verifier passes; production qualification remains unqualified unless genuine evidence has closed every gate.

- [ ] **Step 7: Commit**

```bash
git add 02_Executable_Artifact/run_public_evidence_acquisition.py \
  02_Executable_Artifact/verify_public_evidence_acquisition.py \
  02_Executable_Artifact/tests/test_public_acquisition_cli.py \
  02_Executable_Artifact/PUBLIC_ACQUISITION_RUNBOOK.md \
  02_Executable_Artifact/README.md 02_Executable_Artifact/verify_stage2.py
git commit -m "feat: add resumable public acquisition workflow"
```

---

### Task 6: Execute the authorized public pilot and 417-case crawl

**Files:**
- Create: revisioned evidence artifacts under `02_Executable_Artifact/raw/public_acquisition/`
- Create: revisioned derived artifacts under `02_Executable_Artifact/processed/public_acquisition/`
- Create: revisioned validation artifacts under `02_Executable_Artifact/reports/public_acquisition/`
- Create: `03_Research_Reports/Public_Evidence_Acquisition_2026-08-08.md`
- Modify: `07_Provenance/RELEASE_MANIFEST.md`

**Interfaces:**
- Consumes: the reviewed CLI from Task 5 and all public-source authority in the approved specification.
- Produces: one immutable live revision with raw inventories, 417-case attempt ledger, fixed 10-case pilot results, denominator proof or exact shortfall, reviewer packets, counter projection, validation report, and research report.

- [ ] **Step 1: Run offline planning and freeze the manifests**

```bash
cd 02_Executable_Artifact
uv run python run_public_evidence_acquisition.py plan
uv run python verify_public_evidence_acquisition.py --latest
```

Expected: 417 queued cases, pilot allocation 3/3/2/2, structure valid, scientific counters still fail-closed.

- [ ] **Step 2: Capture public inventories**

```bash
uv run python run_public_evidence_acquisition.py inventory --execute \
  --max-pages 200 --max-bytes 2147483648 --deadline-seconds 3600
```

Expected: hashed Chainlist, AWS, and Sourcify inventories or explicit bounded failure artifacts.

- [ ] **Step 3: Start the immediate bounded 417-case crawl**

```bash
uv run python run_public_evidence_acquisition.py rpc --execute \
  --max-cases 417 --deadline-seconds 21600
```

Expected: every case has at least a queued event and, within the deadline/provider limits, an attempted, partial, unavailable, disputed, or verified terminal observation. Rate limits and missing history remain distinct; the command exits cleanly after checkpointing even when scientific closure is incomplete.

- [ ] **Step 4: Attempt the 20,000-deployment denominator**

```bash
uv run python run_public_evidence_acquisition.py denominator --execute \
  --target-per-chain 5000 --max-bytes 10737418240 --deadline-seconds 21600
```

Expected: exactly 5,000 verified rows per chain or an immutable per-chain shortfall report. No reallocation.

- [ ] **Step 5: Generate candidates, reviewer packets, counters, and verification**

```bash
uv run python run_public_evidence_acquisition.py controls
uv run python run_public_evidence_acquisition.py review-packets
uv run python run_public_evidence_acquisition.py project
uv run python verify_public_evidence_acquisition.py --latest
```

Expected: candidate and packet counts are separate from qualified/adjudicated counters; integrity validation succeeds; scientific incompleteness is reported without failure inflation.

- [ ] **Step 6: Run the complete regression and canonical checker set**

```bash
uv run pytest -q
uv run python verify_stage2.py
uv run python independent_regenerate.py
uv run python production_qualification.py; test $? -eq 3
```

Expected: pytest and structural verifiers pass; production qualification remains exit 3 unless all genuine evidence gates have closed.

- [ ] **Step 7: Write the live research report from generated artifacts**

The report must contain exact attempted/verified counts, per-chain provider capability, failure classes, denominator rows and shortfalls, control candidates versus qualified controls, prepared versus finalized reviews, R5/release status, source inventories, commands, hashes, elapsed time, data volume, limitations, and next external dependencies. It must never infer a positive counter from an attempt.

- [ ] **Step 8: Commit the evidence revision and report**

```bash
git add 02_Executable_Artifact/raw/public_acquisition \
  02_Executable_Artifact/processed/public_acquisition \
  02_Executable_Artifact/reports/public_acquisition \
  03_Research_Reports/Public_Evidence_Acquisition_*.md \
  07_Provenance/RELEASE_MANIFEST.md
git commit -m "data: preserve public acquisition pilot and full crawl"
```

---

### Task 7: Whole-system hardening and final verification

**Files:**
- Modify only files identified by the final review findings.
- Create: `06_QA_Reproducibility/public_acquisition_final_verification.json`
- Create: `06_QA_Reproducibility/public_acquisition_final_verification.md`

**Interfaces:**
- Consumes: complete implementation and live evidence revision.
- Produces: final fresh verification record and corrected package; does not alter scientific counters except through repaired deterministic derivation from unchanged evidence.

- [ ] **Step 1: Run full fresh tests and artifact verification**

```bash
cd 02_Executable_Artifact
uv sync --locked
uv run pytest -q
uv run python verify_stage2.py
uv run python verify_public_evidence_acquisition.py --latest
uv run python independent_regenerate.py
```

Record commands, exit codes, test counts, stdout/stderr hashes, tool versions, and the worktree commit.

- [ ] **Step 2: Verify requirements line by line**

Check the approved design sections against generated artifacts: source inventories, two-lane queue, bounded retries, strict historical evidence, denominator, controls, review packets, counter projection, state model, security, recovery, provenance, acceptance criteria, and no phase promotion. Record every unmet item as a limitation or review finding.

- [ ] **Step 3: Commit final QA artifacts**

```bash
git add 06_QA_Reproducibility/public_acquisition_final_verification.json \
  06_QA_Reproducibility/public_acquisition_final_verification.md
git commit -m "test: record public acquisition final verification"
```
