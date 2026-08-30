# Stage 2 control historical-source acquisition: accountable authority kit

This kit prepares the exact approval payload for the frozen 43-object historical-source plan. It creates no signature, performs no download or RPC call, authorizes no selection, and does not modify Recovery3.

## Frozen request

- Purpose: `HISTORICAL_DENOMINATOR_EXPANSION_ONLY`
- Request schema: `chronosaudit.control_source_acquisition_approval_request.v2`
- Internal request SHA-256: `0cccdc430c3ba18127bbca13ba17ed6dd42e95a3fbbc50e0bb06da8ed005e38e`
- Query-plan SHA-256: `b976ca8ad83eaf4fa114a5b630b435b140c776562f5f5453d0f1212917a581cf`
- Objects: 43
- Maximum bytes: 5,024,970,903
- Deficient cases: 380 across 16 non-overlapping chunk scopes
- Exact pre-covariate shortfall addressed by the plan: 3,490 distinct slots

The accountable owner must select a canonical UTC start and expiry window and use the reviewed principal bound in the allowed-signers registry. The window must be long enough for the explicitly approved source acquisition but should not be broader than operationally necessary.

## Build the unsigned approval and canonical signing payload

Run from `02_Executable_Artifact`:

```bash
./.venv/bin/python build_stage2_control_acquisition_approval.py \
  --chunk-plan processed/stage2_controls/2026-08-17/expansion-chunks/control_denominator_expansion_chunk_plan.csv \
  --chunk-manifest reports/stage2_controls/2026-08-17/expansion-chunks/control_denominator_expansion_chunk_plan_manifest.json \
  --query-plan reports/stage2_controls/2026-08-17/expansion-chunks/control_historical_expansion_query_plan.json \
  --signer-principal '<accountable-principal>' \
  --approval-start-utc '<canonical-UTC-start>' \
  --approval-expires-utc '<canonical-UTC-expiry>' \
  --output-approval '<control-source-acquisition-approval.json>' \
  --output-signing-payload '<control-source-acquisition-signing-payload.json>'
```

The builder independently verifies the frozen query plan and chunk manifest before constructing the approval. The unsigned payload contains `acquisition_authorized: true` because that is the narrowly requested authority, but it has no effective authority until the exact canonical payload receives a valid accountable signature and the verifier accepts it. RPC, selection, stage promotion, and Recovery3 mutation are always false.

## Sign outside Codex with the accountable key

```bash
ssh-keygen -Y sign \
  -f '<accountable-private-key>' \
  -n chronosaudit-stage2-control-source-acquisition-v2 \
  '<control-source-acquisition-signing-payload.json>'
```

The allowed-signers entry and the real-world identity behind the key must be reviewed out of band. Key possession alone is not accountable identity proof.

## Verify the signed approval

```bash
./.venv/bin/python verify_stage2_control_acquisition_approval.py \
  --chunk-plan processed/stage2_controls/2026-08-17/expansion-chunks/control_denominator_expansion_chunk_plan.csv \
  --chunk-manifest reports/stage2_controls/2026-08-17/expansion-chunks/control_denominator_expansion_chunk_plan_manifest.json \
  --query-plan reports/stage2_controls/2026-08-17/expansion-chunks/control_historical_expansion_query_plan.json \
  --approval '<control-source-acquisition-approval.json>' \
  --signature '<control-source-acquisition-signing-payload.json.sig>' \
  --allowed-signers '<reviewed-allowed-signers-file>' \
  --expected-principal '<accountable-principal>' \
  --verification-time-utc '<canonical-UTC-verification-time>' \
  --output-report '<control-source-acquisition-approval-verification.json>'
```

A successful verification permits only the 43 exact source objects, the 5,024,970,903-byte ceiling, the frozen chains and chunk scopes, and mandatory raw receipts plus the accepted-import no-repeat ledger. It does not authorize deployment-verification RPC or candidate selection.

## After verification

1. Reconfirm that the approval is within its validity window.
2. Download only the 43 exact objects and preserve response-header receipts and object hashes.
3. Run the historical-source import verifier.
4. Build and independently verify the globally no-reuse reserve queue.
5. Stop again: a separate queue-hash-bound RPC activation is required before any RPC evidence collection.
