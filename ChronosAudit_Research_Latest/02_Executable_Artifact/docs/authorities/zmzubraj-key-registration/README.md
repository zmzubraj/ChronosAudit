# `zmzubraj` ChronosAudit key-registration package

Status: `AWAITING_OFFLINE_KEY_GENERATION_AND_PUBLIC_REGISTRATION`  
Prepared: 2026-08-20  
Private-key boundary: no private key is contained in this package and Codex must not generate, read, copy, or store it.

## Purpose

This package prepares principal `zmzubraj` for accountable OpenSSH signatures. It does not establish real-world identity by itself, approve a scientific decision, authorize network access, or change a counter.

## Package contents

- `registration_request.json`: frozen principal, purpose, namespaces, and key-handling restrictions.
- `identity_binding.template.json`: out-of-band identity and public-key fingerprint record to complete after key generation.
- `allowed_signers.template`: OpenSSH allowed-signers entry to complete with the public key only.

## Generate the key outside Codex

Run the following yourself in a terminal that Codex cannot access. Replace both bracketed paths with a private location outside the repository and outside Codex-managed directories:

```bash
/usr/bin/ssh-keygen -t ed25519 -a 100 \
  -C 'ChronosAudit accountable author principal zmzubraj' \
  -f '[private-location]/chronosaudit-zmzubraj-ed25519'
```

Use a strong passphrase. Do not paste the private key or passphrase into chat. Do not place the private key under the ChronosAudit repository, `~/.codex`, a shared folder, or a cloud-synchronized workspace.

The public key is the sibling file ending in `.pub`. Only that public file may be supplied for registration.

## Review the public fingerprint

Run this outside Codex and retain the displayed SHA256 fingerprint in your identity record:

```bash
/usr/bin/ssh-keygen -lf '[private-location]/chronosaudit-zmzubraj-ed25519.pub' -E sha256
```

Compare the fingerprint through an out-of-band channel before accepting any allowed-signers update. Key possession alone does not prove that the signer is the real-world accountable author.

## Complete the public registration files

1. Copy `identity_binding.template.json` to a new reviewed registration artifact.
2. Replace its bracketed public values; do not add the private-key path or passphrase.
3. Copy `allowed_signers.template` to a reviewed allowed-signers file and replace `[PUBLIC_KEY_TYPE_AND_BASE64]` with the exact contents of the `.pub` file excluding its trailing comment.
4. Verify permissions and inspect the files before use.
5. Bind the registration artifact and allowed-signers file by SHA-256 in the author-approval request.

The minimal allowed-signers syntax is:

```text
zmzubraj ssh-ed25519 AAAA...
```

## Approved signature namespaces

The request lists the current namespaces needed by the Stage 2 gate chain. A verifier still checks the exact payload, principal, validity window, hashes, and authority flags. Namespace registration never grants blanket approval.

## Signing workflow

Codex may generate a canonical public signing payload inside the repository. Move or copy that payload to your offline signing environment, inspect it, and sign it yourself:

```bash
/usr/bin/ssh-keygen -Y sign \
  -f '[private-location]/chronosaudit-zmzubraj-ed25519' \
  -n '[exact-approved-namespace]' \
  '[canonical-signing-payload.json]'
```

Return only the `.sig` file. Before verification, confirm the signature namespace, payload SHA-256, author principal, and payload authority flags.

## Revocation and rotation

Remove or expire the public allowed-signers entry to revoke the key. A replacement key requires a new registration artifact, fingerprint, public-key hash, allowed-signers hash, and affected approval signatures. Never overwrite the old registration history.

