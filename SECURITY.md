# Security policy

## Reporting a vulnerability

If you discover a security issue in zsc, please do not open a public GitHub
issue. Use one of these private channels instead:

1. GitHub's private "Report a vulnerability" flow under the Security tab of
   this repository (preferred).
2. Email: clear.cmos@outlook.com.

A response, even just an acknowledgement, will follow within a reasonable
time. Coordinated disclosure is appreciated.

## Scope

In scope:

- Cryptographic flaws in the on-disk format or its use of XChaCha20-Poly1305,
  Argon2id, or the chunk authentication scheme.
- Key derivation issues, nonce handling, header authentication.
- Memory hygiene issues affecting the passphrase or derived key.
- Issues in the seal/open/explore subprocess pipeline that could lead to data
  loss, file overwrite, or path traversal.

Out of scope:

- Issues that require local code execution as the user already running zsc.
- Resource exhaustion through legitimately huge but well-formed inputs.
- Theoretical concerns about external `tar` or `zstd` binaries; those are
  trusted system tools.

## Threat model

zsc protects archive contents at rest. It assumes:

- The passphrase is strong and the user's machine is not compromised.
- Anyone who can read the archive cannot also observe the user's
  passphrase entry.
- The system's `tar`, `zstd`, and `xdg-open` binaries are not adversarial.

zsc does not aim to:

- Hide the existence of an archive (no plausible deniability).
- Resist a compromised endpoint (no anti-forensics beyond best-effort
  zeroization of the passphrase and key buffer).
- Provide forward secrecy, since it is a file format, not a session.
