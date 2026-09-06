# openenvcrypt

Local-first encrypted environment files for Rust projects and deployment
servers. Ciphertext belongs in Git; private keys stay on authorized machines,
and secrets are injected into child processes only at runtime.

Encryption is native, SOPS-compatible age: no external `sops`/`rage` binaries
are required, no custom encryption format is introduced, and encrypted files
interchange cleanly with official SOPS tooling.

## Status

Phase 1 + native crypto: workspace foundation, CLI surface, and a byte-for-byte
SOPS-compatible dotenv store over age recipients (verified against official
`sops`). Schema validation, diagnostics, runtime injection, and key rotation
are still being built out.

## Usage (work in progress)

```text
openenvcrypt init
openenvcrypt env create dev
openenvcrypt key generate dev
openenvcrypt set dev SECRET_TOKEN     # value read from stdin
openenvcrypt check dev
openenvcrypt exec dev -- npm start
```

## Security

- Encrypted profiles and public recipients belong in Git.
- Private age keys never do; they live per machine (mode 0600) or in
  `OPENENCRYPT_AGE_KEY` / `SOPS_AGE_KEY` in CI.
- Secrets exist only in process memory and are never printed or logged.

## License

Licensed under either Apache License 2.0 or MIT, at your option.

