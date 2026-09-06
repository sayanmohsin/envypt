# AGENTS.md

Guidance for AI agents and contributors working in this repository.

## Commands

```bash
cargo fmt --all -- --check   # formatting must stay clean
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

CI mirrors the `full` job in `.github/workflows/validate.yml`. The npm/Go
wrapper workflows are added when the release milestone lands.

## Workspace layout

Rust workspace, edition 2024, `rust-version = 1.96`. Single crate `open-envault` at `crates/open-envault`:

- `open-envault` crate — library (`open-envault::load_environment`) + binary `open-envault` (`src/main.rs`), consumed by Arqen and CLI
- Internal modules: `core` (project config, discovery, key-source resolution, atomic IO), `crypto` (SOPS-compatible age encryption), `schema` (validation, dotenv parse/write, `.env.example`), `runtime` (child process exec, env merging, signals), `output` (redaction, fingerprinting, JSON envelopes)

Crate responsibilities and naming must not drift: cryptography, schema and
runtime logic live only in the Rust core. Thin wrappers (npm, Go) invoke the
CLI; they never reimplement crypto.

## Security rules (non-negotiable)

- Never commit plaintext secrets, decrypted `.env` files, or private age keys.
  `.gitignore` already excludes `.env*`, `*.key`, `/target/`.
- Never accept secret values from command-line arguments; read them from stdin.
- Never print decrypted values by default; diagnostics stay redacted.
- Secret values and data keys exist only in process memory and are zeroized.
- Encrypted writes must be atomic (temp file + rename) and key files must be
  mode 0600. Fail closed on invalid config, schema, key, or ciphertext.
- When a `.env.example`/docs change is made, keep it in sync with the schema.
- Test fixtures under `crates/*/tests/fixtures/` (plaintext sample `.env`
  files and `age-identity-*.txt` keys) are throwaway and decrypt only fake
  fixture data. They are never used with real secrets; keep other key material
  out of the tree.

## Crypto

`open-envault::crypto` implements the SOPS dotenv format natively (age
recipients + AES-256-GCM `ENC[...]` values + flattened `sops_*` metadata). No
external `sops`/`rage` binaries are required at runtime. Byte compatibility is
guarded by golden fixtures produced with official `sops` plus an optional
cross-tool test: set `SOPS_BIN` to a real `sops` binary to enable it.

## Conventions

- Add comments sparingly; prefer clear names.
- Errors: `anyhow` with `Context` describing the failing operation. Never put
  secret values into error strings.
- `check`/`doctor`/`diff` expose stable human and JSON output; JSON structure
  and exit codes are a public contract (`docs/contract.md`) — change is breaking.
- Deterministic ordering (BTreeMap) wherever order is observable.

## Version parity

Version lives in `[workspace.package]` in the root `Cargo.toml`; all crates
inherit it via `version.workspace = true`. When the npm release milestone is
added, the npm `package.json` version must match the workspace version (see
`release-please-config.json` extra-files) and a parity check runs in CI.

## Nice Code

Use the project's `DESIGN.md` for product-specific UI decisions. Run `nice-code advise --project .` when adding a new surface and `nice-code --changed --project .` before handoff. Full scan: `nice-code --all --project .`.
