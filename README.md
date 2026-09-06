# envypt

[![crates.io](https://img.shields.io/crates/v/envypt.svg)](https://crates.io/crates/envypt)
[![npm](https://img.shields.io/npm/v/@sayanmohsin/envypt.svg)](https://www.npmjs.com/package/@sayanmohsin/envypt)
[![CI](https://github.com/sayanmohsin/envypt/actions/workflows/validate.yml/badge.svg)](https://github.com/sayanmohsin/envypt/actions/workflows/validate.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

**Local-first, SOPS-compatible encrypted dotenv.** Ciphertext lives in Git; private age keys stay on your machines; secrets are injected into child processes only at runtime — no plaintext `.env` files, no hosted service, no custom crypto.

Works with Rust (Arqen), TypeScript/NestJS, and any language that can spawn a child process. Encrypted files are plain [SOPS](https://getsops.io) age files, so official `sops` can decrypt them and `envypt` can decrypt files produced by `sops`.

## Features

- **One binary, one format** — native Rust, no `sops`/`rage` required at runtime, yet byte-compatible with `sops` 3.13 age
- **Git-native** — `envypt.yaml`, `config/env.schema.yaml`, `secrets/*.env.enc` and `public age recipients` go in Git; private keys never do
- **Fail-closed** — bad config/schema/key/ciphertext → non-zero exit, redacted diagnostics
- **Memory-only secrets** — data keys and values are zeroized, never logged or written to disk (atomic writes, 0600 key files)
- **Schema & diagnostics** — `string`/`integer`/`boolean`/`url`/`enum`/`duration` + `required`/`secret`/`env` guards, human + stable JSON output
- **Runtime injection** — `envypt exec dev -- <cmd>` merges decrypted values into the child’s env and preserves exit codes/signals

## Install

```bash
# Rust (binary + library)
cargo install envypt-cli          # bin `envypt`
# or library for Arqen:
# cargo add envypt

# Node (binary shim + TypeScript API, wraps the Rust binary)
npm i -D @sayanmohsin/envypt
# or pnpm / yarn / bun
```

Prebuilt binaries are attached to each [GitHub Release](https://github.com/sayanmohsin/envypt/releases) (`envypt-<target>` + `checksums.txt`).

## Quick start

```bash
envypt init                       # creates envypt.yaml, config/env.schema.yaml, secrets/, .sops.yaml
envypt env create dev
envypt key generate dev           # → prints # public key: age1...  (add it to envypt.yaml recipients)
# edit envypt.yaml: recipients: [age1...]
envypt set dev DATABASE_URL       # value read from stdin (never argv)
envypt check dev --format json
envypt exec dev -- npm start
```

`envypt.yaml` example:

```yaml
project: my-app
environments:
  dev:
    file: secrets/dev.env.enc
    schema: config/env.schema.yaml
    recipients: [age1ql0...]
```

## CLI

```
envypt init
envypt env create <env>
envypt key generate <env>
envypt set <env> <VAR>            # reads value from stdin
envypt edit <env>                 # $EDITOR on a secure temp file
envypt check <env> [--format human|json]
envypt doctor [--format json]
envypt diff <envA> <envB> [--format json]
envypt rotate <env>
envypt exec <env> -- <cmd> [args...]
envypt example                    # regenerate .env.example from schema
```

`set` never takes a value on the command line; `exec` forwards signals and preserves the child’s exit code; diagnostics never print secret values (one-way `HMAC-SHA256` fingerprints only).

## Configuration

```
envypt.yaml
config/env.schema.yaml
secrets/dev.env.enc
secrets/prod.env.enc
.env.example
```

Key sources (first match wins): `ENVYPT_AGE_KEY` / `SOPS_AGE_KEY` env var → `ENVYPT_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE` → `~/.config/envypt/keys/<env>.txt` (0600). CI: set `SOPS_AGE_KEY` as a GitHub Actions secret.

## TypeScript / NestJS

```ts
import { exec, check } from "@sayanmohsin/envypt";

await exec("dev", "node", ["server.js"]);
const { findings } = await check("dev");
```

The npm package is a thin wrapper — it locates the prebuilt `envypt` binary in `prebuilds/<platform>-<arch>/` and spawns it; no crypto is reimplemented in JS.

## Rust / Arqen

```toml
[dependencies]
envypt = "0.1"
```

```rust
let env = envypt::load_environment("dev")?; // BTreeMap<String,String>, memory-only
```

## Security

See [`docs/architecture.md`](docs/architecture.md) and [`docs/contract.md`](docs/contract.md). Plaintext secrets, decrypted `.env` files, and private age keys must never be committed (`.gitignore` covers `.env*`, `*.key`, `target/`). Test fixtures under `crates/envypt/tests/fixtures/` are throwaway and only decrypt fake data.

## Docs

- [Architecture](docs/architecture.md) — principles, crate map, storage format, key sources
- [Contract](docs/contract.md) — exit codes and stable JSON envelopes for wrappers

## License

Dual-licensed under Apache 2.0 or MIT, at your option.
