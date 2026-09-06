# Usage

## Install

```bash
cargo install envypt              # Rust binary `envypt`
npm i -D @sayanmohsin/envypt     # Node wrapper (prebuilds/<platform>-<arch>/envypt)
```

## Project setup

```bash
envypt init
envypt env create dev
envypt key generate dev            # prints # public key: age1...
# add the printed age1... to envypt.yaml recipients
envypt set dev DATABASE_URL        # paste value on stdin
envypt check dev
cat secrets/dev.env.enc            # ciphertext — safe to commit
```

`envypt exec` is the runtime entrypoint:

```bash
envypt exec dev -- cargo run
envypt exec dev -- node server.js
envypt exec prod -- ./target/release/app
```

It decrypts `secrets/<env>.env.enc` with an age identity from `~/.config/envypt/keys/<env>.txt` (or `ENVYPT_AGE_KEY` / `SOPS_AGE_KEY` in CI), parses dotenv, merges with the parent env, and spawns the child with inherited stdio/signals.

## CI (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- run: cargo install envypt
- env:
    SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
  run: envypt exec prod -- cargo run
```

Or via npm wrapper: `npx @sayanmohsin/envypt exec prod -- npm start`.

## Schema

`config/env.schema.yaml`:

```yaml
variables:
  DATABASE_URL:
    type: url
    required: true
    secret: true
  LOG_LEVEL:
    type: enum
    values: [debug, info, warn, error]
    default: info
```

`envypt check` validates types and `envypt example` regenerates `.env.example`.

## Rust

```rust
let env = envypt::load_environment("dev")?;
```

## TypeScript

```ts
import { check, exec } from "@sayanmohsin/envypt";
await exec("dev", "node", ["server.js"]);
```
