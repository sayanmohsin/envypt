# Usage

## Install

```bash
cargo install open-envault              # Rust binary `open-envault`
npm i -D open-envault     # Node wrapper (prebuilds/<platform>-<arch>/open-envault)
```

## Project setup

```bash
open-envault init
open-envault env create dev
open-envault key generate dev            # prints # public key: age1...
# add the printed age1... to open-envault.yaml recipients
open-envault set dev DATABASE_URL        # paste value on stdin
open-envault check dev
cat secrets/dev.env.enc            # ciphertext — safe to commit
```

`open-envault exec` is the runtime entrypoint:

```bash
open-envault exec dev -- cargo run
open-envault exec dev -- node server.js
open-envault exec prod -- ./target/release/app
```

It decrypts `secrets/<env>.env.enc` with an age identity from `~/.config/open-envault/keys/<env>.txt` (or `ENVYPT_AGE_KEY` / `SOPS_AGE_KEY` in CI), parses dotenv, merges with the parent env, and spawns the child with inherited stdio/signals.

## CI (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- run: cargo install open-envault
- env:
    SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
  run: open-envault exec prod -- cargo run
```

Or via npm wrapper: `npx open-envault exec prod -- npm start`.

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

`open-envault check` validates types and `open-envault example` regenerates `.env.example`.

## Rust

```rust
let env = open-envault::load_environment("dev")?;
```

## TypeScript

```ts
import { check, exec } from "open-envault";
await exec("dev", "node", ["server.js"]);
```
