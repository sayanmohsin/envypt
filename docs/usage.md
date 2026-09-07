# Usage

## Install

```bash
cargo install open-envault              # Rust binary `oenv` (package `open-envault`)
npm i -D open-envault     # Node wrapper (prebuilds/<platform>-<arch>/oenv)
```

## Project setup

```bash
oenv init
oenv env create dev
oenv key generate dev            # prints # public key: age1...
# add the printed age1... to open-envault.yaml recipients
oenv set dev DATABASE_URL        # paste value on stdin
oenv check dev
cat secrets/dev.env.enc            # ciphertext — safe to commit
oenv doctor --format json          # verify profiles, schemas, keys, and decryption
```

`oenv exec` is the runtime entrypoint:

```bash
oenv exec dev -- cargo run
oenv exec dev -- node server.js
oenv exec prod -- ./target/release/app
```

It decrypts `secrets/<env>.env.enc` with an age identity from `~/.config/open-envault/keys/<env>.txt` (or `ENVYPT_AGE_KEY` / `SOPS_AGE_KEY` in CI), parses dotenv, merges with the parent env, and spawns the child with inherited stdio/signals.

For a gradual migration, an existing injector can remain in the parent
environment while selected open-envault values take precedence:

```bash
doppler run -- oenv exec dev --force -- npm start
```

Bulk imports are stdin-only and do not create plaintext files:

```bash
doppler secrets download --no-file --format=json |
  oenv import dev --format json --merge
```

Compare two profiles without printing values. Set the same private pepper for
all environments in the project:

```bash
OPENENVAULT_DIFF_PEPPER="$MIGRATION_PEPPER" oenv diff dev prd --format json
oenv rotate prd
```

## CI (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- run: cargo install open-envault
- env:
    SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
  run: oenv exec prod -- cargo run
```

Or via npm wrapper: `npx oenv exec prod -- npm start`.

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

`open-envault check` validates required, extra, and typed variables. `oenv doctor`
checks every configured profile, schema, recipient list, and decryption path.
`oenv example` regenerates `.env.example`.

## Rust

```rust
let env = open_envault::load_environment("dev")?;
```

## TypeScript

```ts
import { check, exec } from "open-envault";
await exec("dev", "node", ["server.js"]);
```
