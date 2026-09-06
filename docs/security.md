# Security

## What goes in Git

- `open-envault.yaml`, `config/env.schema.yaml`, `.env.example`
- `secrets/*.env.enc` (SOPS age ciphertext)
- Public age recipients (`age1...`)

## What never goes in Git

- Private age keys (`AGE-SECRET-KEY-...`), decrypted `.env` files, or build artifacts containing secrets.
- `.gitignore` covers `.env`, `.env.*`, `*.key`, `*.pem`, `target/`, `.DS_Store`.

## Key handling

- Keys are `age` x25519 (`age-keygen`). Files are `0600`, outside the repo: `~/.config/open-envault/keys/<env>.txt` or `XDG_CONFIG_HOME`.
- CI uses `ENVYPT_AGE_KEY` / `SOPS_AGE_KEY` (private key text) or `*_KEY_FILE`.
- Separate recipients per environment (`dev`, `prod`, `ci`).

## Runtime

- `open-envault exec` decrypts SOPS age files with `age` + `AES-256-GCM` (32-byte nonce), verifies the `sops_mac` (`HMAC-SHA512` over the plaintext tree), and injects values only into the child’s environment (`execve`).
- Plaintext and data keys live only in memory and are zeroized; encrypted writes are atomic (`tmp` + `rename`).
- Diagnostics (`check`/`doctor`/`diff`) are redacted and use one-way `HMAC-SHA256` fingerprints for `diff`.

## Threat model

- An attacker with Git read access sees only ciphertext and public recipients.
- Compromise requires a private key or a running process’s memory.
- `sops` compatibility means any `sops`-aware tooling can audit the files, but `open-envault` never shells out to `sops` at runtime.

## Reporting

Open a GitHub issue for security questions; do not post private keys or decrypted values.
