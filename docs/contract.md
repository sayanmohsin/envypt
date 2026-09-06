# openv contract

This file is the stable, machine-readable contract for `check`, `doctor`, and
`diff`, plus the CLI exit-code scheme. Anything here is public and shared by
wrappers (npm, Go); changing it is breaking and must go through a major version
bump. Secret values never appear in any output described here.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; `check`/`diff` found no findings. |
| 2 | Usage error (unknown flag/command/environment argument shape). |
| 3 | Configuration, key, or decryption failure (invalid config/schema file, missing or wrong key, bad ciphertext, MAC mismatch). Fail-closed. |
| 4 | `check`/`doctor`/`diff` completed but reported findings. |
| 126 | Requested child program could not be found/executed. |
| 127 | Child command line missing (`exec` invoked without a command after `--`). |
| N | `exec`: child process exit code forwarded verbatim. |
| 128+S | `exec`: child terminated by signal S (Unix). |

Other values must not be relied on. Wrappers treat any nonzero exit as failure
and any code outside this table as an internal error.

## JSON envelopes

`check`, `doctor`, and `diff` accept `--format json`. Each emits one JSON
document on stdout:

```jsonc
{
  "ok": true,               // false when exit != 0
  "exit": 0,                // the exit code this run maps to
  "environments": {         // doctor only: per-environment status
    "dev": { "file": "secrets/dev.env.enc", "key": "present", "decrypt": "ok" }
  },
  "variables": {            // diff only: per-variable status
    "API_KEY": { "status": "changed", "fingerprint": "3f0ab9c4e11d" }
  },
  "findings": [             // check/diff: validation + drift findings
    { "variable": "LOG_LEVEL", "kind": "invalid", "message": "invalid enum value" }
  ]
}
```

Field semantics:

- `ok`/`exit` mirror the process exit status.
- `findings[].kind` is one of `missing`, `added`, `removed`, `invalid`,
  `type`, `config`, `key`, `schema`, `decrypt`. `message` never embeds a
  secret value.
- Fingerprints are `HMAC-SHA256(pepper, value)` truncated to 12 bytes hex.
  They are one-way and only comparable within the same project (same pepper).

## Human output

Human mode prints redacted lines such as:

```text
check dev: 2 findings
  DATABASE_URL: invalid url value
  SMTP_PASSWORD: missing required variable
```

Values and keys are never printed. `secret: true` variables additionally have
their value suppressed from error detail.

## CLI summary

```text
openv init
openv env create <env>
openv key generate <env>
openv edit <env>
openv set <env> <VAR>          # value read from stdin, never argv
openv check <env> [--format human|json]
openv example
openv exec <env> -- <cmd>...    # preserves child exit/signals
openv doctor [--format json]
openv diff <envA> <envB> [--format human|json]
openv rotate <env>
```

## Stable CLI guarantees

- Secret values are never accepted as command-line arguments (`set` reads from
  stdin; everything else reads from key sources or files).
- Decrypted values are never printed by default.
- `exec` preserves child exit codes and forwards signals; no plaintext `.env`
  is required or left behind.
- Invalid configuration, schema, key, or ciphertext always fails closed with
  code 3 and a redacted diagnostic on stderr.
