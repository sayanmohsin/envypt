# openenvcrypt

Local-first encrypted environment files for Rust projects and deployment
servers. Ciphertext belongs in Git; private keys stay on authorized machines,
and secrets are injected into child processes only at runtime.

The project is being built around SOPS-compatible age encryption. The initial
release will use installed `sops` and `rage` binaries and will not introduce a
custom encryption format.

## Status

Phase 1 foundation: CLI surface and workspace scaffold. Encryption, schema
validation, runtime injection, and diagnostics are not implemented yet.

## License

Licensed under either Apache License 2.0 or MIT, at your option.

