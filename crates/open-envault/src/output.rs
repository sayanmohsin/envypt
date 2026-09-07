use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn redact(value: &str) -> String {
    if value.is_empty() {
        "<empty>".into()
    } else {
        "<redacted>".into()
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub variable: String,
    pub kind: String,
    pub message: String,
}

pub fn json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

pub fn fingerprint(pepper: &str, value: &str) -> String {
    let mut key = [0u8; 64];
    let pepper = pepper.as_bytes();
    if pepper.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(pepper));
    } else {
        key[..pepper.len()].copy_from_slice(pepper);
    }
    let mut inner = Sha256::new();
    for byte in key {
        inner.update([byte ^ 0x36]);
    }
    inner.update(value.as_bytes());
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    for byte in key {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner);
    hex::encode(&outer.finalize()[..12])
}

#[derive(Debug, Serialize)]
pub struct CheckEnvelope<T: Serialize> {
    pub ok: bool,
    pub exit: u8,
    pub findings: T,
}

#[derive(Debug, Serialize)]
pub struct DiffEnvelope<T: Serialize> {
    pub ok: bool,
    pub exit: u8,
    pub variables: T,
}
