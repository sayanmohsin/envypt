use serde::Serialize;

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
