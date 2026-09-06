use crate::output::Finding;
use anyhow::{Context, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct Schema {
    pub variables: BTreeMap<String, Variable>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Variable {
    #[serde(rename = "type", default = "default_type")]
    pub kind: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_secret")]
    pub secret: bool,
    #[serde(default)]
    pub environments: Vec<String>,
}
fn default_type() -> String {
    "string".into()
}
fn default_secret() -> bool {
    true
}

pub fn load(path: &Path) -> anyhow::Result<Schema> {
    let text =
        fs::read_to_string(path).with_context(|| format!("read schema {}", path.display()))?;
    let schema: Schema = serde_yaml::from_str(&text).context("parse schema YAML")?;
    if schema.variables.is_empty() {
        bail!("schema contains no variables")
    }
    Ok(schema)
}

pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            ))
        })
        .collect()
}

pub fn validate(
    schema: &Schema,
    values: &BTreeMap<String, String>,
    environment: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, rule) in &schema.variables {
        if !rule.environments.is_empty() && !rule.environments.iter().any(|e| e == environment) {
            continue;
        }
        let Some(value) = values.get(name) else {
            if rule.required && rule.default.is_none() {
                findings.push(Finding {
                    variable: name.clone(),
                    kind: "missing".into(),
                    message: "required variable is missing".into(),
                });
            }
            continue;
        };
        let valid = match rule.kind.as_str() {
            "integer" => value.parse::<i64>().is_ok(),
            "boolean" => matches!(value.as_str(), "true" | "false"),
            "url" => value.starts_with("http://") || value.starts_with("https://"),
            "enum" => rule.values.iter().any(|v| v == value),
            "duration" => {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 's' | 'm' | 'h' | 'd'))
            }
            "string" => true,
            _ => false,
        };
        if !valid {
            findings.push(Finding {
                variable: name.clone(),
                kind: "invalid".into(),
                message: format!("invalid {} value", rule.kind),
            });
        }
    }
    findings
}

pub fn example(schema: &Schema) -> String {
    schema
        .variables
        .iter()
        .map(|(name, rule)| {
            let description = rule.description.as_deref().unwrap_or("value");
            let value = if rule.secret {
                ""
            } else {
                rule.default.as_deref().unwrap_or("")
            };
            format!("# {description}\n{name}={value}\n")
        })
        .collect()
}
