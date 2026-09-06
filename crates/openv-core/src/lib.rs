use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub project: String,
    pub environments: BTreeMap<String, Environment>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub file: String,
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub editor: Option<String>,
}
fn default_schema() -> String {
    "config/env.schema.yaml".into()
}
pub fn discover(start: &Path) -> anyhow::Result<PathBuf> {
    let mut current = start.canonicalize()?;
    loop {
        let candidate = current.join("openv.yaml");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !current.pop() {
            bail!("openv.yaml not found")
        }
    }
}
pub fn load(path: &Path) -> anyhow::Result<Project> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_str(&text).context("parse openv.yaml")
}
pub fn environment<'a>(project: &'a Project, name: &str) -> anyhow::Result<&'a Environment> {
    project
        .environments
        .get(name)
        .with_context(|| format!("unknown environment: {name}"))
}
pub fn atomic_write(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(tmp, path)?;
    Ok(())
}
