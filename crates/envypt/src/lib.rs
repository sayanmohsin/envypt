//! Public API for envypt.
//!
//! ```no_run
//! if let Ok(values) = envypt::load_environment("dev") {
//!     for key in values.keys() {
//!         println!("resolved {key}");
//!     }
//! }
//! ```

pub mod core;
pub mod crypto;
pub mod output;
pub mod runtime;
pub mod schema;

use anyhow::Context;
use std::collections::BTreeMap;

/// Discover the project rooted at the current directory, resolve `name`, and
/// decrypt + parse that environment profile into an in-memory map.
pub fn load_environment(name: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let path = core::discover(&std::env::current_dir()?)?;
    let project = core::load(&path)?;
    let profile = core::environment(&project, name)?;
    let root = path.parent().unwrap_or(&path);
    let plaintext = crypto::decrypt_for(&root.join(&profile.file), Some(name))
        .with_context(|| format!("decrypt environment {name}"))?;
    Ok(schema::parse_env(&plaintext))
}
