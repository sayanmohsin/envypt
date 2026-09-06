//! Public API for envypt.
//!
//! Consumers (e.g. the Arqen framework) depend on this facade crate rather
//! than on the internal `envypt-core`/`-crypto` crates. Values returned
//! here exist only in process memory; never log or persist them.
//!
//! ```no_run
//! if let Ok(values) = envypt::load_environment("dev") {
//!     for key in values.keys() {
//!         println!("resolved {key}");
//!     }
//! }
//! ```

use anyhow::Context;
use std::collections::BTreeMap;

pub use envypt_core as core;
pub use envypt_crypto as crypto;
pub use envypt_output as output;
pub use envypt_runtime as runtime;
pub use envypt_schema as schema;

/// Discover the project rooted at the current directory, resolve `name`, and
/// decrypt + parse that environment profile into an in-memory map.
///
/// The caller decides how the values are merged with the process environment
/// (see [`runtime::exec`] and `envypt-core` docs). This function never
/// writes a plaintext file and never prints the returned values.
pub fn load_environment(name: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let path = core::discover(&std::env::current_dir()?)?;
    let project = core::load(&path)?;
    let profile = core::environment(&project, name)?;
    let root = path.parent().unwrap_or(&path);
    let plaintext = crypto::decrypt(&root.join(&profile.file))
        .with_context(|| format!("decrypt environment {name}"))?;
    Ok(schema::parse_env(&plaintext))
}
