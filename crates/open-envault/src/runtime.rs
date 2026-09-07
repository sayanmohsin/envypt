use anyhow::bail;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
};
pub fn exec(
    command: &[String],
    values: &BTreeMap<String, String>,
    force: bool,
) -> anyhow::Result<i32> {
    let Some(program) = command.first() else {
        bail!("a child command is required after --")
    };
    let mut child = Command::new(program);
    child
        .args(&command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if force {
        child.envs(values);
    } else {
        for (name, value) in values {
            if std::env::var_os(name).is_none() {
                child.env(name, value);
            }
        }
    }
    let status = child.status()?;
    Ok(status.code().unwrap_or(128 + status.signal().unwrap_or(0)))
}
trait SignalCode {
    fn signal(&self) -> Option<i32>;
}
impl SignalCode for std::process::ExitStatus {
    fn signal(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            std::os::unix::process::ExitStatusExt::signal(self)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}
