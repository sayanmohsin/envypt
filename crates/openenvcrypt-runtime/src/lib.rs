use anyhow::bail;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
};
pub fn exec(command: &[String], values: &BTreeMap<String, String>) -> anyhow::Result<i32> {
    let Some(program) = command.first() else {
        bail!("a child command is required after --")
    };
    let status = Command::new(program)
        .args(&command[1..])
        .envs(values)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    Ok(status.code().unwrap_or(128 + status.signal().unwrap_or(0)))
}
trait SignalCode {
    fn signal(&self) -> Option<i32>;
}
impl SignalCode for std::process::ExitStatus {
    fn signal(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            return std::os::unix::process::ExitStatusExt::signal(self);
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}
