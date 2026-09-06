use anyhow::{Context, bail};
use std::{env, fs, path::Path, process::Command};

fn tool(name: &str) -> anyhow::Result<String> {
    if let Ok(path) = which(name) {
        return Ok(path);
    }
    bail!("required encryption tool '{name}' was not found; install sops and age/rage")
}
fn which(name: &str) -> Result<String, ()> {
    env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
        .map(Path::new)
        .map(|p| p.join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or(())
}
pub fn decrypt(path: &Path) -> anyhow::Result<String> {
    let sops = tool("sops")?;
    let output = Command::new(sops)
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(path)
        .output()
        .context("run sops decrypt")?;
    if !output.status.success() {
        bail!("sops could not decrypt {}", path.display())
    }
    Ok(String::from_utf8(output.stdout).context("decrypted content was not UTF-8")?)
}
pub fn encrypt(content: &str, path: &Path, recipients: &[String]) -> anyhow::Result<()> {
    let sops = tool("sops")?;
    let age = tool("age").or_else(|_| tool("rage"))?;
    let tmp = path.with_extension("tmp.plain");
    fs::write(&tmp, content)?;
    let mut cmd = Command::new(sops);
    cmd.args(["-e", "--input-type", "dotenv", "--output-type", "dotenv"]);
    for recipient in recipients {
        cmd.args(["--age", recipient]);
    }
    cmd.arg("--output").arg(path).arg(&tmp).env(
        "SOPS_AGE_KEY_FILE",
        env::var("SOPS_AGE_KEY_FILE").unwrap_or_default(),
    );
    let result = cmd.output().context("run sops encrypt");
    let _ = fs::remove_file(&tmp);
    let _ = age;
    let output = result?;
    if !output.status.success() {
        bail!("sops encryption failed")
    }
    Ok(())
}

pub fn generate_key(path: &Path) -> anyhow::Result<String> {
    let binary = tool("age-keygen").or_else(|_| tool("rage-keygen"))?;
    let output = Command::new(binary).output().context("run age-keygen")?;
    if !output.status.success() {
        bail!("key generation failed")
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &output.stdout)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    String::from_utf8(output.stdout).context("generated key was not UTF-8")
}
