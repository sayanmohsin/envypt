use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use openenvcrypt_core::{Project, discover, environment, load};
use openenvcrypt_schema::{example, load as load_schema, parse_env, validate};
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Parser)]
#[command(
    name = "openenvcrypt",
    version,
    about = "Secure encrypted environment files"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}
#[derive(Debug, Subcommand)]
enum CommandKind {
    Init,
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Check {
        environment: String,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    Example,
    Exec {
        environment: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    Doctor,
    Diff {
        left: String,
        right: String,
    },
    Rotate {
        environment: String,
    },
    Edit {
        environment: String,
    },
    Set {
        environment: String,
        variable: String,
    },
}
#[derive(Debug, Subcommand)]
enum EnvCommand {
    Create { environment: String },
}
#[derive(Debug, Subcommand)]
enum KeyCommand {
    Generate { environment: String },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
}

fn project() -> Result<(PathBuf, Project)> {
    let path = discover(&env::current_dir()?)?;
    Ok((path.clone(), load(&path)?))
}
fn profile(name: &str) -> Result<(PathBuf, openenvcrypt_core::Environment)> {
    let (path, project) = project()?;
    Ok((path, environment(&project, name)?.clone()))
}
fn root(path: &Path) -> &std::path::Path {
    path.parent().unwrap_or(path)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::Init => init(),
        CommandKind::Check {
            environment,
            format,
        } => check(&environment, format),
        CommandKind::Example => {
            let (path, project) = project()?;
            let name = project
                .environments
                .keys()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no environments configured"))?;
            let schema = load_schema(&root(&path).join(&environment(&project, name)?.schema))?;
            fs::write(root(&path).join(".env.example"), example(&schema))?;
            Ok(())
        }
        CommandKind::Exec {
            environment,
            command,
        } => {
            let (path, p) = profile(&environment)?;
            let values = parse_env(&openenvcrypt_crypto::decrypt(&root(&path).join(&p.file))?);
            std::process::exit(openenvcrypt_runtime::exec(&command, &values)?);
        }
        CommandKind::Doctor => {
            let _ = project()?;
            println!("project configuration: ok");
            Ok(())
        }
        CommandKind::Edit { environment } => edit(&environment),
        CommandKind::Set {
            environment,
            variable,
        } => set(&environment, &variable),
        CommandKind::Env {
            command: EnvCommand::Create { environment },
        } => {
            println!("add environment {environment} to openenvcrypt.yaml");
            Ok(())
        }
        CommandKind::Key {
            command: KeyCommand::Generate { environment },
        } => generate_key(&environment),
        CommandKind::Diff { .. } => anyhow::bail!("diff is not yet available"),
        CommandKind::Rotate { .. } => anyhow::bail!("rotation is planned after the MVP"),
    }
}
fn init() -> Result<()> {
    let r = env::current_dir()?;
    fs::create_dir_all(r.join("config"))?;
    fs::create_dir_all(r.join("secrets"))?;
    if !r.join("openenvcrypt.yaml").exists() {
        fs::write(
            r.join("openenvcrypt.yaml"),
            "project: my-project\nenvironments:\n  dev:\n    file: secrets/dev.env.enc\n    schema: config/env.schema.yaml\n    recipients: []\n",
        )?;
    }
    if !r.join("config/env.schema.yaml").exists() {
        fs::write(r.join("config/env.schema.yaml"), "variables: {}\n")?;
    }
    if !r.join(".sops.yaml").exists() {
        fs::write(r.join(".sops.yaml"), "creation_rules: []\n")?;
    }
    println!("initialized openenvcrypt project");
    Ok(())
}

fn generate_key(name: &str) -> Result<()> {
    let (path, profile) = profile(name)?;
    let key_path = profile.key_file.map(PathBuf::from).unwrap_or_else(|| {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("openenvcrypt/keys")
            .join(format!("{name}.txt"))
    });
    let key_path = if key_path.to_string_lossy().starts_with("~/") {
        PathBuf::from(env::var("HOME")?).join(key_path.strip_prefix("~/")?)
    } else {
        key_path
    };
    let key = openenvcrypt_crypto::generate_key(&key_path)?;
    println!(
        "{}",
        key.lines()
            .find(|line| line.starts_with("# public key: "))
            .unwrap_or("# public key unavailable")
    );
    let _ = path;
    Ok(())
}
fn check(name: &str, format: Format) -> Result<()> {
    let (path, p) = profile(name)?;
    let values = parse_env(&openenvcrypt_crypto::decrypt(&root(&path).join(&p.file))?);
    let findings = validate(&load_schema(&root(&path).join(&p.schema))?, &values, name);
    match format {
        Format::Human => {
            if findings.is_empty() {
                println!("{name}: ok")
            } else {
                for f in findings {
                    println!("{}: {}", f.variable, f.message)
                }
            }
        }
        Format::Json => println!("{}", openenvcrypt_output::json(&findings)?),
    };
    Ok(())
}
fn edit(name: &str) -> Result<()> {
    let (path, p) = profile(name)?;
    let r = root(&path);
    let tmp = r.join(format!(".openenvcrypt-edit-{}", std::process::id()));
    fs::write(&tmp, openenvcrypt_crypto::decrypt(&r.join(&p.file))?)?;
    let editor = p
        .editor
        .or_else(|| env::var("EDITOR").ok())
        .unwrap_or_else(|| "vi".into());
    let status = Command::new(editor).arg(&tmp).status()?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        anyhow::bail!("editor failed")
    }
    let content = fs::read_to_string(&tmp)?;
    let _ = fs::remove_file(&tmp);
    openenvcrypt_crypto::encrypt(&content, &r.join(&p.file), &p.recipients)
}
fn set(name: &str, variable: &str) -> Result<()> {
    let (path, p) = profile(name)?;
    let r = root(&path);
    let mut values = parse_env(&openenvcrypt_crypto::decrypt(&r.join(&p.file))?);
    eprint!("value for {variable}: ");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    values.insert(variable.into(), value.trim_end().into());
    let text: String = values
        .into_iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    openenvcrypt_crypto::encrypt(&text, &r.join(&p.file), &p.recipients)
}
