use std::{fs, path::Path, process::Command};

const IDENTITY: &str = include_str!("fixtures/age-identity-dev.txt");

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_oenv"))
}

fn recipient() -> String {
    IDENTITY
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap()
        .to_owned()
}

fn identity_line() -> &'static str {
    IDENTITY
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .unwrap()
}

fn project(dir: &Path) {
    fs::create_dir_all(dir.join("config")).unwrap();
    fs::create_dir_all(dir.join("secrets")).unwrap();
    fs::write(
        dir.join("open-envault.yaml"),
        format!(
            "project: test\nenvironments:\n  dev:\n    file: secrets/dev.env.enc\n    schema: config/env.schema.yaml\n    recipients: [{}]\n  prd:\n    file: secrets/prd.env.enc\n    schema: config/env.schema.yaml\n    recipients: [{}]\n",
            recipient()
            , recipient()
        ),
    )
    .unwrap();
    fs::write(
        dir.join("config/env.schema.yaml"),
        "variables:\n  API_KEY:\n    type: string\n    required: true\n  EXTRA:\n    type: string\n",
    )
    .unwrap();
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(binary());
    command
        .current_dir(dir)
        .env("SOPS_AGE_KEY", identity_line());
    command.args(args);
    command
}

#[test]
fn import_json_merges_and_filters_without_printing_values() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path());
    let mut first_command = command(
        dir.path(),
        &["import", "dev", "--format", "json", "--merge"],
    );
    first_command.env("UNUSED", "ignored");
    let first = first_command.output_with_stdin(br#"{"API_KEY":"first","EXTRA":"old"}"#);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!String::from_utf8_lossy(&first.stdout).contains("first"));

    let allowlist = dir.path().join("allowlist.txt");
    fs::write(&allowlist, "API_KEY\n").unwrap();
    let mut second_command = command(
        dir.path(),
        &[
            "import",
            "dev",
            "--format",
            "dotenv",
            "--merge",
            "--allowlist",
            allowlist.to_str().unwrap(),
        ],
    );
    let second = second_command.output_with_stdin(b"API_KEY=second\nEXTRA=new\n");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let check = command(dir.path(), &["check", "dev", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn force_controls_precedence_over_inherited_environment() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path());
    let mut import_command = command(
        dir.path(),
        &["import", "dev", "--format", "dotenv", "--replace"],
    );
    let imported = import_command.output_with_stdin(b"API_KEY=from-file\n");
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    for (args, expected) in [
        (
            vec!["exec", "dev", "--", "sh", "-c", "printf %s $API_KEY"],
            "inherited",
        ),
        (
            vec![
                "exec",
                "dev",
                "--force",
                "--",
                "sh",
                "-c",
                "printf %s $API_KEY",
            ],
            "from-file",
        ),
    ] {
        let mut run = command(dir.path(), &args);
        run.env("API_KEY", "inherited");
        let output = run.output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[test]
fn diff_is_redacted_and_rotate_preserves_decryptability() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path());
    let mut dev_import = command(
        dir.path(),
        &["import", "dev", "--format", "dotenv", "--replace"],
    );
    assert!(
        dev_import
            .output_with_stdin(b"API_KEY=dev\nEXTRA=same\n")
            .status
            .success()
    );
    let mut prd_import = command(
        dir.path(),
        &["import", "prd", "--format", "dotenv", "--replace"],
    );
    assert!(
        prd_import
            .output_with_stdin(b"API_KEY=prd\n")
            .status
            .success()
    );

    let mut diff = command(dir.path(), &["diff", "dev", "prd", "--format", "json"]);
    diff.env("OPENENVAULT_DIFF_PEPPER", "fixture-pepper");
    let output = diff.output().unwrap();
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\"changed\""));
    assert!(!text.contains("dev") || !text.contains("prd"));

    let before = fs::read(dir.path().join("secrets/prd.env.enc")).unwrap();
    let rotated = command(dir.path(), &["rotate", "prd"]).output().unwrap();
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let after = fs::read(dir.path().join("secrets/prd.env.enc")).unwrap();
    assert_ne!(before, after);
    let check = command(dir.path(), &["check", "prd", "--format", "json"])
        .output()
        .unwrap();
    assert!(check.status.success());
}

#[test]
fn check_reports_extra_variables_and_doctor_reports_profile_health() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path());
    let mut import_command = command(
        dir.path(),
        &["import", "dev", "--format", "dotenv", "--replace"],
    );
    assert!(
        import_command
            .output_with_stdin(b"API_KEY=ok\nEXTRA=ok\nUNDECLARED=hidden\n")
            .status
            .success()
    );

    let check = command(dir.path(), &["check", "dev", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(4));
    let check_text = String::from_utf8(check.stdout).unwrap();
    assert!(check_text.contains("\"extra\""));
    assert!(check_text.contains("UNDECLARED"));

    let doctor = command(dir.path(), &["doctor", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(doctor.status.code(), Some(4));
    let doctor_text = String::from_utf8(doctor.stdout).unwrap();
    assert!(doctor_text.contains("\"dev\""));
    assert!(doctor_text.contains("\"decrypt\": \"ok\""));
    assert!(doctor_text.contains("prd: encrypted profile is missing"));
}

#[test]
fn set_rejects_invalid_variable_names() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path());
    let mut set = command(dir.path(), &["set", "dev", "not-valid"]);
    let output = set.output_with_stdin(b"value\n");
    assert!(!output.status.success());
    assert!(!dir.path().join("secrets/dev.env.enc").exists());
}

trait CommandStdin {
    fn output_with_stdin(&mut self, input: &[u8]) -> std::process::Output;
}

impl CommandStdin for Command {
    fn output_with_stdin(&mut self, input: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = self.stdin(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }
}
