//! Integration tests against golden fixtures produced by the official `sops`
//! CLI (see `fixtures/`). The identity files in `fixtures/` are throwaway,
//! test-only keys that decrypt only these fake fixtures; they never hold real
//! secrets.
//!
//! When the `SOPS_BIN` environment variable points at a real `sops` binary,
//! an additional cross-tool test verifies that our encrypted output decrypts
//! with official SOPS.

use envypt::crypto::keys::{self, Identity};
use std::{fs, path::PathBuf, process::Command};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read(name: &str) -> String {
    let path = fixtures().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn dev_identity() -> Identity {
    keys::identity_from_key_text(&read("age-identity-dev.txt")).expect("parse dev identity")
}

fn ci_identity() -> Identity {
    keys::identity_from_key_text(&read("age-identity-ci.txt")).expect("parse ci identity")
}

#[test]
fn decrypt_sops_single_recipient() {
    let encrypted = read("dev.env.enc");
    let plaintext = read("dev.env");
    let out = envypt::crypto::store::decrypt(&encrypted, &[dev_identity()]).unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn decrypt_sops_multi_recipient_with_either_key() {
    let encrypted = read("multi.env.enc");
    let plaintext = read("dev.env");
    assert_eq!(
        envypt::crypto::store::decrypt(&encrypted, &[dev_identity()]).unwrap(),
        plaintext
    );
    assert_eq!(
        envypt::crypto::store::decrypt(&encrypted, &[ci_identity()]).unwrap(),
        plaintext
    );
}

#[test]
fn wrong_key_is_rejected() {
    let encrypted = read("dev.env.enc");
    let err = envypt::crypto::store::decrypt(&encrypted, &[ci_identity()]).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no configured identity") || text.contains("wrong key"),
        "{text}"
    );
}

#[test]
fn tampered_value_is_rejected() {
    let mut encrypted = read("dev.env.enc");
    let marker = "APP_ENV=ENC[AES256_GCM,data:";
    let pos = encrypted.find(marker).expect("find APP_ENV value");
    let replace_at = encrypted[pos + marker.len()..]
        .find('A')
        .map(|i| pos + marker.len() + i)
        .expect("find a base64 char to flip");
    encrypted.replace_range(replace_at..replace_at + 1, "B");
    assert!(envypt::crypto::store::decrypt(&encrypted, &[dev_identity()]).is_err());
}

#[test]
fn tampered_mac_is_rejected() {
    let mut encrypted = read("dev.env.enc");
    let pos = encrypted.find("sops_mac=").expect("find sops_mac");
    let value_start = pos + "sops_mac=".len();
    encrypted.replace_range(value_start..value_start + 1, "B");
    assert!(envypt::crypto::store::decrypt(&encrypted, &[dev_identity()]).is_err());
}

#[test]
fn plaintext_features_roundtrip_through_our_encrypt() {
    let plaintext = read("dev.env");
    let dev_recipient = read_recipient_of("age-identity-dev.txt");
    let encrypted = envypt::crypto::store::encrypt(&plaintext, &[dev_recipient]).unwrap();

    // Comments and empty values keep their on-disk shape; unencrypted suffix
    // values stay plaintext.
    assert!(
        encrypted.contains("#ENC[AES256_GCM,"),
        "comments are encrypted"
    );
    assert!(encrypted.contains("EMPTY=\n"), "empty value stays empty");
    assert!(encrypted.contains("SAMPLE_unencrypted=visible-plaintext\n"));

    // Metadata lines appear in canonical order.
    let order = [
        "sops_age__list_0__map_enc=",
        "sops_age__list_0__map_recipient=",
        "sops_lastmodified=",
        "sops_mac=",
        "sops_unencrypted_suffix=",
        "sops_version=",
    ];
    let mut last = 0usize;
    for key in order {
        let idx = encrypted.find(key).expect("metadata key present");
        assert!(idx > last, "{key} out of order");
        last = idx;
    }

    let decrypted = envypt::crypto::store::decrypt(&encrypted, &[dev_identity()]).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn list_recipients_matches_metadata() {
    let dev = envypt::crypto::store::list_recipients(&read("dev.env.enc")).unwrap();
    assert_eq!(dev.len(), 1);
    let multi = envypt::crypto::store::list_recipients(&read("multi.env.enc")).unwrap();
    assert_eq!(multi.len(), 2);
}

#[test]
fn empty_and_reserved_keys_fail_closed() {
    let recipient = read_recipient_of("age-identity-dev.txt");
    let err = envypt::crypto::store::encrypt("A=1", &[]).unwrap_err();
    assert!(format!("{err:#}").contains("no age recipients"));

    let err = envypt::crypto::store::encrypt("sops_evil=1", std::slice::from_ref(&recipient))
        .unwrap_err();
    assert!(format!("{err:#}").contains("reserved"));

    let err = envypt::crypto::store::encrypt("A=1\nnot-a-key\n", &[recipient]).unwrap_err();
    assert!(format!("{err:#}").contains("invalid dotenv line"));
}

fn read_recipient_of(identity_file: &str) -> keys::Recipient {
    let text = read(identity_file);
    let line = text
        .lines()
        .find(|l| l.starts_with("# public key: age1"))
        .expect("public key header");
    keys::parse_recipient(line.trim_start_matches("# public key: ")).unwrap()
}

#[test]
fn official_sops_can_decrypt_our_output() {
    let Some(sops_bin) = std::env::var_os("SOPS_BIN") else {
        eprintln!("SOPS_BIN not set; skipping official-sops interop check");
        return;
    };
    let plaintext = read("dev.env");
    let recipient = read_recipient_of("age-identity-dev.txt");
    let encrypted = envypt::crypto::store::encrypt(&plaintext, &[recipient]).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let enc_path = dir.path().join("ours.env.enc");
    fs::write(&enc_path, &encrypted).unwrap();
    let key_path = fixtures().join("age-identity-dev.txt");

    let output = Command::new(&sops_bin)
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(&enc_path)
        .env("SOPS_AGE_KEY_FILE", &key_path)
        .output()
        .expect("run official sops");
    assert!(
        output.status.success(),
        "sops failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), plaintext);
}
