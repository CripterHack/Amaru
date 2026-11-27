use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use updater::{RuleFile, RuleUpdate, Signature, UpdateError, Updater};

const OLD: &[u8] = b"rule Previous { condition: true }";
const NEW: &[u8] = b"rule Updated { condition: true }";

async fn serve(files: HashMap<&'static str, &'static [u8]>) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            let path = line.split_whitespace().nth(1).unwrap_or("");
            let (status, bytes) = match files.get(path) {
                Some(body) => ("200 OK", *body),
                None => ("404 Not Found", &b""[..]),
            };
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(bytes).await.unwrap();
        }
    });
    format!("http://{address}")
}

fn update_for(base: &str, files: &[(&str, &[u8])], signing_key: &SigningKey) -> RuleUpdate {
    let mut rules = vec![];
    let mut signatures = vec![];
    for (path, bytes) in files {
        rules.push(RuleFile {
            path: path.to_string(),
            hash: hex::encode(Sha256::digest(bytes)),
            url: format!("{base}/{path}"),
        });
        signatures.push(Signature {
            file_path: path.to_string(),
            signature: signing_key.sign(bytes).to_bytes().to_vec(),
        });
    }
    RuleUpdate {
        version: "1.10.0".to_owned(),
        timestamp: 100,
        rules,
        signatures,
        rollback_version: None,
    }
}

fn install_fixture(root: &Path, key: &SigningKey) -> Updater {
    let rules = root.join("rules");
    fs::create_dir_all(rules.join("official")).unwrap();
    fs::write(rules.join("official/test.yar"), OLD).unwrap();
    fs::write(rules.join("version.txt"), "1.9.0").unwrap();
    Updater::new(rules, root.join("backups"), key.verifying_key().as_bytes()).unwrap()
}

#[tokio::test]
async fn authenticates_new_bytes_and_keeps_nested_backup() {
    let root = tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let updater = install_fixture(root.path(), &key);
    let base = serve(HashMap::from([("/official/test.yar", NEW)])).await;
    let package = update_for(&base, &[("official/test.yar", NEW)], &key);
    updater.apply_update(package.clone()).await.unwrap();
    assert_eq!(
        fs::read(root.path().join("rules/official/test.yar")).unwrap(),
        NEW
    );
    assert_eq!(
        fs::read(root.path().join("rules/version.txt")).unwrap(),
        b"1.10.0"
    );
    let backup = fs::read_dir(root.path().join("backups"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(fs::read(backup.join("official/test.yar")).unwrap(), OLD);
    assert!(updater.apply_update(package).await.is_err());
}

#[tokio::test]
async fn failed_later_download_or_verification_preserves_all_live_files() {
    let root = tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let updater = install_fixture(root.path(), &key);
    let base = serve(HashMap::from([
        ("/official/test.yar", NEW),
        ("/second.yar", NEW),
    ]))
    .await;
    let package = update_for(
        &base,
        &[("official/test.yar", NEW), ("second.yar", NEW)],
        &key,
    );

    let mut invalid_signature = package.clone();
    invalid_signature.signatures[1].signature = key.sign(OLD).to_bytes().to_vec();
    assert!(matches!(
        updater.apply_update(invalid_signature).await,
        Err(UpdateError::Signature(_))
    ));
    let mut invalid_hash = package.clone();
    invalid_hash.rules[1].hash = hex::encode(Sha256::digest(OLD));
    assert!(matches!(
        updater.apply_update(invalid_hash).await,
        Err(UpdateError::Signature(_))
    ));
    let mut absent = package;
    absent.rules[1].url = format!("{base}/missing");
    assert!(matches!(
        updater.apply_update(absent).await,
        Err(UpdateError::Network(_))
    ));

    assert_eq!(
        fs::read(root.path().join("rules/official/test.yar")).unwrap(),
        OLD
    );
    assert_eq!(
        fs::read(root.path().join("rules/version.txt")).unwrap(),
        b"1.9.0"
    );
    assert!(!root.path().join("rules/second.yar").exists());
}

#[test]
fn rejects_ambiguous_signatures_and_nonportable_paths() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let package = update_for("https://example.com", &[("official/test.yar", NEW)], &key);
    let mut invalid = package.clone();
    invalid.signatures.clear();
    assert!(invalid.validate_structure().is_err());
    let mut invalid = package.clone();
    invalid.signatures[0].signature.pop();
    assert!(invalid.validate_structure().is_err());
    let mut invalid = package.clone();
    invalid.signatures[0].file_path = "different.yar".into();
    assert!(invalid.validate_structure().is_err());
    for path in [
        "../test.yar",
        "C:\\test.yar",
        "aux.yar",
        "test.yar:alias.yar",
        "/test.yar",
        "rules/version.txt",
    ] {
        let invalid = update_for("https://example.com", &[(path, NEW)], &key);
        assert!(invalid.validate_structure().is_err(), "{path}");
    }
    let duplicate = update_for(
        "https://example.com",
        &[("test.yar", NEW), ("TEST.yar", NEW)],
        &key,
    );
    assert!(duplicate.validate_structure().is_err());
    assert!(Updater::new(".", "backup", &[1; 31]).is_err());
}

#[tokio::test]
async fn refuses_unsigned_metadata_over_plain_http() {
    let root = tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let updater = install_fixture(root.path(), &key);
    let body = br#"{"current_version":"1.9.0","available_version":"1.9.0","update_url":"","public_key":""}"#;
    let base = serve(HashMap::from([("/manifest.json", &body[..])])).await;
    assert!(matches!(
        updater
            .check_updates(&format!("{base}/manifest.json"))
            .await,
        Err(UpdateError::Network(_))
    ));
}

#[tokio::test]
async fn publisher_output_installs_with_the_pinned_key() {
    let root = tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let updater = install_fixture(root.path(), &key);
    let source = root.path().join("source");
    fs::create_dir_all(source.join("sub")).unwrap();
    fs::write(source.join("sub/a b.yara"), NEW).unwrap();
    let seed_path = root.path().join("seed");
    fs::write(&seed_path, key.to_bytes()).unwrap();
    let base = serve(HashMap::from([("/rules/sub/a%20b.yara", NEW)])).await;
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_sign-update"))
        .current_dir(root.path())
        .arg(source)
        .arg("1.10.0")
        .arg(base)
        .arg(seed_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let package =
        serde_json::from_slice(&fs::read(root.path().join("update.json")).unwrap()).unwrap();
    updater.apply_update(package).await.unwrap();
    assert_eq!(
        fs::read(root.path().join("rules/sub/a b.yara")).unwrap(),
        NEW
    );
}
