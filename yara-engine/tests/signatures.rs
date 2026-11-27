use std::{fs, path::Path};

use tempfile::tempdir;
use yara_engine::{YaraEngine, YaraError};

#[test]
fn bundled_rules_detect_eicar_on_disk_and_in_memory() -> Result<(), YaraError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let engine = YaraEngine::new(root.join("signatures"))?;
    engine.verify_eicar()?;
    let fixture = root.join("test-eicar.txt");
    let on_disk = engine.scan_file(&fixture)?;
    let in_memory = engine.scan_memory(&fs::read(fixture)?)?;

    for matches in [on_disk.matches, in_memory] {
        let eicar = matches
            .iter()
            .find(|m| m.rule_name == "EICAR_Test_File")
            .expect("EICAR signature from the official bundle");
        assert_eq!(eicar.meta["priority"], 10);
        assert!(eicar
            .strings
            .iter()
            .any(|s| s.offset == 0 && s.data.len() == 68));
    }
    assert!(engine.scan_memory(b"ordinary file")?.is_empty());
    Ok(())
}

#[test]
fn reload_preserves_last_working_rules_and_drops_removed_rules() -> Result<(), YaraError> {
    let directory = tempdir()?;
    let rule = directory.path().join("marker.yar");
    fs::write(&rule, "rule Marker { condition: true }")?;
    let mut engine = YaraEngine::new(directory.path())?;

    fs::write(&rule, "rule")?;
    assert!(engine.update_rules().is_err());
    assert_eq!(engine.scan_memory(b"sample")?[0].rule_name, "Marker");

    fs::remove_file(rule)?;
    engine.reload_rules()?;
    assert!(engine.scan_memory(b"sample")?.is_empty());
    assert!(engine.get_rule_metadata().is_empty());
    Ok(())
}

#[test]
fn eicar_self_test_rejects_missing_and_unconditional_rules() -> Result<(), YaraError> {
    let directory = tempdir()?;
    let mut engine = YaraEngine::new(directory.path())?;
    assert!(engine.verify_eicar().is_err());
    fs::write(
        directory.path().join("eicar.yar"),
        "rule EICAR_Test_File { condition: true }",
    )?;
    engine.reload_rules()?;
    assert!(engine.verify_eicar().is_err());
    Ok(())
}
