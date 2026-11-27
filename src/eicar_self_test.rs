use amaru::Config;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{error::Error, io, path::Path};
use yara_engine::YaraEngine;

/// Exercise the installed rules without distributing a native binary containing the test signature.
pub(crate) fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = Config::load(config_path)?;
    let rules = config_path.with_file_name(config.yara_rules_path);
    let engine = YaraEngine::new(&rules)?;
    let sample = STANDARD.decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")?;
    for (bytes, expected) in [(sample.as_slice(), true), (&b"Amaru control"[..], false)] {
        let matches = engine.scan_memory(bytes)?;
        let detected = matches
            .iter()
            .any(|rule| rule.rule_name == "EICAR_Test_File");
        if detected != expected {
            return Err(io::Error::other(format!(
                "EICAR_Test_File returned {detected}, expected {expected} with rules at {}",
                rules.display()
            ))
            .into());
        }
    }
    println!("EICAR_Test_File detected the test sample and cleared the negative control.");
    Ok(())
}
