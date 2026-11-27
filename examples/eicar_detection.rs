// EICAR Test File Detection Example
//
// This example demonstrates how Amaru detects the EICAR test virus file.
// The EICAR test file is a non-malicious file that antivirus programs detect
// to confirm they are working correctly.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::env;
use std::io::Write;
use std::path::PathBuf;

use amaru::{Amaru, Config, MaliciousBehaviorType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    println!("Amaru EICAR Test File Detection Example");
    println!("--------------------------------------");

    let temp = tempfile::tempdir()?;
    let file_path = match env::args_os().nth(1) {
        Some(path) => PathBuf::from(path),
        None => {
            let path = temp.path().join("eicar_test.txt");
            let sample = STANDARD.decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")?;
            std::fs::File::create(&path)?.write_all(&sample)?;
            path
        }
    };
    println!("Scanning file: {}", file_path.display());
    let mut config = Config::load("config.toml")?;
    config.quarantine_config.quarantine_path = temp.path().join("quarantine");

    // Initialize Amaru
    println!("Initializing Amaru...");
    let amaru = Amaru::new(config).await?;

    // Scan the file
    println!("Scanning file...");
    let result = amaru.scan_file(&file_path).await?;

    // Display results
    println!("\nScan Results:");
    println!("-----------------");

    // Check YARA matches
    if !result.yara_matches.is_empty() {
        println!("YARA detections:");
        for (i, detection) in result.yara_matches.iter().enumerate() {
            println!("  {}. Rule: {}", i + 1, detection.rule_name);
            if let Some(desc) = detection
                .meta
                .get("description")
                .and_then(|value| value.as_str())
            {
                println!("     Description: {}", desc);
            }
        }
        println!();
    } else {
        println!("No YARA detections found.");
    }

    // Check behavior detections
    if let Some(behaviors) = result.behaviors {
        println!("Behavior detections:");
        for (i, behavior) in behaviors.iter().enumerate() {
            println!("  {}. Type: {:?}", i + 1, behavior.behavior_type);
            println!("     Description: {}", behavior.description);

            // Check if it's an EICAR test file
            if matches!(behavior.behavior_type, MaliciousBehaviorType::TestFile) {
                println!("\n[EICAR TEST FILE DETECTED]");
                println!("The file has been identified as the EICAR test file.");
                println!("This is a non-malicious file used to test antivirus functionality.");
            }
        }
    } else {
        println!("No suspicious behaviors detected.");
    }

    // Display risk level
    println!("\nRisk Level: {:?}", result.risk_level);

    Ok(())
}
