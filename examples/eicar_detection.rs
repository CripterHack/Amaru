// EICAR Test File Detection Example
//
// This example demonstrates how Amaru detects the EICAR test virus file.
// The EICAR test file is a non-malicious file that antivirus programs detect
// to confirm they are working correctly.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process;

use amaru::{Amaru, Config, MaliciousBehaviorType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    println!("Amaru EICAR Test File Detection Example");
    println!("--------------------------------------");
    
    // Get arguments
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    
    // Check if a file path was provided or create a test file
    let file_path = if args.len() > 1 {
        args[1].clone()
    } else {
        create_eicar_test_file()?
    };
    
    println!("Scanning file: {}", file_path);
    
    // Load default configuration
    let mut config = Config::default();
    
    // Make sure paths exist and are set
    let current_dir = env::current_dir()?;
    let signatures_dir = current_dir.join("signatures");
    if !signatures_dir.exists() {
        println!("Warning: Signatures directory not found at: {}", signatures_dir.display());
        println!("Run this example from the project root or specify a signatures path");
    }
    
    // Set configuration
    config.yara_rules_path = signatures_dir.clone();
    config.enable_heuristic_engine = true;
    
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
            println!("  {}. Rule: {}", i+1, detection.rule_name);
            if let Some(desc) = &detection.description {
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
            println!("  {}. Type: {:?}", i+1, behavior.behavior_type);
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

// Creates a temporary EICAR test file and returns its path
fn create_eicar_test_file() -> Result<String, Box<dyn std::error::Error>> {
    // Create temp directory if it doesn't exist
    let temp_dir = env::temp_dir().join("amaru_test");
    if !temp_dir.exists() {
        fs::create_dir_all(&temp_dir)?;
    }
    
    // Create EICAR file
    let eicar_path = temp_dir.join("eicar_test.txt");
    let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    
    let mut file = File::create(&eicar_path)?;
    file.write_all(eicar_content)?;
    
    println!("Created EICAR test file at: {}", eicar_path.display());
    
    Ok(eicar_path.to_string_lossy().to_string())
} 