use amaru::{Amaru, AmaruError, Config, ScanResult, RiskLevel, ThreatType};
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_initialization() -> Result<(), AmaruError> {
    // Create a temporary config
    let config = Config::default();
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Verify initialization succeeded by checking the components
    assert!(amaru.yara_engine.is_some(), "YARA engine should be initialized");
    assert!(amaru.heuristic_engine.is_none(), "Heuristic engine should not be initialized by default");
    assert!(amaru.realtime_monitor.is_none(), "Real-time monitor should not be initialized by default");
    
    Ok(())
}

#[tokio::test]
async fn test_scan_clean_file() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("clean_file.txt");
    
    // Create a clean test file
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"This is a clean test file with no malicious content").expect("Failed to write test file");
    
    // Create config
    let mut config = Config::default();
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Scan the file
    let result = amaru.scan_file(&file_path).await?;
    
    // Verify the result
    assert_eq!(result.risk_level, RiskLevel::Safe, "Clean file should be marked as safe");
    assert!(result.yara_matches.is_empty(), "Clean file should have no YARA matches");
    assert!(result.threat_details.is_none(), "Clean file should have no threat details");
    
    Ok(())
}

#[tokio::test]
async fn test_scan_malicious_file() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("malicious_file.txt");
    
    // Create a test file with known malicious content (EICAR test string)
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").expect("Failed to write test file");
    
    // Create config with test rules
    let mut config = Config::default();
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Scan the file
    let result = amaru.scan_file(&file_path).await?;
    
    // Verify the result (should detect the EICAR test file)
    assert!(result.risk_level >= RiskLevel::High, "EICAR test file should be marked as high risk");
    assert!(!result.yara_matches.is_empty(), "EICAR test file should have YARA matches");
    assert!(result.threat_details.is_some(), "EICAR test file should have threat details");
    
    Ok(())
}

#[tokio::test]
async fn test_heuristic_engine() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("suspicious_file.exe");
    
    // Create a test file with suspicious PE characteristics
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00").expect("Failed to write test file");
    
    // Create config with heuristic engine enabled
    let mut config = Config::default();
    config.enable_heuristic_engine = true;
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let mut amaru = Amaru::new(config).await?;
    
    // Initialize heuristic engine
    amaru.init_heuristic_engine(None)?;
    
    // Scan the file
    let result = amaru.scan_file(&file_path).await?;
    
    // Verify the heuristic engine was used in the analysis
    assert!(amaru.heuristic_engine.is_some(), "Heuristic engine should be initialized");
    
    Ok(())
}

#[tokio::test]
async fn test_quarantine_system() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("quarantine_test.txt");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    // Create quarantine directory
    fs::create_dir(&quarantine_dir).expect("Failed to create quarantine directory");
    
    // Create a test file
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"Test file for quarantine").expect("Failed to write test file");
    
    // Create config with custom quarantine path
    let mut config = Config::default();
    config.quarantine_config.quarantine_path = quarantine_dir.clone();
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Quarantine the file
    let original_path = amaru.quarantine.quarantine_file(&file_path, "Test quarantine")?;
    
    // Verify file was moved to quarantine
    assert!(!file_path.exists(), "Original file should no longer exist");
    assert!(fs::read_dir(&quarantine_dir).unwrap().count() > 0, "Quarantine directory should contain at least one file");
    
    // Restore the file
    let restored_path = amaru.quarantine.restore_file(&original_path)?;
    
    // Verify file was restored
    assert!(restored_path.exists(), "File should be restored");
    let content = fs::read_to_string(&restored_path).expect("Failed to read restored file");
    assert_eq!(content, "Test file for quarantine", "File content should be preserved");
    
    Ok(())
}

#[tokio::test]
async fn test_realtime_protection() -> Result<(), AmaruError> {
    // Create a temporary directory to monitor
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // Create config with real-time protection enabled
    let mut config = Config::default();
    config.enable_realtime_protection = true;
    config.realtime_config.paths = vec![temp_dir.path().to_path_buf()];
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let mut amaru = Amaru::new(config).await?;
    
    // Enable real-time protection
    amaru.enable_realtime_protection().await?;
    
    // Verify real-time protection was enabled
    assert!(amaru.realtime_monitor.is_some(), "Real-time monitor should be initialized");
    
    // Create a test file in the monitored directory
    let file_path = temp_dir.path().join("monitored_file.txt");
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"Test file for real-time monitoring").expect("Failed to write test file");
    
    // Wait a moment for the file event to be processed
    sleep(Duration::from_millis(1000)).await;
    
    // Disable real-time protection
    amaru.disable_realtime_protection().await?;
    
    // Verify real-time protection was disabled
    assert!(amaru.realtime_monitor.is_none(), "Real-time monitor should be disabled");
    
    Ok(())
}

#[tokio::test]
async fn test_resource_management() -> Result<(), AmaruError> {
    // Create config with resource management settings
    let mut config = Config::default();
    config.resource_config.max_cpu_usage = 0.5; // 50% CPU usage limit
    config.resource_config.max_memory_mb = 1024; // 1GB memory limit
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Optimize resources
    amaru.optimize_resources().await?;
    
    // Verify resource optimization succeeded
    // (We can't easily test the actual resource limits in a unit test,
    // but we can verify the function doesn't fail)
    
    Ok(())
}

#[tokio::test]
async fn test_update_yara_rules() -> Result<(), AmaruError> {
    // Create config
    let config = Config::default();
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Update YARA rules
    // Note: This won't actually download new rules in the test environment,
    // but it should at least run through the update process
    amaru.update_yara_rules().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_integrated_scan() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("integrated_scan_test.txt");
    
    // Create a test file
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"Test file for integrated scan").expect("Failed to write test file");
    
    // Create config with core services enabled
    let mut config = Config::default();
    config.enable_core_services = true;
    config.yara_rules_path = PathBuf::from("signatures/official");
    
    // Initialize Amaru
    let mut amaru = Amaru::new(config).await?;
    
    // Initialize core services
    amaru.init_core_services().await?;
    
    // Perform integrated scan
    let result = amaru.integrated_scan_file(&file_path).await?;
    
    // Verify the scan completed
    assert!(result.scan_complete, "Integrated scan should complete");
    
    Ok(())
}

#[tokio::test]
async fn test_scan_optimization() -> Result<(), AmaruError> {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let file_path = temp_dir.path().join("optimized_scan_test.txt");
    
    // Create a test file
    let mut file = File::create(&file_path).expect("Failed to create test file");
    file.write_all(b"Test file for optimized scan").expect("Failed to write test file");
    
    // Create config
    let config = Config::default();
    
    // Initialize Amaru
    let amaru = Amaru::new(config).await?;
    
    // Perform optimized scan
    let result = amaru.scan_file_optimized(&file_path).await?;
    
    // Verify the scan completed
    assert!(!result.is_malicious, "Test file should not be detected as malicious");
    
    // Scan the same file again - should use cache
    let start = std::time::Instant::now();
    let _result2 = amaru.scan_file_optimized(&file_path).await?;
    let duration = start.elapsed();
    
    // Verify the second scan was faster (due to caching)
    assert!(duration.as_millis() < 100, "Cached scan should be very fast");
    
    Ok(())
} 