use amaru::{
    Amaru, Config, Event, RiskLevel, ThreatType,
    events::{EventChannel, ThreatDetails},
    quarantine::QuarantineError,
};

use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;
use tokio;

#[tokio::test]
async fn test_full_scan_workflow() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    let monitored_dir = temp_dir.path().join("monitored");
    
    fs::create_dir_all(&rules_dir)?;
    fs::create_dir_all(&quarantine_dir)?;
    fs::create_dir_all(&monitored_dir)?;
    
    // Crear regla YARA para detectar malware de prueba
    let rule_content = r#"
rule test_malware {
    meta:
        description = "Detecta malware de prueba"
        author = "CripterHack"
        severity = "high"
    strings:
        $s1 = "malicious_function"
        $s2 = "delete_system32"
        $s3 = "steal_data"
    condition:
        any of them
}

rule test_suspicious {
    meta:
        description = "Detecta comportamiento sospechoso"
        author = "CripterHack"
        severity = "medium"
    strings:
        $s1 = "CreateRemoteThread"
        $s2 = "VirtualAllocEx"
        $s3 = "WriteProcessMemory"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test_rules.yar"), rule_content)?;
    
    // Crear archivo malicioso de prueba
    let malware_file = monitored_dir.join("test_malware.exe");
    let malware_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\
        This is a test malware file containing malicious_function and delete_system32\
        It also uses suspicious APIs like CreateRemoteThread and VirtualAllocEx";
    File::create(&malware_file)?.write_all(malware_content)?;
    
    // Crear archivo limpio de prueba
    let clean_file = monitored_dir.join("clean_file.txt");
    File::create(&clean_file)?.write_all(b"This is a clean file")?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    config.monitored_paths = vec![monitored_dir];
    config.scan_config.max_threads = 2;
    config.scan_config.scan_timeout = 10;
    
    // Crear instancia de Amaru
    let mut amaru = Amaru::new(config).await?;
    
    // Escanear archivo malicioso
    let result = amaru.scan_file(&malware_file).await?;
    
    // Verificar resultado del escaneo
    assert!(!result.yara_matches.is_empty());
    assert_eq!(result.risk_level, RiskLevel::High);
    assert!(result.threat_details.is_some());
    
    if let Some(details) = result.threat_details {
        assert!(!details.matches.is_empty());
        assert!(details.file_size > 0);
        assert!(!details.file_hash.is_empty());
    }
    
    // Escanear archivo limpio
    let result = amaru.scan_file(&clean_file).await?;
    
    // Verificar resultado del archivo limpio
    assert!(result.yara_matches.is_empty());
    assert_eq!(result.risk_level, RiskLevel::Low);
    assert!(result.threat_details.is_none());
    
    // Probar protección en tiempo real
    amaru.enable_realtime_protection().await?;
    
    // Crear nuevo archivo malicioso
    let new_malware = monitored_dir.join("new_malware.exe");
    File::create(&new_malware)?.write_all(b"This file contains steal_data function")?;
    
    // Esperar a que se procese el evento
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    
    // Verificar que el archivo fue puesto en cuarentena
    assert!(!new_malware.exists());
    
    // Deshabilitar protección
    amaru.disable_realtime_protection().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_quarantine_workflow() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    fs::create_dir_all(&quarantine_dir)?;
    
    // Crear archivo de prueba
    let test_file = temp_dir.path().join("test.exe");
    let content = b"Test file content";
    File::create(&test_file)?.write_all(content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Poner archivo en cuarentena
    let quarantine = amaru.quarantine.clone();
    let entry = quarantine.quarantine_file(&test_file, "Test quarantine")?;
    
    // Verificar que el archivo original fue eliminado
    assert!(!test_file.exists());
    
    // Verificar que el archivo está en cuarentena
    assert!(quarantine_dir.join(&entry.quarantine_name).exists());
    
    // Restaurar archivo
    quarantine.restore_file(&entry)?;
    
    // Verificar que el archivo fue restaurado
    assert!(test_file.exists());
    let restored_content = fs::read(&test_file)?;
    assert_eq!(restored_content, content);
    
    Ok(())
}

#[tokio::test]
async fn test_event_handling() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Crear regla YARA
    let rule_content = r#"
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $s1 = "malicious"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Obtener receptor de eventos
    let receiver = amaru.event_receiver();
    
    // Crear y escanear archivo malicioso
    let test_file = temp_dir.path().join("test.exe");
    File::create(&test_file)?.write_all(b"This is a malicious test file")?;
    
    // Escanear archivo
    let _ = amaru.scan_file(&test_file).await?;
    
    // Verificar evento
    if let Ok(event) = receiver.try_recv() {
        match event {
            Event::ThreatDetected { path, threat_type, risk_level, .. } => {
                assert_eq!(path, test_file);
                assert!(matches!(threat_type, ThreatType::YaraMatch { .. }));
                assert!(risk_level >= RiskLevel::Medium);
            }
            _ => panic!("Evento inesperado"),
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_scanning() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Crear regla YARA
    let rule_content = r#"
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $s1 = "test"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    config.scan_config.max_threads = 4;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Crear múltiples archivos
    let mut handles = vec![];
    for i in 0..10 {
        let test_file = temp_dir.path().join(format!("test_{}.txt", i));
        File::create(&test_file)?.write_all(b"test content")?;
        
        let amaru = amaru.clone();
        let test_file = test_file.clone();
        
        // Escanear archivos concurrentemente
        handles.push(tokio::spawn(async move {
            amaru.scan_file(&test_file).await
        }));
    }
    
    // Esperar resultados
    for handle in handles {
        let result = handle.await??;
        assert!(!result.yara_matches.is_empty());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Configurar Amaru con reglas inválidas
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear regla YARA inválida
    let invalid_rule = r#"
rule invalid {
    strings:
        $s1 = "test
    condition:
        $s1
}
"#;
    fs::write(rules_dir.join("invalid.yar"), invalid_rule)?;
    
    // Verificar error al crear instancia
    let result = Amaru::new(config.clone()).await;
    assert!(result.is_err());
    
    // Crear instancia con reglas válidas
    fs::write(rules_dir.join("valid.yar"), "rule test { condition: true }")?;
    let amaru = Amaru::new(config).await?;
    
    // Intentar escanear archivo que no existe
    let result = amaru.scan_file("nonexistent.exe").await;
    assert!(result.is_err());
    
    // Intentar escanear archivo demasiado grande
    let large_file = temp_dir.path().join("large.bin");
    let mut file = File::create(&large_file)?;
    file.set_len(config.scan_config.max_file_size + 1)?;
    
    let result = amaru.scan_file(&large_file).await;
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_behavior_analysis() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Crear regla YARA
    let rule_content = r#"
rule test_malware {
    meta:
        description = "Test malware detection"
    strings:
        $s1 = "VirtualAllocEx"
        $s2 = "WriteProcessMemory"
        $s3 = "CreateRemoteThread"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;
    
    // Crear archivo malicioso de prueba
    let test_file = temp_dir.path().join("test.exe");
    let content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\
        This is a test file that uses VirtualAllocEx and WriteProcessMemory\
        It also contains CreateRemoteThread for process injection";
    File::create(&test_file)?.write_all(content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Escanear archivo
    let result = amaru.scan_file(&test_file).await?;
    
    // Verificar coincidencias YARA
    assert!(!result.yara_matches.is_empty());
    
    // Verificar comportamientos detectados
    assert!(result.behaviors.is_some());
    let behaviors = result.behaviors.unwrap();
    assert!(!behaviors.is_empty());
    
    // Verificar detección de inyección de procesos
    let process_injection = behaviors.iter()
        .find(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection));
    assert!(process_injection.is_some());
    
    // Verificar nivel de riesgo
    assert!(result.risk_level >= RiskLevel::High);
    
    // Verificar detalles de amenaza
    assert!(result.threat_details.is_some());
    let details = result.threat_details.unwrap();
    assert!(details.additional_info.is_some());
    let additional_info = details.additional_info.unwrap();
    assert!(additional_info.get("malicious_behaviors").is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_ransomware_detection() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Crear regla YARA
    let rule_content = r#"
rule test_ransomware {
    meta:
        description = "Test ransomware detection"
    strings:
        $s1 = "BCryptEncrypt"
        $s2 = ".encrypted"
        $s3 = "README.txt"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;
    
    // Crear archivo malicioso de prueba
    let test_file = temp_dir.path().join("test.exe");
    let content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\
        This ransomware uses BCryptEncrypt to encrypt files\
        It creates .encrypted files and a README.txt";
    File::create(&test_file)?.write_all(content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Escanear archivo
    let result = amaru.scan_file(&test_file).await?;
    
    // Verificar coincidencias YARA
    assert!(!result.yara_matches.is_empty());
    
    // Verificar comportamientos detectados
    assert!(result.behaviors.is_some());
    let behaviors = result.behaviors.unwrap();
    assert!(!behaviors.is_empty());
    
    // Verificar detección de ransomware
    let ransomware = behaviors.iter()
        .find(|b| matches!(b.behavior_type, MaliciousBehaviorType::Ransomware));
    assert!(ransomware.is_some());
    
    // Verificar nivel de riesgo
    assert_eq!(result.risk_level, RiskLevel::Critical);
    
    Ok(())
}

#[tokio::test]
async fn test_keylogger_detection() -> Result<(), Box<dyn std::error::Error>> {
    // Crear directorios temporales
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let quarantine_dir = temp_dir.path().join("quarantine");
    
    fs::create_dir_all(&rules_dir)?;
    
    // Crear regla YARA
    let rule_content = r#"
rule test_keylogger {
    meta:
        description = "Test keylogger detection"
    strings:
        $s1 = "SetWindowsHookEx"
        $s2 = "GetAsyncKeyState"
        $s3 = "GetKeyboardState"
    condition:
        any of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;
    
    // Crear archivo malicioso de prueba
    let test_file = temp_dir.path().join("test.exe");
    let content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\
        This keylogger uses SetWindowsHookEx and GetAsyncKeyState\
        It also calls GetKeyboardState to monitor keystrokes";
    File::create(&test_file)?.write_all(content)?;
    
    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = quarantine_dir;
    
    // Crear instancia de Amaru
    let amaru = Amaru::new(config).await?;
    
    // Escanear archivo
    let result = amaru.scan_file(&test_file).await?;
    
    // Verificar coincidencias YARA
    assert!(!result.yara_matches.is_empty());
    
    // Verificar comportamientos detectados
    assert!(result.behaviors.is_some());
    let behaviors = result.behaviors.unwrap();
    assert!(!behaviors.is_empty());
    
    // Verificar detección de keylogger
    let keylogger = behaviors.iter()
        .find(|b| matches!(b.behavior_type, MaliciousBehaviorType::Keylogger));
    assert!(keylogger.is_some());
    
    // Verificar nivel de riesgo
    assert!(result.risk_level >= RiskLevel::High);
    
    Ok(())
} 