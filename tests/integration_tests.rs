mod support;
use amaru::{Amaru, Config, RiskLevel, MaliciousBehaviorType, BehaviorAnalyzer};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;
use tokio;
use std::time::Instant;

#[tokio::test]
async fn test_malware_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear regla YARA para detectar malware
    let rule_content = r#"
rule test_malware {
    meta:
        description = "Test malware detection"
        threat_level = 3
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAllocEx"
        $c = "WriteProcessMemory"
    condition:
        2 of them
}
"#;
    fs::write(rules_dir.join("test.yar"), rule_content)?;

    // Crear archivo malicioso de prueba
    let malware_file = temp_dir.path().join("test_malware.exe");
    let malware_content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        CreateRemoteThread\x00\
        VirtualAllocEx\x00\
        WriteProcessMemory\x00\
    ";
    File::create(&malware_file)?.write_all(&support::import_fixture(support::INJECTION, malware_content))?;

    // Configurar y crear instancia de Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&malware_file, true, false).await?;

    // Verificar detección
    assert!(result.risk_level >= RiskLevel::High);
    assert!(!result.yara_matches.is_empty());
    assert!(result.behaviors.as_ref().map_or(false, |b| !b.is_empty()));

    Ok(())
}

#[tokio::test]
async fn test_ransomware_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear regla YARA para detectar ransomware
    let rule_content = r#"
rule test_ransomware {
    meta:
        description = "Test ransomware detection"
        threat_level = 5
    strings:
        $a = "CryptEncrypt"
        $b = "BCryptEncrypt"
        $c = "vssadmin.exe delete shadows"
    condition:
        2 of them
}
"#;
    fs::write(rules_dir.join("ransomware.yar"), rule_content)?;

    // Crear archivo de prueba con comportamiento de ransomware
    let ransomware_file = temp_dir.path().join("test_ransomware.exe");
    let ransomware_content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        CryptEncrypt\x00\
        BCryptEncrypt\x00\
        vssadmin.exe delete shadows\x00\
    ";
    File::create(&ransomware_file)?.write_all(&support::import_fixture(&[support::ENCRYPTION, support::PERSISTENCE].concat(), ransomware_content))?;

    // Configurar y crear instancia de Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&ransomware_file, true, false).await?;

    // Verificar detección de ransomware
    assert_eq!(result.risk_level, RiskLevel::Critical);
    assert!(result.behaviors.as_ref().map_or(false, |b| 
        b.iter().any(|behavior| matches!(behavior.behavior_type, MaliciousBehaviorType::Ransomware))
    ));

    Ok(())
}

#[tokio::test]
async fn test_realtime_protection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    let monitored_dir = temp_dir.path().join("monitored");
    fs::create_dir_all(&rules_dir)?;
    fs::create_dir_all(&monitored_dir)?;

    // Crear regla YARA
    let rule_content = r#"
rule test_realtime {
    meta:
        description = "Test realtime detection"
    strings:
        $a = "malicious_content"
    condition:
        $a
}
"#;
    fs::write(rules_dir.join("realtime.yar"), rule_content)?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.monitored_paths = vec![monitored_dir.clone()];
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let mut amaru = Amaru::new(config).await?;
    let receiver = amaru.event_receiver();
    
    // Habilitar protección en tiempo real
    amaru.enable_realtime_protection().await?;

    // Crear archivo malicioso
    let malicious_file = monitored_dir.join("test_realtime.exe");
    File::create(&malicious_file)?.write_all(b"malicious_content")?;

    // Esperar eventos
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verificar eventos
    let mut threats_detected = false;
    while let Ok(event) = receiver.try_recv() {
        if let amaru::Event::ThreatDetected { .. } = event {
            threats_detected = true;
            break;
        }
    }

    assert!(threats_detected, "No se detectaron amenazas en tiempo real");

    // Deshabilitar protección
    amaru.disable_realtime_protection().await?;

    Ok(())
}

#[tokio::test]
async fn test_behavior_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear archivo con múltiples comportamientos maliciosos
    let malicious_file = temp_dir.path().join("test_behavior.exe");
    let content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        VirtualAllocEx\x00\
        WriteProcessMemory\x00\
        CreateRemoteThread\x00\
        RegSetValueEx\x00\
        CurrentVersion\\Run\x00\
        IsDebuggerPresent\x00\
        GetAsyncKeyState\x00\
        InternetOpen\x00\
        WSASend\x00\
    ";
    File::create(&malicious_file)?.write_all(&support::import_fixture(&[support::INJECTION, support::PERSISTENCE, support::ENVIRONMENT, support::KEY_INPUT, support::NETWORK].concat(), content))?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&malicious_file, true, false).await?;

    // Verificar detección de comportamientos
    let behaviors = result.behaviors.as_ref().expect("No se detectaron comportamientos");
    
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::SystemPersistence)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Keylogger)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DataExfiltration)));

    Ok(())
}

#[tokio::test]
async fn test_concurrent_scanning() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear regla YARA
    let rule_content = r#"
rule test_concurrent {
    meta:
        description = "Test concurrent scanning"
    strings:
        $a = "test_content"
    condition:
        $a
}
"#;
    fs::write(rules_dir.join("concurrent.yar"), rule_content)?;

    // Crear múltiples archivos de prueba
    let mut files = Vec::new();
    for i in 0..10 {
        let file_path = temp_dir.path().join(format!("test_{}.exe", i));
        File::create(&file_path)?.write_all(b"test_content")?;
        files.push(file_path);
    }

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;

    // Escanear archivos concurrentemente
    let mut handles = Vec::new();
    for file in files {
        let amaru_clone = amaru.clone();
        let handle = tokio::spawn(async move {
            amaru_clone.scan_file(file).await
        });
        handles.push(handle);
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
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Configurar Amaru con reglas inválidas
    let invalid_rule = r#"
rule invalid {
    strings:
        $a = "test
    condition:
        $a
}
"#;
    fs::write(rules_dir.join("invalid.yar"), invalid_rule)?;

    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    // Verificar error en la inicialización
    let result = Amaru::new(config).await;
    assert!(result.is_err());

    // Verificar error al escanear archivo inexistente
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file("nonexistent_file.exe").await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_pe_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = BehaviorAnalyzer::new();

    // Crear archivo PE con secciones sospechosas
    let sections = vec![
        ("UPX0".to_string(), 7.8),
        (".text".to_string(), 6.5),
        (".vmp0".to_string(), 7.9),
        ("encrypt".to_string(), 7.7),
    ];

    let resources = vec![
        "payload.exe".to_string(),
        "config.dat".to_string(),
        "dropper.dll".to_string(),
        "script.vbs".to_string(),
    ];

    // Analizar secciones
    let section_behaviors = analyzer.analyze_sections_optimized(&sections,"sample-sections").await;
    assert!(!section_behaviors.is_empty());
    assert!(section_behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Packing) && b.evidence.contains_key("high_entropy_sections")));

    // Verificar caché de secciones
    let cached_sections = analyzer.analyze_sections_optimized(&sections,"sample-sections").await;
    assert_eq!(section_behaviors, cached_sections);

    // Analizar recursos
    let resource_behaviors = analyzer.analyze_resources(&resources,"sample-resources").await;
    assert!(!resource_behaviors.is_empty());
    assert!(resource_behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion)));

    // Verificar caché de recursos
    let cached_resources = analyzer.analyze_resources(&resources,"sample-resources").await;
    assert_eq!(resource_behaviors, cached_resources);

    Ok(())
}

#[tokio::test]
async fn test_behavior_correlations() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear archivo con comportamientos correlacionados
    let malicious_file = temp_dir.path().join("test_correlation.exe");
    let content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        VirtualAllocEx\x00\
        WriteProcessMemory\x00\
        CreateRemoteThread\x00\
        WSAConnect\x00\
        InternetOpen\x00\
        IsDebuggerPresent\x00\
        CryptEncrypt\x00\
        RegSetValueEx\x00\
        CurrentVersion\\Run\x00\
    ";
    File::create(&malicious_file)?.write_all(&support::import_fixture(&[support::INJECTION, support::NETWORK, support::ENVIRONMENT, support::ENCRYPTION, support::PERSISTENCE].concat(), content))?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&malicious_file, true, false).await?;

    // Verificar detección de comportamientos correlacionados
    let behaviors = result.behaviors.as_ref().expect("No se detectaron comportamientos");
    
    // Verificar APT
    assert!(behaviors.iter().any(|b| 
        matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion) &&
        b.description.contains("APT")
    ));

    // Verificar ransomware avanzado
    assert!(behaviors.iter().any(|b| 
        matches!(b.behavior_type, MaliciousBehaviorType::Ransomware) &&
        b.description.contains("Advanced ransomware")
    ));

    Ok(())
}

#[tokio::test]
async fn test_advanced_evasion_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear archivo con técnicas avanzadas de evasión
    let evasive_file = temp_dir.path().join("test_evasion.exe");
    let content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        IsDebuggerPresent\x00\
        CheckRemoteDebuggerPresent\x00\
        OutputDebugString\x00\
        NtSetInformationProcess\x00\
        ZwSetInformationThread\x00\
        GetTickCount\x00\
        QueryPerformanceCounter\x00\
        GetSystemTime\x00\
        vmware.exe\x00\
        vbox.exe\x00\
    ";
    File::create(&evasive_file)?.write_all(&support::import_fixture(support::ENVIRONMENT, content))?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&evasive_file, true, false).await?;

    // Verificar detección de evasión avanzada
    let behaviors = result.behaviors.as_ref().expect("No se detectaron comportamientos");
    
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::AntiDebug)));
    assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::AntiVM)));

    Ok(())
}

#[tokio::test]
async fn test_advanced_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear archivo con múltiples mecanismos de persistencia
    let persistence_file = temp_dir.path().join("test_persistence.exe");
    let content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        RegSetValueEx\x00\
        CurrentVersion\\Run\x00\
        CreateService\x00\
        schtasks.exe\x00\
        HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00\
        HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\x00\
        Shell32.dll\x00\
        StartupItems\x00\
    ";
    File::create(&persistence_file)?.write_all(&support::import_fixture(support::PERSISTENCE, content))?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&persistence_file, true, false).await?;

    // Verificar detección de persistencia avanzada
    let behaviors = result.behaviors.as_ref().expect("No se detectaron comportamientos");
    
    let persistence_behaviors: Vec<_> = behaviors.iter()
        .filter(|b| matches!(b.behavior_type, MaliciousBehaviorType::SystemPersistence))
        .collect();

    assert!(!persistence_behaviors.is_empty());
    assert!(persistence_behaviors.iter().any(|b| b.confidence >= 80));

    Ok(())
}

#[tokio::test]
async fn test_command_and_control() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempdir()?;
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Crear archivo con comportamientos de C&C
    let cnc_file = temp_dir.path().join("test_cnc.exe");
    let content = b"\
        MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
        InternetOpen\x00\
        InternetConnect\x00\
        HttpSendRequest\x00\
        WSAConnect\x00\
        DnsQuery\x00\
        getaddrinfo\x00\
        SSL_write\x00\
        PR_Write\x00\
        URLDownloadToFile\x00\
    ";
    File::create(&cnc_file)?.write_all(&support::import_fixture(support::NETWORK, content))?;

    // Configurar Amaru
    let mut config = Config::default();
    config.yara_rules_path = rules_dir;
    config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

    let amaru = Amaru::new(config).await?;
    let result = amaru.scan_file_with_options(&cnc_file, true, false).await?;

    // Verificar detección de C&C
    let behaviors = result.behaviors.as_ref().expect("No se detectaron comportamientos");
    
    let cnc_behaviors: Vec<_> = behaviors.iter()
        .filter(|b| matches!(b.behavior_type, MaliciousBehaviorType::CommandAndControl))
        .collect();

    assert!(!cnc_behaviors.is_empty());
    assert!(cnc_behaviors.iter().any(|b| b.confidence >= 70));

    Ok(())
}

#[tokio::test]
async fn test_pe_analysis_performance() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = BehaviorAnalyzer::new();
    let files: Vec<_> = (0..100u8).map(|i| support::import_fixture(support::INJECTION, &[i])).collect();
    let start = Instant::now();
    for bytes in &files {
        let result = analyzer.analyze_optimized(bytes, "")?;
        assert!(result.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection)));
    }
    assert!(start.elapsed().as_secs() < 10);
    let first = analyzer.analyze_optimized(&files[0], "")?;
    assert_eq!(first, analyzer.analyze_optimized(&files[0], "")?);
    let (hits, misses, _, _) = analyzer.get_stats();
    assert_eq!((hits, misses), (2, 100));
    Ok(())
}
