<p align="center">
  <img src="Amaru-logo.svg" alt="Aproxima Logo" width="512" height="512"/>
</p>

# Amaru: Next Generation Antivirus 🛡️  

Origin: Mythological Inca serpent that guards treasures.
Analogy: Coils and neutralizes threats.

**Open-source antivirus for Windows 11 with real-time scanning, YARA rules, Radare2 integration, and Rust-powered efficiency.**  

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)  
![Windows 11 Support](https://img.shields.io/badge/Windows-11-0078D4?logo=windows)  

---

## 📖 Overview  
Amaru is a community-driven fork of ClamWin, supercharged with modern malware detection capabilities:  
- **Real-time protection** via Rust-native file monitoring.  
- **Heuristic analysis** using YARA rules and Radare2 static analysis.  
- **Low resource consumption** thanks to Rust-optimized modules.  

Designed for users who value transparency, customization, and Windows 11 compatibility.  

---

## 🚧 Current Development Status

| **Module**              | **Status**            | **Description**                                      |  
|-------------------------|----------------------|------------------------------------------------------|  
| YARA Engine             | ✅ Simplified        | Basic implementation without native dependencies      |  
| Real-Time Monitor       | ✅ Functional        | File system monitoring with event handling           |  
| Radare2 Analyzer        | ✅ Implemented       | Static analysis with behavior detection              |  
| CLI Interface           | ✅ Operational       | Command-line tools for all features                  |  
| Service Management      | ✅ Implemented       | Windows service control functionality                |  
| Update System           | ✅ Basic             | YARA rules and ClamAV database updates               |  
| GUI                     | 🔄 Pending           | Graphical interface planned for future release       |  

---

## ✨ Key Features  
| **Feature**               | **Technology**          | **Description**                                      |  
|---------------------------|-------------------------|------------------------------------------------------|  
| Real-Time File Monitoring | Rust + FileSystem Events| Watches file changes and scans instantly.            |  
| YARA Rule Engine          | Custom Implementation   | Detects malware patterns with simple rules.          |  
| Static Analysis           | Radare2                 | Examines PE headers, sections, and suspicious strings.|  
| Low-Level Performance     | Rust                    | Memory-safe modules for scanning and hooks.          |  
| Windows 11 Integration    | WinAPI + System Services| Native service integration.                          |  

---

## 🛠️ Installation  

### Prerequisites  
- **Rust** (v1.70+): [Install Guide](https://www.rust-lang.org/tools/install)  
- **Radare2** (Windows build): [Download](https://radare.mikelloc.com/)  

### Steps  
1. Clone the repository:  
   ```bash
   git clone https://github.com/CripterHack/Amaru.git
   cd Amaru
   ```

2. Install Rust (if not already installed):
   ```powershell
   .\rustup-init.exe
   ```
   - Follow the on-screen instructions
   - Restart your terminal after installation

3. Build the project:  
   ```bash
   cargo build --release
   ```

4. Install the application:
   ```bash
   cargo install --path .
   ```

---

## 🚀 Usage  

### Basic Commands  
| Command                                   | Description                                 |  
|-------------------------------------------|---------------------------------------------|  
| `amaru scan --path C:\`                   | Scan a directory                            |  
| `amaru scan --path file.exe --radare2`    | Scan with additional Radare2 analysis       |  
| `amaru analyze --file suspect.exe`        | Analyze a file with Radare2                 |  
| `amaru monitor --action start`            | Start real-time monitoring                  |  
| `amaru monitor --action stop`             | Stop real-time monitoring                   |  
| `amaru monitor --action status`           | Check monitoring status                     |  
| `amaru update --rules`                    | Update YARA rules                           |  
| `amaru update --clamav`                   | Update ClamAV database                      |  
| `amaru reload --rules`                    | Reload YARA rules                           |  
| `amaru service --action install`          | Install Amaru as a Windows service          |  
| `amaru service --action uninstall`        | Uninstall the Windows service               |  
| `amaru service --action start`            | Start the Windows service                   |  
| `amaru service --action stop`             | Stop the Windows service                    |  
| `amaru service --action status`           | Check Windows service status                |  

### Custom YARA Rules  
1. Add rules to `signatures/custom/your_rule.yar`.  
2. Reload the engine:  
   ```powershell
   amaru reload --rules
   ```

### Radare2 Analysis Integration  
```bash
amaru analyze --file suspect.exe
# Output: PE sections, imports, suspicious strings, risk score, and behaviors.
```

---

## 📂 Project Structure  
```  
amaru/  
├── clamwin/           # ClamAV database and integration  
├── yara-engine/       # Simplified YARA implementation  
├── realtime-monitor/  # File system watcher (Rust)  
├── radare2-analyzer/  # Static analysis integration  
├── signatures/        # YARA rules directory  
│   ├── official/      # Built-in/default rules  
│   └── custom/        # User-defined rules  
└── src/               # Main application code  
```

---

## 📝 Next Steps for Development

### Short-term Goals
1. **GUI Development**: Create a user-friendly interface
2. **Enhanced Detection**: Improve YARA rules for better detection rates
3. **Full YARA Integration**: Integrate with native YARA when available
4. **Advanced Behavior Analysis**: Expand radare2 analysis capabilities
5. **Installer Package**: Create an easy-to-use installer

### Medium-term Goals
1. **Cloud Reputation Checking**: Integration with threat intelligence
2. **Sandbox Analysis**: Implement behavior-based detection
3. **Cross-platform Support**: Extend to Linux and macOS
4. **Plugin System**: Create an extensible architecture

---

## 🤝 Contributing  
We welcome PRs! Follow these steps:  
1. Fork the repository.  
2. Create a feature branch: `git checkout -b feat/your-feature`.  
3. Adhere to the [Rust Coding Style](https://github.com/rust-lang/rfcs/blob/master/style-guide/README.md).  
4. Submit a PR with tests and documentation.  

### Funding  
Support us via:  
- [GitHub Sponsors](https://github.com/sponsors/CripterHack)  
- [Open Collective](https://opencollective.com/Amaru)  

---

## 📜 License  
GNU GPLv2. See [LICENSE](LICENSE) for details.  

---

## 🙌 Acknowledgments  
- Original [ClamWin](https://github.com/clamwin/clamwin) Team.  
- VirusTotal for [YARA](https://github.com/VirusTotal/yara).  
- Radare2 community for the reverse-engineering framework.  
- Rust contributors for memory-safe systems programming.  

---

*Disclaimer: Amaru is a community project. It is not endorsed by Cisco Talos or the official ClamAV team.*

### 📌 Next Steps  
1. Customize the `