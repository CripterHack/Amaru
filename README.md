# Amaru: Next Generation Antivirus 🛡️

<p align="center">
  <img src="amaru-app.png" alt="Amaru Logo" width="512" height="512"/>
</p>

Origin: Mythological Inca serpent that guards treasures.  
Analogy: Coils around and neutralizes threats.

**Open-source antivirus for Windows 11 with real-time scanning, YARA rules, Radare2 integration, and Rust-powered efficiency.**

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
![Windows 11 Support](https://img.shields.io/badge/Windows-11-0078D4?logo=windows)
![Build Status](https://img.shields.io/github/workflow/status/CripterHack/Amaru/CI)
![Version](https://img.shields.io/github/v/release/CripterHack/Amaru)

---

## 📖 Overview
Amaru is a community-driven fork of ClamWin, supercharged with modern malware detection capabilities:
- **Real-time protection** via Rust-native file monitoring
- **Heuristic analysis** using YARA rules and Radare2 static analysis
- **Low resource consumption** thanks to Rust-optimized modules
- **Modern UI** built with Tauri + Svelte + TailwindCSS

Designed for users who value transparency, customization, and Windows 11 compatibility.

---

## ✨ Key Features
| **Feature**               | **Technology**          | **Description**                                      |
|--------------------------|-------------------------|---------------------------------------------------|
| Real-Time File Monitoring | `notify-rs` + ClamAV    | Watches file changes and scans instantly            |
| YARA Rule Engine         | YARA 4.3+              | Detects malware patterns with custom/signed rules   |
| Static Analysis          | Radare2                | Examines PE headers, sections, and suspicious strings|
| Low-Level Performance    | Rust                   | Memory-safe modules for scanning and hooks          |
| Windows 11 Integration   | WinAPI + WFP           | Native kernel-level file filtering                 |
| Modern UI               | Tauri + Svelte         | Responsive and efficient user interface            |

---

## 🛠️ System Requirements
- Windows 11 (64-bit)
- 4GB RAM minimum (8GB recommended)
- 1GB free disk space
- Admin privileges for real-time protection

## 📥 Installation

### Prerequisites
1. **Install Rust:**
   ```powershell
   winget install Rustlang.Rust.MSVC
   rustup toolchain install nightly
   rustup default nightly
   ```

2. **Install Dependencies:**
   ```powershell
   # Install Radare2
   winget install radare.radare2
   
   # Install YARA (4.3+)
   # Download from https://github.com/VirusTotal/yara/releases
   
   # For UI development
   winget install OpenJS.NodeJS.LTS
   ```

### Build Steps
1. **Clone and Build:**
   ```bash
   git clone https://github.com/CripterHack/Amaru.git
   cd Amaru
   
   # Build backend
   cargo build --release
   
   # Build GUI
   cd gui
   npm install
   npm run build
   ```

2. **Configure:**
   ```bash
   copy .env.example .env
   # Edit .env with your settings
   ```

---

## 🚀 Usage

### Basic Commands
```bash
# On-demand scan
amaru scan <path>

# Enable real-time protection
amaru protect --enable

# Update YARA rules
amaru update-rules

# Launch GUI
amaru gui
```

### Security Features
- **Real-time Protection:**
  - Kernel-level file system monitoring
  - Process behavior analysis
  - Network traffic inspection (WFP integration)

- **Scanning Capabilities:**
  - YARA pattern matching
  - PE file analysis with Radare2
  - Memory scanning
  - Rootkit detection

- **Update System:**
  - Automatic signature updates
  - Ed25519 cryptographic verification
  - Rollback capability
  - Delta updates for efficiency

---

## 📂 Project Structure
```
amaru/
├── src/                 # Core Rust implementation
├── gui/                 # Tauri + Svelte frontend
├── yara-engine/        # YARA integration
├── radare2-analyzer/   # Static analysis tools
├── realtime-monitor/   # File system monitor
├── updater/           # Update system
├── signatures/        # YARA rules
├── installer/         # Windows installer
└── docs/             # Documentation
```

## 🔧 Development

### Setup Development Environment
```bash
# Install dev tools
cargo install cargo-watch cargo-audit

# Run tests
cargo test --all

# Development mode
cd gui
npm run dev
```

### Security Considerations
- All updates are cryptographically signed
- Privilege separation for different components
- Memory-safe implementation in Rust
- Regular security audits
- CVE monitoring and rapid response

---

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style
- Follow Rust style guidelines
- Use clippy for linting
- Document public APIs
- Include tests for new features

---

## 📜 License
This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments
- [ClamWin](http://www.clamwin.com/) - Original project
- [YARA](https://virustotal.github.io/yara/) - Pattern matching engine
- [Radare2](https://rada.re/n/) - Reverse engineering framework
- [Tauri](https://tauri.app/) - GUI framework
- [Svelte](https://svelte.dev/) - UI library
- [TailwindCSS](https://tailwindcss.com/) - Styling system

## 💬 Support
- [Open an issue](https://github.com/CripterHack/Amaru/issues)
- [Documentation](https://amaru.readthedocs.io/)
- [Community Forum](https://forum.amaru.dev)

---

*Disclaimer: Amaru is a community project and is not affiliated with or endorsed by ClamAV or Cisco Talos.*
