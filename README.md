# Amaru: Next Generation Antivirus 🛡️

<p align="center">
  <img src="amaru-app.png" alt="Amaru Logo" width="512" height="512"/>
</p>

> ⚠️ **Warning**: By now this is an experimental, in-progress version of Amaru Antivirus. It is currently under active development and should not be used in production environments. Features may be incomplete, unstable or subject to significant changes. Use at your own risk.

Origin: Mythological Inca serpent that guards treasures.  
Analogy: Coils around and neutralizes threats.

**Open-source antivirus for Windows 11 with real-time scanning, YARA rules, Radare2 integration, and Rust-powered efficiency.**

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
![Windows 11 Support](https://img.shields.io/badge/Windows-11-0078D4?logo=windows)
[![Validation](https://github.com/CripterHack/Amaru/actions/workflows/validation.yml/badge.svg)](https://github.com/CripterHack/Amaru/actions/workflows/validation.yml)

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

These features define the Windows 11 product scope. Implementation and validation progress vary by component. See the [development status](status_development.md).

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

### Minimum Requirements
- Windows 11 (64-bit)
- 4GB RAM
- 1GB free disk space
- Admin privileges for real-time protection

### Recommended Requirements
- Windows 11 (64-bit, version 22H2 or later)
- 8GB RAM
- 2GB free disk space
- SSD storage
- Admin privileges

### Developer Requirements
- Rust MSVC toolchain with support for Cargo lockfile format 4
- Node.js 18 or later (for UI development)
- Visual Studio Build Tools with C++ workload
- Git for Windows

---

## 📥 Installation

### Release availability

As of 2026-11-27 the project has no published GitHub release. The source tree includes an installer and a packaged executable from earlier development. Their provenance and behavior on Windows 11 still need validation before distribution. Check the [Releases page](https://github.com/CripterHack/Amaru/releases) for versioned downloads.

### Developer Installation
1. **Install Rust:**
   ```powershell
   winget install Rustlang.Rust.MSVC
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

3. **Clone the project and check the build on Windows 11.** The workspace and GUI use separate build commands. A successful build of the complete Windows application is pending.
   ```powershell
   git clone https://github.com/CripterHack/Amaru.git
   cd Amaru
   
   # Build backend
   cargo build --locked --release
   
   # Build GUI
   cd gui
   npm ci
   npm run build
   
   cd ..
   ```

4. **Review the configuration.** The core reads the repository's [config.toml](config.toml) by default.

5. **Run the examples once the backend builds.**
   ```powershell
   # Run the EICAR test file detection example
   cargo run --example eicar_detection
   
   # Run other examples
   cargo run --example use_core_services
   ```

---

## 🚀 Usage

### GUI Interface
The intended desktop workflow on Windows 11 has three steps.

1. Launch Amaru from the Start menu or desktop shortcut.
2. Use the dashboard to view protection status and recent events.
3. Schedule scans and configure protection settings through the Settings page.

### Command Line Interface
The CLI declares the following interfaces for scanning and service management. Dispatch from the application entry point is pending. These examples document the intended syntax. See [src/main.rs](src/main.rs).

```powershell
# Scan a specific file
amaru scan --path C:\path\to\file.exe

# Scan a directory recursively
amaru scan --path C:\Users\Documents --recursive

# Enable real-time protection
amaru monitor --action start

# Update YARA rules
amaru update --rules

# Analyze a suspicious file with detailed reporting
amaru analyze --file C:\suspicious\file.exe --radare2 --heuristic

# Check service status
amaru service --action status
```

The bundled rules are in [signatures/official](signatures/official) and [signatures/custom](signatures/custom). For an on-demand scan with the optional YARA-X tool, see the [command, output and exit codes](docs/technical/yara-x.md).

The planned `amaru test-eicar` command still needs CLI integration. The existing [EICAR example](examples/eicar_detection.rs) and [corpus specification](docs/technical/eicar-corpus.md) describe the detection checks.

### Windows Service
The service interface specifies the following administrator commands. Installation, startup and status reporting still require end-to-end verification on Windows 11.

```powershell
# Install the service (admin privileges required)
amaru service --action install

# Start the service
amaru service --action start

# Stop the service
amaru service --action stop

# Check service status
amaru service --action status
```

### Scheduling
The planned scheduler supports daily and weekly scans. The following examples specify its proposed CLI syntax. The current command parser has no `schedule` subcommand.

```powershell
# Schedule a daily scan at 3 AM
amaru schedule --daily --time "03:00" --path "C:\Users"

# Schedule a weekly scan on Sundays
amaru schedule --weekly --day Sunday --time "02:00" --path "C:\"
```

---

## 🛡️ Security Features

The following protection capabilities describe the design scope. End-to-end validation on Windows 11 is pending.

### Real-time Protection
- **File System Monitoring:** Detects and scans files as they're created or modified
- **Process Behavior Analysis:** Monitors process activities for suspicious behavior
- **Network Traffic Inspection:** Integrates with Windows Filtering Platform
- **Executable Analysis:** Deep inspection of PE files before execution

### Scanning Capabilities
- **Signature-Based Detection:** Using YARA rules and ClamAV databases
- **Heuristic Analysis:** Detects suspicious patterns and behaviors
- **Memory Scanning:** Examines process memory for hidden threats
- **Static Analysis:** Uses Radare2 to analyze executable structure and behavior
- **EICAR Test Detection:** Recognizes the EICAR test file for antivirus validation

### Advanced Protection
- **Quarantine System:** Safely isolates detected threats
- **Behavioral Blocking:** Prevents suspicious activities in real-time
- **Reputation Checking:** Verifies file reputation against known safe files
- **Rootkit Detection:** Identifies hidden and privileged malware

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
```powershell
# Install dev tools
cargo install cargo-watch cargo-audit

# Run tests
cargo test --all

# Development mode
cd gui
npm run dev
```

### Building from Source
```powershell
# Build release version
cargo build --locked --release

# Inspect the available workspace targets
cargo metadata --no-deps --format-version 1

# Run tests
cargo test --all

# Build documentation
cargo doc --open
```

The Windows installer has its own NSIS build process and requires a validated application executable. See the [installer instructions](installer/README.md).

### Testing

For a cross-platform check of the shipped signatures, run the standalone [YARA and YARA-X corpus tests](docs/technical/eicar-corpus.md). Windows integration targets are exercised separately with Cargo.

```powershell
# Run unit tests
cargo test

# Run integration tests
cargo test --workspace --tests

# Run specific test
cargo test --test amaru_core_tests
```

### Debugging
```powershell
# Enable debug logging
$env:RUST_LOG="debug,amaru=trace"
cargo run

# Run with performance profiling
cargo run --features profile_allocation
```

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

## 💬 Support and Community
- [Open an issue](https://github.com/CripterHack/Amaru/issues) for bug reports or feature requests

## 🔄 Contributing
To propose a change, describe the expected behavior and how you will verify it in a [project issue](https://github.com/CripterHack/Amaru/issues). Include the actual checks and their results in the pull request. See the [contribution guidelines](CONTRIBUTING.md).

---

*Disclaimer: Amaru is a community project and is not affiliated with or endorsed by ClamAV or Cisco Talos.*
