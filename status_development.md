# Amaru development status

## Integration status on 2026-11-27

Amaru targets Windows 11 x64 and remains experimental. The integration work builds on `850ec7e` and is tracked in [PR #4](https://github.com/CripterHack/Amaru/pull/4). Check the run for the revision you are installing. [Windows application workflow](.github/workflows/windows-build.yml) · [Component validation](.github/workflows/validation.yml)

| Area | Implemented and exercised | Outstanding acceptance |
|---|---|---|
| Detection rules | Both classic YARA and the standalone YARA-X scanner compile the shipped catalog and pass the selected 651 EICAR variants and three negative controls. | Detection rates on representative samples, archive extraction and independent false-positive measurements. |
| Core and CLI | On-demand scans, memory and file YARA, the EICAR self-test, heuristic PE import analysis, optional Radare2 and error propagation have native tests. Fresh scans verify content before using cached results. | Representative performance measurements on Windows 11 hardware. |
| Monitor and quarantine | The service tracks actual watcher state. A matching digest and an explicit high-risk automatic policy are required to isolate a file. Restoration validates the payload and refuses to overwrite an occupied original path. | Endurance, crash recovery and permission coverage across supported Windows 11 configurations. |
| Desktop | Tauri connects the dashboard, manual scans, cancellation, history and quarantine actions to native results. The Svelte 5 frontend passed its component tests and a production dependency audit reported zero vulnerabilities. Quick scan folders persist per account. Windows Task Scheduler runs scheduled scans as the signed-in user. | Interactive acceptance and accessibility testing on supported Windows 11 editions. |
| Rules updater | Ed25519 verification and compilation of the staged catalog precede activation. A regression covers a correctly signed package containing invalid rules and preserves the installed catalog. | An operational update endpoint with a published trust key. |
| Distribution | The Windows workflow builds the core, desktop and NSIS package from a single checkout. It tests the installed software and upgrade before publishing its development artifact. | A signed release, release provenance and an installation record on Windows 11. |
| Documentation | Local Markdown links and heading anchors are checked in CI. The technical references distinguish implemented interfaces from proposed interfaces. | Keep release evidence with each version and record external service availability separately. |

### Detection and response contract

A successful per-file result carries its SHA-256 digest, risk and supporting evidence. The analyzer's lowest risk label is `Low`. A successful scan with no findings is clean for that scan. Read errors, size skips and cancellations have distinct outcomes. A desktop session aggregates file counts and findings, saves its own identifier and timestamps, and records the action taken. Quarantine is confirmed only after successful isolation.

In the experimental configuration, automatic quarantine is opt-in. When `[quarantine_config] auto_quarantine = true`, monitored files rated `High` or `Critical` are eligible. The digest must still match the bytes analyzed. Manual desktop scans report their findings. The desktop stores history and manually quarantined files under the current user account. Administrative controls access the service's separate quarantine through its Windows pipe. Restoration recovers file content. Original ACLs and filesystem attributes are outside the current archive format.

### Reproducing the results

The [EICAR corpus specification](docs/technical/eicar-corpus.md) and [YARA-X specification](docs/technical/yara-x.md) record the feedback in issues #3 and #2, the input scope and expected results. The bundled marker rules alone do not establish family-specific identification. The [Radare2 component guide](radare2-analyzer/README.md) describes the analyzer and its inputs. The [installer guide](installer/README.md) describes the package build, smoke test and retained data.

Windows CI uses Windows Server 2022 x64. For a production release, record the Windows 11 edition and build, installed revision, installer signature and checksum, service state, detection and quarantine round-trip, and upgrade/uninstall outcomes. There was no published GitHub release at the time of this review.

## Historical assessment from April 2025

The following section preserves the original design, module assessments and roadmap. Its completion labels reflect the assessment recorded in 2025. Use the dated validation record above for current test evidence.


## Project Overview
Amaru is a next-generation open-source antivirus for Windows 11 built with Rust, featuring real-time protection, YARA-based heuristic analysis, and Radare2 integration. The project aims to provide a modern, low-resource alternative to commercial antivirus solutions with transparency and customization as core values.

## Current Progress by Module

### Core Engine (src/)
- **Status**: ✅ Near Complete
- **Validation Status**: ⚠️ Partially Validated
- **Implemented Features**:
  - Core scanning engine with YARA integration
  - Behavior analysis system
  - Quarantine management
  - Configuration system
  - Event handling and notifications
  - Service management for Windows integration
- **Missing Elements**:
  - Complete integration tests
  - Performance optimizations for large-scale scans

### YARA Engine (yara-engine/)
- **Status**: ✅ Complete
- **Validation Status**: ⚠️ Pending Full Validation
- **Implemented Features**:
  - Rule compilation and management
  - File and memory scanning
  - Caching system for optimized performance
  - Rule prioritization
  - Metadata extraction and versioning

### Real-time Monitor (realtime-monitor/)
- **Status**: ✅ Complete
- **Validation Status**: ⚠️ Pending Full Validation
- **Implemented Features**:
  - File system monitoring using notify-rs
  - Configurable filters
  - Event debouncing
  - Process information collection
  - Statistics tracking

### Radare2 Analyzer (radare2-analyzer/)
- **Status**: ⚠️ Partially Complete
- **Validation Status**: ⚠️ Pending Validation
- **Implemented Features**:
  - Basic PE file analysis
  - Integration with core scanning engine
- **Missing Elements**:
  - Deep analysis of suspicious functions
  - Memory scanning capabilities
  - Behavioral pattern detection

### GUI (gui/)
- **Status**: ✅ Near Complete
- **Validation Status**: ✅ Dashboard Component Validated, ⚠️ Other Components Pending
- **Implemented Features**:
  - Tauri + Svelte frontend
  - Dashboard layout and reporting
  - Configuration interface
  - Real-time status visualization
  - Scan history display
  - User notifications system
  - Protection toggle and status display
  - Typed stores for state management
  - Resource usage monitoring
  - Event-driven scan progress updates
  - Improved error handling and messaging
  - Integration of mock data with actual API calls
  - Loading states for asynchronous operations
  - Complete toggle protection feature implementation
  - Activity log and threat monitoring with real data
  - Component testing infrastructure with Vitest and Testing Library
- **Missing Elements**:
  - Full test coverage
  - Internationalization
  - Complete accessibility implementations
- **Validation Notes**:
  - Dashboard component integration with backend successfully validated
  - Event handling and lifecycle management verified
  - Error handling patterns confirmed to be consistent
  - Unit tests implemented for Dashboard component
  - Testing infrastructure set up with Vitest and Testing Library

### Updater (updater/)
- **Status**: ⚠️ Partially Complete
- **Validation Status**: ⚠️ Pending Validation
- **Implemented Features**:
  - Basic update checking
  - YARA rule updates
- **Missing Elements**:
  - Cryptographic verification
  - Delta updates
  - Component-specific updates

### Signatures (signatures/)
- **Status**: ✅ Complete
- **Validation Status**: ⚠️ Pending Validation
- **Implemented Features**:
  - Official rule sets (malware, ransomware, trojans, etc.)
  - Custom rule infrastructure

## Validation Status and Test Plan

### Validated Areas
- ✅ Dashboard component integration with backend APIs
- ✅ Event subscription and cleanup patterns
- ✅ Error handling with proper type narrowing
- ✅ Loading states for asynchronous operations
- ✅ Tauri permission configuration
- ✅ Testing infrastructure for frontend components

### Areas Requiring Validation
- ⚠️ Other GUI components beyond Dashboard
- ⚠️ Backend API implementation completeness
- ⚠️ Cross-component event propagation
- ⚠️ Full scan workflow
- ⚠️ Protection toggle and feature toggle backend implementation

### Testing Priorities
1. **Unit Tests**:
   - Backend API endpoints
   - Event emission and handling
   - Store management in frontend
   - Component rendering and interactions

2. **Integration Tests**:
   - Full scan workflow
   - Threat detection and notification
   - Protection feature toggles
   - Cross-component communication

3. **Manual Testing Scenarios**:
   - Enable/disable protection
   - Toggle various protection features
   - Initiate scan and monitor progress
   - Simulate threat detection

### Validation Issues Identified
1. Potential mismatch between ActivityLogEntry struct in backend and frontend expectations
2. Need to verify unsubscribeActivityLog variable is properly cleaned up
3. Verify all backend APIs exist for frontend calls
4. Ensure consistent error handling between frontend and backend

## Testing Infrastructure

### Frontend Testing
- **Testing Framework**: Vitest + Testing Library for Svelte
- **Test Coverage**:
  - Component rendering tests
  - User interaction tests
  - API integration tests
  - Event handling tests
- **Mock Strategy**:
  - Mock Tauri API calls using vi.mock
  - Mock event listeners
  - Simulate user interactions with fireEvent

### Backend Testing
- **Testing Framework**: Rust's built-in testing infrastructure
- **Test Coverage**:
  - Unit tests for core functionality
  - Integration tests for workflows
  - Performance tests for critical operations
- **Test Types**:
  - Malware detection tests
  - Ransomware detection tests
  - Behavior analysis tests
  - Real-time protection tests

## Code Quality Assessment

### Strengths
- Well-structured modular architecture
- Memory-safe implementation with Rust
- Comprehensive error handling
- Good separation of concerns
- Modern async/await patterns for efficient I/O
- ✅ Type-safe TypeScript frontend
- ✅ Proper state management with Svelte stores
- ✅ Improved error handling with appropriate type narrowing
- ✅ Event-driven architecture for real-time updates
- ✅ Complete async function implementation with proper error handling
- ✅ Testing infrastructure for frontend components

### Areas for Improvement
- Documentation could be more comprehensive
- Some modules have tight coupling
- ✅ Fixed inconsistent naming conventions in frontend
- Limited test coverage
- ✅ Reduced usage of hardcoded mock data
- ✅ Improved permission model in Tauri configuration

## Recent Improvements
1. Implemented proper TypeScript typing for frontend components
2. Fixed missing backend API handlers
3. Standardized naming conventions throughout the codebase
4. Improved state management with typed Svelte stores
5. Enhanced error handling and notifications
6. Added utility functions for consistent formatting
7. Improved theme support
8. Enhanced error handling with proper type narrowing
9. Replaced mock scan functionality with actual API integration
10. Implemented event listeners for scan progress and completion
11. Connected UI elements to backend functionality
12. Improved state synchronization between components
13. Added proper cleanup for event listeners
14. Replaced hardcoded threats and activity log with API data
15. Implemented proper loading states for asynchronous operations
16. Added real backend API calls for protection features
17. Improved Tauri permission configuration for better security
18. Validated Dashboard component integration with backend
19. Added testing infrastructure with Vitest and Testing Library
20. Created component tests for Dashboard functionality

## Next Steps

1. Complete validation of remaining components and modules
2. Develop comprehensive test suite for validated areas
3. Complete backend API implementation for all frontend calls
4. Enhance Radare2 analyzer with more sophisticated PE analysis
5. Improve documentation and user guides
6. Implement internationalization support
7. Enhance accessibility features
8. Complete remaining UI-backend integrations
9. Implement comprehensive error recovery mechanisms
10. Add detailed scan reporting and export functionality
11. Implement real-time scan statistics and performance metrics
12. Add support for custom scan profiles and scheduled scans

## Staged Validation Plan

### Stage 1: Core UI Components (Current Focus)
- Dashboard component (✅ Completed)
- Navigation and layout structure
- Notifications system
- Theme system

### Stage 2: Frontend-Backend Integration
- API contract validation
- Event system validation
- Permission model verification
- Error handling patterns

### Stage 3: Core Engine Functionality
- Scanning functionality
- Protection mechanisms
- Threat detection
- Quarantine system

### Stage 4: Additional Features
- Update system
- Settings and configuration
- Reporting and analytics
- Custom scan profiles

### Stage 5: Performance and Security
- Resource usage optimization
- Security model validation
- Penetration testing
- Performance benchmarking

## Conclusion

The Amaru project has made significant progress with most core components implemented and validation efforts underway. We've established a robust testing infrastructure for the frontend components using Vitest and Testing Library, with initial tests for the Dashboard component already implemented.

Recent improvements have enhanced the integration between frontend and backend systems, replacing hardcoded mock data with real API calls and implementing proper event handling for real-time updates. The Dashboard component has been validated to provide accurate, live data with appropriate loading states and error handling.

Our validation process now includes a structured approach with staged validation plans and clear testing priorities. We've also improved the security model with a more restrictive permission configuration in Tauri. The project continues to move toward a stable release, with focus on completing validation of remaining components, enhancing the testing infrastructure, and improving documentation. 