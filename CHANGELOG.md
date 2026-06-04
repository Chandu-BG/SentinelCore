# Changelog

All notable changes to NovaSentinel are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.1.0] — 2026-06-04

### Added
- **Interactive AI SOC Analyst** — built-in chatbot powered by Ollama (local LLM); answers threat questions, explains phishing analysis, executes remediation commands from natural language
- **Animated Splash Screen** — cinematic startup screen with pulsing progress bar and rotating status messages during SecurityCore initialization
- **Quarantine Vault** — AES-256-CBC encrypted isolation vault; supports restore and permanent delete with checksum verification
- **Sandbox Analyzer** — behavioral analysis of suspicious files in isolated environment; reports file writes, process spawns, registry changes
- **Application Audit view** — installed application scanner with risk scoring, permission analysis, and publisher verification
- **F-Key navigation** — F1–F9 keyboard shortcuts for all modules, safe for use inside text input fields
- **6 built-in UI themes** — Crimson Night (default), Cyber Blue, Emerald Dark, Royal Purple, Graphite Gray, Minimal Light
- **CoreBridge adaptive metrics loop** — automatic back-off when system is under load; watchdog restarts if loop stalls >15s
- **Process termination safeguards** — protected infrastructure list prevents killing Python, Ollama, or NovaSentinel itself
- **SECURITY.md** — responsible disclosure policy and known security considerations
- **CHANGELOG.md** — this file

### Changed
- Settings view fully expanded with About card, feature grid, keyboard shortcut reference, and styled permission toggles
- Metrics polling interval raised from 1.5 s to 2.0 s baseline — reduces continuous CPU overhead
- AI token streaming capped at 20 FPS — eliminates per-token UI stutter on slow hardware
- Dashboard card shadow `blurRadius` reduced 30→15 — halves GPU compositing cost
- Logs view refresh reduced to every 2 s (was 1 s); incremental hash-guarded row update avoids full repaints
- ProcessManager uses atomic snapshot swap — main lock held only during final list assignment
- Scan view uses 25 FPS batch drain timer — findings processed in groups of 8 per tick, never blocking the event loop
- Performance graphs run at 15 FPS only when the view is visible (`showEvent`/`hideEvent` guards)
- `pynvml` FutureWarning permanently suppressed; `nvidia-ml-py` preferred over deprecated `pynvml`

### Fixed
- `NameError: logger` in `dashboard_view.py` — caused silent crash in `_load_persisted_scan()`
- Post-quit signal emission — CoreBridge checks `QApplication.instance()` before emitting metrics signals
- Process termination race condition — `_terminating_pids` set prevents duplicate kill attempts
- Phishing scan crash when result object has no `__dict__` — proper `to_dict()` / `__dict__` fallback chain
- AI chat scroll not reaching bottom on streaming completion
- Theme persistence not loading on startup in some configurations
- `_fetch_logs_stub` dead code removed from `MainWindow` — LogsView uses TelemetryManager directly
- `python311.dll` hardcoded UPX exclude replaced with dynamic Python version string

### Removed
- One-file portable EXE section from `NovaSentinel.spec` — was producing a 595 MB bloated bundle with slow startup
- Unused `fetch_logs_fn` parameter from `LogsView` constructor
- Unused `List` import from `main_window.py`
- `convert_*.py` migration scripts (no longer needed; excluded from tracking)

### Security
- Quarantine vault uses PBKDF2-HMAC-SHA256 with 480,000 iterations for key derivation
- Self-protection engine detects tampering with NovaSentinel's own process
- System critical process guard prevents accidental termination of LSASS, CSRSS, SMSS, and other protected Windows processes
- 15-second cooldown on real-time file scan events prevents scan storms from high-frequency writes

---

## [4.0.0] — 2026-05

### Added
- Full PyQt6 GUI with QStackedWidget view navigation and custom QSS theming
- SecurityCore central orchestrator with 35 detection engines
- CoreBridge thread-safe signal relay between SecurityCore and GUI
- Real-time performance graphs (pyqtgraph) for CPU, RAM, Disk, and Network
- Phishing Intelligence Center with circular gauge risk visualization
- YARA rule scanning integration
- ML anomaly detection (scikit-learn IsolationForest)

---

## [3.x] — 2026-04

### Added
- Core engine development phase
- Initial tkinter prototype (later replaced with PyQt6)
- Ransomware detection engine
- Network threat monitoring
- Process injection detector

---

## [2.x] — 2026-03

### Added
- SQLite database schema
- ML training pipeline
- Initial detection engines

---

## [1.0.0] — 2026-02

### Added
- Initial proof-of-concept — basic file scanning and threat reporting

---

[4.1.0]: https://github.com/Chandu-BG/SentinelCore/releases/tag/v4.1.0
[4.0.0]: https://github.com/Chandu-BG/SentinelCore/releases/tag/v4.0.0
