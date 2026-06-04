# NovaSentinel v4.1 — Release Notes

**Release Date:** June 2026  
**Platform:** Windows 10/11 (64-bit)  
**Python:** 3.11+

---

## What's New in v4.1

### ✨ New Features

- **Interactive AI SOC Analyst** — Built-in chatbot powered by Ollama (local LLM). Answers questions about threats, explains phishing analysis, and can execute remediation commands directly
- **Animated Splash Screen** — Professional startup screen shown during SecurityCore initialization, with pulsing progress bar and status messages
- **Quarantine Vault** — AES-256 encrypted isolation vault with restore and permanent delete capability
- **Sandbox Analyzer** — Behavioral analysis of suspicious files in an isolated environment
- **Application Audit** — Installed application scanner with risk scoring and permission analysis
- **6 UI Themes** — Crimson Night, Cyber Blue, Emerald Dark, Royal Purple, Graphite Gray, Minimal Light
- **F-Key Navigation** — F1–F9 keyboard shortcuts for all modules (safe for text inputs)

### 🚀 Performance Improvements

- SecurityCore initialization moved to background thread — UI never freezes at startup
- Metrics polling interval raised from 1.5s to 2.0s baseline — lower CPU overhead
- Adaptive back-off: metrics loop slows down automatically when system is busy
- Interruptible sleep in metrics thread — instant shutdown response
- AI token streaming at 20 FPS max — eliminates per-token UI stutter
- Telemetry feed hash-guarded — skips rebuild when content unchanged
- Dashboard card shadow reduced from blurRadius 30→15 — halves GPU compositing cost
- ProcessManager uses cached snapshot — metrics loop is O(copy), not O(psutil scan)

### 🛡️ Security Enhancements

- Self-protection engine prevents NovaSentinel from terminating itself
- Protected infrastructure check before any process termination (python.exe, Ollama, etc.)
- System critical process guard (PID 0, 4, Windows system processes)
- 15-second cooldown on redundant real-time file scans (prevents scan storms)
- Auto-quarantine for ML confidence scores > 0.8
- AI context manager with conversation history and live telemetry snapshot binding

### 🐛 Bug Fixes

- Fixed `NameError: logger` in `dashboard_view.py` — caused silent crash in `_load_persisted_scan()`
- Fixed post-quit signal emission — CoreBridge now checks `QApplication.instance()` before emitting
- Fixed process termination race condition — `_terminating_pids` set prevents duplicate kill attempts
- Fixed phishing scan crash when result has no `__dict__` — proper `to_dict()` / `__dict__` fallback
- Fixed AI chat scroll not reaching bottom on token stream completion
- Fixed theme persistence not loading on startup in some configurations

### 📦 Packaging

- New `NovaSentinel.spec` removes `scipy`/`pandas`/`xgboost`/`lightgbm` from bundle (~40 MB saved)
- Expanded excludes list: unused Qt modules, heavy ML frameworks, stdlib dev tools
- UPX exclude list for DLLs that get corrupted by UPX compression
- Windows EXE version resource: Product name, version, copyright embedded in file properties
- Post-build cleanup: removes stray installer EXE files from `dist/_internal`
- Size target: < 400 MB folder build (down from 714 MB in previous build)

### 📚 Documentation

- Complete README rewrite with badges, feature table, quick start, architecture diagram
- MIT License added
- CONTRIBUTING.md guidelines
- Release notes (this file)
- Inline docstrings updated across all modified modules

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 4 GB | 8 GB+ |
| Storage | 800 MB free | 2 GB free |
| CPU | Dual-core 2 GHz | Quad-core 3 GHz+ |
| Privileges | Standard user | Administrator |

> **Administrator privileges** are required for:
> - Blocking IPs via Windows Firewall (netsh)
> - Terminating protected/system processes
> - Writing to protected system directories

---

## Known Limitations

- Ollama AI backend requires separate installation from https://ollama.com
- YARA rule scanning requires `yara-python` to be installed (included in bundled EXE)
- Real-time file monitoring only watches user-specified directories + common threat paths
- GPU metrics require `pynvml` (NVIDIA only); AMD/Intel GPU monitoring not yet supported
- SmartScreen warning on first launch (unsigned binary) — click "More info → Run anyway"

---

## Upgrade from v4.0

No database migration required. The `sentinelcore.db` schema is forward-compatible.

Configuration files in `config/` are preserved. Theme settings persist via `config/version.json`.

---

## Checksums (v4.1 Release)

*To be populated after official release build is signed and published.*

```
NovaSentinel-v4.1-Windows.zip   SHA256: [pending]
NovaSentinel.exe                 SHA256: [pending]
```

---

## Changelog Summary

```
v4.1.0  2026-06  Production release — AI analyst, splash screen, packaging
v4.0.0  2026-05  PyQt6 GUI, full engine integration, SecurityCore orchestrator
v3.x    2026-04  Core engine development, tkinter prototype
v2.x    2026-03  Database, ML engine, initial detection engines
v1.0    2026-02  Initial proof-of-concept
```
