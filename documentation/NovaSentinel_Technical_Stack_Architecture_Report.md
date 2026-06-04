# NovaSentinel Technical Stack & Architecture Report

---

## 1. Project Overview

**NovaSentinel** is a local, high-fidelity endpoint protection system for Windows desktop hosts. It combines multi-threaded host file scans, offline machine learning classification, structural pattern matching (YARA rules), and local explainable Artificial Intelligence (AI) to protect systems without relying on external cloud dependencies.

### Main Purpose
To provide host-isolated threat detection, phishing auditing, process monitoring, and real-time protection, while keeping user system activity, files, and queries strictly private on the host machine.

### Core Cybersecurity Objectives
*   **Privacy-Preserving Threat Intelligence:** Run all structural classifications and semantic reasoning on-device, preventing telemetry exfiltration.
*   **Asynchronous Host Scans:** Isolate file scanning and network lookups in dedicated worker threads to maintain graphical user interface (GUI) responsiveness.
*   **Heuristic Fallback Resilience:** Maintain 100% operational uptime by immediately compiling offline reports if the local AI services time out.
*   **Secure Containment:** Encrypt isolated threat payloads to prevent accidental host execution.

### Main Implemented Features
1.  **Dashboard:** Renders host status, active shields, total threats logged, and real-time physical memory metrics.
2.  **System Scanner:** Performs directory scans utilizing SHA-256 blacklists, Shannon entropy checks, and YARA pattern-matching rules.
3.  **Phishing Intelligence Center:** Audits URL safety asynchronously, combining parallel DNS lookups, SSL certificate validation, lexical feature classification, and AI reasoning.
4.  **Performance Monitor:** Displays live graphs (CPU, RAM, network) and details active process resources (PIDs, memory, network I/O, GPU).
5.  **Sandbox Emulation Verdict:** Runs executables in isolated containers, hooks system calls, and queries local LLMs to generate detailed containment reports.
6.  **Quarantine Manager:** Encrypts isolated files using AES-256-GCM and moves them to a secure quarantine vault.
7.  **Event Logger:** Stores operational and threat logs in an SQLite database, supporting real-time filter queries and CSV, JSON, or TXT exports.
8.  **Settings:** Configures permissions, theme selections, and local LLM configurations.

---

## 2. Application Type

*   **Application Model:** Standalone Desktop Application.
*   **Architecture Pattern:** Client-Side Decoupled Model-View-Controller (MVC) architecture, utilizing background worker threads (QThreads) for scanning tasks and network actions.
*   **Core Technology:** Python-based, utilizing **PyQt6** for GUI layouts and system calls.
*   **Overall Architecture Style:** Multi-threaded Event-Driven Architecture, communicating background status updates to the main GUI thread through thread-safe Qt signals and slots.

---

## 3. Frontend Technologies Used

*   **GUI Framework:** `PyQt6` (v6.6.0+) - Provides core desktop windows, stacked layouts, dialogs, and native widgets.
*   **Visualizations & Graphing Library:** `pyqtgraph` (v0.13.3+) - Renders live host metrics (CPU, memory, network historical charts) inside the Performance tab.
*   **Styling Engine:** `Qt Style Sheets` (QSS) - Loads, parses, and overrides interface colors using dynamic palette tokens.
*   **Animation System:** `PyQt6.QtCore.QPropertyAnimation` - Animates widget transitions, toast slide-ins, and circular gauges at ~60fps.
*   **Typography:** Google Fonts integration (`Outfit`, `Inter`, `Roboto`).
*   **Icons & Assets:** Vector-rendered symbols drawn dynamically inside the paint loops, including:
    *   **CircularGauge:** Custom gauge drawing dynamic tracking rings, active arc values, and status badges.
    *   **CircularProgress:** Animating circular rings used to represent progressive scanning phases.

---

## 4. Backend Technologies Used

*   **Backend Language:** `Python` (v3.11, 64-bit).
*   **Process Telemetry Gathering:** `psutil` (v5.9.0+) - Collects host CPU, RAM, disk, and process I/O data.
*   **Windows Subsystem Interface:** `wmi` (v1.5.1+) - Queries GPU and open hardware metrics via WMI namespaces.
*   **Filesystem Monitor:** `watchdog` (v3.0.0+) - Hooks filesystem operations (creates, modifies) across designated folders.
*   **Asynchronous Framework:** `PyQt6.QtCore.QThread` and `QObject` - Isolates long-running threat scanning, network audits, and AI generation tasks from the main GUI thread.
*   **Network Audits:** `socket` and `ssl` (bundled in Python stdlib) - Performs DNS queries and SSL/TLS handshake audits.
*   **HTTP Client:** `requests` (v2.31.0+) - Handles communication with the local Ollama API server.

---

## 5. Database & Storage

*   **Relational Database:** `SQLite` (accessed via Python's standard library `sqlite3` driver).
*   **Database Configuration:** Runs in **Write-Ahead Logging (WAL)** mode, allowing multi-threaded background writes without blocking UI queries.
*   **File-Based Storage Vault:**
    *   `quarantine/encrypted/`: Stores AES-256-GCM encrypted threat payloads (.qbin).
    *   `quarantine/metadata/`: Stores JSON manifests containing key and nonce manifests (.json).
*   **Log Storage System:** Database table logs (`threat_log`, `system_events`) and plaintext files (`sentinelcore.log`).
*   **Configuration System:** Flat-file JSON manifests (`config/permissions.json`, `config/version.json`) and QSS stylesheet assets.

---

## 6. AI / ML / Security Intelligence Components

*   **Machine Learning Engine:** `LightGBM` (v4.0.0+) and `joblib` (v1.3.0+) - Runs structural classifiers on PE files and lexical domains locally.
*   **PE Structural Classifier (EmberModel):** Classifies PE structural parameters using 2381-dimensional feature vectors.
*   **Lexical URL Classifier (PhishModel):** Evaluates brand impersonation, Shannon character entropy, and subdomain structures.
*   **Pattern-Matching Engine:** `yara-python` (v4.3.1+) - Compiles and applies community YARA rules to detect malware features in files and byte buffers.
*   **Local AI Router (AIManager):** Directs prompts to the local Ollama API endpoint or falls back to local heuristic templates when the AI service is offline.
*   **Local LLM Integration:** Communicates with Ollama over HTTP (`http://localhost:11434/api/generate`) to request threat analysis summaries.

---

## 7. Encryption & Security Libraries

*   **Cryptographic Toolkit:** `cryptography` (v41.0.0+) - Provides cryptographic operations.
*   **Isolation Algorithm:** `AES-256-GCM` (authenticated symmetric encryption) - Encrypts quarantined payloads with unique keys and nonces generated per file.
*   **PE Header Analyzer:** `pefile` (v2023.2.7+) - Parses PE sections, imports, exports, and certificates to feed the machine learning models.
*   **Integrity Verification:** standard `hashlib` driver - Calculates SHA-256 hashes to match files against known malware databases and trusted whitelists.
*   **Signature Auditing:** `ctypes`-based calls - Verifies Authenticode signatures via `WinVerifyTrust` on Windows systems.

---

## 8. APIs & External Services

*   **Ollama REST Interface:** Communicates with local endpoints (`http://localhost:11434/api/generate` and `/api/tags`) over HTTP.
*   **Local Telemetry Services:** Queries local WMI and WinVerifyTrust systems.
*   *Note: NovaSentinel does not require external cloud APIs, threat intelligence feeds, or VirusTotal keys. All scanning, machine learning inference, and AI reasoning run entirely locally on the host.*

---

## 9. Operating Systems & Environment

*   **Primary Tested OS:** Microsoft Windows 10 & 11 (64-bit).
*   **Host System Compatibility:** Fully optimized for Windows host targets, using WMI queries and WinVerifyTrust signatures.
*   **Fallback Capabilities:** Fallbacks ensure core scanning capabilities (hash checks, YARA scans, offline heuristic reports) remain functional if Windows-specific interfaces (such as WMI or Authenticode checks) are unavailable on other platforms.
*   **Runtime Dependency:** Requires Python 3.11 (64-bit) and the local Ollama runtime environment.

---

## 10. Folder Structure Explanation

```
novasentinel/
├── main.py                        # Entry point — SentinelApp
├── config/                        # Theme stylesheets & versions
│   └── themes/                    # QSS stylesheets per theme
├── core/                          # Backend Core Orchestration
│   ├── security_core.py           # Master controller orchestrator
│   ├── telemetry_manager.py       # Host metrics aggregator
│   ├── process_manager.py         # psutil WMI metrics collector
│   ├── dataset_manager.py         # LightGBM offline pipeline
│   ├── intelligence_hub.py        # Threat alert deduplicator (TTL)
│   ├── notification_manager.py    # Toast alert manager
│   ├── realtime_monitor.py        # Watchdog monitor with debouncer
│   └── system_scanner.py          # YARA + pefile + signature verification
├── engines/                       # Threat & AI engines
│   ├── phishing_detector.py       # Asynchronous url checking logic
│   ├── novasentinel_engine.py     # Multi-LLM AI Router
│   ├── ollama_backend.py          # Ollama REST connector
│   └── local_fallback.py          # Offline heuristic compiler
├── gui/                           # PyQt6 View & Widget controllers
│   ├── app.py                     # Bootstrap application shell
│   ├── main_window.py             # Sidebar navigation QMainWindow
│   ├── theme_manager.py           # Loads QSS stylesheets dynamically
│   ├── widgets/                   # Modular interface elements
│   │   ├── sidebar.py             # Navigation sidebar
│   │   ├── metrics_bar.py         # CPU, memory, disk, network mini-gauges
│   │   ├── ai_assistant_widget.py # Floating chat panel
│   │   └── notification_toast.py  # Toast overlay widgets
│   └── views/                     # Switchable panel tabs
│       ├── dashboard_view.py      # Main dashboard with gauges
│       ├── scan_view.py           # File scan interface
│       ├── phishing_view.py       # Asynchronous url check panel
│       ├── performance_view.py    # Live graphs & active process listings
│       ├── quarantine_view.py     # AES-256-GCM vault manager
│       ├── apps_view.py           # Installed programs audit
│       ├── sandbox_view.py        # Containment verdict summaries
│       ├── logs_view.py           # Filterable database log viewer
│       └── settings_view.py       # Permissions & theme selection
├── ml/                            # ML model and YARA logic
│   ├── ember_model.py             # EMBER PE feature extractor
│   ├── phish_model.py             # URL lexical extractor
│   └── yara_scanner.py            # YARA compiler scanner
├── quarantine/                    # Encrypted threat files
│   ├── encrypted/                 # AES-encrypted outputs (.qbin)
│   ├── metadata/                  # Key and nonce JSONs (.json)
│   └── quarantine_manager.py      # Encrypt, decrypt, restore logic
├── database/                      # SQLite event database
├── tests/                         # Automated unit & integration tests
└── documentation/                 # Comprehensive documentation
```

---

## 11. Major Functional Modules

### 1. Dashboard
Renders overall system health using a circular status gauge. It lists active protection shields and provides quick metrics for host CPU load, RAM utilization, and active threat detections.

### 2. Scanner
Performs directory scans using a background thread worker. It computes file hashes, runs YARA rules, measures byte entropy, parses PE headers with `pefile`, and validates digital signatures using Authenticode checks.

### 3. Phishing Intelligence Center
Uses the asynchronous `PhishingAIWorker` thread to audit URLs. The worker resolves host DNS, validates SSL certificates, extracts lexical features, and queries the local AI routing engine to calculate safety metrics in under 5 seconds.

### 4. Performance Monitor
Monitors host performance at 2-second intervals using `psutil`. It charts CPU, memory, and network usage on live `pyqtgraph` graphs and lists active processes with their associated PIDs, memory foot prints, network IO, and GPU usage.

### 5. Sandbox
Audits suspicious files in an isolated runtime environment. It intercepts system calls and API requests, then passes this telemetry to local LLMs to generate detailed containment reports.

### 6. Quarantine
Encrypts detected threat files using AES-256-GCM with a unique key and nonce. It saves the encrypted output as a `.qbin` file and stores the keys and nonces in a separate JSON manifest to allow safe file restoration or permanent deletion.

### 7. Logs
Provides a filterable interface to search operational logs stored in the SQLite database. Logs are categorized by severity level and originating component, and can be exported to CSV, JSON, or plain text formats.

### 8. Settings
Configures active modules, real-time protection folders, and target LLM endpoints. It also handles theme changes, reloading styling configurations across all active views within 50 ms.

### 9. Apps Audit
Scans installed host applications, analyzing their executable properties, signature integrity, and directory locations to calculate safety ratings and assign threat risk badges.

### 10. Real-time Protection
Monitors target directories (Desktop, Downloads, Temp, Startup) using `watchdog` to detect new or modified files. A 500 ms debouncer coalesces rapid events to prevent duplicate notifications before running machine learning and YARA checks on the files.

---

## 12. System Workflow

### Startup Process
```
[Application Startup]
   |
   |-- 1. Initialize SQLite connection (sentinelcore.db in WAL mode)
   |-- 2. Load configurations (permissions, model setups)
   |-- 3. Load QSS stylesheet assets & apply default theme
   |-- 4. Start TelemetryManager background thread (psutil loop)
   |-- 5. Start AIManager health checks (pings localhost:11434)
   |-- 6. Initialize RealtimeMonitor folder watchdog
   |-- 7. Load ML models (ember_lgbm.pkl, phish_lgbm.pkl) on background thread
   v
[Launch MainWindow GUI View]
```

### Scan Workflow
```
[User triggers Directory Scan]
   |
   |-- 1. Create SystemScanner worker thread
   |-- 2. Traverse directory files
   |   |
   |   |-- a. Calculate SHA-256 hash & check local whitelist
   |   |-- b. Run compiled YARA rules
   |   |-- c. Verify Authenticode digital signature via WinVerifyTrust
   |   |-- d. Extract PE features & run offline LightGBM classification
   |   |-- e. Measure Shannon byte entropy (flag high entropy > 7.6)
   |   v
   |-- 3. Emit progress updates to main UI thread via PyQt signals
   |-- 4. Log threats to SQLite and trigger Toast notifications
   v
[Render Scan Result Card in GUI]
```

### Phishing Intelligence Workflow
```
[User enters URL to audit]
   |
   |-- 1. Launch PhishingAIWorker background thread
   |-- 2. Query DNS IP resolution (max 2.0s timeout)
   |-- 3. Audit SSL certificate handshake (max 3.0s timeout)
   |-- 4. Extract lexical features & calculate Shannon entropy
   |-- 5. Request semantic reasoning from AI Engine
   |   |
   |   |-- IF Ollama Online: Stream response tokens
   |   |-- IF Ollama Offline/Timeout (>5.0s): Compile offline 9-section report
   |   v
   |-- 6. Log threat events to SQLite database
   |-- 7. Update UI circular gauges & analysis panels via Qt signals
   v
[Render Phishing Audit Card in GUI]
```

### Sandbox Workflow
```
[User uploads file to Sandbox]
   |
   |-- 1. Launch target executable inside isolated container
   |-- 2. Intercept and hook API calls and system commands
   |-- 3. Aggregate process behavior logs and resource metrics
   |-- 4. Query AI engine to evaluate sandbox telemetry
   |   |
   |   |-- IF Ollama Online: Query local model
   |   |-- IF Ollama Offline/Timeout: Compile heuristic containment report
   |   v
   |-- 5. Display containment report and update safety rating badge
   v
[Display analysis report in Sandbox GUI]
```

### Logging Workflow
```
[Security core fires System Event / Threat Alert]
   |
   |-- 1. Create timestamped database event (ISO 8601 UTC format)
   |-- 2. Write event to SQLite database table via WAL transaction
   |-- 3. Update active Logs table display dynamically in UI
   |-- 4. Allow user to filter logs by severity or message search queries
   v
[Export filtered logs to CSV, JSON, or plain text formats]
```

### Notification Workflow
```
[Security event triggered by Real-Time Monitor]
   |
   |-- 1. Deduplicate alert via IntelligenceHub (using TTL cache)
   |-- 2. Route unique alert details to NotificationManager
   |-- 3. Emit thread-safe PyQt signal to MainWindow GUI
   |-- 4. Instantiate animated QWidget Toast Overlay
   v
[Display auto-dismissing Toast alert in top-right corner]
```

---

## 13. Architecture Summary

NovaSentinel uses a decoupled architecture designed for high-performance host threat detection and private data handling.

```
       +-------------------------------------------------------+
       |                     PyQt6 FRONTEND                    |
       |  - MainWindow    - CircularGauge   - pyqtgraph Charts |
       |  - sidebar       - StackedViews    - Toast Alerts     |
       +---------------------------|---------------------------+
                                   | Thread-safe Qt signals
                                   v
       +-------------------------------------------------------+
       |                  SecurityCore BACKEND                 |
       |  - TelemetryManager   - RealtimeMonitor  - Watchdog   |
       |  - ProcessManager     - LogManager       - SQLite DB  |
       +---------------------------|---------------------------+
                                   | Subsystem dispatch
                                   v
       +-------------------------------------------------------+
       |                     THREAT ENGINES                    |
       |  - YaraScanner        - pefile Parser    - WinVerify  |
       |  - EmberModel (LGBM)  - PhishModel(LGBM) - AES-256 QM |
       +---------------------------|---------------------------+
                                   | Local AI requests
                                   v
       +-------------------------------------------------------+
       |                     LOCAL AI ENGINE                   |
       |  - AIManager (health check)                           |
       |  - Ollama API (llama3 / mistral / phi3)               |
       |  - Local Heuristics Fallback Engine                   |
       +-------------------------------------------------------+
```

Background tasks (directory scans, URL phishing checks, and local LLM requests) run in dedicated `QThread` workers, sending status updates to the main GUI thread through thread-safe Qt signals. This multi-threaded layout keeps the main interface responsive under heavy auditing loads.

Operational logs, process configurations, and threat histories are managed locally by the SQLite database running in WAL mode, ensuring data integrity and fast reads for the UI components.

---

## 14. Libraries & Dependencies

*   **GUI & Graphing:**
    *   `PyQt6` (>=6.6.0) - High-performance Windows application engine.
    *   `pyqtgraph` (>=0.13.3) - High-speed mathematical rendering interface.
*   **Security & Malware Analysis:**
    *   `yara-python` (>=4.3.1) - Multi-platform structural pattern matching engine.
    *   `pefile` (>=2023.2.7) - Executable header parser and feature extractor.
*   **Machine Learning (AI engine):**
    *   `lightgbm` (>=4.0.0) - Fast gradient-boosting framework.
    *   `scikit-learn` (>=1.3.0) - Feature preprocessing pipelines.
    *   `joblib` (>=1.3.0) - Serialized machine learning model loader.
    *   `numpy` (>=1.24.0) - Multi-dimensional array handling library.
*   **Host System & Watchdog:**
    *   `psutil` (>=5.9.0) - System utilization and process telemetry logger.
    *   `watchdog` (>=3.0.0) - Multi-directory filesystem event listener.
    *   `wmi` (>=1.5.1) - Windows subsystem telemetry connector.
*   **Cryptography:**
    *   `cryptography` (>=41.0.0) - AES-256-GCM symmetric block encryptor.
*   **HTTP Client:**
    *   `requests` (>=2.31.0) - REST API connection client.
*   **Testing:**
    *   `pytest` (>=7.4.0) - Python testing framework.
    *   `pytest-timeout` (>=2.1.0) - Strict testing boundary assertion driver.

---

## 15. Development Tools Used

*   **Primary IDE:** Visual Studio Code / Cursor.
*   **Testing Framework:** `pytest` - Automated execution of isolated and full integration tests.
*   **Database Management Tools:** DB Browser for SQLite - Auditing table configurations and transaction execution logs.
*   **Local LLM Orchestrator:** Ollama Desktop - Manages local models (`llama3:latest`, `mistral`, `phi3`).
*   **Python Build Tools:** standard `pip` and virtual environment managers.

---

## 16. Technical Highlights

*   **Non-Blocking UI Execution:** Heavy directory scans, DNS/SSL lookups, and local LLM requests run in independent background threads, preventing interface freezes.
*   **Local Machine Learning Inference:** Uses offline LightGBM classifiers trained on EMBER and lexical feature datasets to analyze files and URLs locally without cloud latencies.
*   **Fail-safe AI Fallbacks:** Integrates local LLM explanations and includes a heuristic fallback compiler to ensure reports are generated when offline or during timeouts.
*   **Multi-Platform Watchdog debouncer:** Watches designated directories and uses coalescing timers to prevent duplicate alerts from rapid filesystem events.
*   **Secure AES-256-GCM Quarantine:** Encrypts threat payloads locally using unique keys and nonces to isolate threats securely.
*   **Write-Ahead Logging (WAL) Mode:** Configures SQLite to allow background database writes concurrently with UI read queries.
