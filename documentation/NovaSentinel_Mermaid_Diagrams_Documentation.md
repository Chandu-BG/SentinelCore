# NovaSentinel: System Architecture & UML Diagrams

This document compiles the core system architecture, data flows, use cases, and database schemas of the **NovaSentinel** cognitive cybersecurity suite. All diagrams are fully represented using standard, syntax-valid **Mermaid UML** blocks, which automatically render inside compatible Markdown viewers.

---

## 1. System Architecture Diagram

This diagram represents the decoupled, multi-layered block architecture of the NovaSentinel host application, separating the PyQt6 user interface views, the background SecurityCore controller, the engine analyzers, and the local storage/AI back-ends.

```mermaid
graph TD
    subgraph Frontend [PyQt6 User Interface Shell]
        MW[MainWindow QMainWindow]
        SB[sidebar QWidget]
        TM[ThemeManager QObject]
        AI_W[AIAssistantWidget Floating widget]
        
        subgraph Views [Switchable View Cards]
            DV[DashboardView]
            SV[ScanView]
            PV[PhishingView]
            PERF[PerformanceView]
            QV[QuarantineView]
            LV[LogsView]
            SET[SettingsView]
        end
    end

    subgraph Core [SecurityCore Controller Hub]
        SC[SecurityCore Master]
        TEL[TelemetryManager Thread]
        PM[ProcessManager WMI]
        RM[RealtimeMonitor Watchdog]
        QM[QuarantineManager]
    end

    subgraph Engines [Analytics & Threat Engines]
        YARA[YaraScanner Compiler]
        PE[PE FeatureExtractor]
        PHD[PhishingDetector]
        AIMGR[AIManager AI Router]
    end

    subgraph Storage [Local Database & Runtimes]
        DB[(SQLite WAL database)]
        OLLAMA[Ollama Local REST API]
    end

    %% UI Connections
    MW --> SB
    MW --> TM
    MW --> AI_W
    MW --> Views
    SB --> Views

    %% UI to Core Connections
    Views -- Qt signals --> SC
    SC -- Thread-safe updates --> Views

    %% Core to Engine Connections
    SC --> TEL
    SC --> PM
    SC --> RM
    SC --> QM
    
    QM --> YARA
    TEL --> PM
    RM --> YARA
    
    SC --> PHD
    SC --> AIMGR
    
    %% Engine to ML/AI/DB
    PHD --> PE
    AIMGR --> OLLAMA
    SC --> DB
```

---

## 2. Data Flow Diagram (DFD Level 0)

Renders the high-level data streams, inputs, and outputs between external entities (the User and the Windows Host System) and the central NovaSentinel process, highlighting how threat analysis and telemetry reports are stored.

```mermaid
graph TD
    subgraph External [External Host Entities]
        USR([Host User])
        FS([Windows Filesystem])
        PS([psutil / WMI Processes])
    end

    subgraph System [NovaSentinel Application Process]
        NS[NovaSentinel Core Processing Engine]
    end

    subgraph Internal [Internal Services & DB]
        DB[(SQLite WAL Database)]
        AI[Local Ollama LLM Service]
    end

    %% Data Input streams
    USR -- "1. Scans, URLs, Prompts" --> NS
    FS -- "2. File events creates, modifies" --> NS
    PS -- "3. Telemetry CPU, RAM, GPU, Net" --> NS

    %% Data Output streams
    NS -- "4. Notifications, Reports, UI stats" --> USR
    NS -- "5. AES-256 encrypted isolate" --> FS

    %% System interactions with internal components
    NS -- "6. Read / Write events" --> DB
    DB -- "7. Log history query results" --> NS
    
    NS -- "8. Threat reasoning prompt" --> AI
    AI -- "9. Streaming explanation tokens" --> NS
```

---

## 3. Use Case Diagram

Exposes how the Host User and the System Administrator interact with the individual functional boundaries and setting overrides of NovaSentinel.

```mermaid
graph TD
    %% Actors
    USR([Host User])
    ADM([System Administrator])

    subgraph Boundary [NovaSentinel Functional Boundary]
        UC_SCAN(1. Perform Host Scans)
        UC_PHISH(2. Audit URL Phishing)
        UC_PERF(3. Monitor Resource Telemetry)
        UC_CHAT(4. Interact with AI Assistant)
        
        UC_QUAR(5. Manage Quarantine Vault)
        UC_LOGS(6. Filter & Export Database Logs)
        UC_SET(7. Configure Local AI & Shields)
    end

    %% User Associations
    USR --> UC_SCAN
    USR --> UC_PHISH
    USR --> UC_PERF
    USR --> UC_CHAT

    %% Administrator Associations
    ADM --> UC_QUAR
    ADM --> UC_LOGS
    ADM --> UC_SET
    ADM --> UC_SCAN
```

---

## 4. Entity-Relationship Diagram (ERD)

Highlights the attributes, structural datatypes, primary keys, check constraints, and relationships of the six SQLite database tables that manage system persistence.

```mermaid
erDiagram
    threat_log {
        integer id PK "AUTOINCREMENT"
        text threat_type NOT_NULL "Category of Threat"
        text description NOT_NULL "Explainability Detail"
        text severity CHECK_IN "low, medium, high, critical"
        text timestamp NOT_NULL "ISO 8601 UTC"
        text file_path NULLABLE "Affected File or URL"
    }
    process_trust {
        text process_name PK "Executable Name"
        integer trust_score DEFAULT_100 "Safety score [0-100]"
        text last_seen NOT_NULL "ISO 8601 UTC"
    }
    blocked_ips {
        integer id PK "AUTOINCREMENT"
        text ip_address UNIQUE "Target IP Address"
        text reason NOT_NULL "Explainability Detail"
        text blocked_at NOT_NULL "ISO 8601 UTC"
    }
    risk_history {
        integer id PK "AUTOINCREMENT"
        text category NOT_NULL "Module Categorization"
        integer score NOT_NULL "Risk score [0-100]"
        text timestamp NOT_NULL "ISO 8601 UTC"
    }
    file_events {
        integer id PK "AUTOINCREMENT"
        text file_path NOT_NULL "Absolute File Path"
        text event_type NOT_NULL "created, modified, deleted"
        text timestamp NOT_NULL "ISO 8601 UTC"
    }
    system_events {
        integer id PK "AUTOINCREMENT"
        text event_type NOT_NULL "System category toggled"
        text description NOT_NULL "Action explanation details"
        text severity NOT_NULL "INFO, WARNING, ERROR"
        text timestamp NOT_NULL "ISO 8601 UTC"
    }

    %% Visual logical relationships mapping database correlations
    threat_log }o--|| file_events : triggers
    system_events }o--|| threat_log : audits
```
