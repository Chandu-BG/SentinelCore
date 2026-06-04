# NovaSentinel Database Schema Documentation

---

## 1. Database Architecture Overview

The **NovaSentinel** platform utilizes a self-contained, high-performance relational database engine powered by **SQLite** (`sentinelcore.db`). Because the application operates completely client-side in a multi-threaded desktop environment, the database is optimized to handle concurrent transaction inputs (e.g., real-time filesystem logs, CPU metrics, and process auditing) while keeping read delays in the graphical user interface below **50 milliseconds**.

### Core Engine Configurations

1.  **Write-Ahead Logging (WAL) Mode:**
    *   *Command:* `PRAGMA journal_mode = WAL;`
    *   *Purpose:* Separates readers and writers, allowing background monitor threads to log system audits while the UI thread reads threats concurrently without database locking blocks.
2.  **Synchronous Level:**
    *   *Command:* `PRAGMA synchronous = NORMAL;`
    *   *Purpose:* Minimizes disk synchronization bottlenecks during rapid monitoring periods, while keeping database integrity safe against sudden power losses.
3.  **Busy Timeout:**
    *   *Command:* `PRAGMA busy_timeout = 5000;`
    *   *Purpose:* Mitigates database lock errors during concurrent writes by retrying transactions for up to 5 seconds.

---

## 2. Entity-Relationship Diagram (ERD)

The relational schema is structured as follows. Although SQLite does not strictly enforce foreign keys unless configured, logical relationships associate threat identifiers, file changes, and logging profiles.

```mermaid
erDiagram
    threat_log {
        integer id PK
        text threat_type NOT_NULL
        text description NOT_NULL
        text severity CHECK_IN
        text timestamp NOT_NULL
        text file_path NULLABLE
    }
    process_trust {
        text process_name PK
        integer trust_score DEFAULT_100
        text last_seen NOT_NULL
    }
    blocked_ips {
        integer id PK
        text ip_address UNIQUE
        text reason NOT_NULL
        text blocked_at NOT_NULL
    }
    risk_history {
        integer id PK
        text category NOT_NULL
        integer score NOT_NULL
        text timestamp NOT_NULL
    }
    file_events {
        integer id PK
        text file_path NOT_NULL
        text event_type NOT_NULL
        text timestamp NOT_NULL
    }
    system_events {
        integer id PK
        text event_type NOT_NULL
        text description NOT_NULL
        text severity NOT_NULL
        text timestamp NOT_NULL
    }
```

---

## 3. Detailed Table Specifications

### 3.1 Table: `threat_log`
Stores historical detections flagged by the scanning and monitoring subsystems, serving as the back-end source for the Dashboard alert grids.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS threat_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
        timestamp TEXT NOT NULL,
        file_path TEXT
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **id** | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | *None* | Unique record identifier for each logged threat event. |
| **threat_type** | `TEXT` | `NOT NULL` | *None* | Categorizes the threat (e.g., `MALWARE`, `PHISHING`, `SUSPICIOUS_PE`, `YARA_MATCH`). |
| **description** | `TEXT` | `NOT NULL` | *None* | Explains the threat detection details. |
| **severity** | `TEXT` | `NOT NULL`, `CHECK(severity IN ('low', 'medium', 'high', 'critical'))` | *None* | Ordered threat level rating (`low`, `medium`, `high`, `critical`). |
| **timestamp** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp format representing when the event was logged. |
| **file_path** | `TEXT` | `NULLABLE` | `NULL` | Absolute file path or target URL associated with the threat entry. |

---

### 3.2 Table: `process_trust`
Caches process names and trust scores compiled by the telemetry managers, supporting the Performance tab and real-time protection shields.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS process_trust (
        process_name TEXT PRIMARY KEY,
        trust_score INTEGER NOT NULL DEFAULT 100 CHECK(trust_score >= 0 AND trust_score <= 100),
        last_seen TEXT NOT NULL
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **process_name** | `TEXT` | `PRIMARY KEY` | *None* | Name of the process executable (e.g., `explorer.exe`, `chrome.exe`). |
| **trust_score** | `INTEGER` | `NOT NULL`, `CHECK(score >= 0 AND score <= 100)` | `100` | Safety score indicating the system's confidence rating in the process. |
| **last_seen** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp tracking when the process was last audited. |

---

### 3.3 Table: `blocked_ips`
Tracks IP addresses blocked by host intrusion shields to prevent malicious Command and Control (C2) communication.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        blocked_at TEXT NOT NULL
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **id** | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | *None* | Unique record identifier for each block rule. |
| **ip_address** | `TEXT` | `UNIQUE`, `NOT NULL` | *None* | Malicious remote IP address flagged by security monitors. |
| **reason** | `TEXT` | `NOT NULL` | *None* | Explainability detail (e.g., `Phishing Domain Host`, `Known C2 Node`). |
| **blocked_at** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp tracking when the block rule was created. |

---

### 3.4 Table: `risk_history`
Caches historical risk ratings to plot system security trends on the Dashboard.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS risk_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        score INTEGER NOT NULL,
        timestamp TEXT NOT NULL
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **id** | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | *None* | Unique record identifier for historical ratings. |
| **category** | `TEXT` | `NOT NULL` | *None* | Section categorization (e.g., `SANDBOX`, `SCAN`, `REALTIME`, `OVERALL`). |
| **score** | `INTEGER` | `NOT NULL` | *None* | Score rating in range [0, 100]. |
| **timestamp** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp tracking when the score history was recorded. |

---

### 3.5 Table: `file_events`
Stores audit history for filesystem modifications captured by the debounced real-time watchdog monitor.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        event_type TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **id** | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | *None* | Unique event transaction ID. |
| **file_path** | `TEXT` | `NOT NULL` | *None* | Absolute path of the targeted file. |
| **event_type** | `TEXT` | `NOT NULL` | *None* | Type of change caught by the watchdog (`created`, `modified`, `deleted`). |
| **timestamp** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp tracking when the change occurred. |

---

### 3.6 Table: `system_events`
Logs operational milestones and configurations (e.g., shield adjustments, theme modifications, database rotations) to support auditing.

*   **SQL Creation Command:**
    ```sql
    CREATE TABLE IF NOT EXISTS system_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    ```

*   **Column Definitions:**

| Column Name | SQLite Data Type | Key Constraints | Default Value | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **id** | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | *None* | Unique operational log ID. |
| **event_type** | `TEXT` | `NOT NULL` | *None* | Categorizes the operational log event (e.g., `SHIELD_TOGGLED`, `THEME_CHANGED`, `ENGINE_INIT`). |
| **description** | `TEXT` | `NOT NULL` | *None* | Explains the action (e.g., `Real-time protection turned OFF`). |
| **severity** | `TEXT` | `NOT NULL` | *None* | Categorizes severity status (`INFO`, `WARNING`, `ERROR`). |
| **timestamp** | `TEXT` | `NOT NULL` | *None* | ISO 8601 UTC timestamp. |

---

## 4. Query Optimizations & Data Retention

To prevent database operations from slowing down the user interface, NovaSentinel applies specific query designs and data retention rules:

### Indexed Parameters
Background queries search logs using targeted indices on timestamp and file path parameters. This prevents full table scans when checking paths or plotting risk ratings:
```sql
CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_event_path ON file_events(file_path);
```

### Automatic Log Rotation Rules
To keep resource footprint low, a database maintenance routine runs on startup to prune operational logs and file events older than 30 days:
```sql
DELETE FROM file_events WHERE datetime(timestamp) < datetime('now', '-30 days');
DELETE FROM system_events WHERE datetime(timestamp) < datetime('now', '-30 days') AND severity = 'INFO';
```
This data retention strategy maintains light database foot prints, ensuring fast search queries and keeping host SSD storage utilization low.
