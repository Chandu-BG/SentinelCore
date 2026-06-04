# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.1.x   | ✅ Active support |
| 4.0.x   | ⚠️ Security patches only |
| < 4.0   | ❌ No longer supported |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

If you discover a security vulnerability in NovaSentinel, please report it responsibly by:

1. **Email**: Open a [GitHub Security Advisory](https://github.com/Chandu-BG/SentinelCore/security/advisories/new) (preferred — keeps report private)
2. **Alternative**: Direct message via GitHub profile

### What to include in your report

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Potential impact and attack scenario
- Your suggested fix (optional but appreciated)
- Your name/handle for acknowledgement (optional)

### Response timeline

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgement | Within 48 hours |
| Severity assessment | Within 7 days |
| Patch or mitigation | Within 30 days (critical: 7 days) |
| Public disclosure | After patch is released |

---

## Security Architecture

NovaSentinel is designed with several security-critical components. Here are relevant security considerations:

### Quarantine Vault
- Files are encrypted with **AES-256-CBC**
- Key derivation uses **PBKDF2-HMAC-SHA256** with **480,000 iterations** (OWASP 2023 recommendation)
- The encryption key (`quarantine.key`) is stored locally and **must not be committed to version control**
- Losing the key makes quarantined files unrecoverable — back up `quarantine.key` separately

### AI Backend (Ollama)
- NovaSentinel communicates with a **locally running** Ollama instance on `localhost:11434`
- No data is sent to external AI services or cloud APIs
- The AI assistant can execute privileged commands (process termination, quarantine) — only run trusted models

### Process Termination
- NovaSentinel can terminate Windows processes — this requires no special privileges for user-owned processes
- Administrator privileges are required to terminate protected system processes
- A hardcoded protection list prevents NovaSentinel from terminating its own process or critical Windows processes (LSASS, CSRSS, etc.)

### IP Blocking
- The network blocking engine uses `netsh advfirewall` — requires **Administrator** privileges
- Blocked IPs are added as Windows Firewall rules under the name `NovaSentinel_Block_<IP>`
- Rules persist after application exit; use the Performance Monitor to view and can be cleared from Windows Firewall settings

### Local Data
- `sentinelcore.db` (SQLite) stores threat history, scan results, and telemetry
- `config/permissions.json` stores engine enable/disable states
- `config/version.json` stores theme preferences
- None of this data is transmitted externally

### Known Security Limitations

1. **Unsigned binary**: The distributed EXE is not code-signed. Windows SmartScreen will warn on first launch. This is expected for community software without a signing certificate.

2. **Ollama trust**: If you run an untrusted model via Ollama, that model has access to the system context provided by NovaSentinel's AI interface.

3. **Local admin bypass**: NovaSentinel does not prevent a local administrator from modifying its own files or database. Self-protection is a best-effort detection layer, not a DRM system.

4. **YARA false positives**: YARA rules may flag benign files. Always review findings before quarantine.

---

## Acknowledgements

Security researchers who responsibly disclose vulnerabilities will be acknowledged in release notes (unless they prefer anonymity).
