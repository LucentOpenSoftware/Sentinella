# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in Sentinella, please report it
responsibly.

### How to Report

Use GitHub's private vulnerability reporting feature if available.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- SHA-256 hash of any involved files (do NOT attach malware samples)

### What NOT to Do

- Do not submit malware samples in public issues or pull requests
- Do not paste credentials, API tokens, or vault keys
- Do not include personal file paths or browsing history
- Do not upload proprietary files

### Hash-Only Reports

When reporting detections or vulnerabilities involving specific files,
share the SHA-256 hash only. This allows verification without exposing
file contents.

```powershell
# Get SHA-256 of a file
Get-FileHash -Algorithm SHA256 "path\to\file"
```

### Scope

The following are in scope for security reports:

- Quarantine vault bypass (restoring to unintended locations)
- IPC protocol injection or privilege escalation
- Self-exclusion bypass (malware evading detection by using Sentinella paths)
- Vault key exposure
- Path traversal in any file operation
- Denial of service against the daemon

### Response

We will acknowledge security reports within 48 hours and aim to provide
a fix or mitigation within 7 days for critical issues.

---

*This policy applies to the Sentinella project only, not to ClamAV or
other third-party components. Report ClamAV vulnerabilities to the
ClamAV project directly.*
