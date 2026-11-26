# Log Sentinel Python Collector

Standalone Linux authentication log collector, normalizer, and rule-based detection engine.

## Local Development Setup

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
```

## Supported Log Sources (Version 1.0)

1. **Ubuntu / Debian `/var/log/auth.log`** (`source_format="auth_log"`)
   - Supports RFC 3164 (`Nov 26 21:42:38`) and ISO-8601 timestamps.
   - Extracts SSH accepted logins (`password`, `publickey`, `keyboard-interactive`), SSH failed logins, invalid user attempts, max auth exceeded / preauth disconnects, PAM `authentication failure;`, `sudo` auth/command events, and local `login`/`su` failures.
2. **Systemd Journal (`journalctl -o short-iso`)** (`source_format="journal"`)
   - Supports ISO timestamps with compact offsets (e.g., `+0530`) and `sshd-session` (Ubuntu 24.04+).
3. **Documented CSV Files** (`source_format="csv"`)
   - **Required columns:** `event_timestamp`, `event_type`, `auth_result` (`success` | `failure` | `unknown`)
   - **Optional columns:** `username`, `source_ip`, `auth_method`, `service`, `raw_event`

Sample logs for testing are located in [samples/](samples/).
