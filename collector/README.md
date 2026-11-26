# Log Sentinel Python Collector

Standalone Linux authentication log collector, normalizer, and rule-based detection engine.

## 1. Local Development & Testing

```bash
python3 -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
```

## 2. Supported Log Sources (Version 1.0)

1. **Ubuntu / Debian `/var/log/auth.log`** (`LOG_SENTINEL_SOURCE_TYPE=auth_log`)
   - Supports RFC 3164 (`Nov 26 21:42:38`) and ISO-8601 timestamps.
   - Extracts SSH accepted logins (`password`, `publickey`, `keyboard-interactive`), SSH failed logins, invalid user attempts, max auth exceeded / preauth disconnects, PAM `authentication failure;`, `sudo` auth/command events, and local `login`/`su` failures.
2. **Systemd Journal (`journalctl -o short-iso`)** (`LOG_SENTINEL_SOURCE_TYPE=journal`)
   - Uses `journalctl -f -n 0 -o short-iso SYSLOG_FACILITY=4 SYSLOG_FACILITY=10`.
3. **Documented CSV Files** (`source_format="csv"` via Log Analyzer / parser API)
   - **Required columns:** `event_timestamp`, `event_type`, `auth_result` (`success` | `failure` | `unknown`)
   - **Optional columns:** `username`, `source_ip`, `auth_method`, `service`, `raw_event`

Sample logs for testing are located in [samples/](samples/).

## 3. Linux Production / VM Setup (Least Privilege — No `root` Needed)

On Ubuntu/Debian, `/var/log/auth.log` is readable by members of the `adm` group (not world-readable), and `systemd` journal is readable by members of `systemd-journal`.

```bash
# 1. Create a dedicated unprivileged service user with read-only log group access
sudo useradd --system --no-create-home --shell /usr/sbin/nologin logsentinel
sudo usermod -aG adm,systemd-journal logsentinel

# 2. Install collector files and create virtualenv
sudo mkdir -p /opt/log-sentinel/collector/data
sudo chown -R logsentinel:logsentinel /opt/log-sentinel/collector/data
cd /opt/log-sentinel/collector
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Configure environment from .env.collector.example
cp .env.collector.example .env
# Edit .env with your Device ID, per-device Collector Token, and Supabase Function URLs
chmod 600 .env
```

## 4. Running the Collector

```bash
# Dry-run test on sample log (no cloud calls)
LOG_SENTINEL_DEVICE_ID=11111111-1111-4111-8111-111111111111 \
LOG_SENTINEL_LOG_PATH=./samples/sample_auth.log \
python -m log_sentinel --once --dry-run --from-beginning

# Continuous live monitoring
python -m log_sentinel --env-file .env
```

### Example `systemd` Service (`/etc/systemd/system/log-sentinel.service`)

```ini
[Unit]
Description=Log Sentinel Authentication Log Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=logsentinel
Group=adm
WorkingDirectory=/opt/log-sentinel/collector
ExecStart=/opt/log-sentinel/collector/.venv/bin/python -m log_sentinel --env-file /opt/log-sentinel/collector/.env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 5. Troubleshooting

- **Permission denied on `/var/log/auth.log`:** Ensure the user running the collector is in the `adm` group (`groups $USER`) and re-login or restart the service.
- **Events not appearing after network drop:** Check `LOG_SENTINEL_LOCAL_LOG_FILE` (`./data/collector.log`). Batches remain buffered safely in `collector_state.sqlite3` and flush automatically with exponential backoff once connectivity returns.
- **401 Unauthorized:** Verify `LOG_SENTINEL_DEVICE_ID` and `LOG_SENTINEL_COLLECTOR_TOKEN` match the device registered in Supabase (`register_monitored_device`).
