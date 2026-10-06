# LogGuard

LogGuard monitors a Linux SSH authentication log for repeated failed logins. It counts failures per source IP in a rolling time window, optionally enriches an IP with AbuseIPDB, and optionally sends an alert to Telegram.

It is intentionally **alert-only**: it does not block addresses, change SSH settings, or edit firewall rules. Investigate and contain activity through your normal incident process.

## Improvements over the initial script

- Secrets come from environment variables rather than source code.
- IPv4 and IPv6 addresses are parsed and validated with Python's `ipaddress` module; optional CIDR ranges can be allowlisted.
- Failed attempts use a rolling window instead of a lifetime counter.
- Log truncation and inode-based rotation are detected.
- State writes are atomic and use restrictive file permissions.
- API results are cached; errors are treated as unknown, not as a clean reputation score.
- Repeated successful alerts have a configurable cooldown. Failed Telegram delivery is retried after a short retry interval rather than on every log line.
- Alerts contain a summary, not the raw authentication line or attempted username.
- AbuseIPDB and Telegram are optional. Without them, threshold alerts still appear in the service log.

## Requirements

- Linux with Python 3.10 or later
- Read access to the chosen authentication log
- Python's standard library only; no third-party Python packages are required
- Optional AbuseIPDB API key and Telegram bot/chat configuration

On Debian or Ubuntu the log is often `/var/log/auth.log`; on other systems it may be `/var/log/secure`, or authentication events may only be available through journald. Set `LOGGUARD_AUTH_LOG` to the correct file. This version tails a text log; it does not read directly from journald.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
```

The `.env.example` file is a template; the program does not automatically read `.env`. Set the values in your service manager or export them in your shell. Do not commit real tokens or place them in this project. For a quick local run, export values and start the monitor:

```bash
export LOGGUARD_AUTH_LOG=/var/log/auth.log
export LOGGUARD_STATE_FILE="$HOME/.local/state/logguard/state.json"
python logguard.py --check-config
python logguard.py
```

By default it begins at the end of the log and processes only new entries. Use `--from-start` to process existing log contents, for example in a test copy. Run `python logguard.py --help` for options.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LOGGUARD_AUTH_LOG` | `/var/log/auth.log` | Authentication log path |
| `LOGGUARD_STATE_FILE` | `$XDG_STATE_HOME/logguard/state.json` or `~/.local/state/logguard/state.json` | Private cache and cooldown state |
| `LOGGUARD_FAIL_THRESHOLD` | `5` | Failures before an alert can be sent |
| `LOGGUARD_WINDOW_SECONDS` | `600` | Rolling period used for the threshold |
| `LOGGUARD_ALERT_COOLDOWN_SECONDS` | `21600` | Minimum time between alerts for one IP |
| `LOGGUARD_WHITELIST` | `127.0.0.1,::1` | Comma-separated IPs or CIDR ranges ignored by the detector |
| `LOGGUARD_POLL_SECONDS` | `0.5` | Poll interval while waiting for new lines |
| `LOGGUARD_HOST_LABEL` | System hostname | Label shown in alerts |
| `LOGGUARD_LOG_LEVEL` | `INFO` | Python logging level |
| `LOGGUARD_REQUIRE_REPUTATION` | `false` | If true, alerts require a known AbuseIPDB score at or above the threshold |
| `ABUSEIPDB_API_KEY` | unset | Enables optional IP reputation lookup |
| `ABUSEIPDB_THRESHOLD` | `50` | Reputation threshold when required; otherwise score is informational |
| `ABUSEIPDB_CACHE_TTL_SECONDS` | `86400` | Cache duration (failed lookups are cached for at most five minutes) |
| `LOGGUARD_TELEGRAM_RETRY_SECONDS` | `60` | Minimum gap between retries after Telegram delivery fails |
| `TELEGRAM_BOT_TOKEN` | unset | Enables Telegram delivery when used with chat ID |
| `TELEGRAM_CHAT_ID` | unset | Destination chat; must be set with the bot token |

An AbuseIPDB score is an external signal, not attribution or proof. The safe default is to alert on repeated authentication failures regardless of reputation, then show a score when available. Setting `LOGGUARD_REQUIRE_REPUTATION=true` deliberately makes the reputation service a gate; outages or missing keys will then suppress alerts.

## Running as a service

Review `systemd/logguard.service`, update its script path if needed, then install it using your distribution's systemd workflow. Create a dedicated unprivileged `logguard` account and grant it read-only access to the authentication log (on Debian/Ubuntu this commonly means membership in `adm`). Protect the environment file containing API keys with owner-only permissions. Do not run the monitor as root just to read the log.

The sample unit uses `StateDirectory=logguard` and expects the state path to be `/var/lib/logguard/state.json`; set `LOGGUARD_STATE_FILE` in its environment file accordingly. Review sandboxing directives against your distribution before enabling the unit.

## Validation and limitations

`--check-config` validates environment values but does not contact external services or prove that the log is readable. Test using a non-production copied log and test credentials first. The rolling failure counts are in memory and reset when the process restarts; the reputation cache and alert cooldown persist. Authentication log formats vary, and this parser intentionally recognizes common OpenSSH messages only. Forward logs to a central collector for durable investigations and use a monitored service manager to restart the process if it exits.

## Security notes

- Keep API keys and the Telegram bot token out of source control and logs.
- Telegram recipients will receive source IP addresses and host labels; configure the destination appropriately.
- Protect the state directory and log output. Do not expose the monitor's state file through a web server.
- Keep the operating system, Python runtime, and dependencies patched.
- This tool does not replace SSH hardening, centralized logging, MFA, rate limiting, or an incident response plan.
