#!/usr/bin/env python3
"""LogGuard: alert on repeated SSH authentication failures.

This monitor is read-only with respect to the host firewall and SSH service.
It tails an authentication log, counts failures in a rolling window, optionally
enriches source IPs with AbuseIPDB, and optionally sends Telegram alerts.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOG = logging.getLogger("logguard")

# OpenSSH messages differ slightly between distributions and releases. Match
# known failure messages, then validate the captured address with ipaddress.
FAILURE_PATTERNS = (
    re.compile(r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+)", re.I),
    re.compile(r"Invalid user \S+ from (?P<ip>\S+)", re.I),
    re.compile(r"maximum authentication attempts exceeded for .* from (?P<ip>\S+)", re.I),
)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True)
class Config:
    auth_log: Path
    state_file: Path
    fail_threshold: int
    window_seconds: int
    alert_cooldown: int
    abuse_threshold: int
    abuse_cache_ttl: int
    telegram_retry_seconds: int
    abuse_api_key: str | None
    telegram_token: str | None
    telegram_chat_id: str | None
    poll_seconds: float
    whitelist: tuple[ipaddress._BaseNetwork, ...]
    host_label: str
    require_reputation: bool

    @classmethod
    def from_environment(cls) -> "Config":
        default_state = Path(os.getenv("XDG_STATE_HOME", Path.home() / ".local/state")) / "logguard/state.json"
        raw_whitelist = os.getenv("LOGGUARD_WHITELIST", "127.0.0.1,::1")
        networks: list[ipaddress._BaseNetwork] = []
        for item in raw_whitelist.split(","):
            item = item.strip()
            if item:
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                except ValueError as exc:
                    raise ValueError(f"Invalid network in LOGGUARD_WHITELIST: {item}") from exc

        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip() or None
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip() or None
        if bool(token) != bool(chat_id):
            raise ValueError("Set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or leave both unset")

        return cls(
            auth_log=Path(os.getenv("LOGGUARD_AUTH_LOG", "/var/log/auth.log")),
            state_file=Path(os.getenv("LOGGUARD_STATE_FILE", str(default_state))),
            fail_threshold=env_int("LOGGUARD_FAIL_THRESHOLD", 5),
            window_seconds=env_int("LOGGUARD_WINDOW_SECONDS", 600),
            alert_cooldown=env_int("LOGGUARD_ALERT_COOLDOWN_SECONDS", 21600),
            abuse_threshold=env_int("ABUSEIPDB_THRESHOLD", 50, minimum=0),
            abuse_cache_ttl=env_int("ABUSEIPDB_CACHE_TTL_SECONDS", 86400),
            telegram_retry_seconds=env_int("LOGGUARD_TELEGRAM_RETRY_SECONDS", 60),
            abuse_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip() or None,
            telegram_token=token,
            telegram_chat_id=chat_id,
            poll_seconds=float(os.getenv("LOGGUARD_POLL_SECONDS", "0.5")),
            whitelist=tuple(networks),
            host_label=os.getenv("LOGGUARD_HOST_LABEL", socket.gethostname()),
            require_reputation=env_bool("LOGGUARD_REQUIRE_REPUTATION", False),
        )


class StateStore:
    """Small atomic JSON store for API cache and alert cooldown timestamps."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.abuse_cache: dict[str, dict[str, Any]] = {}
        self.last_alert: dict[str, float] = {}

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.abuse_cache = data.get("abuse_cache", {}) if isinstance(data.get("abuse_cache", {}), dict) else {}
                self.last_alert = data.get("last_alert", {}) if isinstance(data.get("last_alert", {}), dict) else {}
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning("Could not load state file (%s); starting with an empty cache", type(exc).__name__)

    def save(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps({"abuse_cache": self.abuse_cache, "last_alert": self.last_alert}, separators=(",", ":"))
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as tmp:
                tmp_name = tmp.name
                os.chmod(tmp_name, 0o600)
                tmp.write(payload)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.path)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            LOG.error("Could not save state (%s)", type(exc).__name__)
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass


class Enrichment:
    def __init__(self, config: Config, state: StateStore) -> None:
        self.config = config
        self.state = state
    def abuse_score(self, address: str) -> int | None:
        if not self.config.abuse_api_key:
            return None
        now = time.time()
        cached = self.state.abuse_cache.get(address)
        if isinstance(cached, dict):
            age = now - float(cached.get("timestamp", 0))
            score = cached.get("score")
            ttl = self.config.abuse_cache_ttl if isinstance(score, int) else min(self.config.abuse_cache_ttl, 300)
            if 0 <= age < ttl:
                return score if isinstance(score, int) else None

        try:
            query = urllib.parse.urlencode({"ipAddress": address, "maxAgeInDays": 90})
            request = urllib.request.Request(
                f"https://api.abuseipdb.com/api/v2/check?{query}",
                headers={"Key": self.config.abuse_api_key, "Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
            score = body.get("data", {}).get("abuseConfidenceScore")
            if not isinstance(score, int) or not 0 <= score <= 100:
                raise ValueError("unexpected score in AbuseIPDB response")
            self.state.abuse_cache[address] = {"score": score, "timestamp": now}
            self.state.save()
            return score
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            # Cache failures briefly so a burst cannot hammer the service.
            self.state.abuse_cache[address] = {"score": None, "timestamp": now}
            self.state.save()
            LOG.warning("AbuseIPDB lookup failed for %s (%s)", address, type(exc).__name__)
            return None

    def send_telegram(self, message: str) -> bool:
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            return False
        url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendMessage"
        try:
            payload = urllib.parse.urlencode({"chat_id": self.config.telegram_chat_id, "text": message}).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status < 200 or response.status >= 300:
                    raise urllib.error.HTTPError(url, response.status, "Telegram rejected request", response.headers, None)
            return True
        except (urllib.error.URLError, TimeoutError) as exc:
            # Do not log request URLs: Telegram URLs contain the bot token.
            LOG.error("Telegram delivery failed (%s)", type(exc).__name__)
            return False


class LogGuard:
    def __init__(self, config: Config, state: StateStore, enrichment: Enrichment) -> None:
        self.config = config
        self.state = state
        self.enrichment = enrichment
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.delivery_retry: dict[str, float] = {}
        self.stopping = False

    def stop(self, *_: object) -> None:
        self.stopping = True

    def parse_address(self, line: str) -> str | None:
        for pattern in FAILURE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            raw = match.group("ip").rstrip(".,;:")
            # sshd normally appends a port after the address. The pattern
            # captures the address token only; ipaddress rejects malformed data.
            try:
                return str(ipaddress.ip_address(raw))
            except ValueError:
                LOG.debug("Ignoring invalid address token in auth log")
        return None

    def is_whitelisted(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip.version == net.version and ip in net for net in self.config.whitelist)

    def process_line(self, line: str) -> None:
        address = self.parse_address(line)
        if not address or self.is_whitelisted(address):
            return
        now = time.time()
        events = self.failures[address]
        cutoff = now - self.config.window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        events.append(now)
        count = len(events)
        LOG.info("SSH authentication failure source=%s count=%d window_seconds=%d", address, count, self.config.window_seconds)
        if count < self.config.fail_threshold:
            return

        score = self.enrichment.abuse_score(address)
        if self.config.require_reputation and (score is None or score < self.config.abuse_threshold):
            return

        last = float(self.state.last_alert.get(address, 0))
        if now - last < self.config.alert_cooldown:
            return
        if address in self.delivery_retry and now - self.delivery_retry[address] < self.config.telegram_retry_seconds:
            return

        score_text = f"{score}%" if score is not None else "unavailable"
        message = (
            "LogGuard SSH alert\n"
            f"Host: {self.config.host_label}\n"
            f"Source IP: {address}\n"
            f"Failed attempts: {count} in {self.config.window_seconds} seconds\n"
            f"AbuseIPDB score: {score_text}"
        )
        LOG.warning("SSH alert source=%s count=%d abuse_score=%s", address, count, score_text)
        delivered = self.enrichment.send_telegram(message)
        if delivered or not self.config.telegram_token:
            self.state.last_alert[address] = now
            self.state.save()
            self.delivery_retry.pop(address, None)
        else:
            self.delivery_retry[address] = now

    def monitor(self, from_start: bool = False) -> None:
        if not self.config.auth_log.exists():
            raise FileNotFoundError(f"Authentication log does not exist: {self.config.auth_log}")

        handle = self.config.auth_log.open("r", encoding="utf-8", errors="replace")
        try:
            if not from_start:
                handle.seek(0, os.SEEK_END)
            identity = (os.fstat(handle.fileno()).st_dev, os.fstat(handle.fileno()).st_ino)
            LOG.info("Monitoring %s", self.config.auth_log)

            while not self.stopping:
                line = handle.readline()
                if line:
                    self.process_line(line)
                    continue

                try:
                    stat = self.config.auth_log.stat()
                    path_identity = (stat.st_dev, stat.st_ino)
                    current = os.fstat(handle.fileno())
                    if path_identity != identity or stat.st_size < handle.tell():
                        handle.close()
                        handle = self.config.auth_log.open("r", encoding="utf-8", errors="replace")
                        if not from_start:
                            handle.seek(0, os.SEEK_END)
                        current = os.fstat(handle.fileno())
                        identity = (current.st_dev, current.st_ino)
                        LOG.info("Authentication log rotated or truncated; reopened")
                except FileNotFoundError:
                    # logrotate may briefly remove the path before replacement.
                    time.sleep(self.config.poll_seconds)
                    continue
                time.sleep(self.config.poll_seconds)
        finally:
            handle.close()


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOGGUARD_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor SSH authentication failures and send alerts.")
    parser.add_argument("--from-start", action="store_true", help="Process existing log contents before following new entries")
    parser.add_argument("--check-config", action="store_true", help="Validate environment configuration and exit")
    args = parser.parse_args()
    configure_logging()
    try:
        config = Config.from_environment()
        if config.poll_seconds <= 0:
            raise ValueError("LOGGUARD_POLL_SECONDS must be greater than zero")
        if args.check_config:
            print("Configuration is valid")
            return 0
        state = StateStore(config.state_file)
        state.load()
        app = LogGuard(config, state, Enrichment(config, state))
        signal.signal(signal.SIGINT, app.stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, app.stop)
        LOG.info("LogGuard started; threshold=%d window_seconds=%d reputation_required=%s", config.fail_threshold, config.window_seconds, config.require_reputation)
        if not config.abuse_api_key:
            LOG.info("AbuseIPDB enrichment is disabled; threshold alerts still work")
        if not config.telegram_token:
            LOG.info("Telegram delivery is disabled; alerts will be written to the service log")
        app.monitor(from_start=args.from_start)
        LOG.info("LogGuard stopped")
        return 0
    except (ValueError, OSError) as exc:
        LOG.error("Startup failed: %s", exc)
        return 2
    except Exception:
        LOG.exception("Unexpected fatal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
