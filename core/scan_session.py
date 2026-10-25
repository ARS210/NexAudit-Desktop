"""
core/scan_session.py

Manages a passive `airodump-ng` scan as a background process. The tool
writes CSV snapshots to disk on an interval; we tail/re-parse the CSV
rather than scraping stdout, since airodump-ng's terminal UI is not
meant to be machine-parsed.

This module intentionally exposes NO channel-lock-and-deauth helpers,
no WPA handshake capture triggers, and no injection flags — passive
observation only.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class ScanConfig:
    monitor_interface: str
    output_dir: Path
    session_label: str
    channel: int | None = None  # None = hop all channels (passive default)
    band: str = "abg"  # a/b/g bands to scan


class ScanSession:
    def __init__(self, config: ScanConfig, audit_log_path: Path):
        self.config = config
        self.audit_log_path = audit_log_path
        self.output_prefix = config.output_dir / config.session_label
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.process: subprocess.Popen | None = None

    def _log_command(self, cmd: list[str]):
        line = f"{datetime.utcnow().isoformat()}Z  CMD: {shlex.join(cmd)}"
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_log_path, "a") as f:
            f.write(line + "\n")

    def start(self) -> subprocess.Popen:
        cmd = [
            "airodump-ng",
            "--output-format", "csv",
            "--write", str(self.output_prefix),
            "--band", self.config.band,
        ]
        if self.config.channel:
            cmd += ["--channel", str(self.config.channel)]
        cmd.append(self.config.monitor_interface)

        self._log_command(cmd)
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return self.process

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout: int = 5):
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout)

    def csv_path(self) -> Path:
        # airodump-ng appends "-01.csv" to the given prefix
        return self.output_prefix.with_name(self.output_prefix.name + "-01.csv")
