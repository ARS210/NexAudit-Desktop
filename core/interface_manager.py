"""
core/interface_manager.py

Thin, defensive wrapper around `airmon-ng` for enumerating wireless
interfaces and toggling monitor mode. Every privileged command is
appended to an append-only audit log before execution, so the tool
produces its own evidence trail of what was run and when.

No offensive/attack logic lives here — only interface lifecycle
management needed for passive scanning.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


class ToolNotFoundError(RuntimeError):
    """Raised when a required aircrack-ng suite binary is missing."""


@dataclass
class WirelessInterface:
    name: str
    driver: str = ""
    chipset: str = ""
    mode: str = "unknown"  # "managed" | "monitor" | "unknown"


class InterfaceManager:
    REQUIRED_TOOLS = ("airmon-ng", "airodump-ng")

    def __init__(self, audit_log_path: Path):
        self.audit_log_path = audit_log_path
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._check_tools_present()

    # ---------- setup / safety checks ----------

    def _check_tools_present(self):
        missing = [t for t in self.REQUIRED_TOOLS if shutil.which(t) is None]
        if missing:
            raise ToolNotFoundError(
                "Missing required tool(s): " + ", ".join(missing) +
                ". Install the aircrack-ng suite (e.g. `sudo apt install aircrack-ng`)."
            )

    def _log_command(self, cmd: list[str], note: str = ""):
        line = f"{datetime.utcnow().isoformat()}Z  CMD: {shlex.join(cmd)}"
        if note:
            line += f"  # {note}"
        with open(self.audit_log_path, "a") as f:
            f.write(line + "\n")

    def _run(self, cmd: list[str], note: str = "", timeout: int = 30) -> subprocess.CompletedProcess:
        self._log_command(cmd, note)
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )

    # ---------- interface discovery ----------

    def list_interfaces(self) -> list[WirelessInterface]:
        """
        Parses `airmon-ng` (no args) output, which lists PHY / interface /
        driver / chipset columns.
        """
        result = self._run(["airmon-ng"], note="list interfaces")
        return self._parse_interface_list(result.stdout)

    @staticmethod
    def _parse_interface_list(output: str) -> list[WirelessInterface]:
        interfaces = []
        lines = [l for l in output.splitlines() if l.strip()]
        for line in lines:
            # Typical row: "phy0    wlan0      Realtek ...   RTL8812AU"
            # airmon-ng separates columns with tabs and/or runs of spaces;
            # a single tab still counts as a column boundary.
            parts = re.split(r"\t+| {2,}", line.strip())
            if not parts:
                continue
            # Skip the literal header row ("PHY  Interface  Driver  Chipset"),
            # but NOT data rows, which happen to start with "phy0", "phy1", etc.
            if parts[0].strip().lower() in ("phy", "interface"):
                continue
            if len(parts) >= 2 and re.match(r"^(wlan|wlp|mon)\w*\d*", parts[1] if len(parts) > 1 else ""):
                name = parts[1]
                driver = parts[2] if len(parts) > 2 else ""
                chipset = parts[3] if len(parts) > 3 else ""
                interfaces.append(WirelessInterface(name=name, driver=driver, chipset=chipset))
        return interfaces

    # ---------- monitor mode lifecycle ----------

    def enable_monitor_mode(self, iface: str) -> str:
        """
        Starts monitor mode on `iface`. Returns the resulting monitor
        interface name (often the same name, or `<iface>mon`).
        """
        result = self._run(["airmon-ng", "start", iface], note=f"enable monitor mode on {iface}")
        mon_name = self._extract_monitor_iface_name(result.stdout) or iface
        return mon_name

    def disable_monitor_mode(self, iface: str):
        self._run(["airmon-ng", "stop", iface], note=f"disable monitor mode on {iface}")

    @staticmethod
    def _extract_monitor_iface_name(output: str) -> str | None:
        # airmon-ng typically prints something like:
        # "monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
        match = re.search(r"on\s+\[?\w*\]?(\w+mon)\b", output)
        if match:
            return match.group(1)
        match = re.search(r"monitor mode.*enabled.*?(\w+mon)\b", output, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def kill_interfering_processes(self):
        """
        Wraps `airmon-ng check kill`, which stops NetworkManager/wpa_supplicant
        so they don't fight with monitor mode. Logged like any other command.
        """
        self._run(["airmon-ng", "check", "kill"], note="stop interfering processes")
