#!/usr/bin/env python3
"""
NexAudit — entry point.

Usage:
    python3 main.py

Requirements:
    - Linux, with the aircrack-ng suite installed (airmon-ng, airodump-ng)
    - A wireless adapter that supports monitor mode
    - Run monitor-mode / scan actions with sufficient privileges
      (see README.md — the recommended approach is a scoped sudoers
      entry or `pkexec`, NOT running the whole GUI as root)

NexAudit is for authorized security assessments only. See LEGAL_NOTICE
in version.py, or Help > Legal Notice inside the app.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from version import BUILD_STRING, LEGAL_NOTICE  # noqa: E402


def _preflight():
    if os.name != "posix":
        print("NexAudit targets Linux. Other platforms are unsupported.")
    if os.geteuid() == 0:
        print(
            "WARNING: NexAudit is running as root. It is recommended to run "
            "the GUI as a normal user and grant privileged commands via "
            "sudoers/pkexec instead (see README.md)."
        )


def main():
    print(BUILD_STRING)
    print(LEGAL_NOTICE)
    print("-" * 70)
    _preflight()

    from gui.app import run
    run()


if __name__ == "__main__":
    main()
