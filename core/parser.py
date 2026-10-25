"""
core/parser.py

Parses airodump-ng's CSV output into structured AccessPoint / Station
records. The file has two sections (APs, then client Stations)
separated by a blank line, each with its own header row. The file is
rewritten periodically while a scan runs, and rows can occasionally be
mid-write / malformed — so parsing is defensive: bad rows are skipped
rather than raising.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AccessPoint:
    bssid: str
    first_seen: str
    last_seen: str
    channel: int
    speed: str
    privacy: str
    cipher: str
    authentication: str
    power: int
    beacons: int
    iv_data: int
    essid: str

    @property
    def is_open(self) -> bool:
        p = self.privacy.strip().upper()
        return p in ("", "OPN", "OPEN")


@dataclass
class Station:
    mac: str
    first_seen: str
    last_seen: str
    power: int
    packets: int
    associated_bssid: str


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


def parse_airodump_csv(path: Path) -> tuple[list[AccessPoint], list[Station]]:
    if not path.exists():
        return [], []

    text = path.read_text(errors="replace")
    # The two sections are separated by a blank line
    ap_block, _, station_block = text.partition("\n\n")

    access_points: list[AccessPoint] = []
    reader = csv.reader(ap_block.splitlines())
    next(reader, None)  # header row
    for row in reader:
        if len(row) < 14:
            continue
        try:
            access_points.append(AccessPoint(
                bssid=row[0].strip(),
                first_seen=row[1].strip(),
                last_seen=row[2].strip(),
                channel=_safe_int(row[3]),
                speed=row[4].strip(),
                privacy=row[5].strip(),
                cipher=row[6].strip(),
                authentication=row[7].strip(),
                power=_safe_int(row[8], default=-100),
                beacons=_safe_int(row[9]),
                iv_data=_safe_int(row[10]),
                essid=row[13].strip().strip("\x00"),
            ))
        except IndexError:
            continue

    stations: list[Station] = []
    reader = csv.reader(station_block.splitlines())
    next(reader, None)  # header row
    for row in reader:
        if len(row) < 6:
            continue
        try:
            stations.append(Station(
                mac=row[0].strip(),
                first_seen=row[1].strip(),
                last_seen=row[2].strip(),
                power=_safe_int(row[3], default=-100),
                packets=_safe_int(row[4]),
                associated_bssid=row[5].strip(),
            ))
        except IndexError:
            continue

    return access_points, stations
