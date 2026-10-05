"""Data structures shared by Lantern modules."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Device:
    mac: str
    ip: str
    first_seen: float
    last_seen: float | None
    state: str = "ONLINE"
    name: str = ""
    source: str = "ARP"
    label: str = ""
    fingerprint: str = ""
    ping_result: str = ""


@dataclass
class Flow:
    source: str
    destination: str
    protocol: str
    source_port: int
    destination_port: int
    packets: int
    byte_count: int
    last_seen: float

