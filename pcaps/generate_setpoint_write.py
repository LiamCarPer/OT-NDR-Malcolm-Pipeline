#!/usr/bin/env python3
"""
Generate the Modbus setpoint-write captures used by the NDR pipeline.

The committed captures are small and synthetic by design: the proof this
repository needs must be reproducible without a live plant. This script writes
two captures that contain the same *kind* of operation in two different
contexts, which is what the severity model is built to tell apart:

- ``setpoint_write.pcap`` - 2026-05-01 10:31:00 UTC, outside any approved change
  window, so it is reported CRITICAL.
- ``setpoint_write_maintenance.pcap`` - 2026-05-02 02:15:00 UTC, inside the
  approved window CHG-1042 in ``automation/change_windows.json``, so the same
  classification is reported one step lower.

The output is deterministic: the same commit always produces the same bytes.

Sessions include a full TCP handshake so Suricata treats them as established
flows, which the ``flow:to_server,established`` rules in ot-detection-engineering
require.

Usage:
    python3 pcaps/generate_setpoint_write.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"

HMI = "172.24.0.10"   # Engineering HMI (Purdue L2); not an allowlisted control writer
PLC = "172.21.0.10"   # Intake PLC (Purdue L1)
PLC_PORT = 502

SETPOINT_REGISTER = 1050

CAPTURES = [
    {
        "name": "setpoint_write.pcap",
        "base_time": datetime(2026, 5, 1, 10, 31, 0, tzinfo=timezone.utc).timestamp(),
        "value": 4200,
    },
    {
        "name": "setpoint_write_maintenance.pcap",
        "base_time": datetime(2026, 5, 2, 2, 15, 0, tzinfo=timezone.utc).timestamp(),
        "value": 4150,
    },
]


def modbus(transaction: int, unit: int, function: int, data: bytes) -> bytes:
    """Build a Modbus/TCP frame: MBAP header followed by the PDU."""
    pdu = bytes([function]) + data
    header = (
        transaction.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
    )
    return header + bytes([unit]) + pdu


def read_holding_registers(transaction: int, reference: int, quantity: int) -> bytes:
    """FC 3 read-holding-registers request."""
    return modbus(transaction, 1, 3, reference.to_bytes(2, "big") + quantity.to_bytes(2, "big"))


def read_holding_registers_response(transaction: int, payload: bytes) -> bytes:
    """FC 3 response: byte count followed by the register values."""
    return modbus(transaction, 1, 3, bytes([len(payload)]) + payload)


def write_single_register(transaction: int, reference: int, value: int) -> bytes:
    """FC 6 write-single-register. The response echoes the request."""
    return modbus(transaction, 1, 6, reference.to_bytes(2, "big") + value.to_bytes(2, "big"))


def session(client_port: int, start: float, requests: list[bytes], responses: list[bytes]) -> list:
    """Build one complete TCP session: handshake, request/response pairs, teardown."""
    seq_c, seq_s = 1000, 5000
    packets: list = []
    clock = [start]

    def add(src: str, dst: str, sport: int, dport: int, flags: str, seq: int, ack: int,
            payload: bytes = b"") -> None:
        src_mac, dst_mac = (CLIENT_MAC, SERVER_MAC) if src == HMI else (SERVER_MAC, CLIENT_MAC)
        packet = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            packet = packet / Raw(load=payload)
        packet.time = clock[0]
        packets.append(packet)
        clock[0] += 0.002

    add(HMI, PLC, client_port, PLC_PORT, "S", seq_c, 0)
    add(PLC, HMI, PLC_PORT, client_port, "SA", seq_s, seq_c + 1)
    add(HMI, PLC, client_port, PLC_PORT, "A", seq_c + 1, seq_s + 1)
    ack_c, ack_s = seq_c + 1, seq_s + 1

    for payload, response in zip(requests, responses):
        add(HMI, PLC, client_port, PLC_PORT, "PA", ack_c, ack_s, payload)
        ack_c += len(payload)
        add(PLC, HMI, PLC_PORT, client_port, "A", ack_s, ack_c)
        if response:
            add(PLC, HMI, PLC_PORT, client_port, "PA", ack_s, ack_c, response)
            ack_s += len(response)
            add(HMI, PLC, client_port, PLC_PORT, "A", ack_c, ack_s)

    add(HMI, PLC, client_port, PLC_PORT, "FA", ack_c, ack_s)
    add(PLC, HMI, PLC_PORT, client_port, "FA", ack_s, ack_c + 1)
    add(HMI, PLC, client_port, PLC_PORT, "A", ack_c + 1, ack_s + 1)
    return packets


def build(base_time: float, value: int) -> list:
    """Build one capture: routine polling, then a poll, a setpoint write and a read-back."""
    packets = session(
        41000,
        base_time,
        [read_holding_registers(t, 0, 10) for t in range(1, 5)],
        [read_holding_registers_response(t, bytes(20)) for t in range(1, 5)],
    )
    packets += session(
        41001,
        base_time + 60,
        [
            read_holding_registers(5, 0, 10),
            write_single_register(6, SETPOINT_REGISTER, value),
            read_holding_registers(7, SETPOINT_REGISTER, 2),
        ],
        [
            read_holding_registers_response(5, bytes(20)),
            write_single_register(6, SETPOINT_REGISTER, value),
            read_holding_registers_response(7, value.to_bytes(2, "big") + b"\x00\x00"),
        ],
    )
    return packets


def main() -> None:
    """Write every capture next to this script."""
    here = Path(__file__).resolve().parent
    for spec in CAPTURES:
        packets = build(spec["base_time"], spec["value"])
        out = here / spec["name"]
        wrpcap(str(out), packets)
        print(f"Wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
