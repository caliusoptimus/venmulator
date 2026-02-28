"""Protocol helpers for the emulated Venstar WiFi sensor."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any


def normalize_mac(mac: str) -> str:
    """Normalize MAC to 12 lowercase hex chars (no separators)."""
    cleaned = mac.lower().replace(":", "").replace("-", "")
    if len(cleaned) != 12 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("MAC must be 12 hex chars")
    return cleaned


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint requires non-negative value")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    i = offset
    while i < len(buf):
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too large")
    raise ValueError("truncated varint")


def encode_key(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def encode_field_varint(field_number: int, value: int) -> bytes:
    return encode_key(field_number, 0) + encode_varint(value)


def encode_field_bytes(field_number: int, data: bytes) -> bytes:
    return encode_key(field_number, 2) + encode_varint(len(data)) + data


def parse_fields(buf: bytes) -> list[tuple[int, int, int | bytes]]:
    i = 0
    fields: list[tuple[int, int, int | bytes]] = []
    while i < len(buf):
        key, i = decode_varint(buf, i)
        field_number = key >> 3
        wire_type = key & 0x7
        if wire_type == 0:
            value, i = decode_varint(buf, i)
            fields.append((field_number, wire_type, value))
        elif wire_type == 2:
            length, i = decode_varint(buf, i)
            if i + length > len(buf):
                raise ValueError("truncated field")
            value = buf[i : i + length]
            i += length
            fields.append((field_number, wire_type, value))
        else:
            raise ValueError(f"unsupported wire_type={wire_type}")
    return fields


def temp_c_to_index(temp_c: float) -> int:
    idx = int(round((temp_c + 40.0) * 2.0))
    return max(0, min(253, idx))


def index_to_temp_c(temp_idx: int) -> float:
    return -40.0 + 0.5 * temp_idx


def build_info(
    *,
    sequence: int,
    mac: str,
    unit_id: int,
    sensor_name: str,
    sensor_type: int,
    temp_idx: int,
    battery_percent: int,
) -> bytes:
    mac_norm = normalize_mac(mac)
    parts = [
        encode_field_varint(1, sequence),
        encode_field_varint(2, 1),
        encode_field_bytes(3, mac_norm.encode("ascii")),
        encode_field_varint(4, unit_id),
        encode_field_varint(5, 9),
        encode_field_varint(6, 1),
        encode_field_varint(7, 1),
        encode_field_bytes(8, sensor_name.encode("utf-8")),
        encode_field_varint(9, sensor_type),
        encode_field_varint(10, temp_idx),
        encode_field_varint(11, battery_percent),
    ]
    return b"".join(parts)


def hmac_b64(key: bytes, info_bytes: bytes) -> str:
    digest = hmac.new(key, info_bytes, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def build_message(*, message_type: int, info_bytes: bytes, auth_b64: str) -> bytes:
    body = b"".join(
        [
            encode_field_bytes(1, info_bytes),
            encode_field_bytes(2, auth_b64.encode("ascii")),
        ]
    )
    payload = b"".join(
        [
            encode_field_varint(1, message_type),
            encode_field_bytes(42, body),
        ]
    )
    return payload


def decode_message(payload: bytes) -> dict[str, Any]:
    top = parse_fields(payload)
    msg_type = next(v for f, w, v in top if f == 1 and w == 0)
    body = next(v for f, w, v in top if f == 42 and w == 2)
    if not isinstance(msg_type, int) or not isinstance(body, bytes):
        raise ValueError("invalid payload")

    body_fields = parse_fields(body)
    info = next(v for f, w, v in body_fields if f == 1 and w == 2)
    auth = next(v for f, w, v in body_fields if f == 2 and w == 2)
    if not isinstance(info, bytes) or not isinstance(auth, bytes):
        raise ValueError("invalid body")

    info_fields = parse_fields(info)
    varints = {f: v for f, w, v in info_fields if w == 0 and isinstance(v, int)}
    strings = {f: v for f, w, v in info_fields if w == 2 and isinstance(v, bytes)}

    return {
        "message_type": msg_type,
        "auth_b64": auth.decode("ascii"),
        "info_hex": info.hex(),
        "fields": {
            "sequence": int(varints.get(1, 0)),
            "const_2": int(varints.get(2, 0)),
            "mac": strings.get(3, b"").decode("ascii", errors="ignore"),
            "unit_id": int(varints.get(4, 0)),
            "const_5": int(varints.get(5, 0)),
            "const_6": int(varints.get(6, 0)),
            "const_7": int(varints.get(7, 0)),
            "name": strings.get(8, b"").decode("utf-8", errors="ignore"),
            "sensor_type": int(varints.get(9, 0)),
            "temperature_index": int(varints.get(10, 0)),
            "battery_percent": int(varints.get(11, 0)),
        },
    }
