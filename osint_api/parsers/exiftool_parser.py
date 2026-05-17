from __future__ import annotations
import json
import re


_GPS_FIELDS = {"GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSPosition"}
_PRIVACY_FIELDS = {"Author", "Creator", "Artist", "Copyright", "OwnerName",
                   "GPSLatitude", "GPSLongitude", "CameraOwnerName", "SerialNumber"}


def parse(raw: str) -> dict:
    metadata: dict = {}
    privacy_risks: list[str] = []

    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            metadata = {k: v for k, v in data.items() if not k.startswith("SourceFile")}
    except json.JSONDecodeError:
        # Plain text fallback: "Tag : Value"
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                metadata[k.strip()] = v.strip()

    for field in _PRIVACY_FIELDS:
        if any(field.lower() in k.lower() for k in metadata):
            privacy_risks.append(f"Found potentially sensitive metadata field: {field}")

    gps_present = any(k.startswith("GPS") for k in metadata)

    return {
        "metadata": metadata,
        "gps_present": gps_present,
        "privacy_risks": privacy_risks,
        "field_count": len(metadata),
    }
