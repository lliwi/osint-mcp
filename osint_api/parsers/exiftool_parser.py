"""
ExifTool parser — type-aware metadata extraction.
Handles images, PDFs, and office documents (OOXML, ODF, legacy Office).
"""
from __future__ import annotations

import json
import re
from typing import Any


# ─── Privacy-sensitive fields by category ────────────────────────────────────

_GPS_FIELDS = {
    "GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSPosition",
    "GPSLatitudeRef", "GPSLongitudeRef", "GPSDateTime",
}

_IDENTITY_FIELDS = {
    "Author", "Creator", "Artist", "OwnerName", "CameraOwnerName",
    "LastModifiedBy", "LastSavedBy", "ModifiedBy",
}

_ORG_FIELDS = {
    "Company", "Manager", "Template",
}

_DEVICE_FIELDS = {
    "Make", "Model", "SerialNumber", "LensModel", "LensID",
    "Software", "Application", "AppVersion",
}

_PATH_LEAK_FIELDS = {
    "Template", "LinkedFileName", "SourceFile",
}

# All fields that constitute privacy risks
_ALL_PRIVACY_FIELDS = (
    _GPS_FIELDS | _IDENTITY_FIELDS | _ORG_FIELDS | _DEVICE_FIELDS | _PATH_LEAK_FIELDS
)

# ─── Document type detection ──────────────────────────────────────────────────

_IMAGE_TYPES = {
    "JPEG", "JPG", "PNG", "TIFF", "TIF", "GIF", "WEBP", "BMP",
    "HEIC", "HEIF", "RAW", "CR2", "CR3", "NEF", "ARW", "DNG",
    "ORF", "RW2", "PEF", "SR2", "RAF",
}
_PDF_TYPES = {"PDF"}
_OFFICE_OOXML = {"DOCX", "XLSX", "PPTX", "DOTX", "XLTX", "POTX"}
_OFFICE_ODF   = {"ODT", "ODS", "ODP", "ODF"}
_OFFICE_LEGACY = {"DOC", "XLS", "PPT", "DOT", "XLT", "POT"}
_OFFICE_TYPES  = _OFFICE_OOXML | _OFFICE_ODF | _OFFICE_LEGACY


def _doc_type(metadata: dict) -> str:
    """Returns normalized document type string."""
    file_type = (
        metadata.get("FileType") or
        metadata.get("FileTypeExtension") or
        metadata.get("MIMEType", "")
    ).upper().split("/")[-1].split(";")[0].strip()
    if file_type in _IMAGE_TYPES:
        return "image"
    if file_type in _PDF_TYPES:
        return "pdf"
    if file_type in _OFFICE_TYPES:
        return "office"
    return "unknown"


# ─── Field sets to surface per type ──────────────────────────────────────────

_IMAGE_SURFACE = [
    "Make", "Model", "SerialNumber", "LensModel",
    "DateTimeOriginal", "CreateDate", "ModifyDate",
    "Software", "Artist", "Author", "Copyright", "OwnerName",
    "GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSPosition",
    "ImageWidth", "ImageHeight", "ColorSpace", "BitDepth",
    "ExposureTime", "FNumber", "ISO", "FocalLength",
]

_PDF_SURFACE = [
    "Author", "Creator", "Producer", "Title", "Subject", "Keywords",
    "CreateDate", "ModifyDate",
    "PDFVersion", "Linearized", "Encryption", "PageCount",
    "PageMode", "Tagged", "XMPToolkit",
]

_OFFICE_SURFACE = [
    "Author", "Creator", "LastModifiedBy", "LastSavedBy",
    "Company", "Manager", "Template",
    "CreateDate", "ModifyDate", "LastSaved",
    "RevisionNumber", "TotalEditTime",
    "Words", "Characters", "Pages", "Slides", "Notes", "HiddenSlides",
    "Application", "AppVersion",
    "Title", "Subject", "Keywords", "Description", "Category",
]


def _surface_fields(metadata: dict, field_list: list[str]) -> dict:
    """Returns dict of present fields from the surface list."""
    result = {}
    for field in field_list:
        for key, val in metadata.items():
            if key.lower().replace(" ", "") == field.lower().replace(" ", ""):
                result[field] = val
                break
    return result


# ─── Privacy risk detection ───────────────────────────────────────────────────

def _detect_privacy_risks(metadata: dict, doc_type: str) -> list[str]:
    risks = []
    keys_lower = {k.lower(): k for k in metadata}

    # GPS in images
    if any(f.lower() in keys_lower for f in _GPS_FIELDS):
        risks.append("GPS coordinates found — physical location may be exposed")

    # Identity fields
    identity_found = [
        f for f in _IDENTITY_FIELDS
        if f.lower() in keys_lower and metadata.get(keys_lower.get(f.lower(), ""))
    ]
    if identity_found:
        risks.append(f"Personal identity metadata: {', '.join(identity_found)}")

    # Organisation
    org_found = [
        f for f in _ORG_FIELDS
        if f.lower() in keys_lower and metadata.get(keys_lower.get(f.lower(), ""))
    ]
    if org_found:
        risks.append(f"Organisation metadata: {', '.join(org_found)}")

    # Internal paths (Template usually contains Windows paths)
    template = metadata.get("Template", "")
    if template and ("\\" in str(template) or "/" in str(template)):
        risks.append(f"Internal path leaked in Template field: {template}")

    # Revision history (office)
    if doc_type == "office":
        rev = metadata.get("RevisionNumber", "")
        if rev and int(str(rev) or "0") > 1:
            risks.append(
                f"Document has {rev} revisions — revision history may contain deleted content"
            )
        edit_time = metadata.get("TotalEditTime", "")
        if edit_time:
            risks.append(f"Total edit time exposed: {edit_time}")

    # Device serial number
    serial = metadata.get("SerialNumber") or metadata.get("CameraOwnerName", "")
    if serial:
        risks.append(f"Camera/device serial number found: {serial}")

    return risks


# ─── Public parse function ────────────────────────────────────────────────────

def parse(raw: str) -> dict:
    """
    Parse exiftool -json output.
    Returns typed metadata, surfaced key fields, GPS flag, and privacy risks.
    """
    metadata: dict[str, Any] = {}

    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            # Drop internal exiftool fields
            metadata = {
                k: v for k, v in data.items()
                if not k.startswith("SourceFile") and k != "ExifToolVersion"
            }
    except (json.JSONDecodeError, IndexError):
        # Plain text fallback: "Tag : Value"
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                metadata[k.strip()] = v.strip()

    doc_type = _doc_type(metadata)
    gps_present = any(
        k.startswith("GPS") for k in metadata
    )

    # Surface relevant fields per type
    if doc_type == "image":
        surfaced = _surface_fields(metadata, _IMAGE_SURFACE)
    elif doc_type == "pdf":
        surfaced = _surface_fields(metadata, _PDF_SURFACE)
    elif doc_type == "office":
        surfaced = _surface_fields(metadata, _OFFICE_SURFACE)
    else:
        # Unknown: surface all non-binary fields
        surfaced = {
            k: v for k, v in metadata.items()
            if isinstance(v, (str, int, float, bool)) and len(str(v)) < 500
        }

    privacy_risks = _detect_privacy_risks(metadata, doc_type)

    return {
        "doc_type": doc_type,
        "metadata": metadata,          # full raw metadata
        "surfaced": surfaced,          # key fields for this file type
        "gps_present": gps_present,
        "privacy_risks": privacy_risks,
        "field_count": len(metadata),
        "file_type": metadata.get("FileType", metadata.get("FileTypeExtension", "unknown")),
        "mime_type": metadata.get("MIMEType", ""),
    }
