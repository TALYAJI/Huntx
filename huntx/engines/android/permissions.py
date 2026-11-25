"""HUNTX Android Permissions Analysis Engine.

Categorizes declared Android permissions into standard reconnaissance groups:
- Internet
- Storage
- Camera
- Location
- Contacts
- Microphone
- Phone
- SMS
- Network
- System-level
- Other

Note: Permissions are categorized for reconnaissance; they are NOT labeled as vulnerabilities.

Outputs:
- android/permissions.json
- android/permissions.txt
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from huntx.engines.android.manifest import analyze_manifest

logger = logging.getLogger(__name__)

# Standard permission knowledgebase (pure reconnaissance / descriptions)
PERMISSION_DETAILS: Dict[str, Dict[str, str]] = {
    "android.permission.INTERNET": {
        "category": "Internet",
        "protection": "normal",
        "description": "Allows applications to open network sockets.",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to access information about networks.",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to access information about Wi-Fi networks.",
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to change Wi-Fi connectivity state.",
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to change network connectivity state.",
    },
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to enter Wi-Fi Multicast mode.",
    },
    "android.permission.BLUETOOTH": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to connect to paired bluetooth devices.",
    },
    "android.permission.BLUETOOTH_ADMIN": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to discover and pair bluetooth devices.",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "category": "Network",
        "protection": "dangerous",
        "description": "Required to be able to connect to paired Bluetooth devices.",
    },
    "android.permission.BLUETOOTH_SCAN": {
        "category": "Network",
        "protection": "dangerous",
        "description": "Required to be able to discover and pair nearby Bluetooth devices.",
    },
    "android.permission.BLUETOOTH_ADVERTISE": {
        "category": "Network",
        "protection": "dangerous",
        "description": "Required to be able to advertise to nearby Bluetooth devices.",
    },
    "android.permission.NEARBY_WIFI_DEVICES": {
        "category": "Network",
        "protection": "dangerous",
        "description": "Required to be able to advertise, connect, and determine relative position to nearby Wi-Fi devices.",
    },
    "android.permission.NFC": {
        "category": "Network",
        "protection": "normal",
        "description": "Allows applications to perform I/O operations over NFC.",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to read from external storage.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to write to external storage.",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "category": "Storage",
        "protection": "signature|appop",
        "description": "Allows an application broad access to external storage in scoped storage.",
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to read image files from external storage.",
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to read video files from external storage.",
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to read audio files from external storage.",
    },
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to read visual media selected by user.",
    },
    "android.permission.ACCESS_MEDIA_LOCATION": {
        "category": "Storage",
        "protection": "dangerous",
        "description": "Allows an application to access any geographic locations saved in the user's media collection.",
    },
    "android.permission.CAMERA": {
        "category": "Camera",
        "protection": "dangerous",
        "description": "Required to be able to access the camera device.",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "category": "Location",
        "protection": "dangerous",
        "description": "Allows an app to access precise location.",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "category": "Location",
        "protection": "dangerous",
        "description": "Allows an app to access approximate location.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "category": "Location",
        "protection": "dangerous",
        "description": "Allows an app to access location in the background.",
    },
    "android.permission.READ_CONTACTS": {
        "category": "Contacts",
        "protection": "dangerous",
        "description": "Allows an application to read the user's contacts data.",
    },
    "android.permission.WRITE_CONTACTS": {
        "category": "Contacts",
        "protection": "dangerous",
        "description": "Allows an application to write the user's contacts data.",
    },
    "android.permission.GET_ACCOUNTS": {
        "category": "Contacts",
        "protection": "dangerous",
        "description": "Allows access to the list of accounts in the Accounts Service.",
    },
    "android.permission.RECORD_AUDIO": {
        "category": "Microphone",
        "protection": "dangerous",
        "description": "Allows an application to record audio.",
    },
    "android.permission.READ_PHONE_STATE": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows read only access to phone state, including the phone number of the device.",
    },
    "android.permission.CALL_PHONE": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to initiate a phone call without going through the Dialer.",
    },
    "android.permission.READ_CALL_LOG": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to read the user's call log.",
    },
    "android.permission.WRITE_CALL_LOG": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to write (but not read) the user's call log data.",
    },
    "android.permission.ADD_VOICEMAIL": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to add voicemails into the system.",
    },
    "android.permission.USE_SIP": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to use SIP service.",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows an application to see the number being dialed during an outgoing call.",
    },
    "android.permission.ANSWER_PHONE_CALLS": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows the app to answer an incoming phone call.",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "category": "Phone",
        "protection": "dangerous",
        "description": "Allows read access to the device's phone numbers.",
    },
    "android.permission.SEND_SMS": {
        "category": "SMS",
        "protection": "dangerous",
        "description": "Allows an application to send SMS messages.",
    },
    "android.permission.RECEIVE_SMS": {
        "category": "SMS",
        "protection": "dangerous",
        "description": "Allows an application to receive SMS messages.",
    },
    "android.permission.READ_SMS": {
        "category": "SMS",
        "protection": "dangerous",
        "description": "Allows an application to read SMS messages.",
    },
    "android.permission.RECEIVE_WAP_PUSH": {
        "category": "SMS",
        "protection": "dangerous",
        "description": "Allows an application to receive WAP push messages.",
    },
    "android.permission.RECEIVE_MMS": {
        "category": "SMS",
        "protection": "dangerous",
        "description": "Allows an application to monitor incoming MMS messages.",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows an application to receive the Intent.ACTION_BOOT_COMPLETED broadcast.",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "category": "System-level",
        "protection": "signature|appop",
        "description": "Allows an app to create windows shown on top of all other apps.",
    },
    "android.permission.WRITE_SETTINGS": {
        "category": "System-level",
        "protection": "signature|appop",
        "description": "Allows an application to read or write the system settings.",
    },
    "android.permission.WAKE_LOCK": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows using PowerManager WakeLocks to keep processor from sleeping.",
    },
    "android.permission.POST_NOTIFICATIONS": {
        "category": "System-level",
        "protection": "dangerous",
        "description": "Required to be able to post notifications from an application.",
    },
    "android.permission.SCHEDULE_EXACT_ALARM": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows applications to use exact alarm APIs.",
    },
    "android.permission.USE_BIOMETRIC": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows an application to use device supported biometric modalities.",
    },
    "android.permission.USE_FINGERPRINT": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows an application to use fingerprint hardware.",
    },
    "android.permission.VIBRATE": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows access to the vibrator.",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "category": "System-level",
        "protection": "normal",
        "description": "Allows query of any normal app on the device, regardless of manifest declarations.",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "category": "System-level",
        "protection": "signature|appop",
        "description": "Allows an application to request installing packages.",
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "category": "System-level",
        "protection": "normal",
        "description": "Permission an application must hold in order to use Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS.",
    },
}

CATEGORIES = [
    "Internet",
    "Storage",
    "Camera",
    "Location",
    "Contacts",
    "Microphone",
    "Phone",
    "SMS",
    "Network",
    "System-level",
    "Other",
]


@dataclass
class PermissionItem:
    """Detailed information for a single permission."""

    name: str
    category: str
    protection_level: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def categorize_permission(perm_name: str) -> str:
    """Determine the standard category for a given permission name."""
    clean = perm_name.strip()
    if clean in PERMISSION_DETAILS:
        return PERMISSION_DETAILS[clean]["category"]

    lower = clean.lower()
    if "internet" in lower:
        return "Internet"
    if any(k in lower for k in ["storage", "media", "document"]):
        return "Storage"
    if "camera" in lower:
        return "Camera"
    if "location" in lower or "gps" in lower:
        return "Location"
    if any(k in lower for k in ["contact", "account", "profile"]):
        return "Contacts"
    if any(k in lower for k in ["audio", "microphone", "record"]):
        return "Microphone"
    if any(k in lower for k in ["phone", "call", "voicemail", "telephony"]):
        return "Phone"
    if any(k in lower for k in ["sms", "mms", "wap"]):
        return "SMS"
    if any(k in lower for k in ["network", "wifi", "bluetooth", "nfc", "cellular"]):
        return "Network"
    if any(
        k in lower
        for k in [
            "boot",
            "wake",
            "window",
            "setting",
            "package",
            "service",
            "alarm",
            "vibrate",
            "notification",
            "biometric",
            "fingerprint",
            "admin",
            "bind",
        ]
    ):
        return "System-level"

    return "Other"


def analyze_permissions(
    target: Union[str, Path, Dict[str, Any]],
    output_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Analyze and group declared permissions.

    Args:
        target: APK file path, directory path, or already parsed manifest dict.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `permissions.json` and `permissions.txt`.

    Returns:
        Dict representing permissions analysis grouped by category.
    """
    used_perms: List[str] = []

    if isinstance(target, dict):
        used_perms = target.get("used_permissions", [])
    else:
        manifest_data = analyze_manifest(target)
        used_perms = manifest_data.get("used_permissions", [])

    categorized: Dict[str, List[str]] = {cat: [] for cat in CATEGORIES}
    details: List[PermissionItem] = []

    for perm in used_perms:
        cat = categorize_permission(perm)
        categorized[cat].append(perm)

        meta = PERMISSION_DETAILS.get(perm, {})
        prot = meta.get("protection", "custom" if not perm.startswith("android.permission.") else "unknown")
        desc = meta.get("description", "Standard or vendor Android permission.")

        details.append(
            PermissionItem(
                name=perm,
                category=cat,
                protection_level=prot,
                description=desc,
            )
        )

    # Sort within categories
    for cat in categorized:
        categorized[cat].sort()

    category_counts = {cat: len(perms) for cat, perms in categorized.items() if len(perms) > 0}

    result = {
        "total_permissions": len(used_perms),
        "dangerous_count": sum("dangerous" in d.protection_level for d in details),
        "category_counts": category_counts,
        "categories": {cat: perms for cat, perms in categorized.items() if perms},
        "permissions": [
            {**d.to_dict(), "is_dangerous": "dangerous" in d.protection_level} for d in details
        ],
    }

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Output 1: permissions.json
        json_file = out_path / "permissions.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        # Output 2: permissions.txt
        txt_file = out_path / "permissions.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(format_permissions_txt(result))

    return result


def format_permissions_txt(data: Dict[str, Any]) -> str:
    """Format permissions data into clean human-readable text."""
    lines = [
        "=" * 80,
        "HUNTX - ANDROID PERMISSIONS REPORT",
        "=" * 80,
        f"Total Permissions Declared: {data.get('total_permissions', 0)}",
        "",
        "SUMMARY BY CATEGORY",
        "-" * 80,
    ]

    category_counts = data.get("category_counts", {})
    if not category_counts:
        lines.append("  No permissions declared.")
    else:
        for cat, count in category_counts.items():
            lines.append(f"  {cat:<20}: {count}")

    lines.append("")
    lines.append("DETAILED PERMISSION BREAKDOWN")
    lines.append("-" * 80)

    categories = data.get("categories", {})
    details_map = {p["name"]: p for p in data.get("permissions", [])}

    for cat in CATEGORIES:
        perms = categories.get(cat, [])
        if not perms:
            continue
        lines.append(f"[{cat.upper()}] ({len(perms)})")
        for perm in perms:
            p_info = details_map.get(perm, {})
            prot = p_info.get("protection_level", "unknown")
            desc = p_info.get("description", "")
            lines.append(f"  • {perm}")
            lines.append(f"    Protection : {prot}")
            if desc:
                lines.append(f"    Description: {desc}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("")
    return "\n".join(lines)
