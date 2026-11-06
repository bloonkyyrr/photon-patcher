"""Detection: find a Unity game's backend and every patchable Photon id.

The scanner never trusts a single heuristic.  A *site* is only reported when a
value is anchored by at least one of:

* a ``#US`` / IL2CPP string literal inside an assembly that mentions Photon,
* a Unity length-prefixed string that directly follows a Photon key name
  (``AppIdRealtime``, ``VoiceAppId``, ``AppVersion``, ...),
* a ``key: value`` / ``key=value`` pair in a text based config,
* a GUID literal sitting next to Photon related strings.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
import time
from dataclasses import dataclass, field

from . import il2cpp, dnmeta
from .pe import PEImage, PEError

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
APP_ID = "Realtime / PUN"
VOICE_ID = "Voice"
CHAT_ID = "Chat"
VIDEO_ID = "Video"
FUSION_ID = "Fusion"
QUANTUM_ID = "Quantum"
APP_VERSION = "AppVersion"
UNCLASSIFIED = "Unknown"

# PUN is built on Realtime and shares its id, so both live in APP_ID.
ID_ROLES = (APP_ID, VOICE_ID, CHAT_ID, VIDEO_ID, FUSION_ID, QUANTUM_ID)

# Photon field names, in the order they should be matched (longest first).
PHOTON_KEYS = (
    "appidrealtime",
    "realtimeappid",
    "appidvoice",
    "voiceappid",
    "appidchat",
    "chatappid",
    "appidvideo",
    "videoappid",
    "appidfusion",
    "fusionappid",
    "appidquantum",
    "quantumappid",
    "photonappid",
    "applicationid",
    "appid",
    "appversion",
)

# Which role a field name belongs to (legacy AppID/VoiceAppID/ChatAppID included).
KEY_ROLES = (
    ("quantum", QUANTUM_ID),
    ("fusion", FUSION_ID),
    ("video", VIDEO_ID),
    ("chat", CHAT_ID),
    ("voice", VOICE_ID),
    ("appversion", APP_VERSION),
)

MARKERS = (
    "photon",
    "exitgames",
    "loadbalancingclient",
    "photonnetwork",
    "photonview",
    "photonrealtime",
    "appversion",
    "voiceappid",
    "appid",
    "masterclient",
)

SERVER_HINTS = (
    "ns.photonengine.com",
    "app-eu.exitgames.com",
    "app-us.exitgames.com",
    "app-as.exitgames.com",
    "photonengine.com",
)

ASSET_EXTENSIONS = (".assets", ".asset", ".bundle", ".unity3d", ".ress", ".bytes", ".resource")
TEXT_EXTENSIONS = (".json", ".txt", ".xml", ".cfg", ".ini", ".yaml", ".yml", ".config", ".properties")

MAX_BLOB = 512 * 1024 * 1024

# Assets above MAX_BLOB are never loaded: they are mapped and only the regions
# around Photon looking text are parsed.  One mapped pass finds those regions,
# everything after that touches a few kilobytes at a time.
WINDOW_LOOKBACK = 2048  # bytes kept before a hit (Unity length prefixes)
WINDOW_BYTES = 48 * 1024  # bytes parsed from a hit on (settings objects)
WINDOW_MAX = 512 * 1024  # two hits closer than this share one window
WINDOW_CHUNK = 8 * 1024 * 1024
WINDOW_OVERLAP = 64
WINDOW_MAX_HITS = 4096

# Lower case on purpose: player builds store the ids in lower case keys, and
# "photon" alone covers PhotonServerSettings / PhotonAppSettings / PhotonAppID.
WINDOW_NEEDLES = tuple(
    dict.fromkeys([key.encode("ascii") for key in PHOTON_KEYS] + [b"photon", b"exitgames"])
)

SETTINGS_NAME_RE = re.compile(rb"photon(?:server|app)settings", re.IGNORECASE)
SETTINGS_GAP = 256
SETTINGS_MAX_SLOTS = 16

HEX16 = rb"[\x30-\x39\x41-\x46\x61-\x66]\x00"
GUID_UTF8_RE = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
GUID_UTF16_RE = re.compile(
    HEX16 * 8 + rb"-\x00" + HEX16 * 4 + rb"-\x00" + HEX16 * 4 + rb"-\x00" + HEX16 * 4 + rb"-\x00" + HEX16 * 12
)
GUID_TEXT_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

VERSION_TEXT_RE = re.compile(r"\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]{1,24})?")

KV_RE = re.compile(
    rb"(?i)\b(appidrealtime|realtimeappid|appidvoice|voiceappid|appidchat|chatappid"
    rb"|appidvideo|videoappid|appidfusion|fusionappid|appidquantum|quantumappid"
    rb"|photonappid|applicationid|appid|appversion)"
    rb"\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;}\r\n\x00]{2,100})"
)

UNITY_VERSION_RE = re.compile(rb"20\d\d\.\d+\.\d+[abfp]\d+")


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclass
class Site:
    path: str
    kind: str  # us | il2cpp | unity_str | text | raw
    offset: int  # absolute file offset of the value payload
    encoding: str  # utf-16-le | utf-8
    value: str
    role: str
    confidence: float
    context: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return f"{self.path}|{self.kind}|{self.offset}"

    @property
    def filename(self) -> str:
        return os.path.basename(self.path)

    @property
    def can_change_length(self) -> bool:
        return self.kind in ("us", "il2cpp", "unity_str", "text")


@dataclass
class ScanResult:
    root: str = ""
    backend: str = "Unknown"
    unity_version: str = ""
    game_name: str = ""
    evidence: list[str] = field(default_factory=list)
    server_hints: list[str] = field(default_factory=list)
    sites: list[Site] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0
    elapsed: float = 0.0
    il2cpp_version: str = ""
    managed_assemblies: int = 0
    blob_files: int = 0

    def by_role(self) -> dict[str, list[Site]]:
        groups: dict[str, list[Site]] = {}
        for site in self.sites:
            groups.setdefault(site.role, []).append(site)
        return groups

    @property
    def detected_ids(self) -> list[str]:
        seen: list[str] = []
        for site in self.sites:
            if site.role in (APP_ID, VOICE_ID) and site.value not in seen:
                seen.append(site.value)
        return seen


# --------------------------------------------------------------------------- #
# environment detection
# --------------------------------------------------------------------------- #
def _iter_children(root: str, depth: int = 2):
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name.lower())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                if depth > 1:
                    yield from _iter_children(entry.path, depth - 1)
            else:
                yield entry.path
        except OSError:
            continue


def read_unity_version(root: str) -> str:
    for path in _iter_children(root, depth=2):
        base = os.path.basename(path)
        if base not in ("globalgamemanagers", "data.unity3d") and not base.endswith("_Data"):
            continue
        try:
            with open(path, "rb") as handle:
                head = handle.read(8192)
        except OSError:
            continue
        match = UNITY_VERSION_RE.search(head)
        if match:
            return match.group().decode("latin-1", "replace")
    return ""


def detect_environment(root: str) -> dict:
    info = {
        "backend": "Unknown",
        "unity_version": read_unity_version(root),
        "game_name": os.path.basename(os.path.normpath(root)),
        "managed_dirs": [],
        "il2cpp_metadata": [],
        "big_files": [],
    }
    mono = 0
    il2cpp_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".photonpatcher", "__pycache__", ".git")]
        lowered = {name.lower(): name for name in filenames}
        if os.path.basename(dirpath).lower() == "managed":
            dlls = [os.path.join(dirpath, name) for name in filenames if name.lower().endswith(".dll")]
            if dlls:
                info["managed_dirs"].append(dirpath)
                mono += len(dlls)
        if "global-metadata.dat" in lowered:
            il2cpp_files.append(os.path.join(dirpath, lowered["global-metadata.dat"]))
        if "gameassembly.dll" in lowered:
            il2cpp_files.append(os.path.join(dirpath, lowered["gameassembly.dll"]))
    info["il2cpp_metadata"] = il2cpp_files
    has_il2cpp_metadata = [p for p in il2cpp_files if p.lower().endswith("global-metadata.dat")]
    if mono and not has_il2cpp_metadata:
        info["backend"] = "Mono"
    elif has_il2cpp_metadata and not mono:
        info["backend"] = "IL2CPP"
    elif mono and has_il2cpp_metadata:
        info["backend"] = "Mixed"
    return info


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _read_file(path: str, warnings: list[str]) -> bytes | None:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        warnings.append(f"cannot stat {path}: {exc}")
        return None
    if size > MAX_BLOB:
        warnings.append(f"skipped {os.path.basename(path)} (larger than {MAX_BLOB // (1024 * 1024)} MB)")
        return None
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        warnings.append(f"cannot read {path}: {exc}")
        return None


def _evidence(text: str) -> list[str]:
    lowered = text.lower()
    return [marker for marker in MARKERS if marker in lowered]


def _role_from_key(key: str) -> str:
    """Map a Photon field name (AppIdChat, ChatAppID, ...) to its id type."""
    lowered = key.lower()
    if "version" in lowered:
        return APP_VERSION
    for token, role in KEY_ROLES:
        if token in lowered:
            return role
    return APP_ID


def _role_in_text(text: str) -> str | None:
    """Find an explicit photon field name inside free text."""
    lowered = text.lower()
    for token, role in KEY_ROLES:
        if token in lowered and ("appid" in lowered or "app_id" in lowered or token == "appversion"):
            return role
    return None


def _read_unity_string(data: bytes, position: int) -> tuple[str, int] | None:
    """Read a length-prefixed Unity string at ``position``."""
    if position < 0 or position + 4 > len(data):
        return None
    length = struct.unpack_from("<i", data, position)[0]
    if length <= 0 or length > 1024:
        return None
    start = position + 4
    end = start + length
    if end > len(data):
        return None
    raw = data[start:end]
    if any(byte < 9 or 13 < byte < 32 for byte in raw):
        return None
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value.isprintable():
        return None
    return value, end


def _looks_like_id(value: str) -> bool:
    if not 2 <= len(value) <= 100:
        return False
    if not re.fullmatch(r"[A-Za-z0-9\-_.:]+", value):
        return False
    if re.fullmatch(r"\d+(\.\d+){1,3}", value):  # "1.0", "4.2.1" app versions
        return True
    return any(ch.isalpha() for ch in value) or len(value) >= 8


# --------------------------------------------------------------------------- #
# .NET assemblies
# --------------------------------------------------------------------------- #
def _scan_assembly(path: str, result: ScanResult) -> None:
    data = _read_file(path, result.warnings)
    if data is None:
        return
    try:
        pe = PEImage(data)
        meta = dnmeta.Metadata(data)
        entries = meta.user_strings()
    except (PEError, dnmeta.MetadataError):
        return
    except Exception as exc:  # noqa: BLE001 - never let one file kill a scan
        result.warnings.append(f"{os.path.basename(path)}: metadata parse failed ({exc})")
        return

    result.managed_assemblies += 1
    names = meta.strings_heap_peek()
    joined_values = "\n".join(entry.value for entry in entries)
    evidence = _evidence(names + "\n" + joined_values + "\n" + os.path.basename(path))
    for marker in evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    for hint in SERVER_HINTS:
        if hint in joined_values.lower() and hint not in result.server_hints:
            result.server_hints.append(hint)
    if not evidence:
        return

    key_names = [key for key in PHOTON_KEYS if key in names.lower()]
    values = [entry.value for entry in entries]
    # A GUID can sit inside a longer literal ("appid=...-...;voice=..."), so
    # match occurrences, not just whole strings, and remember where each one is.
    spans = [
        (index, match.start(), match.end(), match.group())
        for index, value in enumerate(values)
        for match in GUID_TEXT_RE.finditer(value)
    ]
    voice_hint = "voice" in names.lower() or any("voice" in value.lower() for value in values)
    appid_hint = key_names or any("appid" in value.lower() for value in values)

    for index, span_start, span_end, guid in spans:
        entry = entries[index]
        window = " | ".join(
            values[max(0, index - 10) : index] + values[index + 1 : index + 11]
        ).lower()
        role = _role_from_prefix(entry.value, span_start, window)
        confidence = 0.55
        if "appid" in window:
            confidence += 0.25
        if len(spans) == 1:
            confidence += 0.15
        if voice_hint and role == APP_ID and len(spans) > 1:
            confidence -= 0.1
        if appid_hint:
            confidence += 0.05
        if _explicit_key(entry.value, span_start):
            confidence += 0.2
        if not _guid_has_context(values, index, span_start) and len(spans) > 1:
            continue
        context = _short_context(values[max(0, index - 3) : index + 4])
        result.sites.append(
            Site(
                path=path,
                kind="us",
                offset=entry.data_offset - entry.prefix_len + 2 * span_start,
                encoding="utf-16-le",
                value=guid,
                role=role,
                confidence=min(confidence, 0.99),
                context=context,
                extra={
                    "heap_offset": entry.heap_offset,
                    "capacity": entry.capacity,
                    "prefix_len": entry.prefix_len,
                    "byte_len": entry.byte_len,
                    "span": [span_start, span_end],
                    "full_value": entry.value,
                },
            )
        )

    # ``const string`` values live in the #Blob heap (not #US), so scan the raw
    # image as well; those can only be replaced with a same-length id.
    classified = {
        site.value: (site.role, site.confidence)
        for site in result.sites
        if site.path == path and site.kind == "us"
    }
    covered = [
        (entry.data_offset - entry.prefix_len, entry.data_offset - entry.prefix_len + entry.capacity)
        for entry in entries
    ]
    for pattern, encoding in ((GUID_UTF16_RE, "utf-16-le"), (GUID_UTF8_RE, "utf-8")):
        for match in pattern.finditer(data):
            offset = match.start()
            if any(start <= offset < end for start, end in covered):
                continue
            value = match.group().decode(encoding)
            if value in classified:
                role, confidence = classified[value]
            else:
                # Unlabelled GUIDs in an assembly are almost always unrelated
                # (assembly guid attributes, audio plugin tags): demand a key.
                near = data[max(0, offset - 64) : offset + 64].lower()
                if not any(key in near for key in (b"appid", b"voiceapp", b"appversion")):
                    continue
                role = VOICE_ID if b"voiceapp" in near else APP_ID
                confidence = 0.55
            result.sites.append(
                Site(
                    path=path,
                    kind="raw",
                    offset=offset,
                    encoding=encoding,
                    value=value,
                    role=role,
                    confidence=confidence,
                    context=_context_around(data, offset, len(match.group())),
                    extra={"length": len(value), "blob": True},
                )
            )
            covered.append((offset, offset + len(match.group())))


def _role_from_prefix(value: str, span_start: int, window: str) -> str:
    """The key right before an id ("appidchat=...", "chat=...") wins."""
    prefix = value[max(0, span_start - 32) : span_start].lower()
    explicit = _role_in_text(prefix)
    if explicit is not None:
        return explicit
    for word, role in (
        ("quantum", QUANTUM_ID),
        ("fusion", FUSION_ID),
        ("video", VIDEO_ID),
        ("chat", CHAT_ID),
        ("voice", VOICE_ID),
    ):
        if word in prefix:
            return role
    if "appid" in prefix or "app_id" in prefix or "app id" in prefix:
        return APP_ID
    return _role_in_text(window) or (VOICE_ID if "voice" in window else APP_ID)


KEY_WORDS = ("appid", "app_id", "app id", "voice", "chat", "video", "fusion", "quantum", "appversion")


def _explicit_key(value: str, span_start: int) -> bool:
    prefix = value[max(0, span_start - 32) : span_start].lower()
    return any(word in prefix for word in KEY_WORDS)


GUID_CONTEXT_HINTS = (
    "appid",
    "voiceapp",
    "chatapp",
    "videoapp",
    "fusionapp",
    "quantumapp",
    "appversion",
    "serveraddress",
)


def _guid_has_context(values: list[str], index: int, span_start: int) -> bool:
    """A GUID literal only counts as a Photon id when something names it.

    Assemblies are full of unrelated GUIDs (audio plugins print debug guids),
    so an unlabelled one is only kept when it is the file's single candidate.
    """
    if _explicit_key(values[index], span_start):
        return True
    neighbours = values[max(0, index - 2) : index] + values[index + 1 : index + 3]
    joined = " | ".join(neighbours).lower()
    return any(hint in joined for hint in GUID_CONTEXT_HINTS)


def _short_context(values: list[str], limit: int = 70) -> str:
    parts: list[str] = []
    for value in values:
        text = value.replace("\n", " ").strip()
        if text:
            parts.append(text)
    joined = " | ".join(parts)
    if len(joined) > limit:
        joined = joined[:limit] + "..."
    return joined


# --------------------------------------------------------------------------- #
# IL2CPP
# --------------------------------------------------------------------------- #
def _scan_global_metadata(path: str, result: ScanResult) -> None:
    data = _read_file(path, result.warnings)
    if data is None:
        return
    try:
        meta = il2cpp.GlobalMetadata(data)
    except il2cpp.Il2CppError as exc:
        result.warnings.append(f"global-metadata.dat: {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        result.warnings.append(f"global-metadata.dat: parse failed ({exc})")
        return

    result.il2cpp_version = meta.version
    values = [literal.value for literal in meta.literals]
    joined = "\n".join(values)
    evidence = _evidence(joined)
    for marker in evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    for hint in SERVER_HINTS:
        if hint in joined.lower() and hint not in result.server_hints:
            result.server_hints.append(hint)
    if not evidence:
        return

    spans = [
        (index, match.start(), match.end(), match.group())
        for index, value in enumerate(values)
        for match in GUID_TEXT_RE.finditer(value)
    ]
    for index, span_start, span_end, guid in spans:
        literal = meta.literals[index]
        window = " | ".join(
            values[max(0, index - 12) : index] + values[index + 1 : index + 13]
        ).lower()
        role = _role_from_prefix(literal.value, span_start, window)
        confidence = 0.55
        if "appid" in window:
            confidence += 0.25
        if len(spans) == 1:
            confidence += 0.15
        if _explicit_key(literal.value, span_start):
            confidence += 0.2
        if not _guid_has_context(values, index, span_start) and len(spans) > 1:
            continue
        result.sites.append(
            Site(
                path=path,
                kind="il2cpp",
                offset=literal.offset,
                encoding="utf-8",
                value=guid,
                role=role,
                confidence=min(confidence, 0.99),
                context=_short_context(values[max(0, index - 3) : index + 4]),
                extra={
                    "literal_index": literal.index,
                    "length": literal.length,
                    "data_index": literal.data_index,
                    "span": [span_start, span_end],
                    "full_value": literal.value,
                },
            )
        )


# --------------------------------------------------------------------------- #
# asset / bundle / text blobs
# --------------------------------------------------------------------------- #
def _scan_blob(path: str, result: ScanResult, textual: bool, progress=None) -> None:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result.warnings.append(f"cannot stat {path}: {exc}")
        return
    if size > MAX_BLOB:
        _scan_blob_windowed(path, size, result, textual, progress)
        return
    data = _read_file(path, result.warnings)
    if data is None:
        return
    result.blob_files += 1
    _scan_blob_data(path, data, result, textual)


def _scan_blob_data(path: str, data: bytes, result: ScanResult, textual: bool) -> None:
    _scan_settings_object(path, data, result)
    # Player builds strip the type tree, so Photon names can sit anywhere in a
    # large asset; sample the whole file instead of only its head.
    samples = [data[: 1024 * 1024]]
    if len(data) > 1024 * 1024:
        samples.append(data[-1024 * 1024 :])
        step = 8 * 1024 * 1024
        for start in range(step, len(data) - 1024 * 1024, step):
            samples.append(data[start : start + 1024 * 1024])
    scanned = b"\n".join(samples).lower()
    blob_evidence = _evidence(
        scanned.decode("latin-1", "replace") + " " + os.path.basename(path).lower()
    )
    for marker in blob_evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    if not blob_evidence and not any(site.path == path for site in result.sites):
        return

    seen_offsets: set[int] = {site.offset for site in result.sites if site.path == path}

    # 1) Unity length-prefixed key/value pairs (works for resources.assets).
    for key in PHOTON_KEYS:
        needle = key.encode("ascii")
        start = 0
        while True:
            position = data.find(needle, start)
            if position < 0:
                break
            start = position + 1
            if position < 4:
                continue
            # Only when the key itself is stored as a Unity string.
            key_prefix = position - 4
            key_len = struct.unpack_from("<i", data, key_prefix)[0]
            if key_len != len(needle):
                continue
            value_position = (position + len(needle) + 3) & ~3
            parsed = _read_unity_string(data, value_position)
            if parsed is None:
                continue
            value, value_end = parsed
            if not _looks_like_id(value) or GUID_TEXT_RE.fullmatch(value) is None:
                if key.lower() != "appversion" or not _looks_like_id(value):
                    continue
            role = _role_from_key(key)
            slot_end = (value_end + 3) & ~3
            result.sites.append(
                Site(
                    path=path,
                    kind="unity_str",
                    offset=value_position + 4,
                    encoding="utf-8",
                    value=value,
                    role=role,
                    confidence=0.97,
                    context=f'{key}: "{value}"',
                    extra={
                        "len_field": value_position,
                        "slot": slot_end - value_position,
                        "key": key,
                    },
                )
            )
            seen_offsets.add(value_position + 4)

    # 2) Text style key: value pairs.
    if textual:
        for match in KV_RE.finditer(data):
            key = match.group(1).decode("latin-1")
            value = match.group(2).decode("latin-1").strip("\"'")
            if not _looks_like_id(value):
                continue
            offset = match.start(2)
            if offset in seen_offsets:
                continue
            result.sites.append(
                Site(
                    path=path,
                    kind="text",
                    offset=offset,
                    encoding="utf-8",
                    value=value,
                    role=_role_from_key(key),
                    confidence=0.95,
                    context=f"{key}: {value}",
                    extra={"length": len(value), "key": key},
                )
            )
            seen_offsets.add(offset)

    # 3) Bare GUID literals near Photon text (UTF-8 then UTF-16LE).
    for pattern, encoding in ((GUID_UTF8_RE, "utf-8"), (GUID_UTF16_RE, "utf-16-le")):
        for match in pattern.finditer(data):
            offset = match.start()
            if offset in seen_offsets:
                continue
            value = match.group().decode(encoding)
            window = data[max(0, offset - 512) : offset + 512].decode("latin-1", "replace").lower()
            if not any(token in window for token in ("photon", "appid", "exitgames", "appversion", "voice")):
                continue
            role = _role_in_text(window) or (VOICE_ID if "voiceapp" in window else APP_ID)
            confidence = 0.6
            if "photonserversettings" in window or "photonappsettings" in window:
                confidence = 0.9
            if _unity_string_prefix(data, offset) == len(value):
                confidence += 0.05
            result.sites.append(
                Site(
                    path=path,
                    kind="raw",
                    offset=offset,
                    encoding=encoding,
                    value=value,
                    role=role,
                    confidence=min(confidence, 0.99),
                    context=_context_around(data, offset, len(value), radius=60),
                    extra={"length": len(value), "blob": True},
                )
            )
            seen_offsets.add(offset)

    # 4) PUN keeps AppVersion in the same settings object as the id, so the
    #    version string sits a few bytes later in the string table.
    anchors = [
        site
        for site in result.sites
        if site.path == path and site.kind == "raw" and site.role == APP_ID and site.confidence >= 0.9
    ]
    for site in anchors:
        found = _version_after(data, site.offset + len(site.value))
        if found is None:
            continue
        length_field, value, slot = found
        if length_field + 4 in seen_offsets:
            continue
        result.sites.append(
            Site(
                path=path,
                kind="unity_str",
                offset=length_field + 4,
                encoding="utf-8",
                value=value,
                role=APP_VERSION,
                confidence=0.75,
                context=f'AppVersion: "{value}" (next to the Photon id)',
                extra={
                    "len_field": length_field,
                    "slot": slot,
                    "key": "appversion",
                    "found_by": "neighbour",
                },
            )
        )


def _scan_blob_windowed(
    path: str, size: int, result: ScanResult, textual: bool, progress=None
) -> None:
    """Scan an asset too large to load by mapping it and parsing windows.

    The ids of a player build live in a single settings object buried in a
    multi-gigabyte bundle, so reading the file is pointless - it is mapped and
    one sequential pass locates every region that can hold a Photon id.  Each
    region is then parsed with the same code the small-file path uses, and the
    offsets are moved back to file coordinates.
    """
    result.blob_files += 1
    name = os.path.basename(path)
    try:
        handle = open(path, "rb")
    except OSError as exc:
        result.warnings.append(f"cannot read {path}: {exc}")
        return
    with handle:
        try:
            mapping = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as exc:
            result.warnings.append(f"cannot map {name}: {exc}")
            return
        with mapping:
            hits = _window_hits(mapping, size, progress)
            for start, end in _merge_windows(hits, size):
                window = mapping[start:end]
                local = ScanResult(root=result.root)
                _scan_settings_object(path, window, local)
                _scan_blob_data(path, window, local, textual)
                for marker in local.evidence:
                    if marker not in result.evidence:
                        result.evidence.append(marker)
                for site in local.sites:
                    site.offset += start
                    if "len_field" in site.extra:
                        site.extra["len_field"] += start
                    result.sites.append(site)
    _dedupe_sites(result, path)


def _window_hits(mapping, size: int, progress=None) -> list[int]:
    """One sequential pass over the mapping, collecting needle offsets."""
    hits: set[int] = set()
    position = 0
    while position < size and len(hits) < WINDOW_MAX_HITS:
        # Lowering the chunk keeps the needles few and the match case blind:
        # the same bundle spells them PhotonServerSettings and appid.
        chunk = mapping[position : position + WINDOW_CHUNK + WINDOW_OVERLAP].lower()
        for needle in WINDOW_NEEDLES:
            start = 0
            while True:
                found = chunk.find(needle, start)
                if found < 0:
                    break
                hits.add(position + found)
                start = found + 1
            if len(hits) >= WINDOW_MAX_HITS:
                break
        position += WINDOW_CHUNK
        if progress:
            progress(min(1.0, position / size if size else 1.0))
    return sorted(hits)


def _merge_windows(hits: list[int], size: int) -> list[tuple[int, int]]:
    """Turn hit offsets into non overlapping [start, end) windows."""
    windows: list[tuple[int, int]] = []
    for hit in hits:
        start = max(0, hit - WINDOW_LOOKBACK)
        end = min(size, start + WINDOW_BYTES)
        if windows:
            previous_start, previous_end = windows[-1]
            if end <= previous_end:
                continue
            if start < previous_end and end - previous_start <= WINDOW_MAX:
                windows[-1] = (previous_start, end)
                continue
        windows.append((start, end))
    return windows


def _dedupe_sites(result: ScanResult, path: str) -> None:
    """Windows can overlap, so keep the best site per file offset."""
    keep: list[Site] = []
    best: dict[tuple[str, int], Site] = {}
    for site in result.sites:
        if site.path != path:
            keep.append(site)
            continue
        key = (site.kind, site.offset)
        existing = best.get(key)
        if existing is None or site.confidence > existing.confidence:
            best[key] = site
    keep.extend(best.values())
    result.sites = keep


def _version_after(data: bytes, position: int, window: int = 96) -> tuple[int, str, int] | None:
    """Find a Unity string that looks like an app version just after an id."""
    limit = min(len(data) - 4, position + window)
    for start in range(max(0, position), limit):
        try:
            length = struct.unpack_from("<i", data, start)[0]
        except struct.error:
            return None
        if not 3 <= length <= 32:
            continue
        raw = data[start + 4 : start + 4 + length]
        if len(raw) < length or not all(32 <= byte < 127 for byte in raw):
            continue
        text = raw.decode("ascii")
        if VERSION_TEXT_RE.fullmatch(text) is None:
            continue
        end = start + 4 + length
        padded = (end + 3) & ~3
        if data[end:padded].strip(b"\0"):
            continue
        return start, text, padded - start
    return None


def _scan_settings_object(path: str, data: bytes, result: ScanResult) -> None:
    """Find the Photon settings object by name and collect the ids inside it.

    Player builds have no type tree, so the object name is the only anchor that
    still exists. Everything that follows it and is framed as a Unity string is
    one of the settings: the first id is the realtime one, later ones belong to
    other Photon products and are left for the user to label.
    """
    if not _may_have_settings_name(data):
        return
    if SETTINGS_NAME_RE.search(data) is None:
        return
    known = {site.offset for site in result.sites if site.path == path}
    for match in SETTINGS_NAME_RE.finditer(data):
        slot = 0
        position = match.end()
        limit = min(len(data), position + 8192)
        previous_end = None
        while position < limit and slot < SETTINGS_MAX_SLOTS:
            found = _next_guid_slot(data, position, limit)
            if found is None:
                break
            offset, value, length_field = found
            # Ids of one settings object are stored back to back. Anything with
            # a gap in front of it belongs to a neighbouring object (the RPC
            # list, script assets, ...) and must not be touched.
            if previous_end is not None and length_field - previous_end > SETTINGS_GAP:
                break
            previous_end = offset + len(value)
            position = previous_end
            if offset in known:
                continue
            role = APP_ID if slot == 0 else UNCLASSIFIED
            confidence = 0.97 if slot == 0 else 0.6
            result.sites.append(
                Site(
                    path=path,
                    kind="raw",
                    offset=offset,
                    encoding="utf-8",
                    value=value,
                    role=role,
                    confidence=confidence,
                    context=f"Photon settings object, id #{slot + 1}",
                    extra={
                        "length": len(value),
                        "blob": True,
                        "len_field": length_field,
                        "slot_index": slot,
                    },
                )
            )
            known.add(offset)
            slot += 1


def _may_have_settings_name(data: bytes) -> bool:
    """Cheap byte search first: this runs for every asset in the game."""
    for needle in (b"PhotonServerSettings", b"PhotonAppSettings", b"photonappsettings", b"photonserversettings"):
        if data.find(needle) >= 0:
            return True
    return False


def _next_guid_slot(data: bytes, position: int, limit: int):
    """Next GUID stored as a Unity string (length prefix, then the text)."""
    for match in GUID_UTF8_RE.finditer(data, position, limit):
        offset = match.start()
        if _unity_string_prefix(data, offset) != len(match.group()):
            continue
        return offset, match.group().decode("utf-8"), offset - 4
    return None


def _unity_string_prefix(data: bytes, offset: int) -> int:
    """Length of the Unity serialized string starting at ``offset``, or -1."""
    if offset < 4:
        return -1
    try:
        length = struct.unpack_from("<i", data, offset - 4)[0]
    except struct.error:
        return -1
    return length if 0 < length <= 4096 else -1


def _context_around(data: bytes, offset: int, length: int, radius: int = 40) -> str:
    start = max(0, offset - radius)
    end = min(len(data), offset + length + radius)
    text = data[start:end].decode("latin-1", "replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return cleaned.strip(".")


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #
def _collect(root: str, deep: bool) -> tuple[list[str], list[str], list[str], list[str]]:
    assemblies: list[str] = []
    metadata: list[str] = []
    assets: list[str] = []
    texts: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".photonpatcher", "__pycache__", ".git")]
        in_managed = os.path.basename(dirpath).lower() == "managed"
        for name in filenames:
            lowered = name.lower()
            path = os.path.join(dirpath, name)
            if lowered.endswith(".ppbak"):
                continue
            if lowered == "global-metadata.dat":
                metadata.append(path)
            elif lowered.endswith(".dll") and (in_managed or deep):
                assemblies.append(path)
            elif lowered.endswith(ASSET_EXTENSIONS) or lowered in ("globalgamemanagers", "resources.assets"):
                assets.append(path)
            elif lowered.endswith(TEXT_EXTENSIONS):
                texts.append(path)
            elif deep and not lowered.endswith((".exe", ".so", ".dylib", ".dat", ".pak")):
                assets.append(path)
    return assemblies, metadata, assets, texts


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def scan(root: str, deep: bool = False, progress=None) -> ScanResult:
    started = time.time()
    root = os.path.abspath(root)
    env = detect_environment(root)
    result = ScanResult(
        root=root,
        backend=env["backend"],
        unity_version=env["unity_version"],
        game_name=env["game_name"],
    )
    if not os.path.isdir(root):
        result.warnings.append(f"{root} is not a directory")
        return result

    assemblies, metadata, assets, texts = _collect(root, deep)
    jobs: list[tuple[str, str]] = []
    jobs += [(path, "assembly") for path in assemblies]
    jobs += [(path, "il2cpp") for path in metadata]
    jobs += [(path, "asset") for path in assets]
    jobs += [(path, "text") for path in texts]

    for done, (path, job) in enumerate(jobs, start=1):
        relative = os.path.relpath(path, root)
        if progress:
            progress(done, len(jobs), relative)

        def file_progress(fraction, _path=path, _done=done, _relative=relative):
            if progress:
                progress(_done, len(jobs), f"{_relative} {int(fraction * 100)}%")

        try:
            if job == "assembly":
                _scan_assembly(path, result)
            elif job == "il2cpp":
                _scan_global_metadata(path, result)
            elif job == "asset":
                _scan_blob(path, result, textual=False, progress=file_progress)
            else:
                _scan_blob(path, result, textual=True, progress=file_progress)
        except Exception as exc:  # noqa: BLE001
            result.warnings.append(f"{os.path.basename(path)}: {exc}")
        result.files_scanned += 1

    result.sites.sort(key=lambda site: (site.path.lower(), site.offset))
    result.elapsed = time.time() - started
    if not result.sites:
        result.warnings.append(
            "no Photon ids detected - the game may be protected, packed, or simply not use Photon"
        )
    return result
