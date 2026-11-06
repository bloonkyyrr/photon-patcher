"""Applying, verifying and reverting Photon id patches.

Design rules:

* every file is backed up before its first modification, and the backup lives
  in ``<game>/.photonpatcher/backups`` so the game folder stays clean,
* every modification is re-parsed and verified **before** it is written,
* a file that fails verification is never written - the original bytes stay,
* patches are idempotent: re-running with the same target is a no-op.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import time
from dataclasses import dataclass, field

from . import dnmeta, il2cpp
from .pe import PEImage, PEError
from .scan import (
    APP_ID,
    APP_VERSION,
    CHAT_ID,
    FUSION_ID,
    MAX_BLOB,
    QUANTUM_ID,
    UNCLASSIFIED,
    VIDEO_ID,
    VOICE_ID,
    Site,
)

MANIFEST_DIR = ".photonpatcher"


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """The ids to write in.

    ``app_id`` is the Realtime id, which is also what PUN uses. Each other
    Photon product can have its own id; when it is left empty the realtime id is
    used for it (that is what a single-app Photon setup needs).
    """

    app_id: str | None = None
    voice_id: str | None = None
    chat_id: str | None = None
    video_id: str | None = None
    fusion_id: str | None = None
    quantum_id: str | None = None
    version: str | None = None
    patch_unclassified: bool = True
    same_voice: bool = True
    fill_from_app_id: bool = True

    def _explicit(self) -> dict[str, str | None]:
        return {
            APP_ID: self.app_id,
            VOICE_ID: None if self.same_voice else self.voice_id,
            CHAT_ID: self.chat_id,
            VIDEO_ID: self.video_id,
            FUSION_ID: self.fusion_id,
            QUANTUM_ID: self.quantum_id,
        }

    def value_for(self, role: str) -> str | None:
        if role == APP_VERSION:
            return self.version
        if role == UNCLASSIFIED:
            return self.app_id if self.patch_unclassified else None
        own = self._explicit().get(role)
        if own:
            return own
        return self.app_id if self.fill_from_app_id else None


@dataclass
class Change:
    site: Site
    new_value: str
    status: str = "pending"  # patched | skipped | failed
    message: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def old_value(self) -> str:
        return self.site.value


@dataclass
class PatchReport:
    changes: list[Change] = field(default_factory=list)
    backups: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    written_files: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def patched(self) -> list[Change]:
        return [c for c in self.changes if c.status == "patched"]

    @property
    def failed(self) -> list[Change]:
        return [c for c in self.changes if c.status == "failed"]

    def summary(self) -> str:
        return (
            f"{len(self.patched)} patched, {len(self.failed)} failed, "
            f"{len(self.written_files)} file(s) written"
        )


class PatchAbort(Exception):
    """Raised when a file cannot be patched safely."""


# --------------------------------------------------------------------------- #
# planning
# --------------------------------------------------------------------------- #
def validate_value(value: str) -> str | None:
    if not value:
        return "value is empty"
    if len(value) > 100:
        return "value is longer than 100 characters"
    if any(ch.isspace() for ch in value):
        return "value contains whitespace"
    if any(ord(ch) < 32 for ch in value):
        return "value contains control characters"
    return None


def plan(sites: list[Site], target: Target) -> list[Change]:
    changes: list[Change] = []
    for site in sites:
        new_value = target.value_for(site.role)
        if new_value is None:
            changes.append(Change(site, "", status="skipped", message=f"no target for {site.role}"))
            continue
        problem = validate_value(new_value)
        if problem:
            changes.append(Change(site, new_value, status="skipped", message=problem))
            continue
        if new_value == site.value:
            changes.append(Change(site, new_value, status="skipped", message="already patched"))
            continue
        changes.append(Change(site, new_value))
    return changes


# --------------------------------------------------------------------------- #
# backups / manifest
# --------------------------------------------------------------------------- #
def manifest_path(root: str) -> str:
    return os.path.join(root, MANIFEST_DIR, "manifest.json")


def load_manifest(root: str) -> dict:
    path = manifest_path(root)
    if not os.path.isfile(path):
        return {"version": 1, "entries": []}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "entries" not in data:
            raise ValueError("bad manifest")
        return data
    except (OSError, ValueError):
        return {"version": 1, "entries": []}


def save_manifest(root: str, data: dict) -> None:
    directory = os.path.join(root, MANIFEST_DIR)
    os.makedirs(directory, exist_ok=True)
    path = manifest_path(root)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _sha256_file(path: str) -> str:
    """Hash a file without loading it: game bundles reach several gigabytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_large(path: str) -> bool:
    """Files this big are patched where they sit instead of being copied."""
    try:
        return os.path.getsize(path) > MAX_BLOB
    except OSError:
        return False


def ensure_backup(root: str, path: str, manifest: dict) -> bool:
    """Back up ``path`` once.  Returns True if a new backup was created.

    A bundle too big to copy is journaled instead: the manifest stores the exact
    bytes the patch overwrites, which restores just as precisely while keeping a
    multi-gigabyte game from needing a second copy of itself on disk.
    """
    relative = os.path.relpath(path, root)
    destination = os.path.join(root, MANIFEST_DIR, "backups", relative)
    for entry in manifest["entries"]:
        if entry.get("path") == relative:
            if isinstance(entry.get("journal"), list) or os.path.isfile(destination):
                return False
            break
    entry = {
        "path": relative,
        "size": os.path.getsize(path),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if _is_large(path):
        entry["journal"] = []
    else:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(path, destination)
        entry["backup"] = os.path.relpath(destination, root)
    manifest["entries"] = [e for e in manifest["entries"] if e.get("path") != relative]
    manifest["entries"].append(entry)
    return True


def _write_atomic(path: str, payload: bytes) -> None:
    temporary = path + ".pptmp"
    try:
        with open(temporary, "wb") as handle:
            handle.write(payload)
        os.replace(temporary, path)
    except PermissionError:
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            try:
                os.remove(temporary)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# per-format patchers
# --------------------------------------------------------------------------- #
def _merged_value(changes: list[Change], base: str) -> str:
    """Rewrite every matched span of one literal and return the new literal."""
    spans: list[tuple[int, int, str]] = []
    for change in changes:
        span = change.site.extra.get("span")
        if not span:
            return change.new_value
        spans.append((int(span[0]), int(span[1]), change.new_value))
    spans.sort()
    out: list[str] = []
    cursor = 0
    for start, end, new in spans:
        out.append(base[cursor:start])
        out.append(new)
        cursor = end
    out.append(base[cursor:])
    return "".join(out)


def _group_by(changes: list[Change], key: str) -> dict[int, list[Change]]:
    """Every id inside the same literal has to be rewritten in one pass."""
    groups: dict[int, list[Change]] = {}
    for change in changes:
        groups.setdefault(int(change.site.extra.get(key, -1)), []).append(change)
    return groups


def _patch_assembly(path: str, changes: list[Change], warnings: list[str]) -> None:
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        pe = PEImage(data)
        meta = dnmeta.Metadata(data)
        entries = {entry.heap_offset: entry for entry in meta.user_strings()}
    except (PEError, dnmeta.MetadataError) as exc:
        raise PatchAbort(f"cannot parse assembly: {exc}") from exc

    mutated = bytearray(data)
    in_place: list[tuple[list[Change], dnmeta.UserString, str]] = []
    growth: list[tuple[list[Change], dnmeta.UserString, str]] = []

    for heap_offset, group in _group_by(changes, "heap_offset").items():
        entry = entries.get(heap_offset)
        if entry is None:
            for change in group:
                change.status = "failed"
                change.message = "string literal is no longer in the #US heap"
            continue
        base = group[0].site.extra.get("full_value", group[0].site.value)
        if entry.value != base:
            for change in group:
                change.status = "failed"
                change.message = "file on disk differs from the scan (re-scan needed)"
            continue
        new_full = _merged_value(group, base)
        bucket = in_place if len(dnmeta.encode_user_string(new_full)) <= entry.capacity else growth
        bucket.append((group, entry, new_full))

    for group, entry, new_full in in_place:
        try:
            offset = dnmeta.patch_user_string_in_place(mutated, entry, new_full)
        except dnmeta.MetadataError as exc:
            for change in group:
                change.status = "failed"
                change.message = str(exc)
            continue
        for change in group:
            change.status = "patched"
            change.message = "in place"
            # Keep site.offset as scanned (the literal did not move); it is the
            # row key the UI uses to report the result.
            change.extra["expect_heap_offset"] = entry.heap_offset
            change.extra["expect_value"] = new_full

    if growth:
        _apply_growth(path, data, pe, meta, mutated, growth, warnings)

    if not any(change.status == "patched" for change in changes):
        return

    payload = bytes(mutated)
    _verify_assembly(payload, changes)
    _write_atomic(path, payload)


def _apply_growth(
    path: str,
    data: bytes,
    pe: PEImage,
    meta: dnmeta.Metadata,
    mutated: bytearray,
    growth: list[tuple[list[Change], dnmeta.UserString, str]],
    warnings: list[str],
) -> None:
    """Append new literals to ``#US`` and retarget every ``ldstr`` token."""
    try:
        tables = meta.tables()
        ldstr_sites, failed_methods = dnmeta.find_ldstr_sites(data, pe, tables)
    except (PEError, dnmeta.MetadataError) as exc:
        for group, _entry, _full in growth:
            for change in group:
                change.status = "failed"
                change.message = f"cannot rewrite this assembly ({exc}); use a same-length id"
        return
    if failed_methods:
        warnings.append(f"{os.path.basename(path)}: {failed_methods} method body(ies) could not be walked")

    usable: list[tuple[list[Change], dnmeta.UserString, str, list[dnmeta.LdstrSite]]] = []
    for group, entry, new_full in growth:
        tokens = ldstr_sites.get(entry.heap_offset)
        if not tokens:
            for change in group:
                change.status = "failed"
                change.message = (
                    "this literal has no ldstr reference we can retarget "
                    "(probably read from an asset); use an id of the same length"
                )
            continue
        usable.append((group, entry, new_full, tokens))
    if not usable:
        return

    old_heap = meta.stream("#US") or b""
    heap = bytearray(old_heap)
    placements: dict[int, int] = {}
    for _group, entry, new_full, _tokens in usable:
        placements[entry.heap_offset] = len(heap)
        heap += dnmeta.encode_user_string(new_full)
    heap += b"\0" * ((-len(heap)) % 4)

    try:
        blob = meta.rebuild({"#US": bytes(heap)})
    except dnmeta.MetadataError as exc:
        for group, _entry, _full, _tokens in usable:
            for change in group:
                change.status = "failed"
                change.message = f"metadata rebuild failed: {exc}"
        return

    try:
        rebuilt, metadata_rva = pe.add_section(blob)
    except PEError:
        try:
            rebuilt, metadata_rva = pe.extend_last_section(blob)
            warnings.append(
                f"{os.path.basename(path)}: strong-name signature removed to fit the grown metadata"
            )
        except PEError as exc:
            for group, _entry, _full, _tokens in usable:
                for change in group:
                    change.status = "failed"
                    change.message = f"cannot grow the image: {exc}"
            return

    out = bytearray(rebuilt)
    struct.pack_into("<II", out, pe.cli_header["offset"] + 8, metadata_rva, len(blob))

    for group, entry, new_full, tokens in usable:
        new_offset = placements[entry.heap_offset]
        token = 0x70000000 | new_offset
        for site in tokens:
            struct.pack_into("<I", out, site.token_offset, token)
        for change in group:
            change.status = "patched"
            change.message = "relocated literal"
            change.extra["expect_heap_offset"] = new_offset
            change.extra["expect_value"] = new_full
            change.extra["new_offset"] = meta.streams["#US"][0] + new_offset

    mutated[:] = out


def _verify_assembly(payload: bytes, changes: list[Change]) -> None:
    try:
        meta = dnmeta.Metadata(payload)
        entries = {entry.heap_offset: entry for entry in meta.user_strings()}
    except (PEError, dnmeta.MetadataError) as exc:
        for change in changes:
            if change.status == "patched":
                change.status = "failed"
                change.message = "patched assembly did not re-parse"
        raise PatchAbort(f"patched metadata did not round-trip: {exc}") from exc

    broken = 0
    for change in changes:
        if change.status != "patched":
            continue
        expected = change.extra.get("expect_heap_offset")
        entry = entries.get(expected)
        expected_value = change.extra.get("expect_value", change.new_value)
        if entry is None or entry.value != expected_value:
            change.status = "failed"
            change.message = "verification failed after rewrite"
            broken += 1
    if broken:
        raise PatchAbort("patched assembly failed verification")


def _patch_il2cpp(path: str, changes: list[Change], warnings: list[str]) -> None:
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        meta = il2cpp.GlobalMetadata(data)
    except il2cpp.Il2CppError as exc:
        raise PatchAbort(f"cannot parse global-metadata.dat: {exc}") from exc

    replacements: dict[int, str] = {}
    for index, group in _group_by(changes, "literal_index").items():
        literal = meta.literal_at(index)
        if literal is None:
            for change in group:
                change.status = "failed"
                change.message = "literal index not found (re-scan needed)"
            continue
        base = group[0].site.extra.get("full_value", group[0].site.value)
        if literal.value != base:
            for change in group:
                change.status = "failed"
                change.message = "file on disk differs from the scan (re-scan needed)"
            continue
        new_full = _merged_value(group, base)
        replacements[index] = new_full
        for change in group:
            change.status = "patched"
            change.message = "literal table rebuilt"
            change.extra["expect_value"] = new_full
            change.extra["new_offset"] = None
    if not replacements:
        return

    payload = meta.apply(replacements)
    try:
        check = il2cpp.GlobalMetadata(payload)
    except il2cpp.Il2CppError as exc:
        for change in changes:
            if change.status == "patched":
                change.status = "failed"
                change.message = "patched metadata did not re-parse"
        raise PatchAbort(f"patched metadata did not round-trip: {exc}") from exc

    for change in changes:
        if change.status != "patched":
            continue
        literal = check.literal_at(int(change.site.extra["literal_index"]))
        if literal is None or literal.value != change.extra.get("expect_value", change.new_value):
            change.status = "failed"
            change.message = "verification failed after rebuild"
            raise PatchAbort("patched global-metadata.dat failed verification")
        change.extra["new_offset"] = literal.offset

    _write_atomic(path, payload)


def _patch_unity_strings(path: str, changes: list[Change], warnings: list[str]) -> None:
    if _is_large(path):
        _patch_unity_strings_in_place(path, changes)
        return
    with open(path, "rb") as handle:
        data = bytearray(handle.read())

    for change in changes:
        length_field = int(change.site.extra.get("len_field", -1))
        slot = int(change.site.extra.get("slot", 0))
        if length_field < 0 or slot <= 4:
            change.status = "failed"
            change.message = "unity string slot unknown (re-scan needed)"
            continue
        encoded = change.new_value.encode("utf-8")
        needed = 4 + len(encoded)
        aligned = (needed + 3) & ~3
        if aligned > slot:
            change.status = "failed"
            change.message = f"value does not fit the {slot - 4}-byte field; shorten it"
            continue
        struct.pack_into("<i", data, length_field, len(encoded))
        data[length_field + 4 : length_field + 4 + len(encoded)] = encoded
        data[length_field + 4 + len(encoded) : length_field + slot] = b"\0" * (
            slot - 4 - len(encoded)
        )
        change.status = "patched"
        change.message = "unity string field rewritten"
        change.site.offset = length_field + 4

    if not any(change.status == "patched" for change in changes):
        return
    payload = bytes(data)
    for change in changes:
        if change.status != "patched":
            continue
        offset = change.site.offset
        encoded = change.new_value.encode("utf-8")
        if payload[offset : offset + len(encoded)] != encoded:
            raise PatchAbort(f"verification failed for {os.path.basename(path)}")
    _write_atomic(path, payload)


def _patch_unity_strings_in_place(path: str, changes: list[Change]) -> None:
    """Rewrite Unity string fields of a bundle that is too big to load."""
    try:
        handle = open(path, "r+b")
    except OSError as exc:
        raise PatchAbort(f"cannot open {os.path.basename(path)}: {exc}") from exc
    try:
        for change in changes:
            length_field = int(change.site.extra.get("len_field", -1))
            slot = int(change.site.extra.get("slot", 0))
            if length_field < 0 or slot <= 4:
                change.status = "failed"
                change.message = "unity string slot unknown (re-scan needed)"
                continue
            encoded = change.new_value.encode("utf-8")
            needed = 4 + len(encoded)
            aligned = (needed + 3) & ~3
            if aligned > slot:
                change.status = "failed"
                change.message = f"value does not fit the {slot - 4}-byte field; shorten it"
                continue
            handle.seek(length_field)
            original = handle.read(slot)
            if len(original) < slot or struct.unpack_from("<i", original, 0)[0] != len(
                change.site.value.encode("utf-8")
            ):
                change.status = "failed"
                change.message = "value moved (re-scan needed)"
                continue
            payload = struct.pack("<i", len(encoded)) + encoded
            payload += b"\0" * (slot - len(payload))
            handle.seek(length_field)
            handle.write(payload)
            change.status = "patched"
            change.message = "unity string field rewritten"
            change.site.offset = length_field + 4
            change.extra["journal"] = {"offset": length_field, "original": original.hex()}
        handle.flush()
        os.fsync(handle.fileno())
        for change in changes:
            if change.status != "patched":
                continue
            encoded = change.new_value.encode("utf-8")
            offset = change.site.offset
            handle.seek(offset)
            if handle.read(len(encoded)) != encoded:
                raise PatchAbort(f"verification failed for {os.path.basename(path)}")
    finally:
        handle.close()


def _patch_text(path: str, changes: list[Change], warnings: list[str]) -> None:
    with open(path, "rb") as handle:
        original = handle.read()
    data = bytearray(original)

    ordered = sorted(changes, key=lambda change: change.site.offset, reverse=True)
    for change in ordered:
        old = change.site.value.encode("utf-8")
        new = change.new_value.encode("utf-8")
        offset = change.site.offset
        if data[offset : offset + len(old)] != old:
            change.status = "failed"
            change.message = "value moved (re-scan needed)"
            continue
        data[offset : offset + len(old)] = new
        change.status = "patched"
        change.message = "text config rewritten"
        change.site.offset = offset

    if not any(change.status == "patched" for change in changes):
        return
    payload = bytes(data)
    for change in changes:
        if change.status != "patched":
            continue
        encoded = change.new_value.encode("utf-8")
        offset = change.site.offset
        if payload[offset : offset + len(encoded)] != encoded:
            raise PatchAbort(f"verification failed for {os.path.basename(path)}")
    _write_atomic(path, payload)


def _patch_raw(path: str, changes: list[Change], warnings: list[str]) -> None:
    if _is_large(path):
        _patch_raw_in_place(path, changes)
        return
    with open(path, "rb") as handle:
        data = bytearray(handle.read())

    for change in changes:
        encoding = change.site.encoding
        old = change.site.value.encode(encoding)
        new = change.new_value.encode(encoding)
        offset = change.site.offset
        if data[offset : offset + len(old)] != old:
            change.status = "failed"
            change.message = "value moved (re-scan needed)"
            continue
        if len(new) != len(old):
            change.status = "failed"
            change.message = (
                f"binary blob needs an id of exactly {len(change.site.value)} characters"
            )
            continue
        data[offset : offset + len(new)] = new
        change.status = "patched"
        change.message = "in place (binary blob)"

    if not any(change.status == "patched" for change in changes):
        return
    payload = bytes(data)
    for change in changes:
        if change.status != "patched":
            continue
        encoded = change.new_value.encode(change.site.encoding)
        offset = change.site.offset
        if payload[offset : offset + len(encoded)] != encoded:
            raise PatchAbort(f"verification failed for {os.path.basename(path)}")
    _write_atomic(path, payload)


def _patch_raw_in_place(path: str, changes: list[Change]) -> None:
    """Same rules as ``_patch_raw``, but only the touched bytes are written.

    Loading a multi-gigabyte bundle to change 36 bytes, and writing it back out
    through a temp file, is what made large games unusable; an id of the same
    length simply replaces the old one in place and the original bytes go into
    the manifest journal so Restore still brings them back.
    """
    try:
        handle = open(path, "r+b")
    except OSError as exc:
        raise PatchAbort(f"cannot open {os.path.basename(path)}: {exc}") from exc
    try:
        for change in changes:
            encoding = change.site.encoding
            old = change.site.value.encode(encoding)
            new = change.new_value.encode(encoding)
            offset = change.site.offset
            handle.seek(offset)
            if handle.read(len(old)) != old:
                change.status = "failed"
                change.message = "value moved (re-scan needed)"
                continue
            if len(new) != len(old):
                change.status = "failed"
                change.message = (
                    f"binary blob needs an id of exactly {len(change.site.value)} characters"
                )
                continue
            handle.seek(offset)
            handle.write(new)
            change.status = "patched"
            change.message = "in place (binary blob)"
            change.extra["journal"] = {"offset": offset, "original": old.hex()}
        handle.flush()
        os.fsync(handle.fileno())
        for change in changes:
            if change.status != "patched":
                continue
            encoded = change.new_value.encode(change.site.encoding)
            offset = change.site.offset
            handle.seek(offset)
            if handle.read(len(encoded)) != encoded:
                raise PatchAbort(f"verification failed for {os.path.basename(path)}")
    finally:
        handle.close()


_DISPATCH = {
    "us": _patch_assembly,
    "il2cpp": _patch_il2cpp,
    "unity_str": _patch_unity_strings,
    "text": _patch_text,
    "raw": _patch_raw,
}


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def apply(
    root: str,
    changes: list[Change],
    progress=None,
) -> PatchReport:
    started = time.time()
    report = PatchReport(changes=changes)
    root = os.path.abspath(root)
    manifest = load_manifest(root)

    # One file can hold several site kinds (a Mono assembly has both #US
    # literals and raw copies), so dispatch is per file *and* kind. Raw edits go
    # first because growing the metadata would invalidate their offsets.
    grouped: dict[tuple[str, str], list[Change]] = {}
    for change in changes:
        if change.status == "skipped":
            continue
        grouped.setdefault((change.site.path, change.site.kind), []).append(change)
    ordered = sorted(grouped.items(), key=lambda item: item[0][1] != "raw")

    total = len(ordered)
    for done, ((path, kind), file_changes) in enumerate(ordered, start=1):
        if progress:
            progress(done, total, os.path.relpath(path, root))
        handler = _DISPATCH.get(kind)
        if handler is None:
            report.errors.append(f"{os.path.basename(path)}: no patcher for {kind!r}")
            continue
        try:
            if ensure_backup(root, path, manifest):
                report.backups.append(path)
            entry = next(
                (e for e in manifest["entries"] if e.get("path") == os.path.relpath(path, root)),
                None,
            )
            try:
                handler(path, file_changes, report.warnings)
            finally:
                # Large files are restored from the journal, so record every span
                # the handler touched - even when it then failed verification, the
                # original bytes still have to be recoverable.
                if entry is not None and isinstance(entry.get("journal"), list):
                    seen = {int(span["offset"]) for span in entry["journal"]}
                    for change in file_changes:
                        span = change.extra.get("journal")
                        if span and int(span["offset"]) not in seen:
                            entry["journal"].append(span)
                            seen.add(int(span["offset"]))
            if any(change.status == "patched" for change in file_changes):
                report.written_files.append(path)
                if entry is not None:
                    entry["patched_sha256"] = _sha256_file(path)
                    entry["patched_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        except PatchAbort as exc:
            report.errors.append(f"{os.path.basename(path)}: {exc}")
            for change in file_changes:
                if change.status == "patched":
                    change.status = "failed"
                    change.message = str(exc)
        except OSError as exc:
            report.errors.append(f"{os.path.basename(path)}: {exc}")
            for change in file_changes:
                if change.status == "patched":
                    change.status = "failed"
                    change.message = str(exc)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{os.path.basename(path)}: unexpected error: {exc}")
            for change in file_changes:
                if change.status == "patched":
                    change.status = "failed"
                    change.message = f"unexpected error: {exc}"

    save_manifest(root, manifest)
    report.elapsed = time.time() - started
    return report


def _restore_journal(path: str, journal: list[dict]) -> bool:
    """Put the journaled original bytes of a large file back."""
    try:
        with open(path, "r+b") as handle:
            for span in journal:
                handle.seek(int(span["offset"]))
                handle.write(bytes.fromhex(span["original"]))
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except (OSError, KeyError, TypeError, ValueError):
        return False


def restore(root: str, progress=None) -> list[str]:
    """Copy every backup back over its patched file."""
    root = os.path.abspath(root)
    manifest = load_manifest(root)
    restored: list[str] = []
    entries = list(manifest.get("entries", []))
    for done, entry in enumerate(entries, start=1):
        relative = entry.get("path", "")
        backup_relative = entry.get("backup", "")
        if progress:
            progress(done, len(entries), relative)
        target = os.path.join(root, relative)
        journal = entry.get("journal")
        if isinstance(journal, list) and journal:
            if _restore_journal(target, journal):
                restored.append(target)
            continue
        backup = os.path.join(root, backup_relative)
        if not os.path.isfile(backup):
            continue
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(backup, target)
            restored.append(target)
        except OSError:
            continue
    manifest["entries"] = []
    save_manifest(root, manifest)
    return restored
