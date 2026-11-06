"""Regression tests for the scan/patch engine.

Run with:  python -m unittest discover -s tests -v

Everything is built from scratch in a temporary folder, so the tests never
touch a real game.  The assembly test uses the .NET Framework C# compiler when
it is available and is skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from photonpatcher import dnmeta, patch, scan

CSC_PATHS = (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
)

SOURCE = """
public static class PhotonConfig
{
    const string AppId = "4a1b2c3d-5e6f-4a8b-9c0d-1e2f3a4b5c6d";
    const string VoiceAppId = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";
    const string ChatAppId = "11223344-5566-4778-899a-bbccddeeff00";
    const string AppVersion = "1.0";
    public static string RealSettings() { return "appid=" + AppId + ";voice=" + VoiceAppId + ";chat=" + ChatAppId + ";ver=" + AppVersion; }
}
"""

OLD_APP = "4a1b2c3d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
OLD_VOICE = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
OLD_CHAT = "11223344-5566-4778-899a-bbccddeeff00"
NEW_APP = "0f0e0d0c-0b0a-4908-8706-050403020100"
NEW_VOICE = "abcdefab-cdef-4abc-8def-abcdefabcdef"


def unity_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    padded = raw + b"\0" * ((-len(raw)) % 4)
    return struct.pack("<i", len(raw)) + padded


def append_unity_string(blob: bytearray, text: str) -> None:
    """Append like Unity does: pad to a 4 byte boundary of the whole file."""
    raw = text.encode("utf-8")
    blob += struct.pack("<i", len(raw))
    blob += raw
    blob += b"\0" * ((-len(blob)) % 4)


def make_asset(gap: bytes = b"", version: str | None = None) -> bytes:
    """A player-build style asset: object name, then the serialized id."""
    blob = bytearray(b"\0" * 128)
    blob += b"PhotonServerSettings"
    blob += b"\0" * ((-len(blob)) % 4)
    blob += gap
    append_unity_string(blob, OLD_APP)
    if version is None:
        blob += b"\1\0\0\0" * 4
    else:
        blob += b"\0" * 12
        append_unity_string(blob, version)
        append_unity_string(blob, "eu")
    return bytes(blob)


class TempGame(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="photonpatcher-test-")
        self.data = os.path.join(self.root, "Game_Data")
        os.makedirs(self.data)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, relative: str, payload: bytes) -> str:
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)
        return path


class TestUserStrings(TempGame):
    def test_encode_roundtrip(self) -> None:
        encoded = dnmeta.encode_user_string("hello")
        self.assertEqual(encoded[0], len("hello") * 2 + 1)
        stored = dnmeta.decode_user_string(encoded) if hasattr(dnmeta, "decode_user_string") else None
        if stored is not None:
            self.assertEqual(stored, "hello")

    def test_ascii_and_unicode_lengths(self) -> None:
        self.assertEqual(len(dnmeta.encode_user_string("abc")), 1 + 6 + 1)
        self.assertEqual(len(dnmeta.encode_user_string("")), 1 + 0 + 1)


class TestAssetScan(TempGame):
    def test_player_build_asset_finds_app_id(self) -> None:
        self.write("Game_Data/resources.assets", make_asset())
        result = scan.scan(self.root)
        values = [site.value for site in result.sites]
        self.assertIn(OLD_APP, values)
        site = next(site for site in result.sites if site.value == OLD_APP)
        self.assertEqual(site.role, scan.APP_ID)
        self.assertGreaterEqual(site.confidence, 0.9)

    def test_asset_patches_in_place_and_restores(self) -> None:
        path = self.write("Game_Data/resources.assets", make_asset())
        with open(path, "rb") as handle:
            original = handle.read()
        result = scan.scan(self.root)
        changes = patch.plan(result.sites, patch.Target(app_id=NEW_APP))
        report = patch.apply(self.root, changes)
        self.assertEqual(report.summary().split(",")[0], "1 patched")

        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        self.assertEqual(patched.count(NEW_APP.encode()), 1)
        self.assertNotIn(OLD_APP.encode(), patched)
        self.assertEqual([site.value for site in scan.scan(self.root).sites], [NEW_APP])

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), original)

    def test_version_next_to_id_is_found_and_repacked(self) -> None:
        path = self.write("Game_Data/data.unity3d", make_asset(version="1.3.7.2-SIPS-debug"))
        with open(path, "rb") as handle:
            original = handle.read()

        result = scan.scan(self.root)
        versions = [site for site in result.sites if site.role == scan.APP_VERSION]
        self.assertEqual([site.value for site in versions], ["1.3.7.2-SIPS-debug"])

        changes = patch.plan(result.sites, patch.Target(version="9.9"))
        report = patch.apply(self.root, changes)
        self.assertEqual(report.patched, [change for change in changes if change.status == "patched"])
        self.assertTrue(report.patched)

        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        start = patched.find(b"9.9")
        self.assertIn(b"\x03\x00\x00\x009.9", patched)
        self.assertEqual(patched[start - 4 : start], b"\x03\x00\x00\x00")
        self.assertNotIn(b"1.3.7.2-SIPS-debug", patched)

    def test_two_ids_in_one_settings_object(self) -> None:
        blob = bytearray(b"\0" * 64)
        blob += b"PhotonServerSettings"
        blob += b"\0" * ((-len(blob)) % 4)
        append_unity_string(blob, OLD_APP)
        blob += b"\0" * 4
        append_unity_string(blob, OLD_CHAT)
        self.write("Game_Data/resources.assets", bytes(blob))

        sites = scan.scan(self.root).sites
        self.assertEqual([site.role for site in sites], [scan.APP_ID, scan.UNCLASSIFIED])
        self.assertGreaterEqual(sites[0].confidence, 0.9)
        self.assertEqual([site.value for site in sites], [OLD_APP, OLD_CHAT])

        target = patch.Target(app_id=NEW_APP, voice_id=NEW_VOICE, same_voice=False)
        changes = patch.plan(sites, target)
        self.assertEqual(changes[0].new_value, NEW_APP)
        self.assertEqual(changes[1].new_value, NEW_APP)  # unknown ids follow --app-id

        changes = patch.plan(sites, patch.Target(app_id=NEW_APP, patch_unclassified=False))
        self.assertEqual(changes[1].status, "skipped")

    def test_unrelated_guid_is_ignored(self) -> None:
        junk = b"\0" * 600 + unity_string(OLD_APP) + b"\0" * 600
        self.write("Game_Data/sharedassets0.assets", junk)
        self.assertEqual(scan.scan(self.root).sites, [])


class TestLargeBundle(TempGame):
    """Bundles past the in-memory limit are mapped, then patched in place.

    The threshold is lowered for the test so a couple of megabytes stand in for
    the multi-gigabyte `data.unity3d` of a real game.
    """

    def setUp(self) -> None:
        super().setUp()
        self.scan_limit = scan.MAX_BLOB
        self.patch_limit = patch.MAX_BLOB
        scan.MAX_BLOB = 1024
        patch.MAX_BLOB = 1024

    def tearDown(self) -> None:
        scan.MAX_BLOB = self.scan_limit
        patch.MAX_BLOB = self.patch_limit
        super().tearDown()

    def write_big_asset(self, version: str | None = None) -> str:
        padding = b"\0" * (1024 * 1024)
        return self.write("Game_Data/data.unity3d", padding + make_asset(version=version) + padding)

    def test_windowed_scan_reports_file_offsets(self) -> None:
        path = self.write_big_asset()
        with open(path, "rb") as handle:
            original = handle.read()

        result = scan.scan(self.root)
        site = next(site for site in result.sites if site.value == OLD_APP)
        self.assertEqual(site.role, scan.APP_ID)
        self.assertEqual(site.offset, original.index(OLD_APP.encode()))

    def test_big_bundle_patches_in_place_and_restores(self) -> None:
        path = self.write_big_asset()
        with open(path, "rb") as handle:
            original = handle.read()

        changes = patch.plan(scan.scan(self.root).sites, patch.Target(app_id=NEW_APP))
        report = patch.apply(self.root, changes)
        self.assertFalse(report.failed, [change.message for change in report.failed])
        self.assertEqual(len(report.patched), 1)

        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        self.assertEqual(patched.count(NEW_APP.encode()), 1)
        self.assertNotIn(OLD_APP.encode(), patched)
        # A multi-gigabyte game must not need a copy of itself to be patched.
        self.assertFalse(os.path.exists(os.path.join(self.root, ".photonpatcher", "backups")))

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), original)

    def test_big_bundle_app_version_patched_in_place(self) -> None:
        path = self.write_big_asset(version="1.3.7.2-SIPS-debug")
        with open(path, "rb") as handle:
            original = handle.read()

        sites = scan.scan(self.root).sites
        versions = [site for site in sites if site.role == scan.APP_VERSION]
        self.assertEqual([site.value for site in versions], ["1.3.7.2-SIPS-debug"])

        report = patch.apply(self.root, patch.plan(sites, patch.Target(version="9.9")))
        self.assertFalse(report.failed, [change.message for change in report.failed])
        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        self.assertIn(b"\x03\x00\x00\x009.9", patched)

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), original)


class TestTextConfig(TempGame):
    def test_product_keys_get_their_own_roles(self) -> None:
        self.write(
            "Game_Data/photon.cfg",
            f"AppIdRealtime={OLD_APP}\nAppIdChat={OLD_CHAT}\nAppIdVoice={OLD_VOICE}\n".encode(),
        )
        roles = {site.value: site.role for site in scan.scan(self.root).sites}
        self.assertEqual(roles.get(OLD_APP), scan.APP_ID)
        self.assertEqual(roles.get(OLD_CHAT), scan.CHAT_ID)
        self.assertEqual(roles.get(OLD_VOICE), scan.VOICE_ID)

    def test_text_patch_and_restore(self) -> None:
        path = self.write(
            "Game_Data/settings.cfg",
            f"[photon]\nAppId={OLD_APP}\nAppVersion=1.0\n".encode(),
        )
        result = scan.scan(self.root)
        self.assertTrue(any(site.kind == "text" for site in result.sites))
        changes = patch.plan(result.sites, patch.Target(app_id=NEW_APP, version="2.5"))
        report = patch.apply(self.root, changes)
        self.assertFalse(report.failed)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn(NEW_APP, text)
        self.assertIn("AppVersion=2.5", text)
        patch.restore(self.root)
        with open(path, encoding="utf-8") as handle:
            self.assertIn(OLD_APP, handle.read())


class TestRoleHeuristics(unittest.TestCase):
    def test_explicit_key_wins(self) -> None:
        self.assertTrue(scan._guid_has_context([f"appid={OLD_APP}"], 0, 6))
        self.assertFalse(scan._guid_has_context(["Dissonance debug", OLD_APP, "buffer full"], 1, 0))

    def test_role_from_prefix(self) -> None:
        self.assertEqual(scan._role_from_prefix(f"voice={OLD_APP}", 6, ""), scan.VOICE_ID)
        self.assertEqual(scan._role_from_prefix(f"appid={OLD_APP}", 6, ""), scan.APP_ID)
        self.assertEqual(scan._role_from_prefix(f"appidchat={OLD_APP}", 10, ""), scan.CHAT_ID)
        self.assertEqual(scan._role_from_prefix(f"appidfusion={OLD_APP}", 12, ""), scan.FUSION_ID)

    def test_role_from_key(self) -> None:
        cases = {
            "AppIdRealtime": scan.APP_ID,
            "AppID": scan.APP_ID,
            "AppIdVoice": scan.VOICE_ID,
            "VoiceAppID": scan.VOICE_ID,
            "AppIdChat": scan.CHAT_ID,
            "ChatAppID": scan.CHAT_ID,
            "AppIdVideo": scan.VIDEO_ID,
            "AppIdFusion": scan.FUSION_ID,
            "AppIdQuantum": scan.QUANTUM_ID,
            "AppVersion": scan.APP_VERSION,
        }
        for key, role in cases.items():
            self.assertEqual(scan._role_from_key(key), role, key)

    def test_product_ids_only_when_asked(self) -> None:
        target = patch.Target(app_id=NEW_APP)
        self.assertEqual(target.value_for(scan.CHAT_ID), NEW_APP)
        self.assertEqual(target.value_for(scan.FUSION_ID), NEW_APP)
        target = patch.Target(app_id=NEW_APP, fill_from_app_id=False)
        self.assertIsNone(target.value_for(scan.CHAT_ID))
        target = patch.Target(app_id=NEW_APP, chat_id="cafebabe-0000-4000-8000-000000000001")
        self.assertEqual(target.value_for(scan.CHAT_ID), "cafebabe-0000-4000-8000-000000000001")

    def test_plan_skips_missing_targets(self) -> None:
        site = scan.Site(
            path="x", kind="text", offset=0, encoding="utf-8",
            value=OLD_APP, role=scan.APP_VERSION, confidence=0.9,
        )
        changes = patch.plan([site], patch.Target(app_id=NEW_APP))
        self.assertEqual(changes[0].status, "skipped")

    def test_same_voice_flag(self) -> None:
        target = patch.Target(app_id=NEW_APP)
        self.assertEqual(target.value_for(scan.VOICE_ID), NEW_APP)
        target = patch.Target(app_id=NEW_APP, voice_id=NEW_VOICE, same_voice=False)
        self.assertEqual(target.value_for(scan.VOICE_ID), NEW_VOICE)


class TestAssemblyPatch(TempGame):
    @classmethod
    def setUpClass(cls) -> None:
        cls.csc = next((path for path in CSC_PATHS if os.path.isfile(path)), None)

    def build_dll(self) -> str:
        source = os.path.join(self.root, "PhotonTest.cs")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write(SOURCE)
        dll = os.path.join(self.root, "PhotonTest.dll")
        result = subprocess.run(
            [self.csc, "/nologo", "/target:library", f"/out:{dll}", source],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return dll

    def test_literal_and_const_are_both_patched(self) -> None:
        if not self.csc:
            self.skipTest("no C# compiler on this machine")
        dll = self.build_dll()
        with open(dll, "rb") as handle:
            target = self.write("Game_Data/Managed/PhotonTest.dll", handle.read())

        result = scan.scan(self.root)
        kinds = {
            (site.kind, site.role)
            for site in result.sites
            if site.value in (OLD_APP, OLD_VOICE, OLD_CHAT)
        }
        self.assertIn(("us", scan.APP_ID), kinds)
        self.assertIn(("us", scan.CHAT_ID), kinds)
        self.assertIn(("raw", scan.APP_ID), kinds)

        changes = patch.plan(result.sites, patch.Target(app_id=NEW_APP, voice_id=NEW_VOICE, same_voice=False))
        report = patch.apply(self.root, changes)
        self.assertFalse(report.failed, [change.message for change in report.failed])

        with open(target, "rb") as handle:
            patched = handle.read()
        meta = dnmeta.Metadata(patched)
        literals = [entry.value for entry in meta.user_strings()]
        folded = next(value for value in literals if NEW_APP in value)
        self.assertIn(NEW_VOICE, folded)
        self.assertIn("chat=" + NEW_APP, folded)
        self.assertNotIn(OLD_APP, folded)
        self.assertNotIn(OLD_VOICE, folded)
        self.assertNotIn(OLD_CHAT, folded)

    def test_restore_returns_original_bytes(self) -> None:
        if not self.csc:
            self.skipTest("no C# compiler on this machine")
        dll = self.build_dll()
        with open(dll, "rb") as handle:
            target = self.write("Game_Data/Managed/PhotonTest.dll", handle.read())
        with open(target, "rb") as handle:
            original = handle.read()

        result = scan.scan(self.root)
        changes = patch.plan(result.sites, patch.Target(app_id=NEW_APP))
        patch.apply(self.root, changes)
        with open(target, "rb") as handle:
            self.assertNotEqual(handle.read(), original)
        patch.restore(self.root)
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), original)


if __name__ == "__main__":
    unittest.main()
