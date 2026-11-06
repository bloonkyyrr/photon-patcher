"""Command line interface for headless / scripted use.

Examples
--------
    python -m photonpatcher scan "C:\\Games\\Secret Neighbor"
    python -m photonpatcher patch "C:\\Games\\Secret Neighbor" --app-id 1111... --version 2.0
    python -m photonpatcher restore "C:\\Games\\Secret Neighbor"
    python -m photonpatcher verify "C:\\Games\\Secret Neighbor" --app-id 1111...
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import patch as patch_mod
from . import scan as scan_mod


def _print_scan(result: scan_mod.ScanResult, verbose: bool = True) -> None:
    print(f"Game        : {result.game_name}")
    print(f"Backend     : {result.backend}")
    if result.unity_version:
        print(f"Unity       : {result.unity_version}")
    if result.il2cpp_version:
        print(f"IL2CPP      : {result.il2cpp_version}")
    print(f"Files       : {result.files_scanned} scanned in {result.elapsed:.2f}s")
    print(f"Photon hints: {', '.join(result.evidence) or 'none'}")
    if result.server_hints:
        print(f"Servers     : {', '.join(result.server_hints)}")
    if not result.sites:
        print("No patchable Photon ids found.")
        for warning in result.warnings[:10]:
            print(f"  ! {warning}")
        return

    print()
    header = f"{'FILE':38s} {'KIND':10s} {'ROLE':11s} {'OLD VALUE':40s} {'CONF':5s}"
    print(header)
    print("-" * len(header))
    for site in result.sites:
        relative = os.path.relpath(site.path, result.root)
        if len(relative) > 37:
            relative = "..." + relative[-34:]
        print(
            f"{relative:38s} {site.kind:10s} {site.role:11s} {site.value[:40]:40s} {site.confidence:0.2f}"
        )
    if result.warnings:
        print()
        for warning in result.warnings[:10]:
            print(f"  ! {warning}")


def cmd_scan(args: argparse.Namespace) -> int:
    result = scan_mod.scan(args.folder, deep=args.deep)
    if args.json:
        payload = {
            "root": result.root,
            "game": result.game_name,
            "backend": result.backend,
            "unity": result.unity_version,
            "il2cpp": result.il2cpp_version,
            "evidence": result.evidence,
            "warnings": result.warnings,
            "sites": [
                {
                    "path": os.path.relpath(site.path, result.root),
                    "kind": site.kind,
                    "role": site.role,
                    "value": site.value,
                    "offset": site.offset,
                    "confidence": round(site.confidence, 3),
                    "context": site.context,
                }
                for site in result.sites
            ],
        }
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        print(f"report written to {args.json}")
    _print_scan(result)
    return 0 if result.sites else 1


ROLE_NAMES = {
    "realtime": scan_mod.APP_ID,
    "pun": scan_mod.APP_ID,
    "voice": scan_mod.VOICE_ID,
    "chat": scan_mod.CHAT_ID,
    "video": scan_mod.VIDEO_ID,
    "fusion": scan_mod.FUSION_ID,
    "quantum": scan_mod.QUANTUM_ID,
    "version": scan_mod.APP_VERSION,
    "appversion": scan_mod.APP_VERSION,
}


def _apply_roles(sites, assignments) -> list[scan_mod.Site]:
    """Re-label ids by value prefix: --role e93ae440=voice."""
    if not assignments:
        return sites
    wanted: list[tuple[str, str]] = []
    for item in assignments:
        value, _, role_name = item.partition("=")
        role = ROLE_NAMES.get(role_name.strip().lower())
        if role is None or not value.strip():
            print(f"ignoring --role {item!r} (use VALUE=realtime|voice|chat|video|fusion|quantum|version)", file=sys.stderr)
            continue
        wanted.append((value.strip().lower(), role))
    for site in sites:
        for prefix, role in wanted:
            if site.value.lower().startswith(prefix):
                site.role = role
                break
    return sites


def _select(sites, args) -> list[scan_mod.Site]:
    selected = list(sites)
    if args.only_old:
        wanted = {value.strip().lower() for value in args.only_old.split(",") if value.strip()}
        selected = [site for site in selected if site.value.lower() in wanted]
    if args.file:
        needle = args.file.lower()
        selected = [site for site in selected if needle in site.path.lower()]
    return selected


def cmd_patch(args: argparse.Namespace) -> int:
    for value in filter(None, (args.app_id, args.voice_id, args.version)):
        problem = patch_mod.validate_value(value)
        if problem:
            print(f"invalid value {value!r}: {problem}", file=sys.stderr)
            return 2

    result = scan_mod.scan(args.folder, deep=args.deep)
    _print_scan(result, verbose=False)
    if not result.sites:
        return 1

    target = patch_mod.Target(
        app_id=args.app_id,
        voice_id=args.voice_id,
        chat_id=args.chat_id,
        video_id=args.video_id,
        fusion_id=args.fusion_id,
        quantum_id=args.quantum_id,
        version=args.version,
        patch_unclassified=not args.skip_unclassified,
        same_voice=args.same_voice if args.same_voice is not None else not args.voice_id,
        fill_from_app_id=args.fill_from_app_id,
    )
    sites = _apply_roles(_select(result.sites, args), args.role)
    changes = patch_mod.plan(sites, target)
    todo = [change for change in changes if change.status == "pending"]
    if not todo:
        print("Nothing to do: every selected id already matches the target.")
        return 0

    print(f"\n{len(todo)} id(s) will be patched:")
    for change in todo:
        print(f"  {os.path.basename(change.site.path):32s} {change.old_value} -> {change.new_value}")

    if args.dry_run:
        print("\ndry run: nothing written")
        return 0
    if not args.yes:
        answer = input("\ncontinue? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("aborted")
            return 1

    report = patch_mod.apply(result.root, changes)
    print()
    for change in report.changes:
        if change.status == "patched":
            print(f"  OK   {os.path.basename(change.site.path):32s} {change.old_value} -> {change.new_value}")
        elif change.status == "failed":
            print(f"  FAIL {os.path.basename(change.site.path):32s} {change.message}")
    for warning in report.warnings:
        print(f"  ! {warning}")
    for error in report.errors:
        print(f"  ERROR {error}")
    print(f"\n{report.summary()} in {report.elapsed:.2f}s")
    return 0 if not report.errors else 1


def cmd_restore(args: argparse.Namespace) -> int:
    restored = patch_mod.restore(args.folder, progress=None)
    if not restored:
        print("no backups found")
        return 1
    for path in restored:
        print(f"restored {path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    result = scan_mod.scan(args.folder, deep=args.deep)
    if args.app_id:
        app_ids = {site.value for site in result.sites if site.role in (scan_mod.APP_ID, scan_mod.VOICE_ID)}
        ok = args.app_id in app_ids
        print(f"app id {args.app_id}: {'present' if ok else 'NOT present'}")
        if args.version:
            versions = {site.value for site in result.sites if site.role == scan_mod.APP_VERSION}
            print(f"version {args.version}: {'present' if args.version in versions else 'NOT present'}")
        return 0 if ok else 1
    _print_scan(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="photonpatcher",
        description="Repoint Photon AppIds inside Unity games (Mono and IL2CPP).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="list every patchable Photon id")
    scan_parser.add_argument("folder")
    scan_parser.add_argument("--deep", action="store_true", help="also scan non-standard files")
    scan_parser.add_argument("--json", help="write a JSON report to this path")
    scan_parser.set_defaults(func=cmd_scan)

    patch_parser = sub.add_parser("patch", help="apply new ids")
    patch_parser.add_argument("folder")
    patch_parser.add_argument("--app-id", "--realtime-id", dest="app_id", help="new Realtime/PUN AppId")
    patch_parser.add_argument("--voice-id", help="new Photon Voice AppId (defaults to --app-id)")
    patch_parser.add_argument("--chat-id", help="new Photon Chat AppId (defaults to --app-id)")
    patch_parser.add_argument("--video-id", help="new Photon Video AppId (defaults to --app-id)")
    patch_parser.add_argument("--fusion-id", help="new Photon Fusion AppId (defaults to --app-id)")
    patch_parser.add_argument("--quantum-id", help="new Photon Quantum AppId (defaults to --app-id)")
    patch_parser.add_argument("--version", help="new AppVersion")
    patch_parser.add_argument(
        "--no-fill",
        dest="fill_from_app_id",
        action="store_false",
        help="do not reuse the realtime id for product ids left empty",
    )
    patch_parser.add_argument("--deep", action="store_true")
    patch_parser.add_argument("--skip-unclassified", action="store_true", help="only patch ids recognised as Photon ids")
    patch_parser.add_argument(
        "--same-voice",
        dest="same_voice",
        action="store_true",
        default=None,
        help="use the app id for voice too (default when --voice-id is omitted)",
    )
    patch_parser.add_argument("--separate-voice", dest="same_voice", action="store_false")
    patch_parser.add_argument(
        "--role",
        action="append",
        metavar="VALUE=ROLE",
        help="label an id, e.g. --role e93ae440=voice (roles: realtime, voice, chat, video, fusion, quantum, version)",
    )
    patch_parser.add_argument("--only-old", help="comma separated list of old ids to touch")
    patch_parser.add_argument("--file", help="only patch files whose path contains this text")
    patch_parser.add_argument("--dry-run", action="store_true")
    patch_parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    patch_parser.set_defaults(func=cmd_patch)

    restore_parser = sub.add_parser("restore", help="copy backups back")
    restore_parser.add_argument("folder")
    restore_parser.set_defaults(func=cmd_restore)

    verify_parser = sub.add_parser("verify", help="re-scan and check a target id is present")
    verify_parser.add_argument("folder")
    verify_parser.add_argument("--app-id")
    verify_parser.add_argument("--version")
    verify_parser.add_argument("--deep", action="store_true")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
