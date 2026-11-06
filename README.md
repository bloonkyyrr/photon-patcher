# Photon Patcher

A desktop tool that rewrites the **Photon** ids baked into a Unity game so it
connects to **your own** Photon application (self-hosted Photon Server, your own
Photon Cloud app, or a private server) instead of the original one.

It knows every Photon id type and keeps them apart:

| Id type | Recognised field names | Notes |
| --- | --- | --- |
| **Realtime / PUN** | `AppIdRealtime`, `AppID`, `AppId`, `PhotonAppID` | PUN runs on Realtime and shares its id, so both are one value |
| **Voice** | `AppIdVoice`, `VoiceAppID` | falls back to the realtime id inside Photon when the game leaves it empty |
| **Chat** | `AppIdChat`, `ChatAppID` | |
| **Video** | `AppIdVideo`, `VideoAppID` | Photon Video needs its own app id |
| **Fusion** | `AppIdFusion`, `FusionAppID` | Fusion 2 `PhotonAppSettings` asset |
| **Quantum** | `AppIdQuantum`, `QuantumAppID` | Quantum's `PhotonServerSettings` asset |
| **AppVersion** | `AppVersion`, `app_version` | the version string sent when joining |

Each type has its own field in the window (and its own CLI flag). Leave one
empty and the game keeps whatever it has - unless **reuse the realtime id** is
ticked, which points every product at your realtime app id. That is what a
single-app Photon setup needs.

How the roles are decided:

* field names in text/YAML configs and in assets that still carry a type tree,
* the key written right before an id inside a literal (`appidchat=...`,
  `voice=...`), which is how PUN builds its settings strings,
* for player-build assets that have no field names at all, the id inside the
  `PhotonServerSettings` / `PhotonAppSettings` object is taken as **Realtime**;
  double-click the **Role** cell to mark it as Voice, Chat, Video, Fusion,
  Quantum or AppVersion instead.

Nothing is game specific: the tool scans a folder, finds the ids, and lets you
tick which ones to replace.

---

## Quick start (GUI)

1. Double-click **`run.bat`** (or `PhotonPatcher.pyw`).
2. **Browse…** to the folder that contains the game `.exe`.
3. Press **Scan**. The table lists everything that looks like a Photon id with a
   confidence score.
4. Type your own **App id** (and voice id / app version if you need them).
5. Tick the rows you want, press **Patch**.
6. If the game misbehaves, press **Restore backups** - every patched file is
   restored from `.photonpatcher\backups` inside the game folder.

Rows above `0.80` confidence are pre-ticked. Click the checkbox column to toggle
a row, double-click the **Role** column to cycle `AppId → VoiceAppId →
AppVersion` when the guess is wrong.

## Quick start (command line)

```bat
python -m photonpatcher scan   "C:\Games\MyGame"
python -m photonpatcher patch  "C:\Games\MyGame" --app-id 1234abcd-... --yes
python -m photonpatcher patch  "C:\Games\MyGame" --app-id 1234abcd-... --voice-id 9999... --version 2.0 --dry-run
python -m photonpatcher patch  "C:\Games\MyGame" --app-id 1234... --chat-id 5678... --fusion-id 9abc... --no-fill

`--app-id` (alias `--realtime-id`) is the PUN/Realtime id. `--voice-id`,
`--chat-id`, `--video-id`, `--fusion-id` and `--quantum-id` override individual
products; `--no-fill` stops the realtime id from being reused for anything left
empty.

`--role` labels an id the scanner could not identify, by value or value prefix:

```bat
python -m photonpatcher patch "C:\Games\RecRoom" --app-id 1234... ^
       --voice-id 5678... --role e93ae440=voice --yes
```
python -m photonpatcher verify "C:\Games\MyGame" --app-id 1234abcd-...
python -m photonpatcher restore "C:\Games\MyGame"
```

`scan --deep` also looks into files with unusual extensions. `patch --json`
writes a machine readable report.

---

## What it actually does

The tool never does blind byte replacement on a whole file. Each file type gets
a real parser, and every write is verified by re-reading the file before it
touches the disk.

**Mono assemblies** (`*_Data\Managed\*.dll`)

* Parses the PE image and the ECMA-335 metadata streams (`#~`, `#Strings`,
  `#US`, `#Blob`).
* Finds GUIDs inside `ldstr` literals, including GUIDs embedded in a longer
  string such as `"appid=...;voice=..."`.
* If the new value fits the existing literal slot it is written in place.
  Otherwise a new literal is appended to the `#US` heap, the metadata is
  rebuilt, the section table is updated (new `.phop` section, or an extension of
  the last section), and every `ldstr` token pointing at the old string is
  retargeted.
* `const string` copies stored in the `#Blob` heap are patched as well, so both
  the literal and the constant end up with the new id.

**IL2CPP builds** (`global-metadata.dat`)

* Parses the metadata header (version agnostic, validated with the `0xFAB11BAF`
  sanity value), rebuilds the string-literal table and repoints the header
  offsets. Written in place when the new table fits, appended otherwise.

**Unity assets / bundles** (`resources.assets`, `*.assets`, `*.bundle`,
`data.unity3d`, …)

* Files above 512 MB are mapped and searched window by window instead of being
  read into memory, so a 5 GB bundle is scanned like any other.
* Finds `key: value` pairs stored as Unity length-prefixed strings.
* Player builds strip the type tree, so field names such as `AppID` are not in
  the file at all. In that case the settings object is found by its name
  (`PhotonServerSettings`, `PhotonAppSettings`) and every id inside it is read
  from its 4-byte length prefix + GUID framing. The first id becomes
  **Realtime**; further ids in the same object become **Unknown** because the
  order differs between PUN versions - label them by double-clicking **Role**,
  or with `--role <value-prefix>=voice` on the command line.
* PUN also stores `AppVersion` inside that same settings object, right after the
  id (for example `AppId`, then `1.3.7.2-SIPS-debug`, then the region). The
  version string is picked up automatically at a lower confidence and rewritten
  *inside its existing field*, so a shorter version is zero-padded and the file
  keeps its exact size - no offsets inside the asset are disturbed.
* This is how IL2CPP games are usually patched: their ids live in
  `data.unity3d` / the asset bundle, not in `global-metadata.dat`.

**Text configs** (`.json`, `.cfg`, `.ini`, `*.txt`, …) - `key=value` and
`key: value` pairs.

**Everything else** - a GUID inside a binary blob is only accepted when a key
name or an already identified literal is adjacent to it.

### Why there is a confidence score

Games are full of GUIDs that have nothing to do with Photon (audio plugins love
printing them). A GUID only becomes a candidate when something names it, and
values sitting next to `PhotonServerSettings` or an explicit `appid=` score
highest. Anything below `0.80` is left unticked.

---

## Safety

* **Backups**: the first time a file is modified, the original is copied to
  `<game>\.photonpatcher\backups\<relative path>`, and
  `.photonpatcher\manifest.json` records the SHA-256 of the patched file.
  A bundle too big to copy (over 512 MB) is journaled instead: the manifest
  keeps the exact bytes the patch overwrote, so **Restore backups** is just as
  exact without needing a second copy of a multi-gigabyte file on disk.
* **Verification**: the patched bytes are re-parsed (metadata, literal table,
  asset string) and compared to the wanted values *before* the write. A file
  that fails verification is left untouched.
* **Idempotent**: re-running a scan after a successful patch finds the new ids;
  patching again is harmless.
* **Strong naming**: if an assembly has to grow and there is no room for a new
  section header, the last section is extended, which invalidates the strong-name
  signature. The tool warns when that happens - such assemblies only load if the
  game does not verify signatures (typical for Unity's `Assembly-CSharp.dll`).

---

## Requirements

* Windows.
* Python 3.10+ with Tkinter (included in the official Windows installer).
* No third-party packages, no .NET runtime, nothing to install.

Run the test suite with:

```bat
python -m unittest discover -s tests -v
```

The assembly tests use the .NET Framework C# compiler (`csc.exe`, shipped with
Windows) to build a throwaway DLL and are skipped automatically if it is missing.

---

## Limitations

* IL2CPP **encrypted** metadata (Rec Room and other protected builds) cannot be
  parsed - the tool reports `bad magic` and keeps going: the Photon ids in those
  games live in the Unity assets, which still work. Only ids that exist *inside*
  the metadata are out of reach for such builds.
* Packed/protected executables that decrypt their assemblies at runtime are not
  handled.
* Ids inside `.resS`/`.resource` streaming files, or inside LZ4/LZMA compressed
  bundles, are not rewritten - the text is not readable there. Uncompressed
  bundles (like `data.unity3d` in most PC IL2CPP builds) work fine.
* Bundles over 512 MB (`data.unity3d` of a big game is often 5 GB) are never
  loaded: they are memory mapped, one sequential pass finds the regions that can
  hold a Photon id, and only those windows are parsed. Patching them rewrites
  the id where it sits, so the file keeps its size and layout. Files are still
  read whole below 512 MB, and the scan spends most of its time on disk I/O for
  a huge bundle (roughly a minute for 5 GB).
* A rewritten `AppVersion` must fit the field it came from (the tool says how
  many bytes are available if it does not).
* A `AppVersion` change can break server-side matchmaking; only change it if your
  server expects the new value.

## Legal

Use this on games you own, with servers you are allowed to run. It rewrites
configuration values only - it contains no DRM circumvention, no piracy tooling
and no code injection. Respect the terms of service of whatever you are modding.
