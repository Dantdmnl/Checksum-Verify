# Privacy & Data Storage

**Checksum-Verify 1.7.0** | Updated October 4, 2026

## Processing and Networking

Checksums are calculated locally. Target file contents, checksum input,
settings, and recent-file history are not uploaded. BLAKE3 sends file bytes to
the local `b3sum.exe` process through standard input. Local and UNC access
follows selected paths; a network share can involve that share's server.

Choosing `U` contacts GitHub for release metadata. Confirming an update
downloads the script. Confirming BLAKE3 setup contacts GitHub for metadata and
the executable. Requests disclose ordinary connection information, including IP
address and User-Agent, to GitHub and its download infrastructure. No startup
update checks or backend downloads happen automatically.

Download checks validate published hashes and sizes, not the trustworthiness of
a potentially compromised publisher.

## Stored Data

| Data            | Location and contents                                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Settings        | `%LOCALAPPDATA%\checksum-tool\settings.json`: preferences, log directory, privacy controls, and optional recent paths               |
| Logs            | Default: `%LOCALAPPDATA%\checksum-tool\checksum_tool.log`; directory configurable. Events, timestamps, errors, and optionally paths |
| Recent history  | In settings; disabled by default, maximum ten entries by default when enabled                                                       |
| Saved checksums | Beside the target when requested: digests, manifest filenames, or metadata                                                          |
| Privacy export  | Uniquely named Desktop JSON: settings, export timestamp, log-file path, and utility version; not log contents                       |
| Update backup   | Uniquely named `.bak` beside the script after replacement                                                                           |
| BLAKE3 backend  | `b3sum.exe` beside the script after automatic setup; manual installation can use `PATH`                                             |

Metadata includes algorithm, digest, creation time, and file information.
Username inclusion is off by default. With path anonymization enabled, metadata
uses the basename instead of the full target path.

The utility does not encrypt these files. Windows permissions apply. Filenames,
paths, and error messages may be sensitive; review logs, exports, and sidecars
before sharing them.

## Privacy Menu

Open `6) Privacy & data`:

| Key | Action                                                                           |
| --- | -------------------------------------------------------------------------------- |
| `1` | Toggle username in metadata and quick/metadata output filenames                  |
| `2` | Toggle path anonymization in logs and metadata                                   |
| `3` | Toggle history tracking; disabling clears saved history                          |
| `4` | View current settings as JSON                                                    |
| `5` | Clear recent history after confirmation                                          |
| `6` | Clear the current log and configured archives after confirmation                 |
| `7` | Export settings information as JSON                                              |
| `8` | Delete settings, current logs, and configured archives; type `DELETE` to confirm |
| `0` | Back                                                                             |

Path anonymization is on by default and redacts recognized Windows/UNC paths in
log messages. It does not guarantee removal of every filename or identifying
detail in arbitrary error text. It does not redact terminal output, settings,
enabled history, or privacy exports. The main menu displays the Windows username
regardless of metadata preferences. Clipboard input is previewed locally before
use.

## Retention and Deletion Limits

Logs rotate at 5 MB with up to five archives. Clearing logs writes a new audit
entry recording the clear action. Deleting all local data exits; a later launch
can create fresh settings/logs.

Privacy changes do not retroactively scrub old logs or metadata. Changing the
log directory does not move or delete logs from the old location.

Deletion does not remove targets, saved checksums, privacy exports, update
backups, the script, BLAKE3 executables, or logs in earlier directories. Delete
those separately when no longer needed. File deletion is not secure erasure.

Auto-copy is off by default. When enabled or requested, checksum text goes to
the Windows clipboard. Clipboard history/sync and other applications are outside
this utility's control. Exiting or deleting local data does not clear the
clipboard.

## Contact

Author: Ruben Draaisma. Questions and issues:
[Checksum-Verify repository](https://github.com/Dantdmnl/Checksum-Verify).
