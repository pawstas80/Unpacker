# Changelog

All notable changes to this project are documented here.

## 1.1.1 - 2026-06-28

- Fixed InstallShield UTF-16 setup files that append extra data after the file table.

## 1.1.0 - 2026-06-27

- Added Microsoft Cabinet `.cab` extraction through `cabinet.dll`.
- Added InstallShield Cabinet `.hdr` / `data*.cab` extraction.
- Added `--list`, `--test`, `--quiet`, `--verbose`, `--log`, and `--recursive`.
- Extended `--list` and `--test` to MSI, `ISSetupStream`, and InstallShield overlay payloads.
- Added recursive extraction for supported nested packages.
- Added detailed extraction logs.

## 1.0.0 - 2026-06-23

- Added command-line help and version output.
- Added extraction support for supported `ISSetupStream` and InstallShield overlay payloads.
- Added safe output path handling to keep extracted files inside the target directory.
- Added Apache 2.0 project license.
- Added third-party notices for vendored and derived code.
- Added GitHub-ready README documentation.
