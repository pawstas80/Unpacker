# Unpacker

Unpacker is a small Windows command-line tool for extracting files from supported installer packages.

Current version: `1.1.1`

## Download

Download the latest package from [GitHub Releases](https://github.com/pawstas80/Unpacker/releases).

## Supported Formats

- `ISSetupStream`
- Windows Installer `.msi` packages
- Microsoft Cabinet `.cab` packages
- InstallShield Cabinet `.hdr` / `.cab` packages
- InstallShield overlay tables:
  - counted UTF-16 tables
  - legacy ANSI tables used by older setup files
  - encrypted InstallShield archives with M1024/zlib payloads

## Build

Requirements: Windows and .NET Framework 4.7.2.

```powershell
git clone https://github.com/pawstas80/Unpacker.git
cd Unpacker
dotnet build .\Unpacker.sln -c Release
```

## Release Package

```powershell
.\scripts\build-release.ps1
```

The script creates `artifacts\Unpacker-v1.1.1-win-x64.zip` with the exe and project documents.

## Usage

```powershell
.\Unpacker\bin\Release\Unpacker.exe [options] <setup.exe|package.msi|archive.cab|data1.hdr> [output-directory]
.\Unpacker\bin\Release\Unpacker.exe --help
.\Unpacker\bin\Release\Unpacker.exe --version
```

If `output-directory` is not provided, files are extracted next to the input file.
Extraction writes a detailed `Unpacker.log` file to the output directory by default.

Common options:

- `--list` - list supported package contents without extracting
- `--test` - test supported package extraction without keeping files
- `--recursive` - extract supported packages found inside the output
- `--max-depth <n>` - recursion depth, default `3`
- `--quiet` - keep console output minimal
- `--verbose` - print every processed file
- `--log <file>` / `--no-log` - customize or disable logging

For MSI packages, `--test` uses a temporary administrative extraction and removes the temporary files when it finishes.

## License

Copyright 2026 pawstas80.

Licensed under the [Apache License 2.0](LICENSE).

Third-party notices are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
