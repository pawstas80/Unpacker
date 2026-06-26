# Unpacker

Unpacker is a small Windows command-line tool for extracting files from supported InstallShield setup executables.

Current version: `1.0.0`

## Download

Download the latest package from [GitHub Releases](https://github.com/pawstas80/Unpacker/releases).

## Supported Formats

- `ISSetupStream`
- InstallShield overlay tables:
  - counted UTF-16 tables
  - legacy ANSI tables used by older setup files

## Build

Requirements: Windows and .NET Framework 4.7.2.

```powershell
git clone https://github.com/pawstas80/Unpacker.git
cd Unpacker
dotnet build .\Unpacker.sln -c Release
```

## Usage

```powershell
.\Unpacker\bin\Release\Unpacker.exe <setup.exe> [output-directory]
.\Unpacker\bin\Release\Unpacker.exe --help
.\Unpacker\bin\Release\Unpacker.exe --version
```

If `output-directory` is not provided, files are extracted next to the input file.

## License

Copyright 2026 pawstas80.

Licensed under the [Apache License 2.0](LICENSE).

Third-party notices are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
