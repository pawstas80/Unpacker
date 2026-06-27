[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$RuntimeLabel = "win-x64",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$solution = Join-Path $root "Unpacker.sln"
$assemblyInfo = Join-Path $root "Unpacker\Properties\AssemblyInfo.cs"
$assemblyText = Get-Content -Path $assemblyInfo -Raw
$versionMatch = [regex]::Match($assemblyText, 'AssemblyInformationalVersion\("([^"]+)"\)')

if (-not $versionMatch.Success) {
    throw "Cannot read AssemblyInformationalVersion from $assemblyInfo"
}

$version = $versionMatch.Groups[1].Value
$outputDirectory = Join-Path $root "Unpacker\bin\$Configuration"
$artifactsDirectory = Join-Path $root "artifacts"
$packageName = "Unpacker-v$version-$RuntimeLabel"
$stagingDirectory = Join-Path $artifactsDirectory $packageName
$zipPath = Join-Path $artifactsDirectory "$packageName.zip"

if (-not $SkipBuild) {
    dotnet build $solution -c $Configuration /p:PlatformTarget=x64
}

if (Test-Path $stagingDirectory) {
    Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
}

New-Item -ItemType Directory -Path $stagingDirectory | Out-Null

$releaseFiles = @(
    (Join-Path $outputDirectory "Unpacker.exe"),
    (Join-Path $outputDirectory "Unpacker.exe.config")
)

foreach ($file in $releaseFiles) {
    if (Test-Path $file) {
        Copy-Item -LiteralPath $file -Destination $stagingDirectory
    }
}

$docs = @(
    "README.md",
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
    "CHANGELOG.md"
)

foreach ($doc in $docs) {
    Copy-Item -LiteralPath (Join-Path $root $doc) -Destination $stagingDirectory
}

if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $stagingDirectory "*") -DestinationPath $zipPath -Force
Write-Host "Created: $zipPath"
