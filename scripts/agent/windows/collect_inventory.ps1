[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$StateDirectory = "$env:ProgramData\ThreatIntelligencePlatform\agent"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


# ============================================================
# Agent metadata
# ============================================================

$SchemaVersion = "inventory/v1"
$AgentName = "tip-windows-agent"
$AgentVersion = "0.2.0"

$UninstallPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


# ============================================================
# Helpers
# ============================================================

function ConvertTo-NullableString {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text
}


function Read-MachineUid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $rawValue = (
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    ).Trim()

    $machineUid = [Guid]::Empty

    $isValid = [Guid]::TryParse(
        $rawValue,
        [ref]$machineUid
    )

    if (-not $isValid) {
        throw (
            "Invalid machine UID stored in '$Path'. " +
            "The file must contain a valid UUID."
        )
    }

    if ($machineUid -eq [Guid]::Empty) {
        throw (
            "Invalid machine UID stored in '$Path': " +
            "nil UUID is not allowed."
        )
    }

    return $machineUid
}


function Get-OrCreateMachineUid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    New-Item `
        -ItemType Directory `
        -Path $Directory `
        -Force `
        -ErrorAction Stop |
        Out-Null

    $machineUidPath = Join-Path `
        -Path $Directory `
        -ChildPath "machine_uid"

    $existingMachineUid = Read-MachineUid `
        -Path $machineUidPath

    if ($null -ne $existingMachineUid) {
        return $existingMachineUid
    }

    $newMachineUid = [Guid]::NewGuid()

    $encoding = New-Object `
        -TypeName System.Text.UTF8Encoding `
        -ArgumentList $false

    $stream = $null

    try {
        $stream = [System.IO.File]::Open(
            $machineUidPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        $bytes = $encoding.GetBytes(
            $newMachineUid.ToString()
        )

        $stream.Write(
            $bytes,
            0,
            $bytes.Length
        )

        $stream.Flush()

        return $newMachineUid
    }
    catch [System.IO.IOException] {
        # Cas rare : deux collectes démarrent en même temps
        # lors du tout premier lancement.
        $existingMachineUid = Read-MachineUid `
            -Path $machineUidPath

        if ($null -eq $existingMachineUid) {
            throw
        }

        return $existingMachineUid
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}


function Get-NativeArchitecture {
    $architecture = $env:PROCESSOR_ARCHITEW6432

    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }

    if ([string]::IsNullOrWhiteSpace($architecture)) {
        return "unknown"
    }

    $normalizedArchitecture = (
        $architecture.Trim().ToUpperInvariant()
    )

    switch ($normalizedArchitecture) {
        "AMD64" {
            return "x86_64"
        }

        "X86" {
            return "x86"
        }

        "ARM64" {
            return "arm64"
        }

        "ARM" {
            return "arm"
        }

        default {
            return (
                $architecture.Trim().ToLowerInvariant()
            )
        }
    }
}


# ============================================================
# Windows machine observation
# ============================================================

function Get-WindowsObservation {
    if ([Environment]::Is64BitOperatingSystem) {
        $registryView = (
            [Microsoft.Win32.RegistryView]::Registry64
        )
    }
    else {
        $registryView = (
            [Microsoft.Win32.RegistryView]::Registry32
        )
    }

    $baseKey = (
        [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            $registryView
        )
    )

    try {
        $currentVersionKey = $baseKey.OpenSubKey(
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            $false
        )

        if ($null -eq $currentVersionKey) {
            throw (
                "Unable to read Windows version information " +
                "from the registry."
            )
        }

        try {
            $productName = ConvertTo-NullableString `
                -Value (
                    $currentVersionKey.GetValue(
                        "ProductName",
                        $null
                    )
                )

            $displayVersion = ConvertTo-NullableString `
                -Value (
                    $currentVersionKey.GetValue(
                        "DisplayVersion",
                        $null
                    )
                )

            $currentBuild = ConvertTo-NullableString `
                -Value (
                    $currentVersionKey.GetValue(
                        "CurrentBuildNumber",
                        $null
                    )
                )

            $ubr = ConvertTo-NullableString `
                -Value (
                    $currentVersionKey.GetValue(
                        "UBR",
                        $null
                    )
                )
        }
        finally {
            $currentVersionKey.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }

    if ($null -eq $productName) {
        $productName = "Microsoft Windows"
    }

    if (
        ($null -ne $displayVersion) -and
        ($null -ne $currentBuild)
    ) {
        if ($null -ne $ubr) {
            $osVersion = (
                "$displayVersion (build $currentBuild.$ubr)"
            )
        }
        else {
            $osVersion = (
                "$displayVersion (build $currentBuild)"
            )
        }
    }
    elseif ($null -ne $currentBuild) {
        $osVersion = $currentBuild
    }
    else {
        $osVersion = (
            [Environment]::OSVersion.Version.ToString()
        )
    }

    return [PSCustomObject][ordered]@{
        hostname = [Environment]::MachineName
        os_name = $productName
        os_version = $osVersion
        architecture = Get-NativeArchitecture
    }
}


# ============================================================
# Registry sources
# ============================================================

function Get-RegistrySources {
    $sources = @()

    if ([Environment]::Is64BitOperatingSystem) {
        $sources += [PSCustomObject]@{
            Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            View = [Microsoft.Win32.RegistryView]::Registry64
            ExternalPrefix = "HKLM64"
        }

        $sources += [PSCustomObject]@{
            Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            View = [Microsoft.Win32.RegistryView]::Registry32
            ExternalPrefix = "HKLM32"
        }

        $sources += [PSCustomObject]@{
            Hive = [Microsoft.Win32.RegistryHive]::CurrentUser
            View = [Microsoft.Win32.RegistryView]::Registry64
            ExternalPrefix = "HKCU64"
        }

        $sources += [PSCustomObject]@{
            Hive = [Microsoft.Win32.RegistryHive]::CurrentUser
            View = [Microsoft.Win32.RegistryView]::Registry32
            ExternalPrefix = "HKCU32"
        }

        return $sources
    }

    $sources += [PSCustomObject]@{
        Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
        View = [Microsoft.Win32.RegistryView]::Registry32
        ExternalPrefix = "HKLM32"
    }

    $sources += [PSCustomObject]@{
        Hive = [Microsoft.Win32.RegistryHive]::CurrentUser
        View = [Microsoft.Win32.RegistryView]::Registry32
        ExternalPrefix = "HKCU32"
    }

    return $sources
}


# ============================================================
# Installed Windows applications
# ============================================================

function Get-InstalledApplicationComponents {
    $components = @()

    $sources = Get-RegistrySources

    foreach ($source in $sources) {
        $baseKey = (
            [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                $source.Hive,
                $source.View
            )
        )

        try {
            $uninstallKey = $baseKey.OpenSubKey(
                $UninstallPath,
                $false
            )

            if ($null -eq $uninstallKey) {
                continue
            }

            try {
                $subKeyNames = @(
                    $uninstallKey.GetSubKeyNames() |
                        Sort-Object
                )

                foreach ($subKeyName in $subKeyNames) {
                    $applicationKey = (
                        $uninstallKey.OpenSubKey(
                            $subKeyName,
                            $false
                        )
                    )

                    if ($null -eq $applicationKey) {
                        continue
                    }

                    try {
                        $displayName = ConvertTo-NullableString `
                            -Value (
                                $applicationKey.GetValue(
                                    "DisplayName",
                                    $null
                                )
                            )

                        if ($null -eq $displayName) {
                            continue
                        }

                        $systemComponent = (
                            ConvertTo-NullableString `
                                -Value (
                                    $applicationKey.GetValue(
                                        "SystemComponent",
                                        $null
                                    )
                                )
                        )

                        if ($systemComponent -eq "1") {
                            continue
                        }

                        $displayVersion = (
                            ConvertTo-NullableString `
                                -Value (
                                    $applicationKey.GetValue(
                                        "DisplayVersion",
                                        $null
                                    )
                                )
                        )

                        $publisher = (
                            ConvertTo-NullableString `
                                -Value (
                                    $applicationKey.GetValue(
                                        "Publisher",
                                        $null
                                    )
                                )
                        )

                        $externalId = (
                            $source.ExternalPrefix +
                            "\" +
                            $UninstallPath +
                            "\" +
                            $subKeyName
                        )

                        $component = (
                            [PSCustomObject][ordered]@{
                                component_type = "application"
                                name = $displayName
                                version = $displayVersion
                                vendor = $publisher
                                external_id = $externalId
                                detected_by = "windows_registry_uninstall"
                            }
                        )

                        $components += $component
                    }
                    finally {
                        $applicationKey.Dispose()
                    }
                }
            }
            finally {
                $uninstallKey.Dispose()
            }
        }
        finally {
            $baseKey.Dispose()
        }
    }

    return $components
}

# ============================================================
# Global Python packages
# ============================================================

function Get-GlobalPythonPackageComponents {
    $components = @()

    # Prefer the regular Python executable. If it is not available,
    # fall back to the Windows Python launcher.
    $pythonCommand = Get-Command `
        -Name "python.exe" `
        -ErrorAction SilentlyContinue

    $usePythonLauncher = $false

    if ($null -eq $pythonCommand) {
        $pythonCommand = Get-Command `
            -Name "py.exe" `
            -ErrorAction SilentlyContinue

        if ($null -ne $pythonCommand) {
            $usePythonLauncher = $true
        }
    }

    if ($null -eq $pythonCommand) {
        return $components
    }

    try {
        if ($usePythonLauncher) {
            $rawOutput = & $pythonCommand.Source `
                -3 `
                -m pip `
                list `
                --format=json `
                2>$null
        }
        else {
            $rawOutput = & $pythonCommand.Source `
                -m pip `
                list `
                --format=json `
                2>$null
        }

        if ($LASTEXITCODE -ne 0) {
            return $components
        }

        $jsonText = (
            $rawOutput |
                Out-String
        ).Trim()

        if (
            [string]::IsNullOrWhiteSpace(
                $jsonText
            )
        ) {
            return $components
        }

        $packages = @(
            $jsonText |
                ConvertFrom-Json
        )

        foreach (
            $package
            in (
                $packages |
                    Sort-Object -Property name
            )
        ) {
            $name = ConvertTo-NullableString `
                -Value $package.name

            $version = ConvertTo-NullableString `
                -Value $package.version

            if (
                ($null -eq $name) -or
                ($null -eq $version)
            ) {
                continue
            }

            $components += (
                [PSCustomObject][ordered]@{
                    component_type = "package"
                    ecosystem = "pypi"
                    package_name = $name
                    version = $version
                    scope = "global"
                    detected_by = "pip_global"
                }
            )
        }
    }
    catch {
        # La collecte pip est optionnelle.
        # Une erreur ne doit jamais interrompre
        # l'inventaire Windows principal.
        return $components
    }

    return $components
}


# ============================================================
# Global npm packages
# ============================================================

function Get-GlobalNpmPackageComponents {
    $components = @()

    # npm.cmd avoids PowerShell execution-policy issues that can
    # occur with npm.ps1 on some Windows installations.
    $npmCommand = Get-Command `
        -Name "npm.cmd" `
        -ErrorAction SilentlyContinue

    if ($null -eq $npmCommand) {
        $npmCommand = Get-Command `
            -Name "npm" `
            -ErrorAction SilentlyContinue
    }

    if ($null -eq $npmCommand) {
        return $components
    }

    try {
        $rawOutput = & $npmCommand.Source `
            list `
            --global `
            --depth=0 `
            --json `
            2>$null

        $jsonText = (
            $rawOutput |
                Out-String
        ).Trim()

        if (
            [string]::IsNullOrWhiteSpace(
                $jsonText
            )
        ) {
            return $components
        }

        $parsed = (
            $jsonText |
                ConvertFrom-Json
        )

        if ($null -eq $parsed.dependencies) {
            return $components
        }

        $properties = @(
            $parsed.dependencies.PSObject.Properties |
                Sort-Object -Property Name
        )

        foreach ($property in $properties) {
            $name = ConvertTo-NullableString `
                -Value $property.Name

            $version = ConvertTo-NullableString `
                -Value $property.Value.version

            if (
                ($null -eq $name) -or
                ($null -eq $version)
            ) {
                continue
            }

            $components += (
                [PSCustomObject][ordered]@{
                    component_type = "package"
                    ecosystem = "npm"
                    package_name = $name
                    version = $version
                    scope = "global"
                    detected_by = "npm_global"
                }
            )
        }
    }
    catch {
        # La collecte npm est optionnelle.
        # Une erreur ne doit jamais interrompre
        # l'inventaire Windows principal.
        return $components
    }

    return $components
}


# ============================================================
# JSON output
# ============================================================

function Write-Utf8WithoutBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $parentDirectory = Split-Path `
        -Parent $Path

    if (
        -not [string]::IsNullOrWhiteSpace(
            $parentDirectory
        )
    ) {
        New-Item `
            -ItemType Directory `
            -Path $parentDirectory `
            -Force `
            -ErrorAction Stop |
            Out-Null
    }

    $encoding = New-Object `
        -TypeName System.Text.UTF8Encoding `
        -ArgumentList $false

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        $encoding
    )
}


# ============================================================
# Collection
# ============================================================

$machineUid = Get-OrCreateMachineUid `
    -Directory $StateDirectory

$machineObservation = Get-WindowsObservation

$components = @(
    Get-InstalledApplicationComponents
    Get-GlobalPythonPackageComponents
    Get-GlobalNpmPackageComponents
)

$inventory = [ordered]@{
    schema_version = $SchemaVersion

    inventory_id = [Guid]::NewGuid().ToString()

    collected_at = (
        [DateTimeOffset]::UtcNow.ToString("o")
    )

    agent = [ordered]@{
        name = $AgentName
        version = $AgentVersion
    }

    machine = [ordered]@{
        machine_uid = $machineUid.ToString()
        hostname = $machineObservation.hostname
        os_name = $machineObservation.os_name
        os_version = $machineObservation.os_version
        architecture = $machineObservation.architecture
    }

    components = $components
}

$json = $inventory |
    ConvertTo-Json -Depth 8


if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-Output $json
}
else {
    Write-Utf8WithoutBom `
        -Path $OutputPath `
        -Content $json
}