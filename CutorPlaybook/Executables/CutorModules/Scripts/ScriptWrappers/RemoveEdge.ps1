#Requires -Version 5.0

<#
	.SYNOPSIS
	Uninstalls or reinstalls Microsoft Edge and its related components. Made by @he3als.

	.Description
	Uninstalls or reinstalls Microsoft Edge and its related components in a non-forceful manner, based upon switches or user choices in a TUI.

	.PARAMETER UninstallEdge
	Uninstalls Edge, leaving the Edge user data.

	.PARAMETER InstallEdge
	Installs Edge, leaving the previous Edge user data.

	.PARAMETER InstallWebView
	Installs Edge WebView2 using the Evergreen installer.

	.PARAMETER RemoveEdgeData
	Removes all Edge user data. Compatible with -InstallEdge.

	.PARAMETER KeepAppX
	Doesn't check for and remove the AppX, in case you want to use alternative AppX removal methods. Doesn't work with UninstallEdge.

	.PARAMETER NonInteractive
	When combined with other parameters, this does not prompt the user for anything.

	.LINK
	https://github.com/he3als/EdgeRemover
#>

param (
    [switch]$UninstallEdge,
    [switch]$InstallEdge,
    [switch]$InstallWebView,
    [switch]$RemoveEdgeData,
    [switch]$KeepAppX,
    [switch]$NonInteractive
)

$version = '1.9.5'

$ProgressPreference = 'SilentlyContinue'
$sys32 = [Environment]::GetFolderPath('System')
$windir = [Environment]::GetFolderPath('Windows')
$env:path = "$windir;$sys32;$sys32\Wbem;$sys32\WindowsPowerShell\v1.0;" + $env:path
$baseKey = 'HKLM:\SOFTWARE' + $(if ([Environment]::Is64BitOperatingSystem) { '\WOW6432Node' }) + '\Microsoft'
$msedgeExe = "$([Environment]::GetFolderPath('ProgramFilesx86'))\Microsoft\Edge\Application\msedge.exe"
$edgeUWP = "$windir\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"

if ($NonInteractive -and (!$UninstallEdge -and !$InstallEdge -and !$InstallWebView)) {
    $NonInteractive = $false
}
if ($InstallEdge -and $UninstallEdge) {
    throw "You can't use both -InstallEdge and -UninstallEdge as arguments."
}

function Pause ($message = 'Press Enter to exit') {
    if (!$NonInteractive) { $null = Read-Host $message }
}

enum LogLevel {
    Success
    Info
    Warning
    Error
    Critical
}
function Write-Status {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Text,
        [LogLevel]$Level = 'Info',
        [switch]$Exit,
        [string]$ExitString = 'Press Enter to exit',
        [int]$ExitCode = 1
    )

    $colour = @(
        'Green',
        'White',
        'Yellow',
        'Red',
        'Red'
    )[$([LogLevel].GetEnumValues().IndexOf($Level))]

    $Text -split "`n" | ForEach-Object {
        Write-Host "[$($Level.ToString().ToUpper())] $_" -ForegroundColor $colour
    }

    if ($Exit) {
        Write-Output ''
        Pause $ExitString
        exit $ExitCode
    }
}

function InternetCheck {
    try {
        Invoke-WebRequest -Uri 'https://www.microsoft.com/robots.txt' -Method GET -TimeoutSec 10 -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Status "Failed to reach Microsoft.com via web request. You must have an internet connection to reinstall Edge and its components.`n$($_.Exception.Message)" -Level Critical -Exit -ExitCode 404
    }
}

function DeleteIfExist($Path) {
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Force -Recurse -Confirm:$false
    }
}

# True if it's installed
function EdgeInstalled {
    Test-Path $msedgeExe
}

function KillEdgeProcesses {
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($service in (Get-Service -Name '*edge*' | Where-Object { $_.DisplayName -like '*Microsoft Edge*' }).Name) {
        Stop-Service -Name $service -Force
    }
    foreach (
        $process in
        (Get-Process | Where-Object { ($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") -or ($_.Name -like '*msedge*') }).Id
    ) {
        Stop-Process -Id $process -Force
    }
    $ErrorActionPreference = 'Continue'
}

function InstallEdgeChromium {
    InternetCheck

    $temp = mkdir (Join-Path $([System.IO.Path]::GetTempPath()) $(New-Guid))
    $msi = "$temp\edge.msi"
    $msiLog = "$temp\edgeMsi.log"

    if ([Environment]::Is64BitOperatingSystem) {
        $arm = ((Get-CimInstance -Class Win32_ComputerSystem).SystemType -match 'ARM64') -or ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64')
        $archString = ('x64', 'arm64')[$arm]
    }
    else {
        $archString = 'x86'
    }

    Write-Status 'Requesting from the Microsoft Edge Update API...'
    try {
        try {
            $edgeUpdateApi = (Invoke-WebRequest 'https://edgeupdates.microsoft.com/api/products' -UseBasicParsing).Content | ConvertFrom-Json
        }
        catch {
            Write-Status "Failed to request from EdgeUpdate API!
Error: $_" -Level Critical -Exit -ExitCode 4
        }

        $edgeItem = ($edgeUpdateApi | ? { $_.Product -eq 'Stable' }).Releases |
        Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq $archString } |
        Where-Object { $_.Artifacts.Count -ne 0 } | Select-Object -First 1

        if ($null -eq $edgeItem) {
            Write-Status 'Failed to parse EdgeUpdate API! No matching artifacts found.' -Level Critical -Exit
        }

        $hashAlg = $edgeItem.Artifacts.HashAlgorithm | % { if ([string]::IsNullOrEmpty($_)) { 'SHA256' } else { $_ } }
        foreach ($var in @{
                link     = $edgeItem.Artifacts.Location
                hash     = $edgeItem.Artifacts.Hash
                version  = $edgeItem.ProductVersion
                sizeInMb = [math]::round($edgeItem.Artifacts.SizeInBytes / 1Mb)
                released = Get-Date $edgeItem.PublishedTime
            }.GetEnumerator()) {
            $val = $var.Value | Select-Object -First 1
            if ($val.Length -le 0) {
                Set-Variable -Name $var.Key -Value 'Undefined'
                if ($var.Key -eq 'link') { throw 'Failed to parse download link!' }
            }
            else {
                Set-Variable -Name $var.Key -Value $val
            }
        }
    }
    catch {
        Write-Status "Failed to parse Microsoft Edge from `"$link`"!
Error: $_" -Level Critical -Exit -ExitCode 5
    }
    Write-Status 'Parsed Microsoft Edge Update API!' -Level Success

    Write-Host "`nDownloading Microsoft Edge:" -ForegroundColor Cyan
    @(
        @('Released on: ', $released),
        @('Version: ', "$version (Stable)"),
        @('Size: ', "$sizeInMb Mb")
    ) | Foreach-Object {
        Write-Host ' - ' -NoNewline -ForegroundColor Magenta
        Write-Host $_[0] -NoNewline -ForegroundColor Yellow
        Write-Host $_[1]
    }

    Write-Output ''
    try {
        if ($null -eq (Get-Command curl.exe -EA 0)) {
            Write-Status "Couldn't find cURL, using Invoke-WebRequest, which is slower..." -Level Warning
            Invoke-WebRequest -Uri $link -Output $msi -UseBasicParsing
        }
        else {
            curl.exe -#L "$link" -o "$msi"
        }
    }
    catch {
        Write-Status "Failed to download Microsoft Edge from `"$link`"!
Error: $_" -Level Critical -Exit -ExitCode 6
    }
    Write-Output ''

    if ($hash -eq 'Undefined') {
        Write-Status "Not verifying hash as it's undefined, download might have failed." -Level Warning
    }
    else {
        Write-Status 'Verifying download by checking its hash...'
        if ((Get-FileHash -LiteralPath $msi -Algorithm $hashAlg).Hash -eq $hash) {
            Write-Status 'Verified the Microsoft Edge installer!' -Level Success
        }
        else {
            Write-Status 'Edge installer hash does not match. The installer might be corrupted. Continuing anyways...' -Level Error
        }
    }

    Write-Status 'Installing Microsoft Edge...'
    Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$msi`" /l `"$msiLog`" /quiet" -Wait
    
    Write-Status 'Repairing Microsoft Edge...'
    Start-Process -FilePath 'msiexec.exe' -ArgumentList "/fa `"$msi`" /l `"$msiLog`" /quiet" -Wait

    if (!(Test-Path $msiLog)) {
        Write-Status "Couldn't find installer log at `"$msiLog`"! This likely means it failed." -Level Critical -Exit -ExitCode 7
    }

    Write-Status -Text "Installer log path: `"$msiLog`""
    if ($null -eq ($(Get-Content $msiLog) -like '*Product: Microsoft Edge -- * completed successfully.*')) {
        Write-Status "Can't find success string from Edge install log - it seems like the install was a failure." -Level Error -Exit -ExitCode 8
    }

    Write-Status -Text 'Installed Microsoft Edge!' -Level Success
}

function InstallWebView {
    InternetCheck

    $dlPath = "$((Join-Path $([System.IO.Path]::GetTempPath()) $(New-Guid)))-webview2.exe"
    $link = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'

    Write-Status 'Downloading Edge WebView...'
    try {
        if ($null -eq (Get-Command curl.exe -EA 0)) {
            Write-Status "Couldn't find cURL, using Invoke-WebRequest, which is slower..." -Level Warning
            Invoke-WebRequest -Uri $link -Output $dlPath -UseBasicParsing
        }
        else {
            curl.exe -Ls "$link" -o "$dlPath"
        }
    }
    catch {
        Write-Status "Failed to download Edge WebView from `"$link`"!
Error: $_" -Level Critical -Exit -ExitCode 9
    }

    Write-Status 'Installing Edge WebView...'
    Start-Process -FilePath "$dlPath" -ArgumentList '/silent /install' -Wait

    Write-Status 'Installed Edge WebView!' -Level Success
}

# SYSTEM check - using SYSTEM previously caused issues
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
    Write-Status "This script can't be ran as TrustedInstaller/SYSTEM.
Please relaunch this script under a regular admin account." -Level Critical -Exit
}
else {
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        if ($PSBoundParameters.Count -le 0 -and !$args) {
            Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs
            exit
        }
        else {
            throw 'This script must be run as an administrator.'
        }
    }
}

$edgeInstalled = EdgeInstalled
if (!$UninstallEdge -and !$InstallEdge -and !$InstallWebView) {
    $host.UI.RawUI.WindowTitle = "Cutor EdgeRemover"

    $RemoveEdgeData = $false
    while (!$continue) {
        Clear-Host
        $description = "This script removes or installs Microsoft Edge."
        Write-Host "$description`n" -ForegroundColor Blue
        Write-Host @"
To select an option, type its number.
To perform an action, also type its number.
"@ -ForegroundColor Yellow

        Write-Host "`nEdge is currently detected as: " -NoNewline -ForegroundColor Green
        Write-Host "$(@("Uninstalled", "Installed")[$edgeInstalled])" -ForegroundColor Cyan

        Write-Host "`n$("-" * $description.Length)" -ForegroundColor Magenta

        Write-Host "`nActions:"
        Write-Host @"
[1] Uninstall Edge
[2] Install Edge
[3] Install WebView
[4] Install both Edge & WebView
"@ -ForegroundColor Cyan

        $userInput = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

        switch ($userInput.VirtualKeyCode) {
            49 {
                # uninstall Edge (1)
                $UninstallEdge = $true
                $continue = $true
            }
            50 {
                # reinstall Edge (2)
                $InstallEdge = $true
                $continue = $true
            }
            51 {
                # reinstall WebView (3)
                $InstallWebView = $true
                $continue = $true
            }
            52 {
                # reinstall both (4)
                $InstallWebView = $true
                $InstallEdge = $true
                $continue = $true
            }
        }
    }

    Clear-Host
}

# Project originally made by ShadowWhisperer and is licensed under CC0-1.0 License
# https://github.com/ShadowWhisperer/Remove-MS-Edge
if ($UninstallEdge) {
    Write-Status "Uninstalling Edge Chromium..."
    try {
        # Asegurarse de que Edge no esté en ejecución
        KillEdgeProcesses

        $pf86    = ${env:ProgramFiles(x86)}
        $pf64    = ${env:ProgramFiles}
        $edgeBase = Join-Path $pf86 'Microsoft\Edge\Application'

        if (-not (Test-Path $edgeBase)) {
            Write-Status "Could not find Edge installation folder at: $edgeBase" -Level Warning
        }
        else {
            # Buscar el setup.exe de la versión más alta instalada
            $installer = Get-ChildItem -Path $edgeBase -Directory -ErrorAction SilentlyContinue |
                         Sort-Object Name -Descending |
                         ForEach-Object {
                             $candidate = Join-Path $_.FullName 'Installer\setup.exe'
                             if (Test-Path $candidate) { $candidate }
                         } | Select-Object -First 1

            if ($null -eq $installer -or -not (Test-Path $installer)) {
                Write-Status "Could not find Edge setup.exe under $edgeBase" -Level Error
            }
            else {
                Write-Status "Running official Edge uninstaller..."
                Start-Process -FilePath $installer `
                    -ArgumentList '--uninstall --system-level --force-uninstall --verbose-logging' `
                    -Wait
                Write-Status "Edge uninstall command finished (check for any errors above)." -Level Success
            }
        }

        # Intentar limpiar carpetas típicas que quedan (best-effort)
        $pathsToRemove = @(
            "$pf86\Microsoft\Edge",
            "$pf86\Microsoft\EdgeUpdate",
            "$pf86\Microsoft\EdgeCore",
            "$pf64\Microsoft\Edge",
            "$pf64\Microsoft\EdgeUpdate",
            "$env:LOCALAPPDATA\Microsoft\Edge",
            "$env:LOCALAPPDATA\Microsoft\EdgeUpdate",
            "$env:PROGRAMDATA\Microsoft\Edge"
        )

        foreach ($p in $pathsToRemove) {
            DeleteIfExist $p
        }

        # Quitar accesos directos de Edge

        # Escritorio público
        DeleteIfExist "$env:PUBLIC\Desktop\Microsoft Edge.lnk"

        # Escritorio del usuario actual
        DeleteIfExist "$([Environment]::GetFolderPath('Desktop'))\Microsoft Edge.lnk"

        # Menú Inicio común (ProgramData)
        DeleteIfExist "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"

        # Menú Inicio del usuario actual (por si también está ahí)
        DeleteIfExist (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Microsoft Edge.lnk')

        # Intentar quitar el Edge UWP antiguo si existe (en muchas builds ya no está)
        try {
            Get-AppxPackage -AllUsers Microsoft.MicrosoftEdge -ErrorAction SilentlyContinue |
                Remove-AppxPackage -ErrorAction SilentlyContinue
        }
        catch {
            # Ignorar errores; en sistemas nuevos este paquete ya no existe
        }

        Write-Output "Finished attempting to remove Microsoft Edge."
    }
    catch {
        Write-Warning "An error occurred while uninstalling Edge: $_"
        return $false
    }
    Write-Output ""
}

