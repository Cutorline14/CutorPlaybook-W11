if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
}

$windir = [Environment]::GetFolderPath('Windows')
& "$windir\CutorModules\initPowerShell.ps1"
$cutorDesktop = "$windir\CutorDesktop"
$cutorModules = "$windir\CutorModules"

$title = 'Preparing Cutor user settings...'

if (!(Test-Path $cutorDesktop) -or !(Test-Path $cutorModules)) {
    Write-Host "Cutor was about to configure user settings, but its files weren't found. :(" -ForegroundColor Red
    Read-Pause
    exit 1
}

$Host.UI.RawUI.WindowTitle = $title
Write-Host $title -ForegroundColor Yellow
Write-Host $('-' * ($title.length + 3)) -ForegroundColor Yellow
Write-Host "You'll be logged out in 10 to 20 seconds, and once you login again, your new account will be ready for use."

# Disable Windows 11 context menu & 'Gallery' in File Explorer
if ([System.Environment]::OSVersion.Version.Build -ge 22000) {
    & "$cutorDesktop\4. Interface Tweaks\Context Menus\Windows 11\Old Context Menu (default).cmd" /silent
    & "$cutorDesktop\4. Interface Tweaks\File Explorer Customization\Gallery\Disable Gallery (default).cmd" /silent

    # Set ThemeMRU (recent themes)
    Set-Theme -Path "$([Environment]::GetFolderPath('Windows'))\Resources\Themes\cutor-dark.theme"
    Set-ThemeMRU | Out-Null
}

# Set lockscreen wallpaper
Set-LockscreenImage

# Disable 'Network' in navigation pane
& "$cutorDesktop\3. General Configuration\File Sharing\Network Navigation Pane\Disable Network Navigation Pane (default).cmd" /silent

# Disable Automatic Folder Discovery
& "$cutorDesktop\4. Interface Tweaks\File Explorer Customization\Automatic Folder Discovery\Disable Automatic Folder Discovery (default).cmd" /silent

# Set visual effects
& "$cutorDesktop\4. Interface Tweaks\Visual Effects (Animations)\Cutor Visual Effects (default).cmd" /silent

# Set taskbar pins 
$valueName = "Browser"
$value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Cutor\SetupOptions" -Name $valueName -ErrorAction Stop
$Browser = $value.$valueName
$Browser

& "$cutorModules\Scripts\taskbarPins.ps1" $Browser
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1

# Leave
Start-Sleep 5 
logoff