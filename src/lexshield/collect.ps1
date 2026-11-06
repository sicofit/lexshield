# LexShield collector. Read-only by design: it reads settings, changes nothing,
# records no file names and opens no network connection of its own. In a domain,
# Windows may ask the domain controller to resolve account names, and folders
# redirected to a server are read over the network.
# tests/test_readonly.py enforces this from the syntax tree: every command, method,
# type and program must be on an allowlist. Output: one JSON object on stdout.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

$errors = New-Object 'System.Collections.Generic.List[string]'

function Get-Safe {
    param([string]$Name, [scriptblock]$Block)
    try { & $Block }
    catch {
        $errors.Add($Name + ': ' + $_.Exception.Message)
        $null
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# Programs are called by their full path: a whoami.exe earlier in PATH, such as the one of
# Git for Windows, would otherwise answer instead of Windows.
function Get-PowerSetting {
    param([string]$SubGroup, [string]$Setting)
    $values = @()
    # /qh is /query including hidden settings such as CONSOLELOCK; both only read.
    $lines = @(& "$env:SystemRoot\System32\powercfg.exe" /qh SCHEME_CURRENT $SubGroup $Setting)
    if ($LASTEXITCODE -ne 0) { throw "powercfg $Setting`: Code $LASTEXITCODE" }
    foreach ($line in $lines) {
        if ($line -match ':\s*0x([0-9a-fA-F]{8})\s*$') { $values += [Convert]::ToInt64($Matches[1], 16) }
    }
    if ($values.Count -lt 2) { return $null }
    # The last two values are the current AC and DC settings.
    return @{ ac = $values[$values.Count - 2]; dc = $values[$values.Count - 1] }
}

function Test-ModernStandby {
    # powercfg /a lists the available sleep states, then a blank line, then the unavailable ones.
    $lines = @(& "$env:SystemRoot\System32\powercfg.exe" /a)
    if ($LASTEXITCODE -ne 0) { throw "powercfg /a: Code $LASTEXITCODE" }
    foreach ($line in $lines) {
        if (-not $line.Trim()) { return $false }
        if ($line -match '\bS0\b') { return $true }
    }
    return $false
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# The person at the device. Started under a separate administrator account, the collector
# would otherwise read that account's settings and folders instead of theirs.
$sessionUser = Get-Safe 'session' { [string](Get-CimInstance -ClassName Win32_ComputerSystem).UserName }
$otherUser = [bool]$sessionUser -and ($sessionUser -ne $identity.Name)
$sessionSid = $identity.User.Value
$userHive = 'HKCU:'
if ($otherUser) {
    $sessionSid = Get-Safe 'session' {
        (New-Object Security.Principal.NTAccount($sessionUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $userHive = $null
    if ($sessionSid) { $userHive = 'Registry::HKEY_USERS\' + $sessionSid }
}

$os = Get-Safe 'os' {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    @{
        product_name    = Get-RegValue $cv 'ProductName'
        edition_id      = Get-RegValue $cv 'EditionID'
        display_version = Get-RegValue $cv 'DisplayVersion'
        build           = [int](Get-RegValue $cv 'CurrentBuild')
        ubr             = Get-RegValue $cv 'UBR'
    }
}

$antivirus = Get-Safe 'antivirus' {
    $products = @()
    foreach ($p in @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct)) {
        # An uninstalled product can leave its entry behind; its program file is then gone.
        $exe = [Environment]::ExpandEnvironmentVariables([string]$p.pathToSignedReportingExe)
        $present = $null
        if ($exe -match '^[A-Za-z]:\\') { $present = Test-Path -LiteralPath $exe }
        $products += @{ name = [string]$p.displayName; product_state = [int64]$p.productState; exe_present = $present }
    }
    @{ products = $products }
}

$defender = Get-Safe 'defender' {
    $m = Get-MpComputerStatus
    @{
        service_enabled    = [bool]$m.AMServiceEnabled
        realtime           = [bool]$m.RealTimeProtectionEnabled
        signature_age_days = [int]$m.AntivirusSignatureAge
    }
}

$firewall = Get-Safe 'firewall' {
    $profiles = @{}
    $inbound = @{}
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
        $profiles[[string]$p.Name] = [string]$p.Enabled
        $inbound[[string]$p.Name] = [string]$p.DefaultInboundAction
    }
    $products = @()
    foreach ($f in @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName FirewallProduct -ErrorAction SilentlyContinue)) {
        $products += @{ name = [string]$f.displayName; product_state = [int64]$f.productState }
    }
    @{ profiles = $profiles; inbound = $inbound; products = $products }
}

$bitlocker = Get-Safe 'bitlocker' {
    $shell = New-Object -ComObject Shell.Application
    $drives = @()
    foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
        $drive = [string]$disk.DeviceID
        $entry = @{
            drive             = $drive
            system            = ($drive -eq $env:SystemDrive)
            shell_value       = $shell.NameSpace($drive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
            protection_status = $null
            volume_status     = $null
        }
        if ($elevated) {
            $volume = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
            if ($null -ne $volume) {
                $entry['protection_status'] = [string]$volume.ProtectionStatus
                $entry['volume_status'] = [string]$volume.VolumeStatus
            }
        }
        $drives += $entry
    }
    @{ drives = $drives }
}

$updates = Get-Safe 'updates' {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $total = $searcher.GetTotalHistoryCount()
    $history = @()
    if ($total -gt 0) {
        foreach ($h in @($searcher.QueryHistory(0, [Math]::Min($total, 300)))) {
            if ($h.ResultCode -eq 2 -and $h.Title -match 'KB(\d{6,7})') {
                $history += @{ date = $h.Date.ToString('yyyy-MM-dd'); kb = 'KB' + $Matches[1]; title = [string]$h.Title }
            }
        }
    }
    $latestHotfix = $null
    try {
        $latest = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($null -ne $latest) { $latestHotfix = $latest.InstalledOn.ToString('yyyy-MM-dd') }
    } catch { $errors.Add('hotfix: ' + $_.Exception.Message) }
    @{ history = $history; latest_hotfix = $latestHotfix }
}

# whoami describes this process; it answers for the person at the device only when they started it.
$currentUserAdmin = $null
if (-not $otherUser) {
    $currentUserAdmin = Get-Safe 'whoami' {
        $groups = (@(& "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh)) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "Code $LASTEXITCODE" }
        $groups.Contains('S-1-5-32-544')
    }
}

$accounts = Get-Safe 'accounts' {
    $users = @{}
    foreach ($u in @(Get-LocalUser)) { $users[$u.SID.Value] = $u }
    $groupClasses = @('Group', 'Gruppe', 'Groupe', 'Gruppo')  # ObjectClass is in the language of Windows
    $found = @()
    $members = $null
    try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544') }
    catch { $errors.Add('localgroup: ' + $_.Exception.Message) }
    if ($null -ne $members) {
        foreach ($m in $members) {
            $found += @{ name = [string]$m.Name; sid = [string]$m.SID.Value; group = ([string]$m.ObjectClass -in $groupClasses); source = [string]$m.PrincipalSource }
        }
    } else {
        # Get-LocalGroupMember fails on some Entra-joined devices; ADSI still lists the members.
        $groupName = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]('WinNT://./' + $groupName + ',group')
        foreach ($member in @($group.Invoke('Members'))) {
            $type = $member.GetType()
            $path = [string]$type.InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
            $class = [string]$type.InvokeMember('Class', 'GetProperty', $null, $member, $null)
            $sidBytes = $type.InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
            $sid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $found += @{ name = $path.Replace('WinNT://', '').Replace('/', '\'); sid = $sid; group = ($class -eq 'Group'); source = 'ADSI' }
        }
    }
    $admins = @()
    foreach ($a in $found) {
        $enabled = $null
        if ($users.ContainsKey($a.sid)) { $enabled = [bool]$users[$a.sid].Enabled }
        $admins += @{ name = $a.name; sid = $a.sid; group = $a.group; source = $a.source; enabled = $enabled; is_current_user = ($a.sid -eq $sessionSid) }
    }
    $currentAdmin = $currentUserAdmin
    if ($otherUser) {
        # Only direct membership is visible here; a group in between leaves the answer open.
        if (@($admins | Where-Object { $_.is_current_user }).Count -gt 0) { $currentAdmin = $true }
        elseif (@($admins | Where-Object { $_.group }).Count -eq 0) { $currentAdmin = $false }
    }
    $builtinAdmin = $null
    $guest = $null
    foreach ($sid in $users.Keys) {
        if ($sid -like '*-500') { $builtinAdmin = [bool]$users[$sid].Enabled }
        if ($sid -like '*-501') { $guest = [bool]$users[$sid].Enabled }
    }
    @{ admins = $admins; builtin_admin_enabled = $builtinAdmin; guest_enabled = $guest; current_user_admin = $currentAdmin }
}

$system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uac = @{
    enable_lua           = Get-RegValue $system 'EnableLUA'
    consent_prompt_admin = Get-RegValue $system 'ConsentPromptBehaviorAdmin'
}

$smb1 = Get-Safe 'smb1' {
    $server = $null
    try { $server = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
    catch { $errors.Add('smbserver: ' + $_.Exception.Message) }
    $clientKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    @{
        server_enabled        = $server
        server_registry       = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
        client_driver_present = (Test-Path -LiteralPath $clientKey)
        client_driver_start   = Get-RegValue $clientKey 'Start'
    }
}

$terminal = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$terminalPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$rdp = @{
    deny_connections        = Get-RegValue $terminal 'fDenyTSConnections'
    policy_deny_connections = Get-RegValue $terminalPolicy 'fDenyTSConnections'
    nla                     = Get-RegValue ($terminal + '\WinStations\RDP-Tcp') 'UserAuthentication'
    policy_nla              = Get-RegValue $terminalPolicy 'UserAuthentication'
}

$lock = Get-Safe 'lock' {
    $result = @{ policy_inactivity_s = Get-RegValue $system 'InactivityTimeoutSecs'; screensaver = $null; screensaver_policy = $null; delay_lock_s = $null }
    if ($userHive) {
        foreach ($entry in @(
                @{ key = 'screensaver'; path = $userHive + '\Control Panel\Desktop' },
                @{ key = 'screensaver_policy'; path = $userHive + '\Software\Policies\Microsoft\Windows\Control Panel\Desktop' })) {
            $result[$entry.key] = @{
                exe_set   = [bool](Get-RegValue $entry.path 'SCRNSAVE.EXE')
                active    = Get-RegValue $entry.path 'ScreenSaveActive'
                secure    = Get-RegValue $entry.path 'ScreenSaverIsSecure'
                timeout_s = Get-RegValue $entry.path 'ScreenSaveTimeOut'
            }
        }
        # Modern Standby: how long after the screen turns off Windows asks for the sign-in.
        $result['delay_lock_s'] = Get-RegValue ($userHive + '\Control Panel\Desktop') 'DelayLockInterval'
    } else { $errors.Add('lock: Einstellungen des angemeldeten Kontos nicht lesbar') }
    foreach ($setting in @(
            @{ key = 'sleep_s'; group = 'SUB_SLEEP'; name = 'STANDBYIDLE' },
            @{ key = 'screen_off_s'; group = 'SUB_VIDEO'; name = 'VIDEOIDLE' },
            @{ key = 'wake_lock'; group = 'SUB_NONE'; name = 'CONSOLELOCK' })) {
        try { $result[$setting.key] = Get-PowerSetting $setting.group $setting.name }
        catch { $errors.Add('powercfg: ' + $_.Exception.Message) }
    }
    try { $result['modern_standby'] = Test-ModernStandby }
    catch { $errors.Add('powercfg: ' + $_.Exception.Message) }
    $result
}

$office = Get-Safe 'office' {
    $c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $releaseIds = Get-RegValue $c2rKey 'ProductReleaseIds'
    $c2r = @()
    if ($releaseIds) { foreach ($id in ([string]$releaseIds).Split(',')) { if ($id.Trim()) { $c2r += $id.Trim() } } }
    $installed = @()
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $name = [string]$key.GetValue('DisplayName')
            if ($name -match '^Microsoft (Office|365) ' -and $key.GetValue('SystemComponent') -ne 1) { $installed += $name }
        }
    }
    $macros = $null
    if ($userHive) {
        $macros = @{}
        foreach ($app in @('Word', 'Excel', 'PowerPoint')) {
            $user = $userHive + '\Software\Microsoft\Office\16.0\' + $app + '\Security'
            $policy = $userHive + '\Software\Policies\Microsoft\Office\16.0\' + $app + '\Security'
            $macros[$app] = @{
                vba_warnings          = Get-RegValue $user 'VBAWarnings'
                policy_vba_warnings   = Get-RegValue $policy 'VBAWarnings'
                policy_block_internet = Get-RegValue $policy 'blockcontentexecutionfrominternet'
            }
        }
    } else { $errors.Add('office: Makroeinstellungen des angemeldeten Kontos nicht lesbar') }
    @{
        c2r_products    = $c2r
        updates_enabled = Get-RegValue $c2rKey 'UpdatesEnabled'
        version         = Get-RegValue $c2rKey 'VersionToReport'
        installed       = $installed
        macros          = $macros
    }
}

$removableRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
$removable = @{
    deny_all                     = Get-RegValue $removableRoot 'Deny_All'
    deny_write_disks             = Get-RegValue ($removableRoot + '\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}') 'Deny_Write'
    bitlocker_required_for_write = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' 'RDVDenyWriteAccess'
}

$network = @{
    llmnr_policy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
}

# Counts only. File names in a law firm often contain client names, so none are recorded.
$localDocs = Get-Safe 'local_docs' {
    if (-not $userHive) { throw 'Ordner des angemeldeten Kontos nicht lesbar' }
    $extensions = @('.pdf', '.doc', '.docx', '.msg', '.eml', '.odt', '.rtf')
    $cutoff = (Get-Date).AddDays(-30)
    $shellFolders = $userHive + '\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    $folders = [ordered]@{
        desktop   = Get-RegValue $shellFolders 'Desktop'
        downloads = Get-RegValue $shellFolders '{374DE290-123F-4565-9164-39C4925E467B}'
    }
    $result = @{}
    foreach ($label in @($folders.Keys)) {
        $path = $folders[$label]
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { $result[$label] = $null; continue }
        $total = 0
        $old = 0
        foreach ($f in @(Get-ChildItem -LiteralPath $path -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue)) {
            if ($extensions -contains $f.Extension.ToLowerInvariant()) {
                $total++
                if ($f.LastWriteTime -lt $cutoff) { $old++ }
            }
        }
        $result[$label] = @{ documents = $total; older_than_30_days = $old }
    }
    $result
}

$hostFacts = @{ name = $env:COMPUTERNAME; elevated = $elevated; other_user = $otherUser }
if ($otherUser) { $hostFacts['session_user'] = $sessionUser }

$facts = [ordered]@{
    schema             = 1
    collected_at       = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:sszzz")
    host               = $hostFacts
    os                 = $os
    antivirus          = $antivirus
    defender           = $defender
    firewall           = $firewall
    bitlocker          = $bitlocker
    updates            = $updates
    accounts           = $accounts
    uac                = $uac
    smb1               = $smb1
    rdp                = $rdp
    lock               = $lock
    secure_boot        = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    secure_boot_ca2023 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' 'UEFICA2023Status'
    office             = $office
    removable          = $removable
    network            = $network
    local_docs         = $localDocs
    collector_errors   = @($errors)
}

Write-Output ($facts | ConvertTo-Json -Depth 8 -Compress)
