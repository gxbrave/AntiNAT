[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)

$ErrorActionPreference = 'Stop'
$InstallerVersion = '1'
$InstallerSchemaVersion = 3
$ExitGeneric = 1
$ExitUsage = 2
$ExitToken = 3
$ExitArtifact = 4
$ExitConflict = 5
$ExitRollback = 6
$ExitPurge = 7
$ExitMigration = 8
$script:TokenTemp = ''
$script:TokenSource = ''
$script:TokenSourceIdentity = ''
$script:SchemaExistedBeforeInstall = $false
$script:SchemaBackup = ''

function Initialize-NativeFileApi {
    if ('AntiNAT.NativeFile' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AntiNAT {
    public sealed class TokenReadHandle : IDisposable {
        public FileStream Stream { get; private set; }
        public string Identity { get; private set; }
        internal TokenReadHandle(SafeFileHandle handle, string identity) {
            Stream = new FileStream(handle, FileAccess.Read, 4096, false);
            Identity = identity;
        }
        public void Dispose() {
            if (Stream != null) { Stream.Dispose(); Stream = null; }
        }
    }

    public static class NativeFile {
        private const uint GenericRead = 0x80000000;
        private const uint Delete = 0x00010000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint BackupSemantics = 0x02000000;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const int FileDispositionInfo = 4;

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInfo { public byte DeleteFile; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string name, uint access, uint share, IntPtr security, uint creation,
            uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle handle, int informationClass, ref FileDispositionInfo information, uint size);

        private static SafeFileHandle Open(string path, uint access) {
            var handle = CreateFile(path, access, ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics, IntPtr.Zero);
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        private static string ReadIdentity(SafeFileHandle handle, out ByHandleFileInformation information, bool allowDirectory) {
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            bool directory = (information.FileAttributes & FileAttributeDirectory) != 0;
            if ((!allowDirectory && directory) || (information.FileAttributes & FileAttributeReparsePoint) != 0 ||
                (!directory && information.NumberOfLinks != 1)) {
                throw new IOException("file is not a regular non-reparse file");
            }
            ulong index = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
            return information.VolumeSerialNumber.ToString("X8") + ":" + index.ToString("X16");
        }

        public static TokenReadHandle OpenRead(string path) {
            var handle = Open(path, GenericRead);
            try {
                ByHandleFileInformation information;
                string identity = ReadIdentity(handle, out information, false);
                return new TokenReadHandle(handle, identity);
            } catch {
                handle.Dispose();
                throw;
            }
        }

        public static void DeleteExact(string path, string expectedIdentity) {
            var handle = Open(path, Delete | FileReadAttributes);
            try {
                ByHandleFileInformation information;
                string identity = ReadIdentity(handle, out information, true);
                if (!String.IsNullOrEmpty(expectedIdentity) && !String.Equals(identity, expectedIdentity, StringComparison.Ordinal)) {
                    throw new IOException("file identity changed before deletion");
                }
                var disposition = new FileDispositionInfo { DeleteFile = 1 };
                if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, (uint)Marshal.SizeOf(typeof(FileDispositionInfo)))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally { handle.Dispose(); }
        }
    }
}
'@
}

function Fail([int] $Code, [string] $Message) {
    [Console]::Error.WriteLine("antinat installer: $Message")
    exit $Code
}

function Validate-Text([string] $Value) {
    if ($null -ne $Value -and $Value.IndexOf([char]0) -ge 0) { Fail $ExitUsage 'value contains a control character' }
    if ($null -ne $Value) { foreach ($character in $Value.ToCharArray()) { if ([char]::IsControl($character)) { Fail $ExitUsage 'value contains a control character' } } }
    if ($null -ne $Value -and ($Value.Contains("`r") -or $Value.Contains("`n") -or $Value.Contains([char]0))) {
        Fail $ExitUsage 'value contains a control character'
    }
}

function Validate-Endpoint([string] $Value) {
    if ([string]::IsNullOrEmpty($Value)) { Fail $ExitUsage 'controller endpoint is required' }
    if ($Value -notmatch '^https://[^\s/?#]+(?::[0-9]+)?(?:/[^\s?#]*)?$' -and
        $Value -notmatch '^http://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]+)?(?:/[^\s?#]*)?$') {
        Fail $ExitUsage 'controller endpoint must use HTTPS; HTTP is limited to local test endpoints'
    }
    if ($Value -match '^http://' -and $env:ANTINAT_TEST_MODE -ne '1') {
        Fail $ExitUsage 'remote controller endpoint must use HTTPS'
    }
    if ($Value -match '@') { Fail $ExitUsage 'controller endpoint must not contain URL userinfo' }
}

function Parse-Arguments([string[]] $InputArguments) {
    if ($InputArguments.Count -eq 0) { Fail $ExitUsage 'a command is required' }
    $script:Command = $InputArguments[0]
    if ($script:Command -notin @('install', 'uninstall', 'purge', 'upgrade')) {
        if ($script:Command -eq '--help' -and $InputArguments.Count -eq 1) { Write-Output 'Usage: install.ps1 {install|uninstall|purge|upgrade} [flags]'; exit 0 }
        if ($script:Command -eq '--version' -and $InputArguments.Count -eq 1) { Write-Output "antinat-installer $InstallerVersion"; exit 0 }
        Fail $ExitUsage 'unknown command'
    }
    $script:Endpoint = ''
    $script:BindInterface = ''
    $script:LogLevel = ''
    $script:AutoUpdate = ''
    $script:GitHubProxy = ''
    $script:DetectionScheduler = ''
    $script:Platform = 'windows'
    $script:TokenFile = ''
    $script:TokenFD = -1
    $script:TokenSource = ''
    $script:ServiceName = 'AntiNATAgent'
    $script:ControllerServiceName = 'AntiNATController'
    $script:Role = if ($env:ANTINAT_ROLE) { $env:ANTINAT_ROLE } else { 'agent' }
    $script:InstallDirOverride = ''
    $script:HelpRequested = $false
    $script:VersionRequested = $false
    for ($i = 1; $i -lt $InputArguments.Count; $i++) {
        $raw = $InputArguments[$i]
        $name = $raw
        $value = $null
        if ($raw.Contains('=')) {
            $split = $raw.IndexOf('=')
            $name = $raw.Substring(0, $split)
            $value = $raw.Substring($split + 1)
        }
        if ($name -in @('--token', '--token-value', '-t') -or $name.StartsWith('--token-') -and $name -notin @('--token-file', '--token-fd')) {
            Fail $ExitUsage 'literal token arguments are forbidden'
        }
        if ($name -in @('--help', '--version')) {
            if ($null -ne $value) { Fail $ExitUsage "$name does not take a value" }
            if ($name -eq '--help') { $script:HelpRequested = $true } else { $script:VersionRequested = $true }
            continue
        }
        if ($name -notin @('--controller-endpoint', '--bind-interface', '--install-dir', '--service-name', '--log-level', '--auto-update', '--github-proxy', '--detection-scheduler', '--platform', '--token-fd', '--token-file')) {
            Fail $ExitUsage 'unknown installer flag'
        }
        if ($null -eq $value) {
            if ($i + 1 -ge $InputArguments.Count -or $InputArguments[$i + 1].StartsWith('-')) { Fail $ExitUsage "$name requires a value" }
            $i++
            $value = $InputArguments[$i]
        }
        if ([string]::IsNullOrEmpty($value)) { Fail $ExitUsage "$name requires a non-empty value" }
        Validate-Text $value
        switch ($name) {
            '--controller-endpoint' { $script:Endpoint = $value }
            '--bind-interface' { $script:BindInterface = $value }
            '--platform' { if ($value -ne 'windows') { Fail $ExitUsage 'Windows installer requires --platform windows' } }
            '--token-file' { $script:TokenFile = $value }
            '--token-fd' {
                $parsedFD = 0
                if (-not [int]::TryParse($value, [ref]$parsedFD) -or $parsedFD -lt 3) { Fail $ExitToken 'token fd must be an open descriptor >= 3' }
                $script:TokenFD = $parsedFD
            }
            '--service-name' { if ($value -ne 'antinat-agent.service' -and $value -ne 'AntiNATAgent') { Fail $ExitUsage 'service name is frozen' }; $script:ServiceName = 'AntiNATAgent' }
            '--install-dir' { $script:InstallDirOverride = $value }
            '--log-level' { $script:LogLevel = $value }
            '--auto-update' { $script:AutoUpdate = $value }
            '--github-proxy' { $script:GitHubProxy = $value }
            '--detection-scheduler' { $script:DetectionScheduler = $value }
        }
    }
    if ($script:HelpRequested -and $script:VersionRequested) { Fail $ExitUsage 'help and version are mutually exclusive' }
    if ($script:TokenFD -ge 0 -and $script:TokenFile -ne '') { Fail $ExitToken 'token fd and token file are mutually exclusive' }
    if (($script:HelpRequested -or $script:VersionRequested) -and ($script:TokenFD -ge 0 -or $script:TokenFile)) { Fail $ExitUsage 'metadata requests cannot select a token input' }
    if ($script:HelpRequested) { Write-Output 'Usage: install.ps1 {install|uninstall|purge|upgrade} [flags]'; exit 0 }
    if ($script:VersionRequested) { Write-Output "antinat-installer $InstallerVersion"; exit 0 }
    if ($script:Role -notin @('agent', 'controller', 'both')) { Fail $ExitUsage 'ANTINAT_ROLE must be agent, controller, or both' }
    if ($script:Command -eq 'install' -and $script:Role -in @('agent', 'both') -and [string]::IsNullOrEmpty($script:Endpoint) -and $env:ANTINAT_TEST_MODE -ne '1') { Fail $ExitUsage 'controller endpoint is required' }
    if ($script:Command -eq 'install' -and $script:InstallDirOverride -ne '' -and $script:InstallDirOverride -ne $script:InstallDir) { Fail $ExitUsage 'install directory is frozen' }
    if ($script:LogLevel -and $script:LogLevel -notin @('debug', 'info', 'warn', 'error')) { Fail $ExitUsage 'unsupported log level' }
    if ($script:AutoUpdate -and $script:AutoUpdate -notin @('disabled', 'manual', 'stable', 'enabled')) { Fail $ExitUsage 'unsupported auto-update policy' }
    if ($script:DetectionScheduler -and $script:DetectionScheduler -notin @('sequential', 'parallel')) { Fail $ExitUsage 'unsupported detection scheduler' }
    if ($script:GitHubProxy -and ($script:GitHubProxy -match '@' -or $script:GitHubProxy -notmatch '^https://[^\s/?#]+(?:/[^\s?#]*)?$')) { Fail $ExitUsage 'GitHub proxy must use HTTPS without URL userinfo' }
}

function Set-Paths {
    $prefix = if ($env:ANTINAT_TEST_ROOT) { $env:ANTINAT_TEST_ROOT.TrimEnd('\', '/') } else { '' }
    function P([string] $Path) {
        if (-not $prefix) { return $Path }
        $full = [IO.Path]::GetFullPath($Path)
        $drive = [IO.Path]::GetPathRoot($full)
        $relative = $full.Substring($drive.Length).TrimStart('\', '/')
        return Join-Path $prefix $relative
    }
    $script:InstallDir = P "$env:ProgramFiles\AntiNAT"
    $script:BinDir = P "$env:ProgramFiles\AntiNAT\bin"
    $script:Agent = P "$env:ProgramFiles\AntiNAT\bin\antinat-agent.exe"
    $script:Controller = P "$env:ProgramFiles\AntiNAT\bin\antinat-controller.exe"
    $script:Hook = P "$env:ProgramFiles\AntiNAT\bin\antinat-hook-runner.exe"
    $script:DataDir = P "$env:ProgramData\AntiNAT"
    $script:Config = P "$env:ProgramData\AntiNAT\agent.conf"
    $script:ServiceDir = P "$env:ProgramData\AntiNAT\services"
    $script:Manifest = P "$env:ProgramData\AntiNAT\ownership-manifest.json"
    $script:OwnershipKey = P "$env:ProgramData\AntiNAT\ownership.key"
    $script:BackupDir = P "$env:ProgramData\AntiNAT\backups"
    $script:SchemaVersion = P "$env:ProgramData\AntiNAT\schema.version"
}

function Assert-NoReparsePath([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $probe = $full
    while ($true) {
        $item = $null
        try {
            $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        } catch {
            if ($_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and
                $_.Exception -isnot [IO.FileNotFoundException] -and
                $_.Exception -isnot [IO.DirectoryNotFoundException]) { throw }
        }
        if ($null -ne $item) {
            if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'path contains a reparse point' }
        }
        $parent = Split-Path -LiteralPath $probe -Parent
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
}

function Get-ExistingItem([string] $Path) {
    try {
        return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException] -or
            $_.Exception -is [IO.FileNotFoundException] -or
            $_.Exception -is [IO.DirectoryNotFoundException]) { return $null }
        throw
    }
}

function Get-SidString($Identity) {
    try {
        if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
        return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Get-TrustedSids {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return @($current, 'S-1-5-32-544', 'S-1-5-18')
}

function Set-PrivateAcl([string] $Path, [bool] $Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $admin = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-544')
    $system = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    foreach ($sid in @($current, $admin, $system)) {
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-StrictFileAcl([string] $Path, [bool] $RequireCurrentOwner) {
    Assert-NoReparsePath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'file is not a regular non-reparse file' }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'file ACL inheritance must be disabled' }
    $trusted = Get-TrustedSids
    $owner = Get-SidString $acl.Owner
    if ($RequireCurrentOwner -and $owner -ne $trusted[0]) { throw 'file owner is not the current user' }
    if (-not $RequireCurrentOwner -and $owner -notin $trusted) { throw 'file owner is not trusted' }
    $hasCurrent = $false
    foreach ($rule in @($acl.Access)) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'file ACL is not a strict allow list' }
        $sid = Get-SidString $rule.IdentityReference
        if ($sid -notin $trusted) { throw 'file ACL grants an untrusted principal' }
        if ($sid -eq $trusted[0]) { $hasCurrent = $true }
    }
    if ($RequireCurrentOwner -and -not $hasCurrent) { throw 'file ACL does not grant the current user access' }
}

function Test-StrictDirectoryAcl([string] $Path) {
    Assert-NoReparsePath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'artifact path is not a regular non-reparse directory' }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'directory ACL inheritance must be disabled' }
    $trusted = Get-TrustedSids
    if ((Get-SidString $acl.Owner) -notin $trusted) { throw 'directory owner is not trusted' }
    foreach ($rule in @($acl.Access)) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'directory ACL is not a strict allow list' }
        if ((Get-SidString $rule.IdentityReference) -notin $trusted) { throw 'directory ACL grants an untrusted principal' }
    }
}

function Set-SystemOnlyAcl([string] $Path, [bool] $Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $system = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    $acl.SetOwner($system)
    $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($system, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-SystemOnlyAcl([string] $Path) {
    Assert-NoReparsePath $Path
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected -or (Get-SidString $acl.Owner) -ne 'S-1-5-18') { throw 'token file ACL is not SYSTEM-owned and protected' }
    foreach ($rule in @($acl.Access)) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or (Get-SidString $rule.IdentityReference) -ne 'S-1-5-18') { throw 'token file ACL grants a principal other than SYSTEM' }
    }
}

function Write-PrivateBytes([string] $Path, [byte[]] $Bytes) {
    $parent = Split-Path -LiteralPath $Path -Parent
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Assert-NoReparsePath $parent
    Assert-NoReparsePath $Path
    $temporary = Join-Path $parent ('.antinat-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        Set-PrivateAcl $temporary $false
        Move-Item -LiteralPath $temporary -Destination $Path -Force
        Set-PrivateAcl $Path $false
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Write-SystemToken([string] $Path, [byte[]] $Bytes) {
    $parent = Split-Path -LiteralPath $Path -Parent
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Assert-NoReparsePath $parent
    Assert-NoReparsePath $Path
    $temporary = Join-Path $parent ('.antinat-token.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        Set-SystemOnlyAcl $temporary $false
        Move-Item -LiteralPath $temporary -Destination $Path -Force
        Set-SystemOnlyAcl $Path $false
        Assert-SystemOnlyAcl $Path
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Write-SchemaVersion {
    $existing = Get-ExistingItem $SchemaVersion
    if ($null -ne $existing) {
        Assert-NoReparsePath $SchemaVersion
        if ($existing.PSIsContainer) { throw 'schema version marker is unsafe' }
    }
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    Write-PrivateBytes $SchemaVersion $encoding.GetBytes("$InstallerSchemaVersion`n")
}

function Backup-SchemaForInstall {
    $script:SchemaExistedBeforeInstall = $false
    $script:SchemaBackup = ''
    $existing = Get-ExistingItem $SchemaVersion
    if ($null -eq $existing) { return }
    $script:SchemaExistedBeforeInstall = $true
    Assert-NoReparsePath $SchemaVersion
    if ($existing.PSIsContainer) { throw 'schema version marker is unsafe' }
    $backup = Join-Path $DataDir ('.schema-rollback.' + [Guid]::NewGuid().ToString('N'))
    try {
        Copy-FileAtomic $SchemaVersion $backup
        Set-PrivateAcl $backup $false
        $script:SchemaBackup = $backup
    } catch {
        try { if ($null -ne (Get-ExistingItem $backup)) { Remove-ExactPath $backup } } catch { }
        throw
    }
}

function Cleanup-SchemaBackup {
    $backup = $script:SchemaBackup
    $script:SchemaBackup = ''
    $script:SchemaExistedBeforeInstall = $false
    if ($backup) {
        try {
            if ($null -ne (Get-ExistingItem $backup)) { Assert-NoReparsePath $backup; Remove-ExactPath $backup }
        } catch { }
    }
}

function Restore-SchemaAfterInstall {
    if ($script:SchemaExistedBeforeInstall) {
        # A failed backup means the marker was never changed; leave it intact.
        if (-not $script:SchemaBackup) { return }
        Copy-FileAtomic $script:SchemaBackup $SchemaVersion
        Set-PrivateAcl $SchemaVersion $false
        return
    }
    if ($null -ne (Get-ExistingItem $SchemaVersion)) { Remove-Owned $DataDir 'schema.version' }
}

function Validate-UpgradeVersion {
    $item = Get-ExistingItem $SchemaVersion
    $previous = $InstallerSchemaVersion - 1
    if ($null -ne $item) {
        Assert-NoReparsePath $SchemaVersion
        if ($item.PSIsContainer -or $item.Length -gt 64) { Fail $ExitMigration 'schema version marker is unsafe' }
        $raw = [IO.File]::ReadAllText($SchemaVersion)
        $parsed = 0L
        if ($raw -notmatch '^(?<version>[1-9][0-9]*)(?:\r?\n)?$' -or
            -not [long]::TryParse($Matches.version, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed) -or
            $parsed -lt 1) {
            Fail $ExitMigration 'schema version marker is invalid'
        }
        $previous = $parsed
    }
    if ($previous -gt $InstallerSchemaVersion -or $InstallerSchemaVersion - $previous -gt 1) {
        Fail $ExitMigration "schema upgrade from $previous to $InstallerSchemaVersion is not N/N-1 compatible"
    }
}

function Invoke-ReleaseDownload([string] $Uri, [string] $OutFile) {
    $parameters = @{ UseBasicParsing = $true; Uri = $Uri; OutFile = $OutFile }
    if ($GitHubProxy) {
        $parameters.Proxy = $GitHubProxy
        $parameters.ProxyUseDefaultCredentials = $false
    }
    Invoke-WebRequest @parameters
}

function Get-ReleaseDirectory {
    if ($env:ANTINAT_ARTIFACT_DIR) {
        $script:ArtifactDir = $env:ANTINAT_ARTIFACT_DIR
        $script:ManifestFile = if ($env:ANTINAT_MANIFEST_FILE) { $env:ANTINAT_MANIFEST_FILE } else { Join-Path $ArtifactDir 'manifest.json' }
        $script:SignatureFile = if ($env:ANTINAT_SIGNATURE_FILE) { $env:ANTINAT_SIGNATURE_FILE } else { Join-Path $ArtifactDir 'manifest.sig' }
        return
    }
    $base = if ($env:ANTINAT_RELEASE_BASE_URL) { $env:ANTINAT_RELEASE_BASE_URL } else { 'https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta' }
    if ($base -match '@' -or $base -notmatch '^https://[^\s/?#]+(?:/[^\s?#]*)?$') { Fail $ExitArtifact 'release base URL must use HTTPS without URL userinfo' }
    $script:ArtifactDir = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $ArtifactDir | Out-Null
    try { Set-PrivateAcl $ArtifactDir $true } catch { Fail $ExitArtifact 'could not protect the release artifact directory' }
    $script:ManifestFile = Join-Path $ArtifactDir 'manifest.json'
    $script:SignatureFile = Join-Path $ArtifactDir 'manifest.sig'
    try {
        Invoke-ReleaseDownload "$base/manifest.json" $ManifestFile
        Invoke-ReleaseDownload "$base/manifest.sig" $SignatureFile
        $manifest = Get-Content -Raw -LiteralPath $ManifestFile | ConvertFrom-Json
        $seen = @{}
        foreach ($property in @($manifest.artifacts.psobject.Properties)) {
            $name = [string]$property.Name
            if ($name -notmatch '^[A-Za-z0-9._/-]+$' -or $name.StartsWith('/') -or $name.Contains('//') -or $name -match '(^|/)\.\.?(?:/|$)') { Fail $ExitArtifact 'release manifest has an unsafe artifact name' }
            $leaf = [IO.Path]::GetFileName($name.Replace('/', '\'))
            if ([string]::IsNullOrEmpty($leaf) -or $seen.ContainsKey($leaf)) { Fail $ExitArtifact 'release manifest has colliding artifact names' }
            $seen[$leaf] = $true
            Invoke-ReleaseDownload "$base/$name" (Join-Path $ArtifactDir $leaf)
        }
    } catch { Fail $ExitArtifact 'release artifact download failed' }
}

function Verify-Release {
    $trust = if ($env:ANTINAT_TRUST_ROOT_FILE) { $env:ANTINAT_TRUST_ROOT_FILE } else { Join-Path $PSScriptRoot '..\deploy\trust\release-ed25519.pub' }
    $artifactItem = Get-ExistingItem $ArtifactDir
    if ($null -eq $artifactItem -or -not $artifactItem.PSIsContainer) { Fail $ExitArtifact 'artifact directory is unavailable' }
    try { Test-StrictDirectoryAcl $ArtifactDir } catch { Fail $ExitArtifact 'artifact directory is not a protected private directory' }
    $trustItem = Get-ExistingItem $trust
    $manifestItem = Get-ExistingItem $ManifestFile
    $signatureItem = Get-ExistingItem $SignatureFile
    if ($null -eq $trustItem -or $trustItem.PSIsContainer) { Fail $ExitArtifact 'pinned release trust root is unavailable' }
    if ($null -eq $manifestItem -or $manifestItem.PSIsContainer -or $null -eq $signatureItem -or $signatureItem.PSIsContainer) { Fail $ExitArtifact 'release manifest or detached signature is missing' }
    try {
        foreach ($path in @($trust, $ManifestFile, $SignatureFile)) { Assert-NoReparsePath $path }
    } catch { Fail $ExitArtifact 'release trust inputs contain a reparse point' }
    try { $manifest = Get-Content -Raw -LiteralPath $ManifestFile | ConvertFrom-Json } catch { Fail $ExitArtifact 'release manifest is invalid JSON' }
    if ($manifest -isnot [System.Management.Automation.PSCustomObject] -or $manifest.artifacts -isnot [System.Management.Automation.PSCustomObject]) { Fail $ExitArtifact 'release manifest must contain an object artifact map' }
    $allowed = @('schema_version', 'release', 'artifacts', 'trust_root', 'signature_algorithm')
    foreach ($property in @($manifest.psobject.Properties)) { if ($property.Name -notin $allowed) { Fail $ExitArtifact 'release manifest has an unknown field' } }
    if ([string]$manifest.schema_version -ne '1' -or ($manifest.signature_algorithm -and [string]$manifest.signature_algorithm -ne 'ed25519')) { Fail $ExitArtifact 'unsupported release manifest' }
    $expectedRoot = if ($env:ANTINAT_TRUST_ROOT_ID) { $env:ANTINAT_TRUST_ROOT_ID } else { 'release-key-2026' }
    if ([string]$manifest.trust_root -ne $expectedRoot) { Fail $ExitArtifact 'release trust root is not pinned' }
    if ($null -eq $manifest.artifacts -or @($manifest.artifacts.psobject.Properties).Count -eq 0) { Fail $ExitArtifact 'release manifest has no artifacts' }
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) { Fail $ExitArtifact 'openssl is required for detached signature verification' }
    & $openssl.Source pkeyutl -verify -pubin -inkey $trust -rawin -in $ManifestFile -sigfile $SignatureFile *> $null
    if ($LASTEXITCODE -ne 0) { Fail $ExitArtifact 'detached release manifest signature failed' }
    $seen = @{}
    foreach ($property in @($manifest.artifacts.psobject.Properties)) {
        $name = [string]$property.Name
        if ($name -notmatch '^[A-Za-z0-9._/-]+$' -or $name.StartsWith('/') -or $name.Contains('//') -or $name -match '(^|/)\.\.?(?:/|$)') { Fail $ExitArtifact 'unsafe artifact name' }
        $leaf = [IO.Path]::GetFileName($name.Replace('/', '\'))
        if ([string]::IsNullOrEmpty($leaf) -or $seen.ContainsKey($leaf)) { Fail $ExitArtifact 'artifact names collide after extraction' }
        $seen[$leaf] = $true
        if ([string]$property.Value -cnotmatch '^[0-9a-f]{64}$') { Fail $ExitArtifact 'artifact digest is not lowercase SHA-256' }
        $path = Join-Path $ArtifactDir $leaf
        $artifactItem = Get-ExistingItem $path
        if ($null -eq $artifactItem -or $artifactItem.PSIsContainer) { Fail $ExitArtifact 'artifact is missing' }
        try { Assert-NoReparsePath $path } catch { Fail $ExitArtifact 'artifact is reparse-point backed' }
        if ($artifactItem.Length -gt 512MB) { Fail $ExitArtifact 'artifact exceeds size limit' }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -cne [string]$property.Value) { Fail $ExitArtifact 'artifact digest mismatch' }
    }
    $script:ReleaseManifest = $manifest
}

function Find-Artifact([string] $Suffix) {
    $matches = @()
    $script:FoundArtifactDigest = ''
    foreach ($property in $ReleaseManifest.artifacts.psobject.Properties) {
        if ($property.Name.EndsWith($Suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $matches += [pscustomobject]@{ Leaf = [IO.Path]::GetFileName($property.Name); Digest = [string]$property.Value }
        }
    }
    if ($matches.Count -ne 1) { return $null }
    $script:FoundArtifactDigest = $matches[0].Digest
    return Join-Path $ArtifactDir $matches[0].Leaf
}

function Get-RoleArtifact([string] $BaseName) {
    $artifact = Find-Artifact ($BaseName + '.exe')
    if (-not $artifact) { $artifact = Find-Artifact $BaseName }
    return $artifact
}

function Require-ReleaseArtifacts {
    $script:AgentReleaseArtifact = $null
    $script:AgentReleaseDigest = ''
    $script:ControllerReleaseArtifact = $null
    $script:ControllerReleaseDigest = ''
    if ($Role -in @('agent', 'both')) {
        $script:AgentReleaseArtifact = Get-RoleArtifact 'antinat-agent-windows-amd64'
        $script:AgentReleaseDigest = $script:FoundArtifactDigest
        if (-not $script:AgentReleaseArtifact) { Fail $ExitArtifact 'Windows Agent artifact is missing' }
    }
    if ($Role -in @('controller', 'both')) {
        $script:ControllerReleaseArtifact = Get-RoleArtifact 'antinat-controller-windows-amd64'
        $script:ControllerReleaseDigest = $script:FoundArtifactDigest
        if (-not $script:ControllerReleaseArtifact) { Fail $ExitArtifact 'Windows Controller artifact is missing' }
    }
}

function Read-TokenBytes([byte[]] $Raw) {
    if ($null -eq $Raw -or $Raw.Length -eq 0 -or $Raw.Length -gt 4096) { throw 'token input exceeds size limit' }
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false, $true)
    try { $text = $encoding.GetString($Raw) } catch { throw 'token input is not valid UTF-8' }
    $text = $text.Trim()
    if ([string]::IsNullOrEmpty($text) -or $text.Length -gt 256) { throw 'token input is empty or too long' }
    foreach ($character in $text.ToCharArray()) {
        if ([char]::IsWhiteSpace($character) -or [char]::IsControl($character) -or [int]$character -eq 0) { throw 'token input contains whitespace or control characters' }
    }
    return $text
}

function Read-TokenStream($Stream) {
    $buffer = New-Object -TypeName byte[] -ArgumentList 4097
    $total = 0
    while ($true) {
        $count = $Stream.Read($buffer, $total, $buffer.Length - $total)
        if ($count -eq 0) { break }
        $total += $count
        if ($total -eq $buffer.Length) { throw 'token input exceeds size limit' }
    }
    $raw = New-Object -TypeName byte[] -ArgumentList $total
    if ($total -gt 0) { [Array]::Copy($buffer, $raw, $total) }
    return Read-TokenBytes $raw
}

function Get-WindowsArgument([string] $Value) {
    $builder = New-Object -TypeName System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ([int]$character -eq 92) { $slashes++; continue }
        if ([int]$character -eq 34) {
            for ($i = 0; $i -lt (2 * $slashes + 1); $i++) { [void]$builder.Append([char]92) }
            [void]$builder.Append([char]34)
        } else {
            for ($i = 0; $i -lt $slashes; $i++) { [void]$builder.Append([char]92) }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    for ($i = 0; $i -lt (2 * $slashes); $i++) { [void]$builder.Append([char]92) }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Read-Token {
    if ($env:ANTINAT_TEST_MODE -eq '1' -and $TokenFD -lt 0 -and -not $TokenFile) { return }
    try {
        if ($TokenFile) {
            Test-StrictFileAcl $TokenFile $true
            Initialize-NativeFileApi
            $opened = [AntiNAT.NativeFile]::OpenRead($TokenFile)
            try {
                $token = Read-TokenStream $opened.Stream
                $script:TokenSourceIdentity = $opened.Identity
            } finally { $opened.Dispose() }
            $script:TokenSource = $TokenFile
        } elseif ($TokenFD -ge 0) {
            # On Windows the frozen descriptor is an inherited native handle.
            # It is borrowed here and is not closed by the installer.
            $safeHandle = New-Object -TypeName Microsoft.Win32.SafeHandles.SafeFileHandle -ArgumentList @([IntPtr]$TokenFD, $false)
            $stream = New-Object -TypeName System.IO.FileStream -ArgumentList @($safeHandle, [IO.FileAccess]::Read, 4096, $false)
            try { $token = Read-TokenStream $stream } finally { $stream.Dispose(); $safeHandle.Dispose() }
        } else {
            $secure = Read-Host 'Enrollment token' -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            [void](Read-TokenBytes ((New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)).GetBytes($token)))
        }
        try {
            New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
            Set-PrivateAcl $DataDir $true
            $path = Join-Path $DataDir ('.enrollment-token.' + [Guid]::NewGuid().ToString('N'))
            $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
            Write-SystemToken $path $encoding.GetBytes($token + [Environment]::NewLine)
            $script:TokenTemp = $path
        } finally {
            $token = $null
            Clear-Variable token -ErrorAction SilentlyContinue
        }
    } catch { throw 'token input rejected' }
}

function Write-Config([string] $TokenPath) {
    $node = if ($env:ANTINAT_NODE_ID) { $env:ANTINAT_NODE_ID } else { $env:COMPUTERNAME }
    Validate-Text $node
    if ([string]::IsNullOrEmpty($node)) { $node = 'antinat-node' }
    if ($node.Length -gt 255) { Fail $ExitUsage 'node id is too long' }
    if ($env:ANTINAT_CONTROLLER_PIN -and $env:ANTINAT_CONTROLLER_PIN -notmatch '^[0-9a-f]{64}$') { Fail $ExitUsage 'controller pin must be lowercase 32-byte hex' }
    function Q([string] $Value) { return "'" + $Value.Replace("'", "'\''") + "'" }
    $contents = @("ANTINAT_ENDPOINT=$(Q $Endpoint)", "ANTINAT_NODE=$(Q $node)", "ANTINAT_STATE=$(Q $DataDir)")
    if ($env:ANTINAT_CONTROLLER_PIN) { $contents += "ANTINAT_PIN=$(Q $env:ANTINAT_CONTROLLER_PIN)" }
    if ($TokenPath) { $contents += "ANTINAT_TOKEN_FILE=$(Q $TokenPath)" }
    if ($BindInterface) { $contents += "ANTINAT_BIND_INTERFACE=$(Q $BindInterface)" }
    if ($GitHubProxy) { $contents += "ANTINAT_GITHUB_PROXY=$(Q $GitHubProxy)" }
    $effectiveLogLevel = if ($LogLevel) { $LogLevel } else { 'info' }
    $effectiveAutoUpdate = if ($AutoUpdate) { $AutoUpdate } else { 'disabled' }
    $effectiveScheduler = if ($DetectionScheduler) { $DetectionScheduler } else { 'sequential' }
    $contents += "ANTINAT_LOG_LEVEL=$(Q $effectiveLogLevel)"
    $contents += "ANTINAT_AUTO_UPDATE=$(Q $effectiveAutoUpdate)"
    $contents += "ANTINAT_DETECTION_SCHEDULER=$(Q $effectiveScheduler)"
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    Write-PrivateBytes $Config $encoding.GetBytes(($contents -join [char]10) + [char]10)
}

function Get-ServiceCommand([bool] $IncludeToken) {
    $node = if ($env:ANTINAT_NODE_ID) { $env:ANTINAT_NODE_ID } else { $env:COMPUTERNAME }
    if ([string]::IsNullOrEmpty($node)) { $node = 'antinat-node' }
    $parts = @(
        (Get-WindowsArgument $Agent), '--state', (Get-WindowsArgument $DataDir),
        '--endpoint', (Get-WindowsArgument $Endpoint), '--node', (Get-WindowsArgument $node)
    )
    if ($env:ANTINAT_CONTROLLER_PIN) { $parts += @('--pin', (Get-WindowsArgument $env:ANTINAT_CONTROLLER_PIN)) }
    if ($IncludeToken -and $script:TokenTemp) { $parts += @('--token-file', (Get-WindowsArgument $script:TokenTemp)) }
    return ($parts -join ' ')
}

function Install-Service([bool] $IncludeToken) {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Fail $ExitConflict 'service already exists' }
    # LocalSystem is retained for the protected token ACL, but the service SID
    # must be restricted so the process does not receive an unrestricted
    # service identity.
    New-Service -Name $ServiceName -BinaryPathName (Get-ServiceCommand $IncludeToken) -DisplayName 'AntiNAT Agent' -StartupType Automatic -Description 'AntiNAT forwarding agent' | Out-Null
    $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $ServiceName)
    if ($null -eq $serviceInfo -or [string]$serviceInfo.StartName -ne 'LocalSystem') {
        & sc.exe delete $ServiceName *> $null
        throw 'service must run as LocalSystem for the protected enrollment token ACL'
    }
    & sc.exe sidtype $ServiceName restricted *> $null
    if ($LASTEXITCODE -ne 0) { throw 'service SID configuration failed' }
    Start-Service -Name $ServiceName
}

function Get-ControllerServiceCommand {
    return (Get-WindowsArgument $Controller) + ' -listen 127.0.0.1:3111 -store ' + (Get-WindowsArgument (Join-Path $DataDir 'controller.db')) + ' -keydir ' + (Get-WindowsArgument (Join-Path $DataDir 'controller-keys'))
}

function Install-ControllerService {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    if (Get-Service -Name $ControllerServiceName -ErrorAction SilentlyContinue) { Fail $ExitConflict 'controller service already exists' }
    New-Service -Name $ControllerServiceName -BinaryPathName (Get-ControllerServiceCommand) -DisplayName 'AntiNAT Controller' -StartupType Automatic -Description 'AntiNAT controller' | Out-Null
    $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $ControllerServiceName)
    if ($null -eq $serviceInfo -or [string]$serviceInfo.StartName -ne 'LocalSystem') {
        & sc.exe delete $ControllerServiceName *> $null
        throw 'controller service must run as LocalSystem'
    }
    & sc.exe sidtype $ControllerServiceName restricted *> $null
    if ($LASTEXITCODE -ne 0) { throw 'controller service SID configuration failed' }
    Start-Service -Name $ControllerServiceName
}

function Install-Services([bool] $IncludeToken) {
    if ($Role -in @('controller', 'both')) { Install-ControllerService }
    if ($Role -in @('agent', 'both')) { Install-Service $IncludeToken }
}

function Update-ServiceCommand {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-ItemProperty -LiteralPath $serviceKey -Name ImagePath -Value (Get-ServiceCommand $false)
}

function Stop-Delete-Service {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    $services = @()
    if ($Role -in @('agent', 'both')) { $services += $ServiceName }
    if ($Role -in @('controller', 'both')) { $services += $ControllerServiceName }
    foreach ($name in $services) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            Stop-Service -Name $name -Force -ErrorAction Stop
            & sc.exe delete $name *> $null
            if ($LASTEXITCODE -ne 0 -and (Get-Service -Name $name -ErrorAction SilentlyContinue)) { throw "service deletion failed: $name" }
        }
    }
}

function Send-RemoteUninstallNotice([string] $Action = 'uninstall') {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    if ($Action -notin @('uninstall', 'purge')) { throw 'unsupported remote lifecycle action' }
    $operationId = [Guid]::NewGuid().ToString('N')
    if ($env:ANTINAT_UNINSTALL_NOTICE_HELPER) {
        $helper = $env:ANTINAT_UNINSTALL_NOTICE_HELPER
        Assert-NoReparsePath $helper
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $process.StartInfo.FileName = $helper
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.Arguments = '--operation-id ' + (Get-WindowsArgument $operationId) + ' --action ' + (Get-WindowsArgument $Action)
        if (-not $process.Start()) { throw 'remote uninstall helper could not start' }
        if (-not $process.WaitForExit(35000)) {
            $process.Kill()
            throw 'remote uninstall receipt timed out'
        }
        if ($process.ExitCode -ne 0) { throw 'remote uninstall receipt was not confirmed' }
        return
    }
    if ($env:ANTINAT_OFFLINE_EXPORT_FILE) {
        $export = $env:ANTINAT_OFFLINE_EXPORT_FILE
        $payload = '{"operation_id":"' + $operationId + '","status":"UNKNOWN","requested_action":"' + $Action + '","action":"operator_review_required"}' + [char]10
        $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
        Write-PrivateBytes $export $encoding.GetBytes($payload)
        Write-Warning 'offline uninstall notice exported; Controller decommission is still required'
    }
    if ($env:ANTINAT_FORCE_OFFLINE_PURGE -ne '1') { throw 'remote uninstall receipt unavailable; use an online helper or explicit offline force' }
}

function Wait-TokenConsumption {
    if (-not $script:TokenTemp) { return }
    if ($env:ANTINAT_TEST_MODE -eq '1') {
        $item = Get-ExistingItem $script:TokenTemp
        if ($null -ne $item) { Assert-NoReparsePath $script:TokenTemp; Remove-Item -LiteralPath $script:TokenTemp -Force }
        return
    }
    for ($i = 0; $i -lt 60; $i++) {
        if ($null -eq (Get-ExistingItem $script:TokenTemp)) { return }
        Start-Sleep -Seconds 1
    }
    throw 'enrollment token was not consumed by the Agent'
}

function Consume-TokenSource {
    if (-not $script:TokenSource) { return }
    Test-StrictFileAcl $script:TokenSource $true
    Initialize-NativeFileApi
    try {
        [AntiNAT.NativeFile]::DeleteExact($script:TokenSource, $script:TokenSourceIdentity)
    } catch { throw 'source token file changed before consumption' }
    if ($null -ne (Get-ExistingItem $script:TokenSource)) { throw 'source token file was not consumed' }
}

function Cleanup-TokenOnFailure {
    if ($script:TokenTemp -and $script:TokenTemp -ne $TokenFile -and $null -ne (Get-ExistingItem $script:TokenTemp)) {
        try { Assert-NoReparsePath $script:TokenTemp; Remove-Item -LiteralPath $script:TokenTemp -Force } catch { }
    }
    $script:TokenTemp = ''
}

function Remove-Owned([string] $Root, [string] $Relative) {
    $relativePath = $Relative.Replace('/', '\')
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath.Contains([char]0) -or $relativePath -match '(^|\\)\.\.?(\\|$)') { throw 'unsafe ownership path' }
    Assert-NoReparsePath $Root
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $path = [IO.Path]::GetFullPath((Join-Path $Root $relativePath))
    if (-not $path.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw 'ownership path escapes its root' }
    $item = Get-ExistingItem $path
    if ($null -eq $item) { return }
    Assert-OwnedTreeSafe $path
    Assert-NoReparsePath $path
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'refusing reparse-point purge' }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $path -Force) { Remove-Owned $path $child.Name }
    }
    Remove-ExactPath $path
}

function Assert-OwnedTreeSafe([string] $Path) {
    $item = Get-ExistingItem $Path
    if ($null -eq $item) { return }
    Assert-NoReparsePath $Path
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'refusing reparse-point purge' }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) { Assert-OwnedTreeSafe $child.FullName }
    } elseif ($item -isnot [IO.FileInfo]) {
        throw 'refusing to purge a non-regular resource'
    }
}

function Remove-ExactPath([string] $Path) {
    $item = Get-ExistingItem $Path
    if ($null -eq $item) { return }
    Assert-NoReparsePath $Path
    Initialize-NativeFileApi
    [AntiNAT.NativeFile]::DeleteExact($Path, '')
}

function Get-CompileTimeResources {
    $resources = @()
    if ($Role -in @('agent', 'both')) {
        $resources += @(
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
            [ordered]@{ root = $DataDir; path = 'state.db' },
            [ordered]@{ root = $DataDir; path = 'node.key' },
            [ordered]@{ root = $DataDir; path = 'terminal.marker' },
            [ordered]@{ root = $DataDir; path = 'agent.marker' },
            [ordered]@{ root = (Split-Path -LiteralPath $Config -Parent); path = 'agent.conf' }
        )
    }
    if ($Role -in @('controller', 'both')) {
        $resources += @(
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
            [ordered]@{ root = $DataDir; path = 'controller.db' },
            [ordered]@{ root = $DataDir; path = 'controller-keys' }
        )
    }
    $resources += @(
        [ordered]@{ root = $DataDir; path = 'schema.version' },
        [ordered]@{ root = $DataDir; path = 'backups' },
        [ordered]@{ root = $DataDir; path = 'ownership-manifest.json' },
        [ordered]@{ root = $DataDir; path = 'ownership.key' }
    )
    return $resources
}

function Get-AllCompileTimeResources {
    return @(
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
        [ordered]@{ root = $DataDir; path = 'state.db' },
        [ordered]@{ root = $DataDir; path = 'node.key' },
        [ordered]@{ root = $DataDir; path = 'controller.db' },
        [ordered]@{ root = $DataDir; path = 'controller-keys' },
        [ordered]@{ root = $DataDir; path = 'terminal.marker' },
        [ordered]@{ root = $DataDir; path = 'agent.marker' },
        [ordered]@{ root = $DataDir; path = 'schema.version' },
        [ordered]@{ root = $DataDir; path = 'backups' },
        [ordered]@{ root = $DataDir; path = 'ownership-manifest.json' },
        [ordered]@{ root = $DataDir; path = 'ownership.key' },
        [ordered]@{ root = (Split-Path -LiteralPath $Config -Parent); path = 'agent.conf' }
    )
}

function Get-OwnershipResourceRole($Resource) {
    $root = [string]$Resource.root
    $path = [string]$Resource.path
    foreach ($allowed in @(Get-AllCompileTimeResources)) {
        if ([IO.Path]::GetFullPath([string]$allowed.root) -ieq [IO.Path]::GetFullPath($root) -and [string]$allowed.path -ieq $path) {
            if ($allowed.path -in @('bin/antinat-agent.exe', 'bin/antinat-hook-runner.exe', 'state.db', 'node.key', 'terminal.marker', 'agent.marker', 'agent.conf')) { return 'agent' }
            if ($allowed.path -in @('bin/antinat-controller.exe', 'controller.db', 'controller-keys')) { return 'controller' }
            return 'shared'
        }
    }
    return 'unknown'
}

function Validate-OwnershipResource($Resource) {
    if ($null -eq $Resource -or [string]::IsNullOrEmpty([string]$Resource.root) -or [string]::IsNullOrEmpty([string]$Resource.path)) { throw 'ownership resource is incomplete' }
    $root = [IO.Path]::GetFullPath([string]$Resource.root)
    if ($root -ne [string]$Resource.root) { throw 'ownership root is not canonical' }
    $path = [string]$Resource.path
    if ($path -notmatch '^[A-Za-z0-9._/-]+$' -or $path.StartsWith('/') -or $path.Contains('//') -or $path -match '(^|/)\.\.?(?:/|$)') { throw 'ownership path is unsafe' }
    $target = [IO.Path]::GetFullPath((Join-Path $root ($path.Replace('/', '\'))))
    if (-not $target.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'ownership path escapes root' }
}

function Test-AllowedOwnershipResource($Resource) {
    foreach ($allowed in @(Get-AllCompileTimeResources)) {
        if ([IO.Path]::GetFullPath([string]$allowed.root) -ieq [IO.Path]::GetFullPath([string]$Resource.root) -and [string]$allowed.path -ieq [string]$Resource.path) { return $true }
    }
    return $false
}

function Get-OwnershipPayload($Manifest) {
    $resources = @()
    foreach ($resource in @($Manifest.resources)) {
        $resources += [ordered]@{ root = [string]$resource.root; path = [string]$resource.path }
    }
    return [ordered]@{
        schema_version = [int]$Manifest.schema_version
        installation_id = [string]$Manifest.installation_id
        resources = $resources
    }
}

function New-RandomBytes([int] $Count) {
    $bytes = New-Object -TypeName byte[] -ArgumentList $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function ConvertTo-Hex([byte[]] $Bytes) {
    return ([BitConverter]::ToString($Bytes).Replace('-', '')).ToLowerInvariant()
}

function Get-HmacHex([string] $Text, [byte[]] $Key) {
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA256 -ArgumentList (,$Key)
    try {
        $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
        return ConvertTo-Hex ($hmac.ComputeHash($encoding.GetBytes($Text)))
    } finally { $hmac.Dispose() }
}

function Test-ConstantTimeEqual([string] $Left, [string] $Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) { $difference = $difference -bor ([int][char]$Left[$i] -bxor [int][char]$Right[$i]) }
    return $difference -eq 0
}

function New-OwnershipManifest {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    Set-PrivateAcl $DataDir $true
    if ($null -eq (Get-ExistingItem $OwnershipKey)) { Write-PrivateBytes $OwnershipKey (New-RandomBytes 32) }
    Test-StrictFileAcl $OwnershipKey $false
    $key = [IO.File]::ReadAllBytes($OwnershipKey)
    if ($key.Length -lt 16) { throw 'ownership HMAC key is too short' }
    $existingManifest = Get-ExistingItem $Manifest
    $installationId = $null
    $resources = @()
    if ($null -ne $existingManifest) {
        $oldManifest = Read-OwnershipManifest
        $installationId = [string]$oldManifest.installation_id
        foreach ($resource in @($oldManifest.resources)) {
            $resources += [ordered]@{ root = [string]$resource.root; path = [string]$resource.path }
        }
    }
    if ([string]::IsNullOrEmpty($installationId)) { $installationId = ConvertTo-Hex (New-RandomBytes 16) }
    foreach ($resource in @(Get-CompileTimeResources)) {
        $duplicate = $false
        foreach ($existing in $resources) {
            if ([IO.Path]::GetFullPath([string]$existing.root) -ieq [IO.Path]::GetFullPath([string]$resource.root) -and [string]$existing.path -ieq [string]$resource.path) {
                $duplicate = $true
                break
            }
        }
        if (-not $duplicate) { $resources += $resource }
    }
    $payload = [ordered]@{
        schema_version = 1
        installation_id = $installationId
        resources = $resources
    }
    $payloadJson = [string]($payload | ConvertTo-Json -Compress -Depth 8)
    $manifest = [ordered]@{
        schema_version = 1
        installation_id = $payload.installation_id
        resources = $payload.resources
        hmac = Get-HmacHex $payloadJson $key
    }
    $manifestJson = [string]($manifest | ConvertTo-Json -Compress -Depth 8)
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    Write-PrivateBytes $Manifest $encoding.GetBytes($manifestJson + [char]10)
}

function Read-OwnershipManifest {
    if ($null -eq (Get-ExistingItem $Manifest) -or $null -eq (Get-ExistingItem $OwnershipKey)) { throw 'ownership manifest or key is missing' }
    Test-StrictFileAcl $Manifest $false
    Test-StrictFileAcl $OwnershipKey $false
    if ((Get-ExistingItem $Manifest).Length -gt 4MB) { throw 'ownership manifest exceeds size limit' }
    try { $manifest = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json } catch { throw 'ownership manifest is invalid JSON' }
    foreach ($property in @($manifest.psobject.Properties)) { if ($property.Name -notin @('schema_version', 'installation_id', 'resources', 'hmac')) { throw 'ownership manifest has an unknown field' } }
    if ([int]$manifest.schema_version -ne 1 -or [string]$manifest.installation_id -notmatch '^[0-9a-f]{32}$' -or [string]$manifest.hmac -notmatch '^[0-9a-f]{64}$') { throw 'ownership manifest fields are invalid' }
    if ($null -eq $manifest.resources) { throw 'ownership manifest has no resources' }
    $resources = @($manifest.resources)
    if ($resources.Count -eq 0) { throw 'ownership manifest has no resources' }
    foreach ($resource in $resources) { Validate-OwnershipResource $resource; if (-not (Test-AllowedOwnershipResource $resource)) { throw 'ownership manifest contains an unallowlisted resource' } }
    $key = [IO.File]::ReadAllBytes($OwnershipKey)
    $payload = Get-OwnershipPayload $manifest
    $payloadJson = [string]($payload | ConvertTo-Json -Compress -Depth 8)
    if (-not (Test-ConstantTimeEqual ([string]$manifest.hmac) (Get-HmacHex $payloadJson $key))) { throw 'ownership manifest HMAC mismatch' }
    return $manifest
}

function Remove-EmptyDirectory([string] $Path) {
    $item = Get-ExistingItem $Path
    if ($null -eq $item) { return }
    Assert-NoReparsePath $Path
    if ($item.PSIsContainer -and @(Get-ChildItem -LiteralPath $Path -Force).Count -eq 0) { Remove-ExactPath $Path }
}

function Purge-Install {
    Stop-Delete-Service
    Send-RemoteUninstallNotice 'purge'
    $manifestVerified = $false
    try {
        $manifest = Read-OwnershipManifest
        $resources = @($manifest.resources)
        $manifestVerified = $true
    } catch {
        Write-Warning 'ownership manifest unavailable or invalid; using compile-time allowlist only'
        $resources = @(Get-CompileTimeResources | Where-Object { (Get-OwnershipResourceRole $_) -ne 'shared' })
    }
    try {
        $keepOtherRole = $false
        if ($manifestVerified) {
            foreach ($resource in $resources) {
                $resourceRole = Get-OwnershipResourceRole $resource
                if (($resourceRole -eq 'agent' -and $Role -notin @('agent', 'both')) -or
                    ($resourceRole -eq 'controller' -and $Role -notin @('controller', 'both'))) { $keepOtherRole = $true }
            }
        }
        $remaining = @()
        foreach ($resource in $resources) {
            $root = [IO.Path]::GetFullPath([string]$resource.root)
            $target = [IO.Path]::GetFullPath((Join-Path $root ([string]$resource.path).Replace('/', '\')))
            Assert-OwnedTreeSafe $target
        }
        foreach ($resource in $resources) {
            $resourceRole = Get-OwnershipResourceRole $resource
            $remove = ($resourceRole -eq 'agent' -and $Role -in @('agent', 'both')) -or
                ($resourceRole -eq 'controller' -and $Role -in @('controller', 'both')) -or
                ($resourceRole -eq 'shared' -and -not $keepOtherRole)
            if ($remove -and $resourceRole -eq 'shared' -and [string]$resource.path -in @('ownership-manifest.json', 'ownership.key')) { $remove = $false }
            if ($remove) {
                Remove-Owned ([string]$resource.root) ([string]$resource.path)
            } else {
                $remaining += [ordered]@{ root = [string]$resource.root; path = [string]$resource.path }
            }
        }
        if (-not $manifestVerified -and
            $null -eq (Get-ExistingItem $Agent) -and
            $null -eq (Get-ExistingItem $Controller)) {
            Remove-Owned $DataDir 'schema.version'
        }
        if ($manifestVerified -and $keepOtherRole) {
            $key = [IO.File]::ReadAllBytes($OwnershipKey)
            $payload = [ordered]@{ schema_version = 1; installation_id = [string]$manifest.installation_id; resources = $remaining }
            $payloadJson = [string]($payload | ConvertTo-Json -Compress -Depth 8)
            $newManifest = [ordered]@{
                schema_version = 1
                installation_id = [string]$manifest.installation_id
                resources = $remaining
                hmac = Get-HmacHex $payloadJson $key
            }
            $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
            Write-PrivateBytes $Manifest $encoding.GetBytes(([string]($newManifest | ConvertTo-Json -Compress -Depth 8)) + [char]10)
        } elseif ($manifestVerified) {
            Remove-Owned $DataDir 'ownership.key'
            Remove-Owned $DataDir 'ownership-manifest.json'
        }
        foreach ($path in @($BinDir, $InstallDir, $ServiceDir, (Split-Path -LiteralPath $Config -Parent), $DataDir)) { Remove-EmptyDirectory $path }
    } catch { Fail $ExitGeneric 'purge refused because an owned path is unsafe or could not be removed' }
    if (-not $manifestVerified) { Write-Warning 'remote decommission status is unknown; verify Controller-side purge separately' }
    if (-not $manifestVerified) {
        Write-Output 'antinat installer: purge complete; allowlisted role resources removed, ownership metadata retained because the manifest was not authenticated'
    } elseif ($keepOtherRole) {
        Write-Output 'antinat installer: current role purge complete; another role and shared ownership state remain'
    } else {
        Write-Output 'antinat installer: purge complete; no owned residue remains'
    }
    exit $ExitPurge
}

function Copy-FileAtomic([string] $Source, [string] $Destination) {
    Assert-NoReparsePath $Source
    $sourceItem = Get-Item -LiteralPath $Source -Force
    if ($sourceItem.PSIsContainer -or $sourceItem.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'source is not a regular non-reparse file' }
    $parent = Split-Path -LiteralPath $Destination -Parent
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Assert-NoReparsePath $parent
    Assert-NoReparsePath $Destination
    $temporary = Join-Path $parent ('.antinat-copy.' + [Guid]::NewGuid().ToString('N'))
    try {
        Copy-Item -LiteralPath $Source -Destination $temporary
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Copy-VerifiedFileAtomic([string] $Source, [string] $Destination, [string] $ExpectedDigest) {
    if ($ExpectedDigest -notmatch '^[0-9a-f]{64}$') { throw 'artifact digest is invalid' }
    Initialize-NativeFileApi
    $opened = [AntiNAT.NativeFile]::OpenRead($Source)
    $parent = Split-Path -LiteralPath $Destination -Parent
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Assert-NoReparsePath $parent
    Assert-NoReparsePath $Destination
    $temporary = Join-Path $parent ('.antinat-verified.' + [Guid]::NewGuid().ToString('N'))
    $hash = [Security.Cryptography.SHA256]::Create()
    $output = $null
    try {
        $output = New-Object -TypeName System.IO.FileStream -ArgumentList @($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 1048576, [IO.FileOptions]::WriteThrough)
        $buffer = New-Object -TypeName byte[] -ArgumentList 1048576
        while (($count = $opened.Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hash.TransformBlock($buffer, 0, $count, $buffer, 0) | Out-Null
            $output.Write($buffer, 0, $count)
        }
        $hash.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        $actual = ConvertTo-Hex $hash.Hash
        if ($actual -ne $ExpectedDigest) { throw 'artifact digest changed during copy' }
        $output.Flush($true)
        $output.Dispose()
        $output = $null
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
        Set-PrivateAcl $Destination $false
    } finally {
        if ($null -ne $output) { $output.Dispose() }
        $opened.Dispose()
        $hash.Dispose()
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Copy-TreeSnapshot([string] $Source, [string] $Destination) {
    $item = Get-ExistingItem $Source
    if ($null -eq $item -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'snapshot tree contains a reparse point' }
    if (-not $item.PSIsContainer) {
        Copy-FileAtomic $Source $Destination
        return
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Assert-NoReparsePath $Destination
    foreach ($child in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-TreeSnapshot $child.FullName (Join-Path $Destination $child.Name)
    }
}

function Test-SnapshotTree([string] $Left, [string] $Right) {
    $leftItem = Get-ExistingItem $Left
    $rightItem = Get-ExistingItem $Right
    if ($null -eq $leftItem -or $null -eq $rightItem) { return $false }
    if ($leftItem.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or $rightItem.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { return $false }
    if ($leftItem.PSIsContainer -ne $rightItem.PSIsContainer) { return $false }
    if (-not $leftItem.PSIsContainer) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Left).Hash -eq (Get-FileHash -Algorithm SHA256 -LiteralPath $Right).Hash
    }
    $leftChildren = @(Get-ChildItem -LiteralPath $Left -Force | ForEach-Object { $_.Name } | Sort-Object)
    $rightChildren = @(Get-ChildItem -LiteralPath $Right -Force | ForEach-Object { $_.Name } | Sort-Object)
    if (($leftChildren -join "`n") -ne ($rightChildren -join "`n")) { return $false }
    foreach ($name in $leftChildren) {
        if (-not (Test-SnapshotTree (Join-Path $Left $name) (Join-Path $Right $name))) { return $false }
    }
    return $true
}

function Get-UpgradeResources {
    $resources = @()
    if ($Role -in @('agent', 'both')) {
        $resources += @(
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
            [ordered]@{ root = $DataDir; path = 'state.db' },
            [ordered]@{ root = $DataDir; path = 'node.key' },
            [ordered]@{ root = $DataDir; path = 'terminal.marker' },
            [ordered]@{ root = $DataDir; path = 'agent.marker' },
            [ordered]@{ root = (Split-Path -LiteralPath $Config -Parent); path = 'agent.conf' }
        )
    }
    if ($Role -in @('controller', 'both')) {
        $resources += @(
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
            [ordered]@{ root = $DataDir; path = 'controller.db' },
            [ordered]@{ root = $DataDir; path = 'controller-keys' }
        )
    }
    $resources += [ordered]@{ root = $DataDir; path = 'schema.version' }
    return $resources
}

function Create-UpgradeSnapshot([string] $Destination) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Set-PrivateAcl $Destination $true
    $records = @()
    $index = 0
    foreach ($resource in @(Get-UpgradeResources)) {
        $relative = ([string]$resource.path).Replace('/', '\')
        $source = [IO.Path]::GetFullPath((Join-Path ([string]$resource.root) $relative))
        Assert-NoReparsePath ([string]$resource.root)
        $record = [ordered]@{ root = $resource.root; path = $resource.path; present = $false; kind = 'missing'; backup = "file-$index" }
        $item = Get-ExistingItem $source
        if ($null -ne $item) {
            if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'upgrade snapshot resource is unsafe' }
            if (-not $item.PSIsContainer -and $item.Length -gt 512MB) { throw 'upgrade snapshot resource is unsafe' }
            $record.kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            if ($record.kind -eq 'directory') {
                Copy-TreeSnapshot $source (Join-Path $Destination $record.backup)
            } else {
                Copy-FileAtomic $source (Join-Path $Destination $record.backup)
            }
            $record.present = $true
        }
        $records += $record
        $index++
    }
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    $raw = [string]($records | ConvertTo-Json -Compress -Depth 8) + [char]10
    Write-PrivateBytes (Join-Path $Destination 'snapshot.json') $encoding.GetBytes($raw)
    return ,$records
}

function Restore-UpgradeSnapshot([string] $Destination, $Records) {
    foreach ($record in $Records) {
        $root = [string]$record.root
        $relative = ([string]$record.path).Replace('/', '\')
        $target = [IO.Path]::GetFullPath((Join-Path $root $relative))
        Assert-NoReparsePath $root
        if ($record.present) {
            $backup = Join-Path $Destination ([string]$record.backup)
            if ([string]$record.kind -eq 'directory') {
                Remove-Owned $root ([string]$record.path)
                Copy-TreeSnapshot $backup $target
            } elseif ([string]$record.kind -eq 'file') {
                Copy-FileAtomic $backup $target
            } else {
                throw 'upgrade snapshot record has an invalid kind'
            }
        } elseif ($null -ne (Get-ExistingItem $target)) {
            Remove-Owned $root ([string]$record.path)
        }
    }
}

function Verify-UpgradeSnapshot([string] $Destination, $Records) {
    foreach ($record in $Records) {
        $root = [string]$record.root
        $target = [IO.Path]::GetFullPath((Join-Path $root ([string]$record.path).Replace('/', '\')))
        $backup = Join-Path $Destination ([string]$record.backup)
        if ($record.present) {
            if (-not (Test-SnapshotTree $target $backup)) { throw "upgrade snapshot restore mismatch: $($record.path)" }
        } elseif ($null -ne (Get-ExistingItem $target)) {
            throw "upgrade snapshot restored an absent resource: $($record.path)"
        }
    }
}

function Rollback-New-Install {
    Stop-Delete-Service
    $resources = @(Get-CompileTimeResources)
    foreach ($resource in $resources) {
        if ([string]$resource.path -eq 'schema.version') { continue }
        if ([string]$resource.path -in @('backups', 'ownership-manifest.json', 'ownership.key') -and
            (($resource.path -eq 'ownership-manifest.json' -and $script:ManifestExistedBeforeInstall) -or
             ($resource.path -eq 'ownership.key' -and $script:OwnershipKeyExistedBeforeInstall) -or
             $resource.path -eq 'backups')) { continue }
        try { Remove-Owned ([string]$resource.root) ([string]$resource.path) } catch { }
    }
    try { Restore-SchemaAfterInstall } catch { }
    Cleanup-SchemaBackup
    foreach ($path in @($BinDir, $InstallDir, $ServiceDir, (Split-Path -LiteralPath $Config -Parent), $DataDir)) {
        try { Remove-EmptyDirectory $path } catch { }
    }
}

function Install-Flow {
    if ($Role -in @('agent', 'both')) { Validate-Endpoint $Endpoint }
    Set-Paths
    Get-ReleaseDirectory
    Verify-Release
    Require-ReleaseArtifacts
    $script:ManifestExistedBeforeInstall = $null -ne (Get-ExistingItem $Manifest)
    $script:OwnershipKeyExistedBeforeInstall = $null -ne (Get-ExistingItem $OwnershipKey)
    if (($Role -in @('agent', 'both') -and $null -ne (Get-ExistingItem $Agent)) -or
        ($Role -in @('controller', 'both') -and $null -ne (Get-ExistingItem $Controller))) { Fail $ExitConflict 'AntiNAT is already installed; use upgrade' }
    New-Item -ItemType Directory -Force -Path $BinDir, $DataDir | Out-Null
    if ($Role -in @('controller', 'both')) {
        $controllerKeys = Join-Path $DataDir 'controller-keys'
        New-Item -ItemType Directory -Force -Path $controllerKeys | Out-Null
        Set-PrivateAcl $controllerKeys $true
    }
    try { Set-PrivateAcl $DataDir $true } catch { Fail $ExitGeneric 'could not protect the data directory' }
    try { Backup-SchemaForInstall } catch { Rollback-New-Install; Fail $ExitGeneric 'could not prepare the schema marker transaction' }
    if ($Role -in @('agent', 'both') -and ($env:ANTINAT_TEST_MODE -ne '1' -or $TokenFile -or $TokenFD -ge 0)) {
        try { Read-Token } catch { Cleanup-TokenOnFailure; Rollback-New-Install; Fail $ExitToken 'token input rejected' }
    }
    try {
        if ($Role -in @('agent', 'both')) {
            Copy-VerifiedFileAtomic $script:AgentReleaseArtifact $Agent $script:AgentReleaseDigest
            Write-Config $script:TokenTemp
        }
        if ($Role -in @('controller', 'both')) {
            Copy-VerifiedFileAtomic $script:ControllerReleaseArtifact $Controller $script:ControllerReleaseDigest
        }
        Write-SchemaVersion
        Install-Services ($Role -in @('agent', 'both') -and $null -ne $script:TokenTemp -and $script:TokenTemp -ne '')
    } catch {
        Cleanup-TokenOnFailure
        Rollback-New-Install
        Fail $ExitGeneric 'installation failed; partial state was removed'
    }
    try {
        if ($Role -in @('agent', 'both')) { Wait-TokenConsumption }
        if ($Role -in @('agent', 'both') -and $script:TokenTemp) {
            # Remove the one-time input from both the config file and the
            # persisted Windows service command after enrollment succeeds.
            Write-Config ''
            Update-ServiceCommand
            Consume-TokenSource
        }
    } catch {
        Cleanup-TokenOnFailure
        Rollback-New-Install
        Fail $ExitToken 'enrollment token was not consumed; installation was rolled back'
    }
    try { New-OwnershipManifest } catch { Cleanup-TokenOnFailure; Rollback-New-Install; Fail $ExitGeneric 'ownership manifest creation failed; installation was rolled back' }
    Cleanup-SchemaBackup
    $script:TokenTemp = ''
    $script:TokenSource = ''
    Write-Output 'antinat installer: install complete'
}

function Upgrade-Flow {
    Set-Paths
    Validate-UpgradeVersion
    Get-ReleaseDirectory
    Verify-Release
    Require-ReleaseArtifacts
    if (($Role -in @('agent', 'both') -and $null -eq (Get-ExistingItem $Agent)) -or
        ($Role -in @('controller', 'both') -and $null -eq (Get-ExistingItem $Controller))) { Fail $ExitConflict 'installation is not present' }
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Set-PrivateAcl $BackupDir $true
    $backup = Join-Path $BackupDir ('upgrade.' + [Guid]::NewGuid().ToString('N'))
    $records = $null
    $wasAgentRunning = $false
    $wasControllerRunning = $false
    try {
        New-Item -ItemType Directory -Path $backup | Out-Null
        Set-PrivateAcl $backup $true
        $agentService = if ($Role -in @('agent', 'both')) { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } else { $null }
        $controllerService = if ($Role -in @('controller', 'both')) { Get-Service -Name $ControllerServiceName -ErrorAction SilentlyContinue } else { $null }
        $wasAgentRunning = $Role -in @('agent', 'both') -and $null -ne $agentService -and $agentService.Status -eq 'Running'
        $wasControllerRunning = $Role -in @('controller', 'both') -and $null -ne $controllerService -and $controllerService.Status -eq 'Running'
        if ($wasAgentRunning) { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
        if ($wasControllerRunning) { Stop-Service -Name $ControllerServiceName -Force -ErrorAction Stop }
        $records = @(Create-UpgradeSnapshot $backup)
        Verify-UpgradeSnapshot $backup $records
        if ($Role -in @('agent', 'both')) {
            Copy-VerifiedFileAtomic $script:AgentReleaseArtifact $Agent $script:AgentReleaseDigest
        }
        if ($Role -in @('controller', 'both')) {
            Copy-VerifiedFileAtomic $script:ControllerReleaseArtifact $Controller $script:ControllerReleaseDigest
        }
        Write-SchemaVersion
        if ($env:ANTINAT_FORCE_HEALTH_FAIL -eq '1') { throw 'health check failed' }
        if ($wasAgentRunning) { Start-Service -Name $ServiceName -ErrorAction Stop }
        if ($wasControllerRunning) { Start-Service -Name $ControllerServiceName -ErrorAction Stop }
        Write-Output 'antinat installer: upgrade complete'
    } catch {
        $cause = $_
        if ($null -eq $records) {
            if ($wasAgentRunning) { try { Start-Service -Name $ServiceName -ErrorAction Stop } catch { } }
            if ($wasControllerRunning) { try { Start-Service -Name $ControllerServiceName -ErrorAction Stop } catch { } }
            Fail $ExitGeneric 'upgrade failed before a complete snapshot was created'
        }
        $rollbackError = $null
        try {
            Restore-UpgradeSnapshot $backup $records
            Verify-UpgradeSnapshot $backup $records
        } catch { $rollbackError = $_ }
        try {
            if ($wasAgentRunning) { Start-Service -Name $ServiceName -ErrorAction Stop }
            if ($wasControllerRunning) { Start-Service -Name $ControllerServiceName -ErrorAction Stop }
        } catch { if ($null -eq $rollbackError) { $rollbackError = $_ } }
        if ($null -ne $rollbackError) {
            Fail $ExitRollback 'upgrade failed; rollback could not be verified'
        }
        Fail $ExitRollback 'upgrade failed; previous version restored'
    }
}

Set-Paths
Parse-Arguments $Arguments
Set-Paths
switch ($script:Command) {
    'install' { Install-Flow }
    'upgrade' { Upgrade-Flow }
    'uninstall' {
        Stop-Delete-Service
        Send-RemoteUninstallNotice 'uninstall'
        if ($Role -in @('agent', 'both')) {
            Remove-Owned $InstallDir 'bin/antinat-agent.exe'
            Remove-Owned $InstallDir 'bin/antinat-hook-runner.exe'
            Remove-Owned (Split-Path -LiteralPath $Config -Parent) 'agent.conf'
        }
        if ($Role -in @('controller', 'both')) { Remove-Owned $InstallDir 'bin/antinat-controller.exe' }
        Write-Output 'antinat installer: service and executable files removed; state retained'
    }
    'purge' { Purge-Install }
}
