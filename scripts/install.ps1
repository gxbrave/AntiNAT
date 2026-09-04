[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)

$ErrorActionPreference = 'Stop'
$InstallerVersion = '1'
$ExitGeneric = 1
$ExitUsage = 2
$ExitToken = 3
$ExitArtifact = 4
$ExitConflict = 5
$ExitRollback = 6
$ExitPurge = 7
$script:TokenTemp = ''
$script:TokenSource = ''

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
    if ($script:HelpRequested) { Write-Output 'Usage: install.ps1 {install|uninstall|purge|upgrade} [flags]'; exit 0 }
    if ($script:VersionRequested) { Write-Output "antinat-installer $InstallerVersion"; exit 0 }
    if ($script:TokenFD -ge 0 -and $script:TokenFile -ne '') { Fail $ExitToken 'token fd and token file are mutually exclusive' }
    if ($script:Command -eq 'install' -and [string]::IsNullOrEmpty($script:Endpoint) -and $env:ANTINAT_TEST_MODE -ne '1') { Fail $ExitUsage 'controller endpoint is required' }
    if ($script:Command -eq 'install' -and $script:InstallDirOverride -ne '' -and $script:InstallDirOverride -ne $script:InstallDir) { Fail $ExitUsage 'install directory is frozen' }
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

function Get-ReleaseDirectory {
    if ($env:ANTINAT_ARTIFACT_DIR) {
        $script:ArtifactDir = $env:ANTINAT_ARTIFACT_DIR
        $script:ManifestFile = if ($env:ANTINAT_MANIFEST_FILE) { $env:ANTINAT_MANIFEST_FILE } else { Join-Path $ArtifactDir 'manifest.json' }
        $script:SignatureFile = if ($env:ANTINAT_SIGNATURE_FILE) { $env:ANTINAT_SIGNATURE_FILE } else { Join-Path $ArtifactDir 'manifest.sig' }
        return
    }
    $base = if ($env:ANTINAT_RELEASE_BASE_URL) { $env:ANTINAT_RELEASE_BASE_URL } else { 'https://github.com/gxbrave/AntiNAT/releases/download/v1.0.0-beta' }
    if ($base -notmatch '^https://[^\s/?#]+(?:/[^\s?#]*)?$') { Fail $ExitArtifact 'release base URL must use HTTPS' }
    $script:ArtifactDir = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $ArtifactDir | Out-Null
    $script:ManifestFile = Join-Path $ArtifactDir 'manifest.json'
    $script:SignatureFile = Join-Path $ArtifactDir 'manifest.sig'
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/manifest.json" -OutFile $ManifestFile
        Invoke-WebRequest -UseBasicParsing -Uri "$base/manifest.sig" -OutFile $SignatureFile
        $manifest = Get-Content -Raw -LiteralPath $ManifestFile | ConvertFrom-Json
        $seen = @{}
        foreach ($property in @($manifest.artifacts.psobject.Properties)) {
            $name = [string]$property.Name
            if ($name -notmatch '^[A-Za-z0-9._/-]+$' -or $name.StartsWith('/') -or $name.Contains('//') -or $name -match '(^|/)\.\.?(?:/|$)') { Fail $ExitArtifact 'release manifest has an unsafe artifact name' }
            $leaf = [IO.Path]::GetFileName($name.Replace('/', '\'))
            if ([string]::IsNullOrEmpty($leaf) -or $seen.ContainsKey($leaf)) { Fail $ExitArtifact 'release manifest has colliding artifact names' }
            $seen[$leaf] = $true
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $ArtifactDir $leaf)
        }
    } catch { Fail $ExitArtifact 'release artifact download failed' }
}

function Verify-Release {
    $trust = if ($env:ANTINAT_TRUST_ROOT_FILE) { $env:ANTINAT_TRUST_ROOT_FILE } else { Join-Path $PSScriptRoot '..\deploy\trust\release-ed25519.pub' }
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
        if ([string]$property.Value -notmatch '^[0-9a-f]{64}$') { Fail $ExitArtifact 'artifact digest is not lowercase SHA-256' }
        $path = Join-Path $ArtifactDir $leaf
        $artifactItem = Get-ExistingItem $path
        if ($null -eq $artifactItem -or $artifactItem.PSIsContainer) { Fail $ExitArtifact 'artifact is missing' }
        try { Assert-NoReparsePath $path } catch { Fail $ExitArtifact 'artifact is reparse-point backed' }
        if ($artifactItem.Length -gt 512MB) { Fail $ExitArtifact 'artifact exceeds size limit' }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne [string]$property.Value) { Fail $ExitArtifact 'artifact digest mismatch' }
    }
    $script:ReleaseManifest = $manifest
}

function Find-Artifact([string] $Suffix) {
    $matches = @()
    foreach ($property in $ReleaseManifest.artifacts.psobject.Properties) {
        if ($property.Name.EndsWith($Suffix, [StringComparison]::OrdinalIgnoreCase)) { $matches += [IO.Path]::GetFileName($property.Name) }
    }
    if ($matches.Count -ne 1) { return $null }
    return Join-Path $ArtifactDir $matches[0]
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
            $item = Get-ExistingItem $TokenFile
            if ($null -eq $item) { throw 'token file is missing' }
            if ($item.Length -gt 4096) { throw 'token input exceeds size limit' }
            $token = Read-TokenBytes ([IO.File]::ReadAllBytes($TokenFile))
            $script:TokenSource = $TokenFile
        }
        if ($TokenFD -ge 0) {
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
    } catch { Fail $ExitToken 'token input rejected' }
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
    # New-Service defaults to LocalSystem. Verify the effective identity because
    # the enrollment token ACL is deliberately restricted to that identity.
    New-Service -Name $ServiceName -BinaryPathName (Get-ServiceCommand $IncludeToken) -DisplayName 'AntiNAT Agent' -StartupType Automatic -Description 'AntiNAT forwarding agent' | Out-Null
    $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $ServiceName)
    if ($null -eq $serviceInfo -or [string]$serviceInfo.StartName -ne 'LocalSystem') {
        & sc.exe delete $ServiceName *> $null
        throw 'service must run as LocalSystem for the protected enrollment token'
    }
    & sc.exe sidtype $ServiceName unrestricted *> $null
    if ($LASTEXITCODE -ne 0) { throw 'service SID configuration failed' }
    Start-Service -Name $ServiceName
}

function Update-ServiceCommand {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-ItemProperty -LiteralPath $serviceKey -Name ImagePath -Value (Get-ServiceCommand $false)
}

function Stop-Delete-Service {
    if ($env:ANTINAT_TEST_MODE -eq '1') { return }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName *> $null
    }
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
    $item = Get-ExistingItem $script:TokenSource
    if ($null -eq $item) { return }
    Test-StrictFileAcl $script:TokenSource $true
    Assert-NoReparsePath $script:TokenSource
    Remove-Item -LiteralPath $script:TokenSource -Force
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
    Remove-Item -LiteralPath $path -Force
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

function Get-CompileTimeResources {
    return @(
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
        [ordered]@{ root = $DataDir; path = 'state.db' },
        [ordered]@{ root = $DataDir; path = 'node.key' },
        [ordered]@{ root = $DataDir; path = 'controller.db' },
        [ordered]@{ root = $DataDir; path = 'terminal.marker' },
        [ordered]@{ root = $DataDir; path = 'agent.marker' },
        [ordered]@{ root = $DataDir; path = 'backups' },
        [ordered]@{ root = $DataDir; path = 'ownership-manifest.json' },
        [ordered]@{ root = $DataDir; path = 'ownership.key' },
        [ordered]@{ root = (Split-Path -LiteralPath $Config -Parent); path = 'agent.conf' }
    )
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
    foreach ($allowed in @(Get-CompileTimeResources)) {
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
    $payload = [ordered]@{
        schema_version = 1
        installation_id = ConvertTo-Hex (New-RandomBytes 16)
        resources = @(Get-CompileTimeResources)
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
    if ($item.PSIsContainer -and @(Get-ChildItem -LiteralPath $Path -Force).Count -eq 0) { Remove-Item -LiteralPath $Path -Force }
}

function Purge-Install {
    Stop-Delete-Service
    $manifestVerified = $false
    try {
        $manifest = Read-OwnershipManifest
        $resources = @($manifest.resources)
        $manifestVerified = $true
    } catch {
        Write-Warning 'ownership manifest unavailable or invalid; using compile-time allowlist only'
        $resources = @(Get-CompileTimeResources)
    }
    try {
        foreach ($resource in $resources) {
            $root = [IO.Path]::GetFullPath([string]$resource.root)
            $target = [IO.Path]::GetFullPath((Join-Path $root ([string]$resource.path).Replace('/', '\')))
            Assert-OwnedTreeSafe $target
        }
        foreach ($resource in $resources) { Remove-Owned ([string]$resource.root) ([string]$resource.path) }
        foreach ($path in @($BinDir, $InstallDir, $ServiceDir, (Split-Path -LiteralPath $Config -Parent), $DataDir)) { Remove-EmptyDirectory $path }
    } catch { Fail $ExitGeneric 'purge refused because an owned path is unsafe or could not be removed' }
    if (-not $manifestVerified) { Write-Warning 'remote decommission status is unknown; verify Controller-side purge separately' }
    Write-Output 'antinat installer: purge complete; no owned residue remains'
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

function Get-UpgradeResources {
    return @(
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
        [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
        [ordered]@{ root = $DataDir; path = 'state.db' },
        [ordered]@{ root = $DataDir; path = 'node.key' },
        [ordered]@{ root = $DataDir; path = 'controller.db' },
        [ordered]@{ root = (Split-Path -LiteralPath $Config -Parent); path = 'agent.conf' }
    )
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
        $record = [ordered]@{ root = $resource.root; path = $resource.path; present = $false; backup = "file-$index" }
        $item = Get-ExistingItem $source
        if ($null -ne $item) {
            if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 512MB) { throw 'upgrade snapshot resource is unsafe' }
            Copy-FileAtomic $source (Join-Path $Destination $record.backup)
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
        $target = [IO.Path]::GetFullPath((Join-Path ([string]$record.root) ([string]$record.path).Replace('/', '\')))
        Assert-NoReparsePath ([string]$record.root)
        if ($record.present) {
            Copy-FileAtomic (Join-Path $Destination ([string]$record.backup)) $target
        } elseif ($null -ne (Get-ExistingItem $target)) {
            Assert-NoReparsePath $target
            $item = Get-Item -LiteralPath $target -Force
            if ($item.PSIsContainer) { throw 'promoted upgrade path is unexpectedly a directory' }
            Remove-Item -LiteralPath $target -Force
        }
    }
}

function Rollback-New-Install {
    Stop-Delete-Service
    $resources = @(Get-CompileTimeResources)
    foreach ($resource in $resources) {
        try { Remove-Owned ([string]$resource.root) ([string]$resource.path) } catch { }
    }
    foreach ($path in @($BinDir, $InstallDir, $ServiceDir, (Split-Path -LiteralPath $Config -Parent), $DataDir)) {
        try { Remove-EmptyDirectory $path } catch { }
    }
}

function Install-Flow {
    if ($Endpoint -and ($Endpoint -notmatch '^https?://[^\s/?#]+(:[0-9]+)?(/[^\s?#]*)?$' -or $Endpoint -match '["<>]')) { Fail $ExitUsage 'controller endpoint is invalid' }
    Set-Paths
    Get-ReleaseDirectory
    Verify-Release
    if ($null -ne (Get-ExistingItem $Agent)) { Fail $ExitConflict 'AntiNAT is already installed; use upgrade' }
    New-Item -ItemType Directory -Force -Path $BinDir, $DataDir | Out-Null
    try { Set-PrivateAcl $DataDir $true } catch { Fail $ExitGeneric 'could not protect the data directory' }
    if ($env:ANTINAT_TEST_MODE -ne '1' -or $TokenFile -or $TokenFD -ge 0) { Read-Token }
    try {
        $agentArtifact = Find-Artifact 'antinat-agent-windows-amd64.exe'
        if (-not $agentArtifact) { $agentArtifact = Find-Artifact 'antinat-agent-windows-amd64' }
        if (-not $agentArtifact) { throw 'Windows Agent artifact is missing' }
        Copy-FileAtomic $agentArtifact $Agent
        Write-Config $script:TokenTemp
        Install-Service ($null -ne $script:TokenTemp -and $script:TokenTemp -ne '')
    } catch {
        Cleanup-TokenOnFailure
        Rollback-New-Install
        Fail $ExitGeneric 'installation failed; partial state was removed'
    }
    try {
        Wait-TokenConsumption
        if ($script:TokenTemp) {
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
    $script:TokenTemp = ''
    $script:TokenSource = ''
    Write-Output 'antinat installer: install complete'
}

function Upgrade-Flow {
    Set-Paths
    Get-ReleaseDirectory
    Verify-Release
    if ($null -eq (Get-ExistingItem $Agent)) { Fail $ExitConflict 'installation is not present' }
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Set-PrivateAcl $BackupDir $true
    $backup = Join-Path $BackupDir ('upgrade.' + [Guid]::NewGuid().ToString('N'))
    $records = $null
    $wasRunning = $false
    try {
        New-Item -ItemType Directory -Path $backup | Out-Null
        Set-PrivateAcl $backup $true
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $wasRunning = $null -ne $service -and $service.Status -eq 'Running'
        if ($wasRunning) { Stop-Service -Name $ServiceName -Force }
        $records = @()
        $index = 0
        foreach ($resource in @(
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-agent.exe' },
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-controller.exe' },
            [ordered]@{ root = $InstallDir; path = 'bin/antinat-hook-runner.exe' },
            [ordered]@{ root = $DataDir; path = 'state.db' },
            [ordered]@{ root = $DataDir; path = 'node.key' },
            [ordered]@{ root = $DataDir; path = 'controller.db' },
            [ordered]@{ root = (Split-Path -Parent $Config); path = 'agent.conf' }
        )) {
            $source = [IO.Path]::GetFullPath((Join-Path ([string]$resource.root) ([string]$resource.path).Replace('/', '\')))
            Assert-NoReparsePath ([string]$resource.root)
            $record = [ordered]@{ root = $resource.root; path = $resource.path; present = $false; backup = "file-$index" }
            $item = Get-ExistingItem $source
            if ($null -ne $item) {
                if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 512MB) { throw 'upgrade snapshot resource is unsafe' }
                Copy-Item -LiteralPath $source -Destination (Join-Path $backup $record.backup)
                $record.present = $true
            }
            $records += $record
            $index++
        }
        $records | ConvertTo-Json -Compress -Depth 8 | Set-Content -LiteralPath (Join-Path $backup 'snapshot.json') -Encoding UTF8
        $artifact = Find-Artifact 'antinat-agent-windows-amd64.exe'
        if (-not $artifact) { $artifact = Find-Artifact 'antinat-agent-windows-amd64' }
        if (-not $artifact) { throw 'Windows Agent artifact is missing' }
        Copy-FileAtomic $artifact $Agent
        if ($env:ANTINAT_FORCE_HEALTH_FAIL -eq '1') { throw 'health check failed' }
        if ($wasRunning) { Start-Service -Name $ServiceName }
        Write-Output 'antinat installer: upgrade complete'
    } catch {
        if ($records) {
            try {
                foreach ($record in $records) {
                    $target = [IO.Path]::GetFullPath((Join-Path ([string]$record.root) ([string]$record.path).Replace('/', '\')))
                    if ($record.present) {
                        Copy-FileAtomic (Join-Path $backup $record.backup) $target
                    } elseif ($null -ne (Get-ExistingItem $target)) {
                        Assert-NoReparsePath $target
                        Remove-Item -LiteralPath $target -Force
                    }
                }
            } catch { }
        }
        if ($wasRunning) { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue }
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
        Remove-Item -LiteralPath $Agent, $Controller, $Hook, $Config -Force -ErrorAction SilentlyContinue
        Write-Output 'antinat installer: service and executable files removed; state retained'
    }
    'purge' { Purge-Install }
}
