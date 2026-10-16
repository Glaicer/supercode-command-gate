Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Read-AarValue {
    param([string]$Prompt, [string]$Default = '', [switch]$Optional)
    while ($true) {
        $label = $Prompt
        if ($Default) { $label += " [$Default]" }
        $value = Read-Host $label
        if ($null -eq $value) { throw 'Input ended; nothing further will be changed.' }
        if ($value -eq '') { $value = $Default }
        if ($value -match '[\x00-\x1f\x7f]') {
            Write-Host 'Control characters are not allowed.'
        } elseif ($Optional -or -not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        } else {
            Write-Host 'Enter a value; this setting has no default.'
        }
    }
}

function Read-AarChoice {
    param([string]$Prompt, [string]$Default, [string[]]$Choices)
    while ($true) {
        $value = Read-AarValue $Prompt $Default
        if ($Choices -ccontains $value) { return $value }
        Write-Host "Choose one of: $($Choices -join ', ')."
    }
}

function Read-AarPath {
    param([string]$Prompt, [string]$Default = '', [switch]$Optional)
    while ($true) {
        $value = Read-AarValue $Prompt $Default -Optional:$Optional
        if ($value -eq '~') { $value = $HOME }
        if ($value -match '^~[\\/]') { $value = Join-Path $HOME $value.Substring(2) }
        if ($value -eq '') { return $value }
        if ($value -match '^[a-zA-Z]:[\\/]|^\\\\[^\\]+\\[^\\]+') {
            return [IO.Path]::GetFullPath($value)
        }
        Write-Host 'Use a full path, such as C:\Users\you\example.'
    }
}

function Test-AarApiUrl {
    param([string]$Value)
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $false }
    $loopback = $uri.Host -in @('localhost', '127.0.0.1', '[::1]', '::1')
    return ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $loopback)) -and
        $uri.Host -ne '' -and $uri.UserInfo -eq '' -and $Value -notmatch '[?#\s]'
}

function ConvertTo-AarTomlString {
    param([string]$Value)
    # shortcut: use Unicode quote escapes until AAR's TOML scanner handles escaped quotes.
    return '"' + $Value.Replace('\', '\\').Replace('"', '\u0022').Replace("`n", '\n').Replace("`r", '\r').Replace("`t", '\t') + '"'
}

function New-AarConfig {
    param(
        [object[]]$Connections = @(), [string]$Profile = 'data-loss',
        [string[]]$ProtectedPaths = @(), [int]$TimeoutMs = 5000,
        [string]$Unavailable = 'deny', [bool]$History = $true, [bool]$SessionTrust = $true
    )
    $lines = New-Object 'Collections.Generic.List[string]'
    if ($Connections.Count) {
        $lines.Add('[assessor]')
        $lines.Add("totalTimeoutMs = $TimeoutMs")
        $lines.Add('onUnavailable = "' + $Unavailable + '"')
        for ($i = 0; $i -lt $Connections.Count; $i++) {
            $connection = $Connections[$i]
            if ($i -gt 0) { $lines.Add(''); $lines.Add('[[assessor.fallbacks]]') }
            $lines.Add('authMode = ' + (ConvertTo-AarTomlString $connection.AuthMode))
            $lines.Add('model = ' + (ConvertTo-AarTomlString $connection.Model))
            if ($connection.AuthMode -eq 'api-key') {
                $lines.Add('baseUrl = ' + (ConvertTo-AarTomlString $connection.BaseUrl))
                $lines.Add('apiKeyEnv = ' + (ConvertTo-AarTomlString $connection.ApiKeyEnv))
            }
        }
        $lines.Add('')
    }
    $lines.Add('[policy]')
    $lines.Add('profile = ' + (ConvertTo-AarTomlString $Profile))
    $paths = @($ProtectedPaths | ForEach-Object { ConvertTo-AarTomlString $_ })
    $lines.Add('protectedPaths = [' + ($paths -join ', ') + ']')
    $lines.Add(''); $lines.Add('[grants]')
    $lines.Add('sessionTrust = ' + $SessionTrust.ToString().ToLowerInvariant())
    $lines.Add(''); $lines.Add('[audit]')
    $lines.Add('enabled = ' + $History.ToString().ToLowerInvariant())
    return ($lines -join "`n") + "`n"
}

function Show-AarStage {
    param([int]$Number, [string]$Name)
    Write-Host "`nStage $Number/6 - $Name" -ForegroundColor Cyan
}

function Get-AarArchitecture {
    $native = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    if (-not $native) { $native = $env:PROCESSOR_ARCHITEW6432 }
    if (-not $native) { $native = $env:PROCESSOR_ARCHITECTURE }
    switch ($native) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported Windows architecture: $native" }
    }
}

function Save-AarFiles {
    param([string]$WorkDir, [string]$BinDir, [string]$ConfigPath, [bool]$KeepConfig, [string]$ConfigBefore)
    if (-not $KeepConfig) {
        if (Test-Path -LiteralPath $ConfigPath) {
            $item = Get-Item -LiteralPath $ConfigPath -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash -ne $ConfigBefore) {
                throw 'Config changed during setup; run the installer again.'
            }
        } elseif ($ConfigBefore) { throw 'Config disappeared during setup; run the installer again.' }
    }
    [void][IO.Directory]::CreateDirectory($BinDir)
    $binaryTemp = Join-Path $BinDir ([IO.Path]::GetRandomFileName())
    $configTemp = $null
    try {
        [IO.File]::Copy((Join-Path $WorkDir 'aar.exe'), $binaryTemp)
        $binary = Join-Path $BinDir 'aar.exe'
        if ([IO.File]::Exists($binary)) { [IO.File]::Replace($binaryTemp, $binary, [NullString]::Value) }
        else { [IO.File]::Move($binaryTemp, $binary) }
        if (-not $KeepConfig) {
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ConfigPath))
            $configTemp = $ConfigPath + '.tmp.' + [IO.Path]::GetRandomFileName()
            [IO.File]::Copy((Join-Path $WorkDir 'config.toml'), $configTemp)
            if ($ConfigBefore) {
                $backup = $ConfigPath + '.bak.' + [IO.Path]::GetRandomFileName()
                [IO.File]::Replace($configTemp, $ConfigPath, $backup)
                Write-Host "Previous config backed up to: $backup"
            } else { [IO.File]::Move($configTemp, $ConfigPath) }
        }
    } finally {
        if ([IO.File]::Exists($binaryTemp)) { [IO.File]::Delete($binaryTemp) }
        if ($configTemp -and [IO.File]::Exists($configTemp)) { [IO.File]::Delete($configTemp) }
    }
}

function Get-AarRelease {
    param([string]$WorkDir, [string]$Architecture)
    $repo = 'Glaicer/supercode-command-gate'
    $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'aar-installer' }
    $tag = $release.tag_name
    $version = $tag -replace '^(aar-)?v', ''
    if ($version -notmatch '^\d+\.\d+\.\d+([+-][a-zA-Z0-9.-]+)?$') { throw 'Invalid or missing release version.' }
    $asset = "aar-v$version-windows-$Architecture.exe"
    $base = "https://github.com/$repo/releases/download/$tag"
    Write-Host "Downloading $asset; SHA-256 verification is required before installation."
    Invoke-WebRequest "$base/$asset" -UseBasicParsing -OutFile (Join-Path $WorkDir 'aar.exe')
    Invoke-WebRequest "$base/SHA256SUMS" -UseBasicParsing -OutFile (Join-Path $WorkDir 'SHA256SUMS')
    $expected = @(
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $WorkDir 'SHA256SUMS'))) {
            if ($line -match '^([a-fA-F0-9]{64})\s+(.+)$' -and $Matches[2] -ceq $asset) { $Matches[1] }
        }
    )
    if ($expected.Count -ne 1) { throw "Missing, duplicate or invalid checksum for $asset." }
    $actual = (Get-FileHash -LiteralPath (Join-Path $WorkDir 'aar.exe') -Algorithm SHA256).Hash
    if ($actual -ne $expected[0]) { throw 'Checksum mismatch; existing files were not changed.' }
}

function Invoke-AarInstaller {
    if ($env:OS -ne 'Windows_NT') { throw 'Use install.sh for Linux/macOS; this installer is for native Windows.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $architecture = Get-AarArchitecture
    $connections = @(); $protectedPaths = @()
    $keepConfig = $false; $configBefore = ''; $timeoutMs = 5000; $unavailable = 'deny'
    $workDir = Join-Path ([IO.Path]::GetTempPath()) ('aar-install-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($workDir)
    try {
        Write-Host 'AAR setup: install the command reviewer and create its TOML config.'
        Write-Host 'This does not install or configure the OpenCode plugin. No API keys will be requested or saved.'

        Show-AarStage 1 'Installation paths'
        Write-Host 'The binary directory holds aar.exe; it should be on your PATH. Administrator rights are not needed.'
        $binDefault = Join-Path $env:LOCALAPPDATA 'aar\bin'
        if ($env:AAR_BIN_DIR) { $binDefault = $env:AAR_BIN_DIR }
        $binDir = Read-AarPath 'Binary directory' $binDefault
        $configDefault = Join-Path $env:APPDATA 'aar\config.toml'
        if ($env:XDG_CONFIG_HOME) { $configDefault = Join-Path $env:XDG_CONFIG_HOME 'aar\config.toml' }
        if ($env:AAR_CONFIG) { $configDefault = $env:AAR_CONFIG }
        Write-Host 'AAR reads AAR_CONFIG first, then XDG_CONFIG_HOME, then APPDATA. Project .aar.toml files can override it.'
        $configPath = Read-AarPath 'Config file' $configDefault
        if ($configPath -ieq (Join-Path $binDir 'aar.exe')) { throw 'The config file and executable must use different paths.' }
        if (Test-Path -LiteralPath $configPath) {
            $item = Get-Item -LiteralPath $configPath -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Config must be a regular file, not a directory or reparse point.' }
            $configBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
            Write-Host 'A config already exists. Keeping it preserves all custom/advanced settings.'
            $keepConfig = (Read-AarChoice '1 = keep existing config, 2 = replace with a new config and backup' '1' @('1', '2')) -eq '1'
        }

        Show-AarStage 2 'Model connection'
        Write-Host 'The Assessor is an LLM that reviews commands local rules cannot decide. API calls may incur provider charges.'
        if (-not $keepConfig) {
            Write-Host '1 = OpenAI-compatible API (your endpoint and key); 2 = ChatGPT subscription via OpenCode; 3 = no LLM.'
            Write-Host 'No LLM means unclear commands are denied. OpenCode mode reads an existing ChatGPT login, never an API key.'
            $mode = Read-AarChoice 'Assessment mode' '1' @('1', '2', '3')
            if ($mode -ne '3') {
                while ($true) {
                    $connection = @{ AuthMode = 'opencode'; Model = ''; BaseUrl = ''; ApiKeyEnv = '' }
                    if ($mode -eq '2') {
                        Write-Host 'Sign in separately with: opencode auth login openai --method chatgpt-browser'
                        Write-Host 'Use the exact model ID supported by that subscription. This wizard does not start login or change credentials.'
                    } else {
                        $connection.AuthMode = 'api-key'
                        Write-Host "Find the OpenAI-compatible base URL and exact model ID in your provider's API documentation."
                        Write-Host 'The URL normally ends in /v1. HTTPS is required, except HTTP on localhost, 127.0.0.1 or [::1].'
                        do {
                            $connection.BaseUrl = Read-AarValue 'API base URL'
                            $valid = Test-AarApiUrl $connection.BaseUrl
                            if (-not $valid) { Write-Host 'Use an HTTPS URL (or local HTTP), without credentials, ?query or #fragment.' }
                        } until ($valid)
                        Write-Host 'Enter only an environment-variable NAME, never the key itself. Set the key before starting OpenCode.'
                        do {
                            $connection.ApiKeyEnv = Read-AarValue 'API key environment-variable name' 'ASSESSOR_API_KEY'
                            $valid = $connection.ApiKeyEnv -cmatch '^[a-zA-Z_][a-zA-Z0-9_]*$'
                            if (-not $valid) { Write-Host 'Use letters, digits and underscores, starting with a letter or underscore.' }
                        } until ($valid)
                    }
                    $connection.Model = Read-AarValue 'Model ID'
                    $connections += $connection
                    Write-Host 'Fallbacks are tried in order only if the previous connection is unavailable, not to overturn a verdict.'
                    if ((Read-AarChoice 'Add a fallback connection? (y/n)' 'n' @('y', 'n')) -eq 'n') { break }
                    $mode = Read-AarChoice 'Fallback: 1 = API, 2 = ChatGPT via OpenCode' '1' @('1', '2')
                }
            }
        } else { Write-Host 'Keeping the existing model configuration.' }

        Show-AarStage 3 'Protection policy'
        Write-Host 'data-loss: focus on substantial irreversible loss of valuable data (recommended default).'
        Write-Host 'balanced: also weigh credentials, privilege and external/network effects. strict: weigh every risk category.'
        Write-Host 'These are review policies, not a sandbox. Hard-deny rules still apply in every profile.'
        if (-not $keepConfig) {
            $profile = Read-AarChoice 'Policy profile' 'data-loss' @('data-loss', 'balanced', 'strict')
            Write-Host 'Protected paths identify valuable data for stricter review. They are not filesystem access controls.'
            Write-Host 'Enter one absolute file/directory per question; blank finishes the list.'
            while ($true) {
                $protected = Read-AarPath 'Protected path (blank to finish)' -Optional
                if ($protected -eq '') { break }
                $protectedPaths += $protected
            }
        } else { Write-Host 'Keeping the existing policy and protected paths.' }

        Show-AarStage 4 'Timeout, failures and history'
        if (-not $keepConfig) {
            if ($connections.Count) {
                Write-Host 'The timeout is the total LLM budget, including fallbacks, in milliseconds (1000 ms = 1 second).'
                Write-Host "The plugin timeout must be longer; this installer does not change the plugin's settings."
                do {
                    $timeout = Read-AarValue 'Total assessment timeout (1-600000 ms)' '5000'
                    $valid = $timeout -match '^[1-9][0-9]{0,5}$' -and [int]$timeout -le 600000
                    if (-not $valid) { Write-Host 'Enter an integer from 1 to 600000.' }
                } until ($valid)
                $timeoutMs = [int]$timeout
                Write-Host 'If every connection fails: deny blocks the command; ask requests human review.'
                Write-Host 'ask only shows a dialog when the plugin supports interactive approvals; never-ask mode still refuses it.'
                $unavailable = Read-AarChoice 'When the Assessor is unavailable' 'deny' @('deny', 'ask')
            }
            Write-Host 'History stores local review evidence and command text for diagnostics; it may contain sensitive project data.'
            $history = (Read-AarChoice 'Save review history? (y/n)' 'y' @('y', 'n')) -eq 'y'
            Write-Host "Session trust permits eligible exact commands to reuse a human's 'Trust for this session' approval."
            Write-Host 'It never approves a command on its own; disabling it still allows one-time approvals.'
            $sessionTrust = (Read-AarChoice 'Enable session trust? (y/n)' 'y' @('y', 'n')) -eq 'y'
            $config = New-AarConfig -Connections $connections -Profile $profile -ProtectedPaths $protectedPaths -TimeoutMs $timeoutMs -Unavailable $unavailable -History $history -SessionTrust $sessionTrust
            [IO.File]::WriteAllText((Join-Path $workDir 'config.toml'), $config, (New-Object Text.UTF8Encoding $false))
        } else { Write-Host 'Keeping the existing behavior settings.' }

        Show-AarStage 5 'Review before making changes'
        Write-Host "Binary: $binDir\aar.exe (an existing binary will be replaced after checksum verification)"
        Write-Host "Config: $configPath"
        if ($keepConfig) { Write-Host 'The existing config will not be changed.' }
        else {
            if ($configBefore) { Write-Host 'Replacement creates a .bak.* copy; custom settings are not merged.' }
            Write-Host $config
        }
        if ((Read-AarChoice 'Download the latest AAR release and apply this setup? (y/n)' 'n' @('y', 'n')) -ne 'y') {
            Write-Host 'Cancelled; existing files were not changed.'
            return
        }

        Show-AarStage 6 'Install and verify'
        Get-AarRelease $workDir $architecture
        Save-AarFiles $workDir $binDir $configPath $keepConfig $configBefore
        Write-Host "`nSetup complete. Binary: $binDir\aar.exe"
        Write-Host "Config: $configPath"
        if (@($env:PATH -split ';') -notcontains $binDir) { Write-Host "Add $binDir to PATH before running aar." }
        Write-Host 'For a custom config location, set AAR_CONFIG to the file above before starting OpenCode.'
        Write-Host 'API mode needs the named key variables in that same environment; no key values were saved by this installer.'
        Write-Host 'doctor checks config and credentials, not model access. In OpenCode mode it may start/contact the local service.'
        if ((Read-AarChoice 'Run aar doctor now (no LLM/provider request)? (y/n)' 'n' @('y', 'n')) -eq 'y') {
            $oldConfig = $env:AAR_CONFIG; $oldWorkspace = $env:AAR_WORKSPACE_ROOT
            Push-Location -LiteralPath $workDir
            try {
                $env:AAR_CONFIG = $configPath; $env:AAR_WORKSPACE_ROOT = $workDir
                & (Join-Path $binDir 'aar.exe') doctor
                if ($LASTEXITCODE -ne 0) { Write-Warning 'Installed, but doctor did not pass. Fix credentials/config and run aar doctor again.' }
            } finally {
                $env:AAR_CONFIG = $oldConfig; $env:AAR_WORKSPACE_ROOT = $oldWorkspace
                Pop-Location
            }
        }
        Write-Host 'The OpenCode plugin is separate and was not installed or changed.'
    } finally {
        [IO.Directory]::Delete($workDir, $true)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-AarInstaller }
    catch { Write-Error $_; exit 1 }
}
