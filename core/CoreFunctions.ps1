# CoreFunctions.ps1
# Provides shared utility functions for ControlAegis.

# --- Project Root and Essential Paths ---
if (-not $Global:ProjectRoot) {
    $Global:ProjectRoot = try { Split-Path -Parent $MyInvocation.MyCommand.Path -Resolve } catch { $(Get-Location).Path }
    Write-Host "WARNING (CoreFunctions): \$Global:ProjectRoot not set. Falling back to '$($Global:ProjectRoot)'." -ForegroundColor Yellow
}
$defaultLogPathBase = Join-Path $Global:ProjectRoot "logs"
$tempPath = Join-Path $Global:ProjectRoot "temp"
$tempBackupPath = Join-Path $tempPath "backup"
$rollbackLogPath = Join-Path $tempPath "rollback.log"

# Ensure temp/backup directories exist
foreach ($path in @($tempPath, $tempBackupPath)) {
    if (-not (Test-Path -Path $path -PathType Container)) {
        try {
            Write-Host "WARNING (CoreFunctions): Creating required directory: $path" -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "CRITICAL ERROR (Core): Failed to create directory '$path': $($_.Exception.Message)" -ForegroundColor Red
            throw "Failed to create essential directory: $path"
        }
    }
}
# --- End Paths ---


# Writes messages to the appropriate log file.
function Write-Log {
    [CmdletBinding(SupportsShouldProcess=$false)] # Prevent interference with -WhatIf/-Confirm
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$level,

        [Parameter(Mandatory = $true)]
        [string]$message
    )

    $logDirectory = $null
    $configLogPath = $null
    $useDefaultPath = $true

    # Check for configured log path in $Global:AppConfig if it exists
    $appConfigExists = Get-Variable -Name 'Global:AppConfig' -ErrorAction SilentlyContinue
    if ($appConfigExists -ne $null) {
        $appConfigValue = Get-Variable -Name 'Global:AppConfig' -ValueOnly
        if ($appConfigValue -ne $null -and $appConfigValue.logs -ne $null -and -not [string]::IsNullOrWhiteSpace($appConfigValue.logs.caminho_logs_local)) {
            $configLogPath = $appConfigValue.logs.caminho_logs_local
            # Resolve relative path if necessary
            if (-not ([System.IO.Path]::IsPathRooted($configLogPath))) {
                try {
                    $configLogPath = Join-Path $Global:ProjectRoot $configLogPath
                    $configLogPath = ([System.IO.Path]::GetFullPath($configLogPath))
                } catch {
                    Write-Host "WARNING (Write-Log): Failed to resolve configured log path. Using default." -ForegroundColor Yellow
                    $configLogPath = $null
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($configLogPath)) {
                $logDirectory = $configLogPath
                $useDefaultPath = $false
            }
        }
    }

    if ($useDefaultPath) {
        $logDirectory = $defaultLogPathBase
    }

    $logFileName = "$($env:COMPUTERNAME)-$($env:USERNAME)-$(Get-Date -Format 'yyyyMMdd').log"
    $logFilePath = Join-Path $logDirectory $logFileName

    try {
        # Ensure log directory exists
        if (-not (Test-Path -Path $logDirectory -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction Stop | Out-Null
            } catch {
                # Fallback to console if directory creation fails
                Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - LOG_INFRA_FAIL - Failed to create log directory '$logDirectory': $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp - $level - $message"
        # Append entry to the log file
        Add-Content -Path $logFilePath -Value $logEntry -Encoding UTF8 -ErrorAction Stop -Confirm:$false
    } catch {
        # Fallback to console if logging fails
        $errorMsg = "{0} - LOG_WRITE_FAIL - Failed to log Level '{1}': '{2}' to '{3}'. Error: {4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level, $message, $logFilePath, $_.Exception.Message
        Write-Host $errorMsg -ForegroundColor Yellow
    }
}

# Sets file/folder permissions.
function Set-FilePermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string]$filePath,
        [Parameter(Mandatory = $true)] [string]$account,
        [Parameter(Mandatory = $true)] [string]$accessRights # e.g., "FullControl", "Modify", "ReadAndExecute"
    )
    try {
        $acl = Get-Acl -Path $filePath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($account, $accessRights, "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $filePath -AclObject $acl
        Write-Log "INFO" "CoreFunctions: Set permissions '$accessRights' for '$account' on '$filePath'."
    } catch {
        Write-Log "ERROR" "CoreFunctions: Failed setting permissions on '$filePath': $($_.Exception.Message)"
        throw
    }
}

# Backs up the current firewall configuration using netsh export.
function Backup-FirewallConfig {
    [CmdletBinding()]
    param()
    if (-not (Test-Path $tempBackupPath -PathType Container)) {
        try { New-Item -ItemType Directory -Path $tempBackupPath -Force -ErrorAction Stop | Out-Null; Write-Log "INFO" "CoreFunctions: Created backup dir: $tempBackupPath" }
        catch { Write-Log "CRITICAL" "CoreFunctions: Failed to create backup dir '$tempBackupPath': $($_.Exception.Message)"; Write-Host "Critical Error: Failed to create '$tempBackupPath'." -ForegroundColor Red; throw "Failed essential directory: $tempBackupPath"}
    }
    $backupFileName = "firewall_$(Get-Date -Format 'yyyyMMddHHmmss').wfw"
    $backupFilePath = Join-Path $tempBackupPath $backupFileName
    Write-Log "DEBUG" "CoreFunctions: Using 'netsh advfirewall export' for backup."
    try {
        Write-Log "DEBUG" "CoreFunctions(BackupFW): Preparing netsh export..."
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo("netsh.exe", "advfirewall export `"$backupFilePath`"")
        $processInfo.RedirectStandardOutput = $true; $processInfo.RedirectStandardError = $true; $processInfo.UseShellExecute = $false; $processInfo.CreateNoWindow = $true
        $process = New-Object System.Diagnostics.Process; $process.StartInfo = $processInfo
        Write-Log "DEBUG" "CoreFunctions(BackupFW): Executing netsh..."
        $process.Start() | Out-Null; $process.WaitForExit()
        Write-Log "DEBUG" "CoreFunctions(BackupFW): netsh finished. ExitCode: $($process.ExitCode)."
        $stdout = $process.StandardOutput.ReadToEnd(); $stderr = $process.StandardError.ReadToEnd()
        if ($stdout) { Write-Log "DEBUG" "CoreFunctions(BackupFW): Stdout: $stdout" }
        if ($stderr) { Write-Log "DEBUG" "CoreFunctions(BackupFW): Stderr: $stderr" }
        # Check exit code and output/error streams for failure indicators, as netsh error reporting is inconsistent.
        if ($process.ExitCode -ne 0 -or $stderr -match '\S' -or $stdout -match 'Erro|Error|Falha|Failed') {
            $errMsg = "Failed 'netsh export' (Code: $($process.ExitCode)). Stderr: $stderr Stdout: $stdout"
            Write-Log "ERROR" "CoreFunctions: $errMsg"
            throw $errMsg
        }
        Write-Log "INFO" "CoreFunctions: Firewall backup (netsh) OK: '$backupFilePath'."
        return $backupFilePath
    } catch {
        Write-Log "ERROR" "CoreFunctions: Exception during Firewall backup (netsh): $($_.Exception.Message)"
        throw
    }
}

# Restores firewall configuration from a backup file using netsh import.
function Restore-FirewallConfig {
    [CmdletBinding()]
    param ( [Parameter(Mandatory = $true)] [string]$backupFilePath )
    if (-not (Test-Path $backupFilePath -PathType Leaf)) { Write-Log "ERROR" "CoreFunctions: Firewall backup '$backupFilePath' not found."; throw "Firewall backup '$backupFilePath' not found." }
    Write-Log "DEBUG" "CoreFunctions: Using 'netsh advfirewall import' for restore."
    try {
        Write-Log "DEBUG" "CoreFunctions(RestoreFW): Preparing netsh import..."
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo("netsh.exe", "advfirewall import `"$backupFilePath`"")
        $processInfo.RedirectStandardOutput = $true; $processInfo.RedirectStandardError = $true; $processInfo.UseShellExecute = $false; $processInfo.CreateNoWindow = $true
        $process = New-Object System.Diagnostics.Process; $process.StartInfo = $processInfo
        Write-Log "DEBUG" "CoreFunctions(RestoreFW): Executing netsh..."
        $process.Start() | Out-Null; $process.WaitForExit()
        Write-Log "DEBUG" "CoreFunctions(RestoreFW): netsh finished. ExitCode: $($process.ExitCode)."
        $stdout = $process.StandardOutput.ReadToEnd(); $stderr = $process.StandardError.ReadToEnd()
        if ($stdout) { Write-Log "DEBUG" "CoreFunctions(RestoreFW): Stdout: $stdout" }
        if ($stderr) { Write-Log "DEBUG" "CoreFunctions(RestoreFW): Stderr: $stderr" }
        # Check exit code first, then check output/error streams for less reliable failure indicators.
        if ($process.ExitCode -ne 0) {
            $errMsg = "Failed 'netsh import' (Code: $($process.ExitCode)). Stderr: $stderr Stdout: $stdout"
            Write-Log "ERROR" "CoreFunctions: $errMsg"
            throw $errMsg
        } elseif ($stdout -notmatch 'Ok.' -and $stderr -match '\S') {
             $errMsg = "Failed 'netsh import' (Code 0 but potential error). Stderr: $stderr Stdout: $stdout"
             Write-Log "ERROR" "CoreFunctions: $errMsg"
             throw $errMsg
         } elseif ($stdout -notmatch 'Ok.') {
             Write-Log "WARN" "CoreFunctions: 'netsh import' OK (Code 0) but stdout ('$stdout') did not contain 'Ok.'."
         }
        Write-Log "INFO" "CoreFunctions: Firewall (netsh) restored from '$backupFilePath'."
    } catch {
        Write-Log "ERROR" "CoreFunctions: Exception during Firewall restore (netsh) from '$backupFilePath': $($_.Exception.Message)"
        throw
    }
}

# Backs up the system hosts file.
function Backup-HostsFile {
    [CmdletBinding()]
    param()
    if (-not (Test-Path $tempBackupPath -PathType Container)) {
        try { New-Item -ItemType Directory -Path $tempBackupPath -Force -ErrorAction Stop | Out-Null; Write-Log "INFO" "CoreFunctions: Created backup dir: $tempBackupPath" }
        catch { Write-Log "CRITICAL" "CoreFunctions: Failed to create backup dir '$tempBackupPath': $($_.Exception.Message)"; Write-Host "Critical Error: Failed to create '$tempBackupPath'." -ForegroundColor Red; throw "Failed essential directory: $tempBackupPath"}
    }
    $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    try {
        $backupFileName = "hosts_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $backupFilePath = Join-Path $tempBackupPath $backupFileName
        Copy-Item -Path $hostsFilePath -Destination $backupFilePath -Force -ErrorAction Stop -Confirm:$false
        Write-Log "INFO" "CoreFunctions: Hosts backup OK: '$backupFilePath'."
        return $backupFilePath
    } catch {
        Write-Log "ERROR" "CoreFunctions: Failed hosts backup: $($_.Exception.Message)"
        throw
    }
}

# Restores the system hosts file from a backup.
function Restore-HostsFile {
    [CmdletBinding()]
    param ( [Parameter(Mandatory = $true)] [string]$backupFilePath )
    $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    if (-not (Test-Path $backupFilePath -PathType Leaf)) { Write-Log "ERROR" "CoreFunctions: Hosts backup '$backupFilePath' not found."; throw "Hosts backup '$backupFilePath' not found." }
    try {
        Copy-Item -Path $backupFilePath -Destination $hostsFilePath -Force -ErrorAction Stop -Confirm:$false
        # Attempt to clear DNS cache after restoring hosts file.
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Log "INFO" "CoreFunctions: Hosts restored from '$backupFilePath' (DNS Cache cleared)."
    } catch {
        Write-Log "ERROR" "CoreFunctions: Failed hosts restore from '$backupFilePath': $($_.Exception.Message)"
        throw
    }
}

# Writes an entry to the rollback log file.
function Write-RollbackLog {
    [CmdletBinding(SupportsShouldProcess=$false)] # Prevent interference
    param (
        [Parameter(Mandatory = $true)] [string]$action,
        [Parameter(Mandatory = $true)] [string]$details,
        [Parameter(Mandatory = $true)] [string]$backupPath
    )
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp|$action|$details|$backupPath"
        $tempDir = Split-Path -Parent $rollbackLogPath
        if (-not (Test-Path $tempDir -PathType Container)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
        Add-Content -Path $rollbackLogPath -Value $logEntry -Encoding UTF8 -ErrorAction Stop -Confirm:$false
    } catch {
        Write-Log "ERROR" "CoreFunctions: Failed write to rollback log: $($_.Exception.Message). Action: $action"
        Write-Host "CRITICAL WARNING: Failed to write rollback log for '$action'." -ForegroundColor Magenta
        # Consider re-throwing here to halt the parent operation if rollback logging is critical?
        # throw $_
    }
}

# Validates if a string conforms to common domain name standards (including IDN), excluding IPs.
function Validate-Domain {
    [CmdletBinding()]
    param ( [Parameter(Mandatory = $true)] [string]$domain )
    # Regex attempts to match standard domain structures, including Internationalized Domain Names (IDN - xn--), up to 253 chars.
    # It explicitly excludes strings that are valid IP addresses.
    if ($domain -match '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{1,59})$' -and $domain.Length -le 253) {
         if (-not (Validate-IPAddress $domain)) {
             return $true
         }
    }
    return $false
}

# Validates if a string is a valid IPv4 or IPv6 address.
function Validate-IPAddress {
    [CmdletBinding()]
    param ( [Parameter(Mandatory = $true)] [string]$ipAddress )
    try {
        # .NET TryParse is the recommended method for IP validation.
        return [System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)
    } catch {
        return $false
    }
}