# LogAnalysisModule.ps1
# Orchestrator module for log analysis tasks, integrating Get, Parse, and Filter modules.
# Also includes log rotation functionality.

# Path to the directory containing this module and its dependencies.
$currentModulePath = Split-Path -Parent $PSCommandPath

# 1. Load dependency modules (Get, Parse, Filter) using dot-sourcing.
try {
    . (Join-Path $currentModulePath "LogGet.ps1")
    . (Join-Path $currentModulePath "LogParse.ps1")
    . (Join-Path $currentModulePath "LogFilter.ps1")
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogAnalysisModule: LogGet, LogParse, LogFilter modules loaded." }
} catch {
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule: Critical failure loading Get/Parse/Filter dependencies: $($_.Exception.Message)" }
    throw "Failed to load LogAnalysisModule dependencies: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------------
# Convenience Functions (Examples combining Get, Parse, Filter)
# -----------------------------------------------------------------------------

# Retrieves and parses Windows Firewall logs from the Event Log.
function Get-ParsedFirewallLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)] [object]$Filter,
        [Parameter(Mandatory = $false)] [int]$MaxEvents,
        [Parameter(Mandatory = $false)] [datetime]$StartTime,
        [Parameter(Mandatory = $false)] [string]$LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        [Parameter(Mandatory = $false)] [string]$ProviderName = "Microsoft-Windows-Windows Firewall With Advanced Security",
        [Parameter(Mandatory = $false)] [string]$ComputerName = $env:COMPUTERNAME
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Requesting parsed firewall logs (Computer: $ComputerName, MaxEvents: $MaxEvents, StartTime: $StartTime)..." }
    try {
        # Call function from LogGet module (no prefix)
        $rawEvents = Get-FirewallLogsFromEventLog -Filter $Filter -MaxEvents $MaxEvents -StartTime $StartTime -LogName $LogName -ProviderName $ProviderName -ComputerName $ComputerName

        if ($null -eq $rawEvents -or @($rawEvents).Count -eq 0) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: No raw firewall events found." }
            return @()
        }

        # Call function from LogParse module (no prefix), filtering out null results from failed parsing
        $parsedLogs = $rawEvents | Parse-EventLogFirewallRecord | Where-Object { $null -ne $_ }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: $($parsedLogs.Count) firewall events parsed." }
        return $parsedLogs

    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule(Get-Parsed): Failed: $($_.Exception.Message)" }
        return @() # Return empty array on failure
    }
}

# Retrieves, parses, optionally filters, and exports firewall logs to a CSV file.
function Export-FirewallLogsToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvOutputPath,

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents,

        [Parameter(Mandatory = $false)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow", "Block")]
        [string]$FilterAction, # Optional filter by action

        [Parameter(Mandatory = $false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Exporting logs to '$CsvOutputPath'..." }
    try {
        # Call local function to get parsed logs
        $parsedLogs = Get-ParsedFirewallLogs -MaxEvents $MaxEvents -StartTime $StartTime -ComputerName $ComputerName

        if ($null -eq $parsedLogs -or $parsedLogs.Count -eq 0) {
             if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogAnalysisModule: No logs found to export." }
             Write-Host "WARNING: No logs found to export." -ForegroundColor Yellow; return
        }

        # Optionally filter logs by action
        if ($PSBoundParameters.ContainsKey('FilterAction') -and -not [string]::IsNullOrWhiteSpace($FilterAction)) {
             $initialCount = $parsedLogs.Count
             # Call function from LogFilter module (no prefix)
             $parsedLogs = $parsedLogs | Filter-LogsByAction -Action $FilterAction
             if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Filtered by '$FilterAction' (Before: $initialCount, After: $($parsedLogs.Count))." }
        }

        if ($parsedLogs.Count -eq 0) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogAnalysisModule: No logs remaining after filtering." }
            Write-Host "WARNING: No logs remaining after filter." -ForegroundColor Yellow; return
        }

        # Ensure output directory exists
        $OutDir = Split-Path -Parent $CsvOutputPath -Resolve
        if (-not (Test-Path $OutDir -PathType Container)) {
            Write-Log "INFO" "LogAnalysisModule: Creating output directory '$OutDir'."
            New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        }

        # Export to CSV
        $parsedLogs | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ',' -ErrorAction Stop

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Exported $($parsedLogs.Count) log records to '$CsvOutputPath'." }
        Write-Host "$($parsedLogs.Count) logs exportados para '$CsvOutputPath'." -ForegroundColor Green

    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule(Export-Csv): Failed: $($_.Exception.Message)" }
        Write-Host "ERRO ao exportar: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Convenience function combining Get, Parse, and multiple Filters.
function Search-FirewallLogs {
    [CmdletBinding()]
    param(
        # Filter parameters passed down to Find-Logs
        [Parameter(Mandatory = $false)] [datetime]$StartTime,
        [Parameter(Mandatory = $false)] [datetime]$EndTime,
        [Parameter(Mandatory = $false)] [string[]]$IPAddress,
        [Parameter(Mandatory = $false)] [int[]]$Port,
        [Parameter(Mandatory = $false)] [ValidateSet("Allow", "Block")] [string]$Action,
        [Parameter(Mandatory = $false)] [string]$Keyword,
        # Parameters for the initial log fetch if no pipeline input
        [Parameter(Mandatory = $false)] [int]$MaxEventsToFetch = 1000,
        [Parameter(Mandatory = $false)] [string]$ComputerName = $env:COMPUTERNAME
        # Note: Other Find-Logs parameters like RuleName, IP/Port Direction etc. could be added here too
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Searching firewall logs (Computer: $ComputerName)..." }
    try {
        # Step 1: Get parsed logs (using local function)
        # Pass StartTime and MaxEvents for initial fetch optimization
        $logs = Get-ParsedFirewallLogs -StartTime $StartTime -MaxEvents $MaxEventsToFetch -ComputerName $ComputerName

        if ($null -eq $logs -or $logs.Count -eq 0) {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) {Write-Log "INFO" "LogAnalysisModule(Search): No initial logs found."}
            Write-Host "Nenhum registro encontrado." -ForegroundColor Yellow
            return @()
        }

        # Step 2: Apply filters using Find-Logs from LogFilter module (no prefix)
        # Pass only the relevant filter parameters that were provided to this function
        $filterParams = @{}
        if ($PSBoundParameters.ContainsKey('EndTime')) { $filterParams['EndTime'] = $EndTime }
        if ($PSBoundParameters.ContainsKey('IPAddress')) { $filterParams['IPAddress'] = $IPAddress }
        if ($PSBoundParameters.ContainsKey('Port')) { $filterParams['Port'] = $Port }
        if ($PSBoundParameters.ContainsKey('Action')) { $filterParams['Action'] = $Action }
        if ($PSBoundParameters.ContainsKey('Keyword')) { $filterParams['Keyword'] = $Keyword }
        # Add other parameters here if exposed (e.g., RuleNamePattern, RuleId, IPDirection, PortDirection, etc.)

        $filteredLogs = Find-Logs -InputLogs $logs @filterParams
        # Find-Logs function already logs its results

        $count = if ($null -ne $filteredLogs) { @($filteredLogs).Count } else { 0 }
        if ($count -gt 0) {
            Write-Host "$count Registros encontrados:" -ForegroundColor Green
            # Select common/useful columns for display
            $filteredLogs | Format-Table Timestamp, Action, Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, RuleId -AutoSize -Wrap
        } else {
            Write-Host "Nenhum registro encontrado." -ForegroundColor Yellow
        }
        return $filteredLogs

    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule(Search): Search failed: $($_.Exception.Message)" }
        Write-Host "ERRO ao buscar logs: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# -----------------------------------------------------------------------------
# Log Rotation Function (Current logic primarily cleans up by max file count)
# -----------------------------------------------------------------------------
function LogAnalysis-RotateLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory,

        [Parameter(Mandatory = $true)]
        [object]$RotationConfig # Expects object with keys like log_rotation_strategy, _size, _max_files
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Checking log rotation in '$LogDirectory'..." }

    try {
        if (-not (Test-Path $LogDirectory -PathType Container)) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogAnalysisModule(Rotate): Directory '$LogDirectory' not found. Skipping rotation." }
            return
        }

        # Define defaults
        $defaultStrategy = "size"
        $defaultMaxSizeMB = 100
        $defaultMaxFiles = 10

        # Safely get configuration values with defaults
        $strategy = if ($RotationConfig -ne $null -and $RotationConfig.PSObject.Properties.Name -contains 'log_rotation_strategy' -and $RotationConfig.log_rotation_strategy -in @('size', 'time')) { $RotationConfig.log_rotation_strategy } else { $defaultStrategy }
        $maxSizeMB = if ($RotationConfig -ne $null -and $RotationConfig.PSObject.Properties.Name -contains 'log_rotation_size' -and $RotationConfig.log_rotation_size -is [int] -and $RotationConfig.log_rotation_size -gt 0) { $RotationConfig.log_rotation_size } else { $defaultMaxSizeMB }
        $maxFiles = if ($RotationConfig -ne $null -and $RotationConfig.PSObject.Properties.Name -contains 'log_rotation_max_files' -and $RotationConfig.log_rotation_max_files -is [int] -and $RotationConfig.log_rotation_max_files -gt 0) { $RotationConfig.log_rotation_max_files } else { $defaultMaxFiles }
        $maxSizeBytes = $maxSizeMB * 1MB

        # Helper scriptblock for warnings (avoids repeating Get-Command check)
        $logWarning = { if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogAnalysisModule(Rotate): $($args[0])" } }
        # Log if defaults were used due to invalid config
        if ($strategy -ne $RotationConfig.log_rotation_strategy) { &$logWarning "Invalid rotation strategy '$($RotationConfig.log_rotation_strategy)', using default '$strategy'."}
        if ($maxSizeMB -ne $RotationConfig.log_rotation_size) { &$logWarning "Invalid rotation size '$($RotationConfig.log_rotation_size)', using default '${maxSizeMB}MB'."}
        if ($maxFiles -ne $RotationConfig.log_rotation_max_files) { &$logWarning "Invalid max files count '$($RotationConfig.log_rotation_max_files)', using default '$maxFiles'."}

        # Get log files, sorted newest first (using LastWriteTime is generally better for logs)
        $logFiles = Get-ChildItem -Path $LogDirectory -Filter "*.log" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($null -eq $logFiles -or $logFiles.Count -eq 0) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule(Rotate): No *.log files found in '$LogDirectory'." }
            return
        }

        # --- Cleanup based on Max File Count ---
        if ($logFiles.Count -gt $maxFiles) {
            $filesToDelete = $logFiles | Select-Object -Skip $maxFiles
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule(Rotate): Exceeded max files limit ($maxFiles). Removing $($filesToDelete.Count) oldest log(s)..." }
            foreach ($file in $filesToDelete) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop -Confirm:$false
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule(Rotate): Removed old log: $($file.Name)" }
                } catch {
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule(Rotate): Failed to remove old log '$($file.FullName)': $($_.Exception.Message)" }
                }
            }
            # Refresh file list after deletion
            $logFiles = Get-ChildItem -Path $LogDirectory -Filter "*.log" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if ($null -eq $logFiles) {$logFiles = @()}
        }

        # --- Check for Rotation Trigger (Current implementation only checks size) ---
        # Note: This section does not actively *rotate* (rename/create new). It only checks the current newest file.
        # Full rotation logic would need to handle renaming, potentially based on date/time or size trigger.
        if ($logFiles.Count -gt 0) {
            $currentLogFile = $logFiles[0] # Newest file based on LastWriteTime
            if ($strategy -eq "size") {
                if ($currentLogFile.Length -gt $maxSizeBytes) {
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogAnalysisModule(Rotate): Current log '$($currentLogFile.Name)' ($([Math]::Round($currentLogFile.Length / 1MB, 2)) MB) exceeds size limit $($maxSizeMB)MB. (Manual rotation may be needed)." }
                } else {
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule(Rotate): Current log '$($currentLogFile.Name)' is within size limit." }
                }
            } elseif ($strategy -eq "time") {
                 # Currently, time strategy only relies on max file cleanup. No active time-based rotation trigger implemented.
                 if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule(Rotate): Strategy is 'time'. Cleanup by maxFiles ($maxFiles) applied if needed." }
            }
        }
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogAnalysisModule: Log rotation check completed for '$LogDirectory'." }

    } catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogAnalysisModule(Rotate): Failed rotating logs in '$LogDirectory': $($_.Exception.Message)" }
        Write-Host "WARNING: Log rotation failed." -ForegroundColor Yellow
    }
}

# Potentially export functions if this were a .psm1
# Export-ModuleMember -Function Get-ParsedFirewallLogs, Export-FirewallLogsToCsv, Search-FirewallLogs, LogAnalysis-RotateLogs