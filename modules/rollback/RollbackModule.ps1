# RollbackModule.ps1
# Provides functions to revert actions based on the rollback log file.

$rollbackLogFilePath = Join-Path $Global:ProjectRoot "temp\rollback.log"

# Initializes the rollback module (checks for log file existence).
function Initialize-Rollback {
    [CmdletBinding()]
    param()
    Write-Log "INFO" "RollbackModule: Initialized."
    if (-not (Test-Path $rollbackLogFilePath -PathType Leaf)) {
        Write-Log "INFO" "RollbackModule: Rollback log file '$rollbackLogFilePath' not found."
    }
}

# Reads and parses entries from the rollback log file.
function Get-RollbackLogEntries {
    [CmdletBinding()]
    param(
        # Optionally return only the last N entries.
        [Parameter(Mandatory = $false)]
        [int]$Last = 0
    )
    Write-Log "DEBUG" "RollbackModule: Reading rollback log '$rollbackLogFilePath'."
    if (-not (Test-Path $rollbackLogFilePath -PathType Leaf)) {
        Write-Log "WARN" "RollbackModule: Rollback log file '$rollbackLogFilePath' not found."
        return @()
    }
    try {
        $logContent = Get-Content -Path $rollbackLogFilePath -Encoding UTF8 -ErrorAction Stop
        $parsedEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($line in $logContent) {
            $parts = $line.Split('|', 4)
            if ($parts.Count -eq 4) {
                try {
                    $entry = [PSCustomObject]@{
                        Timestamp = Get-Date $parts[0]
                        Action = $parts[1].Trim()
                        Details = $parts[2].Trim()
                        BackupPath = $parts[3].Trim()
                        RawLine = $line
                    }
                    $parsedEntries.Add($entry)
                } catch {
                    Write-Log "WARN" "RollbackModule: Ignoring malformed/invalid date rollback log line: '$line'."
                }
            } else {
                Write-Log "WARN" "RollbackModule: Ignoring unexpected format in rollback log line: '$line'."
            }
        }
        # Sort entries descending by timestamp (newest first)
        $sortedEntries = $parsedEntries | Sort-Object Timestamp -Descending
        if ($Last -gt 0 -and $sortedEntries.Count -gt $Last) {
            $result = $sortedEntries[0..($Last - 1)]
            Write-Log "INFO" "RollbackModule: Read last $Last (of $($sortedEntries.Count)) entries."
            return $result
        } else {
            Write-Log "INFO" "RollbackModule: Read $($sortedEntries.Count) entries."
            return $sortedEntries
        }
    } catch {
        Write-Log "ERROR" "RollbackModule: Failed to read/parse rollback log '$rollbackLogFilePath': $($_.Exception.Message)"
        throw "Failed to process rollback log."
    }
}

# Internal function to perform a single rollback action based on a log entry.
function Invoke-RollbackAction {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$LogEntry
    )

    $actionToRevert = $LogEntry.Action
    $backupPath = $LogEntry.BackupPath
    $details = $LogEntry.Details
    $timestamp = $LogEntry.Timestamp

    Write-Log "INFO" "RollbackModule: Attempting to revert '$actionToRevert' from $timestamp using '$backupPath'."

    # Check if backup file exists
    if (-not (Test-Path $backupPath -PathType Leaf)) {
        Write-Log "ERROR" "RollbackModule: Backup file '$backupPath' NOT FOUND. Skipping rollback."
        Write-Host "ERRO: Backup '$backupPath' não encontrado." -ForegroundColor Red
        return $false
    }

    $restoreActionCmd = $null
    $targetResource = $null

    # Determine the correct restore function based on the logged action
    if ($actionToRevert -like "*-HostsEntry" -or $actionToRevert -like "*-BlockedDomain") {
        $restoreActionCmd = "Restore-HostsFile" # Call without global:
        $targetResource = "arquivo Hosts"
    } elseif ($actionToRevert -like "*-FirewallRule" -or $actionToRevert -like "*-BlockedPort" -or $actionToRevert -like "*-Exception") {
        $restoreActionCmd = "Restore-FirewallConfig" # Call without global:
        $targetResource = "configuração Firewall"
    } else {
        Write-Log "ERROR" "RollbackModule: Unknown action type '$actionToRevert'."
        Write-Host "ERRO: Ação '$actionToRevert' desconhecida." -ForegroundColor Red
        return $false
    }

    # Execute restore directly (ShouldProcess removed)
    try {
        Write-Log "INFO" "RollbackModule(TESTING): Executing restore for '$actionToRevert' ($timestamp - $details) from '$backupPath'."
        # Use Invoke-Expression to call the determined restore function with the correct parameter name.
        Invoke-Expression "$restoreActionCmd -backupFilePath '$backupPath'" -ErrorAction Stop # Using -backupFilePath

        Write-Log "INFO" "RollbackModule: Action '$actionToRevert' reverted using '$backupPath'."
        Write-Host "Ação '$actionToRevert' ($timestamp) revertida." -ForegroundColor Green
        return $true
    } catch {
        Write-Log "ERROR" "RollbackModule: Failed restore for '$actionToRevert' using '$backupPath': $($_.Exception.Message)"
        Write-Host "ERRO: Falha restauração $targetResource para '$actionToRevert' ($timestamp): $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main function to initiate the rollback process for N steps.
function Start-Rollback {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 100)]
        [int]$Steps = 1
    )

    Write-Log "INFO" "RollbackModule: Starting rollback for $Steps step(s)."

    try {
        $entriesToRollback = Get-RollbackLogEntries -Last $Steps
        if ($entriesToRollback.Count -eq 0) {
            Write-Log "WARN" "RollbackModule: No actions found in log to revert."
            Write-Host "Nenhuma ação no log para reverter." -ForegroundColor Yellow
            return
        }
        if ($entriesToRollback.Count -lt $Steps) {
            # Corrected log/warning message
            Write-Log "WARN" "RollbackModule: Requested $Steps steps, but only $($entriesToRollback.Count) found."
            Write-Host "AVISO: Pedido $Steps passos, mas apenas $($entriesToRollback.Count) encontrado(s)." -ForegroundColor Yellow
        }

        Write-Host "Ações a reverter (mais recente primeiro):" -ForegroundColor Yellow
        $entriesToRollback | Format-Table Timestamp, Action, Details, BackupPath -AutoSize

        # Execute directly (general ShouldProcess removed)
        Write-Log "INFO" "RollbackModule(TESTING): Executing rollback of $($entriesToRollback.Count) step(s)."

        $rollbackSuccessCount = 0
        $rollbackFailCount = 0
        foreach ($entry in $entriesToRollback) {
            # Call internal action directly
            $success = Invoke-RollbackAction -LogEntry $entry
            if ($success) {
                $rollbackSuccessCount++
            } else {
                $rollbackFailCount++
                Write-Log "ERROR" "RollbackModule: Failed to revert entry from $($entry.Timestamp). Rollback stopped."
                Write-Host "ERRO: Falha ao reverter. Rollback interrompido." -ForegroundColor Red
                break # Stop rollback on first failure
            }
        }

        Write-Log "INFO" "RollbackModule: Rollback finished. Success: $rollbackSuccessCount, Failed/Skipped: $rollbackFailCount."
        Write-Host "Rollback concluído (Sucesso: $rollbackSuccessCount, Falhas/Cancelados: $rollbackFailCount)." -ForegroundColor Cyan

    } catch {
        Write-Log "CRITICAL" "RollbackModule: Critical error during rollback: $($_.Exception.Message)"
        Write-Host "ERRO CRÍTICO durante rollback: $($_.Exception.Message)" -ForegroundColor Red
    }
}