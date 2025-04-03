# LogGet.ps1
# Provides functions to retrieve raw log data from various sources like
# Windows Event Log, text files, and CSV files.

# Retrieves Windows Firewall events using Get-WinEvent.
function Get-FirewallLogsFromEventLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [object]$Filter, # Allows advanced filtering (XPath/XML)

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents,

        [Parameter(Mandatory = $false)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [string]$LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", # Default FW log

        [Parameter(Mandatory = $false)]
        [string]$ProviderName = "Microsoft-Windows-Windows Firewall With Advanced Security", # Default FW provider

        [Parameter(Mandatory = $false)]
        [int[]]$EventId, # Filter by specific Event IDs

        [Parameter(Mandatory = $false)]
        [string]$ComputerName = $env:COMPUTERNAME # Target computer
    )

    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogGet: Attempting Get-WinEvent (Log: $LogName, Provider: $ProviderName, Computer: $ComputerName)" }

    try {
        $params = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }

        # Build FilterHashtable if individual filter parameters are provided
        if (-not $Filter) {
            $filterHashTable = @{}
            if ($LogName) { $filterHashTable['LogName'] = $LogName }
            if ($ProviderName) { $filterHashTable['ProviderName'] = $ProviderName }
            if ($StartTime) { $filterHashTable['StartTime'] = $StartTime }
            if ($EventId) { $filterHashTable['Id'] = $EventId }

            if ($filterHashTable.Keys.Count -gt 0) {
                $params.Add('FilterHashtable', $filterHashTable)
            } elseif ($LogName) {
                # Fallback to LogName if no other filters but LogName is present
                $params.Add('LogName', $LogName)
            } else {
                throw "Specify LogName, ProviderName, or use the Filter parameter."
            }
        } else {
            # Use the provided advanced Filter object
            $params.Add('Filter', $Filter)
        }

        if ($PSBoundParameters.ContainsKey('MaxEvents')) { # Check if MaxEvents was explicitly passed
            $params.Add('MaxEvents', $MaxEvents)
        }

        # Execute Get-WinEvent with constructed parameters
        $events = Get-WinEvent @params

        if ($null -eq $events) {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogGet: No events found matching criteria in '$LogName' on '$ComputerName'." }
            return @() # Return empty array if no events found
        }

        # Ensure $events is always an array for consistent counting
        $count = @($events).Count
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogGet: Retrieved $count firewall events from EventLog '$LogName' on '$ComputerName'." }
        return $events

    } catch [System.UnauthorizedAccessException] {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Access denied to logs on '$ComputerName': $($_.Exception.Message)" }
        throw "Access denied to logs on '$ComputerName'. Check permissions." # User-friendly message
    } catch [System.Management.Automation.RuntimeException] {
        # Catches common errors like invalid computer name, log name, provider name
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Failed Get-WinEvent for '$LogName' on '$ComputerName': $($_.Exception.Message)" }
        throw "Failed to get EventLog '$LogName' on '$ComputerName'. Verify names and connectivity/permissions."
    } catch {
        # Catch any other unexpected errors
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Unexpected error getting EventLog '$LogName' on '$ComputerName': $($_.Exception.Message)" }
        throw # Re-throw unexpected exception
    }
}

# Reads lines from a text log file, with optional filtering and tailing.
function Get-LogsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

        [Parameter(Mandatory = $false)]
        [int]$Tail, # Return only the last N lines

        [Parameter(Mandatory = $false)]
        [string]$SimpleFilter # Simple wildcard filter (*filter*)
    )

    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogGet: Reading file '$FilePath' (Filter: '$SimpleFilter', Tail: $Tail)" }
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Log file not found: '$FilePath'." }
        throw "Log file not found: $FilePath"
    }

    $reader = $null # Ensure $reader is defined for finally block
    try {
        $reader = [System.IO.StreamReader]::new($FilePath, $Encoding)
        $lines = [System.Collections.Generic.List[string]]::new()
        while ($null -ne ($line = $reader.ReadLine())) {
            # Apply simple filter during read if specified
            if (-not $SimpleFilter -or $line -like "*$SimpleFilter*") {
                $lines.Add($line)
            }
        }
        $reader.Close(); $reader.Dispose(); $reader = $null # Close and dispose immediately

        $result = $lines.ToArray()

        # Apply tailing after reading/filtering
        if ($PSBoundParameters.ContainsKey('Tail') -and $Tail -gt 0 -and $result.Count -gt $Tail) {
            $result = $result[($result.Count - $Tail)..($result.Count - 1)]
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogGet: Returned $($result.Count) lines (Tail $Tail) from '$FilePath'." }
        } else {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogGet: Read/Filtered $($result.Count) lines from '$FilePath'." }
        }
        return $result

    } catch {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Failed to read '$FilePath': $($_.Exception.Message)" }
        throw "Failed to read '$FilePath'."
    } finally {
        # Ensure reader is disposed even if errors occurred before explicit close
        if ($reader -ne $null) {
             try { $reader.Close(); $reader.Dispose() } catch {}
        }
    }
}

# Reads log data from a CSV file using Import-Csv.
function Get-CsvLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [char]$Delimiter = ',',

        [Parameter(Mandatory = $false)]
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8 # Parameterized encoding
    )

    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogGet: Importing CSV '$FilePath' with delimiter '$Delimiter'." }
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: CSV log file not found: '$FilePath'." }
        throw "CSV log file not found: $FilePath"
    }

    try {
        $csvData = Import-Csv -Path $FilePath -Delimiter $Delimiter -Encoding $Encoding -ErrorAction Stop
        $count = if ($null -ne $csvData) { @($csvData).Count } else { 0 }
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "LogGet: Imported $count records from CSV '$FilePath'." }
        return $csvData
    } catch {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "LogGet: Failed to import CSV '$FilePath': $($_.Exception.Message)" }
        throw "Failed to import CSV '$FilePath'."
    }
}