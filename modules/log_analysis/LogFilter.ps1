# LogFilter.ps1
# Provides functions to filter collections of parsed log objects based on various criteria.

# Filters log objects based on a time range.
function Filter-LogsByTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $false)]
        [datetime]$StartTime, # Inclusive start time

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime # Inclusive end time
    )
    $filtered = $LogObjects | Where-Object {
        $log = $_
        ($log.PSObject.Properties.Name -contains 'Timestamp' -and $log.Timestamp -is [datetime]) -and
        ($PSBoundParameters['StartTime'] -eq $false -or $log.Timestamp -ge $StartTime) -and # More robust check
        ($PSBoundParameters['EndTime'] -eq $false -or $log.Timestamp -le $EndTime)
    }
    Write-Log "DEBUG" "LogFilter: Time filter resulted in $($filtered.Count) records."
    return $filtered
}

# Filters log objects by one or more IP addresses in source or destination fields.
function Filter-LogsByIP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $true)]
        [string[]]$IPAddress, # Array of IP addresses to match

        [Parameter(Mandatory = $false)]
        [ValidateSet("Any", "Source", "Destination")]
        [string]$Direction = "Any" # Which fields to check
    )
    # Common field names for source and destination IPs across different log types
    $sourceFields = @('SourceAddress', 'RemoteAddress', 'SourceIP', 'ClientIP')
    $destFields = @('DestinationAddress', 'LocalAddress', 'DestinationIP', 'ServerIP')
    $fieldsToCheck = @()
    if ($Direction -in @('Any', 'Source')) { $fieldsToCheck += $sourceFields }
    if ($Direction -in @('Any', 'Destination')) { $fieldsToCheck += $destFields }
    $fieldsToCheck = $fieldsToCheck | Select-Object -Unique

    $filtered = $LogObjects | Where-Object {
        $log = $_; $match = $false
        foreach ($field in $fieldsToCheck) {
            # Check if the field exists and its value is in the provided IPAddress array
            if ($log.PSObject.Properties.Name -contains $field -and $log.$field -in $IPAddress) {
                 $match = $true; break # Match found, no need to check other fields for this log entry
            }
        }
        $match
    }
    Write-Log "DEBUG" "LogFilter: IP filter ('$($IPAddress -join ', ')' - $Direction) resulted in $($filtered.Count)."
    return $filtered
}

# Filters log objects by one or more ports in source or destination fields.
function Filter-LogsByPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $true)]
        [int[]]$Port, # Array of ports to match

        [Parameter(Mandatory = $false)]
        [ValidateSet("Any", "Source", "Destination")]
        [string]$Direction = "Any" # Which fields to check
    )
    # Common field names for source and destination ports
    $sourceFields = @('SourcePort', 'RemotePort')
    $destFields = @('DestinationPort', 'LocalPort', 'Port')
    $fieldsToCheck = @()
    if ($Direction -in @('Any', 'Source')) { $fieldsToCheck += $sourceFields }
    if ($Direction -in @('Any', 'Destination')) { $fieldsToCheck += $destFields }
    $fieldsToCheck = $fieldsToCheck | Select-Object -Unique

    $filtered = $LogObjects | Where-Object {
        $log = $_; $match = $false
        foreach ($field in $fieldsToCheck) {
            if ($log.PSObject.Properties.Name -contains $field -and $log.$field -ne $null) {
                try {
                    # Safely convert log field value to int before comparing with the Port array
                    if ([int]$log.$field -in $Port) { $match = $true; break }
                } catch {} # Ignore conversion errors (e.g., if field contains non-numeric data)
            }
        }
        $match
    }
    Write-Log "DEBUG" "LogFilter: Port filter ('$($Port -join ', ')' - $Direction) resulted in $($filtered.Count)."
    return $filtered
}

# Filters log objects by firewall action (assumes prior normalization).
function Filter-LogsByAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Allow", "Block")]
        [string]$Action
    )
    # Assumes the 'Action' property was normalized by LogParse module
    $filtered = $LogObjects | Where-Object { $_.PSObject.Properties.Name -contains 'Action' -and $_.Action -eq $Action }
    Write-Log "DEBUG" "LogFilter: Action filter ('$Action') resulted in $($filtered.Count)."
    return $filtered
}

# Filters log objects by firewall rule name (using wildcard) or exact rule ID.
function Filter-LogsByRuleName {
    [CmdletBinding(DefaultParameterSetName='Pattern')] # Default to pattern matching
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $true, ParameterSetName='Pattern')]
        [string]$RuleNamePattern, # Rule name pattern (supports wildcards like *)

        [Parameter(Mandatory = $true, ParameterSetName='ID')]
        [string]$RuleId # Exact Rule ID (e.g., from firewall event log)
    )
    $filtered = $LogObjects | Where-Object {
        $log = $_; $match = $false
        if ($PSCmdlet.ParameterSetName -eq 'ID') {
             # Exact match on RuleId field
             if ($log.PSObject.Properties.Name -contains 'RuleId' -and $log.RuleId -eq $RuleId) { $match = $true }
        } else { # ParameterSetName is 'Pattern'
             # Primary check against RuleName field using wildcard match
             if ($log.PSObject.Properties.Name -contains 'RuleName' -and $log.RuleName -like $RuleNamePattern) { $match = $true }
             # Fallback: Check if RuleId field *also* matches the pattern (less common use case)
             elseif ($log.PSObject.Properties.Name -contains 'RuleId' -and $log.RuleId -like $RuleNamePattern) { $match = $true }
        }
        $match
    }
    Write-Log "DEBUG" "LogFilter: Rule filter (Pattern:'$RuleNamePattern', ID:'$RuleId') resulted in $($filtered.Count)."
    return $filtered
}


# Filters log objects by a keyword in specified or all fields.
function Filter-LogsByKeyword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$LogObjects,

        [Parameter(Mandatory = $true)]
        [string]$Keyword,

        [Parameter(Mandatory = $false)]
        [string[]]$FieldsToCheck, # Optional: Limit search to specific fields

        [Parameter(Mandatory = $false)]
        [switch]$CaseSensitive
    )
    $comparisonType = if ($CaseSensitive) { [System.StringComparison]::Ordinal } else { [System.StringComparison]::OrdinalIgnoreCase }

    $filtered = $LogObjects | Where-Object {
        $log = $_; $found = $false
        # Determine which properties to check
        $propsToCheck = if ($PSBoundParameters.ContainsKey('FieldsToCheck')) { $FieldsToCheck } else { $log.PSObject.Properties | Select-Object -ExpandProperty Name }

        foreach ($propName in $propsToCheck) {
            # Check if property exists before trying to access
            if ($log.PSObject.Properties.Name -contains $propName) {
                $propValue = $log.$propName
                # Check if property value contains the keyword using specified comparison type
                if ($propValue -ne $null -and $propValue.ToString().IndexOf($Keyword, $comparisonType) -ge 0) {
                    $found = $true; break # Found keyword, move to next log object
                }
            }
        }
        $found
    }
    $case = if($CaseSensitive){"(Case Sensitive)"}else{"(Case Insensitive)"}
    $scope = if($PSBoundParameters.ContainsKey('FieldsToCheck')) { "in fields $($FieldsToCheck -join ', ')" } else { "in all fields" }
    Write-Log "DEBUG" "LogFilter: Keyword filter ('$Keyword' $case $scope) resulted in $($filtered.Count)."
    return $filtered
}

# Unified function to apply multiple filters sequentially.
# If InputLogs are not provided via pipeline, it defaults to fetching recent firewall logs.
function Find-Logs {
    [CmdletBinding(DefaultParameterSetName='Default')] # Default parameter set
    param(
        [Parameter(ValueFromPipeline = $true, ParameterSetName='Input')] # Accept input from pipeline
        [PSCustomObject[]]$InputLogs,

        [Parameter(ParameterSetName='Default')] # Part of default set if no pipeline input
        [datetime]$StartTime, # If fetching default logs, start from this time

        [Parameter(ParameterSetName='Default')]
        [int]$MaxEventsToFetch = 1000, # Limit for default log fetch

        [Parameter(ParameterSetName='Default')]
        [string]$ComputerName = $env:COMPUTERNAME, # Computer for default fetch

        # Common filter parameters, applicable to both sets
        [Parameter()] [datetime]$EndTime,
        [Parameter()] [string[]]$IPAddress,
        [Parameter()] [ValidateSet("Any", "Source", "Destination")] [string]$IPDirection = "Any",
        [Parameter()] [int[]]$Port,
        [Parameter()] [ValidateSet("Any", "Source", "Destination")] [string]$PortDirection = "Any",
        [Parameter()] [ValidateSet("Allow", "Block")] [string]$Action,
        [Parameter()] [string]$RuleNamePattern,
        [Parameter()] [string]$RuleId,
        [Parameter()] [string]$Keyword,
        [Parameter()] [string[]]$KeywordFields,
        [Parameter()] [switch]$CaseSensitive
    )
    begin {
        $logsToProcess = [System.Collections.Generic.List[PSCustomObject]]::new()
        # Determine if input is coming from pipeline or if default logs need fetching
        if ($PSCmdlet.ParameterSetName -eq 'Input') {
            Write-Log "DEBUG" "Find-Logs: Receiving logs from pipeline..."
            # Pipeline input handled in Process block
        } else {
            # No pipeline input, fetch default logs (firewall)
            Write-Log "INFO" "Find-Logs: No pipeline input detected, fetching default firewall logs (Max: $MaxEventsToFetch)..."
            try {
                 # --- Correção de Prefixo ---
                 # Call function from LogAnalysisModule directly (assuming it's loaded)
                $fetchedLogs = Get-ParsedFirewallLogs -StartTime $StartTime -MaxEvents $MaxEventsToFetch -ComputerName $ComputerName
                # --- Fim Correção de Prefixo ---
                if ($null -ne $fetchedLogs) { $logsToProcess.AddRange(@($fetchedLogs)) }
                 if ($logsToProcess.Count -eq 0) { Write-Log "INFO" "Find-Logs: No default firewall logs found matching criteria." }
                 else { Write-Log "DEBUG" "Find-Logs: Processing $($logsToProcess.Count) fetched firewall logs..." }
            } catch {
                 Write-Log "ERROR" "Find-Logs: Failed to fetch default firewall logs: $($_.Exception.Message)"
                 # Continue with empty list if fetching failed
            }
        }
    }
    process {
         # If input is from pipeline, add to the list
         if ($PSCmdlet.ParameterSetName -eq 'Input' -and $null -ne $InputLogs) {
             $logsToProcess.AddRange(@($InputLogs))
         }
    }
    end {
        # Only proceed if there are logs to process
        if ($logsToProcess.Count -eq 0) {
             Write-Log "INFO" "Find-Logs: No logs to process."
             return @()
        }
        Write-Log "DEBUG" "Find-Logs: Applying filters to $($logsToProcess.Count) log entries..."
        $filteredLogsResult = $logsToProcess # Start with the collected logs

        # Apply filters sequentially if corresponding parameters are bound
        if ($PSBoundParameters.ContainsKey('EndTime')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByTime -EndTime $EndTime }
        if ($PSBoundParameters.ContainsKey('IPAddress')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByIP -IPAddress $IPAddress -Direction $IPDirection }
        if ($PSBoundParameters.ContainsKey('Port')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByPort -Port $Port -Direction $PortDirection }
        if ($PSBoundParameters.ContainsKey('Action')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByAction -Action $Action }
        # Handle mutually exclusive RuleNamePattern/RuleId
        if ($PSBoundParameters.ContainsKey('RuleNamePattern')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByRuleName -RuleNamePattern $RuleNamePattern }
        elseif ($PSBoundParameters.ContainsKey('RuleId')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByRuleName -RuleId $RuleId }
        if ($PSBoundParameters.ContainsKey('Keyword')) { $filteredLogsResult = $filteredLogsResult | Filter-LogsByKeyword -Keyword $Keyword -FieldsToCheck $KeywordFields -CaseSensitive:$CaseSensitive }

        # Ensure result is always an array
        $finalLogs = @($filteredLogsResult)
        $finalCount = $finalLogs.Count
        Write-Log "INFO" "Find-Logs: Search complete. $finalCount record(s) matched."
        return $finalLogs
    }
}