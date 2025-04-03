# LogParse.ps1
# Provides functions to parse raw log data from various sources into structured objects.

# Helper function to translate common protocol numbers to names.
function Convert-ProtocolNumberToString {
    param([int]$ProtocolNumber)
    switch ($ProtocolNumber) {
        1 { return "ICMP" }
        2 { return "IGMP" }
        6 { return "TCP" }
        17 { return "UDP" }
        47 { return "GRE" }
        50 { return "ESP" }
        51 { return "AH" }
        89 { return "OSPF" }
        132 { return "SCTP" }
        default { return $ProtocolNumber.ToString() } # Return number if unknown
    }
}

# Helper function to translate Windows Firewall event codes (e.g., Action/Direction).
# IMPORTANT: Verify these codes against actual event logs on the target system(s) as they can vary.
function Convert-FirewallCodeToString {
    param([string]$Code)
    switch ($Code) {
        '%%14610' { return "Allow" } # Example code for Allow
        '%%14611' { return "Block" } # Example code for Block
        '%%14612' { return "Inbound" } # Example code for Inbound
        '%%14613' { return "Outbound" }# Example code for Outbound
        default { return $Code } # Return original code if unknown
    }
}

# Parses a Windows Firewall Event Log record into a structured object.
function Parse-EventLogFirewallRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    process {
        try {
            # Extract properties by ID. Note: Property IDs might change between OS versions.
            $properties = @{};
            $EventRecord.Properties | ForEach-Object { $properties[$_.Id] = $_.Value }

            # Map specific property IDs to standardized fields. Adjust IDs as necessary.
            $parsed = [PSCustomObject]@{
                Timestamp     = $EventRecord.TimeCreated
                EventId       = $EventRecord.Id
                Level         = $EventRecord.LevelDisplayName
                ComputerName  = $EventRecord.MachineName
                Action        = Convert-FirewallCodeToString($properties[8])  # Example ID for Action
                Direction     = Convert-FirewallCodeToString($properties[10]) # Example ID for Direction
                RuleId        = $properties[9]                                # Example ID for Rule ID/Name (may differ)
                RuleName      = $null # Getting actual rule name from ID can be slow, often omitted here
                Protocol      = Convert-ProtocolNumberToString($properties[12]) # Example ID for Protocol
                ApplicationPath = $properties[23]                               # Example ID for Application Path
                LocalAddress  = $properties[17]                               # Example ID for Local Address
                LocalPort     = $properties[19]                               # Example ID for Local Port
                RemoteAddress = $properties[18]                               # Example ID for Remote Address
                RemotePort    = $properties[20]                               # Example ID for Remote Port
                FilterId      = $properties[6]                                # Example ID for Filter ID
                LayerName     = $properties[4]                                # Example ID for Layer Name
            }
            return $parsed

        } catch {
            # Log parsing errors but don't stop processing pipeline input
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogParse: Failed to parse EventRecord ID $($EventRecord.RecordId) @ $($EventRecord.TimeCreated): $($_.Exception.Message)" }
            return $null # Return null for failed records
        }
    }
}

# Parses a generic plain text log line using either Regex or a Delimiter.
function Parse-PlainTextLogLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$LogLine,

        [Parameter(Mandatory = $false)]
        [regex]$Pattern, # Regex with named capture groups

        [Parameter(Mandatory = $false)]
        [char]$Delimiter, # Simple character delimiter

        [Parameter(Mandatory = $false)]
        [string[]]$Headers # Optional headers for delimited data
    )

    process {
        try {
            $parsedObject = [PSCustomObject]@{ RawLine = $LogLine }

            if ($Pattern) {
                $match = $Pattern.Match($LogLine)
                if ($match.Success) {
                    # Add named capture groups as properties
                    $Pattern.GetGroupNames() | Where-Object { $_ -ne '0' } | ForEach-Object {
                        $parsedObject | Add-Member NoteProperty $_ $match.Groups[$_].Value
                    }
                } else {
                    $parsedObject | Add-Member NoteProperty 'ParseError' 'RegexNoMatch'
                    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogParse: Line did not match Regex: '$LogLine'" }
                }
            } elseif ($Delimiter) {
                $values = $LogLine.Split($Delimiter)
                if ($Headers) {
                    # Use provided headers
                    for ($i = 0; $i -lt [System.Math]::Min($values.Count, $Headers.Count); $i++) {
                        $parsedObject | Add-Member NoteProperty $Headers[$i] $values[$i]
                    }
                    if ($values.Count -ne $Headers.Count) {
                         $parsedObject | Add-Member NoteProperty 'ParseWarning' 'ColumnCountMismatch'
                    }
                } else {
                    # Use default Col1, Col2... headers
                    for ($i = 0; $i -lt $values.Count; $i++) {
                        $parsedObject | Add-Member NoteProperty "Col$($i+1)" $values[$i]
                    }
                }
            } else {
                # No parsing method specified
                $parsedObject | Add-Member NoteProperty 'ParseNote' 'NoPatternOrDelimiter'
            }

            # Attempt automatic Timestamp conversion if field exists
            if ($parsedObject.PSObject.Properties.Name -contains 'Timestamp' -and $parsedObject.Timestamp -is [string]) {
                 try { $parsedObject.Timestamp = Get-Date $parsedObject.Timestamp } catch {}
            } elseif (($parsedObject.PSObject.Properties.Name -contains 'Date') -and ($parsedObject.PSObject.Properties.Name -contains 'Time')) {
                 try { $parsedObject | Add-Member NoteProperty Timestamp (Get-Date "$($parsedObject.Date) $($parsedObject.Time)") } catch {}
            }

            return $parsedObject
        } catch {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogParse: Failed to parse line '$LogLine': $($_.Exception.Message)" }
            # Return minimal error object for traceability
            return [PSCustomObject]@{ RawLine=$LogLine; ParseError=$true; ErrorMessage=$_.Exception.Message }
        }
    }
}


# Parses/normalizes an object read from a CSV file (e.g., via Import-Csv).
function Parse-CsvLogRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$CsvRecord
    )
    process {
        try {
            # Add source info and attempt type conversions
            $output = $CsvRecord | Select-Object *, @{N='RecordSource'; E='CSV'}

            # Attempt common type conversions (Timestamp, Ports) safely
            if ($output.PSObject.Properties.Name -contains 'Timestamp' -and $output.Timestamp -is [string]) {
                 try { $output.Timestamp = Get-Date $output.Timestamp } catch { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogParse(CSV): Failed Timestamp conversion: $($output.Timestamp)"} }
            }
            if ($output.PSObject.Properties.Name -contains 'Port' -and $output.Port -is [string]) {
                 try { $output.Port = [int]$output.Port } catch { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogParse(CSV): Failed Port conversion: $($output.Port)"} }
            }
            if ($output.PSObject.Properties.Name -contains 'LocalPort' -and $output.LocalPort -is [string]) {
                 try { $output.LocalPort = [int]$output.LocalPort } catch { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogParse(CSV): Failed LocalPort conversion: $($output.LocalPort)"} }
            }
            if ($output.PSObject.Properties.Name -contains 'RemotePort' -and $output.RemotePort -is [string]) {
                 try { $output.RemotePort = [int]$output.RemotePort } catch { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "LogParse(CSV): Failed RemotePort conversion: $($output.RemotePort)"} }
            }
            return $output
        } catch {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "LogParse: Failed to parse/normalize CSV record: $($CsvRecord | Out-String). Error: $($_.Exception.Message)" }
            return $null
        }
    }
}