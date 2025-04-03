# HostsModule.ps1
# Provides functions to interact with the system's hosts file for blocking domains.

# Adds a "0.0.0.0 domain" entry to the hosts file.
function Hosts-AddEntry {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter()]
        [string]$ipAddress = "0.0.0.0", # Currently hardcoded to block

        [Parameter(Mandatory=$true)]
        [string]$domain
    )

    if (-not (Validate-Domain $domain)) { # Call without global:
        throw "HostsModule: Invalid domain format: $domain"
    }
    if ($ipAddress -ne "0.0.0.0") {
        throw "HostsModule: Invalid IP address '$ipAddress'. Only '0.0.0.0' is supported by this function."
    }

    $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    $entryToAdd = "$ipAddress`t$domain" # Use Tab separator

    try {
        Write-Log "INFO" "HostsModule(TESTING): Executing AddEntry for '$entryToAdd' in '$hostsFilePath'."
        # Backup is handled by the caller

        # Check existence before adding
        $currentContent = Get-Content -Path $hostsFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($currentContent -match "^\s*$([regex]::Escape($ipAddress))\s+$([regex]::Escape($domain))\s*(`$|#)") {
            Write-Log "INFO" "HostsModule: Entry '$entryToAdd' already exists."
            Write-Host "WARNING: Hosts entry for '$domain' already exists." -ForegroundColor Yellow
            return
        }

        # Append the new entry
        $lastLine = $currentContent[-1]
        if ($lastLine -match '\S') { Add-Content -Path $hostsFilePath -Value "" -Encoding UTF8 }
        Add-Content -Path $hostsFilePath -Value $entryToAdd -Encoding UTF8 -ErrorAction Stop -Confirm:$false

        Write-Log "INFO" "HostsModule: Hosts entry added: $entryToAdd"
        # Rollback log is handled by the caller

    } catch {
        Write-Log "ERROR" "HostsModule: Failed to add entry '$entryToAdd': $($_.Exception.Message)"
        throw
    }
}

# Removes a "0.0.0.0 domain" entry from the hosts file.
# Uses StreamReader as an alternative read method attempt.
function Hosts-RemoveEntry {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)]
        [string]$domain
    )

    if (-not (Validate-Domain $domain)) { # Call without global:
        throw "HostsModule: Invalid domain format: $domain"
    }

    $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    $pattern = "^\s*0\.0\.0\.0\s+$([regex]::Escape($domain))\s*($|#.*)"

    try {
        Write-Log "INFO" "HostsModule(TESTING): Executing RemoveEntry for '$domain' (using StreamReader) in '$hostsFilePath'."
        # Backup is handled by the caller

        # --- Alternative Read Method using StreamReader ---
        $stream = $null
        $reader = $null
        $hostsContentLines = [System.Collections.Generic.List[string]]::new()
        $hostsContent = @() # Default to empty array
        try {
            if (-not (Test-Path $hostsFilePath -PathType Leaf)) { throw "Hosts file '$hostsFilePath' not found for reading."}
            # Attempt to open with Read access, allowing other readers
            $stream = [System.IO.File]::Open($hostsFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
            while($null -ne ($line = $reader.ReadLine())) {
                $hostsContentLines.Add($line)
            }
            $hostsContent = $hostsContentLines.ToArray() # Assign if read succeeded
            Write-Log "DEBUG" "HostsModule: Successfully read $($hostsContent.Length) lines from hosts file via StreamReader."
        } catch [System.IO.IOException] {
             # Catch specific IO errors during open/read
             Write-Log "ERROR" "HostsModule: IOException reading hosts file '$hostsFilePath' via StreamReader: $($_.Exception.Message)"
             # Check if the specific "stream not readable" error occurred
             if ($_.Exception.Message -like "*fluxo não era legível*") {
                 throw "Falha ao ler arquivo hosts (StreamReader): O fluxo não era legível. Possível bloqueio por AV/EDR?"
             } else {
                 throw "Falha ao ler arquivo hosts (StreamReader). Pode estar bloqueado por outro processo? $($_.Exception.Message)"
             }
        } catch {
            # Catch other potential errors during read setup
            Write-Log "ERROR" "HostsModule: Unexpected error reading hosts file '$hostsFilePath' via StreamReader: $($_.Exception.Message)"
            throw # Re-throw other errors
        } finally {
            # Ensure streams are closed if opened
            if ($reader -ne $null) { $reader.Close() } # Closes underlying stream too
            elseif ($stream -ne $null) { $stream.Close() }
        }
        # --- End Alternative Read Method ---

        $initialLineCount = $hostsContent.Length
        # Filter out lines matching the pattern
        $newHostsContent = $hostsContent | Where-Object { $_ -notmatch $pattern }

        # Only write back if content actually changed
        if ($newHostsContent.Count -lt $initialLineCount) {
            Set-Content -Path $hostsFilePath -Value $newHostsContent -Encoding UTF8 -Force -ErrorAction Stop -Confirm:$false
            Write-Log "INFO" "HostsModule: Hosts entry removed for '$domain'."
            # Rollback log is handled by the caller
        } else {
            Write-Log "WARN" "HostsModule: No hosts entry found to remove for '$domain'."
            Write-Host "WARNING: No hosts entry found to remove for '$domain'." -ForegroundColor Yellow
        }
    } catch {
        # Catch errors from the main try block (including re-thrown read errors)
        Write-Log "ERROR" "HostsModule: Failed to remove entry for '$domain': $($_.Exception.Message)"
        throw
    }
}

# Checks if a specific "IP domain" entry exists in the hosts file.
function Hosts-TestEntry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$domain,

        [Parameter(Mandatory = $false)]
        [string]$ipAddress = "0.0.0.0"
    )
    try {
        $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
        if (-not (Test-Path $hostsFilePath)) { return $false }
        $pattern = "^\s*$([regex]::Escape($ipAddress))\s+$([regex]::Escape($domain))\s*($|#.*)"
        return (Select-String -Path $hostsFilePath -Pattern $pattern -Quiet -Encoding UTF8 -ErrorAction SilentlyContinue)
    } catch {
        Write-Log "ERROR" "HostsModule: Failed to test entry for '$domain': $($_.Exception.Message)"
        throw
    }
}