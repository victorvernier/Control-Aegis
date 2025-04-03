# ConfigModule.ps1
# Provides functions for loading, saving, and interacting with config.json,
# including file locking for safe write operations.
# FINAL VERSION (Alt. Write Method): Uses internal helper function to resolve config path reliably
# and alternative FileStream writing in Save-Config.

# Holds the file stream for exclusive locking during write operations.
$script:configLockStream = $null

# Internal helper function to reliably get the full path to config.json
function _GetConfigPath {
    # Ensures it uses the current value of $Global:ProjectRoot every time
    if (-not $Global:ProjectRoot) { throw "Global:ProjectRoot is not defined when getting config path." }
    return (Join-Path $Global:ProjectRoot "config\config.json")
}

# Acquires an exclusive lock on the configuration file.
function Lock-Config {
    $localConfigPath = _GetConfigPath # Get path via helper
    if ($script:configLockStream) {
        Write-Log "WARN" "ConfigModule: Lock attempt ignored, already held: $localConfigPath."
        return
    }
    try {
        # Open with FileShare.None to ensure exclusive access for writing.
        $script:configLockStream = [System.IO.File]::Open($localConfigPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        Write-Log "DEBUG" "ConfigModule: Lock acquired: $localConfigPath."
    } catch [System.IO.IOException] {
        Write-Log "ERROR" "ConfigModule: Failed to lock '$localConfigPath'. File in use? Error: $($_.Exception.Message)"
        throw "Failed to lock '$localConfigPath'. Is it open elsewhere?"
    } catch {
        Write-Log "ERROR" "ConfigModule: Unexpected error locking '$localConfigPath': $($_.Exception.Message)"
        throw
    }
}

# Releases the exclusive lock on the configuration file.
function Unlock-Config {
    $localConfigPath = _GetConfigPath # Get path via helper (for logging)
    if ($script:configLockStream) {
        try {
            $script:configLockStream.Close()
            $script:configLockStream.Dispose()
            $script:configLockStream = $null
            Write-Log "DEBUG" "ConfigModule: Lock released: $localConfigPath."
        } catch {
            Write-Log "ERROR" "ConfigModule: Error releasing lock for '$localConfigPath': $($_.Exception.Message)"
            $script:configLockStream = $null
            throw
        }
    } else {
        Write-Log "DEBUG" "ConfigModule: Attempted to release a non-existent lock."
    }
}

# Loads, parses, and validates config.json.
function Load-Config {
    [CmdletBinding()]
    param()
    $localConfigPath = _GetConfigPath # Get path via helper
    Write-Host "DEBUG_LOADCONFIG: Inside Load-Config, using path '$localConfigPath'" # Keep debug line

    if (-not (Test-Path $localConfigPath -PathType Leaf)) {
        Write-Log "CRITICAL" "ConfigModule: Configuration file '$localConfigPath' not found."
        throw "Configuration file '$localConfigPath' not found."
    }

    $readStream = $null
    try {
        $readStream = [System.IO.File]::Open($localConfigPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $streamReader = [System.IO.StreamReader]::new($readStream, [System.Text.Encoding]::UTF8)
        $jsonContent = $streamReader.ReadToEnd()
        $streamReader.Close()

        $configObject = $jsonContent | ConvertFrom-Json -ErrorAction Stop
        [void](Validate-Config -config $configObject) # Call validator

        Write-Log "DEBUG" "ConfigModule: Configuration loaded and validated: '$localConfigPath'."
        return $configObject
    } catch {
        Write-Log "CRITICAL" "ConfigModule: Failed to load/parse/validate '$localConfigPath': $($_.Exception.Message)"
        if ($_.Exception -is [System.Management.Automation.RuntimeException] -and $_.Exception.InnerException -is [Newtonsoft.Json.JsonException]) {
             throw "Failed to load '$localConfigPath'. JSON Syntax Error?: $($_.Exception.InnerException.Message)"
        } elseif ($_.Exception.InnerException -is [System.Text.Json.JsonException]) {
             throw "Failed to load '$localConfigPath'. JSON Syntax Error?: $($_.Exception.InnerException.Message)"
        } elseif ($_.CategoryInfo.Activity -eq 'Validate-Config') {
             throw "Failed to load '$localConfigPath'. Configuration validation failed: $($_.Exception.Message)"
        } else {
             throw "Failed to load/parse/validate '$localConfigPath': $($_.Exception.Message)"
        }
    } finally {
        if ($readStream) {
            try { $readStream.Close(); $readStream.Dispose() } catch {
                 Write-Log "WARN" "ConfigModule: Exception closing/disposing read stream for '$localConfigPath': $($_.Exception.Message)"
            }
        }
    }
}

# Validates, saves the configuration object to config.json, and updates $Global:AppConfig.
function Save-Config {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$configObjectToSave
    )
    $localConfigPath = _GetConfigPath # Get path via helper

    try {
        [void](Validate-Config -config $configObjectToSave)
        Write-Log "DEBUG" "ConfigModule(Save): Configuration object passed validation."
    } catch {
        Write-Log "ERROR" "ConfigModule(Save): Attempted to save invalid configuration object: $($_.Exception.Message)"
        throw "Invalid configuration provided to Save-Config: $($_.Exception.Message)"
    }

    $Global:AppConfig = $configObjectToSave

    Lock-Config # Acquire exclusive lock
    $writer = $null # Define $writer outside try block for potential use in finally if needed (though not strictly necessary here)
    try {
        $jsonOutput = $configObjectToSave | ConvertTo-Json -Depth 10

        # --- Alternative Write Method using FileStream from Lock ---
        try {
            $stream = $script:configLockStream # Get stream from the existing lock
            if ($null -eq $stream) { throw "Lock stream is null, cannot write." } # Safety check
            $stream.SetLength(0) # Truncate the file to zero length
            # Use StreamWriter to write the string content; UTF8 encoding by default
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::UTF8)
            $writer.Write($jsonOutput)
            $writer.Flush() # Ensure buffer is flushed to the stream
            # DO NOT close the writer here, as it would close the underlying stream ($script:configLockStream)
            # Unlock-Config in the outer finally block will handle closing the stream.
            Write-Log "INFO" "ConfigModule: Configuration saved via FileStream: '$localConfigPath'."
        } catch {
            # Catch errors during the FileStream write operation
            Write-Log "ERROR" "ConfigModule: Failed to save (FileStream method) '$localConfigPath': $($_.Exception.Message)"
            throw # Re-throw inner exception to be caught by the outer catch
        }
        # --- End Alternative Write Method ---

        # Original Set-Content line is now replaced by the block above.
        # Set-Content -Path $localConfigPath -Value $jsonOutput -Encoding UTF8 -Force -ErrorAction Stop -Confirm:$false
        # Write-Log "INFO" "ConfigModule: Configuration saved: '$localConfigPath'."

    } catch {
        # Catch errors from Lock-Config, ConvertTo-Json, or the alternative write method
        Write-Log "ERROR" "ConfigModule: Failed during save operation for '$localConfigPath': $($_.Exception.Message)"
        throw # Re-throw to signal failure to the caller
    } finally {
        # $writer automatically disposed when $script:configLockStream is disposed by Unlock-Config
        Unlock-Config # Ensure lock is always released
    }
}

# Gets a specific value from the in-memory configuration ($Global:AppConfig) using dot notation path.
function Get-ConfigValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$path # e.g., "bloqueio.portas_tcp"
    )

    Write-Log "DEBUG" "Get-ConfigValue: Requested path '$path'."
    if ($null -eq $Global:AppConfig) { Write-Log "ERROR" "Get-ConfigValue: \$Global:AppConfig is NULL!"; throw "\$Global:AppConfig is not defined." }

    try {
        $value = $Global:AppConfig;
        $pathParts = $path.Split(".");

        foreach ($part in $pathParts) {
             $propertyExists = $false
             if ($value -ne $null) {
                 # Check PSCustomObject property or Hashtable key
                 if ($value -is [PSCustomObject] -and $value.PSObject.Properties[$part] -ne $null) {
                     $propertyExists = $true
                     $value = $value.$part
                 } elseif ($value -is [hashtable] -and $value.ContainsKey($part)) {
                     $propertyExists = $true
                     $value = $value[$part]
                 } elseif ($value -is [array] -and $part -match '^\d+$' -and [int]$part -ge 0 -and [int]$part -lt $value.Count) {
                     # Allow accessing array elements by index in path
                     $propertyExists = $true
                     $value = $value[[int]$part]
                 }
             }

             if (-not $propertyExists) {
                 Write-Log "WARN" "ConfigModule(Get-ConfigValue): Path '$path' (part: '$part') not found in config object."
                 return $null
             }
         }
        Write-Log "DEBUG" "ConfigModule(Get-ConfigValue): Value obtained for '$path'."
        return $value
    } catch {
        Write-Log "ERROR" "ConfigModule(Get-ConfigValue): Failed to get value for '$path': $($_.Exception.Message)"
        throw
    }
}


# Updates a specific value in the configuration file using dot notation path.
# Performs a read-modify-write operation under an exclusive lock.
function Update-ConfigValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$path, # e.g., "logs.log_rotation_size"

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$value
    )

    Lock-Config # Acquire exclusive lock
    try {
        # Load the LATEST configuration from disk to modify.
        $currentConfig = Load-Config
        # Create a deep copy to work on.
        $tempConfig = $currentConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json

        $targetObject = $tempConfig
        $pathParts = $path.Split(".")
        $finalProperty = $pathParts[-1]

        # Navigate nested structure to find the parent object.
        for ($i = 0; $i -lt $pathParts.Count - 1; $i++) {
            $part = $pathParts[$i]
            $propertyExists = $false
            if ($targetObject -ne $null) {
                 if ($targetObject -is [PSCustomObject] -and $targetObject.PSObject.Properties[$part] -ne $null) {
                     $propertyExists = $true
                     $targetObject = $targetObject.$part
                 } elseif ($targetObject -is [hashtable] -and $targetObject.ContainsKey($part)) {
                     $propertyExists = $true
                     $targetObject = $targetObject[$part]
                 }
            }
            if (-not $propertyExists) { throw "Invalid path '$path' (intermediate part '$part' not found)." }
        }

        # Update the final property on the target parent object.
        if ($targetObject -is [PSCustomObject]) {
             if ($targetObject.PSObject.Properties[$finalProperty] -ne $null) { $targetObject.PSObject.Properties.Remove($finalProperty) }
             $targetObject | Add-Member -MemberType NoteProperty -Name $finalProperty -Value $value -Force
        } elseif ($targetObject -is [hashtable]) {
            $targetObject[$finalProperty] = $value
        } else {
            $pathToParent = ($pathParts | Select-Object -SkipLast 1) -join '.'
            throw "Cannot set property '$finalProperty'. Parent object at path '$pathToParent' is not a modifiable object (PSCustomObject/Hashtable)."
        }

        # Save the modified structure back to disk.
        Save-Config -configObjectToSave $tempConfig # Save-Config validates and updates $Global:AppConfig

        Write-Log "INFO" "ConfigModule(Update-ConfigValue): Path '$path' updated and saved."
    } catch {
        Write-Log "ERROR" "ConfigModule(Update-ConfigValue): Failed to update path '$path': $($_.Exception.Message)"
        throw
    } finally {
        Unlock-Config # Ensure lock release
    }
}