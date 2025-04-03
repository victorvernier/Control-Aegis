# CliBlockedPorts.ps1
# Implements the internal logic for managing blocked ports (Firewall Block Rules).
# Handles interaction with FirewallModule, ConfigModule, and CoreFunctions.

# Internal logic to add a blocked port rule and update configuration.
function Cli-AddBlockedPort {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)] [ValidateSet("TCP", "UDP")] [string]$protocol,
        [Parameter(Mandatory = $true)] [int]$port,
        [Parameter(Mandatory = $false)] [ValidateSet("inbound", "outbound")] [string]$direction
    )

    # Determine effective direction, defaulting to outbound if not specified.
    $effectiveDirection = "outbound"
    if ($PSBoundParameters.ContainsKey('direction') -and -not [string]::IsNullOrWhiteSpace($direction)) {
        $effectiveDirection = $direction
    } else {
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "CliBlockedPorts: Direction not specified, using default '$effectiveDirection'." }
    }

    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "CliBlockedPorts: Attempting to block Port $protocol/$port ($effectiveDirection)..." }
    if ($port -lt 0 -or $port -gt 65535) { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "CliBlockedPorts: Invalid port: $port" }; Write-Host "ERRO: Porta inválida: $port." -ForegroundColor Red; return }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-FirewallConfig # Call without global:
        $ruleNameSuffix = "Block_${protocol}_${port}_${effectiveDirection}"

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliBlockedPorts(TESTING): Executing AddBlockedPort for CA_$ruleNameSuffix."

        Firewall-AddRule -direction $effectiveDirection -action "block" -protocol $protocol -port $port -name $ruleNameSuffix -remoteip $null # Call without global:

        Write-RollbackLog -action "Add-BlockedPort" -details "Protocolo: $protocol, Porta: $port, Direção: $effectiveDirection" -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json; # Deep copy

        $configKey = "portas_$($protocol.ToLower())"
        # Ensure structure exists in the copy
        if ($null -eq $configCopy) { $configCopy = [PSCustomObject]@{} }
        if (-not $configCopy.PSObject.Properties.Name.Contains('bloqueio')) { $configCopy | Add-Member NoteProperty 'bloqueio' ([PSCustomObject]@{}) }
        if (-not $configCopy.bloqueio.PSObject.Properties.Name.Contains($configKey)) { $configCopy.bloqueio | Add-Member NoteProperty $configKey @() }
        if ($configCopy.bloqueio.$configKey -isnot [array]) { $configCopy.bloqueio.$configKey = @($configCopy.bloqueio.$configKey) } # Ensure array

        # Add port to the copy if it doesn't exist
        if ($port -notin $configCopy.bloqueio.$configKey) {
            $configCopy.bloqueio.$configKey = ($configCopy.bloqueio.$configKey + $port) | Sort-Object -Unique
            Write-Log "DEBUG" "CliBlockedPorts: Port $port added to list '$configKey' (in config copy)."
            # Save the modified copy
            Save-Config -configObjectToSave $configCopy # Call without global:
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "CliBlockedPorts: Port $protocol/$port ($effectiveDirection) blocked (Rule CA_$ruleNameSuffix)." }
            Write-Host "Porta $protocol/$port ($effectiveDirection) bloqueada." -ForegroundColor Green
        } else {
             Write-Log "WARN" "CliBlockedPorts: Port $protocol/$port already in list '$configKey'. Config not saved."
             Write-Host "AVISO: Porta $protocol/$port já existe na configuração." -ForegroundColor Yellow
        }

    } catch {
        $logMsg = "CliBlockedPorts: Failed to add block for {0}/{1} ({2}): {3}" -f $protocol, $port, $effectiveDirection, $_.Exception.Message
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" $logMsg }
        $consoleMsg = "ERRO add bloqueio {0}/{1} ({2}): {3}" -f $protocol, $port, $effectiveDirection, $_.Exception.Message; Write-Host $consoleMsg -ForegroundColor Red
    }
}

# Internal logic to remove a blocked port rule and update configuration.
function Cli-RemoveBlockedPort {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)] [ValidateSet("TCP", "UDP")] [string]$protocol,
        [Parameter(Mandatory = $true)] [int]$port,
        [Parameter(Mandatory = $false)] [ValidateSet("inbound", "outbound")] [string]$direction
    )

    # Determine effective direction, defaulting to outbound if not specified.
    $effectiveDirection = "outbound"
    if ($PSBoundParameters.ContainsKey('direction') -and -not [string]::IsNullOrWhiteSpace($direction)) { $effectiveDirection = $direction }
    else { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "DEBUG" "CliBlockedPorts: Remove direction not specified, using default '$effectiveDirection'."} }

    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "INFO" "CliBlockedPorts: Attempting to remove block for Port $protocol/$port ($effectiveDirection)..." }
    if ($port -lt 0 -or $port -gt 65535) { if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" "CliBlockedPorts: Invalid port for removal: $port" }; Write-Host "ERRO: Porta inválida: $port." -ForegroundColor Red; return }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-FirewallConfig # Call without global:
        $ruleNameSuffix = "Block_${protocol}_${port}_${effectiveDirection}"

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliBlockedPorts(TESTING): Executing RemoveBlockedPort for CA_$ruleNameSuffix."

        Firewall-RemoveRule -name $ruleNameSuffix # Call without global:

        Write-RollbackLog -action "Remove-BlockedPort" -details "Protocolo: $protocol, Porta: $port, Direção: $effectiveDirection" -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json; # Deep copy

        $configKey = "portas_$($protocol.ToLower())"
        $configModified = $false

        # Check if config structure exists in the copy
        if ($configCopy.PSObject.Properties.Name.Contains('bloqueio') -and $configCopy.bloqueio.PSObject.Properties.Name.Contains($configKey)) {
            # Ensure it's an array
            if ($configCopy.bloqueio.$configKey -is [array]) {
                $currentPorts = $configCopy.bloqueio.$configKey
                $initialCount = $currentPorts.Count
                # Remove the port from the copy
                $configCopy.bloqueio.$configKey = ($currentPorts | Where-Object { $_ -ne $port }) | Sort-Object -Unique
                # Check if the count decreased
                if ($configCopy.bloqueio.$configKey.Count -lt $initialCount) {
                    $configModified = $true
                    Write-Log "INFO" "CliBlockedPorts: Port $protocol/$port removed from list '$configKey' (in config copy)."
                } else {
                    if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "CliBlockedPorts: Port $protocol/$port not found in config list '$configKey' to remove." }
                    Write-Host "AVISO: Porta $protocol/$port não encontrada na configuração." -ForegroundColor Yellow
                }
            } else {
                 if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "CliBlockedPorts: Config key '$configKey' is not an array." }
                 Write-Host "AVISO: Configuração interna para portas $protocol inconsistente." -ForegroundColor Yellow
            }
        } else {
            if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "WARN" "CliBlockedPorts: Blocked port list '$configKey' not found in config." }
            Write-Host "AVISO: Nenhuma porta $protocol bloqueada encontrada na configuração." -ForegroundColor Yellow
        }

        # Save the copy only if it was modified
        if ($configModified) {
            Save-Config -configObjectToSave $configCopy # Call without global:
            Write-Host "Bloqueio porta $protocol/$port ($effectiveDirection) removido." -ForegroundColor Green
        } else {
             Write-Host "Nenhuma alteração feita na configuração (porta não encontrada)." -ForegroundColor Yellow
        }

    } catch {
        $logMsg = "CliBlockedPorts: Failed to remove block for {0}/{1} ({2}): {3}" -f $protocol, $port, $effectiveDirection, $_.Exception.Message
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" $logMsg }
        $consoleMsg = "ERRO rem bloqueio {0}/{1} ({2}): {3}" -f $protocol, $port, $effectiveDirection, $_.Exception.Message; Write-Host $consoleMsg -ForegroundColor Red
    }
}

# Lists configured blocked ports (reads from $Global:AppConfig via Get-ConfigValue).
function Cli-ListBlockedPorts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "UDP")]
        [string]$protocol
    )
    try {
        $configKey = "bloqueio.portas_$($protocol.ToLower())"
        # Use Get-ConfigValue which reads from the in-memory $Global:AppConfig
        $blockedPortsValue = Get-ConfigValue -path $configKey # Call without global:

        $blockedPorts = @() # Initialize as empty array
        if ($null -ne $blockedPortsValue) {
            # Ensure it's an array even if config has only one value
            $blockedPorts = @($blockedPortsValue)
        }

        if ($blockedPorts.Count -eq 0) {
            Write-Host "Nenhuma porta $protocol bloqueada na configuração." -ForegroundColor Yellow
            return
        }

        Write-Host "Portas $protocol bloqueadas na configuração:" -ForegroundColor Green
        # Ensure uniqueness and sort for display
        foreach ($port in ($blockedPorts | Sort-Object -Unique)) { Write-Host "- $port" }

    } catch {
        $logMsg = "CliBlockedPorts: Failed to list {0} ports: {1}" -f $protocol, $_.Exception.Message
        if(Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "ERROR" $logMsg }
        $consoleMsg = "ERRO ao listar portas {0}: {1}" -f $protocol, $_.Exception.Message; Write-Host $consoleMsg -ForegroundColor Red
    }
}