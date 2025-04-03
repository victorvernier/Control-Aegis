# CliExceptions.ps1
# Implements the internal logic for managing ControlAegis exceptions (Firewall Allow Rules).
# Handles interaction with FirewallModule, ConfigModule, and CoreFunctions.

# Internal logic to add a firewall exception rule and update configuration.
function Cli-AddException {
    [CmdletBinding(DefaultParameterSetName = 'IP')] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)] [ValidateSet("TCP", "UDP")] [string]$protocol,
        [Parameter(Mandatory = $true)] [int]$port,
        [Parameter(ParameterSetName = 'IP', Mandatory = $true)] [string]$remoteip,
        [Parameter(ParameterSetName = 'Domain', Mandatory = $true)] [string]$domain,
        [Parameter()] [ValidateSet("inbound", "outbound")] [string]$direction = "outbound"
    )

    Write-Log "INFO" "CliExceptions: Attempting to add exception $protocol/$port ($direction) - IP:'$remoteip' Domain:'$domain'..."

    # Input Validation
    if ($port -lt 0 -or $port -gt 65535) { Write-Log "ERROR" "CliExceptions: Invalid port: $port"; Write-Host "ERRO: Porta inválida: $port." -ForegroundColor Red; return }
    if ($pscmdlet.ParameterSetName -eq 'IP' -and -not (Validate-IPAddress $remoteip)) { Write-Log "ERROR" "CliExceptions: Invalid IP address: $remoteip"; Write-Host "ERRO: IP inválido: $remoteip" -ForegroundColor Red; return }
    if ($pscmdlet.ParameterSetName -eq 'Domain' -and -not (Validate-Domain $domain)) { Write-Log "ERROR" "CliExceptions: Invalid domain: $domain"; Write-Host "ERRO: Domínio inválido: $domain" -ForegroundColor Red; return }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-FirewallConfig # Call without global:

        # Generate a descriptive rule name suffix based on parameters
        $ruleTarget = if ($pscmdlet.ParameterSetName -eq 'IP') { $remoteip } else { $domain }
        $sanitizedTarget = $ruleTarget -replace '[^a-zA-Z0-9.-]', '_' # Sanitize for rule name
        $ruleNameSuffixBase = "Allow_${protocol}_${port}_${direction}_$($sanitizedTarget)"
        # Truncate rule name suffix if potentially too long (using a safe limit)
        $ruleNameSuffix = $ruleNameSuffixBase.Substring(0, [System.Math]::Min(255, $ruleNameSuffixBase.Length))

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliExceptions(TESTING): Executing AddException for CA_$ruleNameSuffix."

        # Prepare parameters for Firewall-AddRule
        $paramsFirewall = @{
            Name        = $ruleNameSuffix
            Direction   = $direction
            Action      = "allow"
            Protocol    = $protocol.ToUpper() # Ensure uppercase
            Port        = $port
            RemoteIP    = $null # Default to null (Any for general rules)
            DisplayName = "Allow $protocol/$port ($direction) for $ruleTarget (ControlAegis)"
            Enabled     = "True"
        }
        if ($pscmdlet.ParameterSetName -eq 'IP') { $paramsFirewall['RemoteIP'] = $remoteip }

        # Add the rule to the firewall
        Firewall-AddRule @paramsFirewall # Call without global:

        # Log action for rollback
        $details = "Protocolo: $protocol, Porta: $port, Direção: $direction"
        if ($pscmdlet.ParameterSetName -eq 'IP') { $details += ", IP Remoto: $remoteip" }
        if ($pscmdlet.ParameterSetName -eq 'Domain') { $details += ", Domínio: $domain" }
        Write-RollbackLog -action "Add-Exception" -details $details -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json # Deep copy

        $configKey = "portas_$($protocol.ToLower())"

        # Ensure configuration structure exists in the copy
        if ($null -eq $configCopy) { $configCopy = [PSCustomObject]@{} }
        if (-not $configCopy.PSObject.Properties.Name.Contains('excecoes')) { $configCopy | Add-Member NoteProperty 'excecoes' ([PSCustomObject]@{}) }
        if (-not $configCopy.excecoes.PSObject.Properties.Name.Contains($configKey)) { $configCopy.excecoes | Add-Member NoteProperty $configKey @() }
        if (-not $configCopy.excecoes.PSObject.Properties.Name.Contains('dominios_permitidos')) { $configCopy.excecoes | Add-Member NoteProperty 'dominios_permitidos' @() }
        if ($configCopy.excecoes.$configKey -isnot [array]) { $configCopy.excecoes.$configKey = @($configCopy.excecoes.$configKey) } # Ensure array

        # Create the new exception object
        $newException = [PSCustomObject]@{
            porta     = $port
            protocolo = $protocol.ToUpper()
            direcao   = $direction
            tipo      = if ($pscmdlet.ParameterSetName -eq 'IP' -or $pscmdlet.ParameterSetName -eq 'Domain') { $null } else { 'geral' } # Mark specific vs general
            remoteip  = if ($pscmdlet.ParameterSetName -eq 'IP') { $remoteip } else { $null }
            dominio   = if ($pscmdlet.ParameterSetName -eq 'Domain') { $domain } else { $null }
        }

        # Check for duplicates before adding to the config copy
        $isDuplicate = $false
        foreach ($existingEx in $configCopy.excecoes.$configKey) {
             if ($existingEx.porta -eq $newException.porta -and
                 $existingEx.protocolo -eq $newException.protocolo -and
                 $existingEx.direcao -eq $newException.direcao -and
                 $existingEx.tipo -eq $newException.tipo -and
                 $existingEx.remoteip -eq $newException.remoteip -and
                 $existingEx.dominio -eq $newException.dominio) {
                 $isDuplicate = $true; break
             }
        }

        if (-not $isDuplicate) {
             $configCopy.excecoes.$configKey += $newException # Add to array in copy
             Write-Log "DEBUG" "CliExceptions: Exception added to list '$configKey' (in config copy)."
        } else {
             Write-Log "WARN" "CliExceptions: Duplicate exception not added to config: $details"
             Write-Host "AVISO: Exceção já existe na configuração." -ForegroundColor Yellow
        }

        # Add domain to allowed list if it's a domain-specific exception (in copy)
        if ($pscmdlet.ParameterSetName -eq 'Domain') {
            if ($configCopy.excecoes.dominios_permitidos -isnot [array]) { $configCopy.excecoes.dominios_permitidos = @($configCopy.excecoes.dominios_permitidos) }
             if ($domain -notin $configCopy.excecoes.dominios_permitidos) {
                 $configCopy.excecoes.dominios_permitidos = ($configCopy.excecoes.dominios_permitidos + $domain) | Sort-Object -Unique
                 Write-Log "DEBUG" "CliExceptions: Domain '$domain' added/ensured in 'dominios_permitidos' (in config copy)."
             }
        }

        # Save the modified copy (Save-Config validates again and updates $Global:AppConfig)
        Save-Config -configObjectToSave $configCopy # Call without global:

        Write-Log "INFO" "CliExceptions: Exception added (Rule CA_$ruleNameSuffix): $details"
        Write-Host "Exceção adicionada para '$ruleTarget'." -ForegroundColor Green

    } catch {
        Write-Log "ERROR" "CliExceptions: Failed to add exception: $($_.Exception.Message)"
        Write-Host "ERRO ao adicionar exceção: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Internal logic to remove a firewall exception rule and update configuration.
function Cli-RemoveException {
    [CmdletBinding(DefaultParameterSetName = 'IP')] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)] [ValidateSet("TCP", "UDP")] [string]$protocol,
        [Parameter(Mandatory = $true)] [int]$port,
        [Parameter(ParameterSetName = 'IP', Mandatory=$true)] [string]$remoteip,
        [Parameter(ParameterSetName = 'Domain', Mandatory=$true)] [string]$domain,
        [Parameter()] [ValidateSet("inbound", "outbound")] [string]$direction = "outbound"
    )

    Write-Log "INFO" "CliExceptions: Attempting to remove exception $protocol/$port ($direction) - IP:'$remoteip' Domain:'$domain'..."

    # Basic port validation
    if ($port -lt 0 -or $port -gt 65535) { Write-Log "ERROR" "CliExceptions: Invalid port: $port"; Write-Host "ERRO: Porta inválida: $port." -ForegroundColor Red; return }
    # Format validation is optional on remove, issue only warning
    if ($pscmdlet.ParameterSetName -eq 'IP' -and -not (Validate-IPAddress $remoteip)) { Write-Log "WARN" "CliExceptions(Remove): Invalid IP format provided: $remoteip" }
    if ($pscmdlet.ParameterSetName -eq 'Domain' -and -not (Validate-Domain $domain)) { Write-Log "WARN" "CliExceptions(Remove): Invalid domain format provided: $domain" }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-FirewallConfig # Call without global:

        # Reconstruct the rule name suffix to remove based on parameters
        $ruleTarget = if ($pscmdlet.ParameterSetName -eq 'IP') { $remoteip } else { $domain }
        $sanitizedTarget = $ruleTarget -replace '[^a-zA-Z0-9.-]', '_'
        $ruleNameSuffixBase = "Allow_${protocol}_${port}_${direction}_$($sanitizedTarget)"
        $ruleNameSuffix = $ruleNameSuffixBase.Substring(0, [System.Math]::Min(255, $ruleNameSuffixBase.Length)) # Use same truncation

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliExceptions(TESTING): Executing RemoveException for CA_$ruleNameSuffix."

        # Attempt to remove the rule from the firewall
        Firewall-RemoveRule -name $ruleNameSuffix # Call without global:
        # Note: Firewall-RemoveRule currently throws if netsh fails, but might not error if rule simply doesn't exist.

        # Log action for rollback (log even if rule/config didn't exist, to allow rollback of mistaken removal)
        $details = "Protocolo: $protocol, Porta: $port, Direção: $direction"; if ($pscmdlet.ParameterSetName -eq 'IP') { $details += ", IP Remoto: $remoteip" }; if ($pscmdlet.ParameterSetName -eq 'Domain') { $details += ", Domínio: $domain" }
        Write-RollbackLog -action "Remove-Exception" -details $details -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json; # Deep copy

        $configKey = "portas_$($protocol.ToLower())"; $configModified = $false

        # Check if the exception list exists in the copy
        if ($configCopy.excecoes -and $configCopy.excecoes.PSObject.Properties.Name.Contains($configKey) -and $configCopy.excecoes.$configKey -is [array]) {
            $currentExceptions = $configCopy.excecoes.$configKey
            $initialCount = $currentExceptions.Count

            # Filter the list in the copy, keeping only entries that DO NOT match the removal criteria
            $configCopy.excecoes.$configKey = $currentExceptions | Where-Object {
                $ex = $_
                $match = $false # Assume it doesn't match by default
                if ($ex.porta -eq $port -and $ex.protocolo -eq $protocol.ToUpper() -and $ex.direcao -eq $direction) {
                     # Match base criteria, now check specific target unless it's a general rule
                     $isGeneralRule = ($ex.PSObject.Properties.Name -contains 'tipo' -and $ex.tipo -eq 'geral')
                     if (-not $isGeneralRule) {
                         if ($pscmdlet.ParameterSetName -eq 'IP' -and $ex.remoteip -eq $remoteip) {
                             $match = $true # Matches specific IP exception
                         } elseif ($pscmdlet.ParameterSetName -eq 'Domain' -and $ex.dominio -eq $domain) {
                             $match = $true # Matches specific Domain exception
                         }
                     }
                     # Note: This logic will NOT remove 'geral' type exceptions via this function.
                }
                -not $match # Return true if it does NOT match (to keep it)
            }

            # Check if the count decreased, meaning something was removed from the copy
            if ($configCopy.excecoes.$configKey.Count -lt $initialCount) {
                Write-Log "INFO" "CliExceptions: Exception removed from list '$configKey' (in config copy)."
                $configModified = $true
            } else {
                Write-Log "WARN" "CliExceptions: Matching exception not found in config list '$configKey' to remove."
                Write-Host "AVISO: Exceção não encontrada na configuração para remover." -ForegroundColor Yellow
            }
        } else { Write-Log "WARN" "CliExceptions: Exception list '$configKey' not found in config." }

        # Remove domain from allowed list if a domain exception was successfully removed from the config copy
        if ($configModified -and $pscmdlet.ParameterSetName -eq 'Domain') {
            if ($configCopy.excecoes -and $configCopy.excecoes.PSObject.Properties.Name.Contains('dominios_permitidos') -and $configCopy.excecoes.dominios_permitidos -is [array]) {
                 $domPermInitialCount = $configCopy.excecoes.dominios_permitidos.Count
                 $configCopy.excecoes.dominios_permitidos = ($configCopy.excecoes.dominios_permitidos | Where-Object { $_ -ne $domain }) | Sort-Object -Unique
                 if($configCopy.excecoes.dominios_permitidos.Count -lt $domPermInitialCount) {
                     Write-Log "INFO" "CliExceptions: Domain '$domain' removed from 'dominios_permitidos' list (in config copy)."
                     # $configModified is already true
                 }
            }
        }

        # Save the modified copy back only if changes were made to it
        if ($configModified) {
            Save-Config -configObjectToSave $configCopy # Call without global:
            Write-Host "Exceção para '$ruleTarget' removida." -ForegroundColor Green
        } else {
             Write-Host "Nenhuma alteração feita na configuração (exceção não encontrada)." -ForegroundColor Yellow
        }

    } catch {
        Write-Log "ERROR" "CliExceptions: Failed to remove exception: $($_.Exception.Message)"
        Write-Host "ERRO ao remover exceção: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Lists configured exceptions (reads from disk via Load-Config).
function Cli-ListExceptions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("TCP", "UDP")]
        [string]$protocol # Optional: filter by protocol
    )
    try {
        # Load config directly from disk for listing to ensure accuracy
        $config = Load-Config # Call without global:

        Write-Host "`nConfigured Exceptions List:" -ForegroundColor Green
        if (-not $config.excecoes) { Write-Host "No 'excecoes' section found in configuration." -ForegroundColor Yellow; return }

        $foundException = $false
        $protocolsToList = if ($PSBoundParameters.ContainsKey('protocol')) { @($protocol) } else { @('TCP', 'UDP') }
        $configSections = @{ TCP = 'portas_tcp'; UDP = 'portas_udp' }

        foreach ($proto in $protocolsToList) {
            $configKey = $configSections[$proto]
            if ($config.excecoes.PSObject.Properties.Name.Contains($configKey)) {
                 if ($config.excecoes.$configKey -is [array] -and $config.excecoes.$configKey.Count -gt 0) {
                    Write-Host "`n  $proto Exceptions:" -ForegroundColor Cyan
                    # Sort for consistent display: general first, then by port, then target
                    $sortedExceptions = $config.excecoes.$configKey | Sort-Object @{E={if($_.tipo -eq 'geral'){0}else{1}}}, port, remoteip, dominio
                    foreach ($exception in $sortedExceptions) {
                         $details = "- Port: $($exception.porta)"
                         # Safely access potentially missing properties
                         $protoDisplay = if ($exception.PSObject.Properties.Name -contains 'protocolo'){$exception.protocolo}else{$proto}
                         $dirDisplay = if ($exception.PSObject.Properties.Name -contains 'direcao'){$exception.direcao}else{'<N/A>'}
                         $details += ", Proto: $protoDisplay, Dir: $dirDisplay"
                         if ($exception.PSObject.Properties.Name -contains 'tipo' -and $exception.tipo -eq 'geral') {
                             $details += " (General Rule - Any IP)"
                         } else {
                             if ($exception.PSObject.Properties.Name -contains 'remoteip' -and $exception.remoteip) { $details += ", IP: $($exception.remoteip)" }
                             if ($exception.PSObject.Properties.Name -contains 'dominio' -and $exception.dominio) { $details += ", Domain: $($exception.dominio)" }
                         }
                         Write-Host "    $details"
                         $foundException = $true
                    }
                 } elseif (-not $PSBoundParameters.ContainsKey('protocol')) { Write-Host "`n  $proto Exceptions: None." -ForegroundColor Yellow }
            } elseif (-not $PSBoundParameters.ContainsKey('protocol')) { Write-Host "`n  $proto Exceptions: Section '$configKey' not found." -ForegroundColor Yellow }
        }

         # List Allowed Domains separately if no protocol filter applied
         if (-not $PSBoundParameters.ContainsKey('protocol') -and $config.excecoes.PSObject.Properties.Name.Contains('dominios_permitidos')) {
             if ($config.excecoes.dominios_permitidos -is [array] -and $config.excecoes.dominios_permitidos.Count -gt 0) {
                 Write-Host "`n  Allowed Domains (from Domain Exceptions):" -ForegroundColor Cyan
                 foreach ($domain in ($config.excecoes.dominios_permitidos | Sort-Object)) { Write-Host "    - $domain"; $foundException = $true }
             } elseif (-not $PSBoundParameters.ContainsKey('protocol')) { Write-Host "`n  Allowed Domains: None." -ForegroundColor Yellow }
         }

        # Final messages if nothing was found
        if (-not $foundException -and $PSBoundParameters.ContainsKey('protocol')) { Write-Host "`nNo exceptions found for protocol $protocol." -ForegroundColor Yellow }
        elseif (-not $foundException) { Write-Host "`nNo exceptions configured." -ForegroundColor Yellow }
        Write-Host ""

    } catch {
        Write-Log "ERROR" "CliExceptions: Failed to list exceptions: $($_.Exception.Message)"
        Write-Host "ERRO ao listar exceções: $($_.Exception.Message)" -ForegroundColor Red
    }
}