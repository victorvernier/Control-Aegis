# CliBlockedDomains.ps1
# Implements the internal logic for managing blocked domains (Hosts file and Config).
# Handles interaction with HostsModule, ConfigModule, and CoreFunctions.

# Internal logic to add a domain to the blocked list (hosts file and config).
function Cli-AddBlockedDomain {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)]
        [string]$domain
    )

    Write-Log "INFO" "CliBlockedDomains: Attempting to add domain '$domain'..."

    if (-not (Validate-Domain $domain)) { # Call without global:
        Write-Log "ERROR" "CliBlockedDomains: Invalid domain format: '$domain'."
        Write-Host "ERRO: Formato de domínio inválido: $domain" -ForegroundColor Red
        return
    }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-HostsFile # Call without global: Backup BEFORE any changes

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliBlockedDomains(TESTING): Executing AddBlockedDomain for '$domain'."

        # Modify hosts file
        Hosts-AddEntry -domain $domain # Call without global:

        # Log for rollback
        Write-RollbackLog -action "Add-BlockedDomain" -details "Domínio: $domain" -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json; # Deep copy

        # Ensure structure exists in the copy
        if ($null -eq $configCopy) { $configCopy = [PSCustomObject]@{} }
        if (-not $configCopy.PSObject.Properties.Name.Contains('bloqueio')) { $configCopy | Add-Member NoteProperty 'bloqueio' ([PSCustomObject]@{}) }
        if (-not $configCopy.bloqueio.PSObject.Properties.Name.Contains('dominios_bloqueados')) { $configCopy.bloqueio | Add-Member NoteProperty 'dominios_bloqueados' @() }
        if ($configCopy.bloqueio.dominios_bloqueados -isnot [array]) { $configCopy.bloqueio.dominios_bloqueados = @($configCopy.bloqueio.dominios_bloqueados) } # Ensure array

        # Add the domain to the copy if it doesn't exist
        if ($domain -notin $configCopy.bloqueio.dominios_bloqueados) {
            $configCopy.bloqueio.dominios_bloqueados = ($configCopy.bloqueio.dominios_bloqueados + $domain) | Sort-Object -Unique
            Write-Log "DEBUG" "CliBlockedDomains: Domain '$domain' added to list (in config copy)."
            # Save the modified copy
            Save-Config -configObjectToSave $configCopy # Call without global:
            Write-Log "INFO" "CliBlockedDomains: Domain '$domain' added to hosts file and config."
            Write-Host "Domínio '$domain' adicionado com sucesso." -ForegroundColor Green
        } else {
            Write-Log "WARN" "CliBlockedDomains: Domain '$domain' already in list. Config not saved."
            Write-Host "AVISO: Domínio '$domain' já existe na configuração." -ForegroundColor Yellow
        }

    } catch {
        Write-Log "ERROR" "CliBlockedDomains: Failed to add domain '$domain': $($_.Exception.Message)"
        Write-Host "ERRO ao adicionar domínio '$domain': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Internal logic to remove a domain from the blocked list (hosts file and config).
function Cli-RemoveBlockedDomain {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param (
        [Parameter(Mandatory = $true)]
        [string]$domain
    )

    Write-Log "INFO" "CliBlockedDomains: Attempting to remove domain '$domain'..."

    if (-not (Validate-Domain $domain)) { # Call without global:
        Write-Log "ERROR" "CliBlockedDomains: Invalid domain format for removal: '$domain'."
        Write-Host "ERRO: Formato de domínio inválido: $domain" -ForegroundColor Red
        return
    }

    $backupFilePath = $null
    try {
        $backupFilePath = Backup-HostsFile # Call without global: Backup BEFORE any changes

        # Execute directly (ShouldProcess removed)
        Write-Log "INFO" "CliBlockedDomains(TESTING): Executing RemoveBlockedDomain for '$domain'."

        # Modify hosts file
        Hosts-RemoveEntry -domain $domain # Call without global:

        # Log for rollback
        Write-RollbackLog -action "Remove-BlockedDomain" -details "Domínio: $domain" -backupPath $backupFilePath # Call without global:

        # Modify configuration based on a copy of the in-memory state ($Global:AppConfig)
        if ($null -eq $Global:AppConfig) { throw "Global configuration \$Global:AppConfig is not defined." }
        $configCopy = $Global:AppConfig | ConvertTo-Json -Depth 10 | ConvertFrom-Json; # Deep copy

        $configModified = $false

        # Check if config structure exists in the copy
        if ($configCopy.PSObject.Properties.Name.Contains('bloqueio') -and $configCopy.bloqueio.PSObject.Properties.Name.Contains('dominios_bloqueados')) {
            # Ensure it's an array
            if ($configCopy.bloqueio.dominios_bloqueados -is [array]) {
                $initialCount = $configCopy.bloqueio.dominios_bloqueados.Count
                # Remove the domain from the copy
                $configCopy.bloqueio.dominios_bloqueados = ($configCopy.bloqueio.dominios_bloqueados | Where-Object { $_ -ne $domain }) | Sort-Object -Unique
                # Check if count decreased
                if ($configCopy.bloqueio.dominios_bloqueados.Count -lt $initialCount) {
                    $configModified = $true
                    Write-Log "INFO" "CliBlockedDomains: Domain '$domain' removed from list (in config copy)."
                } else {
                    Write-Log "WARN" "CliBlockedDomains: Domain '$domain' not found in config list to remove."
                    Write-Host "AVISO: Domínio '$domain' não encontrado na configuração." -ForegroundColor Yellow
                }
            } else {
                 Write-Log "WARN" "CliBlockedDomains: Key 'dominios_bloqueados' is not an array."
                 Write-Host "AVISO: Configuração interna para domínios bloqueados inconsistente." -ForegroundColor Yellow
            }
        } else {
            Write-Log "WARN" "CliBlockedDomains: Blocked domain list not found in config."
            Write-Host "AVISO: Nenhum domínio bloqueado encontrado na configuração." -ForegroundColor Yellow
        }

        # Save the copy only if it was modified
        if ($configModified) {
            Save-Config -configObjectToSave $configCopy # Call without global:
            Write-Host "Domínio '$domain' removido." -ForegroundColor Green
        } else {
            Write-Host "Nenhuma alteração feita na configuração (domínio não encontrado)." -ForegroundColor Yellow
        }

    } catch {
        Write-Log "ERROR" "CliBlockedDomains: Failed to remove domain '$domain': $($_.Exception.Message)"
        Write-Host "ERRO ao remover domínio '$domain': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Lists configured blocked domains (reads from $Global:AppConfig via Get-ConfigValue).
function Cli-ListBlockedDomains {
    [CmdletBinding()]
    param ()

    try {
        $blockedDomainsValue = Get-ConfigValue -path "bloqueio.dominios_bloqueados" # Call without global:

        $blockedDomains = @() # Initialize as empty array
        if ($null -ne $blockedDomainsValue) {
            $blockedDomains = @($blockedDomainsValue) # Ensure array
        }

        if ($blockedDomains.Count -eq 0) {
            Write-Host "Nenhum domínio bloqueado na configuração." -ForegroundColor Yellow
            return
        }

        Write-Host "Domínios bloqueados na configuração:" -ForegroundColor Green
        # Sort for display
        foreach ($domain in ($blockedDomains | Sort-Object)) { Write-Host "- $domain" }

    } catch {
        Write-Log "ERROR" "CliBlockedDomains: Failed to list domains: $($_.Exception.Message)"
        Write-Host "ERRO ao listar domínios: $($_.Exception.Message)" -ForegroundColor Red
    }
}