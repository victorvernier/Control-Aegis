# ControlAegis.psm1
# Main module script coordinating network control (Hosts, Firewall) and logging features.

# --- Project Root Definition ---
# Ensure $Global:ProjectRoot is set, used by other modules to find dependencies.
$Global:ProjectRoot = Split-Path -Parent $PSCommandPath -Resolve
# --- DEBUG LINE ADDED ---
Write-Host "DEBUG_INIT: Global:ProjectRoot defined as '$($Global:ProjectRoot)'"
# --- END DEBUG LINE ---
# --- End Definition ---

# 1. Load Dependency Modules via Dot-Sourcing
# Errors during loading are critical and will terminate the script.
Write-Host "Loading ControlAegis modules..."
try {
    $coreModulePath = Join-Path $Global:ProjectRoot "core\CoreFunctions.ps1"
    $configModulePath = Join-Path $Global:ProjectRoot "modules\config\ConfigModule.ps1"
    $configValidationModulePath = Join-Path $Global:ProjectRoot "modules\config\ConfigValidation.ps1"
    $firewallModulePath = Join-Path $Global:ProjectRoot "modules\firewall\FirewallModule.ps1"
    $hostsModulePath = Join-Path $Global:ProjectRoot "modules\hosts\HostsModule.ps1"
    $logAnalysisModulePath = Join-Path $Global:ProjectRoot "modules\log_analysis\LogAnalysisModule.ps1" # Includes Get/Parse/Filter
    $cliBlockedDomainsModulePath = Join-Path $Global:ProjectRoot "modules\cli\CliBlockedDomains.ps1"
    $cliBlockedPortsModulePath = Join-Path $Global:ProjectRoot "modules\cli\CliBlockedPorts.ps1"
    $cliExceptionsModulePath = Join-Path $Global:ProjectRoot "modules\cli\CliExceptions.ps1"
    $rollbackModulePath = Join-Path $Global:ProjectRoot "modules\rollback\RollbackModule.ps1"

    # Load in dependency order (Core first, then others)
    . $coreModulePath
    . $configValidationModulePath # Depends on Core (Write-Log, Validators)
    . $configModulePath # Depends on Core, Validation
    . $firewallModulePath # Depends on Core
    . $hostsModulePath # Depends on Core
    . $logAnalysisModulePath # Depends on Core (and loads LogGet/Parse/Filter internally)
    . $rollbackModulePath # Depends on Core
    # Load CLI implementation modules last
    . $cliBlockedDomainsModulePath # Depends on Core, Config, Hosts, Rollback
    . $cliBlockedPortsModulePath # Depends on Core, Config, Firewall, Rollback
    . $cliExceptionsModulePath # Depends on Core, Config, Firewall, Rollback

    Write-Log "INFO" "ControlAegis: All modules loaded successfully."
} catch {
    # If Write-Log itself failed, this might not work, but attempt logging.
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "CRITICAL" "ControlAegis: Critical failure loading modules: $($_.Exception.Message)" }
    Write-Host "Critical Error: Failed to load dependency modules. Terminating." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1 # Terminate script if core modules cannot be loaded
}

# 2. Verify Administrative Privileges
# Internal function, not exported.
function Test-AdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-AdminPrivileges)) {
    Write-Log "ERROR" "ControlAegis: Administrative privileges required.";
    Write-Host "ERROR: This script requires administrative privileges to run." -ForegroundColor Red
    exit 1
} else {
    Write-Log "INFO" "ControlAegis: Admin privileges OK."
}

# 3. Define and Ensure Essential Paths
$configPath = Join-Path $Global:ProjectRoot "config" # Base config dir path
$defaultLogBasePath = Join-Path $Global:ProjectRoot "Logs" # Default logs dir path
$tempPath = Join-Path $Global:ProjectRoot "temp" # Base temp dir path
# Backup path defined/created within CoreFunctions
$configuredLogPath = $null # Will hold path from config if valid

Write-Host "Verifying/Creating required base directories..."
# Ensure base config and default log directories exist
foreach ($path in @($configPath, $defaultLogBasePath)) {
    if (-not (Test-Path -Path $path -PathType Container)) {
        Write-Host "Creating required directory: $path" -ForegroundColor Yellow
        try {
            New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
            Write-Log "INFO" "ControlAegis: Created directory: $path"
        } catch {
            Write-Log "CRITICAL" "ControlAegis: Failed to create '$path': $($_.Exception.Message)"
            Write-Host "Critical Error: Failed to create '$path'." -ForegroundColor Red
            exit 1
        }
    }
}
# Temp/Backup directories are created within CoreFunctions upon first use if needed.

# --- Initial State Application Functions (No ShouldProcess in Test Version) ---
function Apply-InitialHostsConfiguration {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param ( [Parameter(Mandatory = $true)] [PSObject]$Config )

    Write-Log "INFO" "ControlAegis: Synchronizing hosts file...";
    $backupFilePath = $null;
    $hostsFilePath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts";
    try {
        $backupFilePath = Backup-HostsFile # Call without global:
        $configuredDomains = @()
        # Check structure before accessing
        if ($Config.bloqueio -and $Config.bloqueio.PSObject.Properties.Name.Contains('dominios_bloqueados') -and $Config.bloqueio.dominios_bloqueados -is [array]) {
            # Validate domains from config, ignore invalid ones/wildcards for hosts file context
            $validDomains = $Config.bloqueio.dominios_bloqueados | Where-Object { Validate-Domain $_ } # Call without global:
            $invalidOrWildcard = $Config.bloqueio.dominios_bloqueados | Where-Object { -not (Validate-Domain $_) } # Call without global:
            if ($invalidOrWildcard) { Write-Log "WARN" "ControlAegis(HostsSync): Invalid/Wildcard domains ignored for hosts file: $($invalidOrWildcard -join ', ')"; Write-Host "WARNING: Invalid/Wildcard domains ignored for hosts file: $($invalidOrWildcard -join ', ')" -ForegroundColor Yellow }
            $configuredDomains = $validDomains | Select-Object -Unique
        } else { Write-Log "INFO" "ControlAegis(HostsSync): 'bloqueio.dominios_bloqueados' array not found or invalid in config." }

        if (-not (Test-Path $hostsFilePath -PathType Leaf)) { throw "Hosts file not found: $hostsFilePath" }

        $hostsContentLines = Get-Content -Path $hostsFilePath -Encoding UTF8 -ErrorAction Stop
        $newHostsContentLines = [System.Collections.Generic.List[string]]::new()
        $domainsToWrite = $configuredDomains
        $domainsToWriteSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($domainsToWrite.Count -gt 0) { foreach ($domain in $domainsToWrite) { [void]$domainsToWriteSet.Add($domain) } }

        $ipBlock = "0.0.0.0"
        # Process existing lines: Keep non-managed lines, keep managed lines if still in config, remove managed lines if no longer in config.
        foreach ($line in $hostsContentLines) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -match "^\s*$([regex]::Escape($ipBlock))\s+([\S]+)") { # Match lines starting with 0.0.0.0
                $domainInLine = $matches[1]
                if ($domainsToWriteSet.Contains($domainInLine)) {
                    $newHostsContentLines.Add($line) # Keep line, domain is still configured to be blocked
                    [void]$domainsToWriteSet.Remove($domainInLine) # Mark as processed
                } else {
                    Write-Log "DEBUG" "ControlAegis(HostsSync): Removing hosts entry for '$domainInLine' (not in config)." # Domain removed from config
                }
            } else {
                $newHostsContentLines.Add($line) # Keep comments and other lines
            }
        }

        # Add domains from config that were not found in the file
        $domainsToAddNow = $domainsToWriteSet
        if ($domainsToAddNow.Count -gt 0) {
             if ($newHostsContentLines.Count -gt 0 -and $newHostsContentLines[-1] -match '\S') { $newHostsContentLines.Add("") } # Add blank line if needed
             foreach ($domain in ($domainsToAddNow | Sort-Object)) {
                 Write-Log "DEBUG" "ControlAegis(HostsSync): Adding hosts entry for '$domain'."
                 $newHostsContentLines.Add("$ipBlock`t$domain") # Use Tab separator
             }
         }

        # Compare content and write only if changed
        if (($hostsContentLines -join "`n") -ne ($newHostsContentLines -join "`n")) {
            Write-Log "INFO" "ControlAegis(HostsSync): Hosts file differs from configuration. Updating..."
            # Execute directly (ShouldProcess removed)
            Write-Log "INFO" "ControlAegis(TESTING): Updating hosts file '$hostsFilePath'."
            Set-Content -Path $hostsFilePath -Value $newHostsContentLines -Encoding UTF8 -Force -ErrorAction Stop -Confirm:$false
            try {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                Write-Log "INFO" "ControlAegis(HostsSync): DNS Client Cache cleared."
            } catch { Write-Log "WARN" "ControlAegis(HostsSync): Failed to clear DNS Client Cache: $($_.Exception.Message)"}
            Write-Log "INFO" "ControlAegis: Hosts file synchronization completed (changes applied)."
        } else {
            Write-Log "INFO" "ControlAegis(HostsSync): Hosts file already synchronized."
            Write-Log "INFO" "ControlAegis: Hosts file synchronization completed (no changes)."
        }
    } catch { Write-Log "ERROR" "ControlAegis: Critical failure during hosts file sync: $($_.Exception.Message)"; Write-Host "ERROR: Failed hosts file sync." -ForegroundColor Red; throw }
}

function Apply-InitialFirewallConfiguration {
    [CmdletBinding()] # SupportsShouldProcess removed for testing
    param ( [Parameter(Mandatory = $true)] [PSObject]$Config )

    Write-Log "INFO" "ControlAegis: Synchronizing Firewall rules...";
    $backupFilePath = $null;
    try {
        $backupFilePath = Backup-FirewallConfig # Call without global:
        $existingRules = @{}
        (Firewall-GetRules) | ForEach-Object { $existingRules[$_.Name] = $_ } # Call without global:
        $existingRuleNames = $existingRules.Keys
        Write-Log "DEBUG" "ControlAegis(FirewallSync): Found $($existingRules.Count) existing CA_* rules."

        $desiredRules = @{} # Hashtable to store rules defined in config

        # Generate desired 'Block' rules from config
        foreach ($protocol in @("tcp", "udp")) {
            $configKey = "portas_$protocol"
            if ($Config.bloqueio -and $Config.bloqueio.PSObject.Properties.Name.Contains($configKey) -and $Config.bloqueio.$configKey -is [array]) {
                foreach ($port in $Config.bloqueio.$configKey | Where-Object {$_ -is [int] -and $_ -ge 0 -and $_ -le 65535}) {
                    # Assume block rules from config are always outbound unless specified otherwise (current default)
                    $ruleSuffix = "Block_${protocol}_${port}_outbound"
                    $ruleName = "CA_$ruleSuffix"
                    $desiredRules[$ruleName] = @{ Name = $ruleSuffix; Direction = "outbound"; Action = "block"; Protocol = $protocol.ToUpper(); Port = $port; RemoteIP = $null }
                }
            }
        }

        # Generate desired 'Allow' rules (exceptions) from config
        foreach ($protocolConfigKey in @("portas_tcp", "portas_udp")) {
            if ($Config.excecoes -and $Config.excecoes.PSObject.Properties.Name.Contains($protocolConfigKey) -and $Config.excecoes.$protocolConfigKey -is [array]) {
                foreach ($exception in $Config.excecoes.$protocolConfigKey) {
                    # Validate structure (already done by Validate-Config, but double-check basics)
                    if ($exception -is [PSCustomObject] -and
                        $exception.PSObject.Properties.Name -contains 'porta' -and ($exception.porta -is [int]) -and
                        $exception.PSObject.Properties.Name -contains 'protocolo' -and ($exception.protocolo -in @('TCP','UDP')) -and
                        $exception.PSObject.Properties.Name -contains 'direcao' -and ($exception.direcao -in @('inbound', 'outbound')) )
                    {
                        $port = $exception.porta; $proto = $exception.protocolo.ToUpper(); $dir = $exception.direcao
                        $isGeneral = $exception.PSObject.Properties.Name -contains 'tipo' -and $exception.tipo -eq 'geral'
                        $remoteIp = if($exception.PSObject.Properties.Name -contains 'remoteip') { $exception.remoteip } else { $null }

                        $ruleNameSuffix = $null
                        $ruleParams = @{ Direction = $dir; Action = "allow"; Protocol = $proto; Port = $port }

                        if ($isGeneral) {
                             $ruleSuffix = "Allow_${proto}_${port}_${dir}_Any"
                             $ruleParams['RemoteIP'] = $null
                        } elseif (-not [string]::IsNullOrWhiteSpace($remoteIp)) {
                            if (Validate-IPAddress $remoteIp) { # Call without global:
                                $sanitizedTarget = $remoteIp -replace '[^a-zA-Z0-9.-]', '_'
                                $ruleSuffixBase = "Allow_${proto}_${port}_${dir}_$($sanitizedTarget)"
                                $ruleSuffix = $ruleSuffixBase.Substring(0, [System.Math]::Min(255, $ruleSuffixBase.Length))
                                $ruleParams['RemoteIP'] = $remoteIp
                            } else { Write-Log "WARN" "ControlAegis(FirewallSync): Skipping invalid IP exception '$remoteIp'."}
                        } # Domain exceptions don't directly translate to standard firewall rules here

                        if ($ruleSuffix) {
                            $ruleParams['Name'] = $ruleSuffix
                             # Add DisplayName for clarity in Firewall GUI
                            $ruleParams['DisplayName'] = "Allow $proto/$port ($dir) for $(if($isGeneral){'Any'}else{$remoteIp}) (ControlAegis)"
                            $ruleName = "CA_$ruleSuffix"
                            $desiredRules[$ruleName] = $ruleParams
                        }
                    } else { Write-Log "WARN" "ControlAegis(FirewallSync): Skipping malformed exception: $($exception | ConvertTo-Json -Depth 1 -Compress)" }
                }
            }
        }

        # Determine rules to add and remove
        $rulesToAdd = ($desiredRules.Keys | Where-Object { $_ -notin $existingRuleNames })
        # Only remove rules with the CA_ prefix that are no longer in the desired configuration
        $rulesToRemove = $existingRuleNames | Where-Object { $_ -notin $desiredRules.Keys }

        if ($rulesToAdd.Count -eq 0 -and $rulesToRemove.Count -eq 0) {
            Write-Log "INFO" "ControlAegis(FirewallSync): Firewall already synchronized."
        } else {
            Write-Log "INFO" "ControlAegis(FirewallSync): Synchronizing - Add: $($rulesToAdd.Count), Remove: $($rulesToRemove.Count)"
            # Add missing rules
            foreach ($ruleName in $rulesToAdd) {
                $ruleParams = $desiredRules[$ruleName]
                Write-Log "DEBUG" "ApplyInitialFW: Adding rule '$ruleName'"
                try {
                    # Execute directly (ShouldProcess removed)
                    Write-Log "INFO" "ControlAegis(TESTING): Creating firewall rule '$ruleName'."
                    Firewall-AddRule @ruleParams | Out-Null # Call without global:
                    Write-Log "DEBUG" "ApplyInitialFW: Call to add '$($ruleParams.Name)' returned."
                } catch { Write-Log "ERROR" "ControlAegis(FW Sync): Failed to add rule '$ruleName': $($_.Exception.Message)"; throw }
            }
            # Remove obsolete rules
            foreach ($ruleName in $rulesToRemove) {
                $ruleSuffix = $ruleName.Substring(3) # Get name without CA_ prefix for Firewall-RemoveRule
                Write-Log "DEBUG" "ApplyInitialFW: Removing rule '$ruleName'"
                try {
                    # Execute directly (ShouldProcess removed)
                     Write-Log "INFO" "ControlAegis(TESTING): Removing firewall rule '$ruleName'."
                    Firewall-RemoveRule -name $ruleSuffix | Out-Null # Call without global:
                    Write-Log "DEBUG" "ApplyInitialFW: Call to remove '$ruleSuffix' returned."
                } catch { Write-Log "ERROR" "ControlAegis(FW Sync): Failed to remove rule '$ruleName': $($_.Exception.Message)"; throw }
            }
        }
        Write-Log "INFO" "ControlAegis: Firewall synchronization completed."
    } catch { Write-Log "ERROR" "ControlAegis: Critical failure during firewall sync: $($_.Exception.Message)"; Write-Host "ERROR: Failed firewall sync." -ForegroundColor Red; throw $_ }
}
# --- End Initial State ---

# 4. Load Config, Validate, Apply Initial State
Write-Host "Loading and validating configuration..."
try {
    $Global:AppConfig = Load-Config # Call without global: Loads config and validates internally
    Write-Log "INFO" "ControlAegis: Configuration loaded and validated."

    # Determine and ensure configured log path exists, if specified
    $configuredLogPath = $null
    if ($Global:AppConfig.logs -ne $null -and -not [string]::IsNullOrWhiteSpace($Global:AppConfig.logs.caminho_logs_local)) {
        $configuredLogPath = $Global:AppConfig.logs.caminho_logs_local
        if (-not ([System.IO.Path]::IsPathRooted($configuredLogPath))) {
            try {
                $configuredLogPath = Join-Path $Global:ProjectRoot $configuredLogPath
                $configuredLogPath = ([System.IO.Path]::GetFullPath($configuredLogPath))
            } catch { Write-Host "WARNING: Failed to resolve configured log path. Using default." -ForegroundColor Yellow; $configuredLogPath = $null }
        }
        if (($configuredLogPath -ne $null) -and ($configuredLogPath -ne $defaultLogBasePath) -and (-not (Test-Path -Path $configuredLogPath -PathType Container))) {
            Write-Host "Creating configured log directory: $configuredLogPath" -ForegroundColor Yellow
            try {
                New-Item -ItemType Directory -Path $configuredLogPath -Force -ErrorAction Stop | Out-Null
                Write-Log "INFO" "ControlAegis: Created configured log directory: $configuredLogPath"
            } catch { Write-Log "ERROR" "ControlAegis: Failed to create configured log dir '$configuredLogPath': $($_.Exception.Message)"; Write-Host "WARNING: Failed create configured log dir '$configuredLogPath'." -ForegroundColor Yellow }
        }
    }

    Write-Host "Applying initial state (Hosts and Firewall)..." -ForegroundColor Cyan
    Apply-InitialHostsConfiguration -Config $Global:AppConfig
    Apply-InitialFirewallConfiguration -Config $Global:AppConfig
    Write-Host "Initial state application completed." -ForegroundColor Cyan
} catch {
    Write-Log "CRITICAL" "ControlAegis: Failed to load/validate/apply config: $($_.Exception.Message)"
    Write-Host "Critical Error: Failed config/sync process. Check config/logs. Terminating." -ForegroundColor Red
    exit 1
}

# 5. Initialize Rollback System
Write-Host "Initializing Rollback system..."
try {
    Initialize-Rollback # Call without global:
    Write-Log "INFO" "ControlAegis: Rollback system initialized."
} catch { Write-Log "ERROR" "ControlAegis: Failed to initialize Rollback: $($_.Exception.Message)"; Write-Host "Warning: Failed to initialize Rollback: $($_.Exception.Message)" -ForegroundColor Yellow }

# 6. Perform Log Rotation Check
Write-Host "Checking log rotation..."
try {
    $logConfig = $Global:AppConfig.logs # Renamed from logConf
    if ($logConfig) {
        # Use configured path if valid, otherwise default
        $logDirToRotate = if ($configuredLogPath -and (Test-Path $configuredLogPath -PathType Container)) { $configuredLogPath } else { $defaultLogBasePath }
        if (Test-Path $logDirToRotate -PathType Container) {
            LogAnalysis-RotateLogs -LogDirectory $logDirToRotate -RotationConfig $logConfig # Call without global:
            # Log message moved inside LogAnalysis-RotateLogs
        } else { Write-Log "WARN" "ControlAegis: Log directory '$logDirToRotate' not found. Rotation skipped."; Write-Host "WARNING: Log directory '$logDirToRotate' not found." -ForegroundColor Yellow }
    } else { Write-Log "WARN" "ControlAegis: 'logs' section not found in config. Rotation skipped."; Write-Host "WARNING: Log rotation settings not found." -ForegroundColor Yellow }
} catch { Write-Log "ERROR" "ControlAegis: Log rotation failed: $($_.Exception.Message)"; Write-Host "Warning: Log rotation failed: $($_.Exception.Message)" -ForegroundColor Yellow }

# 7. Define CLI Wrapper Functions (No ShouldProcess in Test Version)
Write-Log "INFO" "ControlAegis: Defining CLI functions..."

function Add-BlockedDomain {
    [CmdletBinding()] # SupportsShouldProcess removed
    param ([Parameter(Mandatory = $true)][string]$domain)
    try {
        Cli-AddBlockedDomain -domain $domain
    } catch { Write-Log "ERROR" "Wrapper(Add-BlockedDomain): Failed: $($_.Exception.Message)" }
}
function Remove-BlockedDomain {
    [CmdletBinding()] # SupportsShouldProcess removed
    param ([Parameter(Mandatory = $true)][string]$domain)
    try {
        Cli-RemoveBlockedDomain -domain $domain
    } catch { Write-Log "ERROR" "Wrapper(Remove-BlockedDomain): Failed: $($_.Exception.Message)" }
}
function List-BlockedDomains {
    [CmdletBinding()]
    param ()
    try { Cli-ListBlockedDomains } catch { Write-Log "ERROR" "Wrapper(List-BlockedDomains): Failed: $($_.Exception.Message)" }
}

function Add-BlockedPort {
    [CmdletBinding()] # SupportsShouldProcess removed
    param (
        [Parameter(Mandatory = $true)][ValidateSet("TCP", "UDP")][string]$protocol,
        [Parameter(Mandatory = $true)][int]$port,
        [Parameter(Mandatory = $false)][ValidateSet("inbound", "outbound")][string]$direction
    )
    try {
        $cliParams = @{ protocol = $protocol; port = $port }
        if ($PSBoundParameters.ContainsKey('direction')) { $cliParams['direction'] = $direction }
        Cli-AddBlockedPort @cliParams
    } catch { Write-Log "ERROR" "Wrapper(Add-BlockedPort): Failed: $($_.Exception.Message)" }
}

function Remove-BlockedPort {
    [CmdletBinding()] # SupportsShouldProcess removed
    param (
        [Parameter(Mandatory = $true)][ValidateSet("TCP", "UDP")][string]$protocol,
        [Parameter(Mandatory = $true)][int]$port,
        [Parameter(Mandatory = $false)][ValidateSet("inbound", "outbound")][string]$direction
    )
    try {
        $cliParams = @{ protocol = $protocol; port = $port }
        if ($PSBoundParameters.ContainsKey('direction')) { $cliParams['direction'] = $direction }
        Cli-RemoveBlockedPort @cliParams
    } catch { Write-Log "ERROR" "Wrapper(Remove-BlockedPort): Failed: $($_.Exception.Message)" }
}

function List-BlockedPorts {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][ValidateSet("TCP", "UDP")][string]$protocol)
    try { Cli-ListBlockedPorts -protocol $protocol } catch { Write-Log "ERROR" "Wrapper(List-BlockedPorts): Failed: $($_.Exception.Message)" }
}
function Add-Exception {
    [CmdletBinding(DefaultParameterSetName = 'IP')] # SupportsShouldProcess removed
    param (
        [Parameter(Mandatory = $true)][ValidateSet("TCP", "UDP")][string]$protocol,
        [Parameter(Mandatory = $true)][int]$port,
        [Parameter(ParameterSetName = 'IP', Mandatory = $true)][string]$remoteip,
        [Parameter(ParameterSetName = 'Domain', Mandatory = $true)][string]$domain,
        [Parameter()][ValidateSet("inbound", "outbound")][string]$direction
    )
    try {
        $cliParams = @{ protocol=$protocol; port=$port }
        if ($PSBoundParameters.ContainsKey('direction')) { $cliParams['direction'] = $direction }
        if ($PSBoundParameters.ContainsKey('remoteip')) { $cliParams['remoteip'] = $remoteip }
        if ($PSBoundParameters.ContainsKey('domain')) { $cliParams['domain'] = $domain }
        Cli-AddException @cliParams
    } catch { Write-Log "ERROR" "Wrapper(Add-Exception): Failed: $($_.Exception.Message)" }
}
function Remove-Exception {
     [CmdletBinding(DefaultParameterSetName = 'IP')] # SupportsShouldProcess removed
    param (
        [Parameter(Mandatory = $true)][ValidateSet("TCP", "UDP")][string]$protocol,
        [Parameter(Mandatory = $true)][int]$port,
        [Parameter(ParameterSetName = 'IP', Mandatory=$true)][string]$remoteip,
        [Parameter(ParameterSetName = 'Domain', Mandatory=$true)][string]$domain,
        [Parameter()][ValidateSet("inbound", "outbound")][string]$direction
    )
    try {
        $cliParams = @{ protocol=$protocol; port=$port }
        if ($PSBoundParameters.ContainsKey('direction')) { $cliParams['direction'] = $direction }
        if ($PSBoundParameters.ContainsKey('remoteip')) { $cliParams['remoteip'] = $remoteip }
        if ($PSBoundParameters.ContainsKey('domain')) { $cliParams['domain'] = $domain }
        Cli-RemoveException @cliParams
    } catch { Write-Log "ERROR" "Wrapper(Remove-Exception): Failed: $($_.Exception.Message)" }
}

# --- CORREÇÃO Wrapper List-Exceptions ---
function List-Exceptions {
    [CmdletBinding()] # SupportsShouldProcess removed previously
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("TCP", "UDP")]
        [string]$protocol # Opcional para o usuário
    )
    try {
        # Verifica se o usuário especificou o parâmetro -protocol
        if ($PSBoundParameters.ContainsKey('protocol')) {
            # Se sim, chama a função interna passando o protocolo
            Cli-ListExceptions -protocol $protocol
        } else {
            # Se não, chama a função interna SEM o parâmetro -protocol
            Cli-ListExceptions
        }
    } catch {
        Write-Log "ERROR" "Wrapper(List-Exceptions): Failed: $($_.Exception.Message)"
    }
}
# --- FIM CORREÇÃO ---

function Invoke-Rollback {
    [CmdletBinding()] # SupportsShouldProcess removed
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1,100)]
        [int]$Steps = 1
    )
    Write-Log "INFO" "Wrapper: Invoking Rollback - Steps: $Steps (TESTING - NO PROMPT)"
    try {
        Start-Rollback -Steps $Steps # Call without global:
    } catch { Write-Log "ERROR" "Wrapper(Invoke-Rollback): Failed: $($_.Exception.Message)" }
}


# --- Final Message ---
Write-Log "INFO" "ControlAegis: Script initialized and ready (TESTING VERSION - NO PROMPTS)."
Write-Host "`nControlAegis initialized and synchronized (TESTING VERSION - NO PROMPTS)." -ForegroundColor Green
Write-Host "Use the defined functions (e.g., Add-BlockedDomain, Invoke-Rollback) to manage." -ForegroundColor Green
Write-Host "Run Get-Command -Module $PSCommandPath to see available commands." -ForegroundColor Cyan

# --- Export Public Functions ---
# Only export the functions intended for the end user.
Export-ModuleMember -Function Add-BlockedDomain, Remove-BlockedDomain, List-BlockedDomains, `
                            Add-BlockedPort, Remove-BlockedPort, List-BlockedPorts, `
                            Add-Exception, Remove-Exception, List-Exceptions, `
                            Invoke-Rollback