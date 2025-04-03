# FirewallModule.ps1
# Provides functions to interact with Windows Firewall using netsh advfirewall for modifications
# and Get-NetFirewallRule for reads. All rules managed by this module use the "CA_" prefix.

# Internal helper to execute netsh commands and parse results.
function Invoke-NetshCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Arguments,

        [Parameter(Mandatory=$true)]
        [string]$OperationForLog # e.g., "add rule", "delete rule"
    )

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo("netsh.exe", $Arguments)
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo

    Write-Log "DEBUG" "Invoke-NetshCommand: Executing 'netsh.exe $Arguments'"
    try {
        $process.Start() | Out-Null
        $process.WaitForExit() # Wait for the external process to finish
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()

        Write-Log "DEBUG" "Invoke-NetshCommand: ExitCode: $($process.ExitCode)"
        if ($stdout) { Write-Log "DEBUG" "Invoke-NetshCommand: Stdout: $stdout" }
        if ($stderr) { Write-Log "DEBUG" "Invoke-NetshCommand: Stderr: $stderr" }

        # Check for errors: non-zero exit code, non-empty stderr, or specific error keywords in stdout.
        # This broad check is needed due to netsh's inconsistent error reporting.
        if ($process.ExitCode -ne 0 -or $stderr -match '\S' -or $stdout -match 'Erro|Error|Falha|Failed|inválido|invalid' -or $stdout -match 'No rules match the specified criteria') {
             # Treat "No rules match" during delete as a potential non-error scenario later if needed, but log as error for now from netsh itself.
             $errMsg = "Failed to execute netsh $OperationForLog (ExitCode: $($process.ExitCode)). Stderr: $stderr Stdout: $stdout"
             # Check for the specific "invalid value" error from the manual test
             if ($stdout -match 'Um valor especificado nao é válido' -or $stderr -match 'Um valor especificado nao é válido') {
                 $errMsg = "Failed to execute netsh $OperationForLog. A specified value is not valid. Command: netsh.exe $Arguments"
             }
             Write-Log "ERROR" "Invoke-NetshCommand: $errMsg"
             throw $errMsg # Throw exception on failure
        }

        Write-Log "DEBUG" "Invoke-NetshCommand: Netsh command for '$OperationForLog' appears successful."
        return $true

    } catch {
        Write-Log "ERROR" "Invoke-NetshCommand: Exception while executing netsh $OperationForLog : $($_.Exception.Message)"
        throw # Re-throw exceptions
    }
}


# Adds a firewall rule using netsh. Handles rule name prefixing ("CA_").
function Firewall-AddRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("inbound", "outbound")]
        [string]$direction,

        [Parameter(Mandatory = $true)]
        [ValidateSet("allow", "block")]
        [string]$action,

        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "UDP")]
        [string]$protocol,

        [Parameter(Mandatory = $true)]
        [int]$port,

        [Parameter(Mandatory = $true)]
        [string]$name, # Descriptive suffix (e.g., Block_TCP_445_outbound)

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$remoteip,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName = $null, # Optional: DisplayName for the rule

        [Parameter(Mandatory = $false)]
        [string]$Enabled = "True" # Optional: Enable/disable rule (Input as String "True"/"False" or $true/$false)
    )

    # Input validation
    if ($port -lt 0 -or $port -gt 65535) { Write-Log "ERROR" "FirewallModule: Invalid port: $port"; throw "FirewallModule: Invalid port: $port" }
    if ($remoteip -and -not (Validate-IPAddress $remoteip)) { Write-Log "ERROR" "FirewallModule: Invalid remote IP: $remoteip"; throw "FirewallModule: Invalid remote IP: $remoteip" } # Call without global:

    $fullRuleName = "CA_$name" # Prepend standard prefix

    Write-Log "DEBUG" "FirewallModule(netsh): Preparing to add rule '$fullRuleName'..."

    # Check if rule already exists using preferred cmdlet first, falling back to netsh show.
    $ruleExists = $false
    try {
        if (Get-NetFirewallRule -Name $fullRuleName -PolicyStore System -ErrorAction SilentlyContinue) {
            $ruleExists = $true
        }
    } catch {
        Write-Log "WARN" "FirewallModule(netsh): Get-NetFirewallRule check failed. Trying 'netsh show' as fallback."
    }
    if (-not $ruleExists) {
        try {
            $showArgs = "advfirewall firewall show rule name=`"$fullRuleName`""
            $psi = New-Object System.Diagnostics.ProcessStartInfo("netsh.exe", $showArgs)
            $psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true;
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.WaitForExit()
            $o = $p.StandardOutput.ReadToEnd()
            if ($p.ExitCode -eq 0 -and $o -match $fullRuleName) { $ruleExists = $true }
        } catch {
            Write-Log "WARN" "FirewallModule(netsh): Error checking rule existence via 'netsh show': $($_.Exception.Message)"
        }
    }

    if ($ruleExists) {
        Write-Log "WARN" "FirewallModule: Rule '$fullRuleName' already exists. No action taken."
        Write-Host "WARNING: Rule '$fullRuleName' already exists." -ForegroundColor Yellow
        return # Idempotency: do nothing if rule exists
    }

    # Construct netsh arguments
    $netshArgs = "advfirewall firewall add rule name=`"$fullRuleName`" "
    $netshDir = if ($direction -eq 'inbound') { 'in' } else { 'out' }
    $netshArgs += "dir=$netshDir action=$($action.ToLower()) protocol=$($protocol.ToUpper()) localport=$port "
    if (-not [string]::IsNullOrWhiteSpace($remoteip)) {
        $netshArgs += "remoteip=`"$remoteip`" " # Quote remote IP
    }
    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $netshArgs += "description=`"$DisplayName`" " # Use description field for DisplayName via netsh
    }

    # --- !!! CORREÇÃO APLICADA AQUI !!! ---
    # Convert boolean or string 'True'/'False' input to 'yes'/'no' for netsh enable parameter
    $enableValueForNetsh = if (($Enabled -is [bool] -and $Enabled -eq $true) -or ($Enabled -is [string] -and $Enabled -eq 'True')) {
                               "yes"
                           } else {
                               "no"
                           }
    $netshArgs += "enable=$enableValueForNetsh profile=any"
    # --- !!! FIM DA CORREÇÃO !!! ---

    try {
        # Execute netsh command via helper
        Invoke-NetshCommand -Arguments $netshArgs -OperationForLog "add rule '$fullRuleName'"

        $remoteIpDisplay = if (-not [string]::IsNullOrWhiteSpace($remoteip)) { $remoteip } else { 'Any' }
        Write-Log "INFO" "FirewallModule: Rule '$fullRuleName' added via netsh (Proto: $protocol, Port: $port, Dir: $direction, Action: $action, RemoteIP: $remoteIpDisplay)."

    } catch {
        # Error already logged by Invoke-NetshCommand
        throw "Failed to add rule '$fullRuleName' via netsh." # Re-throw
    }
}

# Removes a firewall rule using netsh. Handles rule name prefixing ("CA_").
function Firewall-RemoveRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$name # Descriptive suffix (e.g., Block_TCP_445_outbound)
    )

    $fullRuleName = "CA_$name"
    Write-Log "DEBUG" "FirewallModule(netsh): Preparing to remove rule '$fullRuleName'..."

    $netshArgs = "advfirewall firewall delete rule name=`"$fullRuleName`""

    try {
        # Execute netsh command via helper
        Invoke-NetshCommand -Arguments $netshArgs -OperationForLog "delete rule '$fullRuleName'"
        # Note: Consider refining Invoke-NetshCommand or adding checks here
        # if "No rules match..." should not be treated as a hard error during removal.
        Write-Log "INFO" "FirewallModule: Removal attempt for rule '$fullRuleName' via netsh completed."

    } catch {
        # Error already logged by Invoke-NetshCommand
        throw "Failed to remove rule '$fullRuleName' via netsh." # Re-throw
    }
}

# Gets managed firewall rules (prefixed with "CA_") using Get-NetFirewallRule cmdlet.
function Firewall-GetRules {
    [CmdletBinding()]
    param()
    Write-Log "DEBUG" "FirewallModule: Attempting to get CA_* rules via Get-NetFirewallRule..."
    try {
        # Using the cmdlet is preferred for querying.
        $rules = Get-NetFirewallRule -PolicyStore System -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "CA_*" }
        if ($null -eq $rules) { return @() }
        return $rules
    } catch {
        Write-Log "ERROR" "FirewallModule: Failed to get rules (CA_*) via Get-NetFirewallRule: $($_.Exception.Message)"
        return @() # Return empty on error
    }
}