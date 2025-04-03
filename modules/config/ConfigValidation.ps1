# ConfigValidation.ps1
# Provides function to validate the structure and values of the configuration object.

# Validates the loaded configuration object ($Global:AppConfig).
function Validate-Config {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$config
    )

    Write-Log "DEBUG" "ConfigValidation: Starting configuration validation..."

    if (-not $config) { throw "Configuration object is null or empty." }

    # Check required top-level sections
    $requiredSections = @("bloqueio", "excecoes", "logs");
    foreach ($section in $requiredSections) {
        if (-not $config.PSObject.Properties.Name.Contains($section)) {
            throw "Seção '$section' faltando na configuração."
        }
    }

    # Validate 'bloqueio' section
    if ($config.bloqueio) {
        if ($config.bloqueio.PSObject.Properties.Name -contains 'portas_tcp') {
            if ($config.bloqueio.portas_tcp -isnot [array]) { throw "'bloqueio.portas_tcp' não é um array." }
            foreach ($port in $config.bloqueio.portas_tcp) {
                if ($port -isnot [int] -or $port -lt 0 -or $port -gt 65535) { throw "Porta TCP inválida ('$port') encontrada em 'bloqueio.portas_tcp'." }
            }
        } else { throw "Chave 'portas_tcp' faltando na seção 'bloqueio'."}

        if ($config.bloqueio.PSObject.Properties.Name -contains 'portas_udp') {
            if ($config.bloqueio.portas_udp -isnot [array]) { throw "'bloqueio.portas_udp' não é um array." }
            foreach ($port in $config.bloqueio.portas_udp) {
                if ($port -isnot [int] -or $port -lt 0 -or $port -gt 65535) { throw "Porta UDP inválida ('$port') encontrada em 'bloqueio.portas_udp'." }
            }
        } else { throw "Chave 'portas_udp' faltando na seção 'bloqueio'."}

        if ($config.bloqueio.PSObject.Properties.Name -contains 'dominios_bloqueados') {
            if ($config.bloqueio.dominios_bloqueados -isnot [array]) { throw "'bloqueio.dominios_bloqueados' não é um array." }
            foreach ($domain in $config.bloqueio.dominios_bloqueados) {
                if ($domain -isnot [string] -or [string]::IsNullOrWhiteSpace($domain)) { throw "Domínio bloqueado inválido ('$domain') encontrado em 'bloqueio.dominios_bloqueados'." }
                # Basic format check, stricter validation happens in Validate-Domain if needed elsewhere
                 if ($domain -match '^\s|\s$|[\*\?]') { throw "Formato de domínio bloqueado inválido (contém espaços ou wildcards não suportados aqui): '$domain'." }
            }
        } else { throw "Chave 'dominios_bloqueados' faltando na seção 'bloqueio'."}
    } else { throw "Seção 'bloqueio' está faltando ou é nula."} # Should have been caught earlier, but for safety

    # Validate 'excecoes' section
    if ($config.excecoes) {
        foreach ($key in @('portas_tcp', 'portas_udp')) {
            if ($config.excecoes.PSObject.Properties.Name.Contains($key)) {
                if ($config.excecoes.$key -isnot [array]) { throw "'excecoes.$key' não é um array." }
                for ($i = 0; $i -lt $config.excecoes.$key.Count; $i++) {
                    $exception = $config.excecoes.$key[$i]; $exceptionPath = "excecoes.$key[$i]"
                    if ($exception -isnot [PSCustomObject]) { throw "Item '$exceptionPath' não é um objeto." }

                    $isGeneral = $false;
                    if ($exception.PSObject.Properties.Name.Contains('tipo') -and $exception.tipo -eq 'geral') { $isGeneral = $true }

                    if (-not $exception.PSObject.Properties.Name.Contains('porta') -or $exception.porta -isnot [int] -or $exception.porta -lt 0 -or $exception.porta -gt 65535) { throw "'porta' inválida ou faltando em '$exceptionPath'." }
                    if (-not $exception.PSObject.Properties.Name.Contains('protocolo') -or $exception.protocolo -notin @('TCP', 'UDP')) { throw "'protocolo' inválido (deve ser 'TCP' ou 'UDP') ou faltando em '$exceptionPath'." }
                    if (-not $exception.PSObject.Properties.Name.Contains('direcao') -or $exception.direcao -notin @('inbound', 'outbound')) { throw "'direcao' inválida (deve ser 'inbound' ou 'outbound') ou faltando em '$exceptionPath'." }

                    if ($isGeneral) {
                        # General exceptions must NOT have remoteip or dominio
                        if (($exception.PSObject.Properties.Name.Contains('remoteip') -and $exception.remoteip -ne $null) -or ($exception.PSObject.Properties.Name.Contains('dominio') -and $exception.dominio -ne $null)) {
                            throw "Exceção do tipo 'geral' em '$exceptionPath' não deve conter 'remoteip' ou 'dominio'."
                        }
                    } else {
                        # Specific exceptions MUST have EITHER remoteip OR dominio
                        $hasRemoteIp = $exception.PSObject.Properties.Name.Contains('remoteip') -and -not [string]::IsNullOrWhiteSpace($exception.remoteip)
                        $hasDomain = $exception.PSObject.Properties.Name.Contains('dominio') -and -not [string]::IsNullOrWhiteSpace($exception.dominio)
                        if (-not ($hasRemoteIp -or $hasDomain)) { throw "Exceção específica em '$exceptionPath' deve conter 'remoteip' ou 'dominio' não vazio." }
                        if ($hasRemoteIp -and $hasDomain) { throw "Exceção específica em '$exceptionPath' não pode conter 'remoteip' E 'dominio' simultaneamente." }

                        # Validate formats if present
                        if ($hasRemoteIp -and -not (Validate-IPAddress $exception.remoteip)) { throw "'remoteip' ('$($exception.remoteip)') inválido em '$exceptionPath'." }
                        if ($hasDomain -and -not (Validate-Domain $exception.dominio)) { throw "'dominio' ('$($exception.dominio)') inválido em '$exceptionPath'." }
                    }
                }
            } else {
                Write-Log "DEBUG" "ConfigValidation: Key '$key' not found in 'excecoes'." # Optional key, not an error
            }
        }
        # Validate 'dominios_permitidos' - now primarily linked to domain exceptions
        if ($config.excecoes.PSObject.Properties.Name.Contains('dominios_permitidos')) {
            if ($config.excecoes.dominios_permitidos -isnot [array]) { throw "'excecoes.dominios_permitidos' não é um array." }
            foreach ($domain in $config.excecoes.dominios_permitidos) {
                if ($domain -isnot [string] -or [string]::IsNullOrWhiteSpace($domain)) { throw "Entrada inválida ('$domain') em 'excecoes.dominios_permitidos'." }
                if (-not (Validate-Domain $domain)) { throw "Formato de domínio inválido em 'dominios_permitidos': '$domain'." }
            }
        } else {
             Write-Log "DEBUG" "ConfigValidation: Key 'dominios_permitidos' not found in 'excecoes'." # Optional key
        }
    } else { throw "Seção 'excecoes' está faltando ou é nula." }

    # Validate 'logs' section
    if ($config.logs) {
        # Check optional keys and their types/values if they exist
        if ($config.logs.PSObject.Properties.Name.Contains('ativar_logs_ad') -and $config.logs.ativar_logs_ad -isnot [bool]) { throw "'logs.ativar_logs_ad' deve ser um valor booleano (true/false)." }
        if ($config.logs.PSObject.Properties.Name.Contains('log_rotation_strategy') -and $config.logs.log_rotation_strategy -notin @('size', 'time')) { throw "'logs.log_rotation_strategy' deve ser 'size' ou 'time'." }
        if ($config.logs.PSObject.Properties.Name.Contains('log_rotation_size') -and ($config.logs.log_rotation_size -isnot [int] -or $config.logs.log_rotation_size -le 0) ){ throw "'logs.log_rotation_size' deve ser um inteiro positivo." }
        if ($config.logs.PSObject.Properties.Name.Contains('log_rotation_max_files') -and ($config.logs.log_rotation_max_files -isnot [int] -or $config.logs.log_rotation_max_files -le 0) ){ throw "'logs.log_rotation_max_files' deve ser um inteiro positivo." }
        if ($config.logs.PSObject.Properties.Name.Contains('caminho_logs_local') -and (-not ($config.logs.caminho_logs_local -is [string]) -or [string]::IsNullOrWhiteSpace($config.logs.caminho_logs_local)) ){ throw "'logs.caminho_logs_local' deve ser uma string não vazia." }
        # Conditional validation for AD path
        $adLoggingEnabled = $config.logs.PSObject.Properties.Name.Contains('ativar_logs_ad') -and $config.logs.ativar_logs_ad -eq $true
        if ($adLoggingEnabled) {
            if (-not $config.logs.PSObject.Properties.Name.Contains('caminho_logs_ad') -or -not ($config.logs.caminho_logs_ad -is [string]) -or [string]::IsNullOrWhiteSpace($config.logs.caminho_logs_ad)) {
                 throw "'logs.caminho_logs_ad' deve ser uma string não vazia quando 'ativar_logs_ad' é true."
            }
             # Basic UNC path check (optional enhancement)
             # if ($config.logs.caminho_logs_ad -notmatch '^\\\\[^\\]+\\[^\\]+') { Write-Log "WARN" "ConfigValidation: 'caminho_logs_ad' ('$($config.logs.caminho_logs_ad)') não parece um caminho UNC válido."}
        }
    } else { throw "Seção 'logs' está faltando ou é nula." }

    Write-Log "INFO" "ConfigValidation: config.json validated successfully."
    return $true
}