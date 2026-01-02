<#
.SYNOPSIS
    SwiftLogger - A PowerShell module for comprehensive logging with optional syslog integration.

.DESCRIPTION
    SwiftLogger provides flexible logging capabilities including:
    - Local file logging (plain text and JSON formats)
    - Optional syslog integration with RFC5424/RFC3164 support
    - Colored console output
    - IPv6 support
    - UDP/TCP/TLS transport with fallback

.NOTES
    Module:     SwiftLogger
    Version:    1.0.0.5
    Author:     Scott Powdrill
    License:    GPL-3.0
#>

#region Configuration Functions

function Set-LogConfiguration {
    <#
    .SYNOPSIS
        Configures global logging settings used by SwiftLogger functions.

    .DESCRIPTION
        Sets up the logging configuration including log file paths, syslog server settings,
        and output format preferences. All parameters are optional and only update the
        specified settings, preserving existing values for unspecified parameters.

    .PARAMETER AppName
        Application name identifier, included in JSON logs and syslog messages.

    .PARAMETER SysLogServer
        Hostname or IP address of the syslog server. Optional - syslog is disabled if not set.

    .PARAMETER SysLogPort
        Port number of the syslog server (typically 514 for UDP/TCP, 6514 for TLS).

    .PARAMETER SysLogRFC
        Syslog protocol version. Valid values: 'RFC5424' (default), 'RFC3164'.

    .PARAMETER LogFilePath
        Directory path where log files will be created.

    .PARAMETER LogName
        Base name for log files (without extension).

    .PARAMETER ScriptName
        Name of the calling script, included in logs for identification.

    .PARAMETER ScriptVersion
        Version of the calling script, included in logs.

    .PARAMETER SendSyslog
        Whether Write-Log should automatically send messages to syslog. Default: $false

    .PARAMETER JsonLogging
        Whether Write-Log should output JSON format logs. Default: $false

    .PARAMETER QuietMode
        Suppress console output globally. Default: $false

    .PARAMETER ConnectionTimeoutSeconds
        Timeout for TCP/TLS connections to syslog server. Default: 5

    .EXAMPLE
        Set-LogConfiguration -LogFilePath "C:\Logs" -LogName "MyApp" -ScriptName "Deploy"

        Configures local-only logging without syslog.

    .EXAMPLE
        Set-LogConfiguration -SysLogServer "syslog.example.com" -SendSyslog $true -JsonLogging $true

        Enables syslog and JSON logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [String]$AppName,
        [Parameter()] [String]$SysLogServer,
        [Parameter()] [int]$SysLogPort,
        [ValidateSet('RFC5424', 'RFC3164')] [Parameter()] [string]$SysLogRFC,
        [Parameter()] [String]$LogFilePath,
        [Parameter()] [String]$LogName,
        [Parameter()] [String]$ScriptName,
        [Parameter()] [String]$ScriptVersion,
        [Parameter()] [bool]$SendSyslog,
        [Parameter()] [bool]$JsonLogging,
        [Parameter()] [bool]$QuietMode,
        [Parameter()] [int]$ConnectionTimeoutSeconds
    )

    # Set values only if explicitly provided
    if ($PSBoundParameters.ContainsKey('AppName')) { $Global:SwiftLogger_AppName = $AppName }
    if ($PSBoundParameters.ContainsKey('SysLogServer')) { $Global:SwiftLogger_SysLogServer = $SysLogServer }
    if ($PSBoundParameters.ContainsKey('SysLogPort')) { $Global:SwiftLogger_SysLogPort = $SysLogPort }
    if ($PSBoundParameters.ContainsKey('LogFilePath')) { $Global:SwiftLogger_LogFilePath = $LogFilePath }
    if ($PSBoundParameters.ContainsKey('LogName')) { $Global:SwiftLogger_LogName = $LogName }
    if ($PSBoundParameters.ContainsKey('ScriptName')) { $Global:SwiftLogger_ScriptName = $ScriptName }
    if ($PSBoundParameters.ContainsKey('ScriptVersion')) { $Global:SwiftLogger_ScriptVersion = $ScriptVersion }
    if ($PSBoundParameters.ContainsKey('SendSyslog')) { $Global:SwiftLogger_SendSyslog = [System.Convert]::ToBoolean($SendSyslog) }
    if ($PSBoundParameters.ContainsKey('JsonLogging')) { $Global:SwiftLogger_JsonLogging = [System.Convert]::ToBoolean($JsonLogging) }
    if ($PSBoundParameters.ContainsKey('QuietMode')) { $Global:SwiftLogger_QuietMode = [System.Convert]::ToBoolean($QuietMode) }
    if ($PSBoundParameters.ContainsKey('ConnectionTimeoutSeconds')) { $Global:SwiftLogger_ConnectionTimeout = $ConnectionTimeoutSeconds }

    # Set RFC with default
    $Global:SwiftLogger_SyslogRFC = if ($PSBoundParameters.ContainsKey('SysLogRFC')) { $SysLogRFC } else { if (-not $Global:SwiftLogger_SyslogRFC) { 'RFC5424' } else { $Global:SwiftLogger_SyslogRFC } }

    # Set defaults for uninitialized values
    if ($null -eq $Global:SwiftLogger_SendSyslog) { $Global:SwiftLogger_SendSyslog = $false }
    if ($null -eq $Global:SwiftLogger_JsonLogging) { $Global:SwiftLogger_JsonLogging = $false }
    if ($null -eq $Global:SwiftLogger_QuietMode) { $Global:SwiftLogger_QuietMode = $false }
    if ($null -eq $Global:SwiftLogger_ConnectionTimeout) { $Global:SwiftLogger_ConnectionTimeout = 5 }

    # Ensure log directory exists if path is provided
    if (-not [string]::IsNullOrWhiteSpace($Global:SwiftLogger_LogFilePath)) {
        if (-not (Test-Path -Path $Global:SwiftLogger_LogFilePath -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $Global:SwiftLogger_LogFilePath -Force | Out-Null
                Write-Verbose "Created log directory: $Global:SwiftLogger_LogFilePath"
            }
            catch {
                throw "Failed to create log directory '$Global:SwiftLogger_LogFilePath': $_"
            }
        }
    }

    # Define global severity and message ID maps
    $Global:SwiftLogger_SeverityMap = @{error = 3; warn = 4; success = 5; general = 6; debug = 7 }
    $Global:SwiftLogger_MsgIdMap = @{ error = 'ERR'; warn = 'WRN'; success = 'SUC'; general = 'INF'; debug = 'DBG' }

    # Maintain backward compatibility with old variable names
    $Global:AppName = $Global:SwiftLogger_AppName
    $Global:SysLogServer = $Global:SwiftLogger_SysLogServer
    $Global:SysLogPort = $Global:SwiftLogger_SysLogPort
    $Global:LogFilePath = $Global:SwiftLogger_LogFilePath
    $Global:LogName = $Global:SwiftLogger_LogName
    $Global:ScriptName = $Global:SwiftLogger_ScriptName
    $Global:ScriptVersion = $Global:SwiftLogger_ScriptVersion
    $Global:SendSyslog = $Global:SwiftLogger_SendSyslog
    $Global:JsonLogging = $Global:SwiftLogger_JsonLogging
    $Global:SyslogRFC = $Global:SwiftLogger_SyslogRFC
    $Global:severityMap = $Global:SwiftLogger_SeverityMap
    $Global:msgIdMap = $Global:SwiftLogger_MsgIdMap

    if (-not $Global:SwiftLogger_QuietMode) {
        Write-Host "SwiftLogger configuration updated:" -ForegroundColor Green
        Write-Host "  LogFilePath: $Global:SwiftLogger_LogFilePath" -ForegroundColor Cyan
        Write-Host "  LogName: $Global:SwiftLogger_LogName" -ForegroundColor Cyan
        Write-Host "  AppName: $Global:SwiftLogger_AppName" -ForegroundColor Cyan
        Write-Host "  ScriptName: $Global:SwiftLogger_ScriptName" -ForegroundColor Cyan
        Write-Host "  JsonLogging: $Global:SwiftLogger_JsonLogging" -ForegroundColor Cyan
        Write-Host "  SendSyslog: $Global:SwiftLogger_SendSyslog" -ForegroundColor Cyan
        if ($Global:SwiftLogger_SendSyslog) {
            Write-Host "  SysLogServer: $Global:SwiftLogger_SysLogServer" -ForegroundColor Cyan
            Write-Host "  SysLogPort: $Global:SwiftLogger_SysLogPort" -ForegroundColor Cyan
            Write-Host "  SysLogRFC: $Global:SwiftLogger_SyslogRFC" -ForegroundColor Cyan
        }
    }
}

function Get-LogConfiguration {
    <#
    .SYNOPSIS
        Retrieves the current SwiftLogger configuration.

    .DESCRIPTION
        Returns the current logging configuration as a PSCustomObject.
        Useful for debugging or exporting configuration.

    .PARAMETER AsHashtable
        Return configuration as a hashtable instead of PSCustomObject.

    .EXAMPLE
        Get-LogConfiguration

        Returns current configuration as a custom object.

    .EXAMPLE
        Get-LogConfiguration -AsHashtable

        Returns current configuration as a hashtable.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [hashtable])]
    param(
        [Parameter()] [switch]$AsHashtable
    )

    $config = @{
        AppName                  = $Global:SwiftLogger_AppName
        SysLogServer             = $Global:SwiftLogger_SysLogServer
        SysLogPort               = $Global:SwiftLogger_SysLogPort
        SysLogRFC                = $Global:SwiftLogger_SyslogRFC
        LogFilePath              = $Global:SwiftLogger_LogFilePath
        LogName                  = $Global:SwiftLogger_LogName
        ScriptName               = $Global:SwiftLogger_ScriptName
        ScriptVersion            = $Global:SwiftLogger_ScriptVersion
        SendSyslog               = $Global:SwiftLogger_SendSyslog
        JsonLogging              = $Global:SwiftLogger_JsonLogging
        QuietMode                = $Global:SwiftLogger_QuietMode
        ConnectionTimeoutSeconds = $Global:SwiftLogger_ConnectionTimeout
    }

    if ($AsHashtable) {
        return $config
    }
    else {
        return [PSCustomObject]$config
    }
}

function Test-LogConfiguration {
    <#
    .SYNOPSIS
        Validates the current SwiftLogger configuration.

    .DESCRIPTION
        Checks if the required configuration settings are present and valid.
        Returns $true if configuration is valid, $false otherwise.

    .PARAMETER RequireSyslog
        Also validate syslog-specific settings (server, port).

    .PARAMETER ThrowOnError
        Throw an exception instead of returning $false if validation fails.

    .EXAMPLE
        if (Test-LogConfiguration) { Write-Log -msg "Ready" -type "general" }

    .EXAMPLE
        Test-LogConfiguration -RequireSyslog -ThrowOnError
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [switch]$RequireSyslog,
        [Parameter()] [switch]$ThrowOnError
    )

    $errors = @()

    # Check basic logging requirements
    if ([string]::IsNullOrWhiteSpace($Global:SwiftLogger_LogFilePath)) {
        $errors += "LogFilePath is not configured. Use Set-LogConfiguration -LogFilePath <path>"
    }
    elseif (-not (Test-Path -Path $Global:SwiftLogger_LogFilePath -PathType Container)) {
        $errors += "LogFilePath '$Global:SwiftLogger_LogFilePath' does not exist and could not be created."
    }

    if ([string]::IsNullOrWhiteSpace($Global:SwiftLogger_LogName)) {
        $errors += "LogName is not configured. Use Set-LogConfiguration -LogName <name>"
    }

    # Check syslog requirements if requested
    if ($RequireSyslog -or $Global:SwiftLogger_SendSyslog) {
        if ([string]::IsNullOrWhiteSpace($Global:SwiftLogger_SysLogServer)) {
            $errors += "SysLogServer is not configured but SendSyslog is enabled."
        }
        if (-not $Global:SwiftLogger_SysLogPort -or $Global:SwiftLogger_SysLogPort -le 0) {
            $errors += "SysLogPort is not configured or invalid."
        }
    }

    if ($errors.Count -gt 0) {
        if ($ThrowOnError) {
            throw "SwiftLogger configuration is invalid:`n- $($errors -join "`n- ")"
        }
        foreach ($err in $errors) {
            Write-Warning "SwiftLogger: $err"
        }
        return $false
    }

    return $true
}

function Reset-LogConfiguration {
    <#
    .SYNOPSIS
        Resets the SwiftLogger configuration to default values.

    .DESCRIPTION
        Clears all SwiftLogger global variables, returning the module to an unconfigured state.

    .EXAMPLE
        Reset-LogConfiguration
    #>
    [CmdletBinding()]
    param()

    # Clear SwiftLogger variables
    $Global:SwiftLogger_AppName = $null
    $Global:SwiftLogger_SysLogServer = $null
    $Global:SwiftLogger_SysLogPort = $null
    $Global:SwiftLogger_LogFilePath = $null
    $Global:SwiftLogger_LogName = $null
    $Global:SwiftLogger_ScriptName = $null
    $Global:SwiftLogger_ScriptVersion = $null
    $Global:SwiftLogger_SendSyslog = $false
    $Global:SwiftLogger_JsonLogging = $false
    $Global:SwiftLogger_QuietMode = $false
    $Global:SwiftLogger_SyslogRFC = 'RFC5424'
    $Global:SwiftLogger_ConnectionTimeout = 5
    $Global:SwiftLogger_SeverityMap = $null
    $Global:SwiftLogger_MsgIdMap = $null

    # Clear backward-compatible variables
    $Global:AppName = $null
    $Global:SysLogServer = $null
    $Global:SysLogPort = $null
    $Global:LogFilePath = $null
    $Global:LogName = $null
    $Global:ScriptName = $null
    $Global:ScriptVersion = $null
    $Global:SendSyslog = $null
    $Global:JsonLogging = $null
    $Global:SyslogRFC = $null
    $Global:severityMap = $null
    $Global:msgIdMap = $null

    Write-Verbose "SwiftLogger configuration has been reset."
}

#endregion

#region Syslog Functions

function New-StructuredSyslogData {
    <#
    .SYNOPSIS
        Creates RFC5424-compliant structured data for syslog messages.

    .DESCRIPTION
        Generates a structured data element in the format [SDID key1="value1" key2="value2"]
        for use with RFC5424 syslog messages.

    .PARAMETER SDID
        Structured Data ID. Custom SDIDs should follow format: name@enterpriseNumber (e.g., exampleSDID@32473)

    .PARAMETER Params
        Hashtable of key-value pairs for the structured data fields.

    .EXAMPLE
        $data = New-StructuredSyslogData -SDID "user@32473" -Params @{username="jdoe"; action="login"}
        # Returns: [user@32473 username="jdoe" action="login"]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SDID,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$Params
    )

    $pairs = $Params.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, '"' + $_.Value + '"' }
    return "[$SDID {0}]" -f ($pairs -join ' ')
}

function Invoke-Syslog {
    <#
    .SYNOPSIS
        Sends syslog messages to a syslog server with RFC5424/RFC3164 support.

    .DESCRIPTION
        Sends messages via UDP, TCP, or TLS with automatic fallback to UDP on failure.
        Supports both modern RFC5424 and legacy RFC3164 message formats.

    .PARAMETER EndPoint
        Hostname or IP address of the syslog server. Supports IPv4, IPv6, and FQDN.

    .PARAMETER Port
        Port number of the syslog server (typically 514 for UDP/TCP, 6514 for TLS).

    .PARAMETER Message
        The syslog message body.

    .PARAMETER Facility
        RFC5424 facility code (0-23). Default: 1 (user-level messages)

    .PARAMETER Severity
        RFC5424 severity level (0-7). Default: 6 (informational)

    .PARAMETER AppName
        Application name in syslog header. Default: "swiftLogger"

    .PARAMETER ProcID
        Process identifier. Default: current process ID

    .PARAMETER MsgID
        Message identifier for correlation. Default: "PSLogging"

    .PARAMETER StructuredData
        RFC5424 structured data element. Use "-" for none.

    .PARAMETER RFC
        Syslog protocol version: 'RFC5424' or 'RFC3164'. Default from configuration.

    .PARAMETER Transport
        Transport protocol: 'UDP', 'TCP', or 'TLS'. Default: 'UDP'

    .PARAMETER IsJson
        If true, adds JSON structured data tag.

    .PARAMETER AllowUntrustedCertificates
        For TLS transport, skip certificate validation. Default: $false (validate certs)

    .EXAMPLE
        Invoke-Syslog -EndPoint "syslog.example.com" -Port 514 -Message "Test message"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndPoint,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [ValidateRange(0, 23)]
        [int]$Facility = 1,

        [ValidateRange(0, 7)]
        [int]$Severity = 6,

        [string]$AppName = "swiftLogger",
        [string]$ProcID = $PID,
        [string]$MsgID = "PSLogging",
        [string]$StructuredData = "-",

        [ValidateSet('RFC5424', 'RFC3164')]
        [string]$RFC,

        [ValidateSet('UDP', 'TCP', 'TLS')]
        [string]$Transport = 'UDP',

        [bool]$IsJson = $false,
        [switch]$AllowUntrustedCertificates
    )

    # Use global RFC setting if not specified
    if (-not $RFC) {
        $RFC = if ($Global:SwiftLogger_SyslogRFC) { $Global:SwiftLogger_SyslogRFC } else { 'RFC5424' }
    }

    $timeout = if ($Global:SwiftLogger_ConnectionTimeout) { $Global:SwiftLogger_ConnectionTimeout * 1000 } else { 5000 }

    try {
        $PRI = ($Facility * 8) + $Severity
        $Hostname = [System.Net.Dns]::GetHostName()

        if ($RFC -eq 'RFC5424') {
            $Version = 1
            $Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            if ($IsJson -and $StructuredData -eq '-') { $StructuredData = '[json@32473 tag="json"]' }
            $SyslogMessage = "<$PRI>$Version $Timestamp $Hostname $AppName $ProcID $MsgID $StructuredData $Message"
        }
        else {
            $Timestamp = (Get-Date).ToString("MMM dd HH:mm:ss")
            $SyslogMessage = "<$PRI>$Timestamp $Hostname $($AppName): $Message"
        }

        $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) | Where-Object { $_.AddressFamily -in @('InterNetwork', 'InterNetworkV6') } | Select-Object -First 1
        if (-not $IP) { throw "Unable to resolve endpoint '$EndPoint'" }

        $EndPoints = New-Object System.Net.IPEndPoint($IP, $Port)
        $EncodedText = [Text.Encoding]::UTF8.GetBytes($SyslogMessage)
        $sent = $false

        switch ($Transport) {
            'UDP' {
                $Socket = $null
                try {
                    $Socket = New-Object System.Net.Sockets.UdpClient
                    [void]$Socket.Send($EncodedText, $EncodedText.Length, $EndPoints)
                    $sent = $true
                    Write-Verbose "Syslog sent via UDP to $EndPoint`:$Port"
                }
                catch {
                    Write-Verbose "UDP send failed: $_"
                }
                finally {
                    if ($Socket) { $Socket.Dispose() }
                }
            }
            'TCP' {
                $Client = $Stream = $null
                try {
                    $Client = New-Object System.Net.Sockets.TcpClient
                    $connectTask = $Client.ConnectAsync($IP.ToString(), $Port)
                    if (-not $connectTask.Wait($timeout)) {
                        throw "Connection timed out after $($timeout/1000) seconds"
                    }
                    $Stream = $Client.GetStream()
                    $Stream.Write($EncodedText, 0, $EncodedText.Length)
                    $sent = $true
                    Write-Verbose "Syslog sent via TCP to $EndPoint`:$Port"
                }
                catch {
                    Write-Verbose "TCP send failed: $_"
                }
                finally {
                    if ($Stream) { $Stream.Dispose() }
                    if ($Client) { $Client.Dispose() }
                }
            }
            'TLS' {
                $Client = $Stream = $SslStream = $null
                try {
                    $Client = New-Object System.Net.Sockets.TcpClient
                    $connectTask = $Client.ConnectAsync($IP.ToString(), $Port)
                    if (-not $connectTask.Wait($timeout)) {
                        throw "Connection timed out after $($timeout/1000) seconds"
                    }
                    $Stream = $Client.GetStream()

                    # Certificate validation callback
                    $certCallback = if ($AllowUntrustedCertificates) {
                        { param($s, $c, $ch, $e) $true }
                    }
                    else {
                        { param($sslSender, $cert, $chain, $sslErrors) $sslErrors -eq [System.Net.Security.SslPolicyErrors]::None }
                    }

                    $SslStream = New-Object System.Net.Security.SslStream($Stream, $false, $certCallback)
                    $SslStream.AuthenticateAsClient($EndPoint)
                    $SslStream.Write($EncodedText, 0, $EncodedText.Length)
                    $sent = $true
                    Write-Verbose "Syslog sent via TLS to $EndPoint`:$Port"
                }
                catch {
                    Write-Verbose "TLS send failed: $_"
                }
                finally {
                    if ($SslStream) { $SslStream.Dispose() }
                    if ($Stream) { $Stream.Dispose() }
                    if ($Client) { $Client.Dispose() }
                }
            }
        }

        # Fallback to UDP if primary transport failed
        if (-not $sent -and $Transport -ne 'UDP') {
            $Socket = $null
            try {
                $Socket = New-Object System.Net.Sockets.UdpClient
                [void]$Socket.Send($EncodedText, $EncodedText.Length, $EndPoints)
                Write-Verbose "Fallback to UDP successful."
                $sent = $true
            }
            catch {
                Write-Error "Fallback to UDP also failed: $_"
            }
            finally {
                if ($Socket) { $Socket.Dispose() }
            }
        }

        return $sent

    }
    catch {
        Write-Error "Failed to send syslog message: $_"
        return $false
    }
}

#endregion

#region Logging Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes log entries to file and optionally to console and syslog.

    .DESCRIPTION
        Primary logging function that handles console output, file logging (text or JSON),
        and optional syslog delivery. Can be used without syslog configuration for local-only logging.

    .PARAMETER msg
        The log message text to write.

    .PARAMETER type
        Log level/type: 'error', 'warn', 'success', 'general', or 'debug'

    .PARAMETER SendSysLog
        Override global setting to send this message to syslog.

    .PARAMETER OutputJson
        Override global setting to output this message in JSON format.

    .PARAMETER Quiet
        Suppress console output for this message only.

    .PARAMETER PassThru
        Return the log entry object for pipeline processing.

    .EXAMPLE
        Write-Log -msg "Application started" -type "general"

        Simple local logging.

    .EXAMPLE
        Write-Log -msg "Error occurred" -type "error" -SendSysLog $true

        Log locally and send to syslog.

    .EXAMPLE
        $entry = Write-Log -msg "Processing" -type "general" -PassThru -Quiet

        Log to file silently and capture the entry object.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$msg,

        [Parameter(Mandatory = $true)]
        [ValidateSet('error', 'warn', 'success', 'general', 'debug', IgnoreCase = $true)]
        [String]$type,

        [Parameter()]
        [bool]$SendSysLog,

        [Parameter()]
        [bool]$OutputJson,

        [Parameter()]
        [switch]$Quiet,

        [Parameter()]
        [switch]$PassThru
    )

    # Validate configuration before proceeding
    if (-not (Test-LogConfiguration)) {
        throw "SwiftLogger is not properly configured. Use Set-LogConfiguration first."
    }

    # Apply global defaults if parameters not explicitly provided
    if (-not $PSBoundParameters.ContainsKey('SendSysLog')) {
        $SendSysLog = switch ($Global:SwiftLogger_SendSyslog) {
            { $_ -is [bool] } { $_ }
            { $_ -is [string] } { [System.Convert]::ToBoolean($_) }
            default { $false }
        }
    }

    if (-not $PSBoundParameters.ContainsKey('OutputJson')) {
        $OutputJson = switch ($Global:SwiftLogger_JsonLogging) {
            { $_ -is [bool] } { $_ }
            { $_ -is [string] } { [System.Convert]::ToBoolean($_) }
            default { $false }
        }
    }

    # Determine if console output should be suppressed
    $suppressConsole = $Quiet.IsPresent -or $Global:SwiftLogger_QuietMode

    # Generate log entry
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - [$type] - $msg"
    $logFile = Join-Path -Path $Global:SwiftLogger_LogFilePath -ChildPath "$($Global:SwiftLogger_LogName).log"
    $logFileJson = Join-Path -Path $Global:SwiftLogger_LogFilePath -ChildPath "$($Global:SwiftLogger_LogName).json"

    # Create entry object for JSON/PassThru
    $entryObject = [PSCustomObject]@{
        timestamp    = $timestamp
        level        = $type.ToLower()
        message      = $msg
        appName      = $Global:SwiftLogger_AppName
        script       = $Global:SwiftLogger_ScriptName
        version      = $Global:SwiftLogger_ScriptVersion
        computerName = $env:ComputerName
    }

    # Console output with colors (unless suppressed)
    if (-not $suppressConsole) {
        switch ($type.ToLower()) {
            "error" { Write-Host $logEntry -ForegroundColor DarkRed -BackgroundColor Red }
            "warn" { Write-Host $logEntry -ForegroundColor DarkYellow -BackgroundColor Yellow }
            "success" { Write-Host $logEntry -ForegroundColor DarkGreen -BackgroundColor Green }
            "general" { Write-Host $logEntry -ForegroundColor Black -BackgroundColor White }
            "debug" { Write-Host $logEntry -ForegroundColor DarkBlue -BackgroundColor Blue }
        }
    }

    # File output
    try {
        if ($OutputJson) {
            $jsonEntry = $entryObject | ConvertTo-Json -Compress
            Add-Content -Path $logFileJson -Value $jsonEntry -ErrorAction Stop
        }
        else {
            Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Failed to write to log file: $_"
    }

    # Syslog delivery (only if configured and enabled)
    if ($SendSysLog) {
        if ([string]::IsNullOrWhiteSpace($Global:SwiftLogger_SysLogServer)) {
            Write-Warning "SendSysLog is enabled but SysLogServer is not configured. Skipping syslog."
        }
        elseif (-not $Global:SwiftLogger_SysLogPort -or $Global:SwiftLogger_SysLogPort -le 0) {
            Write-Warning "SendSysLog is enabled but SysLogPort is not configured. Skipping syslog."
        }
        else {
            $severity = $Global:SwiftLogger_SeverityMap[$type.ToLower()]
            if (-not $severity) { $severity = 6 }
            $msgId = $Global:SwiftLogger_MsgIdMap[$type.ToLower()]
            if (-not $msgId) { $msgId = 'UNKNOWN' }

            $syslogMessage = if ($OutputJson) {
                $entryObject | ConvertTo-Json -Compress
            }
            elseif ($Global:SwiftLogger_SyslogRFC -eq 'RFC3164') {
                "[$Global:SwiftLogger_AppName] [$Global:SwiftLogger_ScriptName] - [$type] - $msg"
            }
            else {
                $msg
            }

            try {
                Invoke-Syslog -EndPoint $Global:SwiftLogger_SysLogServer `
                    -Port $Global:SwiftLogger_SysLogPort `
                    -Message $syslogMessage `
                    -Severity $severity `
                    -MsgID $msgId `
                    -AppName $Global:SwiftLogger_AppName `
                    -IsJson:$OutputJson `
                    -Verbose:$VerbosePreference | Out-Null
            }
            catch {
                Write-Warning "Failed to send syslog message: $_"
            }
        }
    }

    # Return object if PassThru requested
    if ($PassThru) {
        return $entryObject
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Set-LogConfiguration',
    'Get-LogConfiguration',
    'Test-LogConfiguration',
    'Reset-LogConfiguration',
    'New-StructuredSyslogData',
    'Invoke-Syslog',
    'Write-Log'
)
