function Set-LogConfiguration {
    param(
        [Parameter()] [String]$AppName,
        [Parameter()] [String]$SysLogServer,
        [Parameter()] [int]$SysLogPort,
        [ValidateSet('RFC5424','RFC3164')] [Parameter()] [string]$SysLogRFC,
        [Parameter()] [String]$LogFilePath,
        [Parameter()] [String]$LogName,
        [Parameter()] [String]$ScriptName,
        [Parameter()] [String]$ScriptVersion,
        [Parameter()] [bool]$SendSyslog,
        [Parameter()] [bool]$JsonLogging
    )

    if ($PSBoundParameters.ContainsKey('AppName'))        { $Global:AppName        = $AppName }
    if ($PSBoundParameters.ContainsKey('SysLogServer'))   { $Global:SysLogServer   = $SysLogServer }
    if ($PSBoundParameters.ContainsKey('SysLogPort'))     { $Global:SysLogPort     = $SysLogPort }
    if ($PSBoundParameters.ContainsKey('LogFilePath'))    { $Global:LogFilePath    = $LogFilePath }
    if ($PSBoundParameters.ContainsKey('LogName'))        { $Global:LogName        = $LogName }
    if ($PSBoundParameters.ContainsKey('ScriptName'))     { $Global:ScriptName     = $ScriptName }
    if ($PSBoundParameters.ContainsKey('ScriptVersion'))  { $Global:ScriptVersion  = $ScriptVersion }
    if ($PSBoundParameters.ContainsKey('SendSyslog'))     { $Global:SendSyslog     = [System.Convert]::ToBoolean($SendSyslog) }
    if ($PSBoundParameters.ContainsKey('JsonLogging'))    { $Global:JsonLogging    = [System.Convert]::ToBoolean($JsonLogging) }
    $Global:SyslogRFC = if ($PSBoundParameters.ContainsKey('SysLogRFC')) { $SysLogRFC } else { 'RFC5424' }

    # Ensure log directory exists
    if (-not [string]::IsNullOrWhiteSpace($Global:LogFilePath)) {
        if (-not (Test-Path -Path $Global:LogFilePath -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $Global:LogFilePath -Force | Out-Null
                Write-Host "Created missing log directory: $Global:LogFilePath" -ForegroundColor Yellow
            } catch {
                throw "Failed to create log directory: $_"
            }
        }
    } else {
        throw "LogFilePath cannot be null or empty."
    }

    # Define global severity and message ID maps
    $Global:severityMap = @{error = 3; warn = 4; success = 5; general = 6; debug = 7 }
    $Global:msgIdMap = @{ error='ERR'; warn='WRN'; success='SUC'; general='INF'; debug='DBG' }

    Write-Host "Log configuration updated:" -ForegroundColor Green
    Write-Host "AppName: $Global:AppName" -ForegroundColor Cyan
    Write-Host "SysLogServer: $Global:SysLogServer" -ForegroundColor Cyan
    Write-Host "SysLogPort: $Global:SysLogPort" -ForegroundColor Cyan
    Write-Host "SysLogRFC: $Global:SyslogRFC" -ForegroundColor Cyan
    Write-Host "LogFilePath: $Global:LogFilePath" -ForegroundColor Cyan
    Write-Host "LogName: $Global:LogName" -ForegroundColor Cyan
    Write-Host "ScriptName: $Global:ScriptName" -ForegroundColor Cyan
    Write-Host "ScriptVersion: $Global:ScriptVersion" -ForegroundColor Cyan
    Write-Host "SendSyslog: $Global:SendSyslog" -ForegroundColor Cyan
    Write-Host "JsonLogging: $Global:JsonLogging" -ForegroundColor Cyan
    Write-Host "SeverityMap: $(($Global:severityMap | ConvertTo-Json -Compress))" -ForegroundColor Cyan
    Write-Host "MessageIDMap: $(($Global:msgIdMap | ConvertTo-Json -Compress))" -ForegroundColor Cyan
}

function New-StructuredSyslogData {
    Param (
        [Parameter(Mandatory)] [string] $SDID,
        [Parameter(Mandatory)] [hashtable] $Params
    )
    $pairs = $Params.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, '"' + $_.Value + '"' }
    return "[$SDID {0}]" -f ($pairs -join ' ')
}

function Invoke-Syslog {
    param(
        [Parameter(Mandatory)] [string] $EndPoint,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Message,
        [ValidateRange(0,23)] [int] $Facility = 1,
        [ValidateRange(0,7)] [int] $Severity = 6,
        [string] $AppName = "swiftLogger",
        [string] $ProcID = $PID,
        [string] $MsgID = "PSLogging",
        [string] $StructuredData = "-",
        [ValidateSet('RFC5424','RFC3164')] [string] $RFC = $Global:SyslogRFC,
        [ValidateSet('UDP','TCP','TLS')] [string] $Transport = 'UDP',
        [bool]$IsJson = $false
    )

    try {
        $PRI = ($Facility * 8) + $Severity
        $Hostname = [System.Net.Dns]::GetHostName()

        if ($RFC -eq 'RFC5424') {
            $Version = 1
            $Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            if ($IsJson -and $StructuredData -eq '-') { $StructuredData = '[json@32473 tag="json"]' }
            $SyslogMessage = "<$PRI>$Version $Timestamp $Hostname $AppName $ProcID $MsgID $StructuredData $Message"
        } else {
            $Timestamp = (Get-Date).ToString("MMM dd HH:mm:ss")
            $SyslogMessage = "<$PRI>$Timestamp $Hostname $($AppName): $Message"
        }

        $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) | Where-Object { $_.AddressFamily -in @('InterNetwork','InterNetworkV6') } | Select-Object -First 1
        if (-not $IP) { throw "Unable to resolve endpoint $EndPoint" }

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
                } catch {
                    Write-Verbose "UDP send failed: $_"
                } finally {
                    if ($Socket) { $Socket.Dispose() }
                }
            }
            'TCP' {
                $Client = $Stream = $null
                try {
                    $Client = New-Object System.Net.Sockets.TcpClient($IP.ToString(), $Port)
                    $Stream = $Client.GetStream()
                    $Stream.Write($EncodedText, 0, $EncodedText.Length)
                    $sent = $true
                } catch {
                    Write-Verbose "TCP send failed: $_"
                } finally {
                    if ($Stream) { $Stream.Dispose() }
                    if ($Client) { $Client.Dispose() }
                }
            }
            'TLS' {
                $Client = $Stream = $SslStream = $null
                try {
                    $Client = New-Object System.Net.Sockets.TcpClient($IP.ToString(), $Port)
                    $Stream = $Client.GetStream()
                    $SslStream = New-Object System.Net.Security.SslStream($Stream, $false, ({$true}))
                    $SslStream.AuthenticateAsClient($EndPoint)
                    $SslStream.Write($EncodedText, 0, $EncodedText.Length)
                    $sent = $true
                } catch {
                    Write-Verbose "TLS send failed: $_"
                } finally {
                    if ($SslStream) { $SslStream.Dispose() }
                    if ($Stream) { $Stream.Dispose() }
                    if ($Client) { $Client.Dispose() }
                }
            }
        }

        if (-not $sent) {
            $Socket = $null
            try {
                $Socket = New-Object System.Net.Sockets.UdpClient
                [void]$Socket.Send($EncodedText, $EncodedText.Length, $EndPoints)
                Write-Verbose "Fallback to UDP successful."
            } catch {
                Write-Error "Fallback to UDP failed: $_"
            } finally {
                if ($Socket) { $Socket.Dispose() }
            }
        }

    } catch {
        Write-Error "Failed to send syslog message: $_"
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)] [String]$msg,
        [Parameter(Mandatory=$true)] [String]$type,
        [Parameter()] [bool]$SendSysLog = $false,
        [Parameter()] [bool]$OutputJson = $false
    )

    # Apply global defaults if they exist
    if (-not $PSBoundParameters.ContainsKey('SendSysLog')) {
        $SendSysLog = switch ($Global:SendSyslog) {
            {$_ -is [bool]}   { $_ }
            {$_ -is [string]} { [System.Convert]::ToBoolean($_) }
            default           { $false }
        }
    }

    if (-not $PSBoundParameters.ContainsKey('OutputJson')) {
        $OutputJson = switch ($Global:JsonLogging) {
            {$_ -is [bool]}   { $_ }
            {$_ -is [string]} { [System.Convert]::ToBoolean($_) }
            default           { $false }
        }
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - [$type] - $msg"
    $logFile = "$Global:LogFilePath\$Global:LogName.log"
    $logFileJson = "$Global:LogFilePath\$Global:LogName.json"

    if ($OutputJson) {
        $jsonEntry = @{ timestamp=$timestamp; level=$type; message=$msg; appName=$Global:AppName; script=$Global:ScriptName; version=$Global:ScriptVersion; computerName=$env:ComputerName } | ConvertTo-Json -Compress
    }

    switch ($type.ToLower()) {
        "error"   { Write-Host $logEntry -ForegroundColor DarkRed -BackgroundColor Red }
        "warn"    { Write-Host $logEntry -ForegroundColor DarkYellow -BackgroundColor Yellow }
        "success" { Write-Host $logEntry -ForegroundColor DarkGreen -BackgroundColor Green }
        "general" { Write-Host $logEntry -ForegroundColor Black -BackgroundColor White }
        "debug"   { Write-Host $logEntry -ForegroundColor DarkBlue -BackgroundColor Blue }
        default   { Write-Host "Warning: Invalid log type." -ForegroundColor Yellow }
    }

    if ($OutputJson) { Add-Content -Path $logFileJson -Value $jsonEntry } else { Add-Content -Path $logFile -Value $logEntry }

    if ($SendSysLog) {
        $severity = $global:severityMap[$type.ToLower()] ; if (-not $severity) { $severity = 6 }
        $msgId = $global:msgIdMap[$type.ToLower()] ; if (-not $msgId) { $msgId = 'UNKNOWN' }
        $syslogMessage = if ($OutputJson) { $jsonEntry } elseif ($Global:SyslogRFC -eq 'RFC3164') { "[$Global:AppName] [$Global:ScriptName] - [$type] - $msg" } else { "$msg" }
        Invoke-Syslog -EndPoint $Global:SysLogServer -Port $Global:SysLogPort -Message $syslogMessage -Severity $severity -MsgID $msgId -AppName $Global:AppName -IsJson:$OutputJson -Verbose
    }
}

Export-ModuleMember -Function Invoke-Syslog, Write-Log, New-StructuredSyslogData, Set-LogConfiguration