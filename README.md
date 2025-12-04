# swiftLogger

A PowerShell module for comprehensive logging and syslog integration with RFC5424/RFC3164 support, JSON formatting, IPv6, and intelligent UDP/TCP/TLS fallback capabilities. Designed for enterprise logging scenarios requiring flexible, multi-transport log delivery.

## Features

- **RFC5424 & RFC3164 Compliance**: Full support for both RFC5424 (modern) and RFC3164 (legacy) syslog protocols
- **JSON Structured Logging**: Generate structured JSON log entries with comprehensive context (timestamp, level, message, script name, version, computer name)
- **Dual Output Support**: Write logs to both file-based logs and JSON log files simultaneously
- **IPv6 Support**: Works with both IPv4 and IPv6 addresses with automatic address family detection
- **Intelligent Transport Fallback**: Attempt TCP or TLS first, with automatic fallback to UDP if primary transport fails
- **Colored Console Output**: Color-coded log levels in PowerShell console (Error, Warning, Success, General, Debug)
- **Flexible Facility/Severity Mapping**: Full RFC5424 facility (0-23) and severity (0-7) support with automatic mapping
- **Structured Data Support**: Create RFC5424 structured data elements with custom SDIDs
- **Global Configuration**: Centralized logging configuration accessible throughout your scripts

## Installation

Install from the [PowerShell Gallery](https://www.powershellgallery.com/packages/swiftLogger):

```powershell
Install-Module -Name swiftLogger
```

## Quick Start

### 1. Configure Logging

Before using the module, configure your logging settings:

```powershell
Set-LogConfiguration -SysLogServer "syslog.example.com" `
                     -SysLogPort 514 `
                     -LogFilePath "C:\Logs" `
                     -LogName "MyApplication" `
                     -ScriptName "MyScript" `
                     -ScriptVersion "1.0" `
                     -SendSyslog $true `
                     -JsonLogging $true
```

### 2. Write Logs

Use the Write-Log function with different log types:

```powershell
Write-Log -msg "Application started" -type "general"
Write-Log -msg "Processing file" -type "success"
Write-Log -msg "Something went wrong" -type "error"
Write-Log -msg "Detailed debug info" -type "debug"
Write-Log -msg "Check this condition" -type "warn"
```

### 3. Send Direct Syslog Messages

For more control over syslog parameters:

```powershell
Invoke-Syslog -EndPoint "syslog.example.com" `
              -Port 514 `
              -Message "Custom syslog message" `
              -Facility 16 `
              -Severity 5 `
              -Transport "TCP"
```

### 4. Create Structured Syslog Data

Build RFC5424 structured data elements:

```powershell
$structData = New-StructuredSyslogData -SDID "exampleSDID@32473" `
                                       -Params @{
                                           user = "john.doe"
                                           action = "login"
                                           result = "success"
                                       }
```

## Detailed Function Reference

### Set-LogConfiguration

Configures global logging settings used by other functions.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `AppName` | String | No | Application name identifier, included in JSON logs and syslog messages. Used to identify the source application in logs. |
| `SysLogServer` | String | No | Hostname or IP address of the syslog server. Used by `Write-Log` when `SendSyslog` is enabled. |
| `SysLogPort` | Integer | No | Port number of the syslog server (typically 514 for UDP/TCP, 6514 for TLS). Used by `Write-Log` when `SendSyslog` is enabled. |
| `LogFilePath` | String | No | Directory path where log files will be created. Both `.log` and `.json` files are written here. |
| `LogName` | String | No | Base name for log files (without extension). Creates `{LogName}.log` and `{LogName}.json` files. |
| `ScriptName` | String | No | Name of the calling script, included in JSON logs and syslog messages for identification. |
| `ScriptVersion` | String | No | Version of the calling script, included in JSON logs and syslog messages. |
| `SendSyslog` | Boolean | No | Whether `Write-Log` should automatically send messages to the syslog server. Default: $false |
| `JsonLogging` | Boolean | No | Whether `Write-Log` should output JSON format logs. If $true, both JSON and plain text logs are written. Default: $false |

**Example:**

```powershell
Set-LogConfiguration -AppName "MyApplication" `
                     -SysLogServer "10.0.0.50" `
                     -SysLogPort 514 `
                     -LogFilePath "C:\Logs\MyApp" `
                     -LogName "Application" `
                     -ScriptName "Deploy-Script" `
                     -ScriptVersion "2.1.0" `
                     -SendSyslog $true `
                     -JsonLogging $true
```

---

### Write-Log

Writes log entries to file and optionally to syslog server. Handles colored console output, file logging, JSON logging, and syslog delivery.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `msg` | String | Yes | - | The log message text to write. |
| `type` | String | Yes | - | Log level/type. Valid values: `error`, `warn`, `success`, `general`, `debug` |
| `SendSysLog` | Boolean | No | $Global:SendSyslog | Override global setting to send this message to syslog. |
| `OutputJson` | Boolean | No | $Global:JsonLogging | Override global setting to output this message in JSON format. |

**Log Type Color Mapping:**

| Type | Console Color | Syslog Severity | Description |
|------|---------------|-----------------|-------------|
| `error` | Dark Red on Red | 3 (Error) | Critical error condition |
| `warn` | Dark Yellow on Yellow | 4 (Warning) | Warning condition |
| `success` | Dark Green on Green | 5 (Notice) | Successful operation |
| `general` | Black on White | 6 (Info) | General informational message |
| `debug` | Dark Blue on Blue | 7 (Debug) | Debug-level detail |

**Output Files:**

- Plain Text: `{LogFilePath}\{LogName}.log` - Contains timestamp, log type, and message
- JSON Format: `{LogFilePath}\{LogName}.json` - Contains structured JSON with metadata

**JSON Log Entry Example:**

**JSON Log Entry Example:**

```json
{"timestamp":"2025-12-04 16:35:22","level":"error","message":"Database connection failed","appName":"MyApplication","script":"Deploy-Script","version":"2.1.0","computerName":"SERVER01"}
```

**Message ID Mapping:**

When using `Write-Log` with the syslog feature enabled, MsgID is automatically mapped based on the log type:

| Log Type | MsgID | Purpose |
|----------|-------|---------|
| `error` | ERR | Error condition messages |
| `warn` | WRN | Warning condition messages |
| `success` | SUC | Successful operation messages |
| `general` | INF | General informational messages |
| `debug` | DBG | Debug-level detail messages |

**Example:**

```powershell
Write-Log -msg "User authentication successful" -type "success"
Write-Log -msg "Retry attempt 3 of 5" -type "debug" -SendSysLog $true
```

---

### Invoke-Syslog

Sends syslog messages directly to a syslog server with full RFC5424/RFC3164 support, multiple transport options, and intelligent fallback.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `EndPoint` | String | Yes | - | Hostname or IP address of the syslog server. Can be IPv4, IPv6, or FQDN. |
| `Port` | Integer | Yes | - | Port number of the syslog server (514 for standard, 6514 for TLS). |
| `Message` | String | Yes | - | The syslog message body. |
| `Facility` | Integer | No | 1 (User-level) | RFC5424 facility code (0-23). Defines message source category. |
| `Severity` | Integer | No | 6 (Informational) | RFC5424 severity level (0-7). Defines message priority. |
| `AppName` | String | No | "swiftLogger" | Application name in syslog header. Identifies the source application. Set via `Set-LogConfiguration`. |
| `ProcID` | String | No | $PID (current process ID) | Process identifier in syslog header. |
| `MsgID` | String | No | "PSLogging" | Message identifier in syslog header for tracking/correlation. Auto-mapped by `Write-Log` based on log type. |
| `StructuredData` | String | No | "-" | RFC5424 structured data element (e.g., `[exampleSDID@32473 key1="value1"]`). Use "-" for none. |
| `RFC` | String | No | "RFC5424" | Syslog protocol version. Valid values: `RFC5424` (modern), `RFC3164` (legacy). |
| `Transport` | String | No | "UDP" | Primary transport protocol. Valid values: `UDP`, `TCP`, `TLS` |
| `IsJson` | Boolean | No | $false | If $true, marks message as JSON in structured data for syslog server handling. |

**Facility Codes (0-23):**

| Code | Name | Purpose |
|------|------|---------|
| 0 | kernel messages | Operating system kernel |
| 1 | user-level messages | User-level applications |
| 2 | mail system | Mail system |
| 3 | system daemons | System daemons |
| 4 | security/authorization | Security/authorization messages |
| 16 | local use 0 (local0) | Local application use |
| 17-23 | local use 1-7 (local1-7) | Local application use |

**Severity Codes (0-7):**

| Code | Name | Description |
|------|------|-------------|
| 0 | Emergency | System unusable |
| 1 | Alert | Action must be taken immediately |
| 2 | Critical | Critical condition |
| 3 | Error | Error condition |
| 4 | Warning | Warning condition |
| 5 | Notice | Normal but significant condition |
| 6 | Informational | Informational message |
| 7 | Debug | Debug-level detail |

**Transport Behavior:**

- **UDP**: Connectionless, fast, best-effort delivery. Tries first in fallback chain.
- **TCP**: Connection-based, reliable delivery. Falls back to UDP on failure.
- **TLS**: Encrypted TCP connection with certificate validation. Falls back to UDP on failure.

**Example - Basic Syslog:**

```powershell
Invoke-Syslog -EndPoint "syslog.corp.com" `
              -Port 514 `
              -Message "Application startup completed successfully"
```

**Example - With Severity and Facility:**

```powershell
Invoke-Syslog -EndPoint "syslog.corp.com" `
              -Port 514 `
              -Message "Database connection failed" `
              -Facility 16 `
              -Severity 3 `
              -AppName "DatabaseService"
```

**Example - RFC3164 Legacy Format:**

```powershell
Invoke-Syslog -EndPoint "legacy-syslog.internal" `
              -Port 514 `
              -Message "Old system event" `
              -RFC "RFC3164" `
              -Transport "UDP"
```

**Example - With Structured Data:**

```powershell
$structData = New-StructuredSyslogData -SDID "user@32473" `
                                       -Params @{uid="12345"; username="jdoe"}
Invoke-Syslog -EndPoint "syslog.corp.com" `
              -Port 514 `
              -Message "User login event" `
              -Facility 4 `
              -Severity 6 `
              -StructuredData $structData
```

---

### New-StructuredSyslogData

Creates RFC5424-compliant structured data elements for inclusion in syslog messages.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `SDID` | String | Yes | Structured Data ID (SDID). Custom SDIDs should follow format: `name@enterpriseNumber`. Example: `exampleSDID@32473` |
| `Params` | Hashtable | Yes | Key-value pairs containing the structured data fields. Values are automatically quoted. |

**Returns:** String in format `[SDID key1="value1" key2="value2"]`

**Example:**

```powershell
$structData = New-StructuredSyslogData -SDID "user@32473" `
                                       -Params @{
                                           username = "jdoe"
                                           action = "login"
                                           result = "success"
                                           ipaddress = "192.168.1.100"
                                       }
# Output: [user@32473 username="jdoe" action="login" result="success" ipaddress="192.168.1.100"]
```

---

## Advanced Usage Examples

### Complete Logging Workflow

```powershell
# 1. Configure once at script start
Set-LogConfiguration -SysLogServer "syslog.corp.com" `
                     -SysLogPort 514 `
                     -LogFilePath "C:\Logs\Deployment" `
                     -LogName "Deploy-2025-12-04" `
                     -ScriptName "Deploy-WebApp" `
                     -ScriptVersion "3.2.1" `
                     -SendSyslog $true `
                     -JsonLogging $true

# 2. Use Write-Log throughout script
try {
    Write-Log -msg "Starting application deployment" -type "general"
    
    # Do work...
    
    Write-Log -msg "Application deployed successfully" -type "success"
} catch {
    Write-Log -msg "Deployment failed: $_" -type "error"
}

# 3. Send audit event with structured data
$auditData = New-StructuredSyslogData -SDID "audit@32473" `
                                      -Params @{
                                          action = "deploy"
                                          user = $env:USERNAME
                                          target = "prod-web-01"
                                          status = "completed"
                                      }
Invoke-Syslog -EndPoint "syslog.corp.com" `
              -Port 514 `
              -Message "Production deployment completed" `
              -Facility 4 `
              -Severity 5 `
              -StructuredData $auditData
```

### Multi-Transport Scenario

```powershell
# Try encrypted TLS first, fallback to TCP, then UDP
Invoke-Syslog -EndPoint "secure-syslog.internal" `
              -Port 6514 `
              -Message "Sensitive audit event" `
              -Transport "TLS" `
              -Facility 4 `
              -Severity 2
```

### JSON-Only Logging

```powershell
# Log structured JSON for downstream processing
Set-LogConfiguration -LogFilePath "C:\Logs\API" `
                     -LogName "rest-api" `
                     -ScriptName "API-Service" `
                     -ScriptVersion "1.0" `
                     -JsonLogging $true

Write-Log -msg "Incoming request from 192.168.1.50 for /api/users" -type "general"
# Creates JSON: {"timestamp":"2025-12-04 16:35:22","level":"general","message":"Incoming request...","script":"API-Service","version":"1.0","computerName":"SERVER01"}
```

---

## Global Variables

After calling `Set-LogConfiguration`, the following global variables are available:

- `$Global:AppName` - Application name identifier
- `$Global:SysLogServer` - Syslog server hostname/IP
- `$Global:SysLogPort` - Syslog server port
- `$Global:LogFilePath` - Log file directory
- `$Global:LogName` - Log file name
- `$Global:ScriptName` - Calling script name
- `$Global:ScriptVersion` - Script version
- `$Global:SendSyslog` - Whether to send to syslog
- `$Global:JsonLogging` - Whether to use JSON format

---

## Requirements

- PowerShell 5.1 or higher
- Network access to syslog server (for syslog functionality)
- Write permissions to log file path
- For TLS transport: Valid SSL/TLS certificates on syslog server

## License

This project is licensed under the GNU General Public License v3.0 - see [GNU GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html) for details.

## Author

Scott Powdrill

## Support

For issues, feature requests, or contributions, please visit the project repository or the [PowerShell Gallery](https://www.powershellgallery.com/packages/swiftLogger) package page.
