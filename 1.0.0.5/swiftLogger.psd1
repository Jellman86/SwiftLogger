@{
    RootModule        = 'swiftlogger.psm1'
    ModuleVersion     = '1.0.0.5'
    GUID              = 'e2f9f8b2-4d2e-4f9a-bb7d-abcdef445566'
    Author            = 'Scott Powdrill'
    Description       = 'PowerShell module for logging and syslog integration with RFC5424/RFC3164, JSON support, IPv6, UDP/TCP/TLS fallback. Works standalone (local logging) or with syslog servers.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Set-LogConfiguration',
        'Get-LogConfiguration',
        'Test-LogConfiguration',
        'Reset-LogConfiguration',
        'New-StructuredSyslogData',
        'Invoke-Syslog',
        'Write-Log'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('Log', 'Logging', 'Syslog', 'RFC5424', 'RFC3164', 'JSON', 'PowerShell')
            LicenseUri   = 'https://github.com/Jellman86/SwiftLogger/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Jellman86/SwiftLogger'
            ReleaseNotes = @'
Version 1.0.0.5:
- Added Get-LogConfiguration to query current settings
- Added Test-LogConfiguration to validate configuration
- Added Reset-LogConfiguration to clear settings
- Added connection timeout for TCP/TLS (prevents hangs)
- Added QuietMode and -Quiet switch to suppress console output
- Added -PassThru switch to Write-Log for pipeline support
- Fixed TLS certificate validation (now validates by default)
- Added -AllowUntrustedCertificates switch for TLS
- Added full comment-based help for all functions
- Improved error handling throughout
- Local-only logging works without syslog configuration
- Maintains backward compatibility with v1.0.0.4 global variables
'@
        }
    }
}
