
@{
    RootModule = 'swiftlogger.psm1'
    ModuleVersion = '1.0.0.4'
    GUID = 'e2f9f8b2-4d2e-4f9a-bb7d-abcdef445566'
    Author = 'Scott Powdrill'
    Description = 'PowerShell module for logging and syslog integration with RFC5424, JSON support, IPv6, UDP/TCP/TLS fallback, and configuration helper.'
    FunctionsToExport = @('Invoke-Syslog','Write-Log','New-StructuredSyslogData','Set-LogConfiguration')
    PowerShellVersion = '5.1'
    PrivateData = @{
            PSData = @{
                Tags                       = @('Log','Syslog','RFC5424','JSON','PowerShell')
                LicenseUri                 = 'https://github.com/Jellman86/SwiftLogger/blob/main/LICENSE'
                ProjectUri                 = 'https://github.com/Jellman86/SwiftLogger'
                ReleaseNotes               = 'Updated to fix boolean handling in structured data.'
            }
    }
}
