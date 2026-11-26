@{
    RootModule        = 'WinEventTriage.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b74c51f2-8a4f-41c8-9a21-6c7f92b41901'
    Author            = 'Gabriel Souza (@gavicoding)'
    CompanyName       = 'Gavicoding'
    Copyright         = '(c) 2026 Gabriel Souza. MIT License.'
    Description       = 'Read-only Windows Security, System, PowerShell, and Defender Event Log triage engine mapped to MITRE ATT&CK.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Export-WinEventSnapshot',
        'Invoke-WinEventTriage',
        'Get-WinEventTriageRule'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
