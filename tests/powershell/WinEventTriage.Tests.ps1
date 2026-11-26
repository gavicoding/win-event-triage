BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $repoRoot 'WinEventTriage\WinEventTriage.psd1') -Force
    $script:SamplesDir = Join-Path $repoRoot 'samples'
}

Describe 'WinEventTriage Module' {
    It 'lists all 23 MITRE ATT&CK rules in English and Portuguese' {
        $enRules = Get-WinEventTriageRule -Language en
        $ptRules = Get-WinEventTriageRule -Language pt
        $enRules.Count | Should -Be 23
        $ptRules.Count | Should -Be 23
        $enRules[0].RuleId | Should -Be 'WET001'
    }

    It 'detects multi-stage ransomware intrusion indicators' {
        $rep = Invoke-WinEventTriage -SnapshotPath (Join-Path $script:SamplesDir 'ransomware-intrusion.json') -Language en
        $ids = @($rep.Findings | ForEach-Object { $_.RuleId } | Select-Object -Unique)
        $ids | Should -Contain 'WET001'
        $ids | Should -Contain 'WET002'
        $ids | Should -Contain 'WET003'
        $ids | Should -Contain 'WET005'
        $ids | Should -Contain 'WET008'
        $ids | Should -Contain 'WET010'
        $ids | Should -Contain 'WET011'
        $ids | Should -Contain 'WET012'
        $ids | Should -Contain 'WET014'
        $rep.RiskScore | Should -Be 100
    }

    It 'detects insider escalation, scheduled task, audit tampering, and DCSync' {
        $rep = Invoke-WinEventTriage -SnapshotPath (Join-Path $script:SamplesDir 'insider-lateral-movement.json') -Language pt
        $ids = @($rep.Findings | ForEach-Object { $_.RuleId } | Select-Object -Unique)
        $ids | Should -Contain 'WET004'
        $ids | Should -Contain 'WET006'
        $ids | Should -Contain 'WET007'
        $ids | Should -Contain 'WET009'
        $ids | Should -Contain 'WET013'
        $ids | Should -Contain 'WET015'
        $ids | Should -Contain 'WET016'
        $ids | Should -Contain 'WET018'
    }

    It 'reads the bundled .evtx sample with the same results as the JSON snapshot' {
        $fromJson = Invoke-WinEventTriage -SnapshotPath (Join-Path $script:SamplesDir 'ransomware-intrusion.json') -Language en
        $fromEvtx = Invoke-WinEventTriage -EvtxPath (Join-Path $script:SamplesDir 'ransomware-intrusion.evtx') -Language en
        $a = @($fromJson.Findings | ForEach-Object { $_.RuleId } | Sort-Object)
        $b = @($fromEvtx.Findings | ForEach-Object { $_.RuleId } | Sort-Object)
        ($b -join ',') | Should -Be ($a -join ',')
    }

    It 'detects Sysmon, RDP, Defender and service tampering and ignores the same IDs from other providers' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('wet-extra-' + [guid]::NewGuid().ToString('N') + '.json')
        $events = @(
            @{ EventId = 13; Provider = 'Microsoft-Windows-Sysmon'; TimeCreated = '2026-11-25T10:00:00Z'; Computer = 'WS1'; Data = @{ TargetObject = 'HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\updater'; Details = 'C:\Users\Public\u.exe' } }
            @{ EventId = 11; Provider = 'Microsoft-Windows-Sysmon'; TimeCreated = '2026-11-25T10:01:00Z'; Computer = 'WS1'; Data = @{ TargetFilename = 'C:\Users\ana\Desktop\HOW_TO_DECRYPT.txt' } }
            @{ EventId = 1149; Provider = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager'; TimeCreated = '2026-11-25T10:02:00Z'; Computer = 'WS1'; Data = @{ Param1 = 'adm'; Param3 = '203.0.113.9' } }
            @{ EventId = 1116; Provider = 'Microsoft-Windows-Windows Defender'; TimeCreated = '2026-11-25T10:03:00Z'; Computer = 'WS1'; Data = @{ 'Threat Name' = 'Trojan:Win32/Test'; Path = 'C:\tmp\x.exe' } }
            @{ EventId = 7040; Provider = 'Service Control Manager'; TimeCreated = '2026-11-25T10:04:00Z'; Computer = 'WS1'; Data = @{ param1 = 'Microsoft Defender Antivirus Service'; param2 = 'auto start'; param3 = 'disabled' } }
            @{ EventId = 10; Provider = 'Microsoft-Windows-Sysmon'; TimeCreated = '2026-11-25T10:05:00Z'; Computer = 'WS1'; Data = @{ TargetImage = 'C:\Windows\system32\lsass.exe'; SourceImage = 'C:\Users\x\m.exe'; GrantedAccess = '0x1010' } }
            @{ EventId = 104; Provider = 'Some-Other-Provider'; TimeCreated = '2026-11-25T10:06:00Z'; Computer = 'WS1'; Data = @{} }
            @{ EventId = 11; Provider = 'Some-Other-Provider'; TimeCreated = '2026-11-25T10:07:00Z'; Computer = 'WS1'; Data = @{ TargetFilename = 'C:\x\HOW_TO_DECRYPT.txt' } }
        )
        try {
            [System.IO.File]::WriteAllText($tmp, (@{ events = $events } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
            $rep = Invoke-WinEventTriage -SnapshotPath $tmp -Language en
            $ids = @($rep.Findings | ForEach-Object { $_.RuleId } | Sort-Object)
            ($ids -join ',') | Should -Be 'WET005,WET019,WET020,WET021,WET022,WET023'
        }
        finally {
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        }
    }

    It 'returns zero findings on clean business-hours baseline' {
        $rep = Invoke-WinEventTriage -SnapshotPath (Join-Path $script:SamplesDir 'clean-baseline.json') -Language en
        $rep.Findings.Count | Should -Be 0
        $rep.RiskScore | Should -Be 0
    }

    It 'parses native Event Viewer XML exports and anonymizes output files' {
        $outDir = Join-Path $TestDrive 'reports'
        $rep = Invoke-WinEventTriage -SnapshotPath (Join-Path $script:SamplesDir 'sample-eventviewer.xml') -OutputDir $outDir -Language pt -Anonymize
        $ids = @($rep.Findings | ForEach-Object { $_.RuleId } | Select-Object -Unique)
        $ids | Should -Contain 'WET003'
        $ids | Should -Contain 'WET010'
        $rep.Findings[0].Computer | Should -Match '^ANON-'
        Test-Path (Join-Path $outDir 'triage-report.html') | Should -BeTrue
        Test-Path (Join-Path $outDir 'triage-report.csv') | Should -BeTrue
        Test-Path (Join-Path $outDir 'triage-report.json') | Should -BeTrue
        Test-Path (Join-Path $outDir 'triage-report.md') | Should -BeTrue
    }
}
