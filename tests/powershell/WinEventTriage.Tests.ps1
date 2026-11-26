BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $repoRoot 'WinEventTriage\WinEventTriage.psd1') -Force
    $script:SamplesDir = Join-Path $repoRoot 'samples'
}

Describe 'WinEventTriage Module' {
    It 'lists all 18 MITRE ATT&CK rules in English and Portuguese' {
        $enRules = Get-WinEventTriageRule -Language en
        $ptRules = Get-WinEventTriageRule -Language pt
        $enRules.Count | Should -Be 18
        $ptRules.Count | Should -Be 18
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
