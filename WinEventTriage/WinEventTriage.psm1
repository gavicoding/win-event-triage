Set-StrictMode -Version Latest

$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$script:RuleCatalog = @(
    [pscustomobject]@{ RuleId = 'WET001'; Severity = 'High';     Tactic = 'Credential Access';    Technique = 'T1110.001'; EventIds = @(4625) }
    [pscustomobject]@{ RuleId = 'WET002'; Severity = 'Critical'; Tactic = 'Credential Access';    Technique = 'T1110';     EventIds = @(4625, 4624) }
    [pscustomobject]@{ RuleId = 'WET003'; Severity = 'Critical'; Tactic = 'Credential Access';    Technique = 'T1558.003'; EventIds = @(4769) }
    [pscustomobject]@{ RuleId = 'WET004'; Severity = 'High';     Tactic = 'Credential Access';    Technique = 'T1110';     EventIds = @(4740) }
    [pscustomobject]@{ RuleId = 'WET005'; Severity = 'Critical'; Tactic = 'Credential Access';    Technique = 'T1003.001'; EventIds = @(4656, 4663, 4688, 4104) }
    [pscustomobject]@{ RuleId = 'WET006'; Severity = 'Critical'; Tactic = 'Persistence';          Technique = 'T1098';     EventIds = @(4728, 4732, 4756) }
    [pscustomobject]@{ RuleId = 'WET007'; Severity = 'High';     Tactic = 'Persistence';          Technique = 'T1136';     EventIds = @(4720, 4728, 4732) }
    [pscustomobject]@{ RuleId = 'WET008'; Severity = 'High';     Tactic = 'Persistence';          Technique = 'T1543.003'; EventIds = @(7045, 4697) }
    [pscustomobject]@{ RuleId = 'WET009'; Severity = 'High';     Tactic = 'Persistence';          Technique = 'T1053.005'; EventIds = @(4698, 4702, 106) }
    [pscustomobject]@{ RuleId = 'WET010'; Severity = 'Critical'; Tactic = 'Defense Evasion';      Technique = 'T1070.001'; EventIds = @(1102, 104) }
    [pscustomobject]@{ RuleId = 'WET011'; Severity = 'Critical'; Tactic = 'Impact';               Technique = 'T1490';     EventIds = @(4688, 4104) }
    [pscustomobject]@{ RuleId = 'WET012'; Severity = 'Critical'; Tactic = 'Defense Evasion';      Technique = 'T1562.001'; EventIds = @(5001, 5007, 5010, 5012) }
    [pscustomobject]@{ RuleId = 'WET013'; Severity = 'High';     Tactic = 'Defense Evasion';      Technique = 'T1562.002'; EventIds = @(4719) }
    [pscustomobject]@{ RuleId = 'WET014'; Severity = 'Critical'; Tactic = 'Execution';            Technique = 'T1059.001'; EventIds = @(4104, 4688) }
    [pscustomobject]@{ RuleId = 'WET015'; Severity = 'High';     Tactic = 'Lateral Movement';     Technique = 'T1021.001'; EventIds = @(4624, 4648) }
    [pscustomobject]@{ RuleId = 'WET016'; Severity = 'High';     Tactic = 'Defense Evasion';      Technique = 'T1218';     EventIds = @(4688) }
    [pscustomobject]@{ RuleId = 'WET017'; Severity = 'Medium';   Tactic = 'Initial Access';       Technique = 'T1078';     EventIds = @(4672, 4624) }
    [pscustomobject]@{ RuleId = 'WET018'; Severity = 'Critical'; Tactic = 'Credential Access';    Technique = 'T1003.006'; EventIds = @(4662) }
    [pscustomobject]@{ RuleId = 'WET019'; Severity = 'High'; Tactic = 'Lateral Movement'; Technique = 'T1021.001'; EventIds = @(1149, 4778) }
    [pscustomobject]@{ RuleId = 'WET020'; Severity = 'High'; Tactic = 'Persistence'; Technique = 'T1547.001'; EventIds = @(13, 4657) }
    [pscustomobject]@{ RuleId = 'WET021'; Severity = 'Critical'; Tactic = 'Impact'; Technique = 'T1486'; EventIds = @(11) }
    [pscustomobject]@{ RuleId = 'WET022'; Severity = 'High'; Tactic = 'Execution'; Technique = 'T1204.002'; EventIds = @(1116, 1117) }
    [pscustomobject]@{ RuleId = 'WET023'; Severity = 'High'; Tactic = 'Defense Evasion'; Technique = 'T1562.001'; EventIds = @(7040, 7036) }
)

function Get-WETLocale {
    param(
        [ValidateSet('en', 'pt')]
        [string]$Language = 'en'
    )
    $fileName = 'en.json'
    if ($Language -eq 'pt') {
        $fileName = 'pt-BR.json'
    }
    $path = Join-Path (Join-Path $script:ModuleRoot 'locales') $fileName
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    return ($raw | ConvertFrom-Json)
}

function Get-WETField {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = ''
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) {
        return $prop.Value
    }
    return $Default
}

function ConvertFrom-WETXmlEvent {
    param([Parameter(Mandatory = $true)][xml]$Doc)

    $eventsList = New-Object System.Collections.Generic.List[object]
    $ns = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $nodes = $Doc.SelectNodes('//e:Event', $ns)
    if ($null -eq $nodes -or $nodes.Count -eq 0) {
        $nodes = $Doc.SelectNodes('//Event')
    }
    foreach ($node in $nodes) {
        $sys = $node.System
        if ($null -eq $sys) { continue }
        $evIdText = [string]$sys.EventID
        if ($sys.EventID -is [System.Xml.XmlElement]) {
            $evIdText = $sys.EventID.InnerText
        }
        $evId = 0
        [void][int]::TryParse($evIdText, [ref]$evId)
        $timeCreated = ''
        if ($null -ne $sys.TimeCreated) {
            $timeCreated = [string]$sys.TimeCreated.GetAttribute('SystemTime')
        }
        # EventData/Data (named or not, like the Python reader) and UserData leaf values;
        # SelectNodes avoids StrictMode errors when a block is empty or missing
        $dataBag = [ordered]@{}
        $unnamed = 0
        foreach ($d in @($node.SelectNodes("./*[local-name()='EventData']/*[local-name()='Data']"))) {
            $k = [string]$d.GetAttribute('Name')
            if (-not $k) { $k = 'Data_{0}' -f $unnamed; $unnamed++ }
            $dataBag[$k] = [string]$d.InnerText
        }
        foreach ($leaf in @($node.SelectNodes("./*[local-name()='UserData']//*[not(*)]"))) {
            $k = [string]$leaf.LocalName
            if (-not $dataBag.Contains($k)) { $dataBag[$k] = [string]$leaf.InnerText }
        }
        $eventsList.Add([pscustomobject]@{
            EventId    = $evId
            TimeCreated = $timeCreated
            Provider   = [string]$sys.Provider.GetAttribute('Name')
            Computer   = [string]$sys.Computer
            LogName    = [string]$sys.Channel
            Message    = [string](Get-WETField -Object $node -Name 'Message' -Default '')
            Data       = [pscustomobject]$dataBag
        })
    }
    return $eventsList.ToArray()
}

function ConvertFrom-WETWinEventRecord {
    param([Parameter(Mandatory = $true)]$Record)

    $xmlDoc = [xml]$Record.ToXml()
    $parsed = @(ConvertFrom-WETXmlEvent -Doc $xmlDoc)
    if ($parsed.Count -gt 0) {
        $item = $parsed[0]
        $item | Add-Member -MemberType NoteProperty -Name 'Message' -Value ([string]$Record.Message) -Force
        return $item
    }
    return [pscustomobject]@{
        EventId     = [int]$Record.Id
        TimeCreated = $Record.TimeCreated.ToUniversalTime().ToString('o')
        Provider    = [string]$Record.ProviderName
        Computer    = [string]$Record.MachineName
        LogName     = [string]$Record.LogName
        Message     = [string]$Record.Message
        Data        = [pscustomobject]@{}
    }
}

function Get-WETSeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 4 }
        'High'     { return 3 }
        'Medium'   { return 2 }
        'Low'      { return 1 }
        default    { return 0 }
    }
}

function Get-WETSeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 25 }
        'High'     { return 14 }
        'Medium'   { return 6 }
        'Low'      { return 2 }
        default    { return 0 }
    }
}

function Test-WETPrivateIp {
    param([string]$IpAddress)
    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return $true }
    $trim = $IpAddress.Trim()
    if ($trim -eq '-' -or $trim -eq '127.0.0.1' -or $trim -eq '::1' -or $trim -eq 'localhost') { return $true }
    if ($trim -match '^10\.' -or $trim -match '^192\.168\.' -or $trim -match '^169\.254\.') { return $true }
    if ($trim -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    return $false
}

function Protect-WETValue {
    param(
        [string]$Text,
        [bool]$Anonymize
    )
    if (-not $Anonymize -or [string]::IsNullOrEmpty($Text)) { return $Text }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        $hex = ([System.BitConverter]::ToString($hash)).Replace('-', '').Substring(0, 8).ToLowerInvariant()
        return ('ANON-' + $hex)
    }
    finally {
        $sha.Dispose()
    }
}

function Get-WinEventTriageRule {
    <#
    .SYNOPSIS
    Lists all 18 WinEventTriage detection rules with MITRE ATT&CK metadata.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('en', 'pt')]
        [string]$Language = 'en'
    )
    $locale = Get-WETLocale -Language $Language
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $script:RuleCatalog) {
        $copy = Get-WETField -Object $locale.rules -Name $rule.RuleId -Default $null
        $title = $rule.RuleId
        $remediation = ''
        if ($null -ne $copy) {
            $title = [string](Get-WETField -Object $copy -Name 'title' -Default $rule.RuleId)
            $remediation = [string](Get-WETField -Object $copy -Name 'remediation' -Default '')
        }
        $result.Add([pscustomobject]@{
            RuleId      = $rule.RuleId
            Severity    = $rule.Severity
            Tactic      = $rule.Tactic
            Technique   = $rule.Technique
            EventIds    = ($rule.EventIds -join ',')
            Title       = $title
            Remediation = $remediation
        })
    }
    return $result.ToArray()
}

function Export-WinEventSnapshot {
    <#
    .SYNOPSIS
    Exports local Windows Event Logs into a portable JSON snapshot without modifying system state.
    #>
    [CmdletBinding()]
    param(
        [string[]]$LogName = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational'),
        [int]$Hours = 24,
        [int]$MaxEventsPerLog = 2000,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * [Math]::Abs($Hours))
    $collected = New-Object System.Collections.Generic.List[object]
    foreach ($log in $LogName) {
        try {
            $records = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $cutoff } -MaxEvents $MaxEventsPerLog -ErrorAction Stop
            foreach ($rec in $records) {
                $collected.Add((ConvertFrom-WETWinEventRecord -Record $rec))
            }
        }
        catch {
            Write-Verbose ("Skipping log {0}: {1}" -f $log, $_.Exception.Message)
        }
    }
    $payload = [pscustomobject]@{
        schema_version = 1
        exported_at    = (Get-Date).ToUniversalTime().ToString('o')
        computer       = $env:COMPUTERNAME
        hours_window   = $Hours
        events         = $collected.ToArray()
    }
    $json = $payload | ConvertTo-Json -Depth 8
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) {
        [void](New-Item -ItemType Directory -Path $dir -Force)
    }
    [System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}

function Invoke-WinEventTriage {
    <#
    .SYNOPSIS
    Runs read-only MITRE ATT&CK triage over JSON snapshots, EVTX files, XML exports, or live local logs.
    #>
    [CmdletBinding()]
    param(
        [string]$SnapshotPath,
        [string]$EvtxPath,
        [string[]]$LogName = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational'),
        [int]$Hours = 24,
        [string]$OutputDir,
        [ValidateSet('en', 'pt')]
        [string]$Language = 'en',
        [int]$BusinessHoursStart = 7,
        [int]$BusinessHoursEnd = 20,
        [int]$BruteForceThreshold = 5,
        [switch]$Anonymize
    )

    $locale = Get-WETLocale -Language $Language
    $patternsPath = Join-Path $script:ModuleRoot 'patterns.json'
    $sigPatterns = ([System.IO.File]::ReadAllText($patternsPath, [System.Text.Encoding]::UTF8)) | ConvertFrom-Json
    $sourceLabel = 'Live Windows Logs'
    $rawEvents = @()

    if ($SnapshotPath) {
        $resolved = (Resolve-Path -Path $SnapshotPath).Path
        $sourceLabel = Split-Path -Leaf $resolved
        $text = [System.IO.File]::ReadAllText($resolved, [System.Text.Encoding]::UTF8)
        if ($resolved.ToLowerInvariant().EndsWith('.xml')) {
            $xmlDoc = [xml]$text
            $rawEvents = ConvertFrom-WETXmlEvent -Doc $xmlDoc
        }
        else {
            $parsedJson = $text | ConvertFrom-Json
            if ($parsedJson -is [System.Array]) {
                $rawEvents = $parsedJson
            }
            elseif ($null -ne $parsedJson.events) {
                $rawEvents = @($parsedJson.events)
            }
        }
    }
    elseif ($EvtxPath) {
        $resolvedEvtx = (Resolve-Path -Path $EvtxPath).Path
        $sourceLabel = Split-Path -Leaf $resolvedEvtx
        $evtxRecords = Get-WinEvent -Path $resolvedEvtx -ErrorAction Stop
        $buf = New-Object System.Collections.Generic.List[object]
        foreach ($rec in $evtxRecords) {
            $buf.Add((ConvertFrom-WETWinEventRecord -Record $rec))
        }
        $rawEvents = $buf.ToArray()
    }
    else {
        $cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * [Math]::Abs($Hours))
        $buf = New-Object System.Collections.Generic.List[object]
        foreach ($log in $LogName) {
            try {
                $recs = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $cutoff } -MaxEvents 2000 -ErrorAction Stop
                foreach ($rec in $recs) {
                    $buf.Add((ConvertFrom-WETWinEventRecord -Record $rec))
                }
            }
            catch {
                Write-Verbose ("Could not query log {0}: {1}" -f $log, $_.Exception.Message)
            }
        }
        $rawEvents = $buf.ToArray()
    }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($ev in $rawEvents) {
        $tsStr = [string](Get-WETField -Object $ev -Name 'TimeCreated' -Default '')
        $dt = [datetimeoffset]::UtcNow
        if ($tsStr) {
            [void][datetimeoffset]::TryParse($tsStr, [ref]$dt)
        }
        $dataObj = Get-WETField -Object $ev -Name 'Data' -Default ([pscustomobject]@{})
        $events.Add([pscustomobject]@{
            EventId     = [int](Get-WETField -Object $ev -Name 'EventId' -Default 0)
            TimeCreated = $tsStr
            ParsedTime  = $dt.ToUniversalTime()
            Computer    = [string](Get-WETField -Object $ev -Name 'Computer' -Default 'unknown-host')
            Provider    = [string](Get-WETField -Object $ev -Name 'Provider' -Default '')
            Message     = [string](Get-WETField -Object $ev -Name 'Message' -Default '')
            Data        = $dataObj
        })
    }
    $sortedEvents = @($events | Sort-Object -Property ParsedTime)

    $findings = New-Object System.Collections.Generic.List[object]
    $ruleById = @{}
    foreach ($r in $script:RuleCatalog) { $ruleById[$r.RuleId] = $r }

    $addFinding = {
        param([string]$RuleId, [string]$Ts, [string]$HostName, [string]$Account, [string]$SourceIp, [string]$Evidence)
        $meta = $ruleById[$RuleId]
        $copy = Get-WETField -Object $locale.rules -Name $RuleId -Default $null
        $title = $RuleId
        $remed = ''
        if ($null -ne $copy) {
            $title = [string](Get-WETField -Object $copy -Name 'title' -Default $RuleId)
            $remed = [string](Get-WETField -Object $copy -Name 'remediation' -Default '')
        }
        $dispHost = Protect-WETValue -Text $HostName -Anonymize ([bool]$Anonymize)
        $dispAcct = Protect-WETValue -Text $Account -Anonymize ([bool]$Anonymize)
        $findings.Add([pscustomobject]@{
            RuleId        = $RuleId
            Severity      = $meta.Severity
            SeverityRank  = (Get-WETSeverityRank -Severity $meta.Severity)
            Tactic        = $meta.Tactic
            Technique     = $meta.Technique
            Title         = $title
            Timestamp     = $Ts
            Computer      = $dispHost
            Account       = $dispAcct
            SourceIp      = $SourceIp
            Evidence      = $Evidence
            Remediation   = $remed
        })
    }

    # Pre-index Event 4625 (failed logons) for WET001 & WET002
    $failedByIp = @{}
    $failedLogons = @($sortedEvents | Where-Object { $_.EventId -eq 4625 })
    foreach ($f in $failedLogons) {
        $ip = [string](Get-WETField -Object $f.Data -Name 'IpAddress' -Default '-')
        if (-not $failedByIp.ContainsKey($ip)) {
            $failedByIp[$ip] = New-Object System.Collections.Generic.List[object]
        }
        $failedByIp[$ip].Add($f)
    }

    foreach ($ipKey in $failedByIp.Keys) {
        $group = $failedByIp[$ipKey]
        if ($group.Count -ge $BruteForceThreshold) {
            $firstTime = $group[0].ParsedTime
            $lastTime = $group[$group.Count - 1].ParsedTime
            if (($lastTime - $firstTime).TotalMinutes -le 15) {
                $targets = @($group | ForEach-Object { [string](Get-WETField -Object $_.Data -Name 'TargetUserName' -Default 'unknown') } | Select-Object -Unique)
                & $addFinding 'WET001' $group[$group.Count - 1].TimeCreated $group[0].Computer ($targets -join ',') $ipKey ("{0} failed logons (4625) from {1} within 15m targeting: {2}" -f $group.Count, $ipKey, ($targets -join ', '))
            }
        }
    }

    # Correlate WET002 (4625 burst -> 4624 success within 15 min)
    $successLogons = @($sortedEvents | Where-Object { $_.EventId -eq 4624 })
    foreach ($ok in $successLogons) {
        $okIp = [string](Get-WETField -Object $ok.Data -Name 'IpAddress' -Default '-')
        $okUser = [string](Get-WETField -Object $ok.Data -Name 'TargetUserName' -Default '')
        if ($okIp -ne '-' -and $failedByIp.ContainsKey($okIp)) {
            $priorFails = @($failedByIp[$okIp] | Where-Object {
                ($_.ParsedTime -le $ok.ParsedTime) -and (($ok.ParsedTime - $_.ParsedTime).TotalMinutes -le 15)
            })
            if ($priorFails.Count -ge [Math]::Min(3, $BruteForceThreshold)) {
                & $addFinding 'WET002' $ok.TimeCreated $ok.Computer $okUser $okIp ("Successful logon (4624) for '{0}' from {1} after {2} failed attempts within 15m." -f $okUser, $okIp, $priorFails.Count)
            }
        }
    }

    # WET007 correlation set (4720 -> 4728/4732)
    $createdUsers = @{}
    foreach ($ev in $sortedEvents) {
        if ($ev.EventId -eq 4720) {
            $u = [string](Get-WETField -Object $ev.Data -Name 'TargetUserName' -Default '')
            if ($u) { $createdUsers[$u.ToLowerInvariant()] = $ev }
            if ($ev.ParsedTime.Hour -lt $BusinessHoursStart -or $ev.ParsedTime.Hour -ge $BusinessHoursEnd) {
                $actor = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
                & $addFinding 'WET007' $ev.TimeCreated $ev.Computer $u '-' ("New user '{0}' created off-hours by '{1}'." -f $u, $actor)
            }
        }
    }

    $privGroups = @('domain admins', 'enterprise admins', 'schema admins', 'administrators', 'backup operators', 'remote desktop users')
    $privGroupEvents = 0
    $lockoutEvents = @($sortedEvents | Where-Object { $_.EventId -eq 4740 })
    if ($lockoutEvents.Count -ge 3) {
        $lockedNames = @($lockoutEvents | ForEach-Object { [string](Get-WETField -Object $_.Data -Name 'TargetUserName' -Default 'user') } | Select-Object -Unique)
        & $addFinding 'WET004' $lockoutEvents[$lockoutEvents.Count - 1].TimeCreated $lockoutEvents[0].Computer ($lockedNames -join ',') '-' ("{0} account lockouts (4740) detected: {1}" -f $lockoutEvents.Count, ($lockedNames -join ', '))
    }

    $providers = @{
        eventlog = @('microsoft-windows-eventlog', 'eventlog')
        tasks    = @('microsoft-windows-taskscheduler')
        defender = @('microsoft-windows-windows defender', 'windows defender')
        scm      = @('service control manager')
        rdp      = @('microsoft-windows-terminalservices-remoteconnectionmanager', 'microsoft-windows-terminalservices-localsessionmanager')
    }
    $runKeyRx = '(?i)\\(?:Software\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunServices|Policies\\Explorer\\Run)|Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\(?:Userinit|Shell))\b'
    $ransomRx = '(?i)(?:\\|/)(?:[^\\/]*(?:decrypt|restore|recover|ransom|how[_ -]?to|readme[_ -]?(?:now|warning|for[_ -]?decrypt))[^\\/]*\.(?:txt|html?|hta|url)|[^\\/]+\.(?:locked|encrypted|crypt|crypted|enc[0-9]*|lockbit|ryk|conti|akira|blackcat|phobos|8base))$'
    $secSvcRx = '(?i)\b(?:windefend|microsoft defender|windows defender|eventlog|windows event log|sense|wscsvc|security center|mpssvc|windows firewall|wdnissvc|sysmon64?)\b'
    $disabledRx = '(?i)\b(?:disabled|desativad[oa]|stopped|parad[oa]|interrompid[oa])\b'

    foreach ($ev in $sortedEvents) {
        $eid = $ev.EventId
        $msg = $ev.Message
        $prov = ([string]$ev.Provider).ToLowerInvariant()
        $sysmon = $prov -eq 'microsoft-windows-sysmon'
        $fromSrc = { param($src) (-not $prov) -or ($providers[$src] -contains $prov) }
        # Sysmon 1 = process creation (like 4688); IDs 1/3/10/11/13 only count when Sysmon wrote them
        if ($sysmon -and $eid -eq 1) { $eid = 4688 }
        elseif ((@(1, 3, 10, 11, 13) -contains $eid) -and -not $sysmon) { $eid = -1 * $eid }
        $who = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default '')
        if (-not $who) { $who = [string](Get-WETField -Object $ev.Data -Name 'User' -Default 'unknown') }

        if ($sysmon -and $eid -eq 10) {
            $target = ([string](Get-WETField -Object $ev.Data -Name 'TargetImage' -Default '')).ToLowerInvariant()
            $srcImg = [string](Get-WETField -Object $ev.Data -Name 'SourceImage' -Default '')
            $access = ([string](Get-WETField -Object $ev.Data -Name 'GrantedAccess' -Default '')).ToLowerInvariant()
            $benign = $srcImg -match '(?i)\\(?:MsMpEng|csrss|wininit|lsm|svchost|services|wmiprvse|taskmgr|procexp64?)\.exe$'
            if ($target.EndsWith('\lsass.exe') -and -not $benign -and (@('0x1010', '0x1410', '0x1438', '0x143a', '0x1fffff', '0x40') -contains $access)) {
                & $addFinding 'WET005' $ev.TimeCreated $ev.Computer $who '-' ("Process '{0}' opened LSASS memory (access {1})." -f $srcImg, $access)
            }
        }
        if (($sysmon -and $eid -eq 13) -or $eid -eq 4657) {
            $key = [string](Get-WETField -Object $ev.Data -Name 'TargetObject' -Default '')
            if (-not $key) { $key = [string](Get-WETField -Object $ev.Data -Name 'ObjectName' -Default '') }
            $details = [string](Get-WETField -Object $ev.Data -Name 'Details' -Default '')
            if ($key -match $runKeyRx) {
                & $addFinding 'WET020' $ev.TimeCreated $ev.Computer $who '-' ("Autostart registry value set: {0} = {1}" -f $key, $details.Substring(0, [Math]::Min(100, $details.Length)))
            }
        }
        if ($sysmon -and $eid -eq 11) {
            $fname = [string](Get-WETField -Object $ev.Data -Name 'TargetFilename' -Default '')
            if ($fname -match $ransomRx) {
                & $addFinding 'WET021' $ev.TimeCreated $ev.Computer $who '-' ("Ransom note or encrypted file written: {0}" -f $fname)
            }
        }
        if ((@(1116, 1117) -contains $eid) -and (& $fromSrc 'defender')) {
            $threat = [string](Get-WETField -Object $ev.Data -Name 'Threat Name' -Default '')
            if (-not $threat) { $threat = $msg.Substring(0, [Math]::Min(80, $msg.Length)) }
            $tpath = [string](Get-WETField -Object $ev.Data -Name 'Path' -Default '')
            $action = if ($eid -eq 1117) { 'blocked/removed' } else { 'detected' }
            & $addFinding 'WET022' $ev.TimeCreated $ev.Computer '-' '-' (("Defender {0} '{1}' {2}" -f $action, $threat, $tpath.Substring(0, [Math]::Min(100, $tpath.Length))).Trim())
        }
        if ((@(7040, 7036) -contains $eid) -and (& $fromSrc 'scm')) {
            $svc = [string](Get-WETField -Object $ev.Data -Name 'param1' -Default '')
            if (-not $svc) { $svc = $msg }
            $state = ('{0} {1} {2}' -f (Get-WETField -Object $ev.Data -Name 'param2' -Default ''), (Get-WETField -Object $ev.Data -Name 'param3' -Default ''), $msg)
            if ($svc -match $secSvcRx -and $state -match $disabledRx) {
                & $addFinding 'WET023' $ev.TimeCreated $ev.Computer '-' '-' ("Security service '{0}' changed to: {1}" -f $svc.Substring(0, [Math]::Min(60, $svc.Length)), $state.Trim().Substring(0, [Math]::Min(80, $state.Trim().Length)))
            }
        }
        if (($eid -eq 1149 -and (& $fromSrc 'rdp')) -or $eid -eq 4778) {
            $rip = [string](Get-WETField -Object $ev.Data -Name 'Param3' -Default '')
            if (-not $rip) { $rip = [string](Get-WETField -Object $ev.Data -Name 'ClientAddress' -Default '') }
            $ru = [string](Get-WETField -Object $ev.Data -Name 'Param1' -Default '')
            if (-not $ru) { $ru = [string](Get-WETField -Object $ev.Data -Name 'AccountName' -Default '') }
            if ($rip -and -not (Test-WETPrivateIp -IpAddress $rip)) {
                $what = if ($eid -eq 1149) { 'RDP authentication (1149)' } else { 'RDP session reconnected (4778)' }
                & $addFinding 'WET019' $ev.TimeCreated $ev.Computer $ru $rip ("{0} for '{1}' from internet IP {2}." -f $what, $ru, $rip)
            }
        }

        $cmdLine = [string](Get-WETField -Object $ev.Data -Name 'CommandLine' -Default '')
        if (-not $cmdLine) { $cmdLine = [string](Get-WETField -Object $ev.Data -Name 'Image' -Default '') }
        $scriptBlock = [string](Get-WETField -Object $ev.Data -Name 'ScriptBlockText' -Default '')
        $combinedCmd = ($cmdLine + ' ' + $scriptBlock + ' ' + $msg).Trim()

        # WET003: Kerberoasting 4769 RC4 0x17
        if ($eid -eq 4769) {
            $encType = [string](Get-WETField -Object $ev.Data -Name 'TicketEncryptionType' -Default '')
            $spn = [string](Get-WETField -Object $ev.Data -Name 'ServiceName' -Default '')
            $acct = [string](Get-WETField -Object $ev.Data -Name 'TargetUserName' -Default '')
            $ip = [string](Get-WETField -Object $ev.Data -Name 'IpAddress' -Default '-')
            if ($encType -eq '0x17' -and $spn -and ($spn -notmatch '\$$') -and ($spn -notmatch '^krbtgt')) {
                & $addFinding 'WET003' $ev.TimeCreated $ev.Computer $acct $ip ("Kerberos TGS 4769 with RC4 (0x17) requested for SPN '{0}'." -f $spn)
            }
        }

        # WET005: Credential dumping LSASS / NTDS
        if ($eid -in @(4656, 4663, 4688, 4104)) {
            $objName = [string](Get-WETField -Object $ev.Data -Name 'ObjectName' -Default '')
            if ($objName -match 'lsass\.exe' -or $combinedCmd -match $sigPatterns.lsass_ntds_regex) {
                $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
                & $addFinding 'WET005' $ev.TimeCreated $ev.Computer $subj '-' ("LSASS/NTDS credential access pattern: {0}" -f ($combinedCmd.Substring(0, [Math]::Min(110, $combinedCmd.Length))))
            }
        }

        # WET006: Privileged group add
        if ($eid -in @(4728, 4732, 4756)) {
            $grp = [string](Get-WETField -Object $ev.Data -Name 'TargetUserName' -Default '')
            $member = [string](Get-WETField -Object $ev.Data -Name 'MemberName' -Default 'unknown')
            $actor = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            if ($privGroups -contains $grp.ToLowerInvariant()) {
                $privGroupEvents++
                & $addFinding 'WET006' $ev.TimeCreated $ev.Computer $member '-' ("'{0}' added to privileged group '{1}' by '{2}'." -f $member, $grp, $actor)
            }
            $memberLow = ($member -replace '^CN=([^,]+),.*$', '$1').ToLowerInvariant()
            if ($createdUsers.ContainsKey($memberLow)) {
                & $addFinding 'WET007' $ev.TimeCreated $ev.Computer $member '-' ("Newly created account '{0}' was added to '{1}'." -f $member, $grp)
            }
        }

        # WET008: Suspicious service 7045 / 4697
        if ($eid -eq 4697 -or ($eid -eq 7045 -and (& $fromSrc 'scm'))) {
            $srvName = [string](Get-WETField -Object $ev.Data -Name 'ServiceName' -Default 'unknown')
            $imgPath = [string](Get-WETField -Object $ev.Data -Name 'ImagePath' -Default '')
            if ($imgPath -match $sigPatterns.service_suspicious_regex) {
                & $addFinding 'WET008' $ev.TimeCreated $ev.Computer 'SYSTEM' '-' ("Suspicious service '{0}' installed with path '{1}'." -f $srvName, $imgPath)
            }
        }

        # WET009: Scheduled task persistence 4698 / 4702 / 106
        if ($eid -in @(4698, 4702) -or ($eid -eq 106 -and (& $fromSrc 'tasks'))) {
            $taskName = [string](Get-WETField -Object $ev.Data -Name 'TaskName' -Default 'unknown')
            $taskContent = [string](Get-WETField -Object $ev.Data -Name 'TaskContent' -Default '')
            if (($taskContent + ' ' + $msg) -match $sigPatterns.task_suspicious_regex) {
                & $addFinding 'WET009' $ev.TimeCreated $ev.Computer ([string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')) '-' ("Suspicious scheduled task '{0}' registered." -f $taskName)
            }
        }

        # WET010: Audit log cleared 1102 / 104
        if (($eid -in @(1102, 104)) -and (& $fromSrc 'eventlog')) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            & $addFinding 'WET010' $ev.TimeCreated $ev.Computer $subj '-' ("Event log cleared (EventID {0}) by '{1}'." -f $eid, $subj)
        }

        # WET011: Shadow copy wipe / recovery sabotage
        if ($eid -in @(4688, 4104) -and $combinedCmd -match $sigPatterns.shadow_wipe_regex) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            & $addFinding 'WET011' $ev.TimeCreated $ev.Computer $subj '-' ("Shadow copy/recovery sabotage command: {0}" -f ($combinedCmd.Substring(0, [Math]::Min(110, $combinedCmd.Length))))
        }

        # WET012: Defender disabled/tampered/alert
        if (($eid -in @(5001, 5007, 5010, 5012)) -and (& $fromSrc 'defender')) {
            & $addFinding 'WET012' $ev.TimeCreated $ev.Computer 'Defender' '-' ("Microsoft Defender protection changed (EventID {0}): {1}" -f $eid, $msg)
        }

        # WET013: Audit policy modified 4719
        if ($eid -eq 4719) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            & $addFinding 'WET013' $ev.TimeCreated $ev.Computer $subj '-' ("System audit policy changed by '{0}'." -f $subj)
        }

        # WET014: Obfuscated/download-cradle PowerShell
        if ($eid -in @(4104, 4688) -and $combinedCmd -match $sigPatterns.powershell_suspicious_regex) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            & $addFinding 'WET014' $ev.TimeCreated $ev.Computer $subj '-' ("Suspicious PowerShell execution: {0}" -f ($combinedCmd.Substring(0, [Math]::Min(110, $combinedCmd.Length))))
        }

        # WET015: External RDP (Type 10) or explicit credentials (4648)
        if ($eid -eq 4624) {
            $ltype = [string](Get-WETField -Object $ev.Data -Name 'LogonType' -Default '')
            $ip = [string](Get-WETField -Object $ev.Data -Name 'IpAddress' -Default '-')
            $u = [string](Get-WETField -Object $ev.Data -Name 'TargetUserName' -Default '')
            if ($ltype -eq '10' -and -not (Test-WETPrivateIp -IpAddress $ip)) {
                & $addFinding 'WET015' $ev.TimeCreated $ev.Computer $u $ip ("External RDP logon (Type 10) for '{0}' from IP {1}." -f $u, $ip)
            }
        }
        if ($eid -eq 4648) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            $targ = [string](Get-WETField -Object $ev.Data -Name 'TargetUserName' -Default 'unknown')
            $srv = [string](Get-WETField -Object $ev.Data -Name 'TargetServerName' -Default 'unknown')
            if ($subj -notmatch '\$$') {
                & $addFinding 'WET015' $ev.TimeCreated $ev.Computer $subj '-' ("Explicit credentials used (4648): '{0}' -> '{1}' on '{2}'." -f $subj, $targ, $srv)
            }
        }

        # WET016: LOLBin abuse
        if ($eid -eq 4688 -and $combinedCmd -match $sigPatterns.lolbin_regex) {
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            & $addFinding 'WET016' $ev.TimeCreated $ev.Computer $subj '-' ("LOLBin remote/lateral abuse: {0}" -f ($combinedCmd.Substring(0, [Math]::Min(110, $combinedCmd.Length))))
        }

        # WET017: Off-hours privileged logon (4672)
        if ($eid -eq 4672) {
            $acct = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default '')
            if ($acct -and ($acct -notmatch '\$$') -and ($acct -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$')) {
                if ($ev.ParsedTime.Hour -lt $BusinessHoursStart -or $ev.ParsedTime.Hour -ge $BusinessHoursEnd) {
                    & $addFinding 'WET017' $ev.TimeCreated $ev.Computer $acct '-' ("Privileged logon (4672) outside business hours for '{0}' at {1} UTC." -f $acct, $ev.ParsedTime.ToString('HH:mm'))
                }
            }
        }

        # WET018: DCSync 4662
        if ($eid -eq 4662) {
            $props = ([string](Get-WETField -Object $ev.Data -Name 'Properties' -Default '')).ToLowerInvariant()
            $subj = [string](Get-WETField -Object $ev.Data -Name 'SubjectUserName' -Default 'unknown')
            $hasGuid = $false
            foreach ($g in $sigPatterns.dcsync_guids) {
                if ($props.Contains([string]$g)) { $hasGuid = $true; break }
            }
            if ($hasGuid -and ($subj -notmatch '\$$')) {
                & $addFinding 'WET018' $ev.TimeCreated $ev.Computer $subj '-' ("DS-Replication-Get-Changes requested by non-DC account '{0}'." -f $subj)
            }
        }
    }

    $sortedFindings = @($findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, @{ Expression = 'Timestamp'; Descending = $false }, @{ Expression = 'RuleId'; Descending = $false })

    $counts = [pscustomobject]@{
        Critical = @($sortedFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($sortedFindings | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = @($sortedFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = @($sortedFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    }
    $rawScore = 0
    foreach ($item in $sortedFindings) { $rawScore += (Get-WETSeverityWeight -Severity $item.Severity) }
    $riskScore = [Math]::Min(100, $rawScore)

    $report = [pscustomobject]@{
        Tool           = 'win-event-triage'
        Version        = '1.0.0'
        Language       = $Language
        Source         = $sourceLabel
        EventsAnalyzed = $sortedEvents.Count
        RiskScore      = $riskScore
        Counts         = $counts
        Findings       = $sortedFindings
    }

    if ($OutputDir) {
        if (-not (Test-Path $OutputDir)) {
            [void](New-Item -ItemType Directory -Path $OutputDir -Force)
        }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)

        # JSON
        $jsonPath = Join-Path $OutputDir 'triage-report.json'
        [System.IO.File]::WriteAllText($jsonPath, ($report | ConvertTo-Json -Depth 6), $utf8NoBom)

        # CSV
        $csvPath = Join-Path $OutputDir 'triage-report.csv'
        $csvLines = New-Object System.Collections.Generic.List[string]
        $csvLines.Add('RuleId,Severity,Tactic,Technique,Timestamp,Computer,Account,SourceIp,Title,Evidence,Remediation')
        foreach ($f in $sortedFindings) {
            $cols = @($f.RuleId, $f.Severity, $f.Tactic, $f.Technique, $f.Timestamp, $f.Computer, $f.Account, $f.SourceIp, $f.Title, $f.Evidence, $f.Remediation) | ForEach-Object {
                '"' + (([string]$_).Replace('"', '""')) + '"'
            }
            $csvLines.Add(($cols -join ','))
        }
        [System.IO.File]::WriteAllText($csvPath, ($csvLines -join "`n") + "`n", $utf8NoBom)

        # Markdown
        $mdPath = Join-Path $OutputDir 'triage-report.md'
        $mdLines = New-Object System.Collections.Generic.List[string]
        $mdLines.Add(("# {0}" -f $locale.ui.report_title))
        $mdLines.Add("")
        $mdLines.Add(("- **{0}:** {1}" -f $locale.ui.host_label, $sourceLabel))
        $mdLines.Add(("- **{0}:** {1}" -f $locale.ui.events_analyzed, $sortedEvents.Count))
        $mdLines.Add(("- **{0}:** {1}/100" -f $locale.ui.risk_score, $riskScore))
        $mdLines.Add("")
        foreach ($f in $sortedFindings) {
            $mdLines.Add(("- **[{0}] {1} ({2})** {3} - ``{4}``" -f $f.Severity.ToUpper(), $f.RuleId, $f.Technique, $f.Title, $f.Evidence))
        }
        [System.IO.File]::WriteAllText($mdPath, ($mdLines -join "`n") + "`n", $utf8NoBom)

        # HTML
        $htmlPath = Join-Path $OutputDir 'triage-report.html'
        $rowHtml = ''
        foreach ($f in $sortedFindings) {
            $enc = [System.Net.WebUtility]
            $rowHtml += ("<tr><td><b>{0}</b></td><td>{1}<br/><small>{2}</small></td><td>{3} / {4}</td><td>{5}</td><td><code>{6}</code><br/><small>{7}</small></td></tr>`n" -f `
                $enc::HtmlEncode($f.Severity.ToUpper()), `
                $enc::HtmlEncode($f.RuleId), `
                $enc::HtmlEncode($f.Title), `
                $enc::HtmlEncode($f.Tactic), `
                $enc::HtmlEncode($f.Technique), `
                $enc::HtmlEncode($f.Timestamp), `
                $enc::HtmlEncode($f.Evidence), `
                $enc::HtmlEncode($f.Remediation))
        }
        if (-not $rowHtml) {
            $rowHtml = ('<tr><td colspan="5">' + [System.Net.WebUtility]::HtmlEncode([string]$locale.ui.clean_status) + '</td></tr>')
        }
        $htmlDoc = @"
<!DOCTYPE html>
<html lang="$Language">
<head>
  <meta charset="utf-8" />
  <title>$([System.Net.WebUtility]::HtmlEncode([string]$locale.ui.report_title))</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0b101b; color: #e6edf7; margin: 28px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; background: #121a2b; }
    th, td { border: 1px solid #24304a; padding: 10px 12px; text-align: left; vertical-align: top; }
    th { color: #93a4c3; }
    code { background: #0a0e18; padding: 2px 5px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>$([System.Net.WebUtility]::HtmlEncode([string]$locale.ui.report_title))</h1>
  <p>$([System.Net.WebUtility]::HtmlEncode([string]$locale.ui.host_label)): <b>$([System.Net.WebUtility]::HtmlEncode($sourceLabel))</b> | $($locale.ui.events_analyzed): <b>$($sortedEvents.Count)</b> | $($locale.ui.risk_score): <b>$riskScore/100</b></p>
  <table>
    <thead><tr><th>$($locale.ui.severity)</th><th>$($locale.ui.rule)</th><th>$($locale.ui.mitre)</th><th>$($locale.ui.timestamp)</th><th>$($locale.ui.evidence)</th></tr></thead>
    <tbody>$rowHtml</tbody>
  </table>
</body>
</html>
"@
        [System.IO.File]::WriteAllText($htmlPath, $htmlDoc, $utf8NoBom)
    }

    return $report
}

Export-ModuleMember -Function Export-WinEventSnapshot, Invoke-WinEventTriage, Get-WinEventTriageRule
