<#
PSSCP v6.2.0 - PowerShell Script Checker Plus

Purpose
-------
Autonomous, static-only, best-effort proof-read gate for PowerShell scripts.
It is designed to review AI-generated or engineer-provided PowerShell before anyone tries to run it.
It scans .ps1, .psm1 and .psd1 files recursively from the chosen root folder.
It does NOT execute the scripts being scanned.

Default use
-----------
Open PowerShell/Windows Terminal in the folder you want to scan, then run:

    irm 'https://raw.githubusercontent.com/bluedawg874/PS_Script_Checker_Plus/refs/heads/main/PSSCP.ps1' | iex

Optional controls
-----------------
    $env:PSSCP_PATH='C:\Scripts'          # Scan a specific folder instead of current directory
    $env:PSSCP_NO_INSTALL='1'             # Do not auto-install PSScriptAnalyzer
    $env:PSSCP_WRITE_REPORTS='1'          # Write JSON, MD, SARIF, CSV and AI prompt files
    $env:PSSCP_INCLUDE_INFO='0'           # Hide Info findings in the full console detail
    $env:PSSCP_NO_CROSS_PARSE='1'         # Skip parser probe under powershell.exe/pwsh.exe
    $env:PSSCP_FAIL_ON='Error'            # Never, Critical, Error, Warning
    $env:PSSCP_MIN_SCORE='75'             # Gate fail if any file score is below this
    $env:PSSCP_CI='1'                     # Exit 1 on gate failure
    $env:PSSCP_SELFTEST='1'               # Run built-in static self-test snippets instead of current folder
    $env:PSSCP_KEEP_SELFTEST='1'           # Keep temporary self-test files for troubleshooting
    $env:PSSCP_PROFILE='General'          # General, Strict, Report, Cloud, Destructive
    $env:PSSCP_CHANGED_ONLY='1'           # In a Git repo, scan changed PowerShell files only; does not fall back to full scan
    $env:PSSCP_EXCLUDE='regex'            # Additional path exclusion regex
    $env:PSSCP_MAX_FILE_MB='5'            # Skip huge files
    $env:PSSCP_MAX_EVIDENCE='1200'        # Evidence length per finding

Suppression comments
--------------------
Use sparingly and always include a reason:

    # PSSCP:ignore-next-line PSSCP040 - Intentional scoped cleanup of temp folder
    Remove-Item $TempPath -Recurse -Force

    # PSSCP:ignore PSSCP080 - Console-only helper intentionally uses Write-Host

Suppression keys can be a finding ID, category, area, or *.
Suppression comments without a reason are themselves reported.

Limitations
-----------
Static analysis estimates validity. It cannot prove permissions, live API coverage, Graph/Azure pagination correctness,
tenant completeness, runtime output accuracy, business intent, or whether a script is safe to run in a specific environment.
#>

& {
    $ErrorActionPreference = 'Continue'

    # -----------------------------
    # Configuration
    # -----------------------------
    $ToolName = 'PSSCP'
    $ToolVersion = '6.2.0'
    $Profile = if($env:PSSCP_PROFILE){ $env:PSSCP_PROFILE } else { 'General' }
    $AutoInstallDeps = ($env:PSSCP_NO_INSTALL -ne '1')
    $WriteReports = ($env:PSSCP_WRITE_REPORTS -eq '1')
    $CrossParse = ($env:PSSCP_NO_CROSS_PARSE -ne '1')
    $IncludeInfo = ($env:PSSCP_INCLUDE_INFO -ne '0')
    $ChangedOnly = ($env:PSSCP_CHANGED_ONLY -eq '1')
    $SelfTest = ($env:PSSCP_SELFTEST -eq '1')
    $KeepSelfTest = ($env:PSSCP_KEEP_SELFTEST -eq '1')
    $FailOn = if($env:PSSCP_FAIL_ON){ $env:PSSCP_FAIL_ON } else { 'Never' }
    $MinScore = 0
    if(-not [int]::TryParse([string]$env:PSSCP_MIN_SCORE,[ref]$MinScore)){ $MinScore = 0 }
    $MaxEvidence = 1200
    if($env:PSSCP_MAX_EVIDENCE -and [int]::TryParse([string]$env:PSSCP_MAX_EVIDENCE,[ref]$MaxEvidence) -and $MaxEvidence -lt 80){ $MaxEvidence = 80 }
    $MaxFileMB = 5
    if(-not [int]::TryParse([string]$env:PSSCP_MAX_FILE_MB,[ref]$MaxFileMB)){ $MaxFileMB = 5 }

    $BaseRoot = if($env:PSSCP_PATH){ (Resolve-Path -LiteralPath $env:PSSCP_PATH -ErrorAction SilentlyContinue).Path } else { (Get-Location).Path }
    if(-not $BaseRoot){ Write-Host 'Invalid PSSCP_PATH or current directory.' -ForegroundColor Red; return }

    $Root = $BaseRoot
    $Extensions = @('.ps1','.psm1','.psd1')
    $DefaultExclude = '[\\/](\.git|\.hg|\.svn|bin|obj|node_modules|packages|\.terraform|\.venv|venv|dist|build|out|__pycache__)[\\/]'
    $AdditionalExclude = [string]$env:PSSCP_EXCLUDE

    $Findings = [Collections.Generic.List[object]]::new()
    $Summary = [Collections.Generic.List[object]]::new()
    $Grouped = $null
    $CommandCache = @{}
    $PerFileFunctions = @{}
    $FunctionToFiles = @{}
    $Suppressions = @{}
    $FileByLowerPath = @{}
    $KnownChangedFiles = @{}
    $SuppressionKnownAreas = @('Parser','Requires','Read','Encoding','Formatting','Signature','CrossParse','Command','DynamicCommand','Alias','Parameter','DotSource','LocalFunction','ModuleFamily','Context','Risk','DestructiveScope','PipelineScope','ShouldProcess','ErrorHandling','PrivilegedChange','Elevation','Pipeline','Security','Secret','RemoteExecution','Encoded','Interop','SupplyChain','Unicode','Errors','Retry','Pagination','ReportQuality','Context','OutputLoss','Csv','Console','Path','PS7Syntax','WindowsSpecific','Placeholder','CommentMismatch','Marker','DeadCode','Manifest','PSScriptAnalyzer','Suppression','SelfTest','Dependency','Inventory')

    # -----------------------------
    # Rule metadata / helper functions
    # -----------------------------
    $RuleMeta = @{
        PSSCP000=@{Title='Tool/dependency status';Category='Dependency'}
        PSSCP001=@{Title='Parser syntax error';Category='Syntax'}
        PSSCP002=@{Title='Cross-host parser mismatch';Category='Syntax'}
        PSSCP003=@{Title='File/read/format issue';Category='Syntax'}
        PSSCP010=@{Title='#Requires issue';Category='Dependency'}
        PSSCP011=@{Title='Missing or unavailable command/module';Category='Dependency'}
        PSSCP012=@{Title='Alias usage';Category='Maintainability'}
        PSSCP013=@{Title='Invalid or suspicious parameter';Category='Dependency'}
        PSSCP014=@{Title='Dot-source/local dependency issue';Category='Dependency'}
        PSSCP015=@{Title='Module family/context issue';Category='Dependency'}
        PSSCP020=@{Title='High-impact command';Category='Safety'}
        PSSCP021=@{Title='Unsafe destructive scope';Category='Safety'}
        PSSCP022=@{Title='ShouldProcess/WhatIf issue';Category='Safety'}
        PSSCP023=@{Title='Administrative/context assumption';Category='Safety'}
        PSSCP024=@{Title='Security-sensitive system change';Category='Safety'}
        PSSCP030=@{Title='Secret/token/credential pattern';Category='Security'}
        PSSCP031=@{Title='Remote execution or encoded content';Category='Security'}
        PSSCP032=@{Title='Native/interop/reflection pattern';Category='Security'}
        PSSCP033=@{Title='Repository/supply-chain pattern';Category='Security'}
        PSSCP034=@{Title='Unicode/encoding/signature issue';Category='Security'}
        PSSCP040=@{Title='Error handling issue';Category='Reliability'}
        PSSCP041=@{Title='Retry/throttling resilience issue';Category='Reliability'}
        PSSCP042=@{Title='Pagination/completeness issue';Category='Reliability'}
        PSSCP050=@{Title='Output/report quality issue';Category='Output'}
        PSSCP051=@{Title='Output-loss pipeline issue';Category='Output'}
        PSSCP052=@{Title='Context/path/output assumption';Category='Output'}
        PSSCP060=@{Title='AI-script smell/placeholder/comment mismatch';Category='Maintainability'}
        PSSCP061=@{Title='Dead code or unused scaffolding hint';Category='Maintainability'}
        PSSCP062=@{Title='Compatibility issue';Category='Compatibility'}
        PSSCP070=@{Title='PSScriptAnalyzer finding';Category='Maintainability'}
        PSSCP080=@{Title='Manifest/data file issue';Category='Maintainability'}
        PSSCP090=@{Title='Suppression issue';Category='Maintainability'}
        PSSCP900=@{Title='Self-test result';Category='Tool'}
    }

    function _Rank([string]$Severity){
        if($Severity -eq 'Critical'){ return 0 }
        if($Severity -eq 'Error'){ return 1 }
        if($Severity -eq 'Warning'){ return 2 }
        if($Severity -eq 'Info'){ return 3 }
        return 4
    }
    function _Rating([int]$Score){
        if($Score -ge 90){ return 'High' }
        if($Score -ge 75){ return 'Good' }
        if($Score -ge 50){ return 'Moderate' }
        if($Score -ge 25){ return 'Low' }
        return 'Very low'
    }
    function _Evidence([object]$Value){
        if($null -eq $Value){ return '' }
        $s = (($Value.ToString() -replace '\s+',' ').Trim())
        if($s.Length -gt $MaxEvidence){ return $s.Substring(0,$MaxEvidence) + ' ...[truncated]' }
        return $s
    }
    function _Rel([string]$Path){
        try { return (Resolve-Path -LiteralPath $Path -Relative) } catch { return $Path }
    }
    function _LineFromIndex([string]$Raw,[int]$Index){
        if($Index -lt 0 -or $Index -gt $Raw.Length){ return 0 }
        return (($Raw.Substring(0,$Index) -split "`r?`n").Count)
    }
    function _Has([string]$Raw,[string]$Pattern){
        return [regex]::IsMatch($Raw,$Pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    function _BaseImpact([string]$Severity,[string]$Confidence,[string]$Category){
        $n = 0
        if($Severity -eq 'Critical'){ $n = 35 }
        elseif($Severity -eq 'Error'){ $n = 22 }
        elseif($Severity -eq 'Warning'){ $n = 7 }
        else{ $n = 0 }
        if($Confidence -eq 'Low'){ $n = [Math]::Floor($n * 0.5) }
        elseif($Confidence -eq 'Medium'){ $n = [Math]::Floor($n * 0.8) }
        if($Category -eq 'Security' -or $Category -eq 'Syntax'){ $n = [Math]::Ceiling($n * 1.25) }
        elseif($Category -eq 'Safety' -or $Category -eq 'Reliability'){ $n = [Math]::Ceiling($n * 1.1) }
        if($Profile -match 'Strict|Destructive' -and $Severity -eq 'Warning'){ $n += 2 }
        if($Profile -match 'Report|Cloud' -and $Category -in @('Reliability','Output')){ $n += 2 }
        return [int]$n
    }
    function _Score($Items){
        $score = 100
        foreach($item in @($Items)){
            if($null -ne $item.ScoreImpact){ $score -= [int]$item.ScoreImpact }
        }
        return [Math]::Max(0,$score)
    }
    function _ScoreCategory($Items,[string]$Category){
        return _Score (@($Items | Where-Object { $_.Category -eq $Category }))
    }
    function _Distance([string]$A,[string]$B){
        if($null -eq $A){ $A = '' }
        if($null -eq $B){ $B = '' }
        if($A -eq $B){ return 0 }
        if($A.Length -eq 0){ return $B.Length }
        if($B.Length -eq 0){ return $A.Length }
        $d = New-Object 'int[,]' ($A.Length + 1),($B.Length + 1)
        for($i=0;$i -le $A.Length;$i++){ $d.SetValue($i,$i,0) }
        for($j=0;$j -le $B.Length;$j++){ $d.SetValue($j,0,$j) }
        for($i=1;$i -le $A.Length;$i++){
            for($j=1;$j -le $B.Length;$j++){
                if([char]::ToLowerInvariant($A[($i-1)]) -eq [char]::ToLowerInvariant($B[($j-1)])){ $cost = 0 } else { $cost = 1 }
                $del = [int]$d.GetValue(($i-1),$j) + 1
                $ins = [int]$d.GetValue($i,($j-1)) + 1
                $sub = [int]$d.GetValue(($i-1),($j-1)) + $cost
                $d.SetValue([Math]::Min([Math]::Min($del,$ins),$sub),$i,$j)
            }
        }
        return [int]$d.GetValue($A.Length,$B.Length)
    }
    function _Closest([string]$Name,$Valid){
        $best = $null; $bestD = 999
        foreach($v in @($Valid)){
            $dist = _Distance $Name $v
            if($dist -lt $bestD){ $bestD = $dist; $best = $v }
        }
        if($best -and $bestD -le [Math]::Max(2,[Math]::Floor($Name.Length/3))){ return $best }
        return $null
    }
    function _CommandParams($CommandAst){
        @($CommandAst.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName } | Where-Object { $_ })
    }
    function _CommandText($CommandAst){
        try { return $CommandAst.Extent.Text } catch { return '' }
    }
    function _CommandName($CommandAst){
        try { return $CommandAst.GetCommandName() } catch { return $null }
    }
    function _IsCommandInTry($Ast,$CommandAst){
        $tries = @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] },$true))
        foreach($t in $tries){
            if($CommandAst.Extent.StartOffset -ge $t.Body.Extent.StartOffset -and $CommandAst.Extent.EndOffset -le $t.Body.Extent.EndOffset){ return $true }
        }
        return $false
    }
    function _EnclosingFunction($FunctionAsts,$Node){
        foreach($fn in @($FunctionAsts)){
            if($Node.Extent.StartOffset -ge $fn.Extent.StartOffset -and $Node.Extent.EndOffset -le $fn.Extent.EndOffset){ return $fn }
        }
        return $null
    }
    function _FindSuppressionComments([string]$Raw){
        $list = [Collections.Generic.List[object]]::new()
        $lines = @($Raw -split "`r?`n")
        for($i=0;$i -lt $lines.Count;$i++){
            $line = $lines[$i]
            $m = [regex]::Match($line,'#\s*PSSCP:ignore-next-line\s+([^\s]+)(?:\s*-\s*(.+))?','IgnoreCase')
            if($m.Success){ $list.Add([pscustomobject]@{Line=$i+2;Keys=@($m.Groups[1].Value -split ',');Reason=$m.Groups[2].Value.Trim();Raw=$line.Trim()}) | Out-Null }
            $m = [regex]::Match($line,'#\s*PSSCP:ignore\s+([^\s]+)(?:\s*-\s*(.+))?','IgnoreCase')
            if($m.Success -and $line -notmatch 'ignore-next-line'){ $list.Add([pscustomobject]@{Line=0;Keys=@($m.Groups[1].Value -split ',');Reason=$m.Groups[2].Value.Trim();Raw=$line.Trim()}) | Out-Null }
        }
        return @($list)
    }
    function _IsSuppressed([string]$File,[string]$Id,[string]$Category,[string]$Area,[int]$Line){
        if(-not $Suppressions.ContainsKey($File)){ return $false }
        $idL = ([string]$Id).ToLowerInvariant(); $catL = ([string]$Category).ToLowerInvariant(); $areaL = ([string]$Area).ToLowerInvariant()
        foreach($s in @($Suppressions[$File])){
            if($s.Line -ne 0 -and $s.Line -ne $Line){ continue }
            foreach($k in @($s.Keys)){
                $key = ([string]$k).Trim().ToLowerInvariant()
                if($key -eq '*' -or $key -eq $idL -or $key -eq $catL -or $key -eq $areaL){ return $true }
            }
        }
        return $false
    }
    function _Add([string]$File,[string]$Id,[string]$Severity,[string]$Category,[string]$Area,[int]$Line,[string]$Confidence,[string]$Issue,[string]$Recommendation,[object]$Evidence=''){
        if($Id -ne 'PSSCP090' -and $File -and $File -ne '<PSSCP>' -and (_IsSuppressed $File $Id $Category $Area $Line)){ return }
        $impact = _BaseImpact $Severity $Confidence $Category
        $title = if($RuleMeta.ContainsKey($Id)){ $RuleMeta[$Id].Title } else { $Area }
        $Findings.Add([pscustomobject]@{
            Id=$Id;Title=$title;Severity=$Severity;Category=$Category;Area=$Area;Line=$Line;Confidence=$Confidence;ScoreImpact=$impact;File=$File;Issue=$Issue;Recommendation=$Recommendation;Evidence=(_Evidence $Evidence)
        }) | Out-Null
    }
    function _ResolveDotSourcePath([string]$BaseDir,[string]$Text){
        $t = ($Text -replace '^\s*\.\s+','').Trim().Trim('"').Trim("'")
        if([string]::IsNullOrWhiteSpace($t)){ return $null }
        if($t -match '[\$\*\?\[\]]'){ return $null }
        try{
            if([IO.Path]::IsPathRooted($t)){ return [IO.Path]::GetFullPath($t) }
            return [IO.Path]::GetFullPath((Join-Path $BaseDir $t))
        }catch{ return $null }
    }
    function _RiskClass([string]$Command){
        if($Command -match '^(Remove|Clear)-'){ return 'Destructive' }
        if($Command -match '^(Set|New|Update|Add|Grant|Revoke|Register|Unregister|Enable|Disable|Start|Stop|Restart|Move|Rename)-'){ return 'StateChange' }
        if($Command -match '^(Invoke)-' -or $Command -in @('Start-Process','cmd','cmd.exe','powershell','powershell.exe','pwsh','pwsh.exe')){ return 'ExternalOrInvoke' }
        return 'Review'
    }
    function _MdCell([object]$Value){
        if($null -eq $Value){ return '' }
        return (([string]$Value) -replace '\|','\|' -replace "`r?`n",' ')
    }
    function _WriteMarkdown([string]$Path,$Context,$Summary,$Findings){
        $b = [Text.StringBuilder]::new()
        [void]$b.AppendLine('# PSSCP Static Analysis Report')
        [void]$b.AppendLine('')
        [void]$b.AppendLine('## Context')
        foreach($p in $Context.PSObject.Properties){ [void]$b.AppendLine("- **$($p.Name):** $($p.Value)") }
        [void]$b.AppendLine('')
        [void]$b.AppendLine('## Summary')
        [void]$b.AppendLine('| File | Score | Rating | Critical | Errors | Warnings | Info | Syntax | Security | Safety | Reliability | Output | Dependency | Maintainability | Compatibility |')
        [void]$b.AppendLine('|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
        foreach($s in @($Summary | Sort-Object Score,File)){
            [void]$b.AppendLine("| $(_MdCell $s.File) | $($s.Score) | $(_MdCell $s.Rating) | $($s.Critical) | $($s.Errors) | $($s.Warnings) | $($s.Info) | $($s.SyntaxScore) | $($s.SecurityScore) | $($s.SafetyScore) | $($s.ReliabilityScore) | $($s.OutputScore) | $($s.DependencyScore) | $($s.MaintainabilityScore) | $($s.CompatibilityScore) |")
        }
        [void]$b.AppendLine('')
        [void]$b.AppendLine('## Findings')
        foreach($f in @($Findings | Sort-Object File,@{Expression={_Rank $_.Severity}},Line,Id)){
            [void]$b.AppendLine("### [$(_MdCell $f.Severity)] $(_MdCell $f.Id) $(_MdCell $f.File):$($f.Line) - $(_MdCell $f.Title)")
            [void]$b.AppendLine("- **Category:** $(_MdCell $f.Category)")
            [void]$b.AppendLine("- **Area:** $(_MdCell $f.Area)")
            [void]$b.AppendLine("- **Confidence:** $(_MdCell $f.Confidence)")
            [void]$b.AppendLine("- **Issue:** $(_MdCell $f.Issue)")
            [void]$b.AppendLine("- **Recommendation:** $(_MdCell $f.Recommendation)")
            if($f.Evidence){ [void]$b.AppendLine('- **Evidence:** `' + (($f.Evidence -replace '`','``')) + '`') }
            [void]$b.AppendLine('')
        }
        Set-Content -LiteralPath $Path -Value $b.ToString() -Encoding UTF8
    }
    function _WriteSarif([string]$Path,$Findings,$Context){
        $rules = @($Findings | Sort-Object Id -Unique | ForEach-Object { @{ id=$_.Id; name=$_.Title; shortDescription=@{text=$_.Title}; help=@{text=$_.Recommendation} } })
        $results = @($Findings | Where-Object File -ne '<PSSCP>' | ForEach-Object {
            if($_.Severity -in @('Critical','Error')){ $level='error' } elseif($_.Severity -eq 'Warning'){ $level='warning' } else { $level='note' }
            @{ ruleId=$_.Id; level=$level; message=@{text="$($_.Issue) Recommendation: $($_.Recommendation)"}; locations=@(@{physicalLocation=@{artifactLocation=@{uri=$_.File};region=@{startLine=[Math]::Max(1,[int]$_.Line)}}}) }
        })
        @{ version='2.1.0'; '$schema'='https://json.schemastore.org/sarif-2.1.0.json'; runs=@(@{tool=@{driver=@{name=$Context.Tool;version=$Context.ToolVersion;informationUri='https://github.com/bluedawg874/PS_Script_Checker_Plus';rules=$rules}};results=$results}) } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    function _WritePrompt([string]$Path,$Context,$Summary,$Findings){
        $text = @"
You are reviewing PowerShell scripts using PSSCP static-analysis output.

Goal:
Fix Critical, Error, and Warning findings first. Preserve intended functionality. Do not remove features merely to silence findings. Do not weaken safety controls. Explain any finding intentionally left unresolved. Add PSSCP suppression comments only when the risk is understood, acceptable, and justified.

Context:
$($Context | Format-List * | Out-String)

Summary:
$($Summary | Sort-Object Score,File | Format-Table -AutoSize | Out-String -Width 32767)

Findings:
$($Findings | Where-Object Severity -ne 'Info' | Sort-Object File,@{Expression={_Rank $_.Severity}},Line,Id | Format-List Id,Severity,Category,Area,Confidence,File,Line,Issue,Recommendation,Evidence | Out-String -Width 32767)
"@
        Set-Content -LiteralPath $Path -Value $text -Encoding UTF8
    }

    # -----------------------------
    # Self-test fixtures: scanned statically only, never executed
    # -----------------------------
    if($SelfTest){
        $Root = Join-Path $env:TEMP ('PSSCP_SelfTest_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Root 'BadSyntax.ps1') -Value 'function Test-Bad { if($true) { Write-Host "missing brace" ' -Encoding UTF8
        $riskFixture = @'
$password="P@ssw0rd!"
$url="https://example.com/a.ps1"
iex (irm $url)
Remove-Item * -Recurse -Force -ErrorAction SilentlyContinue
try { Get-Process | Out-Null } catch {}
'@
        Set-Content -LiteralPath (Join-Path $Root 'Risky.ps1') -Value $riskFixture -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $Root 'OutputLoss.ps1') -Value 'Get-Process | Format-Table | Export-Csv .\out.csv' -Encoding UTF8
        _Add '<PSSCP>' 'PSSCP900' Info Tool SelfTest 0 High "Self-test mode enabled; temporary static fixtures created under $Root" 'No target scripts outside the self-test folder will be scanned'
    }

    # -----------------------------
    # Dependency bootstrap: PSScriptAnalyzer
    # -----------------------------
    try { if($PSVersionTable.PSVersion.Major -le 5){ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } } catch {}
    $SA = Get-Module -ListAvailable PSScriptAnalyzer -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if(-not $SA -and $AutoInstallDeps){
        _Add '<PSSCP>' 'PSSCP000' Info Dependency Dependency 0 High 'PSScriptAnalyzer not found; attempting CurrentUser install' 'Allow install, or set PSSCP_NO_INSTALL=1 to skip automatic dependency installation'
        try {
            if((Get-Command Install-PackageProvider -ErrorAction SilentlyContinue) -and -not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)){
                $pp = @{ Name='NuGet'; MinimumVersion='2.8.5.201'; Force=$true; ErrorAction='Stop' }
                if((Get-Command Install-PackageProvider).Parameters.ContainsKey('Scope')){ $pp.Scope='CurrentUser' }
                Install-PackageProvider @pp | Out-Null
            }
        } catch { _Add '<PSSCP>' 'PSSCP000' Warning Dependency Dependency 0 Medium 'NuGet provider bootstrap failed' 'Install NuGet/PowerShellGet manually if PSScriptAnalyzer install fails' $_.Exception.Message }
        try {
            $cmd = Get-Command Install-Module -ErrorAction Stop
            $im = @{ Name='PSScriptAnalyzer'; Scope='CurrentUser'; Force=$true; AllowClobber=$true; Repository='PSGallery'; ErrorAction='Stop' }
            if($cmd.Parameters.ContainsKey('AcceptLicense')){ $im.AcceptLicense = $true }
            Install-Module @im
            _Add '<PSSCP>' 'PSSCP000' Info Dependency Dependency 0 High 'PSScriptAnalyzer installed to CurrentUser' 'No action required'
        } catch { _Add '<PSSCP>' 'PSSCP000' Warning Dependency Dependency 0 Medium 'Automatic PSScriptAnalyzer install failed' 'Run: Install-Module PSScriptAnalyzer -Scope CurrentUser -Force' $_.Exception.Message }
        $SA = Get-Module -ListAvailable PSScriptAnalyzer -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    }
    if($SA){
        try { Import-Module PSScriptAnalyzer -ErrorAction Stop; _Add '<PSSCP>' 'PSSCP000' Info Dependency Dependency 0 High "PSScriptAnalyzer loaded: $($SA.Version)" 'No action required' }
        catch { _Add '<PSSCP>' 'PSSCP000' Warning Dependency Dependency 0 Medium 'PSScriptAnalyzer import failed' 'Repair/reinstall PSScriptAnalyzer' $_.Exception.Message }
    } else {
        _Add '<PSSCP>' 'PSSCP000' Warning Dependency Dependency 0 High 'PSScriptAnalyzer unavailable' 'Install-Module PSScriptAnalyzer -Scope CurrentUser -Force for fuller analysis'
    }

    # -----------------------------
    # File discovery
    # -----------------------------
    $Files = @()
    if($ChangedOnly -and (Get-Command git -ErrorAction SilentlyContinue)){
        try {
            $changed = @(git -C $Root status --porcelain 2>$null | ForEach-Object {
                $x = $_
                if($x.Length -ge 4){
                    $p = $x.Substring(3).Trim()
                    if($p -match ' -> '){ $p = ($p -split ' -> ')[-1] }
                    $p.Trim('"')
                }
            } | Where-Object { $_ })
            foreach($c in $changed){
                $p = Join-Path $Root $c
                if(Test-Path -LiteralPath $p -PathType Leaf){ $KnownChangedFiles[$p.ToLowerInvariant()] = $p }
            }
        } catch {}
    }
    if($KnownChangedFiles.Count -gt 0){
        $Files = @(Get-Item -LiteralPath @($KnownChangedFiles.Values) -ErrorAction SilentlyContinue | Where-Object { $Extensions -contains $_.Extension -and $_.FullName -notmatch $DefaultExclude -and ([string]::IsNullOrWhiteSpace($AdditionalExclude) -or $_.FullName -notmatch $AdditionalExclude) -and ($_.Length/1MB) -le $MaxFileMB })
    } elseif($ChangedOnly){
        Write-Host "PSSCP_CHANGED_ONLY=1 but no changed PowerShell files were found under $Root" -ForegroundColor Yellow
        return
    } else {
        $Files = @(Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $Extensions -contains $_.Extension -and $_.FullName -notmatch $DefaultExclude -and ([string]::IsNullOrWhiteSpace($AdditionalExclude) -or $_.FullName -notmatch $AdditionalExclude) -and ($_.Length/1MB) -le $MaxFileMB })
    }
    if(-not $Files.Count){ Write-Host "No PowerShell files found under $Root" -ForegroundColor Yellow; return }
    foreach($f in $Files){ $FileByLowerPath[$f.FullName.ToLowerInvariant()] = $true }

    # -----------------------------
    # First pass: collect functions and suppressions
    # -----------------------------
    foreach($f in $Files){
        $rel = _Rel $f.FullName
        try {
            $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            $Suppressions[$rel] = @(_FindSuppressionComments $raw)
            foreach($s in @($Suppressions[$rel])){
                if([string]::IsNullOrWhiteSpace($s.Reason)){ _Add $rel 'PSSCP090' Warning Maintainability Suppression $s.Line Medium 'PSSCP suppression has no justification' 'Add a short reason after a hyphen so reviewers know why the suppression is acceptable' $s.Raw }
                foreach($k in @($s.Keys)){
                    $kk = $k.Trim()
                    if($kk -and $kk -ne '*' -and -not $RuleMeta.ContainsKey($kk) -and ($RuleMeta.Values.Category -notcontains $kk) -and ($SuppressionKnownAreas -notcontains $kk)){
                        _Add $rel 'PSSCP090' Info Maintainability Suppression $s.Line Low "Suppression key '$kk' is not a known rule ID/category/area" 'Verify the suppression key matches the intended finding; otherwise it may not suppress anything' $s.Raw
                    }
                    if($kk -eq '*'){
                        _Add $rel 'PSSCP090' Warning Maintainability Suppression $s.Line Medium 'Wildcard suppression used' 'Avoid broad suppressions unless the whole file is intentionally exempt and the reason is clear' $s.Raw
                    }
                }
            }
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tok,[ref]$err)
            $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },$true) | ForEach-Object Name | Sort-Object -Unique)
            $PerFileFunctions[$f.FullName] = $names
            foreach($n in $names){
                if(-not $FunctionToFiles.ContainsKey($n)){ $FunctionToFiles[$n] = [Collections.Generic.List[string]]::new() }
                $FunctionToFiles[$n].Add($f.FullName) | Out-Null
            }
        } catch { _Add $rel 'PSSCP003' Error Syntax Read 0 High 'Failed first-pass file read or parse' 'Fix file access, encoding, or syntax enough for analysis' $_.Exception.Message }
    }

    function _CrossParse([string]$HostName,[string]$File,[string]$Rel){
        $cmd = Get-Command $HostName -ErrorAction SilentlyContinue | Select-Object -First 1
        if(-not $cmd){ return }
        $probe = '$p=$args[0];$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e);if($e){$e|%{"ERR|$($_.Extent.StartLineNumber)|$($_.Message)"}}else{"OK"}'
        try {
            $out = & $cmd.Source -NoProfile -Command $probe $File 2>&1
            foreach($line in @($out)){
                $s = $line.ToString()
                if($s -like 'ERR|*'){
                    $parts = $s -split '\|',3
                    $ln = 0; [void][int]::TryParse($parts[1],[ref]$ln)
                    _Add $Rel 'PSSCP002' Critical Syntax CrossParse $ln High "$HostName parser reported a syntax error" 'Fix syntax or make the script compatible with the intended PowerShell host' $parts[2]
                }
            }
        } catch { _Add $Rel 'PSSCP002' Info Syntax CrossParse 0 Low "$HostName cross-parse probe failed" 'Usually safe to ignore unless cross-version compatibility matters' $_.Exception.Message }
    }

    # -----------------------------
    # Main analysis loop
    # -----------------------------
    foreach($f in $Files){
        $startIndex = $Findings.Count
        $rel = _Rel $f.FullName
        $raw = ''
        try {
            $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
        } catch { _Add $rel 'PSSCP003' Critical Syntax Read 0 High 'File could not be read' 'Fix file access/encoding/path before review' $_.Exception.Message; continue }

        # Basic file format / trust checks.
        if($bytes.Length -gt 1 -and $bytes[0] -eq 0 -and $bytes[1] -eq 0){ _Add $rel 'PSSCP003' Warning Syntax Encoding 0 Medium 'Possible binary or UTF-16/null-byte-heavy file detected' 'Verify this is a text PowerShell script' }
        if([regex]::IsMatch($raw,'[\u202A-\u202E\u2066-\u2069]')){ _Add $rel 'PSSCP034' Warning Security Unicode 0 High 'Bidirectional/hidden Unicode control character detected' 'Inspect and remove hidden Unicode controls before running or reviewing code' }
        $crlf = ([regex]::Matches($raw,"`r`n")).Count; $lf = ([regex]::Matches($raw,"(?<!`r)`n")).Count
        if($crlf -gt 0 -and $lf -gt 0){ _Add $rel 'PSSCP003' Info Syntax Formatting 0 Low 'Mixed CRLF/LF line endings detected' 'Normalise line endings if tooling behaves inconsistently' }
        try {
            if(Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue){
                $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction SilentlyContinue
                if($sig -and $sig.Status -notin @('Valid','NotSigned')){ _Add $rel 'PSSCP034' Warning Security Signature 0 Medium "Authenticode signature status: $($sig.Status)" 'Verify signature status before trusting the file' $sig.StatusMessage }
            }
        } catch {}

        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$parseErrors)
        foreach($pe in @($parseErrors)){ _Add $rel 'PSSCP001' Critical Syntax Parser $pe.Extent.StartLineNumber High $pe.Message 'Fix syntax before attempting to run the script' $pe.Extent.Text }
        if($CrossParse){ _CrossParse 'powershell.exe' $f.FullName $rel; _CrossParse 'pwsh.exe' $f.FullName $rel }

        $commandAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] },$true))
        $functionAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },$true))
        $paramAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] },$true))
        $varAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] },$true))
        $assignAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] },$true))
        $catchAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] },$true))
        $pipelineAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.PipelineAst] },$true))
        $typeAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] },$true))

        $commands = @($commandAsts | ForEach-Object { [pscustomobject]@{Ast=$_;Name=(_CommandName $_);Line=$_.Extent.StartLineNumber;Text=(_CommandText $_);Params=@(_CommandParams $_)} } | Where-Object Name)
        $dynamicCommands = @($commandAsts | Where-Object { -not (_CommandName $_) })
        $functionNames = @($functionAsts | ForEach-Object Name | Sort-Object -Unique)
        $variableNames = @($varAsts | ForEach-Object { $_.VariablePath.UserPath } | Where-Object { $_ } | Sort-Object -Unique)
        $dotSourcedPaths = [Collections.Generic.List[string]]::new()

        # #Requires checks.
        $req = $ast.ScriptRequirements
        try {
            if($req.RequiredPSVersion -and $PSVersionTable.PSVersion -lt $req.RequiredPSVersion){ _Add $rel 'PSSCP010' Critical Dependency Requires 0 High "Script requires PowerShell $($req.RequiredPSVersion); current is $($PSVersionTable.PSVersion)" 'Run in the required PowerShell version or adjust the script requirement only if compatible' }
            foreach($edition in @($req.RequiredPSEditions)){
                if($edition -and $edition -ne $PSVersionTable.PSEdition){ _Add $rel 'PSSCP062' Warning Compatibility PSEdition 0 Medium "Script requires PSEdition $edition; current is $($PSVersionTable.PSEdition)" 'Run under the intended PowerShell edition or verify compatibility' }
            }
            $requiresElevation = $false
            try { $requiresElevation = [bool]$req.IsElevationRequired -or [bool]$req.RequiresElevation } catch {}
            if($requiresElevation){
                $isAdmin = $false
                try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) } catch {}
                if(-not $isAdmin){ _Add $rel 'PSSCP010' Warning Dependency Requires 0 High 'Script declares #Requires -RunAsAdministrator but current shell is not elevated' 'Open an elevated PowerShell session if you intend to run it' }
            }
            foreach($m in @($req.RequiredModules)){
                $mn = if($m.Name){ $m.Name } else { [string]$m }
                if($mn -and -not (Get-Module -ListAvailable -Name $mn -ErrorAction SilentlyContinue)){ _Add $rel 'PSSCP010' Error Dependency Requires 0 High "Required module missing: $mn" 'Install/import the required module or add dependency bootstrapping' }
            }
        } catch { _Add $rel 'PSSCP010' Info Dependency Requires 0 Low 'Unable to fully inspect #Requires metadata' 'Manually verify required versions/modules/elevation if present' $_.Exception.Message }

        # Dot-sourced dependency checks.
        foreach($cAst in $commandAsts){
            try {
                if($cAst.InvocationOperator.ToString() -eq 'Dot'){
                    $p = _ResolveDotSourcePath $f.DirectoryName $cAst.Extent.Text
                    if($p){
                        $dotSourcedPaths.Add($p) | Out-Null
                        if(-not (Test-Path -LiteralPath $p)){ _Add $rel 'PSSCP014' Error Dependency DotSource $cAst.Extent.StartLineNumber High 'Dot-sourced file does not exist' 'Fix path or include the dependency before running' $cAst.Extent.Text }
                    } else { _Add $rel 'PSSCP014' Warning Dependency DotSource $cAst.Extent.StartLineNumber Medium 'Dynamic dot-sourced path cannot be statically verified' 'Manually verify dot-sourced dependency exists and is trusted' $cAst.Extent.Text }
                }
            } catch {}
        }
        $dotFunctionNames = @()
        foreach($dp in @($dotSourcedPaths)){
            if($PerFileFunctions.ContainsKey($dp)){ $dotFunctionNames += @($PerFileFunctions[$dp]) }
        }

        foreach($dc in $dynamicCommands){ _Add $rel 'PSSCP011' Warning Dependency DynamicCommand $dc.Extent.StartLineNumber Medium 'Dynamic command cannot be statically resolved' 'Manually verify the invoked command or path before running' $dc.Extent.Text }

        # Command dependency, alias, parameter checks.
        $commonParams = @('Verbose','Debug','ErrorAction','WarningAction','InformationAction','ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer','PipelineVariable','WhatIf','Confirm')
        foreach($cmdName in @($commands.Name | Sort-Object -Unique)){
            if($functionNames -contains $cmdName){ continue }
            if($dotFunctionNames -contains $cmdName){ continue }
            if($FunctionToFiles.ContainsKey($cmdName)){
                _Add $rel 'PSSCP014' Warning Dependency LocalFunction 0 Medium "Function '$cmdName' exists in another scanned file but is not clearly dot-sourced/imported here" 'Dot-source/import the file explicitly or avoid relying on scan-folder coincidence' ($FunctionToFiles[$cmdName] -join ', ')
                continue
            }
            if(-not $CommandCache.ContainsKey($cmdName)){ $CommandCache[$cmdName] = Get-Command -Name $cmdName -ErrorAction SilentlyContinue }
            $gc = $CommandCache[$cmdName]
            if(-not $gc){
                _Add $rel 'PSSCP011' Warning Dependency Command 0 Medium "Command missing, dynamic, external, or not currently loaded: $cmdName" 'Verify required module, import, PATH executable, or local function definition before running'
                continue
            }
            if($gc.CommandType -eq 'Alias'){ _Add $rel 'PSSCP012' Warning Maintainability Alias 0 High "Alias used: $cmdName -> $($gc.ResolvedCommandName)" 'Replace aliases with full command names for reliability and reviewability' }
            foreach($cmdUse in @($commands | Where-Object Name -eq $cmdName)){
                if($gc.Parameters){
                    $valid = @($gc.Parameters.Keys + $commonParams | Sort-Object -Unique)
                    foreach($pn in @($cmdUse.Params)){
                        if($valid -notcontains $pn){
                            $suggest = _Closest $pn $valid
                            $rec = if($suggest){ "Verify parameter; possible intended parameter: -$suggest" } else { 'Verify the parameter is valid for this command/module version. Dynamic parameters may be host/provider-specific.' }
                            _Add $rel 'PSSCP013' Warning Dependency Parameter $cmdUse.Line Medium "Parameter -$pn was not found on command $cmdName" $rec $cmdUse.Text
                        }
                    }
                }
            }
        }

        # Module family / context inference.
        $cmdList = @($commands.Name | Sort-Object -Unique)
        $requiresModulesText = (($req.RequiredModules | ForEach-Object { if($_.Name){$_.Name}else{[string]$_} }) -join ',')
        $importModuleText = (($commands | Where-Object Name -eq 'Import-Module' | ForEach-Object Text) -join ' ')
        $families = [Collections.Generic.List[string]]::new()
        if($cmdList -match '^(Get|Set|New|Remove|Update|Invoke|Connect|Disconnect)-Mg'){ $families.Add('Microsoft.Graph') | Out-Null }
        if($cmdList -match '^(Get|Set|New|Remove|Update|Invoke|Connect|Disconnect)-Az'){ $families.Add('Az') | Out-Null }
        if($cmdList -match '^(Get|Set|New|Remove|Update|Connect|Disconnect)-PnP'){ $families.Add('PnP.PowerShell') | Out-Null }
        if(($cmdList -match '^(Get|Set|New|Remove|Update)-AD') -or (($cmdList -contains 'Import-Module') -and ($raw -match 'ActiveDirectory'))){ $families.Add('ActiveDirectory') | Out-Null }
        if($cmdList -match '^(Get|Set|New|Remove|Update)-EXO' -or $cmdList -contains 'Connect-ExchangeOnline' -or $cmdList -match '^(Get|Set|New|Remove)-Mailbox|^(Get|Set|New|Remove)-Recipient'){ $families.Add('ExchangeOnlineManagement') | Out-Null }
        foreach($fam in @($families | Sort-Object -Unique)){
            _Add $rel 'PSSCP015' Info Dependency ModuleFamily 0 Low "Detected likely module family: $fam" 'Verify module requirement/import/connection handling matches the script intent'
            if($requiresModulesText -notmatch [regex]::Escape($fam.Split('.')[0]) -and $importModuleText -notmatch [regex]::Escape($fam.Split('.')[0])){ _Add $rel 'PSSCP015' Info Dependency ModuleFamily 0 Low "No obvious #Requires/Import-Module for detected family $fam" 'Consider adding #Requires -Modules or explicit Import-Module for repeatability' }
        }
        if(($cmdList -match '^(Get|Set|New|Remove|Update|Invoke)-Mg') -and ($cmdList -notcontains 'Connect-MgGraph')){ _Add $rel 'PSSCP023' Warning Safety Context 0 Medium 'Microsoft Graph cmdlets used but no Connect-MgGraph command detected' 'Verify the script establishes Graph authentication/context elsewhere' }
        if(($cmdList -match '^(Get|Set|New|Remove|Update)-Az') -and ($cmdList -notcontains 'Connect-AzAccount')){ _Add $rel 'PSSCP023' Warning Safety Context 0 Medium 'Az cmdlets used but no Connect-AzAccount command detected' 'Verify the script establishes Azure context/subscription elsewhere' }
        if(($cmdList -match '^(Get|Set|New|Remove|Update)-PnP') -and ($cmdList -notcontains 'Connect-PnPOnline')){ _Add $rel 'PSSCP023' Warning Safety Context 0 Medium 'PnP cmdlets used but no Connect-PnPOnline command detected' 'Verify the script establishes SharePoint/PnP context elsewhere' }
        if(($cmdList -match '^(Get|Set|New|Remove|Update)-EXO|^(Get|Set|New|Remove)-Mailbox|^(Get|Set|New|Remove)-Recipient') -and ($cmdList -notcontains 'Connect-ExchangeOnline')){ _Add $rel 'PSSCP023' Warning Safety Context 0 Medium 'Exchange cmdlets used but no Connect-ExchangeOnline command detected' 'Verify Exchange Online/session context is established elsewhere' }
        if(($raw -match 'AzureAD|MSOnline') -and ($raw -match 'Microsoft\.Graph|Connect-MgGraph|Get-Mg')){ _Add $rel 'PSSCP015' Warning Dependency ModuleFamily 0 Medium 'Deprecated AzureAD/MSOnline style appears mixed with Microsoft Graph' 'Verify module compatibility and migration path; avoid mixing modules unless intentional' }

        # Risk, destructive scope, ShouldProcess, and admin-sensitive checks.
        $changeRegex = '^(Remove|Set|New|Clear|Disable|Enable|Update|Add|Grant|Revoke|Register|Unregister|Move|Rename)-'
        $highImpact = @($commands | Where-Object { $_.Name -match $changeRegex -or $_.Name -match '^Invoke-' -or $_.Name -in @('Start-Process','cmd','cmd.exe','powershell','powershell.exe','pwsh','pwsh.exe') })
        foreach($hc in $highImpact){
            $class = _RiskClass $hc.Name
            _Add $rel 'PSSCP020' Warning Safety Risk $hc.Line Medium "High-impact command detected: $($hc.Name) [$class]" 'Manually review intent, scope, safety controls, rollback, and error handling' $hc.Text
            if($class -eq 'Destructive' -and ($hc.Text -match '\*' -or $hc.Params -contains 'Recurse' -or $hc.Text -match '\|\s*Remove-')){ _Add $rel 'PSSCP021' Warning Safety DestructiveScope $hc.Line High 'Potentially broad destructive operation detected' 'Narrow the target, validate path/input, add WhatIf/ShouldProcess, and confirm rollback expectations' $hc.Text }
            $fn = _EnclosingFunction $functionAsts $hc.Ast
            $scopeText = if($fn){ $fn.Extent.Text } else { $raw }
            if($hc.Name -match $changeRegex -and -not ($scopeText -match 'SupportsShouldProcess' -and $scopeText -match '\$PSCmdlet\.ShouldProcess|ShouldProcess\s*\(')){ _Add $rel 'PSSCP022' Warning Safety ShouldProcess $hc.Line High 'Change command is not clearly guarded by a local ShouldProcess/WhatIf pattern' 'Add CmdletBinding(SupportsShouldProcess) and wrap the change operation in ShouldProcess' $hc.Text }
            if($hc.Name -match $changeRegex -and -not (_IsCommandInTry $ast $hc.Ast) -and $hc.Text -notmatch '-ErrorAction\s+Stop' -and $raw -notmatch '\$ErrorActionPreference\s*=\s*[''\"]Stop[''\"]'){
                if($Profile -match 'Strict|Destructive'){ _Add $rel 'PSSCP040' Warning Reliability ErrorHandling $hc.Line Medium 'Change command has no obvious try/catch or terminating ErrorAction handling' 'Consider try/catch with -ErrorAction Stop around change operations' $hc.Text }
            }
        }
        $securitySensitive = @('Set-ExecutionPolicy','Unblock-File','Add-MpPreference','Set-MpPreference','Disable-NetFirewallRule','New-NetFirewallRule','Set-NetFirewallRule','Register-ScheduledTask','New-Service','Set-Service','sc.exe','netsh')
        foreach($sc in @($commands | Where-Object { $securitySensitive -contains $_.Name -or $_.Text -match 'Administrators|HKLM:|HKEY_LOCAL_MACHINE|Defender|Firewall|ScheduledTask' })){
            _Add $rel 'PSSCP024' Warning Safety PrivilegedChange $sc.Line Medium 'Security-sensitive or admin-level operation detected' 'Verify elevation, target scope, rollback, and whether this is acceptable before running' $sc.Text
        }
        if(($raw -match 'HKLM:|HKEY_LOCAL_MACHINE|Add-MpPreference|Set-MpPreference|New-NetFirewallRule|Register-ScheduledTask|New-Service') -and $raw -notmatch 'WindowsPrincipal|IsInRole|RunAsAdministrator|#Requires\s+-RunAsAdministrator'){
            _Add $rel 'PSSCP023' Warning Safety Elevation 0 Medium 'Likely admin-level operations without obvious elevation check' 'Add #Requires -RunAsAdministrator or an explicit elevation check where appropriate'
        }

        # Pipeline shape / output loss.
        foreach($pl in $pipelineAsts){
            $names = @($pl.PipelineElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandAst] } | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            if(($names -match '^Format-') -and ($names -match 'Export-Csv|ConvertTo-Json|Out-File|Set-Content|Add-Content')){ _Add $rel 'PSSCP051' Warning Output Pipeline $pl.Extent.StartLineNumber High 'Formatted output appears in a pipeline that writes/exports data' 'Keep structured objects until the final display/export stage; do not export Format-* output' $pl.Extent.Text }
            if(($names[0] -match '^Get-') -and ($names -match '^Remove-|^Set-|^Disable-|^Clear-') -and $pl.Extent.Text -notmatch 'Where-Object|\?|Select-Object|ForEach-Object'){
                _Add $rel 'PSSCP021' Warning Safety PipelineScope $pl.Extent.StartLineNumber High 'Get-* output flows into a change/destructive command without obvious narrowing filter' 'Add explicit filtering, confirmation, and ShouldProcess before pipeline-driven changes' $pl.Extent.Text
            }
        }

        # Regex/static text rules.
        $patterns = @(
            @('PSSCP030','Warning','Security','Secret','(?i)(password|passwd|secret|token|apikey|api_key|clientsecret|client_secret)\s*=\s*["''][^"'']{4,}["'']','Possible hardcoded secret/token assignment','Use secure input, a vault, environment-specific secret handling, or clearly marked sample placeholders','High'),
            @('PSSCP030','Warning','Security','Secret','ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+','Token-like string/JWT pattern detected','Remove secrets from scripts; rotate if this is a real credential','High'),
            @('PSSCP031','Critical','Security','RemoteExecution','Invoke-Expression|\biex\b','Invoke-Expression / iex detected','Avoid string execution; use direct commands or validated script blocks','High'),
            @('PSSCP031','Critical','Security','RemoteExecution','(Invoke-RestMethod|Invoke-WebRequest|irm|iwr).{0,120}(Invoke-Expression|\biex\b)|\|\s*(Invoke-Expression|iex)\b','Download-to-execute pattern detected','Do not pipe remote content directly into execution unless you explicitly trust, pin and verify it','High'),
            @('PSSCP031','Warning','Security','Encoded','-EncodedCommand|FromBase64String|ToBase64String','Encoded/base64 command or content pattern detected','Verify whether this is legitimate encoding or an obfuscation/execution pattern','Medium'),
            @('PSSCP032','Warning','Security','Interop','Add-Type|DllImport|Reflection\.Assembly|New-Object\s+-ComObject|\[Runtime\.InteropServices','Native interop/reflection/COM pattern detected','Review trust, platform compatibility, and whether native code is necessary','Medium'),
            @('PSSCP033','Warning','Security','SupplyChain','Install-Module|Install-Script|Set-PSRepository|Register-PSRepository|Unregister-PSRepository','Repository/module installation command detected','Verify repository trust, version pinning, and supply-chain controls','Medium'),
            @('PSSCP040','Warning','Reliability','Errors','-ErrorAction\s+SilentlyContinue|\$ErrorActionPreference\s*=\s*["'']SilentlyContinue["'']','Silent error handling detected','Avoid hiding failures unless explicitly justified, logged, and reflected in final status','High'),
            @('PSSCP060','Warning','Maintainability','Placeholder','<tenant-id>|<subscription-id>|<client-id>|YOUR_|REPLACE_ME|CHANGEME|example\.com|contoso\.com|TODO_REPLACE','Placeholder/sample value detected','Replace placeholders with parameters, validated inputs, or documented samples before use','Medium'),
            @('PSSCP080','Info','Maintainability','Marker','TODO|FIXME|HACK|TEMP|WORKAROUND','Marker detected','Resolve or explicitly confirm before production use','Low')
        )
        foreach($p in $patterns){
            foreach($m in [regex]::Matches($raw,$p[4],[Text.RegularExpressions.RegexOptions]::IgnoreCase)){
                _Add $rel $p[0] $p[1] $p[2] $p[3] (_LineFromIndex $raw $m.Index) $p[7] $p[5] $p[6] $m.Value
            }
        }

        # Error handling / catch quality.
        foreach($catch in $catchAsts){
            $ct = $catch.Extent.Text
            if($ct -match '^\s*catch\s*\{\s*\}\s*$'){ _Add $rel 'PSSCP040' Warning Reliability Errors $catch.Extent.StartLineNumber High 'Empty catch block detected' 'Handle, log, rethrow, or collect the error instead of silently ignoring it' $ct }
            elseif($ct -notmatch '\$_|\$PSItem|Write-Error|throw|return|Write-Warning|Add\(|\.Add\('){ _Add $rel 'PSSCP040' Info Reliability Errors $catch.Extent.StartLineNumber Low 'Catch block does not clearly expose or record the caught error' 'Verify exceptions are surfaced in a useful way' $ct }
        }

        # Retry/throttling and API completeness heuristics.
        $usesNetwork = ($cmdList -match 'Invoke-RestMethod|Invoke-WebRequest' -or $raw -match 'graph\.microsoft\.com|https?://')
        if($usesNetwork -and $raw -notmatch 'retry|backoff|429|TooManyRequests|Start-Sleep|Retry-After'){
            _Add $rel 'PSSCP041' Warning Reliability Retry 0 Medium 'Network/API calls detected without obvious retry/throttling handling' 'Consider retry/backoff handling for transient failures and throttling where appropriate'
        }
        if($raw -match 'graph\.microsoft\.com' -and $raw -notmatch '@odata\.nextLink|nextLink'){
            _Add $rel 'PSSCP042' Warning Reliability Pagination 0 High 'Microsoft Graph REST usage without obvious @odata.nextLink handling' 'Add pagination handling to avoid incomplete results from Graph list endpoints'
        }
        foreach($mg in @($commands | Where-Object { $_.Name -match '^Get-Mg' })){
            if($mg.Text -notmatch '\s-All(\s|$)' -and $mg.Text -notmatch '-(UserId|GroupId|DeviceId|Id)\s'){
                _Add $rel 'PSSCP042' Warning Reliability Pagination $mg.Line Medium "Graph collection cmdlet may need -All: $($mg.Name)" 'Verify whether the command returns a collection and add -All or pagination handling if needed' $mg.Text
            }
        }
        foreach($ex in @($commands | Where-Object { $_.Name -match '^(Get-Mailbox|Get-Recipient|Get-DistributionGroup|Get-UnifiedGroup|Get-EXO)' })){
            if($ex.Text -notmatch '-ResultSize\s+Unlimited'){
                _Add $rel 'PSSCP042' Warning Reliability Pagination $ex.Line Medium "Exchange collection command may need -ResultSize Unlimited: $($ex.Name)" 'Add -ResultSize Unlimited where full tenant coverage is intended' $ex.Text
            }
        }
        if($cmdList -match 'Search-AzGraph|Invoke-AzResourceGraphQuery' -and $raw -notmatch 'SkipToken|First|Skip|while|do\s*\{'){
            _Add $rel 'PSSCP042' Warning Reliability Pagination 0 Medium 'Azure Resource Graph usage without obvious paging/limit handling' 'Verify query limits and implement paging/skip-token logic if full coverage is required'
        }

        # Output/report quality and context assumptions.
        $commentText = (([regex]::Matches($raw,'(?m)^\s*#.*$') | ForEach-Object { $_.Value }) -join "`n")
        $hasOutputCmd = $raw -match 'Export-Csv|ConvertTo-Json|Out-File|Set-Content|Add-Content|Export-Clixml|ConvertTo-Html'
        $looksLikeReport = ($commentText -match '(?i)export|report|inventory|audit|csv|json|evidence' -or $hasOutputCmd)
        if($commentText -match '(?i)read.?only|dry.?run|no\s+changes|does\s+not\s+modify' -and $highImpact.Count -gt 0){ _Add $rel 'PSSCP060' Warning Maintainability CommentMismatch 0 Medium 'Comments imply read-only/dry-run behaviour but change commands exist' 'Verify comments match actual behaviour and add WhatIf/ShouldProcess where appropriate' }
        if($commentText -match '(?i)export|report|csv|json' -and -not $hasOutputCmd){ _Add $rel 'PSSCP050' Warning Output ReportQuality 0 Medium 'Comments mention export/report output but no obvious structured/file output command was found' 'Verify the script produces the promised output' }
        if($looksLikeReport){
            if($raw -notmatch 'Count|Measure-Object|Total|Summary'){ _Add $rel 'PSSCP050' Info Output ReportQuality 0 Low 'Report/export script has no obvious count/final summary' 'Consider adding per-section counts and a final summary for validation' }
            if($raw -notmatch 'Failed|Failure|Skipped|ErrorSummary|Errors|Warnings'){ _Add $rel 'PSSCP050' Info Output ReportQuality 0 Low 'Report/export script has no obvious failed/skipped/error collection summary' 'Consider collecting and reporting failed or skipped items' }
            if($raw -match 'Export-Csv' -and $raw -notmatch 'Join-Path|New-Item\s+-ItemType\s+Directory|Test-Path'){ _Add $rel 'PSSCP052' Info Output Context 0 Low 'CSV/file export without obvious output folder creation/path validation' 'Ensure output directories exist and paths are predictable' }
            if($raw -match 'ConvertTo-Json' -and $raw -notmatch '-Depth\s+([5-9]|\d{2,})'){ _Add $rel 'PSSCP050' Warning Output ReportQuality 0 Medium 'ConvertTo-Json without sufficient explicit -Depth detected' 'Set an appropriate -Depth for nested objects to avoid truncated JSON' }
        }
        if($raw -match 'Format-(Table|List|Wide).{0,160}(Export-Csv|ConvertTo-Json|Set-Content|Out-File)' -or $raw -match '(Export-Csv|ConvertTo-Json|Set-Content|Out-File).{0,160}Format-(Table|List|Wide)'){
            _Add $rel 'PSSCP051' Warning Output OutputLoss 0 High 'Possible Format-* near export/output operation' 'Avoid exporting formatted text when structured objects are expected'
        }
        if($raw -match 'Export-Csv' -and $raw -notmatch '-NoTypeInformation'){ _Add $rel 'PSSCP050' Info Output Csv 0 Low 'Export-Csv without -NoTypeInformation detected' 'Usually harmless in newer PowerShell; verify expected CSV format for target hosts' }
        if($raw -match 'Write-Host' -and -not $hasOutputCmd -and $raw -notmatch 'Write-Output'){
            _Add $rel 'PSSCP050' Info Output Console 0 Low 'Script appears to rely mainly on Write-Host output' 'Acceptable for console helpers; prefer structured output for automation or reports'
        }
        if($raw -match '[A-Za-z]:\\[^\s"'']+' -or $raw -match '/Users/|/home/|/tmp/'){
            _Add $rel 'PSSCP052' Info Output Path 0 Low 'Hardcoded absolute path pattern detected' 'Verify path is intended or convert it to a parameter/default'
        }
        if($raw -notmatch '\$PSScriptRoot|Join-Path|Test-Path' -and $raw -match '\.\\|\.ps1|\.csv|\.json'){
            _Add $rel 'PSSCP052' Info Output Path 0 Low 'Relative path usage without obvious PSScriptRoot/Test-Path handling' 'Verify expected working directory or anchor paths to PSScriptRoot'
        }

        # Compatibility checks.
        if($raw -match '\?\?'){ _Add $rel 'PSSCP062' Info Compatibility PS7Syntax 0 Medium 'Null-coalescing operator detected' 'Requires PowerShell 7+; verify target host compatibility' }
        if($raw -match '\?\s*[^:]+\s*:'){ _Add $rel 'PSSCP062' Info Compatibility PS7Syntax 0 Low 'Possible ternary operator detected' 'Requires PowerShell 7+ if this is actual ternary syntax' }
        if($raw -match 'ForEach-Object\s+-Parallel'){ _Add $rel 'PSSCP062' Warning Compatibility PS7Syntax 0 Medium 'ForEach-Object -Parallel detected' 'Requires PowerShell 7+ and has runspace/state considerations' }
        if($raw -match 'New-Object\s+-ComObject|HKLM:|Registry::|Get-WmiObject'){ _Add $rel 'PSSCP062' Info Compatibility WindowsSpecific 0 Medium 'Windows-specific PowerShell/registry/COM/WMI pattern detected' 'Verify target platform is Windows/Windows PowerShell where required' }

        # Dead code / AI scaffolding hints.
        foreach($fn in @($functionNames)){
            if(@($commands | Where-Object Name -eq $fn).Count -eq 0){ _Add $rel 'PSSCP061' Info Maintainability DeadCode 0 Low "Function appears defined but not called in the same scan context: $fn" 'Verify whether it is intentionally exported, dot-sourced, or unused scaffolding' }
        }
        foreach($as in $assignAsts){
            try {
                $leftText = $as.Left.Extent.Text
                if($leftText -match '^\$([A-Za-z_][A-Za-z0-9_]*)$'){
                    $vn = $Matches[1]
                    if($vn -notin @('null','true','false','ErrorActionPreference','VerbosePreference','InformationPreference','WarningPreference') -and @($varAsts | Where-Object { $_.VariablePath.UserPath -eq $vn }).Count -le 1){
                        _Add $rel 'PSSCP061' Info Maintainability DeadCode $as.Extent.StartLineNumber Low "Variable appears assigned but not referenced elsewhere: `$$vn" 'Verify whether this is unused scaffolding or intended future use' $as.Extent.Text
                    }
                }
            } catch {}
        }

        # PSD1 / manifest checks.
        if($f.Extension -eq '.psd1'){
            try { $null = Import-PowerShellDataFile -LiteralPath $f.FullName -ErrorAction Stop }
            catch { _Add $rel 'PSSCP080' Error Maintainability Manifest 0 High '.psd1 failed Import-PowerShellDataFile validation' 'Fix PowerShell data file syntax/content' $_.Exception.Message }
            try {
                if($f.Name -like '*.psd1'){ $null = Test-ModuleManifest -Path $f.FullName -ErrorAction Stop }
            } catch { _Add $rel 'PSSCP080' Info Maintainability Manifest 0 Low 'Test-ModuleManifest failed or file is not a module manifest' 'Ignore for non-module data files; fix if intended as a module manifest' $_.Exception.Message }
        }

        # PSScriptAnalyzer.
        if($SA){
            try {
                foreach($a in @(Invoke-ScriptAnalyzer -Path $f.FullName -Severity Error,Warning,Information -ErrorAction Stop)){
                    $sev = if($a.Severity -eq 'Error'){'Error'}elseif($a.Severity -eq 'Warning'){'Warning'}else{'Info'}
                    $ev = ''; try { if($a.Extent){ $ev = $a.Extent.Text } } catch {}
                    _Add $rel 'PSSCP070' $sev Maintainability PSScriptAnalyzer $a.Line High "$($a.RuleName): $($a.Message)" 'Fix the rule finding or document why it is acceptable' $ev
                }
            } catch { _Add $rel 'PSSCP070' Warning Maintainability PSScriptAnalyzer 0 Medium 'PSScriptAnalyzer failed on this file' 'Check parser state and rerun analysis' $_.Exception.Message }
        } else { _Add $rel 'PSSCP070' Warning Maintainability PSScriptAnalyzer 0 High 'PSScriptAnalyzer is not installed' 'Install-Module PSScriptAnalyzer -Scope CurrentUser -Force, then rerun for best-practice analysis' }

        # Per-file summary.
        _Add $rel 'PSSCP000' Info Maintainability Inventory 0 Low "Inventory: commands=$(@($commands.Name | Sort-Object -Unique).Count), functions=$($functionNames.Count), params=$($paramAsts.Count), variables=$($variableNames.Count), types=$($typeAsts.Count)" 'Use this inventory to verify the script shape matches expectations'
        $fileFindings = @($Findings | Select-Object -Skip $startIndex)
        $critical = @($fileFindings | Where-Object Severity -eq 'Critical').Count
        $errors = @($fileFindings | Where-Object Severity -eq 'Error').Count
        $warnings = @($fileFindings | Where-Object Severity -eq 'Warning').Count
        $infos = @($fileFindings | Where-Object Severity -eq 'Info').Count
        $score = _Score $fileFindings
        $Summary.Add([pscustomobject]@{
            File=$rel;Score=$score;Rating=(_Rating $score);Critical=$critical;Errors=$errors;Warnings=$warnings;Info=$infos;Lines=($raw -split "`r?`n").Count;SizeKB=[Math]::Round($f.Length/1KB,1);
            SyntaxScore=(_ScoreCategory $fileFindings 'Syntax');SecurityScore=(_ScoreCategory $fileFindings 'Security');SafetyScore=(_ScoreCategory $fileFindings 'Safety');ReliabilityScore=(_ScoreCategory $fileFindings 'Reliability');OutputScore=(_ScoreCategory $fileFindings 'Output');DependencyScore=(_ScoreCategory $fileFindings 'Dependency');MaintainabilityScore=(_ScoreCategory $fileFindings 'Maintainability');CompatibilityScore=(_ScoreCategory $fileFindings 'Compatibility')
        }) | Out-Null
    }

    # -----------------------------
    # Self-test result sanity hints
    # -----------------------------
    if($SelfTest){
        $expected = @('PSSCP001','PSSCP030','PSSCP031','PSSCP040','PSSCP051')
        foreach($id in $expected){
            if(@($Findings | Where-Object Id -eq $id).Count -gt 0){ _Add '<PSSCP>' 'PSSCP900' Info Tool SelfTest 0 High "Self-test detected expected rule $id" 'No action required' }
            else { _Add '<PSSCP>' 'PSSCP900' Warning Tool SelfTest 0 Medium "Self-test did not detect expected rule $id" 'Review checker logic if this persists' }
        }
    }

    # -----------------------------
    # Context, grouped findings, reports, gate and output
    # -----------------------------
    $saStatus = if($SA){ "Enabled: $($SA.Version)" } else { 'Unavailable' }
    $Context = [pscustomobject]@{
        Tool=$ToolName;ToolVersion=$ToolVersion;Profile=$Profile;RunTime=(Get-Date).ToString('s');Root=$Root;FilesScanned=$Files.Count;ChangedOnly=$ChangedOnly;SelfTest=$SelfTest;ExecutedTargetScripts=$false;
        PowerShell="$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)";PSScriptAnalyzer=$saStatus;AutoInstallDependencies=$AutoInstallDeps;CrossParse=$CrossParse;WriteReports=$WriteReports;FailOn=$FailOn;MinScore=$MinScore;MaxFileMB=$MaxFileMB;KeepSelfTest=$KeepSelfTest
    }

    $GateFail = $false; $GateReasons = [Collections.Generic.List[string]]::new()
    if($FailOn -ne 'Never'){
        $order = @{ Critical=1; Error=2; Warning=3; Info=4 }
        $threshold = if($order.ContainsKey($FailOn)){ $order[$FailOn] } else { 99 }
        if(@($Findings | Where-Object { $order.ContainsKey($_.Severity) -and $order[$_.Severity] -le $threshold }).Count -gt 0){ $GateFail = $true; $GateReasons.Add("Findings at or above threshold: $FailOn") | Out-Null }
    }
    if($MinScore -gt 0 -and @($Summary | Where-Object Score -lt $MinScore).Count -gt 0){ $GateFail = $true; $GateReasons.Add("One or more files below minimum score: $MinScore") | Out-Null }

    Write-Host "`n=== $ToolName v$ToolVersion Static Analysis Context ===" -ForegroundColor Cyan
    $Context | Format-List * | Out-String -Width 32767 | Write-Host
    Write-Host "`n=== Static Validity Summary ===" -ForegroundColor Cyan
    $Summary | Sort-Object Score,File | Format-Table -AutoSize | Out-String -Width 32767 | Write-Host
    Write-Host "`n=== Grouped Finding Counts ===" -ForegroundColor Cyan
    if($Findings.Count){
        $Findings | Group-Object Id,Severity,Category,Area | Sort-Object Name | Select-Object Count,Name | Format-Table -AutoSize | Out-String -Width 32767 | Write-Host
    } else { Write-Host 'No findings.' -ForegroundColor Green }
    Write-Host "`n=== Recommendations / Findings - Full Detail ===" -ForegroundColor Cyan
    if($IncludeInfo){ $display = @($Findings) } else { $display = @($Findings | Where-Object Severity -ne 'Info') }
    if($display.Count){
        $display | Sort-Object File,@{Expression={_Rank $_.Severity}},Line,Id | Format-List Id,Title,Severity,Category,Area,Confidence,ScoreImpact,File,Line,Issue,Recommendation,Evidence | Out-String -Width 32767 | Write-Host
    } else { Write-Host 'No findings to display.' -ForegroundColor Green }
    Write-Host "`n=== AI / Engineer Remediation Prompt ===" -ForegroundColor Cyan
    Write-Host 'Fix Critical/Error/Warning findings first. Preserve intended functionality. Do not remove features merely to silence findings. Do not weaken safety controls. Explain any finding intentionally ignored. Use justified PSSCP suppression comments only where the risk is understood and accepted.'

    if($WriteReports){
        try {
            $jsonPath = Join-Path $Root 'PSSCP_Report.json'
            $mdPath = Join-Path $Root 'PSSCP_Report.md'
            $sarifPath = Join-Path $Root 'PSSCP_Report.sarif'
            $csvPath = Join-Path $Root 'PSSCP_Summary.csv'
            $promptPath = Join-Path $Root 'PSSCP_AI_RemediationPrompt.txt'
            [pscustomobject]@{ Context=$Context; Summary=$Summary; Findings=$Findings } | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            _WriteMarkdown $mdPath $Context @($Summary) @($Findings)
            _WriteSarif $sarifPath @($Findings) $Context
            $Summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            _WritePrompt $promptPath $Context @($Summary) @($Findings)
            Write-Host "`nReports written:" -ForegroundColor Cyan
            Write-Host $jsonPath; Write-Host $mdPath; Write-Host $sarifPath; Write-Host $csvPath; Write-Host $promptPath
        } catch { Write-Host "Report write failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    if($GateFail){
        Write-Host "`nPSSCP gate failed: $($GateReasons -join '; ')" -ForegroundColor Red
        $global:LASTEXITCODE = 1
        if($env:PSSCP_CI -eq '1'){ exit 1 }
    } else {
        Write-Host "`nPSSCP gate passed or gate disabled." -ForegroundColor Green
        $global:LASTEXITCODE = 0
    }
    Write-Host 'Static only. Scripts were not executed. This estimates static validity only; it cannot prove runtime permissions, API coverage, pagination, live data correctness, output completeness, or business efficacy.' -ForegroundColor Green
    if($SelfTest -and -not $KeepSelfTest -and -not $WriteReports){ try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
}
