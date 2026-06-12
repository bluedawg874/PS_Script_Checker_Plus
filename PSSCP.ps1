&{
$sa=!!(Get-Module -ListAvailable PSScriptAnalyzer -EA 0|Select -First 1);if($sa){Import-Module PSScriptAnalyzer -EA 0}
$A=[Collections.Generic.List[object]]::new();$S=[Collections.Generic.List[object]]::new();$C=@{}
function _A($f,$s,$a,$n,$m,$r,$x=''){$A.Add([pscustomobject]@{File=$f;Severity=$s;Area=$a;Line=$n;Issue=$m;Recommendation=$r;Evidence=(($x-replace'\s+',' ').Trim())})|Out-Null}
function _R($s){switch($s){{$_-ge90}{'High'}{$_-ge75}{'Good'}{$_-ge50}{'Moderate'}{$_-ge25}{'Low'}default{'Very low'}}}
$F=@(Get-ChildItem . -Recurse -File -EA 0|Where {$_.Extension -in '.ps1','.psm1','.psd1' -and $_.FullName -notmatch '\\(\.git|bin|obj|node_modules|packages|\.terraform)\\'})
if(!$F){Write-Host "No PowerShell files found." -ForegroundColor Yellow;return}
foreach($f in $F){
$r=Resolve-Path $f.FullName -Relative;$b=$A.Count
try{$raw=Get-Content $f.FullName -Raw -EA Stop}catch{_A $r Critical Read 0 "File could not be read" "Fix file access/encoding/path before review" $_.Exception.Message;continue}
$t=$null;$e=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e)
$e|ForEach{_A $r Critical Parser $_.Extent.StartLineNumber $_.Message "Fix syntax before attempting to run the script" $_.Extent.Text}
$ca=@($ast.FindAll({param($n)$n -is [System.Management.Automation.Language.CommandAst]},$true))
$cm=@($ca|ForEach{[pscustomobject]@{C=$_.GetCommandName();L=$_.Extent.StartLineNumber;T=$_.Extent.Text}}|Where C)
$dy=@($ca|Where{-not $_.GetCommandName()})
$fn=@($ast.FindAll({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)|ForEach Name|Sort -Unique)
$pa=@($ast.FindAll({param($n)$n -is [System.Management.Automation.Language.ParameterAst]},$true))
$va=@($ast.FindAll({param($n)$n -is [System.Management.Automation.Language.VariableExpressionAst]},$true)|ForEach{$_.VariablePath.UserPath}|Sort -Unique)
$req=$ast.ScriptRequirements
if($req.RequiredPSVersion -and $PSVersionTable.PSVersion -lt $req.RequiredPSVersion){_A $r Critical Requires 0 "Script requires PowerShell $($req.RequiredPSVersion); current is $($PSVersionTable.PSVersion)" "Run in the required PowerShell version or lower the requirement only if compatible"}
foreach($rm in @($req.RequiredModules)){$mn=if($rm.Name){$rm.Name}else{[string]$rm};if($mn -and !(Get-Module -ListAvailable $mn -EA 0)){_A $r Error Requires 0 "Required module missing: $mn" "Install/import the module or add dependency bootstrapping"}}
foreach($d in $dy){_A $r Warning Dependency $d.Extent.StartLineNumber "Dynamic command cannot be statically resolved" "Manually verify the invoked command/path before running" $d.Extent.Text}
foreach($c in @($cm.C|Sort -Unique)){if($fn -contains $c){continue};if(!$C.ContainsKey($c)){$C[$c]=Get-Command $c -EA 0};$g=$C[$c];if(!$g){_A $r Warning Dependency 0 "Command missing, dynamic, external, or not currently loaded: $c" "Verify module/import/path/function definition before running"}elseif($g.CommandType -eq 'Alias'){_A $r Warning Alias 0 "Alias used: $c -> $($g.ResolvedCommandName)" "Replace aliases with full command names for reliability"}}
$cm|Where{$_.C -match '^(Remove|Set|New|Clear|Disable|Enable|Update|Start|Stop|Restart|Invoke|Add|Grant|Revoke|Disconnect|Connect|Register|Unregister)-' -or $_.C -in @('Invoke-Expression','iex','cmd','cmd.exe','powershell','powershell.exe','pwsh','pwsh.exe','Start-Process')}|ForEach{_A $r Warning Risk $_.L "High-impact or external command: $($_.C)" "Manually review intent, scope, error handling, and rollback/safety controls" $_.T}
if(($cm.C -match '^(Remove|Set|New|Clear|Disable|Enable|Update|Add|Grant|Revoke|Register|Unregister)-') -and !($raw -match 'SupportsShouldProcess' -and $raw -match '\$PSCmdlet\.ShouldProcess|ShouldProcess\s*\(')){_A $r Warning Safety 0 "Change commands found without clear full ShouldProcess/WhatIf pattern" "Add CmdletBinding(SupportsShouldProcess) and wrap changes in ShouldProcess"}
$p=@(
@('Critical','Security','Invoke-Expression|\biex\b','Invoke-Expression/iex detected','Avoid string execution; use direct command invocation or validated script blocks'),
@('Warning','Security','(?i)(password|secret|token|apikey|clientsecret)\s*=','Possible secret/token assignment','Avoid hardcoded secrets; use secure input, vault, or environment-specific secret handling'),
@('Warning','Errors','SilentlyContinue','Silent error handling detected','Avoid hiding failures unless explicitly justified and logged'),
@('Warning','Errors','catch\s*\{\s*\}','Empty catch block detected','Handle, log, or rethrow the exception'),
@('Info','Network','https?://','URL detected','Verify URL trust, version pinning, and download/remote execution behaviour'),
@('Info','Marker','TODO|FIXME|HACK|TEMP','Marker detected','Resolve or confirm before production use')
)
foreach($i in $p){[regex]::Matches($raw,$i[2],'IgnoreCase')|ForEach{$ln=($raw.Substring(0,$_.Index)-split"`r?`n").Count;_A $r $i[0] $i[1] $ln $i[3] $i[4] $_.Value}}
_A $r Info Inventory 0 "Commands: $((@($cm.C|Sort -Unique))-join', ')" "Review command inventory for unexpected calls"
if($fn){_A $r Info Inventory 0 "Functions: $($fn-join', ')" "Review function structure and naming"}
if($pa){_A $r Info Inventory 0 "Parameters: $((@($pa.Name.VariablePath.UserPath|Sort -Unique))-join', ')" "Review required inputs, defaults, and validation"}
if($sa){try{Invoke-ScriptAnalyzer $f.FullName -Severity Error,Warning,Information|ForEach{$sv=if($_.Severity-eq'Error'){'Error'}elseif($_.Severity-eq'Warning'){'Warning'}else{'Info'};_A $r $sv PSScriptAnalyzer $_.Line "$($_.RuleName): $($_.Message)" "Fix the rule finding or document why it is acceptable" $_.Extent.Text}}catch{_A $r Warning PSScriptAnalyzer 0 "PSScriptAnalyzer failed" "Check the script/parser state and rerun analysis" $_.Exception.Message}}else{_A $r Info PSScriptAnalyzer 0 "PSScriptAnalyzer not installed" "Optional but recommended: Install-Module PSScriptAnalyzer -Scope CurrentUser -Force"}
$d=@($A|Select-Object -Skip $b);$cr=@($d|Where Severity -eq Critical).Count;$er=@($d|Where Severity -eq Error).Count;$w=@($d|Where Severity -eq Warning).Count;$in=@($d|Where Severity -eq Info).Count;$sc=[math]::Max(0,100-($cr*30)-($er*15)-($w*5))
$S.Add([pscustomobject]@{File=$r;Score=$sc;Rating=_R $sc;Critical=$cr;Errors=$er;Warnings=$w;Info=$in;Lines=($raw-split"`r?`n").Count;Commands=@($cm.C|Sort -Unique).Count;Functions=$fn.Count;Params=$pa.Count;Variables=$va.Count})|Out-Null
}
Write-Host "`n=== Static Validity Summary ===" -ForegroundColor Cyan
$S|Sort Score,File|Format-Table -AutoSize|Out-String -Width 8192|Write-Host
Write-Host "`n=== Recommendations / Findings ===" -ForegroundColor Cyan
if($A.Count){$A|Sort File,@{e={switch($_.Severity){Critical{0}Error{1}Warning{2}Info{3}default{4}}}},Line|Format-Table -AutoSize File,Severity,Area,Line,Issue,Recommendation,Evidence|Out-String -Width 8192|Write-Host}else{Write-Host "No findings." -ForegroundColor Green}
Write-Host "`nStatic only. Scripts were not executed." -ForegroundColor Green
}
