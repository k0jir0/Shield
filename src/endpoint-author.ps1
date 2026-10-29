$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$WarningPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$inputText = [Console]::In.ReadToEnd()
if ($inputText.Length -gt 65536) { throw 'Endpoint authoring input exceeds its bound.' }
$request = ConvertFrom-Json -InputObject $inputText
$systemDirectory = [Environment]::SystemDirectory
$module = Join-Path $systemDirectory 'WindowsPowerShell\v1.0\Modules\ConfigCI\ConfigCI.psd1'
$baseline = Join-Path ([System.IO.Directory]::GetParent($systemDirectory).FullName) 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml'
Import-Module -Name $module -Force -ErrorAction Stop
$rules = @()
foreach ($application in $request.applications) {
    $rules += @(New-CIPolicyRule -DriverFilePath $application -Level Hash -ErrorAction Stop)
}
$rules += @(New-CIPolicyRule -DriverFilePath $PSCommandPath -Level Hash -ErrorAction Stop)
if ($rules.Count -eq 0) { throw 'No native file-hash rules were generated.' }
$hashPolicy = Join-Path $request.directory 'applications.xml'
$policy = Join-Path $request.directory 'policy.xml'
New-CIPolicy -FilePath $hashPolicy -Rules $rules -UserPEs -MultiplePolicyFormat -ErrorAction Stop | Out-Null
Merge-CIPolicy -PolicyPaths @($baseline, $hashPolicy) -OutputFilePath $policy -ErrorAction Stop | Out-Null
Set-CIPolicyIdInfo -FilePath $policy -ResetPolicyID -PolicyName $request.name -ErrorAction Stop | Out-Null
Set-CIPolicyVersion -FilePath $policy -Version $request.version -ErrorAction Stop | Out-Null
Set-RuleOption -FilePath $policy -Option 0 -ErrorAction Stop | Out-Null
Set-RuleOption -FilePath $policy -Option 6 -ErrorAction Stop | Out-Null
Set-RuleOption -FilePath $policy -Option 16 -ErrorAction Stop | Out-Null

function Read-Policy([string] $path) {
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($path, $settings)
    try {
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        return ,$document
    } finally { $reader.Dispose() }
}

$disabledOptions = @{
    3 = 'Enabled:Audit Mode'
    10 = 'Enabled:Boot Audit On Failure'
    11 = 'Disabled:Script Enforcement'
    13 = 'Enabled:Managed Installer'
    14 = 'Enabled:Intelligent Security Graph Authorization'
    17 = 'Enabled:Allow Supplemental Policies'
    18 = 'Disabled:Runtime FilePath Rule Protection'
    21 = 'Enabled:Developer Mode Dynamic Code Trust'
}
foreach ($number in $disabledOptions.Keys) {
    $document = Read-Policy $policy
    $options = @($document.SiPolicy.Rules.Rule | ForEach-Object { [string]$_.Option })
    if ($options -contains $disabledOptions[$number]) {
        Set-RuleOption -FilePath $policy -Option $number -Delete -ErrorAction Stop | Out-Null
    }
}
$document = Read-Policy $policy
$document.SiPolicy.PolicyID = $request.policy_id
$document.SiPolicy.BasePolicyID = $request.policy_id
$document.SiPolicy.SetAttribute('PolicyType', 'Base Policy')
$document.Save($policy)
$options = @($document.SiPolicy.Rules.Rule | ForEach-Object { [string]$_.Option })
foreach ($required in @('Enabled:UMCI', 'Enabled:Unsigned System Integrity Policy', 'Enabled:Update Policy No Reboot')) {
    if ($options -notcontains $required) { throw 'A required endpoint enforcement option is absent.' }
}
foreach ($disabled in $disabledOptions.Values) {
    if ($options -contains $disabled) { throw 'An unsupported policy-expansion or audit option remains.' }
}
if (@($document.SiPolicy.SigningScenarios.SigningScenario | Where-Object { $_.Value -eq '12' }).Count -ne 1) {
    throw 'The policy does not contain exactly one user-mode signing scenario.'
}
ConvertFrom-CIPolicy -XmlFilePath $policy -BinaryFilePath (Join-Path $request.directory 'policy.cip') -ErrorAction Stop | Out-Null
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject @{
    policy_id = [string]$document.SiPolicy.PolicyID
    base_policy_id = [string]$document.SiPolicy.BasePolicyID
    version = [string]$document.SiPolicy.VersionEx
    options = $options
}))
