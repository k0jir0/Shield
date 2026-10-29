$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows') {
    throw 'Account provisioning is restricted to a disposable GitHub-hosted Windows VM'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted VM setup step requires its administrator token'
}

$name = 'ShieldCI'
$profile = Join-Path $env:SystemDrive "Users\$name"
if ((Get-LocalUser -Name $name -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $profile)) {
    throw 'Refusing to reuse an existing test identity or profile'
}
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$work = Join-Path $env:RUNNER_TEMP ("Shield-standard-user-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$random = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($random) } finally { $rng.Dispose() }
$password = ConvertTo-SecureString ([Convert]::ToBase64String($random) + 'Aa1!') -AsPlainText -Force
$user = New-LocalUser -Name $name -Password $password -AccountNeverExpires -PasswordNeverExpires
$saved = @{}
$variables = @('RUSTUP_HOME', 'CARGO_HOME', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'USERNAME', 'USERDOMAIN', 'HOMEDRIVE', 'HOMEPATH')
foreach ($key in $variables) { $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
try {
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    $sid = '*' + $user.SID.Value
    $rustup = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE '.rustup' }
    $cargoBin = Split-Path -Parent (Get-Command rustup -ErrorAction Stop).Source
    foreach ($path in @($root, $work)) {
        & icacls $path /grant "${sid}:(OI)(CI)M" /T /Q
        if ($LASTEXITCODE -ne 0) { throw 'Unable to grant the test identity access to its workspace' }
    }
    foreach ($path in @($rustup, $cargoBin)) {
        & icacls $path /grant "${sid}:(OI)(CI)RX" /T /Q
        if ($LASTEXITCODE -ne 0) { throw 'Unable to grant read/execute access to the installed toolchain' }
    }
    foreach ($directory in @('cargo', 'temp')) {
        New-Item -ItemType Directory -Path (Join-Path $work $directory) | Out-Null
    }
    $env:RUSTUP_HOME = $rustup
    $env:CARGO_HOME = Join-Path $work 'cargo'
    $env:TEMP = Join-Path $work 'temp'
    $env:TMP = $env:TEMP
    $env:USERPROFILE = $profile
    $env:APPDATA = Join-Path $profile 'AppData\Roaming'
    $env:LOCALAPPDATA = Join-Path $profile 'AppData\Local'
    $env:USERNAME = $name
    $env:USERDOMAIN = $env:COMPUTERNAME
    $env:HOMEDRIVE = $env:SystemDrive
    $env:HOMEPATH = "\Users\$name"
    $credential = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$name", $password)
    $script = Join-Path $PSScriptRoot 'native-tests.ps1'
    $report = Join-Path $work 'reports'
    $stdout = Join-Path $work 'stdout.log'
    $stderr = Join-Path $work 'stderr.log'
    $arguments = '-NoLogo -NoProfile -File "{0}" -ReportDirectory "{1}"' -f $script, $report
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -Credential $credential -LoadUserProfile -WorkingDirectory $root -ArgumentList $arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
    Get-Content -LiteralPath $stdout
    Get-Content -LiteralPath $stderr
    if ($process.ExitCode -ne 0) { throw "Non-elevated native checks failed: exit $($process.ExitCode)" }
} finally {
    foreach ($key in $variables) { [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process') }
    Remove-LocalUser -SID $user.SID
}
