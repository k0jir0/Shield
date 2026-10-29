param(
    [Parameter(Mandatory = $true)]
    [string]$ReportDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Cargo {
    param([string[]]$CargoArguments)
    & rustup run $script:Toolchain cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo command failed: $($CargoArguments -join ' ')"
    }
}

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Push-Location -LiteralPath $root
try {
    $text = Get-Content -LiteralPath 'rust-toolchain.toml' -Raw
    $match = [regex]::Match($text, '(?m)^channel\s*=\s*"([^"]+)"\s*$')
    if (-not $match.Success) { throw 'Pinned toolchain channel is missing' }
    $script:Toolchain = $match.Groups[1].Value
    & rustup run $script:Toolchain rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw 'Pre-provision the pinned Rust/MSVC toolchain on the authorized disposable runner'
    }
    Invoke-Cargo -CargoArguments @('build', '--locked')
    $debug = Join-Path $root 'target\debug\shield.exe'
    $doctor = & $debug doctor
    if ($LASTEXITCODE -ne 0) { throw 'Native environment inventory failed' }
    $environment = ($doctor -join [Environment]::NewLine) | ConvertFrom-Json
    if ($environment.elevated -ne $false) {
        throw 'Native tests require a non-elevated process; do not bypass the runtime elevation guard'
    }
    if (-not [System.IO.Path]::IsPathRooted($ReportDirectory)) {
        throw 'Report directory must be an absolute path'
    }
    if (Test-Path -LiteralPath $ReportDirectory) {
        throw 'Refusing to overwrite an existing report directory'
    }
    New-Item -ItemType Directory -Path $ReportDirectory | Out-Null
    Invoke-Cargo -CargoArguments @('test', '--locked', '--all-targets')
    Invoke-Cargo -CargoArguments @('build', '--release', '--locked')
    Invoke-Cargo -CargoArguments @('test', '--release', '--locked', '--all-targets')
    foreach ($configuration in @('debug', 'release')) {
        $image = Join-Path $root "target\$configuration\shield.exe"
        $report = Join-Path $ReportDirectory "$configuration.json"
        & $image selftest --report $report
        if ($LASTEXITCODE -ne 0) { throw "$configuration native canaries failed" }
        $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        $hash = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($result.binary_sha256 -cne $hash -or
            $result.all_passed -ne $true -or
            @($result.observations).Count -ne 8 -or
            @($result.observations | Where-Object { $_.passed -ne $true }).Count -ne 0) {
            throw "$configuration report does not bind eight passing scoped observations to the exact executable"
        }
    }
    Write-Output "Software checks passed; scoped reports retained at $ReportDirectory. No integrated protection gate is certified."
} finally {
    Pop-Location
}
