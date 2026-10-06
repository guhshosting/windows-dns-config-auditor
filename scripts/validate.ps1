param([string]$Generator = 'Ninja')
$ErrorActionPreference = 'Stop'
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
# Run from an x64 MSVC developer shell. No local DNS settings are changed.
foreach ($configuration in @('Debug','Release')) {
    $buildPath = 'build-' + $configuration.ToLowerInvariant()
    Invoke-Checked -Program cmake -Arguments @('-S','.', '-B',$buildPath,'-G',$Generator,"-DCMAKE_BUILD_TYPE=$configuration",'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    Invoke-Checked -Program cmake -Arguments @('--build',$buildPath)
    Invoke-Checked -Program ctest -Arguments @('--test-dir',$buildPath,'--output-on-failure')
}
Invoke-Checked -Program node -Arguments @('scripts/validate-json.js','build-release')
Invoke-Checked -Program cmake -Arguments @('--install','build-release','--prefix','install')
Write-Output 'Basic validation passed. See VALIDATION.md for static analysis, ASan, token and packet checks.'

