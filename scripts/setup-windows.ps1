param(
    [string]$Python = "python",
    [switch]$Dev
)
$ErrorActionPreference = "Stop"
$solomonRoot = Split-Path -Parent $PSScriptRoot
$solomonPython = Join-Path $solomonRoot ".venv\Scripts\python.exe"
Push-Location -LiteralPath $solomonRoot
try {
    if (-not (Test-Path -LiteralPath $solomonPython)) {
        if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
            throw "Instale Python 3.12 ou superior (gratuito) e execute novamente."
        }
        & $Python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 2)"
        if ($LASTEXITCODE -ne 0) { throw "Solomon requer Python 3.12 ou superior." }
        & $Python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Falha ao criar ambiente Python local." }
    }
    $env:PYTHONUTF8 = "1"
    $solomonPackage = if ($Dev) { ".[dev]" } else { "." }
    & $solomonPython -m pip install -e $solomonPackage
    if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependencias gratuitas do projeto." }
    & $solomonPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Dependencias inconsistentes no ambiente local." }
    & $solomonPython -m solomon status
    if ($LASTEXITCODE -ne 0) { throw "Falha na verificacao do Solomon." }
    Write-Host "Pronto. Abra .\solomon.cmd ou execute .\solomon.cmd demo"
} finally {
    Pop-Location
}
