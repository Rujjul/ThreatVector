param([switch]$WithRetrieval)
$ErrorActionPreference = 'Stop'
$repositoryPath = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repositoryPath
try {
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
    }
    $pythonPath = Join-Path $repositoryPath '.venv/Scripts/python.exe'
    & $pythonPath -c "import sys; assert sys.version_info[:2] == (3, 10), 'Use Python 3.10 for the pinned retrieval stack.'"
    if ($LASTEXITCODE -ne 0) { throw 'The pinned setup requires Python 3.10.' }
    node -e "const [major,minor]=process.versions.node.split('.').map(Number); if (major<22 || (major===22 && minor<12)) process.exit(1)"
    if ($LASTEXITCODE -ne 0) { throw 'Use Node 22.12 or later.' }
    & $pythonPath -m pip install -r backend/requirements-dev.lock
    if ($LASTEXITCODE -ne 0) { throw 'Backend installation failed.' }
    if ($WithRetrieval) {
        & $pythonPath -m pip install torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
        if ($LASTEXITCODE -ne 0) { throw 'CPU Torch installation failed.' }
        & $pythonPath -m pip install -r backend/requirements-index.lock
        if ($LASTEXITCODE -ne 0) { throw 'Retrieval installation failed.' }
    }
    & $pythonPath -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed.' }
    Push-Location -LiteralPath (Join-Path $repositoryPath 'frontend')
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend installation failed.' }
    } finally { Pop-Location }
} finally { Pop-Location }
