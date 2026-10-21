$ErrorActionPreference = 'Stop'
$repositoryPath = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repositoryPath
try {
    $pythonPath = Join-Path $repositoryPath '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Run scripts/setup.ps1 first.' }
    & $pythonPath -c "import faiss; from importlib.metadata import version; [version(p) for p in ('torch','sentence-transformers','transformers')]; print('Full retrieval test dependencies are installed.')"
    if ($LASTEXITCODE -ne 0) { throw 'Full checks require setup.ps1 -WithRetrieval; do not treat skipped native checks as full verification.' }
    & $pythonPath -m pytest --basetemp=data/test-temp-delivery
    if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
    & $pythonPath -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency check failed.' }
    & $pythonPath -m compileall -q backend
    if ($LASTEXITCODE -ne 0) { throw 'Backend compilation failed.' }
    Push-Location -LiteralPath (Join-Path $repositoryPath 'frontend')
    try {
        npm test
        if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw 'Whitespace check failed.' }
} finally { Pop-Location }
