param([string]$Destination)
$ErrorActionPreference='Stop'
if(-not $Destination){$Destination=Join-Path $PSScriptRoot 'dist\win-x64'}
dotnet publish (Join-Path $PSScriptRoot 'src\RazeWatch\RazeWatch.csproj') -c Release -r win-x64 --self-contained true -o $Destination
if($LASTEXITCODE -ne 0){throw 'Publish failed'}
foreach($name in @('README.md','CHECKPOINT.md')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $Destination}
foreach($name in @('licenses','docs','sample-report-v0.2')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $Destination -Recurse -Force}
Write-Output 'Self-contained win-x64 build and notices copied. Run --self-test before distribution.'
