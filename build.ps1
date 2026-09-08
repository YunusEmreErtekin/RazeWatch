param([string]$Destination)
$ErrorActionPreference='Stop'
if(-not $Destination){$Destination=Join-Path $PSScriptRoot 'dist\win-x64'}
dotnet publish (Join-Path $PSScriptRoot 'src\RazeWatch\RazeWatch.csproj') -c Release -r win-x64 --self-contained true -o $Destination
if($LASTEXITCODE -ne 0){throw 'Publish failed'}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $Destination
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'licenses') -Destination $Destination -Recurse -Force
Write-Output 'Self-contained win-x64 build and notices copied. Run --self-test before distribution.'
