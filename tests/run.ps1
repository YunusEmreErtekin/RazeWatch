param([switch]$RestrictedAccess,[switch]$Gui)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
dotnet build (Join-Path $root 'src\RazeWatch\RazeWatch.csproj') -c Release
if($LASTEXITCODE -ne 0){throw 'Build failed'}
$exe=Join-Path $root 'src\RazeWatch\bin\Release\net8.0-windows\win-x64\RazeWatch.exe'
$testArgs=@('--self-test')
if($RestrictedAccess){$testArgs+='--restricted-test'}
if($Gui){$testArgs+=@('--ui-test',(Join-Path $env:TEMP ('RazeWatch-ui-'+[guid]::NewGuid().ToString('N'))))}
& $exe @testArgs
if($LASTEXITCODE -ne 0){throw 'Test failed'}
