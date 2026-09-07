# Invoked in Windows PowerShell 5.1 using an encoded command, without changing execution policy.
# $Module and $Phase are set by the host. No external tools or network requests.
$ErrorActionPreference='Stop'
function Emit($kind,$data) {
  [pscustomobject]@{ Kind=$kind; Phase=$Phase; Utc=[DateTime]::UtcNow.ToString('o'); Data=$data } | ConvertTo-Json -Depth 12 -Compress
}
function Section($name,[scriptblock]$body) {
  $begin=[DateTime]::UtcNow
  try {
    $n=0
    & $body | ForEach-Object { Emit $name $_; $n++ }
    Emit 'module-status' ([pscustomobject]@{Module=$name; Status=$(if($n){'success'}else{'success-empty'}); Records=$n; StartUtc=$begin.ToString('o'); EndUtc=[DateTime]::UtcNow.ToString('o')})
  } catch {
    Emit 'module-status' ([pscustomobject]@{Module=$name; Status=$(if($_.CategoryInfo.Category -eq 'PermissionDenied'){'access-denied'}else{'error'}); StartUtc=$begin.ToString('o'); EndUtc=[DateTime]::UtcNow.ToString('o'); Error=$_.Exception.Message; ErrorId=$_.FullyQualifiedErrorId})
  }
}
switch($Module) {
'system' {
 Section 'os-clock' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,LocalDateTime,CurrentTimeZone; Get-TimeZone | Select-Object Id,BaseUtcOffset,SupportsDaylightSavingTime }
 Section 'services' { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId }
 Section 'drivers' { Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName,ServiceType }
}
'network' {
 Section 'adapters' { Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceIndex,Status,LinkSpeed,MacAddress,Virtual,HardwareInterface }
 Section 'addresses' { Get-NetIPAddress | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,AddressFamily,PrefixLength,AddressState,PrefixOrigin }
 Section 'dns-servers' { Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses }
 Section 'dns-cache' { Get-DnsClientCache | Select-Object Entry,Name,Data,Type,Status,TimeToLive }
 Section 'routes' { Get-NetRoute | Select-Object InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,Protocol,State,AddressFamily }
 Section 'proxy-pac' { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL,AutoDetect }
 Section 'winhttp-proxy' { $v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'; [pscustomobject]@{WinHttpSettings=$v.WinHttpSettings} }
}
'hosts' {
 Section 'hosts' { $path=[IO.Path]::Combine($env:SystemRoot,'System32\drivers\etc\hosts'); $f=[IO.FileInfo]::new($path); if($f.Length -gt 1048576){throw 'hosts exceeds 1 MiB limit'}; [pscustomobject]@{Path=$path; Content=[IO.File]::ReadAllText($path)} }
}
'firewall' {
 Section 'firewall-profiles' { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName }
 Section 'firewall-rules' { Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile,PolicyStoreSourceType }
 Section 'firewall-port-filters' { Get-NetFirewallPortFilter | Select-Object InstanceID,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget }
 Section 'firewall-app-filters' { Get-NetFirewallApplicationFilter | Select-Object InstanceID,Program,Package }
}
'persistence' {
 Section 'tasks-including-disabled' { Get-ScheduledTask | ForEach-Object { [pscustomobject]@{TaskPath=$_.TaskPath;TaskName=$_.TaskName;State=[string]$_.State;Actions=$_.Actions|Select-Object Execute,Arguments,WorkingDirectory;Xml=Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath} } }
 Section 'wmi-filters' { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name,Query,QueryLanguage,EventNamespace }
 Section 'wmi-command-consumers' { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Select-Object Name,ExecutablePath,CommandLineTemplate,RunInteractively }
 Section 'wmi-script-consumers' { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | Select-Object Name,ScriptingEngine,ScriptFileName,ScriptText }
 Section 'wmi-bindings' { Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Select-Object Filter,Consumer }
 Section 'bits-all-users' { Get-BitsTransfer -AllUsers | Select-Object JobId,DisplayName,JobState,OwnerAccount,CreationTime,ModificationTime,TransferType,FilesTotal,FilesTransferred }
}
'registry' {
 foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
  $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
  foreach($key in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit')) {
   Section "registry-$view-$key" {
    $k=$base.OpenSubKey($key)
    if($k){try {
     foreach($n in $k.GetValueNames()){ if($n -notmatch '(?i)password|credential|token|secret'){[pscustomobject]@{Hive='HKLM';View=[string]$view;Key=$key;Name=$n;Value=$k.GetValue($n)}} }
     foreach($child in $k.GetSubKeyNames()){ $sub=$k.OpenSubKey($child); try {foreach($n in $sub.GetValueNames()){if($n -in @('Debugger','GlobalFlag','ReportingMode','MonitorProcess')){[pscustomobject]@{Hive='HKLM';View=[string]$view;Key="$key\$child";Name=$n;Value=$sub.GetValue($n)}}}} finally {$sub.Dispose()} }
    } finally {$k.Dispose()}}
   }
  }
  $base.Dispose()
  $users=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,$view)
  foreach($sid in $users.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-\d+(?:-\d+)+$'}) {
   foreach($suffix in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\Internet Settings')) {
    Section "user-registry-$view-$sid-$suffix" {
     $k=$users.OpenSubKey("$sid\$suffix"); if($k){try {foreach($n in $k.GetValueNames()){if($suffix -notlike '*Internet Settings' -or $n -in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect')){[pscustomobject]@{Sid=$sid;View=[string]$view;Key=$suffix;Name=$n;Value=$k.GetValue($n)}}}}finally{$k.Dispose()}}
    }
   }
  }
  $users.Dispose()
 }
 Section 'profile-coverage' { Get-CimInstance Win32_UserProfile | Select-Object SID,LocalPath,Loaded,Special,LastUseTime }
}
'accounts' {
 Section 'local-users' { Get-LocalUser | Select-Object Name,SID,Enabled,LastLogon,PasswordLastSet,PrincipalSource }
 Section 'local-groups' { Get-LocalGroup | ForEach-Object { $g=$_; [pscustomobject]@{Name=$g.Name;SID=[string]$g.SID;Kind='group'}; try {Get-LocalGroupMember -SID $g.SID | ForEach-Object {[pscustomobject]@{GroupSid=[string]$g.SID;Name=$_.Name;SID=[string]$_.SID;ObjectClass=$_.ObjectClass;PrincipalSource=$_.PrincipalSource}}}catch{[pscustomobject]@{GroupSid=[string]$g.SID;Error=$_.Exception.Message;Status='partial'}}} }
 Section 'logon-sessions' { Get-CimInstance Win32_LogonSession | Select-Object LogonId,LogonType,StartTime,AuthenticationPackage }
 Section 'logged-on-users' { Get-CimInstance Win32_LoggedOnUser | Select-Object Antecedent,Dependent }
}
'security' {
 Section 'defender-status' { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureVersion }
 Section 'defender-detections' { Get-MpThreatDetection | Select-Object DetectionID,ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,ProcessName,Resources,CurrentThreatExecutionStatusID }
 Section 'defender-exclusions' { Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress,DisableRealtimeMonitoring }
 Section 'remote-management' { Get-CimInstance Win32_Service | Where-Object {$_.Name -match 'TeamViewer|AnyDesk|ScreenConnect|RustDesk|Splashtop|VNC|LogMeIn|WinRM|TermService' -or $_.PathName -match 'TeamViewer|AnyDesk|ScreenConnect|RustDesk|Splashtop|VNC|LogMeIn'} | Select-Object Name,State,StartMode,PathName }
}
'browser' {
 foreach($root in @('HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Microsoft\Edge','HKLM:\SOFTWARE\Policies\Mozilla\Firefox','HKCU:\SOFTWARE\Policies\Google\Chrome','HKCU:\SOFTWARE\Policies\Microsoft\Edge','HKCU:\SOFTWARE\Policies\Mozilla\Firefox')) {
  Section "browser-policy-$root" { if(Test-Path $root){ $keys=@(Get-Item $root)+@(Get-ChildItem $root -Recurse); foreach($k in $keys){foreach($n in $k.GetValueNames()){[pscustomobject]@{Key=$k.Name;Name=$n;Value=$k.GetValue($n)}}} } }
 }
 Section 'browser-extensions' {
  foreach($profile in Get-CimInstance Win32_UserProfile | Where-Object {-not $_.Special}) {
   foreach($browser in @('Google\Chrome','Microsoft\Edge','BraveSoftware\Brave-Browser')) {
    $root=Join-Path $profile.LocalPath "AppData\Local\$browser\User Data"
    if(Test-Path -LiteralPath $root){
     foreach($dir in Get-ChildItem -LiteralPath $root -Directory | Where-Object {$_.Name -eq 'Default' -or $_.Name -like 'Profile *'}) {
      $ext=Join-Path $dir.FullName 'Extensions'
      if(Test-Path -LiteralPath $ext){ foreach($id in Get-ChildItem -LiteralPath $ext -Directory | Select-Object -First 100){foreach($ver in Get-ChildItem -LiteralPath $id.FullName -Directory | Select-Object -First 3){$mf=Join-Path $ver.FullName 'manifest.json';if(Test-Path -LiteralPath $mf){$f=Get-Item -LiteralPath $mf;if($f.Length -lt 1048576){$j=Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json;[pscustomobject]@{Sid=$profile.SID;Browser=$browser;Profile=$dir.Name;Id=$id.Name;Version=$j.version;Name=$j.name;Permissions=$j.permissions;HostPermissions=$j.host_permissions;Path=$mf;Coverage='100 IDs / 3 versions per profile cap; localized names unresolved'}}}}} }
     }
    }
   }
   $ff=Join-Path $profile.LocalPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
   if(Test-Path -LiteralPath $ff){foreach($dir in Get-ChildItem -LiteralPath $ff -Directory){$f=Join-Path $dir.FullName 'extensions.json';if((Test-Path -LiteralPath $f) -and (Get-Item -LiteralPath $f).Length -lt 4194304){(Get-Content -LiteralPath $f -Raw|ConvertFrom-Json).addons|Select-Object id,version,active,type,path,location}}}
  }
 }
}
'files' {
 Section 'startup-files' {
  $paths=@([Environment]::GetFolderPath('CommonStartup'))
  foreach($p in Get-CimInstance Win32_UserProfile | Where-Object {-not $_.Special}){$paths+=Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'}
  foreach($p in $paths){if(Test-Path -LiteralPath $p){Get-ChildItem -LiteralPath $p -File | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Attributes}}
 }
 Section 'recent-files-bounded' {
  foreach($p in Get-CimInstance Win32_UserProfile | Where-Object {-not $_.Special}){
   foreach($sub in @('Downloads','AppData\Local\Temp','AppData\Roaming','AppData\Local')){
    $dir=Join-Path $p.LocalPath $sub
    if(Test-Path -LiteralPath $dir){Get-ChildItem -LiteralPath $dir -File | Where-Object {$_.LastWriteTimeUtc -gt [DateTime]::UtcNow.AddDays(-7)} | Select-Object -First 200 | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Attributes,@{n='Scope';e={'Top-level only; 7 days; max 200 per directory; no content'}}}
   }
  }
 }
}
'artifacts' {
 Section 'historical-artifact-metadata' {
  foreach($path in @("$env:SystemRoot\Prefetch","$env:SystemRoot\AppCompat\Programs\Amcache.hve","$env:SystemRoot\System32\sru\SRUDB.dat")){
   if(Test-Path -LiteralPath $path){$i=Get-Item -LiteralPath $path;if($i.PSIsContainer){Get-ChildItem -LiteralPath $path -File|Select-Object -First 500|Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc}else{$i|Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc}}
  }
  foreach($p in Get-CimInstance Win32_UserProfile | Where-Object {-not $_.Special}){
   foreach($sub in @('AppData\Roaming\Microsoft\Windows\Recent','AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations','AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')){
    $dir=Join-Path $p.LocalPath $sub;if(Test-Path -LiteralPath $dir){Get-ChildItem -LiteralPath $dir -File|Select-Object -First 200|Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc}
   }
  }
 }
}
}
