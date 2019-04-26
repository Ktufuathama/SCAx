<#
  Asset
    Edit
    Validate
  Queries
    Run
    Edit
  Policy
    Enumerate Policy Id
    Import for big changes
    Export for documentation
    Edit for small changes
    Compare <-> BPG with proof
  Scans
    Monitor either continually or on demand
      Hook to email for start/status info?
    Run scans
    Stop scans
    Import for big changes
    Export for documentation
    Edit for small changes
    Compare <-> BPG with proof
  Report
    Monitor either continually or on demand
      Hook to email for start/status info?
    Run report
    Stop report
    Import for big changes
    Export for monthly scans
    Edit for small changes
    Compare <-> BPG with proof
  Tasks
    Target Scan
      Edit 'Target' asset
      Validate policy, scan, and report
      Execute scan and monitor
      [opt] Run and download|email report
      [opt] Run query
    Inspection Check
      Gather and format inspection controls (ACAS BPG and documentation)
      Online
        Get policy, scan, and report responses
        Perform checks against controls and output results
      Offline
        Export policy, scan, and report definitions
        Perform checks against controls and document results
    View Plugins
      ?
  Utility Scripts TODO:
    Invoke-SCAxConsole
#>

<#function Test-SetCredential {
  param(
    [string]$Name,
    [string]$Description,
    [string]$Username,
    [securestring]$PasswordInitial,
    [securestring]$PasswordConfirm,
      [validateset("snmp", "ssh", "windows")]
    [string]$OSType,
    [string]$AuthType = "password"

  )
  if (!$Username) {
    $Username = Read-Host "`n`tUsername "
  }

  while ($true) {
    if (!$PasswordInitial) {
      $PasswordInitial = Read-Host "`n`tPasswordInitial " -assecurestring
    }
    if (!$PasswordConfirm) {
      $PasswordConfirm = Read-Host "`tPasswordConfirm " -assecurestring
    }
    try {
      $Initial = $([system.runtime.interopservices.marshal]::ptrtostringauto( `
        [system.runtime.interopservices.marshal]::securestringtobstr($PasswordInitial)))
      $Confirm = $([system.runtime.interopservices.marshal]::ptrtostringauto( `
        [system.runtime.interopservices.marshal]::securestringtobstr($PasswordConfirm)))
      if ($Initial -ceq $Confirm) {
        BREAK
      }
      $PasswordInitial = $null
      $PasswordConfirm = $null
      Write-Host "`n`tPasswords do not match. Try again..."
    }
    catch {
      $_
    }
  }
  Invoke-SCAx -resource '/credential' -method 'Post' -body
  Invoke-SCAx '/analysis' Post -body '{"type":"vuln","query":{"id":"17239"},"sourceType":"cumulative"}' "WVS Metrics All" -> C,H,M,L
  Invoke-SCAx '/analysis' Post -body '{"type":"vuln","query":{"id":"17240"},"sourceType":"cumulative"}' "Failed Credential/No Registry Access" -> Count
  Invoke-SCAx '/analysis' Post -body '{"type":"vuln","query":{"id":"17241"},"sourceType":"cumulative"}' "Nessus Scan Details" -> Count
  Invoke-SCAx '/analysis' Post -body '{"type":"vuln","query":{"id":"17242"},"sourceType":"cumulative"}' "WVS Metrics 30+" -> 'C','H','M','L'
}#>
function Initialize-SCAx {
  [cmdletbinding()]
  param(
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$UserName,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [securestring]$Password,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$ServerUri,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$ProxyUri,
    [switch]$Import,
    [string]$ImportPath = "$($PSScriptRoot)\SCAx.json",
      [alias('Block')]
    [switch]$BlockPolicyOverride,
      [alias('SV')]
    [switch]$SetVariable
  )
  if ($Import -and (Test-Path -path $ImportPath -ea 'SilentlyContinue')) {
    $Json = Get-Content -path $ImportPath | ConvertFrom-Json
    $Username = $Json.SCAx.Username
    $Password = ($Json.SCAx.Password | ConvertTo-SecureString)
    $ServerUri = $Json.SCAx.ServerUri
    if ($Json.SCAx.ProxyUri) {
      $ProxyUri = $Json.SCAx.ProxyUri
    }
  }
  else {
    if ($Import) {
      Write-Warning "Incorrect Path: $($ImportPath)"
    }
    if (!$Username) {
      $Username = (Read-Host "Username`n")
    }
    if (!$Password) {
      $Password = (Read-Host "Password`n" -assecurestring)
    }
    if (!$ServerUri) {
      $ServerUri = (Read-Host "ServerUri`n")
    }
    if (!$ProxyUri) {
      $ProxyUri = (Read-Host "ProxyUri`n")
    }
  }
  if (!$BlockPolicyOverride) {
    Grant-PolicyOverride
  }
  $Return = New-Object 'psobject' -property (@{
    SCAx = [ordered]@{
      Username = $Username
      Password = $Password
      ServerUri = $ServerUri
      ProxyUri = $ProxyUri
      Status = 'NotAuthenticated'
      Token = $null
      Session = $null
      Object = $null
    }
  })
  if ($SetVariable) {
    $global:_SCAx = $Return.SCAx
  }
  else {
    RETURN $Return
  }
}
function Connect-SCAx {
  [cmdletbinding()]
  param(
      [parameter(valuefrompipelinebypropertyname=$true)]
      [validatenotnullorempty()]
    [psobject]$SCAx
  )
  if ($global:_SCAx) {
    $SCAx = $global:_SCAx
  }
  elseif ($MyInvocation.BoundParameters -contains 'SCAx') {
    #Nothing...
  }
  else {
    Write-Warning "SCAx Object Missing"
    RETURN
  }
  $Body = (@{
    'username' = $SCAx.Username
    'password' = $([system.runtime.interopservices.marshal]::ptrtostringauto(`
      [system.runtime.interopservices.marshal]::securestringtobstr($SCAx.Password)))
    'releaseSession' = $true
  } | ConvertTo-Json -compress)
  $Splat = @{
    Uri = "$($SCAx.ServerUri)/token"
    Method = 'Post'
    Body = $Body
    UseBasicParsing = $true
    ContentType = 'application/json'
    SessionVariable = 'Session'
  }
  if ($SCAx.ProxyUri) {
    $Splat.add('Proxy', $SCAx.ProxyUri)
    $Splat.add('ProxyUseDefaultCredentials', $true)
  }
  try {
    $Token = (Invoke-RestMethod @Splat).Response.Token
  }
  catch [system.net.webexception] {
    Write-Host $_ -fore 'Red'
  }
  catch {
    $_
  }
  if (!$Token -or !$Session) {
    Write-Warning 'Failure: No Token returned.'
  }
  else {
    Write-Host "[+]" -fore 'Black' -back 'DarkGreen' -nonewline
    Write-Host " SCAx - Connected" -fore 'DarkGreen'
    $SCAx.Token = $Token
    $SCAx.Session = $Session
    $SCAx.Status = 'Authenticated'
  }
  if ($global:_SCAx) {
    $global:_SCAx = $SCAx
  }
  else {
    RETURN (New-Object 'psobject' -property @{'SCAx' = $SCAx})
  }
}
function Invoke-SCAx {
  [cmdletbinding()]
  param(
    [string]$Resource, #DynamicParameter? Pull from configs potential the resources.
      [validateset('Delete', 'Get', 'Patch', 'Post')]
    [string]$Method,
    [string]$Body,
    [string]$InFile,
    [string]$OutFile,
    [switch]$Passthru,
      [parameter(valuefrompipelinebypropertyname=$true)]
      [validatenotnullorempty()]
    [psobject]$SCAx
  )
  if ($global:_SCAx) {
    $SCAx = $_SCAx
  }
  elseif ($MyInvocation.BoundParameters -contains 'SCAx') {
    #Nothing...
  }
  else {
    Write-Warning "SCAx Object Missing"
    RETURN
  }
  $Splat = @{
    Uri = "$($SCAx.ServerUri)$($Resource)"
    Method = $Method
    Headers= @{'X-SecurityCenter' = $SCAx.Token}
    ContentType = 'application/json'
    UseBasicParsing = $true
    WebSession = $SCAx.Session
  }
  if ($SCAx.ProxyUri) {
    $Splat.add('Proxy', $SCAx.ProxyUri)
    $Splat.add('ProxyUseDefaultCredentials', $true)
  }
  if ($Body) {
    $Splat.add('Body', $Body)
  }
  if ($InFile) {
    $Splat.add('InFile', $InFile)
  }
  if ($OutFile) {
    $Splat.add('OutFile', $OutFile)
  }
  $SCAx.Object = $null
  try {
    $SCAx.Object = Invoke-RestMethod @Splat
  }
  catch [system.net.webexception] {
    if ($_ -like "*Access Denied*") {
      Write-Host "Access Denied" -fore 'darkred'
      $SCAx.Object = $_
    }
    else {
      Write-Host $_ -fore 'magenta'
      $SCAx.Object = $_
    }
  }
  catch {
    $_
    $SCAx.Object = $_
  }
  finally {
    $SCAx.Session.Headers.clear()
  }
  if (!$SCAx.Object) {
    Write-Warning 'No Reply'
  }
  if ($global:_SCAx) {
    $global:_SCAx = $SCAx
    if ($Passthru) {
      RETURN $SCAx.Object
    }
  }
  else {
    RETURN (New-Object 'psobject' -property @{'SCAx' = $SCAx})
  }
}
function Grant-PolicyOverride {
  if (!([system.management.automation.pstypename]'trustallcertspolicy').type) {
    Add-Type @"
      using System.Net;
      using System.Security.Cryptography.X509Certificates;
      public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
          ServicePoint srvPoint,
          X509Certificate certificate,
          WebRequest request,
          int certificateProblem
        ) {
          return true;
        }
      }
"@
  }
  [system.net.servicepointmanager]::certificatepolicy = New-Object 'trustallcertspolicy'
  [system.net.servicepointmanager]::servercertificatevalidationcallback = $null
  [system.net.servicepointmanager]::securityprotocol = `
    [system.net.securityprotocoltype]::tls -bor `
    [system.net.securityprotocoltype]::tls11 -bor `
    [system.net.securityprotocoltype]::tls12 -bor `
    [system.net.securityprotocoltype]::ssl3
}
function ConvertFrom-UnixTime {
  [cmdletbinding()]
  param(
      [parameter(valuefrompipeline=$true)]
    [long]$UnixTime,
    [string]$Format = 'ddMMMyy HH:mm:ss.f'
  )
  try {
    $Return = ([datetime]::new('1970','1','1').addseconds($UnixTime).tostring($Format))
  }
  catch {
    $_
  }
  RETURN $Return
}
function ConvertTo-UnixTime {
  [cmdletbinding()]
  param(
      [parameter(valuefrompipeline=$true)]
    [datetime]$DateTime
  )
  try {
    $Return = (New-TimeSpan -start '1970-01-01 00:00:00' -end $DateTime).totalseconds
  }
  catch {
    $_
  }
  RETURN $Return
}
function Load-Json {
  param(
    [string]$Path
  )
  try {
    $Json = Get-Content -path $Path | ConvertFrom-Json
    [string]$Json = $Json | ConvertTo-Json -depth 100 -compress
  }
  catch {
    $_
  }
  RETURN $Json
}
function Resolve-SCAxWVS {
  $Props = New-Object 'system.collections.specialized.ordereddictionary'
  $Splat = @{
    Resource = '/analysis'
    Method = 'Post'
    Body = '{"type":"vuln","query":{"id":"17242"},"sourceType":"cumulative"}'
    Passthru = $true
  }
  (Invoke-SCAx @Splat).response.results `
    | Measure-Object -Property 'severityCritical' , 'severityHigh', 'severityMedium', 'severityLow' -sum `
    | foreach {
      $Props.add($_.Property.trimstart('severity'), $_.Sum)
    }
  $Splat.Body = '{"type":"vuln","query":{"id":"17241"},"sourceType":"cumulative"}'
  $FailedCount = (Invoke-SCAx @Splat).response.results.count
  $Props.add('Failed', $FailedCount)
  $Splat.Body = '{"type":"vuln","query":{"id":"17240"},"sourceType":"cumulative"}'
  $TotalCount = (Invoke-SCAx @Splat).response.results.count
  $Props.add('Total', $TotalCount)
  $WVS = [math]::round((((($Props.Critical + $Props.High) * 10) + ($Props.Medium * 4) + $Props.Low) / 15) / ($Props.Total - $Props.Failed), 2)
  $Props.add('WVS', $WVS)
  RETURN (New-Object 'psobject' -property $Props)
}
