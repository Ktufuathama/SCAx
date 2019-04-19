<#
  Asset
    Edit
  Queries
    Run
    Edit
  Scans
    Edit
    Run
    Stop
    Monitor
  Policy
    Import
    Export
    Edit
    Validate= BPG
  Report
    Import
    Export
    Edit
    Run
    Stop
    Download
    Monitor
    Validate = BPG
#>
function Initialize-SCAx {
  [cmdletbinding()]
  param(
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$Username,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [securestring]$Password,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$ServerUri,
      [parameter(valuefrompipelinebypropertyname=$true)]
    [string]$ProxyUri,
    [switch]$Import,
    [string]$ImportPath = "$($PSScriptRoot)\SCAx.json",
      [alias('SV')]
    [switch]$SetVariable
  )
  if ($Import -and (Test-Path -path $ImportPath -ea 'SilentlyContinue')) {
    $Json = Get-Content -path $ImportPath | ConvertFrom-Json
    $Username = $Json.Username
    $Password = ($Json.Password | ConvertTo-SecureString)
    $ServerUri = $Json.ServerUri
    if ($Json.ProxyUri) {
      $ProxyUri = $Json.ProxyUri
    }
  }
  else {
    if ($Import) {
      Write-Warning "Incorrect Path: $($ImportPath)"
    }
    if (!$Username) {
      $Username = (Read-Host "`tUsername ")
    }
    if (!$Password) {
      $Password = (Read-Host "`tPassword " -assecurestring)
    }
    if (!$ServerUri) {
      $ServerUri = (Read-Host "`tServerUri ")
    }
    if (!$ProxyUri) {
      $ProxyUri = (Read-Host "`tProxyUri ")
    }
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
    $SCAx = $_SCAx
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
    [string]$Resource, #DynamicParameter? Pull from configs all the resources.
      [validateset('Delete', 'Get', 'Patch', 'Post')]
    [string]$Method,
    [string]$Body,
    [string]$InFile,
    [string]$OutFile,
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
  }
  else {
    RETURN (New-Object 'psobject' -property @{'SCAx' = $SCAx})
  }
}
function Grant-Override {
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
  param(
    $UnixTime,
    $Format = 'ddMMMyy HH:mm:ss.f'
  )
  RETURN ([datetime]::new('1970','1','1').addseconds($UnixTime).tostring($Format))
}