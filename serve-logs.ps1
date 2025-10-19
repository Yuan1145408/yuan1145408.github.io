param([int]$Port = 8000)
$ErrorActionPreference = 'Stop'

$prefix = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "Simple server running at $prefix"

$root = Get-Location

function Get-ContentType([string]$path) {
  switch -Regex ($path) {
    '.*\.html$' { return 'text/html' }
    '.*\.css$'  { return 'text/css' }
    '.*\.js$'   { return 'application/javascript' }
    '.*\.json$' { return 'application/json' }
    '.*\.svg$'  { return 'image/svg+xml' }
    default      { return 'application/octet-stream' }
  }
}

while ($true) {
  $ctx = $listener.GetContext()
  $req = $ctx.Request
  $method = $req.HttpMethod
  $urlPath = $req.Url.AbsolutePath
  $localPath = $req.Url.LocalPath.TrimStart('/')
  if ([string]::IsNullOrEmpty($localPath)) { $localPath = 'index.html' }
  $fsPath = Join-Path $root $localPath
  $status = 200

  try {
    if (Test-Path $fsPath) {
      $bytes = [System.IO.File]::ReadAllBytes($fsPath)
      $ctx.Response.ContentType = Get-ContentType $fsPath
      $ctx.Response.ContentLength64 = $bytes.Length
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } else {
      $status = 404
      $ctx.Response.StatusCode = 404
      $buf = [Text.Encoding]::UTF8.GetBytes('Not Found')
      $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
    }
  } catch {
    $status = 500
    $ctx.Response.StatusCode = 500
    $msg = $_.Exception.Message
    $buf = [Text.Encoding]::UTF8.GetBytes($msg)
    $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
  } finally {
    $ctx.Response.Close()
    $ts = Get-Date -Format o
    Write-Host "$ts $method $urlPath -> $localPath [$status]"
  }
}