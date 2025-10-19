param(
  [string]$Root = "C:\niaoA",
  [int]$Port = 8007,
  [string]$BindHost = "127.0.0.1"
)

Write-Host "Serving APK directory: $Root on http://${BindHost}:$Port/"

$listener = New-Object System.Net.HttpListener
$prefix = "http://${BindHost}:$Port/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "Server started. Press Ctrl+C to stop."

function Get-ContentType($path) {
  $ext = [System.IO.Path]::GetExtension($path).ToLower()
  switch ($ext) {
    ".apk" { return "application/vnd.android.package-archive" }
    ".json" { return "application/json" }
    default { return "application/octet-stream" }
  }
}

while ($true) {
  try {
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $res = $ctx.Response
    # CORS
    try { $res.Headers.Add("Access-Control-Allow-Origin", "*") } catch {}

    $rel = [System.Web.HttpUtility]::UrlDecode($req.Url.AbsolutePath.TrimStart('/'))
    if ([string]::IsNullOrWhiteSpace($rel)) { $rel = "" }
    $target = Join-Path $Root $rel

    if (Test-Path $target -PathType Leaf) {
      $bytes = [System.IO.File]::ReadAllBytes($target)
      $res.ContentType = Get-ContentType $target
      $res.OutputStream.Write($bytes, 0, $bytes.Length)
      $res.OutputStream.Close()
    } elseif (Test-Path $target -PathType Container) {
      $files = Get-ChildItem -Path $target | Select-Object Name, Length
      $html = "<html><head><meta charset='utf-8'><title>Index of /$rel</title></head><body><h3>Index of /$rel</h3><ul>"
      foreach ($f in $files) {
        $html += "<li><a href='$rel/$($f.Name)'>$($f.Name)</a> - $([math]::Round($f.Length/1MB,2)) MB" + "</li>"
      }
      $html += "</ul></body></html>"
      $buf = [System.Text.Encoding]::UTF8.GetBytes($html)
      $res.ContentType = "text/html; charset=utf-8"
      $res.OutputStream.Write($buf, 0, $buf.Length)
      $res.OutputStream.Close()
    } else {
      $res.StatusCode = 404
      $msg = "Not Found"
      $buf = [System.Text.Encoding]::UTF8.GetBytes($msg)
      $res.OutputStream.Write($buf, 0, $buf.Length)
      $res.OutputStream.Close()
    }
  } catch {
    Write-Host "Error: $_"
  }
}