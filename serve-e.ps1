Param(
  [int]$Port = 8006,
  [string]$Root = "E:\鸟"
)

Write-Host "Serving $Root on http://localhost:$Port/"
Set-Location $Root
python -m http.server $Port