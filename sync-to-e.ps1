$Src = "C:\Users\Administrator\Downloads\摸金小助手1.4\niao"
$Dst = "E:\鸟"

Write-Host "Sync start: $Src -> $Dst"
if (!(Test-Path $Dst)) {
  New-Item -ItemType Directory -Path $Dst -Force | Out-Null
}

# 使用 robocopy 做镜像同步（排除无关目录），PowerShell 不支持反斜杠续行，改用数组参数
$args = @(
  $Src,
  $Dst,
  '/MIR','/MT:16','/R:1','/W:1','/NFL','/NDL','/NP','/NJH','/NJS',
  '/XD','.git','.github','logs','node_modules',
  '/XF','*.tmp','*.log','*.pyc'
)
robocopy @args

$code = $LASTEXITCODE
Write-Host "Robocopy exit code: $code"
if ($code -ge 8) {
  Write-Warning "同步可能遇到错误（退出码 >= 8），请检查输出信息。"
} else {
  Write-Host "Sync done."
}