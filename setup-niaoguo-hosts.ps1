<#
用途：将 niaoguo.com 与 www.niaoguo.com 映射到本机 127.0.0.1，以便在浏览器访问这两个域名时打开当前项目本地服务器。

使用方法（管理员权限 PowerShell）：
1) 在项目目录打开 PowerShell（右键以管理员运行）
2) 执行：
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\setup-niaoguo-hosts.ps1
3) 启动站点：
   - 无端口：python -m http.server 80   （需要管理员权限）
   - 或使用端口：python -m http.server 8000 （访问 http://niaoguo.com:8000/）
#>

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "请以管理员权限运行此脚本（右键 PowerShell 以管理员运行）。"
  exit 1
}

$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
Write-Host "Hosts 路径： $hostsPath"

try {
  $original = Get-Content -Path $hostsPath -ErrorAction Stop
} catch {
  Write-Error "读取 hosts 失败：$_"
  exit 1
}

# 备份 hosts
$backupPath = "$hostsPath.bak"
try {
  Set-Content -Path $backupPath -Value ($original -join "`n") -ErrorAction Stop
  Write-Host "已备份 hosts 到： $backupPath"
} catch {
  Write-Warning "备份失败（不影响后续写入）：$_"
}

# 移除旧映射（若存在），追加新映射
$filtered = $original | Where-Object { $_ -notmatch "\bniaoguo\.com\b" }
$newLines = @(
  "127.0.0.1 niaoguo.com",
  "127.0.0.1 www.niaoguo.com"
)
$final = $filtered + $newLines

try {
  Set-Content -Path $hostsPath -Value ($final -join "`n") -ErrorAction Stop
  Write-Host "已写入映射：niaoguo.com / www.niaoguo.com -> 127.0.0.1"
} catch {
  Write-Error "写入 hosts 失败：$_"
  exit 1
}

Write-Host "完成。现在可在浏览器访问："
Write-Host " - http://niaoguo.com/ （若本地服务器监听 80 端口）"
Write-Host " - http://niaoguo.com:8000/ （若本地服务器监听 8000 端口）"