Param(
  [string]$Message = ""
)

# 切换到脚本所在目录（即仓库根：niao）
Set-Location $PSScriptRoot

# 统一使用 HTTP/1.1 + Windows Schannel，避免部分网络的空回复/重置问题
$GitPushOpts = @("-c","http.version=HTTP/1.1","-c","http.sslBackend=schannel")

# 提交信息
if ([string]::IsNullOrWhiteSpace($Message)) {
  $Message = "site: 更新 " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

# 开始提交
Write-Host "[publish] add -A"
git add -A

# 如果没有变化，git commit 会报错；这里用 try/catch 做友好提示
try {
  Write-Host "[publish] commit -m '$Message'"
  git commit -m $Message
} catch {
  Write-Host "[publish] 无文件变更或提交失败：" $_.Exception.Message
}

# 推送到 origin/main
Write-Host "[publish] push -u origin main"
& git @GitPushOpts push -u origin main

Write-Host "[publish] 完成。如遇身份认证提示，请按 GitHub 帐号登录或使用 PAT。"