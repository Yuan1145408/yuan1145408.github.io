# 域名绑定与加速配置（shaniao.com）

目标：将 `shaniao.com` 绑定到 GitHub Pages（用户 `yuan145408`），并可选接入 Cloudflare 用作 CDN 与 301 跳转。

## 一、清理错误记录（在你的域名 DNS 控制台）
- 删除 `@` 的 `A 119.29.209.32`
- 删除 `www` 的 `A 122.114.41.145`
- 如存在其他与 GitHub/Cloudflare 无关的 `A/AAAA` 记录，全部移除

## 二、正确记录（直接指向 GitHub Pages）
- 顶级 `@`（根域）：添加 4 条 `A` 记录（TTL 600）：
  - 185.199.108.153
  - 185.199.109.153
  - 185.199.110.153
  - 185.199.111.153
- 子域 `www`：添加 `CNAME`（TTL 600）：
  - `www -> yuan145408.github.io`

## 三、仓库设置（GitHub Pages）
- 在仓库 `Settings -> Pages`：
  - `Custom domain` 填写：`shaniao.com`
  - 勾选 `Enforce HTTPS`
- 仓库已包含 `CNAME` 文件（内容：`shaniao.com`），请保持不变

## 四、可选：Cloudflare 加速与 301 规范化（推荐）
1) 将域名的 NS 替换为 Cloudflare 提供的两条名称服务器（在域名注册商处操作）
2) Cloudflare DNS（均开启 Proxied）：
   - `@`：`CNAME -> yuan145408.github.io`（Cloudflare 会自动 CNAME Flatten 到 A）
   - `www`：`CNAME -> yuan145408.github.io`
3) Cloudflare SSL/TLS：
   - 模式选择 `Full`
   - 开启 `Always Use HTTPS` 与 `Automatic HTTPS Rewrites`
4) Cloudflare 重定向规则（301）：
   - 规则：`www.shaniao.com/*` 永久重定向到 `https://shaniao.com/$1`
   - 可选：将所有 `http://*` 重定向到 `https://$1`

## 五、自检（NS/解析生效通常需要 5–30 分钟）
- PowerShell：
  - `Resolve-DnsName shaniao.com` 应显示 GitHub/Cloudflare 目标（不再是 `119.29.209.32`）
  - `Resolve-DnsName www.shaniao.com` 应显示 `CNAME -> yuan145408.github.io`
  - `Test-NetConnection -ComputerName shaniao.com -Port 443` 应为 `TcpTestSucceeded : True`
- 浏览器：
  - 访问 `https://www.shaniao.com/` 应 301 到 `https://shaniao.com/`
  - 访问 `https://shaniao.com/` 正常返回页面并显示 HTTPS 锁标

## 六、临时访问（在 DNS/解析尚未生效期间）
- 使用 `https://yuan145408.github.io/<你的仓库名>/` 进行测试
- 生效后统一使用 `https://shaniao.com/`

