# 鸟国网站：静态站点与部署指引
本项目为纯前端静态站点（`index.html` + `styles.css` + `script.js` + 若干 HTML），不依赖后端服务。你可以将它完整部署到 GitHub Pages 或 Netlify，并直接通过公网访问。

## 一键接入
- GitHub Pages 工作流：`.github/workflows/pages.yml`
- Netlify 配置：`netlify.toml`
- 添加 `.nojekyll` 以避免 Jekyll 处理
- 分享地址生成规则：兼容主站与子路径（GitHub 项目站点）
---

## 部署到 GitHub Pages（推荐）
1) 在 GitHub 创建一个仓库（Public 或 Private with Pages），例如：`yourname/niaoguo-site`
2) 在本地运行以下命令（PowerShell）：

```powershell
# 初始化并推送到 GitHub（将 <YOUR_REMOTE_URL> 替换为你的远程仓库）
 git init
 git add .
 git commit -m "Init static site"
 git branch -M main
 git remote add origin <YOUR_REMOTE_URL>
 git push -u origin main
```

3) 仓库设置 -> Pages -> Source 选择 GitHub Actions，默认会自动使用 `pages.yml` 发布。
4) 成功后将得到站点地址：
- 用户主页：https://<username>.github.io/
- 项目站点：https://<username>.github.io/<repo>/

> 提示：如果你使用项目站点（带子路径），站内的“布局站点分享”会包含实际子路径，复制即可用。
---

## 部署到 Netlify
1) 登录 Netlify，选择 “Add new site” -> “Import from Git”，绑定你的 GitHub 仓库。
2) Build 命令留空（本项目为纯静态），Publish directory 使用项目根目录（已在 `netlify.toml` 指定为 `.`）。
3) 部署完成后即可获得站点 URL，可在 Netlify 中绑定自定义域名。
---

## 自定义域名与 HTTPS
- GitHub Pages：仓库设置 -> Pages -> Custom domain，按提示在你的 DNS 服务商添加 CNAME 记录。
- Netlify：在域名管理中添加站点域，将 DNS 指向 Netlify，或使用 CNAME 指向分配的子域。
---

## 可选优化（非必须）
- `.gitignore`：如果不需要上传较大的二进制或临时文件，可以在本地添加如下目录/文件后再提交：
  ```gitignore
  *.exe
  *.dll
  niao/
  disasm.txt
  report.txt
  ```
- 镜像与国内访问：如需配置更多镜像或本地访问模式，可在 `script.js` 为特定条目添加 `mirrors` 字段并覆盖。
- SEO：如需调整 `<link rel="canonical">` 以匹配你的自定义域，可在 `index.html` 中更新。
---

## 本地预览
在项目目录运行：
```powershell
python -m http.server 8000
```
访问 `http://localhost:8000/` 进行本地预览。
---

如需我为你创建仓库并接入，或编写自动化脚本（含仓库 URL 注入），请把你的 GitHub 仓库地址发我即可。

