# 鸟国网站：静态站点与部署指引
本项目为纯前端静态站点（`index.html` + `styles.css` + `script.js` + 若干 HTML），不依赖后端服务。你可以将它完整部署到 GitHub Pages 或 Netlify，并直接通过公网访问。

## 一键接入
- GitHub Pages 工作流：`.github/workflows/pages.yml`
- Netlify 配置：`netlify.toml`
- 添加 `.nojekyll` 以避免 Jekyll 处理
- 分享地址生成规则：兼容主站与子路径（GitHub 项目站点）
---

## 账号系统（本地版）
纯静态站点没有服务端，账号保存在浏览器 `localStorage`：
- 密码使用 **PBKDF2-SHA256（随机盐 + 12 万次迭代）** 摘要存储，不保存明文；浏览器不支持 WebCrypto 时（如 `file://`）自动降级并在记录里标记算法
- 登录态有效期：默认 12 小时，勾选“记住我”为 30 天；过期自动失效
- 用户名 2-20 位（字母/数字/下划线/中文），密码至少 6 位；连续 5 次密码错误锁定 60 秒
- 顶栏显示当前用户名，点击打开账号面板（积分、有效期、退出登录）
- 相关入口：`script.js` 中的 `Niao.auth`（`loginEx` / `registerEx` / `logout` / `sessionInfo`）
> 这套机制只适合演示与本地使用，不能替代服务端认证。

## 全站动效
- 页面进入、卡片滚动入场、页面切换淡出，全部只使用 `opacity` / `transform`
- 元素进入视口后立即停止观察，动态渲染的卡片通过 `MutationObserver` 增量接管
- `prefers-reduced-motion: reduce` 下自动关闭全部动效

## 聚合搜索（search.html）

深色科技风聚合检索入口，**站内索引 + 全网公开数据源**，零外部依赖、零 API Key、零后端：

| 文件 | 作用 |
|---|---|
| `search.html` / `search.css` | 页面结构与视觉（范围切换、来源条、结果卡） |
| `search.js` | 主控：站内检索、范围/分类/来源筛选、建议、去重合并、渲染 |
| `search-sources.js` | **搜索源配置**（15 个源，新增源只改这个文件） |
| `search-web.js` | 全网检索引擎：并发请求、超时/代理兜底、归一化、去重、相关性排序 |
| `search-index.json` | 站内索引（构建期生成），内容更新后执行 `python build_search_index.py` |

### 已接入的搜索源（均无需 API Key）

| 分组 | 源 | 接口 |
|---|---|---|
| 百科 | 维基百科（中/英）、Minecraft Wiki（中/英） | MediaWiki `action=query&list=search` |
| 我的世界 | MC百科、Modrinth | MC百科搜索结果页 HTML 解析 / Modrinth v2 search |
| 代码 | GitHub、npm | `api.github.com/search/repositories`、`registry.npmjs.org/-/v1/search` |
| 问答 | Stack Overflow、Super User、Ask Ubuntu、Hacker News | StackExchange API / Algolia HN |
| 学术 | Crossref、OpenAlex | `api.crossref.org/works`、`api.openalex.org/works` |
| 图书 | Open Library | `openlibrary.org/search.json` |

### 搜索源配置方式

在 `search-sources.js` 的 `SOURCES` 数组里追加一个对象即可，无需改动其它文件：

```js
{
  id: 'example',            // 唯一标识（URL 参数 / 筛选 / 去重统计都用它）
  name: '示例站点',          // 结果卡片上显示的来源名
  short: '示例',             // 来源条上的短名
  badge: 'E',               // 结果卡左侧的小徽标（1-3 个字符）
  group: 'wiki',            // wiki | code | qa | academic | book | minecraft
  weight: 1.0,              // 基础权重 0.9~1.25，越大越靠前
  home: 'https://example.com',
  proxyable: false,          // 直连失败时是否允许走公共 CORS 代理（被墙站点设 true）
  build: (q) => 'https://example.com/api?q=' + encodeURIComponent(q),
  parse: (data) => (data.items || []).map(it => ({
    title: it.title, snippet: it.desc, url: it.url, badges: ['标签']
  }))
}
```

要点：
- **必须跨域可用**：浏览器直连要求接口返回 `Access-Control-Allow-Origin`；不支持的站点只能作为「继续搜索」外链
- **HTML 源**：设置 `kind: 'html'` 并实现 `parseText(doc)`（如 `mcmod` 用 `DOMParser` 解析 `.result-item`）
- **被墙站点**：`proxyable: true` 时先直连、失败后自动走 `NIAO_SEARCH_PROXIES`（默认 allorigins），仍失败则降级为「来源条上的失败标记」，不影响其它源
- 分组 `group` 决定「我的世界」专题页能检索到哪些源

### 检索与排序

- **并发**：所有源同时请求，单源直连 6s、代理 6s、整体上限 7.5s，慢源不会拖住页面
- **去重**：URL 规范化（去 `www`/hash/`utm_*` 等追踪参数、末尾斜杠）+ 标题同源判重，保留分数更高的一条并合并来源名
- **相关性**：标题整词命中 42（带位置衰减）、完全相等 60、前缀 26、子串 16；摘要命中 +7、徽标 +4、域名命中 +10；再乘源权重，源内排名只给 ≤6 的小幅加成
- **站内优先**：站内条目 +12 分（人工整理，命中更精确），因此同名噪声不会盖过站内结果
- **降级**：所有源都失败时保留站内结果并提示，不会白屏

### 交互

- 范围切换：`全部 / 站内 / 全网`（URL 参数 `s`），分类筛选只在「站内/全部」下出现
- 来源条：显示每个源返回条数与耗时，点击可按单一来源过滤；失败的源以虚线标记（超时/失败/无结果）
- 结果卡：标题 + 完整链接（域名高亮 + 路径）+ 摘要 + 来源标签 + 复制/打开
- 关键词高亮、搜索建议、最近搜索、`↑↓`/`Enter` 键盘导航、`/` 或 `Ctrl+K` 聚焦、分页加载
- 底部「继续搜索」：把同一关键词交给 Bing / Google / 百度 / DuckDuckGo / GitHub（通用搜索引擎无公开跨域接口，因此以直达链接方式提供）

### 我的世界专题（minecraft.html）

页面新增「MC 资料搜索」分区，复用同一套引擎（`groups: ['minecraft']`）：
- 内容类型：`全部内容 / 模组 Mod / 游戏版本 / 整合包·实例`
- 模组 → MC百科 + Modrinth + 双 Wiki；版本 → 双 Wiki（`1.21` 自动改写为 `Java版 1.21`）；整合包 → MC百科 + 中文 Wiki（补「整合包」）
- 结果展示来源、摘要、直达链接，并保留原有启动器、模组下载、Modrinth、MCPEDL 等入口与交互

### 验证步骤

```bash
python serve.py                  # 启动本地服务（端口 5600）
# 1) 站内：http://127.0.0.1:5600/search.html?q=python&s=site   应 10 条，无来源条
# 2) 全网：http://127.0.0.1:5600/search.html?q=react&s=all     应 60+ 条，来源条含 10+ 个源
# 3) 我的世界：http://127.0.0.1:5600/minecraft.html           输入 sodium，选「模组 Mod」
# 4) 去重：搜索 python，元信息里「已合并重复 N 条」应为 0 或正数且列表无重复 URL
node --check search.js && node --check search-sources.js && node --check search-web.js
python build_search_index.py     # 内容更新后重建站内索引
```
注意：维基百科、OpenLibrary 在部分网络下不可达，来源条会显示「超时/失败」，这是预期的降级行为。

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
在项目目录运行（默认端口 5600，已为文本资源统一补上 `charset=utf-8`）：
```powershell
python serve.py
```
或用标准库临时起一个静态服务（端口 8000）：
```powershell
python -m http.server 8000
```
访问 `http://localhost:5600/`（或 `http://localhost:8000/`）进行本地预览。
---

## 仓库卫生
- `.gitignore` 已忽略二进制/反编译产物与日志（`*.dll`、`*.exe`、`disasm.txt`、`*.log` 等）。
- `users.json` / `sessions.json` / `points.json` / `keys.json` 属于本地演示数据或敏感信息，已加入 `.gitignore`；
  **若这些文件曾被提交过，.gitignore 不会把它们从历史中移除**，需要另行执行 `git rm --cached` 并清理历史。
- 站点为纯前端静态页，不含后端；页面中的登录与积分均保存在浏览器 localStorage。
---

如需我为你创建仓库并接入，或编写自动化脚本（含仓库 URL 注入），请把你的 GitHub 仓库地址发我即可。

