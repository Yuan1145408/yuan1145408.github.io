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

## 小游戏（arcade.html）
站内自带、纯前端运行，不依赖任何外站嵌入（原来 iframe 外站常被 X-Frame-Options 拦截，导致白屏）：
- **单人 / 双人模式统一**：`?g=<游戏>&mode=2p` 直达双人模式；支持双人的游戏在页内可一键切换模式
- **站内 20 款小游戏**（`arcade.html` + `arcade-games.js`）：2048、俄罗斯方块、贪吃蛇（含双人同屏）、扫雷、
  吃豆人、像素鸟、数独、国际象棋（AI / 2P）、西洋跳棋（AI / 2P）、四子棋、井字棋、黑白棋（后三者均 AI / 2P）、
  记忆翻牌、打砖块、乒乓（1P vs AI / 2P）、十五拼图、太空侵略者、恐龙跑酷、接龙、麻将连连看
- 开源网页游戏整合：`webgames.json` 中 `embeddable: true` 的条目在小游戏大厅底部统一展示，走站内播放器
- `games-extra.json` 每个小游戏带 `modes` 与 `play1p` / `play2p` 字段，游戏专区卡片渲染
  「单人模式 / 双人模式」按钮；同源内嵌不再显示「本站游玩」按钮
- 网页游戏整合：`webgames.json` 中实测允许嵌入的条目（`embeddable: true`）已同步到
  游戏专区「网页游戏 · 站内畅玩」区块，经 `webgames.html?play=<id>` 的站内播放器运行

## 我的世界实例管理（mc-instances.html）
| 能力 | 说明 |
|---|---|
| 存储 | 实例（世界/模组/配置，可选依赖）以 Git 提交形式存放在你的 GitHub 仓库 `<root>/<id>/` 下 |
| 增量上传 | 每文件算 git blob SHA 与仓库现有路径比对，未改动零请求跳过；大文件按 16MB 切块存 `parts/` |
| 版本识别 | `mmc-pack.json` → `versions/*.json`（Forge/Fabric 坐标）→ `logs/latest.log` → 手动填写 |
| 同步 | 三方比较（本地 / 上次同步基线 / 云端），冲突逐文件决策，`saves/` 世界默认保留本地 |
| 缓存 | Cache Storage 按内容哈希缓存，分块级续传，写盘后按 sha256 校验 |
| 启动 | 写入 `niao-launch.cmd` + `launch-plan.json`，双击调用本地启动器；可选注册 `niao-mc://` 协议 |

## 我的世界网页版（minecraft-web.html）
| 能力 | 说明 |
|---|---|
| 版本选择 | 读取 Mojang 官方 `version_manifest_v2`（925+ 版本，含快照/旧版），跨域失败时回退内置常用版本清单 |
| 启动方式 | 浏览器网页版（Eaglercraft，1.5.2 / 1.8.8）、本地启动器参数摘要、导出实例 JSON |
| Mod 启动器 | 内置 Prism / HMCL / PCL2 / 官方启动器，可添加自定义启动器并配置路径、内存、JVM 参数、游戏目录 |
| 模组管理 | 添加 / 编辑 / 删除 / 启用 / 禁用 / 搜索 / 按加载器筛选 / 导出清单；启用状态带入启动向导 |
| 数据存储 | 全部存 `localStorage`（`niao.mc.launchers.v1` / `niao.mc.mods.v1` / `niao.mc.settings.v1`），无后端 |

## 下载中心（download.html）
| 能力 | 说明 |
|---|---|
| 链接解析 | 自动识别直链、网盘分享文案（可从整段文字中提取链接与提取码） |
| 网盘支持 | 百度 / 夸克 / 蓝奏云 / 123 云盘 / 阿里云盘；提取分享地址与提取码，一键复制 |
| 远端探测 | 读取大小、是否支持 `Range`、文件名（`Content-Disposition`） |
| 多线程下载 | 按 `Range` 分片并发（1–8），单分片失败自动重试；不支持分段时降级单线程 |
| 进度滑条 | 实时百分比 / 已下载 / 速度 / 剩余时间；拖动滑条可预览进度，松开回到实时 |
| 暂停续传 | 暂停后仅重下未完成分片；取消则丢弃 |
| 保存 | 内存合并为 Blob 后 `a[download]` 保存；跨域受限时可改用“用浏览器下载” |

核心实现：`download-core.js`（`NiaoDownloader.parseLink / probe / createTask`），页面为 `download.html`。

> 说明：跨域响应默认只暴露少数响应头，`Content-Length` / `Content-Range` 常被隐藏；
> 此时无法得知总大小，界面会显示“已下载 X / 大小未知”，并在完成后补齐真实大小。
> 多线程需要服务器同时满足「支持 Range」与「允许跨域读取响应头」。

## 设置（settings.html）
集中配置，保存在 `localStorage`（`niao.settings.v1`），`app-settings.js` 提供 `NiaoSettings.get/set/reset/onChange`：
- **下载**：并发分片数、分片大小、失败重试、解析后自动开始、保存方式
- **安装**：直装行为（自动 / 交给浏览器 / 总开新标签）、安装前检查、记住选择
- **搜索**：默认范围、每页条数、代理兜底开关、启用的搜索源（可逐源关闭）

搜索页与下载中心会在初始化时读取设置，并在 `niao:settings` 事件后即时生效。

## 直装与跨域链接
- `downloads.html` / `games.html` 曾经设 `static=false` 且指向不存在的 `localhost:5050`，导致点击“直接安装”被登录/积分拦截；已统一为 `static=true`
- 新增全局接管：点击指向跨域可执行文件的按钮时，自动转到 `download.html?url=...`，由下载器显示进度并保存；同源文件仍交给浏览器
- 可在设置里把安装方式改为“总是打开新标签”以恢复原始行为

## 搜索源新增：gamer520
- 站点 `https://www.gamer520.com`，站内搜索 `?s=关键词`，结果为 WordPress 文章列表
- 该站未返回 `Access-Control-Allow-Origin`，且公共代理对其经常超时，因此：
  - 配置 `forceProxy: true`，直接走代理（依次尝试 allorigins → codetabs → cors.eu.org）
  - 全部失败时，来源条显示为**可点击的「直达」**，跳转 gamer520 站内搜索结果，不占结果位

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

