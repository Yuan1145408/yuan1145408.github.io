/* ============================================================
   我的世界 · 客户端资源解析与静默启动引擎
   ------------------------------------------------------------
   目标：当所选版本没有内置网页客户端时，不再提示用户跳转/新窗口，
        而是在后台按优先级静默获取「客户端 + 依赖库 + 资源索引」，
        校验通过后自动完成配置并尝试启动本地客户端。

   下载源优先级（每个产物都会逐级降级，并记录失败原因）：
     1) HMCL 下载源（BMCLAPI）
     2) PCL  下载源（BMCLAPI 备用节点）
     3) MC百科（资料库，用于定位可用直链）
     4) Mojang 官方源（最终兜底）
     5) Forge Maven（依赖库专用备用源）

   约束：
     - 全流程只用 fetch，不调用 window.open / <a download>，
       不产生任何页面跳转或浏览器下载窗口。
     - 浏览器无法直接执行本地可执行文件，因此「启动」通过
       本地启动器 + niao-mc:// 协议桥完成；桥未启用时明确阻止启动并记录日志。
   ============================================================ */
(function (global) {
  'use strict';

  /* ---------------- 常量 ---------------- */

  var WEB_VERSIONS = ['1.5.2', '1.8.8'];

  var CACHE_NAME = 'niao-mc-res-v1';
  var CACHE_HOST = 'https://niao-mc-res.local/';
  var BRIDGE_KEY = 'niao.mc.bridge.v1';
  var PLAN_KEY = 'niao.mc.plan.v1';
  var IDB_NAME = 'niao-mc-fs';
  var IDB_STORE = 'handles';

  // 单文件与整体预算（避免误下超大资源拖垮页面）
  var LIMITS = {
    fileTimeout: 45000,
    metaTimeout: 12000,
    retry: 2,
    concurrency: 4,
    assetSample: 24,
    assetMax: 2500,
    totalBytes: 900 * 1024 * 1024
  };

  /* ---------------- 下载源定义 ---------------- */

  var SOURCES = [
    {
      id: 'hmcl', name: 'HMCL 下载源', kind: 'mirror',
      manifest: 'https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json',
      versionJson: function (v) { return 'https://bmclapi2.bangbang93.com/version/' + v + '/json'; },
      client: function (v) { return 'https://bmclapi2.bangbang93.com/version/' + v + '/client'; },
      maven: function (p) { return 'https://bmclapi2.bangbang93.com/maven/' + p; },
      asset: function (h) { return 'https://bmclapi2.bangbang93.com/assets/' + h; },
      assetIndex: function (v) { return 'https://bmclapi2.bangbang93.com/version/' + v + '/assets'; }
    },
    {
      id: 'pcl', name: 'PCL 下载源', kind: 'mirror',
      manifest: 'https://bmclapi.bangbang93.com/mc/game/version_manifest_v2.json',
      versionJson: function (v) { return 'https://bmclapi.bangbang93.com/version/' + v + '/json'; },
      client: function (v) { return 'https://bmclapi.bangbang93.com/version/' + v + '/client'; },
      maven: function (p) { return 'https://bmclapi.bangbang93.com/maven/' + p; },
      asset: function (h) { return 'https://bmclapi.bangbang93.com/assets/' + h; },
      assetIndex: function (v) { return 'https://bmclapi.bangbang93.com/version/' + v + '/assets'; }
    },
    {
      id: 'mcmod', name: 'MC百科', kind: 'catalog',
      search: function (q) { return 'https://search.mcmod.cn/s?key=' + encodeURIComponent(q); }
    },
    {
      id: 'official', name: 'Mojang 官方源', kind: 'official',
      manifest: 'https://launchermeta.mojang.com/mc/game/version_manifest_v2.json',
      maven: function (p) { return 'https://libraries.minecraft.net/' + p; },
      asset: function (h) { return 'https://resources.download.minecraft.net/' + h.slice(0, 2) + '/' + h; }
    },
    {
      id: 'forge', name: 'Forge Maven', kind: 'maven-only',
      maven: function (p) { return 'https://maven.minecraftforge.net/' + p; }
    }
  ];

  // 依赖库的公共 Maven 备用源（不托管 Mojang 私有坐标，但能覆盖大多数开源库）
  var EXTRA_MAVEN = [
    // Sponge 的公共仓库镜像了 Mojang 自家构件，且开放跨域，是浏览器内补齐依赖的关键源
    { id: 'sponge', name: 'Sponge Maven', base: 'https://repo.spongepowered.org/repository/maven-public/' },
    { id: 'tencent', name: '腾讯云 Maven', base: 'https://mirrors.cloud.tencent.com/nexus/repository/maven-public/' },
    { id: 'aliyun', name: '阿里云 Maven', base: 'https://maven.aliyun.com/repository/public/' },
    { id: 'tuna', name: '清华 Maven', base: 'https://mirrors.tuna.tsinghua.edu.cn/maven-central/' },
    { id: 'repo1', name: 'Maven Central', base: 'https://repo1.maven.org/maven2/' }
  ];

  // 公共 CORS 代理：仅作最后兜底（直连、站点代理都失败后才会用到）
  var CORS_PROXIES = [
    { id: 'allorigins', name: '公共代理 allorigins', wrap: function (u) { return 'https://api.allorigins.win/raw?url=' + encodeURIComponent(u); } },
    { id: 'codetabs', name: '公共代理 codetabs', wrap: function (u) { return 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(u); } }
  ];

  // 资源文件（assets）的浏览器友好镜像：jsDelivr 对 GitHub 仓库提供 CORS
  var ASSET_CDN = {
    id: 'jsdelivr', name: 'jsDelivr 资源镜像',
    url: function (version, key) {
      return 'https://cdn.jsdelivr.net/gh/InventivetalentDev/minecraft-assets@' +
        encodeURIComponent(version) + '/assets/' + key;
    }
  };

  var STAGE_LABEL = {
    health: '探测下载源',
    meta: '获取版本清单',
    client: '下载客户端',
    libraries: '下载依赖库',
    assetIndex: '获取资源索引',
    assets: '下载资源文件',
    configure: '生成启动配置',
    verify: '校验资源完整性',
    bridge: '尝试启动客户端'
  };

  /* ---------------- 代理配置 ----------------
     设置结构（niao.settings.v1）：
       download.proxyOn / download.proxyUrl   自定义代理（前缀型或 {url} 模板型）
       search.proxy                            是否允许公共 CORS 代理兜底
     -------------------------------------------------- */

  function readSettings() {
    // localStorage 是唯一真源：其它标签页/设置页保存后立即可见
    try {
      var raw = localStorage.getItem('niao.settings.v1');
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      }
    } catch (e) { /* 忽略 */ }
    try {
      if (global.NiaoSettings && typeof global.NiaoSettings.get === 'function') {
        var viaApi = global.NiaoSettings.get();
        if (viaApi && typeof viaApi === 'object') return viaApi;
      }
    } catch (e) { /* 忽略 */ }
    return {};
  }

  function readProxy() {
    var s = readSettings();
    var on = s['download.proxyOn'];
    var url = String(s['download.proxyUrl'] || '').trim();
    // 兼容旧版嵌套写法 { download: { proxyOn, proxyUrl } }
    if (!on && s.download && s.download.proxyOn) {
      on = true;
      url = String(s.download.proxyUrl || '').trim();
    }
    if (!on || !/^https?:\/\//i.test(url)) return '';
    if (url.indexOf('{url}') >= 0 || url.indexOf('?') >= 0) return url;
    return url.replace(/\/+$/, '') + '/';
  }

  // 支持三种代理写法：{url} 模板、?url= 查询型、纯前缀型
  function viaProxy(url, proxy) {
    if (!proxy) return url;
    if (proxy.indexOf('{url}') >= 0) return proxy.replace(/\{url\}/g, encodeURIComponent(url));
    if (/[?&]url=$/.test(proxy)) return proxy + encodeURIComponent(url);
    if (proxy.indexOf('?') >= 0) {
      return proxy + (/[?&]$/.test(proxy) ? '' : '&') + 'url=' + encodeURIComponent(url);
    }
    return proxy + url;
  }

  // 公共 CORS 代理：受「允许公共代理兜底」开关控制
  function publicProxies() {
    var s = readSettings();
    if (s['search.proxy'] === false) return [];
    var list = global.NIAO_SEARCH_PROXIES;
    if (Array.isArray(list) && list.length) {
      return list.map(function (p) { return { id: p.name, name: p.name, wrap: p.wrap }; });
    }
    return CORS_PROXIES;
  }

  /* ---------------- 小工具 ---------------- */

  function err(code, message, stage, detail) {
    var e = new Error(message);
    e.code = code;
    e.stage = stage || '';
    e.detail = detail || '';
    return e;
  }

  function fmtSize(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  function shortUrl(u) {
    try {
      var x = new URL(u);
      return x.host + x.pathname;
    } catch (e) { return String(u).slice(0, 60); }
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function sha1Hex(buf) {
    var d = await crypto.subtle.digest('SHA-1', buf);
    return Array.prototype.map.call(new Uint8Array(d), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  // 带超时 + 外部取消的 fetch
  async function fetchWith(url, opts, timeout, outerSignal) {
    opts = opts || {};
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeout || LIMITS.fileTimeout);
    function onOuter() { ctrl.abort(); }
    if (outerSignal) {
      if (outerSignal.aborted) { clearTimeout(timer); throw err('E_ABORT', '操作已取消'); }
      outerSignal.addEventListener('abort', onOuter, { once: true });
    }
    try {
      return await fetch(url, Object.assign({ cache: 'no-store' }, opts, { signal: ctrl.signal }));
    } catch (e) {
      if (e && e.name === 'AbortError') {
        if (outerSignal && outerSignal.aborted) throw err('E_ABORT', '操作已取消');
        throw err('E_TIMEOUT', '请求超时（' + Math.round((timeout || LIMITS.fileTimeout) / 1000) + 's）');
      }
      throw err('E_NET', '网络不可达或跨域被拦截（CORS）');
    } finally {
      clearTimeout(timer);
      if (outerSignal) outerSignal.removeEventListener('abort', onOuter);
    }
  }

  /* ---------------- 缓存（Cache Storage） ---------------- */

  async function cacheOpen() {
    if (!global.caches) throw err('E_CACHE', '当前浏览器不支持 Cache Storage');
    return caches.open(CACHE_NAME);
  }

  async function cacheGet(key) {
    try {
      var c = await cacheOpen();
      var r = await c.match(CACHE_HOST + key);
      return r ? await r.blob() : null;
    } catch (e) { return null; }
  }

  async function cachePut(key, blob) {
    var c = await cacheOpen();
    await c.put(CACHE_HOST + key, new Response(blob));
    return true;
  }

  async function cacheStats() {
    try {
      var c = await cacheOpen();
      var keys = await c.keys();
      var bytes = 0;
      for (var i = 0; i < keys.length; i++) {
        var r = await c.match(keys[i]);
        if (r) bytes += (await r.blob()).size;
      }
      return { count: keys.length, bytes: bytes };
    } catch (e) { return { count: 0, bytes: 0 }; }
  }

  async function cacheClear() {
    try { return await caches.delete(CACHE_NAME); } catch (e) { return false; }
  }

  /* ---------------- 目录句柄持久化（IndexedDB） ---------------- */

  function idbOpen() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  async function saveDirHandle(handle) {
    try {
      var db = await idbOpen();
      await new Promise(function (resolve, reject) {
        var tx = db.transaction(IDB_STORE, 'readwrite');
        tx.objectStore(IDB_STORE).put(handle, 'instance-root');
        tx.oncomplete = resolve;
        tx.onerror = function () { reject(tx.error); };
      });
      return true;
    } catch (e) { return false; }
  }

  async function loadDirHandle() {
    try {
      var db = await idbOpen();
      return await new Promise(function (resolve, reject) {
        var tx = db.transaction(IDB_STORE, 'readonly');
        var r = tx.objectStore(IDB_STORE).get('instance-root');
        r.onsuccess = function () { resolve(r.result || null); };
        r.onerror = function () { reject(r.error); };
      });
    } catch (e) { return null; }
  }

  async function ensurePermission(handle, mode) {
    if (!handle || !handle.queryPermission) return true;
    var q = await handle.queryPermission({ mode: mode || 'readwrite' });
    if (q === 'granted') return true;
    var r = await handle.requestPermission({ mode: mode || 'readwrite' });
    return r === 'granted';
  }

  /* ---------------- 源健康探测 ---------------- */

  var healthCache = null;

  async function probeSource(src, signal) {
    if (src.kind === 'catalog') {
      // 资料库只探测可达性；它不提供文件直链
      try {
        var r = await fetchWith(src.search('Minecraft'), { method: 'GET' }, LIMITS.metaTimeout, signal);
        return { ok: r.ok, note: r.ok ? '可访问（仅目录，无直链）' : 'HTTP ' + r.status };
      } catch (e) {
        return { ok: false, note: e.message };
      }
    }
    var url = src.manifest || (src.maven && src.maven('org/ow2/asm/asm/9.6/asm-9.6.jar'));
    try {
      var res = await fetchWith(url, { headers: { Range: 'bytes=0-255' } }, LIMITS.metaTimeout, signal);
      return { ok: res.ok, note: res.ok ? 'HTTP ' + res.status : 'HTTP ' + res.status };
    } catch (e) {
      return { ok: false, note: e.message };
    }
  }

  async function healthCheck(ctx) {
    if (healthCache) {
      ctx.log('源探测结果复用本次会话缓存');
      return healthCache;
    }
    var out = {};
    ctx.log('开始探测下载源可用性…');
    for (var i = 0; i < SOURCES.length; i++) {
      var s = SOURCES[i];
      var r = await probeSource(s, ctx.signal);
      out[s.id] = r.ok;
      ctx.log((r.ok ? '  ✓ ' : '  ✗ ') + s.name + '：' + r.note + (r.ok ? '' : '（将跳过该源）'));
    }
    healthCache = out;
    var usable = Object.keys(out).filter(function (k) { return out[k]; });
    ctx.log('可用源：' + (usable.length ? usable.map(sourceName).join('、') : '无'));
    if (!usable.length && !readProxy()) {
      ctx.log('提示：可在「设置 → 下载代理」配置代理后再试，浏览器直连会被部分镜像的跨域策略拦截。');
    }
    if (!usable.length) throw err('E_ALL_SOURCES', '所有下载源均不可用', 'health');
    return out;
  }

  function sourceName(id) {
    var s = SOURCES.filter(function (x) { return x.id === id; })[0];
    return s ? s.name : id;
  }

  /* ---------------- MC百科定位 ---------------- */

  async function mcmodLocate(version, ctx) {
    // MC百科是资料库：尝试从搜索结果与详情页里找可直连的文件地址
    ctx.log('MC百科：检索 “Minecraft ' + version + ' 客户端下载”…');
    var src = SOURCES.filter(function (s) { return s.id === 'mcmod'; })[0];
    var html;
    try {
      var res = await fetchWith(src.search('Minecraft ' + version + ' 客户端 下载'), {}, LIMITS.metaTimeout, ctx.signal);
      html = await res.text();
    } catch (e) {
      ctx.log('MC百科检索失败：' + e.message);
      return null;
    }
    var pages = [];
    String(html).replace(/href="([^"]*\/download\/\d+\.html)"/g, function (m, u) {
      if (pages.length < 2) pages.push(u.indexOf('//') === 0 ? 'https:' + u : u);
      return m;
    });
    if (!pages.length) {
      ctx.log('MC百科：未检索到版本下载详情页');
      return null;
    }
    for (var i = 0; i < pages.length; i++) {
      var page;
      try {
        page = await (await fetchWith(pages[i], {}, LIMITS.metaTimeout, ctx.signal)).text();
      } catch (e) { continue; }
      var direct = String(page).match(/https?:\/\/[^\s"'<>]+\.(?:jar|json|zip)\b/);
      if (direct) {
        ctx.log('MC百科：找到直连文件 ' + shortUrl(direct[0]));
        return { url: direct[0], page: pages[i] };
      }
    }
    ctx.log('MC百科：详情页未暴露可直连的文件地址（页面依赖前端脚本），跳过');
    return null;
  }

  /* ---------------- 版本元数据 ---------------- */

  async function fetchJson(url, ctx, timeout) {
    var res = await fetchWith(url, {}, timeout || LIMITS.metaTimeout, ctx.signal);
    if (!res.ok) throw err('E_HTTP', 'HTTP ' + res.status, 'meta');
    var text = await res.text();
    try { return JSON.parse(text); } catch (e) { throw err('E_SCHEMA', '返回内容不是合法 JSON', 'meta'); }
  }

  async function resolveMeta(version, health, ctx) {
    ctx.stage('meta');
    var official = SOURCES.filter(function (s) { return s.id === 'official'; })[0];
    var mirrors = SOURCES.filter(function (s) {
      return health[s.id] && s.versionJson;
    });
    var lastErr = null;

    // 第一梯队：HMCL → PCL（镜像源的版本 JSON）
    for (var i = 0; i < mirrors.length; i++) {
      var m = mirrors[i];
      try {
        ctx.log(m.name + '：请求版本 JSON…');
        var meta = await fetchJson(m.versionJson(version), ctx);
        if (!meta || (!meta.mainClass && !meta.jar)) throw err('E_SCHEMA', '版本 JSON 缺少关键字段', 'meta');
        ctx.log('元数据就绪：' + version + ' · mainClass=' + (meta.mainClass || '（继承）') +
          ' · 依赖 ' + (meta.libraries || []).length + ' 个');
        return { meta: meta, source: m.name, attempts: 1 + i };
      } catch (e) {
        if (e.code === 'E_ABORT') throw e;
        lastErr = e;
        ctx.log(m.name + ' 获取元数据失败：' + e.message + '，降级到下一个源');
      }
    }

    // 第二梯队：MC百科（资料库，尝试定位可直连的版本文件）
    ctx.log('镜像源均不可用，尝试 MC百科…');
    var mc = await mcmodLocate(version, ctx).catch(function () { return null; });
    if (mc) {
      try {
        var meta2 = await fetchJson(mc.url, ctx);
        if (meta2 && (meta2.mainClass || meta2.jar)) {
          ctx.log('元数据来自 MC百科 直连文件：' + shortUrl(mc.url));
          return { meta: meta2, source: 'MC百科', attempts: 99 };
        }
      } catch (e2) {
        ctx.log('MC百科 文件不可解析：' + e2.message + '，继续降级到官方源');
      }
    }

    // 第三梯队：官方源（最终兜底）
    try {
      ctx.log('官方源：读取版本清单…');
      var man = await fetchJson(official.manifest, ctx);
      var hit = (man.versions || []).filter(function (v) { return v.id === version; })[0];
      if (!hit) throw err('E_NO_VERSION', '官方清单里没有版本 ' + version, 'meta');
      var meta3 = await fetchJson(hit.url, ctx);
      if (!meta3 || (!meta3.mainClass && !meta3.jar)) throw err('E_SCHEMA', '版本 JSON 缺少关键字段', 'meta');
      ctx.log('元数据就绪（官方源）：' + version + ' · 依赖 ' + (meta3.libraries || []).length + ' 个');
      return { meta: meta3, source: 'Mojang 官方源', attempts: 99 };
    } catch (e) {
      if (e.code === 'E_ABORT') throw e;
      ctx.log('官方源获取元数据失败：' + e.message);
    }

    throw err('E_META', '所有源都无法获取 ' + version + ' 的版本元数据' +
      (lastErr ? '（最后一次错误：' + lastErr.message + '）' : ''), 'meta');
  }

  /* ---------------- 镜像 URL 构造 ---------------- */

  function libraryPath(name) {
    // group:artifact:version[:classifier]
    var parts = String(name || '').split(':');
    if (parts.length < 3) return '';
    var group = parts[0].replace(/\./g, '/');
    var artifact = parts[1];
    var ver = parts[2];
    var classifier = parts[3] ? '-' + parts[3] : '';
    return group + '/' + artifact + '/' + ver + '/' + artifact + '-' + ver + classifier + '.jar';
  }

  function osAllowed(lib, osName) {
    var rules = lib.rules;
    if (!rules || !rules.length) return true;
    var allow = false;
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      var match = true;
      if (r.os && r.os.name && r.os.name !== osName) match = false;
      if (match) allow = r.action === 'allow';
    }
    return allow;
  }

  function currentOs() {
    var ua = navigator.userAgent || '';
    if (/Windows/i.test(ua)) return 'windows';
    if (/Mac/i.test(ua)) return 'osx';
    return 'linux';
  }

  /* ---------------- 单文件多源下载 ---------------- */

  async function downloadOne(task, ctx) {
    // task: {key, urls:[{url,label}], sha1, size, label}
    // 末尾追加代理兜底：直连全部失败后，通过站点配置的代理重试一次
    if (ctx.proxy) {
      var head = task.urls[0];
      if (head) {
        task.urls = task.urls.concat([{ url: viaProxy(head.url, ctx.proxy), label: head.label + '（经站点代理）' }]);
      }
    }
    // 最后兜底：公共 CORS 代理（对跨域无 ACAO 的镜像有效）
    var primary = task.urls[0];
    if (primary) {
      ctx.publicProxies.forEach(function (p) {
        task.urls = task.urls.concat([{ url: p.wrap(primary.url), label: primary.label + '（' + p.name + '）' }]);
      });
    }
    var cached = await cacheGet(task.key);
    if (cached) {
      ctx.stats.cached++;
      ctx.stats.bytes += cached.size;
      return { blob: cached, source: '缓存', fromCache: true };
    }
    var lastErr = null;
    for (var i = 0; i < task.urls.length; i++) {
      var c = task.urls[i];
      var host = '';
      try { host = new URL(c.url).host; } catch (e) { host = c.url.slice(0, 30); }
      if (ctx.deadHost && ctx.deadHost[host]) continue; // 该主机已熔断
      var isProxy = /代理/.test(c.label || '');
      var perTimeout = isProxy ? 15000 : LIMITS.fileTimeout;
      for (var attempt = 0; attempt <= LIMITS.retry; attempt++) {
        try {
          var res = await fetchWith(c.url, {}, perTimeout, ctx.signal);
          if (!res.ok) throw err('E_HTTP', 'HTTP ' + res.status, ctx.stageName);
          var blob = await res.blob();
          if (c.lenient) {
            // 第三方镜像副本：只保证字节可读，不强制官方哈希（可能与官方发布存在细微差异）
            ctx.stats.unverified++;
            await cachePut(task.key, blob);
            ctx.stats.bytes += blob.size;
            ctx.stats.downloaded++;
            ctx.stats.sourceUsed[c.label] = (ctx.stats.sourceUsed[c.label] || 0) + 1;
            return { blob: blob, source: c.label, fromCache: false, lenient: true };
          }
          if (task.size && blob.size !== task.size) {
            throw err('E_SIZE', '大小不符（期望 ' + task.size + '，实际 ' + blob.size + '）', ctx.stageName);
          }
          if (task.sha1) {
            var got = await sha1Hex(await blob.arrayBuffer());
            if (got.toLowerCase() !== String(task.sha1).toLowerCase()) {
              throw err('E_HASH', 'SHA-1 校验失败', ctx.stageName);
            }
            ctx.stats.verified++;
          } else {
            ctx.stats.unverified++;
          }
          await cachePut(task.key, blob);
          ctx.stats.bytes += blob.size;
          ctx.stats.downloaded++;
          ctx.hostOk[host] = (ctx.hostOk[host] || 0) + 1;
          ctx.doneKeys[task.key] = true;
          if (c.source !== '缓存' && c.label) ctx.stats.sourceUsed[c.label] = (ctx.stats.sourceUsed[c.label] || 0) + 1;
          return { blob: blob, source: c.label, fromCache: false };
        } catch (e) {
          if (e.code === 'E_ABORT') throw e;
          lastErr = e;
          var retryable = e.code === 'E_TIMEOUT' || e.code === 'E_NET';
          if (retryable && attempt < LIMITS.retry) {
            await sleep(400 * Math.pow(2, attempt));
            continue;
          }
          ctx.log('  ✗ ' + task.label + ' @ ' + shortUrl(c.url) + '：' + e.message);
          ctx.hostFail[host] = (ctx.hostFail[host] || 0) + 1;
          var missingArtifact = e.code === 'E_HTTP' && /404/.test(e.message);
          if (missingArtifact && ctx.hostFail[host] >= 5 && !ctx.hostOk[host] && !ctx.deadHost[host]) {
            ctx.deadHost[host] = true;
            ctx.log('  ⚠ ' + host + ' 连续 404 且从未成功，判定不含所需构件，本次任务内跳过', 'warn');
            break;
          }
          if (ctx.hostFail[host] >= 3 && !ctx.hostOk[host] && !ctx.deadHost[host]) {
            ctx.deadHost[host] = true;
            ctx.log('  ⚠ ' + host + ' 连续失败 3 次，本次任务内不再尝试该主机', 'warn');
          }
          break;
        }
      }
    }
    throw err('E_DOWNLOAD', (lastErr ? lastErr.message : '下载失败') + '：' + task.label, ctx.stageName);
  }

  async function runPool(tasks, limit, worker) {
    var idx = 0;
    var workers = [];
    for (var w = 0; w < Math.min(limit, tasks.length); w++) {
      workers.push((async function () {
        while (true) {
          var i = idx++;
          if (i >= tasks.length) return;
          await worker(tasks[i], i);
        }
      })());
    }
    await Promise.all(workers);
  }

  /* ---------------- 主机可用性探测 ----------------
     目的：避免"每个文件都把每个镜像试一遍"造成的长时间等待。
     做法：用一个小文件对每个候选主机发一次 Range 请求，
           能读到响应（含 404）说明跨域可用；全部超时/被拦截则判定不可用。
     -------------------------------------------------- */
  async function probeMavenHosts(health, ctx, version) {
    var rel = 'org/ow2/asm/asm/9.6/asm-9.6.jar';
    var cands = [];
    SOURCES.forEach(function (s) {
      if (health[s.id] && s.maven) cands.push({ name: s.name, make: s.maven, probe: s.maven(rel) });
    });
    EXTRA_MAVEN.forEach(function (m) {
      cands.push({ name: m.name, make: function (r) { return m.base + r; }, probe: m.base + rel });
    });
    if (ctx.proxy) {
      cands.unshift({
        name: '自定义代理',
        make: function (r) { return viaProxy('https://libraries.minecraft.net/' + r, ctx.proxy); },
        probe: viaProxy('https://libraries.minecraft.net/' + rel, ctx.proxy)
      });
    }
    ctx.publicProxies.forEach(function (p) {
      cands.push({
        name: p.name,
        make: function (r) { return p.wrap('https://libraries.minecraft.net/' + r); },
        probe: p.wrap('https://libraries.minecraft.net/' + rel)
      });
    });

    var usable = [];
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i];
      var ok = false;
      var lastMsg = '';
      for (var attempt = 0; attempt < 2 && !ok; attempt++) {
        try {
          var res = await fetchWith(c.probe, { headers: { Range: 'bytes=0-255' } }, 7000, ctx.signal);
          ok = true;
          usable.push(c);
          ctx.log('  ✓ 依赖库源可用：' + c.name + '（HTTP ' + res.status + '）');
        } catch (e) {
          if (e.code === 'E_ABORT') throw e;
          lastMsg = e.message;
          if (attempt === 0) await sleep(350);
        }
      }
      if (!ok) ctx.log('  ✗ 依赖库源不可用：' + c.name + '（' + lastMsg + '）');
    }
    return usable;
  }

  async function probeAssetHosts(health, ctx, version, sampleHash) {
    var cands = [];
    SOURCES.forEach(function (s) {
      if (health[s.id] && s.asset && sampleHash) {
        cands.push({ name: s.name, make: s.asset, probe: s.asset(sampleHash) });
      }
    });
    cands.push({
      name: ASSET_CDN.name,
      make: function (hash, key) { return ASSET_CDN.url(version, key); },
      probe: ASSET_CDN.url(version, 'minecraft/lang/en_us.json'),
      needsKey: true, lenient: true
    });
    if (ctx.proxy && sampleHash) {
      cands.unshift({
        name: '自定义代理',
        make: function (hash) { return viaProxy('https://resources.download.minecraft.net/' + hash.slice(0, 2) + '/' + hash, ctx.proxy); },
        probe: viaProxy('https://resources.download.minecraft.net/' + sampleHash.slice(0, 2) + '/' + sampleHash, ctx.proxy)
      });
    }
    var usable = [];
    for (var i = 0; i < cands.length; i++) {
      try {
        var res = await fetchWith(cands[i].probe, { headers: { Range: 'bytes=0-255' } }, 7000, ctx.signal);
        usable.push(cands[i]);
        ctx.log('  ✓ 资源源可用：' + cands[i].name + '（HTTP ' + res.status + '）');
      } catch (e) {
        ctx.log('  ✗ 资源源不可用：' + cands[i].name + '（' + e.message + '）');
      }
    }
    return usable;
  }

  /* ---------------- 主流程 ---------------- */

  async function resolve(version, opts) {
    opts = opts || {};
    var t0 = Date.now();
    var ctx = {
      signal: opts.signal,
      proxy: readProxy(),
      publicProxies: publicProxies(),
      hostFail: {},
      hostOk: {},
      deadHost: {},
      doneKeys: {},
      stageName: 'health',
      stats: {
        downloaded: 0, cached: 0, verified: 0, unverified: 0,
        bytes: 0, sourceUsed: {}, failed: 0, skipped: [], processed: 0
      },
      log: opts.onLog || function () {},
      stage: function (name) {
        ctx.stageName = name;
        if (opts.onProgress) {
          opts.onProgress({
            stage: name,
            label: STAGE_LABEL[name] || name,
            done: ctx.stats.processed,
            total: ctx.total || 0,
            bytes: ctx.stats.bytes
          });
        }
      }
    };

    ctx.log('=== 开始解析 Minecraft ' + version + '（静默模式，不跳转、不弹下载）===');
    if (ctx.proxy) {
      ctx.log('已启用自定义代理：' + ctx.proxy + '（直连失败后经代理重试）');
    } else {
      ctx.log('未启用自定义代理（设置 → 下载代理）');
    }
    ctx.log(ctx.publicProxies.length
      ? '公共代理兜底：已开启（' + ctx.publicProxies.map(function (p) { return p.name; }).join('、') + '）'
      : '公共代理兜底：已关闭（设置 → 搜索 → 允许公共代理兜底）');
    if (WEB_VERSIONS.indexOf(version) >= 0) {
      ctx.log('提示：' + version + ' 同时存在网页客户端；本次按本地客户端资源流程处理。');
    }

    var health = await healthCheck(ctx);
    ctx.stage('health');

    // 1) 元数据
    var metaRes = await resolveMeta(version, health, ctx);
    var meta = metaRes.meta;
    var osName = currentOs();
    ctx.log('当前系统识别为：' + osName);

    // 缓存版本 JSON（本地启动器需要 versions/<id>/<id>.json）
    try {
      await cachePut('meta/' + version + '.json', new Blob([JSON.stringify(meta, null, 2)], { type: 'application/json' }));
    } catch (e) { ctx.log('版本 JSON 缓存失败：' + e.message); }

    // 2) 客户端 jar
    ctx.stage('client');
    var clientDl = (meta.downloads && meta.downloads.client) || null;
    var clientUrls = [];
    SOURCES.forEach(function (s) {
      if (health[s.id] && s.client) clientUrls.push({ url: s.client(version), label: s.name });
    });
    if (clientDl && clientDl.url) clientUrls.push({ url: clientDl.url, label: 'Mojang 官方源' });
    if (!clientUrls.length) throw err('E_NO_SOURCE', '没有任何可用的客户端下载地址', 'client');

    ctx.log('下载客户端 jar（' + (clientDl ? fmtSize(clientDl.size) : '大小未知') + '）…');
    var clientBlob = (await downloadOne({
      key: 'client/' + version + '.jar',
      urls: clientUrls,
      sha1: clientDl && clientDl.sha1,
      size: clientDl && clientDl.size,
      label: '客户端 ' + version
    }, ctx)).blob;
    ctx.log('客户端就绪：' + fmtSize(clientBlob.size));

    // 3) 依赖库
    ctx.stage('libraries');
    ctx.log('探测依赖库下载源…');
    var mavens = await probeMavenHosts(health, ctx, version);
    if (!mavens.length) {
      throw err('E_LIB_SOURCE', '所有依赖库下载源均不可用（多为跨域拦截），已阻止启动。' +
        (ctx.proxy ? '已配置自定义代理但仍失败，请检查代理是否可用。'
          : '请在「设置 → 下载代理」填写代理并启用，或在「设置 → 搜索」打开「允许公共代理兜底」。'), 'libraries');
    }
    ctx.log('可用依赖库源：' + mavens.map(function (m) { return m.name; }).join('、'));

    var libEntries = [];
    (meta.libraries || []).forEach(function (lib) {
      if (!osAllowed(lib, osName)) return;
      var dl = lib.downloads && lib.downloads.artifact;
      var rel = (dl && dl.path) || libraryPath(lib.name);
      if (!rel) return;
      var urls = mavens.map(function (m) { return { url: m.make(rel), label: m.name }; });
      libEntries.push({
        key: 'libs/' + rel,
        rel: rel,
        urls: urls,
        sha1: dl && dl.sha1,
        size: dl && dl.size,
        label: rel
      });
      // natives（Windows 等平台）
      var cls = lib.downloads && lib.downloads.classifiers;
      if (cls) {
        var nk = 'natives-' + osName;
        var nat = cls[nk];
        if (nat) {
          var nrel = nat.path || rel;
          var nurls = mavens.map(function (m) { return { url: m.make(nrel), label: m.name }; });
          if (nat.url) nurls.push({ url: nat.url, label: 'Mojang 官方源' });
          libEntries.push({
            key: 'natives/' + nrel, rel: nrel, urls: nurls,
            sha1: nat.sha1, size: nat.size, label: nrel + '（native）'
          });
        }
      }
    });

    ctx.total = libEntries.length + 1;
    await runPool(libEntries, LIMITS.concurrency, async function (t) {
      try {
        await downloadOne(t, ctx);
      } catch (e) {
        if (e.code === 'E_ABORT') throw e;
        // 依赖库允许个别失败，但必须记录，后面校验阶段会判定
        ctx.stats.failed++;
        ctx.stats.skipped.push({ path: t.rel, reason: e.message });
        ctx.log('  ! 依赖库缺失：' + t.rel + '（' + e.message + '）');
      }
      ctx.stats.processed++;
      if (opts.onProgress) {
        opts.onProgress({
          stage: 'libraries', label: STAGE_LABEL.libraries,
          done: ctx.stats.processed, total: ctx.total, bytes: ctx.stats.bytes
        });
      }
    });
    // 第二轮回填：镜像偶发抖动常导致个别文件失败，单独补一次
    var failedTasks = libEntries.filter(function (t) { return !ctx.doneKeys[t.key]; });
    if (failedTasks.length) {
      ctx.log('有 ' + failedTasks.length + ' 个依赖首次失败，进行第 2 轮重试…', 'warn');
      for (var fi = 0; fi < failedTasks.length && fi < 40; fi++) {
        if (ctx.signal && ctx.signal.aborted) break;
        await sleep(300);
        try {
          await downloadOne(failedTasks[fi], ctx);
          ctx.stats.failed = Math.max(0, ctx.stats.failed - 1);
          ctx.log('  ↻ 重试成功：' + failedTasks[fi].rel, 'ok');
        } catch (e) {
          if (e.code === 'E_ABORT') throw e;
        }
      }
    }
    var stillMissing = libEntries.filter(function (t) { return !ctx.doneKeys[t.key]; }).length;
    ctx.log('依赖库完成：成功 ' + (libEntries.length - stillMissing) + ' / ' + libEntries.length +
      (stillMissing ? '（仍缺 ' + stillMissing + ' 个）' : ''), stillMissing ? 'warn' : 'ok');

    // 4) 资源索引
    ctx.stage('assetIndex');
    var assetIndexId = (meta.assetIndex && meta.assetIndex.id) || meta.assets || '';
    var assetIndex = null;
    if (assetIndexId) {
      var aiUrls = [];
      SOURCES.forEach(function (s) {
        if (health[s.id] && s.assetIndex) aiUrls.push({ url: s.assetIndex(version), label: s.name });
      });
      if (meta.assetIndex && meta.assetIndex.url) aiUrls.push({ url: meta.assetIndex.url, label: 'Mojang 官方源' });
      try {
        var aiBlob = (await downloadOne({
          key: 'indexes/' + assetIndexId + '.json',
          urls: aiUrls,
          sha1: meta.assetIndex && meta.assetIndex.sha1,
          size: meta.assetIndex && meta.assetIndex.size,
          label: '资源索引 ' + assetIndexId
        }, ctx)).blob;
        assetIndex = JSON.parse(await aiBlob.text());
        ctx.log('资源索引就绪：' + assetIndexId + '，对象 ' + Object.keys(assetIndex.objects || {}).length + ' 个');
      } catch (e) {
        if (e.code === 'E_ABORT') throw e;
        ctx.log('资源索引获取失败：' + e.message + '（将继续，游戏内音效/语言可能缺失）');
      }
    }

    // 5) 资源文件（默认抽样，避免一次拉取数千个小文件）
    ctx.stage('assets');
    var mode = opts.assets || 'sample';
    var assetKeys = [];
    if (assetIndex && assetIndex.objects && mode !== 'none') {
      var all = Object.keys(assetIndex.objects);
      var priority = ['minecraft/lang/zh_cn.json', 'minecraft/lang/en_us.json',
        'icons/icon_16x16.png', 'icons/icon_32x32.png', 'minecraft/font/default.json'];
      priority.forEach(function (k) { if (assetIndex.objects[k]) assetKeys.push(k); });
      if (mode === 'full') {
        assetKeys = all.slice(0, LIMITS.assetMax);
        ctx.log('按完整模式拉取资源 ' + assetKeys.length + ' 个（上限 ' + LIMITS.assetMax + '）');
      } else {
        var rest = all.filter(function (k) { return assetKeys.indexOf(k) < 0; }).slice(0, LIMITS.assetSample);
        assetKeys = assetKeys.concat(rest);
        ctx.log('抽样拉取资源 ' + assetKeys.length + ' 个（完整资源可在配置中改为完整模式）');
      }
    }

    var assetHosts = [];
    if (assetKeys.length) {
      ctx.log('探测资源文件下载源…');
      assetHosts = await probeAssetHosts(health, ctx, version, assetIndex.objects[assetKeys[0]].hash);
    }
    var assetTasks = assetKeys.map(function (k) {
      var obj = assetIndex.objects[k];
      var urls = assetHosts.map(function (h) {
        return { url: h.needsKey ? h.make(obj.hash, k) : h.make(obj.hash), label: h.name, lenient: !!h.lenient };
      });
      if (assetIndex && assetIndex.virtual) { /* 虚拟资源仍在 objects 中 */ }
      return {
        key: 'objects/' + obj.hash,
        rel: 'assets/objects/' + obj.hash.slice(0, 2) + '/' + obj.hash,
        urls: urls,
        sha1: obj.hash,
        size: obj.size,
        label: k
      };
    });

    var assetFail = 0;
    if (assetTasks.length) {
      await runPool(assetTasks, 6, async function (t) {
        try { await downloadOne(t, ctx); }
        catch (e) {
          if (e.code === 'E_ABORT') throw e;
          assetFail++;
          ctx.log('  ! 资源缺失：' + t.label + '（' + e.message + '）');
        }
        ctx.stats.processed++;
      });
      ctx.log('资源文件完成：成功 ' + (assetTasks.length - assetFail) + ' / ' + assetTasks.length);
    }

    // 6) 生成配置
    ctx.stage('configure');
    var plan = buildPlan(meta, version, opts, {
      assetIndexId: assetIndexId,
      libEntries: libEntries,
      clientSize: clientBlob.size
    });
    plan.assets = assetKeys.filter(function (k) {
      return assetIndex && assetIndex.objects[k];
    }).map(function (k) { return assetIndex.objects[k].hash; });
    ctx.log('启动配置生成：mainClass=' + plan.mainClass + '，classpath ' + plan.classpath.length +
      ' 项，资源文件 ' + plan.assets.length + ' 个，内存 ' + plan.memoryMB + ' MB');

    // 7) 校验
    ctx.stage('verify');
    var verify = await verifyPlan(plan, ctx);
    ctx.log('校验结果：通过 ' + verify.ok + ' 项，缺失 ' + verify.missing.length + ' 项，跳过校验 ' + verify.unverified + ' 项');
    if (verify.missing.length) {
      var shortList = verify.missing.map(function (p) { return p.replace(/^libraries\//, ''); });
      ctx.log('缺失清单（共 ' + shortList.length + ' 项）：');
      shortList.slice(0, 20).forEach(function (p) { ctx.log('  - ' + p); });
      if (shortList.length > 20) ctx.log('  … 其余 ' + (shortList.length - 20) + ' 项见控制台');
      var steps = [];
      if (!ctx.proxy) steps.push('在「设置 → 下载代理」填写一个可用代理并勾选启用');
      if (!ctx.publicProxies.length) steps.push('在「设置 → 搜索」打开「允许公共代理兜底」');
      steps.push('确认网络能访问 repo.spongepowered.org（本流程唯一公开的 Mojang 私有构件源）');
      steps.push('上述都无效时换一个版本重试，或改用本地启动器自行补全依赖');
      var stepText = steps.map(function (t, i) {
        return ['①', '②', '③', '④', '⑤'][i] + t;
      }).join('；');
      throw err('E_VERIFY',
        '资源不完整（缺失 ' + shortList.length + ' 项），已阻止启动。缺失：' +
        shortList.slice(0, 6).join('、') + (shortList.length > 6 ? ' 等' : '') +
        '。处理步骤：' + stepText, 'verify', verify.missing);
    }

    var elapsed = Date.now() - t0;
    ctx.log('=== 资源准备完成：' + fmtSize(ctx.stats.bytes) + '，用时 ' + (elapsed / 1000).toFixed(1) + 's ===');

    return {
      ok: true,
      version: version,
      source: metaRes.source,
      meta: meta,
      plan: plan,
      assetIndex: assetIndex,
      stats: ctx.stats,
      verify: verify,
      elapsedMs: elapsed
    };
  }

  /* ---------------- 启动配置 ---------------- */

  function fillArgs(args, ctxVars) {
    return (args || []).map(function (a) {
      return String(a).replace(/\$\{([a-z_]+)\}/g, function (m, k) {
        return ctxVars[k] != null ? ctxVars[k] : m;
      });
    });
  }

  function buildPlan(meta, version, opts, extra) {
    extra = extra || {};
    var osName = currentOs();
    var memory = opts.memoryMB || 4096;
    var vars = {
      auth_player_name: 'Player',
      version_name: version,
      game_directory: '.',
      assets_root: 'assets',
      assets_index_name: extra.assetIndexId || 'legacy',
      auth_uuid: '0',
      auth_access_token: '0',
      user_type: 'legacy',
      version_type: 'release',
      natives_directory: 'versions/' + version + '/natives',
      launcher_name: 'niao-web-launcher',
      launcher_version: '1.0'
    };

    var classpath = ['versions/' + version + '/' + version + '.jar'];
    (extra.libEntries || []).forEach(function (e) {
      if (e.rel && e.rel.indexOf('natives/') !== 0) classpath.push('libraries/' + e.rel);
    });

    var sep = osName === 'windows' ? ';' : ':';
    var jvmArgs = ['-Xmx' + memory + 'm', '-Xms' + Math.round(memory / 2) + 'm',
      '-Djava.library.path=versions/' + version + '/natives',
      '-Dminecraft.launcher.brand=niao-web-launcher',
      '-Dminecraft.launcher.version=1.0',
      '-cp', classpath.join(sep)];

    var gameArgs = [];
    if (meta.minecraftArguments) {
      gameArgs = String(meta.minecraftArguments).split(/\s+/);
    } else if (meta.arguments && meta.arguments.game) {
      gameArgs = meta.arguments.game.filter(function (a) { return typeof a === 'string'; });
    }

    return {
      format: 'niao-launch-plan/1',
      id: 'niao-' + version,
      name: '鸟国网站 ' + version,
      mcVersion: version,
      mainClass: meta.mainClass || '',
      jar: 'versions/' + version + '/' + version + '.jar',
      assetIndex: extra.assetIndexId || '',
      classpath: classpath,
      jvmArgs: jvmArgs,
      gameArgs: fillArgs(gameArgs, vars),
      memoryMB: memory,
      natives: 'versions/' + version + '/natives',
      launcher: opts.launcher || null,
      createdAt: new Date().toISOString()
    };
  }

  /* ---------------- 校验 ---------------- */

  async function verifyPlan(plan, ctx) {
    var missing = [];
    var ok = 0;
    var unverified = 0;
    for (var i = 0; i < plan.classpath.length; i++) {
      var p = plan.classpath[i];
      var key = p.indexOf('versions/') === 0 ? 'client/' + plan.mcVersion + '.jar' : 'libs/' + p.replace(/^libraries\//, '');
      var b = await cacheGet(key);
      if (!b || !b.size) missing.push(p);
      else ok++;
    }
    if (!plan.assetIndex) unverified++;
    return { ok: ok, missing: missing, unverified: unverified };
  }

  /* ---------------- 写入本地实例目录 ---------------- */

  async function materialize(plan, dirHandle, opts) {
    opts = opts || {};
    var log = opts.onLog || function () {};
    if (!dirHandle) throw err('E_NO_DIR', '还没有选择实例目录');
    var granted = await ensurePermission(dirHandle, 'readwrite');
    if (!granted) throw err('E_FS_DENIED', '实例目录写入权限被拒绝');

    log('开始写入实例目录：' + dirHandle.name);
    var root = dirHandle;

    async function ensure(parts) {
      var d = root;
      for (var i = 0; i < parts.length; i++) d = await d.getDirectoryHandle(parts[i], { create: true });
      return d;
    }
    async function put(path, blob) {
      var seg = path.split('/');
      var name = seg.pop();
      var dir = await ensure(seg);
      var fh = await dir.getFileHandle(name, { create: true });
      var w = await fh.createWritable();
      await w.write(blob);
      await w.close();
    }

    var written = 0;

    // 客户端 jar
    var jar = await cacheGet('client/' + plan.mcVersion + '.jar');
    if (!jar) throw err('E_MISSING', '缓存中缺少客户端 jar');
    await put('versions/' + plan.mcVersion + '/' + plan.mcVersion + '.jar', jar);
    written++;

    // 依赖库
    for (var i = 0; i < plan.classpath.length; i++) {
      var p = plan.classpath[i];
      if (p.indexOf('libraries/') !== 0) continue;
      var rel = p.replace(/^libraries\//, '');
      var b = await cacheGet('libs/' + rel);
      if (!b) { log('  ! 跳过缺失库：' + rel); continue; }
      await put('libraries/' + rel, b);
      written++;
    }

    // 版本 JSON
    var vjson = await cacheGet('meta/' + plan.mcVersion + '.json');
    if (vjson) {
      await put('versions/' + plan.mcVersion + '/' + plan.mcVersion + '.json', vjson);
      written++;
    }

    // 资源索引
    if (plan.assetIndex) {
      var idx = await cacheGet('indexes/' + plan.assetIndex + '.json');
      if (idx) { await put('assets/indexes/' + plan.assetIndex + '.json', idx); written++; }
    }

    // 资源对象
    var assetHashes = plan.assets || [];
    for (var a = 0; a < assetHashes.length; a++) {
      var h = assetHashes[a];
      var ab = await cacheGet('objects/' + h);
      if (!ab) { log('  ! 跳过缺失资源：' + h.slice(0, 8)); continue; }
      await put('assets/objects/' + h.slice(0, 2) + '/' + h, ab);
      written++;
    }

    // 启动脚本与配置
    var text = JSON.stringify(plan, null, 2);
    await put('launch-plan.json', new Blob([text], { type: 'application/json' }));

    var bat = buildCmd(plan);
    await put('niao-launch.cmd', new Blob(['\ufeff' + bat], { type: 'text/plain' }));
    written += 2;

    log('已写入 ' + written + ' 个文件到 ' + dirHandle.name + '（含 niao-launch.cmd / launch-plan.json）');
    return { written: written, dirName: dirHandle.name };
  }

  function buildCmd(plan) {
    var launcher = plan.launcher && plan.launcher.path ? plan.launcher.path : '';
    var lines = [
      '@echo off',
      'chcp 65001 >nul',
      'title 启动 ' + plan.name,
      'cd /d "%~dp0"'
    ];
    if (launcher) {
      lines.push('start "" "' + launcher + '"');
      lines.push('if errorlevel 1 (');
      lines.push('  echo 未找到启动器：' + launcher);
      lines.push('  pause');
      lines.push(')');
    } else {
      lines.push('echo 未配置启动器路径，请在站点「实例管理」中选择启动器后重新生成。');
      lines.push('pause');
    }
    lines.push('rem 内存 ' + plan.memoryMB + 'MB · 版本 ' + plan.mcVersion);
    return lines.join('\r\n') + '\r\n';
  }

  /* ---------------- 启动桥 ---------------- */

  function readBridge() {
    try { return JSON.parse(localStorage.getItem(BRIDGE_KEY) || '{}') || {}; }
    catch (e) { return {}; }
  }

  function enableBridge(flag) {
    var b = readBridge();
    b.enabled = !!flag;
    b.updatedAt = new Date().toISOString();
    try { localStorage.setItem(BRIDGE_KEY, JSON.stringify(b)); } catch (e) { /* 忽略 */ }
    return b;
  }

  async function launch(plan, opts) {
    opts = opts || {};
    var log = opts.onLog || function () {};
    if (!plan) return { ok: false, code: 'E_PLAN', message: '缺少启动配置' };
    var bridge = readBridge();
    if (!bridge.enabled) {
      log('未启用本地协议桥（niao-mc://），无法从浏览器直接启动本地客户端。');
      return {
        ok: false,
        code: 'E_NO_BRIDGE',
        message: '资源与配置已就绪，但浏览器的安全模型不允许直接执行本地程序；' +
          '请用本地启动器打开实例目录，或在站内启用 niao-mc:// 协议桥后重试。'
      };
    }
    try {
      log('通过 niao-mc:// 协议桥请求启动…');
      global.location.href = 'niao-mc://launch/' + encodeURIComponent(plan.id);
      return { ok: true, mode: 'protocol' };
    } catch (e) {
      return { ok: false, code: 'E_BRIDGE', message: '协议启动失败：' + e.message };
    }
  }

  /* ---------------- 对外接口 ---------------- */

  global.McResolver = {
    WEB_VERSIONS: WEB_VERSIONS,
    SOURCES: SOURCES,
    STAGE_LABEL: STAGE_LABEL,
    LIMITS: LIMITS,
    EXTRA_MAVEN: EXTRA_MAVEN,
    CORS_PROXIES: CORS_PROXIES,
    ASSET_CDN: ASSET_CDN,
    readProxy: readProxy,
    viaProxy: viaProxy,
    publicProxies: publicProxies,
    resolve: resolve,
    materialize: materialize,
    buildPlan: buildPlan,
    buildCmd: buildCmd,
    verifyPlan: verifyPlan,
    launch: launch,
    readBridge: readBridge,
    enableBridge: enableBridge,
    saveDirHandle: saveDirHandle,
    loadDirHandle: loadDirHandle,
    ensurePermission: ensurePermission,
    cacheStats: cacheStats,
    cacheGet: cacheGet,
    cacheClear: cacheClear,
    healthCheck: async function (log) {
      var ctx = { log: log || function () {}, signal: null, stats: {} };
      return healthCheck(ctx);
    },
    _resetHealth: function () { healthCache = null; }
  };
})(window);
