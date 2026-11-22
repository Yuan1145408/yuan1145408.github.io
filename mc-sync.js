/* ============================================================
   鸟国网站 · 我的世界实例同步引擎
   ------------------------------------------------------------
   职责：
   1) 扫描本地实例目录 → 生成清单（大小 / git blob sha / sha256 / 分块）
   2) 版本识别：mmc-pack.json → versions/*.json → latest.log → 手填
   3) 三方差异（本地 / 上次同步基线 / 云端最新）与冲突分类
   4) 下载缓存（Cache Storage，按内容哈希去重，分块级续传）
   5) 写入本地目录（File System Access）并校验
   6) 生成启动脚本与协议注册表（浏览器只当入口，游戏仍本地运行）
   ============================================================ */
(function (global) {
  'use strict';

  var SCHEMA = 'niao-mc-instance/2';
  var CACHE_NAME = 'niao-mc-files-v1';
  var CACHE_HOST = 'https://niao-mc-cache.local/';
  var RECORD_PREFIX = 'niao.mc.sync.';

  // 默认纳入 / 排除规则：只同步“最小可复现集”，可重建的部分不占仓库体积
  var DEFAULT_INCLUDE = ['mods/', 'config/', 'defaultconfigs/', 'saves/', 'resourcepacks/', 'shaderpacks/',
    'datapacks/', 'kubejs/', 'scripts/', 'options.txt', 'servers.dat', 'optionsof.txt', 'realms_persistence.json'];
  var DEFAULT_EXCLUDE = ['libraries/', 'assets/', 'versions/', 'logs/', 'crash-reports/', '.git/', 'backups/',
    'screenshots/', '.cache/', 'temp/', 'usercache.json', 'launcher_profiles.json', 'launcher_accounts.json',
    'session.lock', '*.tmp', '*.log'];

  /* ---------------- 规则匹配 ---------------- */
  function compileRules(include, exclude) {
    function globMatch(pattern, str) {
      var re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
      return re.test(str);
    }
    function matchRule(rule, path) {
      var isDir = /\/$/.test(rule);
      var body = rule.replace(/\/$/, '');
      if (isDir) return path === body || path.indexOf(body + '/') === 0;
      if (body.indexOf('/') < 0) {
        // 不含路径分隔符的规则同时匹配文件名与完整路径
        return globMatch(body, path.split('/').pop()) || globMatch(body, path);
      }
      return globMatch(body, path);
    }
    var inc = (include || DEFAULT_INCLUDE);
    var exc = (exclude || DEFAULT_EXCLUDE);
    return {
      accept: function (path) {
        var p = String(path || '').replace(/^\/+/, '');
        if (exc.some(function (r) { return matchRule(r, p); })) return false;
        if (!inc.length) return true;
        return inc.some(function (r) { return matchRule(r, p); });
      },
      include: inc, exclude: exc
    };
  }

  /* ---------------- 目录遍历 ---------------- */
  // 支持 File System Access 的目录句柄，或 [{path, file}] 列表（<input webkitdirectory> 回退）
  async function walkDir(dirHandle, onFile, prefix) {
    prefix = prefix || '';
    for await (const entry of dirHandle.values()) {
      const path = prefix ? prefix + '/' + entry.name : entry.name;
      if (entry.kind === 'file') {
        await onFile(path, await entry.getFile(), entry);
      } else if (entry.kind === 'directory') {
        await walkDir(entry, onFile, path);
      }
    }
  }

  /**
   * 扫描实例目录并生成可上传条目
   * @param {{dirHandle?:object, files?:Array<{path:string,file:File}>, include?:string[], exclude?:string[],
   *          onProgress?:function, signal?:object, chunkSize?:number, readBytes?:boolean}} opts
   */
  async function scanInstance(opts) {
    var rules = compileRules(opts.include, opts.exclude);
    var chunkSize = opts.chunkSize || global.McGh.CHUNK_SIZE;
    var entries = [], skipped = [], totalBytes = 0, index = 0;

    async function handle(path, file) {
      if (opts.signal && opts.signal.aborted) throw new global.McGh.GhError('E_ABORT', '操作已取消');
      if (!rules.accept(path)) { skipped.push({ path: path, size: file.size, reason: '规则排除' }); return; }
      if (file.size === 0) { skipped.push({ path: path, size: 0, reason: '空文件' }); return; }
      index++;
      // 单文件读取，算两个哈希后立即释放，避免整份实例占内存
      var bytes = new Uint8Array(await file.arrayBuffer());
      var gitSha = await global.McGh.gitBlobSha(bytes);
      var hash = await global.McGh.sha256(bytes);
      var entry = {
        path: path, size: file.size, gitSha: gitSha, cid: hash,
        lastModified: file.lastModified || 0,
        file: file,
        chunked: bytes.length > chunkSize,
        chunkSize: chunkSize,
        partCount: bytes.length > chunkSize ? Math.ceil(bytes.length / chunkSize) : 0
      };
      bytes = null;
      totalBytes += file.size;
      entries.push(entry);
      if (opts.onProgress) opts.onProgress({ phase: 'scan', index: index, path: path, size: file.size, totalBytes: totalBytes });
    }

    if (opts.dirHandle) {
      await walkDir(opts.dirHandle, handle);
    } else if (opts.files) {
      // 先按路径排序，保证清单稳定
      var sorted = opts.files.slice().sort(function (a, b) { return a.path < b.path ? -1 : 1; });
      for (var i = 0; i < sorted.length; i++) await handle(sorted[i].path, sorted[i].file);
    }
    entries.sort(function (a, b) { return a.path < b.path ? -1 : 1; });
    return { entries: entries, skipped: skipped, totalBytes: totalBytes, fileCount: entries.length };
  }

  /* ---------------- 版本识别 ---------------- */
  var LOADER_RE = [
    { re: /net\.minecraftforge:forge:([\d.]+)-([\w.\-]+)/i, type: 'forge' },
    { re: /net\.neoforged:neoforge:([\w.\-]+)/i, type: 'neoforge' },
    { re: /net\.fabricmc:fabric-loader:([\w.\-]+)/i, type: 'fabric' },
    { re: /org\.quiltmc:quilt-loader:([\w.\-]+)/i, type: 'quilt' },
    { re: /com\.mumfrey:liteloader:([\w.\-]+)/i, type: 'liteloader' }
  ];

  function parseVersionJson(json) {
    var out = { mc: '', loader: null, rawId: json.id || '' };
    var id = String(json.id || '');
    var m = id.match(/^(\d+\.\d+(?:\.\d+)?)(?:[-_](forge|fabric|neoforge|quilt|liteloader)[-_]?([\w.\-]+))?/i);
    if (m) {
      out.mc = m[1];
      if (m[2]) out.loader = { type: m[2].toLowerCase(), version: m[3] || '' };
    }
    if (!out.mc && json.inheritsFrom) out.mc = String(json.inheritsFrom);
    if (!out.mc && json.clientVersion) out.mc = String(json.clientVersion);

    (json.libraries || []).forEach(function (lib) {
      var name = lib && (lib.name || (lib.downloads && lib.downloads.artifact && lib.downloads.artifact.path));
      if (!name) return;
      for (var i = 0; i < LOADER_RE.length; i++) {
        var hit = String(name).match(LOADER_RE[i].re);
        if (hit) {
          if (LOADER_RE[i].type === 'forge' && hit.length >= 3) {
            if (!out.mc) out.mc = hit[1];
            out.loader = { type: 'forge', version: hit[2] };
          } else {
            out.loader = { type: LOADER_RE[i].type, version: hit[1] };
          }
          return;
        }
      }
    });
    if (!out.mc && json.assetIndex && json.assetIndex.id) {
      // 极老版本没有 inheritsFrom 时，靠 assetIndex 不能反推，交给上层
    }
    return out;
  }

  // Prism / MultiMC 的 mmc-pack.json
  function parseMmcPack(json) {
    var out = { mc: '', loader: null };
    (json.components || []).forEach(function (c) {
      var uid = String(c.uid || '');
      if (uid === 'net.minecraft') out.mc = String(c.version || '');
      else if (/forge/i.test(uid) && uid !== 'net.neoforged') out.loader = { type: 'forge', version: String(c.version || '') };
      else if (/neoforge/i.test(uid)) out.loader = { type: 'neoforge', version: String(c.version || '') };
      else if (/fabric-loader/i.test(uid)) out.loader = { type: 'fabric', version: String(c.version || '') };
      else if (/quilt-loader/i.test(uid)) out.loader = { type: 'quilt', version: String(c.version || '') };
    });
    // NeoForge 的版本号常形如 20.4.237（对应 1.20.4），可反推
    if (out.loader && out.loader.type === 'neoforge' && !out.mc) {
      var mm = out.loader.version.match(/^(\d+)\.(\d+)/);
      if (mm) out.mc = mm[1] + '.' + mm[2];
    }
    return out;
  }

  function parseLog(text) {
    if (!text) return { mc: '', loader: null };
    var out = { mc: '', loader: null };
    var line = text.split(/\r?\n/).slice(0, 80).join('\n');
    var m1 = line.match(/Loading Minecraft\s+([\d.]+)\s+with\s+(Forge|NeoForge|Fabric Loader|Quilt Loader)\s+([\w.\-+]+)/i);
    if (m1) {
      out.mc = m1[1];
      var t = m1[2].toLowerCase();
      out.loader = { type: t.indexOf('forge') === 0 ? 'forge' : (t.indexOf('neo') === 0 ? 'neoforge' : (t.indexOf('quilt') >= 0 ? 'quilt' : 'fabric')), version: m1[3] };
      return out;
    }
    var m2 = line.match(/mixin[^\n]*?(?:Minecraft|MC)\s*([\d.]+)/i);
    if (m2) out.mc = m2[1];
    return out;
  }

  /**
   * 版本识别：priority = mmc-pack.json > versions/*.json > logs/latest.log > 手填
   * @param {Object<string,string>} textMap 路径 → 文本内容（只需包含关键文件）
   */
  function detectVersion(textMap) {
    var result = { mc: '', loader: null, source: '', candidates: [] };

    function tryJson(path, parser, label) {
      if (!textMap[path]) return false;
      try {
        var v = parser(JSON.parse(textMap[path]));
        if (v.mc || v.loader) {
          result.mc = result.mc || v.mc;
          result.loader = result.loader || v.loader;
          result.candidates.push({ source: label, mc: v.mc, loader: v.loader });
          return true;
        }
      } catch (_) { /* 忽略损坏的 json */ }
      return false;
    }

    if (tryJson('mmc-pack.json', parseMmcPack, 'mmc-pack.json')) result.source = 'mmc-pack';
    // mmc-pack 可能只给了 MC 版本，继续用 versions/*.json 补加载器
    if (!result.mc || !result.loader) {
      var vkeys = Object.keys(textMap).filter(function (p) {
        return /^versions\/[^\/]+\/[^\/]+\.json$/.test(p);
      });
      for (var i = 0; i < vkeys.length; i++) {
        var before = result.loader;
        if (tryJson(vkeys[i], parseVersionJson, vkeys[i])) {
          if (!result.source) result.source = 'version-json';
          if (result.loader && !before) break;
        }
      }
    }
    if (!result.source && textMap['logs/latest.log']) {
      var lg = parseLog(textMap['logs/latest.log']);
      if (lg.mc || lg.loader) {
        result.mc = lg.mc; result.loader = lg.loader;
        result.source = 'latest.log';
        result.candidates.push({ source: 'logs/latest.log', mc: lg.mc, loader: lg.loader });
      }
    }
    if (!result.mc) result.source = result.source || 'none';
    return result;
  }

  /* ---------------- 清单 ---------------- */
  async function buildManifest(scan, meta) {
    var files = scan.entries.map(function (e) {
      var base = {
        path: e.path, size: e.size, cid: e.cid, gitSha: e.gitSha, mtime: e.lastModified || 0
      };
      if (e.chunked) {
        base.chunked = true;
        base.partCount = e.partCount;
        base.chunkSize = e.chunkSize;
        base.parts = [];
        var per = e.size / e.partCount;
        for (var pi = 0; pi < e.partCount; pi++) {
          base.parts.push({
            path: 'parts/' + e.path.replace(/[^\w.\-\/]/g, '_') + '.part' + String(pi).padStart(3, '0'),
            size: pi === e.partCount - 1 ? e.size - Math.floor(per) * pi : Math.floor(per)
          });
        }
      }
      return base;
    });
    var worlds = files.filter(function (f) { return f.path.indexOf('saves/') === 0; })
      .map(function (f) { return f.path.split('/')[1]; })
      .filter(function (v, i, a) { return v && a.indexOf(v) === i; });

    var modList = files.filter(function (f) { return f.path.indexOf('mods/') === 0; })
      .map(function (f) {
        var n = f.path.split('/').pop();
        return { name: n.replace(/\.jar$/i, ''), file: f.path, size: f.size, cid: f.cid };
      });

    var fpSource = JSON.stringify({
      mc: meta.mc || '',
      loader: meta.loader || null,
      mods: modList.map(function (m) { return m.name + ':' + m.cid.slice(0, 12); }).sort()
    });
    var fingerprint = await global.McGh.sha256(global.McGh.utf8(fpSource));

    return {
      schema: SCHEMA,
      id: meta.id,
      name: meta.name || meta.id,
      description: meta.description || '',
      createdAt: meta.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: {
        mc: meta.mc || '',
        loader: meta.loader || null,
        source: meta.versionSource || 'manual',
        fingerprint: fingerprint
      },
      launch: {
        memoryMB: meta.memoryMB || 4096,
        jvmArgs: meta.jvmArgs || '-XX:+UseG1GC',
        launcher: meta.launcher || null,
        java: meta.java || ''
      },
      stats: {
        fileCount: files.length,
        totalSize: scan.totalBytes,
        worldCount: worlds.length,
        modCount: modList.length
      },
      worlds: worlds,
      mods: modList,
      files: files
    };
  }

  function validateManifest(m) {
    if (!m || typeof m !== 'object') throw new Error('清单为空');
    if (m.schema !== SCHEMA && m.schema !== 'niao-mc-instance/1') {
      var e = new global.McGh.GhError('E_SCHEMA', '清单版本 ' + m.schema + ' 不受支持');
      throw e;
    }
    if (!Array.isArray(m.files)) throw new Error('清单缺少 files 字段');
    return m;
  }

  /* ---------------- 差异与冲突 ---------------- */
  /**
   * 三方差异
   * @param {Object<string,{cid:string,size?:number}>} local 本地现状
   * @param {Object<string,{cid:string}>} base 上次同步基线（可为空 = 首次同步）
   * @param {Object<string,{cid:string,size:number}>} remote 云端最新
   * @param {{protectWorlds?:boolean}} opts
   */
  function diffThreeWay(local, base, remote, opts) {
    opts = opts || {};
    var protectWorlds = opts.protectWorlds !== false;
    var paths = {};
    [local, base, remote].forEach(function (map) {
      Object.keys(map || {}).forEach(function (p) { paths[p] = 1; });
    });

    var out = { download: [], keepLocal: [], deleteLocal: [], conflict: [], unchanged: [], localNew: [] };

    Object.keys(paths).sort().forEach(function (p) {
      var l = local[p], b = base[p], r = remote[p];
      var lc = l && l.cid, bc = b && b.cid, rc = r && r.cid;
      var isWorld = /^saves\//.test(p);
      var row = { path: p, local: l || null, base: b || null, remote: r || null, isWorld: isWorld };

      if (lc && rc && lc === rc) { out.unchanged.push(row); return; }
      if (!lc && !rc) { return; } // 两边都没有

      if (!bc) {
        // 没有基线：本地有云端有且不同 → 冲突；只有一边 → 单向操作
        if (lc && rc) { out.conflict.push(Object.assign(row, { reason: 'both-new' })); return; }
        if (rc) { out.download.push(row); return; }
        out.localNew.push(row); return;
      }
      // 有基线
      var localChanged = lc !== bc;
      var remoteChanged = rc !== bc;

      if (!localChanged && remoteChanged) {
        if (!rc) { out.deleteLocal.push(Object.assign(row, { reason: 'remote-deleted' })); return; }
        out.download.push(row); return;
      }
      if (localChanged && !remoteChanged) {
        if (!lc) { out.keepLocal.push(Object.assign(row, { reason: 'local-deleted' })); return; }
        out.keepLocal.push(Object.assign(row, { reason: 'local-modified' })); return;
      }
      if (localChanged && remoteChanged) {
        if (lc === rc) { out.unchanged.push(row); return; }
        // 本地改了、云端也改了 → 冲突；世界存档默认保护本地
        if (protectWorlds && isWorld) {
          out.conflict.push(Object.assign(row, { reason: 'world-both-modified', preferLocal: true }));
        } else {
          out.conflict.push(Object.assign(row, { reason: 'both-modified' }));
        }
        return;
      }
      // 两边都没变（但 cid 不等基线，理论上不会到这里）
      if (lc && rc && lc !== rc) out.conflict.push(Object.assign(row, { reason: 'unknown' }));
    });

    return out;
  }

  /* ---------------- 缓存 ---------------- */
  async function cacheOpen() {
    if (!global.caches) throw new global.McGh.GhError('E_QUOTA', '当前浏览器不支持缓存存储（Cache Storage）');
    return caches.open(CACHE_NAME);
  }
  function cacheKey(cid) { return CACHE_HOST + cid; }

  async function cacheGet(cid) {
    try {
      var c = await cacheOpen();
      var res = await c.match(cacheKey(cid));
      return res ? await res.blob() : null;
    } catch (e) { return null; }
  }
  async function cachePut(cid, blob) {
    try {
      var c = await cacheOpen();
      await c.put(cacheKey(cid), new Response(blob));
      return true;
    } catch (e) { return false; }
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

  /* ---------------- 本地目录读写 ---------------- */
  async function ensureDir(root, parts) {
    var dir = root;
    for (var i = 0; i < parts.length; i++) {
      dir = await dir.getDirectoryHandle(parts[i], { create: true });
    }
    return dir;
  }

  async function writeFileToDir(root, path, blob) {
    var seg = path.split('/');
    var name = seg.pop();
    var dir = await ensureDir(root, seg);
    try {
      var fh = await dir.getFileHandle(name, { create: true });
      var w = await fh.createWritable();
      await w.write(blob);
      await w.close();
      return true;
    } catch (e) {
      if (e && (e.name === 'NotAllowedError' || e.name === 'SecurityError')) {
        throw new global.McGh.GhError('E_FS_DENIED', '写入 ' + path + ' 被拒绝：' + e.message);
      }
      if (e && (e.name === 'NoModificationAllowedError' || e.name === 'InvalidStateError')) {
        throw new global.McGh.GhError('E_FS_LOCKED', path + ' 被占用，可能游戏正在运行。');
      }
      throw e;
    }
  }

  // 读取本地实例目录的“快速指纹”（大小 + 修改时间），用于不读全文的差异比较
  async function readLocalIndex(dirHandle, rules) {
    var map = {};
    async function walk(dir, prefix) {
      for await (var entry of dir.values()) {
        var p = prefix ? prefix + '/' + entry.name : entry.name;
        if (entry.kind === 'file') {
          var f = await entry.getFile();
          map[p] = { size: f.size, mtime: f.lastModified, file: f };
        } else if (entry.kind === 'directory') {
          if (rules && !rules.accept(p + '/x')) continue;
          await walk(entry, p);
        }
      }
    }
    await walk(dirHandle, '');
    return map;
  }

  /* ---------------- 同步记录 ---------------- */
  function recordKey(cfg) {
    return RECORD_PREFIX + [cfg.owner, cfg.repo, cfg.id].join('/');
  }
  function getRecord(cfg) {
    try { return JSON.parse(localStorage.getItem(recordKey(cfg)) || 'null'); } catch (e) { return null; }
  }
  function saveRecord(cfg, rec) {
    try { localStorage.setItem(recordKey(cfg), JSON.stringify(rec)); return true; }
    catch (e) { return false; }
  }
  function clearRecord(cfg) { try { localStorage.removeItem(recordKey(cfg)); } catch (e) {} }

  /**
   * 下载单个文件（含分块），带缓存与校验
   */
  async function fetchFile(cfg, manifest, fileEntry, commitSha, opts) {
    var McGh = global.McGh;
    var onProgress = opts && opts.onProgress || function () {};

    var cached = await cacheGet(fileEntry.cid);
    if (cached) {
      if (cached.size === fileEntry.size) return { blob: cached, fromCache: true };
      await cacheClearEntry(fileEntry.cid);
    }

    var bytes;
    if (fileEntry.chunked && Array.isArray(fileEntry.parts)) {
      var views = [];
      for (var i = 0; i < fileEntry.parts.length; i++) {
        var part = fileEntry.parts[i];
        var cachedPart = await cacheGet(part.gitSha);
        if (!cachedPart) {
          var pbytes = await McGh.withRetry(function () {
            return McGh.downloadBytes(McGh.rawUrl(cfg.owner, cfg.repo, commitSha, rootPrefix(cfg) + part.path));
          }, { retries: 2 });
          cachedPart = new Blob([pbytes]);
          await cachePut(part.gitSha, cachedPart);
        }
        views.push(new Uint8Array(await cachedPart.arrayBuffer()));
        onProgress(fileEntry.path, i + 1, fileEntry.parts.length);
      }
      bytes = new Uint8Array(views.reduce(function (n, v) { return n + v.length; }, 0));
      var off = 0;
      views.forEach(function (v) { bytes.set(v, off); off += v.length; });
    } else {
      bytes = await McGh.withRetry(function () {
        return McGh.downloadBytes(McGh.rawUrl(cfg.owner, cfg.repo, commitSha, rootPrefix(cfg) + 'files/' + fileEntry.path), {
          onProgress: function (r, t) { onProgress(fileEntry.path, r, t); }
        });
      }, { retries: 2 });
    }

    // 完整性校验：内容哈希必须与清单一致
    var got = await McGh.sha256(bytes);
    if (got !== fileEntry.cid) {
      var e = new McGh.GhError('E_HASH', '文件校验失败：' + fileEntry.path + '（期望 ' + fileEntry.cid.slice(0, 10) + '，实际 ' + got.slice(0, 10) + '）', { retryable: true });
      throw e;
    }
    var blob = new Blob([bytes]);
    await cachePut(fileEntry.cid, blob);
    return { blob: blob, fromCache: false };
  }
  async function cacheClearEntry(cid) {
    try { var c = await cacheOpen(); await c.delete(cacheKey(cid)); } catch (e) {}
  }
  function rootPrefix(cfg) {
    return ((cfg.root || '.mc-instances').replace(/^\/+|\/+$/g, '')) + '/' + cfg.id + '/';
  }

  /* ---------------- 启动 ---------------- */
  function buildLaunchPlan(manifest, launcher) {
    return {
      instanceId: manifest.id,
      name: manifest.name,
      mcVersion: manifest.version.mc,
      loader: manifest.version.loader,
      memoryMB: manifest.launch.memoryMB,
      jvmArgs: manifest.launch.jvmArgs,
      java: manifest.launch.java || '',
      launcher: launcher || manifest.launch.launcher || null,
      generatedAt: new Date().toISOString(),
      note: '本文件由鸟国网站生成：浏览器只负责同步与生成启动脚本，游戏本体由本地启动器运行。'
    };
  }

  function buildLaunchScript(plan, platform) {
    var mem = plan.memoryMB || 4096;
    var jvm = plan.jvmArgs || '';
    var launcherPath = plan.launcher && plan.launcher.path || '';
    if (platform === 'win') {
      var lines = [
        '@echo off',
        'chcp 65001 >nul',
        'title 启动 ' + (plan.name || plan.instanceId),
        'cd /d "%~dp0"'
      ];
      if (launcherPath) {
        if (plan.launcher.type === 'prism') {
          lines.push('start "" "' + launcherPath + '" --launch "' + plan.instanceId + '"');
        } else {
          lines.push('start "" "' + launcherPath + '"');
        }
        lines.push('if errorlevel 1 (');
        lines.push('  echo 未找到启动器，请检查 launch-plan.json 中的路径');
        lines.push('  pause');
        lines.push(')');
      } else {
        lines.push('echo 还没有配置启动器路径，请在本站“同步与启动”里选择启动器后重新生成。');
        lines.push('pause');
      }
      lines.push('rem 内存分配：' + mem + 'MB，JVM 参数：' + jvm);
      return lines.join('\r\n') + '\r\n';
    }
    var sh = [
      '#!/usr/bin/env bash',
      'cd "$(dirname "$0")" || exit 1',
      launcherPath ? ('"' + launcherPath + '"' + (plan.launcher.type === 'prism' ? ' --launch "' + plan.instanceId + '"' : '')) : 'echo "请先在 launch-plan.json 中配置启动器路径"'
    ];
    return sh.join('\n') + '\n';
  }

  // Windows 协议注册：让浏览器里的「启动」按钮能唤起本地脚本
  function buildProtocolReg(cmdPath) {
    var p = String(cmdPath || '%USERPROFILE%\\AppData\\Roaming\\.minecraft\\niao-launch.cmd').replace(/\\/g, '\\\\');
    return [
      'Windows Registry Editor Version 5.00',
      '',
      '[HKEY_CLASSES_ROOT\\niao-mc]',
      '@="URL:NIAO Minecraft Launcher"',
      '"URL Protocol"=""',
      '',
      '[HKEY_CLASSES_ROOT\\niao-mc\\shell\\open\\command]',
      '@="\\"' + p + '\\" \\"%1\\""',
      ''
    ].join('\r\n');
  }

  global.McSync = {
    SCHEMA: SCHEMA,
    DEFAULT_INCLUDE: DEFAULT_INCLUDE,
    DEFAULT_EXCLUDE: DEFAULT_EXCLUDE,
    compileRules: compileRules,
    scanInstance: scanInstance,
    detectVersion: detectVersion,
    parseVersionJson: parseVersionJson,
    parseMmcPack: parseMmcPack,
    parseLog: parseLog,
    buildManifest: buildManifest,
    validateManifest: validateManifest,
    diffThreeWay: diffThreeWay,
    cacheGet: cacheGet, cachePut: cachePut, cacheStats: cacheStats, cacheClear: cacheClear,
    ensureDir: ensureDir, writeFileToDir: writeFileToDir, readLocalIndex: readLocalIndex,
    getRecord: getRecord, saveRecord: saveRecord, clearRecord: clearRecord,
    fetchFile: fetchFile, rootPrefix: rootPrefix,
    buildLaunchPlan: buildLaunchPlan, buildLaunchScript: buildLaunchScript, buildProtocolReg: buildProtocolReg
  };
})(window);
