/* ============================================================
   鸟国网站 · 我的世界实例管理（界面层）
   ------------------------------------------------------------
   - 连接 GitHub（令牌只用于本页请求，默认存 sessionStorage）
   - 上传：选目录 → 扫描 / 版本识别 → 预检 → 增量提交
   - 同步：选目录 → 三方差异 → 冲突决策 → 下载写盘 → 生成启动脚本
   ============================================================ */
(function () {
  'use strict';

  var McGh = window.McGh, McSync = window.McSync;
  var $ = function (id) { return document.getElementById(id); };

  var LS = {
    CFG: 'niao.mc.gh.v1',
    TOKEN: 'niao.mc.gh.token',
    SESSION_TOKEN: 'niao.mc.gh.token.session'
  };

  var cfg = { owner: '', repo: '', branch: 'main', root: '.mc-instances' };
  var token = '';
  var connected = false;

  // 上传上下文
  var up = { dirHandle: null, files: null, scan: null, version: null, abort: null, ready: false, id: '' };
  // 同步上下文
  var sy = { dirHandle: null, manifest: null, commit: null, diff: null, cfgId: '', abort: null, rowChoice: {}, tab: 'conflict' };

  /* ---------------- 小工具 ---------------- */
  function show(el, yes) { if (el) el.hidden = !yes; }
  function logTo(el, line) {
    if (!el) return;
    el.hidden = false;
    var ts = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    el.textContent += '[' + ts + '] ' + line + '\n';
    el.scrollTop = el.scrollHeight;
  }
  function clearLog(el) { if (el) { el.textContent = ''; el.hidden = true; } }
  function fmtSize(n) {
    if (!n && n !== 0) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function errText(e) {
    if (!e) return '未知错误';
    if (e.code) return '[' + e.code + '] ' + (e.message || '') + (e.meta && e.meta.hint ? '\n→ ' + e.meta.hint : '\n→ ' + McGh.hintFor(e.code));
    return e.message || String(e);
  }
  function setBar(el, ratio) {
    if (!el) return;
    el.hidden = false;
    var i = el.querySelector('i');
    if (i) i.style.width = Math.max(0, Math.min(100, Math.round(ratio * 100))) + '%';
  }
  function downloadText(name, text, mime) {
    var blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  /* ---------------- 配置 ---------------- */
  function loadCfg() {
    try {
      var saved = JSON.parse(localStorage.getItem(LS.CFG) || 'null');
      if (saved) {
        cfg.owner = saved.owner || ''; cfg.repo = saved.repo || '';
        cfg.branch = saved.branch || 'main'; cfg.root = saved.root || '.mc-instances';
      }
    } catch (e) { /* 忽略 */ }
    $('miOwner').value = cfg.owner;
    $('miRepo').value = cfg.repo;
    $('miBranch').value = cfg.branch;
    $('miRoot').value = cfg.root;
    var remembered = localStorage.getItem(LS.TOKEN) || '';
    if (remembered) { token = remembered; $('miToken').value = remembered; $('miRemember').checked = true; }
    else {
      try { token = sessionStorage.getItem(LS.SESSION_TOKEN) || ''; } catch (e) { token = ''; }
      if (token) $('miToken').value = token;
    }
  }
  function saveCfg() {
    cfg.owner = $('miOwner').value.trim();
    cfg.repo = $('miRepo').value.trim();
    cfg.branch = $('miBranch').value.trim() || 'main';
    cfg.root = $('miRoot').value.trim() || '.mc-instances';
    try { localStorage.setItem(LS.CFG, JSON.stringify(cfg)); } catch (e) { /* 忽略 */ }
  }
  function saveToken() {
    token = $('miToken').value.trim();
    try { localStorage.removeItem(LS.TOKEN); sessionStorage.removeItem(LS.SESSION_TOKEN); } catch (e) {}
    if (!token) return;
    if ($('miRemember').checked) { try { localStorage.setItem(LS.TOKEN, token); } catch (e) {} }
    else { try { sessionStorage.setItem(LS.SESSION_TOKEN, token); } catch (e) {} }
  }

  /* ---------------- 连接 ---------------- */
  async function connect() {
    saveCfg(); saveToken();
    var log = $('miConnLog'), state = $('miConnState');
    clearLog(log);
    if (!token) { state.innerHTML = '<span class="mi-err">请先填写访问令牌</span>'; return; }
    if (!cfg.owner || !cfg.repo) { state.innerHTML = '<span class="mi-err">请填写仓库所有者与仓库名</span>'; return; }
    state.textContent = '正在验证…';
    var btn = $('miConnectBtn'); btn.disabled = true;
    try {
      var user = await McGh.getUser(token);
      logTo(log, '令牌属于账号：' + user.login);
      var repo = await McGh.getRepo(token, cfg.owner, cfg.repo);
      var canWrite = !!(repo.permissions && repo.permissions.push);
      logTo(log, '仓库：' + repo.full_name + '（' + (repo.private ? '私有' : '公开') + '，默认分支 ' + (repo.default_branch || 'main') + '）');
      logTo(log, '写入权限：' + (canWrite ? '已具备' : '缺失（只读）'));
      if (repo.size) logTo(log, '仓库当前体积：约 ' + fmtSize(repo.size * 1024));
      if (!canWrite) throw new McGh.GhError('E_SCOPE', '令牌对 ' + repo.full_name + ' 没有写入权限');
      var ref = await McGh.getRef(token, cfg.owner, cfg.repo, cfg.branch);
      logTo(log, '分支 ' + cfg.branch + '：' + (ref.exists ? 'HEAD ' + ref.commitSha.slice(0, 8) : '不存在（上传时会自动创建）'));
      connected = true;
      state.innerHTML = '<span class="mi-ok">已连接 ' + esc(repo.full_name) + '</span>';
      await loadInstances();
    } catch (e) {
      connected = false;
      state.innerHTML = '<span class="mi-err">连接失败</span>';
      logTo(log, errText(e));
    } finally { btn.disabled = false; }
  }

  /* ---------------- 实例列表 ---------------- */
  async function loadInstances() {
    var grid = $('miInstanceGrid');
    if (!connected) { grid.innerHTML = '<p class="mi-empty">连接 GitHub 后这里会列出仓库中的实例。</p>'; return; }
    grid.innerHTML = '<p class="mi-empty">正在读取…</p>';
    try {
      var dirs = await McGh.listDir(token, cfg.owner, cfg.repo, cfg.root, cfg.branch);
      var instDirs = dirs.filter(function (d) { return d.type === 'dir'; });
      if (!instDirs.length) {
        grid.innerHTML = '<p class="mi-empty">这个目录下还没有实例，先在下方上传一个吧。</p>';
        return;
      }
      grid.innerHTML = '';
      for (var i = 0; i < instDirs.length; i++) {
        var d = instDirs[i];
        var m = null;
        try {
          m = await McGh.getContentJson(token, cfg.owner, cfg.repo, cfg.root + '/' + d.name + '/instance.json', cfg.branch);
          m = typeof m === 'string' ? JSON.parse(m) : m;
        } catch (e) { m = null; }
        grid.appendChild(instanceCard(d.name, m));
      }
    } catch (e) {
      grid.innerHTML = '<p class="mi-empty">读取失败：' + esc(errText(e).split('\n')[0]) + '</p>';
    }
  }

  function instanceCard(id, m) {
    var el = document.createElement('div');
    el.className = 'card';
    var rec = McSync.getRecord({ owner: cfg.owner, repo: cfg.repo, id: id });
    if (!m) {
      el.innerHTML = '<h4>' + esc(id) + '</h4><p class="mi-note">清单缺失或格式损坏，无法同步。</p>';
      return el;
    }
    var ver = m.version || {};
    var loader = ver.loader ? (ver.loader.type + ' ' + ver.loader.version) : '原版';
    var st = m.stats || {};
    var synced = rec ? new Date(rec.syncedAt).toLocaleString('zh-CN', { hour12: false }) : '从未同步';
    el.innerHTML =
      '<div class="mi-inst">' +
        '<div class="mi-inst__main">' +
          '<h4>' + esc(m.name || id) + ' <span class="mi-badge">' + esc(id) + '</span></h4>' +
          '<p class="mi-note" style="margin:4px 0 8px;">' + esc(m.description || '') + '</p>' +
          '<p class="mi-kv"><b>版本</b><span>' + esc(ver.mc || '未知') + ' · ' + esc(loader) + '</span></p>' +
          '<p class="mi-kv"><b>内容</b><span>' + (st.fileCount || 0) + ' 个文件 · ' + fmtSize(st.totalSize || 0) + ' · ' +
            (st.modCount || 0) + ' 个模组 · ' + (st.worldCount || 0) + ' 个世界</span></p>' +
          '<p class="mi-kv"><b>更新</b><span>' + esc((m.updatedAt || '').slice(0, 19).replace('T', ' ')) + '</span></p>' +
          '<p class="mi-kv"><b>本机</b><span>' + esc(synced) + '</span></p>' +
        '</div>' +
        '<div class="mi-row" style="align-items:flex-start;">' +
          '<button class="btn primary" type="button" data-sync="' + esc(id) + '">同步到本地</button>' +
          '<button class="btn" type="button" data-detail="' + esc(id) + '">查看清单</button>' +
        '</div>' +
      '</div>';
    return el;
  }

  /* ---------------- 版本源读取 ---------------- */
  async function readTextFromDir(dirHandle, path) {
    try {
      var seg = path.split('/'), name = seg.pop(), dir = dirHandle;
      for (var i = 0; i < seg.length; i++) dir = await dir.getDirectoryHandle(seg[i]);
      var fh = await dir.getFileHandle(name);
      var f = await fh.getFile();
      if (f.size > 2 * 1024 * 1024) return '';
      return await f.text();
    } catch (e) { return ''; }
  }

  async function collectVersionSources(dirHandle) {
    var map = {};
    var mmc = await readTextFromDir(dirHandle, 'mmc-pack.json');
    if (mmc) map['mmc-pack.json'] = mmc;
    try {
      var vdir = await dirHandle.getDirectoryHandle('versions');
      var n = 0;
      for await (var entry of vdir.values()) {
        if (entry.kind !== 'directory' || n >= 3) continue;
        var txt = await readTextFromDir(vdir, entry.name + '/' + entry.name + '.json');
        if (txt) { map['versions/' + entry.name + '/' + entry.name + '.json'] = txt; n++; }
      }
    } catch (e) { /* 没有 versions 目录 */ }
    var lg = await readTextFromDir(dirHandle, 'logs/latest.log');
    if (lg) map['logs/latest.log'] = lg.slice(0, 20000);
    return map;
  }

  /* ---------------- 上传流程 ---------------- */
  async function pickUploadDir() {
    if (!window.showDirectoryPicker) {
      $('miScanState').innerHTML = '<span class="mi-warn">当前浏览器不支持目录读写，请用右侧“兼容模式”选择文件夹。</span>';
      return;
    }
    try {
      up.dirHandle = await window.showDirectoryPicker({ mode: 'read' });
      up.files = null;
      await scanUpload();
    } catch (e) {
      if (e && e.name === 'AbortError') return;
      $('miScanState').innerHTML = '<span class="mi-err">' + esc(e.message || '无法读取目录') + '</span>';
    }
  }

  async function scanUpload() {
    var state = $('miScanState');
    var preview = $('miUploadPreview');
    var log = $('miUploadLog');
    clearLog(log);
    state.textContent = '正在扫描…';
    up.scan = null; up.version = null; up.ready = false;
    $('miPublishBtn').disabled = true;

    try {
      var scan;
      // 勾选“包含依赖”时放宽为全量（仅排除日志与缓存类）
      var deps = $('miIncludeDeps') && $('miIncludeDeps').checked;
      var scanOpts = deps
        ? { include: [], exclude: ['logs/', 'crash-reports/', '.git/', 'backups/', 'session.lock', '*.tmp'] }
        : {};
      if (up.dirHandle) {
        scan = await McSync.scanInstance(Object.assign({
          dirHandle: up.dirHandle,
          onProgress: function (p) { state.textContent = '扫描中：' + p.index + ' 个文件（' + fmtSize(p.totalBytes) + '）'; }
        }, scanOpts));
        up.version = await detectUpVersion(up.dirHandle);
      } else {
        scan = await McSync.scanInstance(Object.assign({
          files: up.files,
          onProgress: function (p) { state.textContent = '扫描中：' + p.index + ' 个文件（' + fmtSize(p.totalBytes) + '）'; }
        }, scanOpts));
        up.version = null;
      }
      up.scan = scan;
      show(preview, true);

      state.innerHTML = '<span class="mi-ok">已扫描 ' + scan.fileCount + ' 个文件 · ' + fmtSize(scan.totalBytes) +
        (scan.skipped.length ? '（跳过 ' + scan.skipped.length + ' 项）' : '') + '</span>';

      // 自动填表单
      var guessId = (up.dirHandle && up.dirHandle.name) || 'instance';
      $('miInstId').value = sanitizeId(guessId);
      $('miInstName').value = guessId;
      applyVersion(up.version);
      logTo(log, '纳入 ' + scan.fileCount + ' 个文件，合计 ' + fmtSize(scan.totalBytes) + '；跳过 ' + scan.skipped.length + ' 项');
      if (scan.skipped.length) {
        var first = scan.skipped.slice(0, 6).map(function (s) { return s.path + '（' + s.reason + '）'; });
        logTo(log, '跳过示例：' + first.join('、'));
      }
      up.ready = true;
      $('miPublishBtn').disabled = false;
      $('miPublishBtn').textContent = '开始上传';
    } catch (e) {
      up.ready = false;
      state.innerHTML = '<span class="mi-err">扫描失败</span>';
      logTo(log, errText(e));
    }
  }

  async function detectUpVersion(dirHandle) {
    try {
      var map = await collectVersionSources(dirHandle);
      return McSync.detectVersion(map);
    } catch (e) { return { mc: '', loader: null, source: 'none' }; }
  }

  function sanitizeId(s) {
    return String(s || 'instance').toLowerCase().replace(/[^\w\-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'instance';
  }

  function applyVersion(v) {
    var hint = $('miVersionHint');
    if (!v || (!v.mc && !v.loader)) {
      if (hint) hint.innerHTML = '<span class="mi-warn">未自动识别出版本，请手动填写 MC 版本与加载器。</span>';
      return;
    }
    if (v.mc) $('miMcVersion').value = v.mc;
    if (v.loader) {
      $('miLoaderType').value = v.loader.type || '';
      $('miLoaderVersion').value = v.loader.version || '';
    }
    if (hint) {
      var src = { 'mmc-pack': 'mmc-pack.json', 'version-json': 'versions/*.json', 'latest.log': 'logs/latest.log', 'none': '未识别' }[v.source] || v.source;
      hint.innerHTML = '版本来源：<b>' + esc(src) + '</b>（可手动修正）' +
        (v.candidates && v.candidates.length > 1 ? '；共发现 ' + v.candidates.length + ' 条候选' : '');
    }
  }

  async function dryRun() {
    var log = $('miUploadLog');
    clearLog(log);
    if (!up.scan) return;
    var total = up.scan.totalBytes;
    var big = up.scan.entries.filter(function (e) { return e.size > McGh.HARD_FILE_LIMIT; });
    var chunked = up.scan.entries.filter(function (e) { return e.chunked; });
    logTo(log, '预检结果：');
    logTo(log, '· 文件数 ' + up.scan.fileCount + '，合计 ' + fmtSize(total));
    logTo(log, '· 需要分块的文件：' + (chunked.length ? chunked.length + ' 个' : '无'));
    logTo(log, '· 超过 GitHub 单文件上限：' + (big.length ? big.length + ' 个（' + big.map(function (e) { return e.path; }).join('、') + '）' : '无'));
    if (total > 900 * 1024 * 1024) logTo(log, '· 警告：实例超过 900MB，仓库体积会明显膨胀，建议精简 resourcepacks/shaderpacks');
    else if (total > 300 * 1024 * 1024) logTo(log, '· 提示：实例超过 300MB，首次上传会比较久（之后只有改动的文件才会重传）');
    try {
      var head = await McGh.getRef(token, cfg.owner, cfg.repo, cfg.branch);
      if (!head.exists) {
        logTo(log, '· 分支 ' + cfg.branch + ' 不存在，上传时将创建首个提交');
        return;
      }
      var entries = await McGh.getTree(token, cfg.owner, cfg.repo, head.commitSha);
      var prefix = (cfg.root.replace(/^\/+|\/+$/g, '')) + '/' + sanitizeId($('miInstId').value) + '/';
      var existing = {};
      entries.forEach(function (e) { if (e.type === 'blob' && e.path.indexOf(prefix) === 0) existing[e.path] = e.sha; });
      var reuse = 0, send = 0;
      up.scan.entries.forEach(function (e) {
        if (existing[prefix + e.path] === e.gitSha) { reuse++; send += 0; } else { send += e.size; }
      });
      logTo(log, '· 云端已有同内容文件可复用：' + reuse + ' 个');
      logTo(log, '· 本次实际需要上传：' + fmtSize(send));
      logTo(log, '预检完成，可以开始上传。');
    } catch (e) {
      logTo(log, '预检读取云端失败：' + errText(e));
    }
  }

  async function publish() {
    if (!up.scan || !up.ready) return;
    if (!connected) { $('miScanState').innerHTML = '<span class="mi-err">请先连接 GitHub</span>'; return; }
    var id = sanitizeId($('miInstId').value);
    var log = $('miUploadLog'), bar = $('miUpBar');
    var btn = $('miPublishBtn'), cancel = $('miCancelBtn');
    clearLog(log);
    var mc = $('miMcVersion').value.trim();
    var lt = $('miLoaderType').value;
    var lv = $('miLoaderVersion').value.trim();
    if (!mc) { logTo(log, '请填写 MC 版本（版本识别失败时需要手动指定）'); return; }

    up.abort = new AbortController();
    btn.disabled = true; show(cancel, true); show(bar, true);
    logTo(log, '开始上传实例 ' + id + ' …');

    try {
      var manifest = await McSync.buildManifest(up.scan, {
        id: id,
        name: $('miInstName').value.trim() || id,
        description: $('miInstDesc').value.trim(),
        mc: mc,
        loader: lt ? { type: lt, version: lv } : null,
        versionSource: up.version ? up.version.source : 'manual',
        memoryMB: 4096
      });
      var res = await McGh.publish({
        token: token, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch,
        root: cfg.root, id: id, entries: up.scan.entries, manifestJson: manifest,
        signal: up.abort.signal,
        versionLabel: mc + (lt ? ' ' + lt + ' ' + lv : ''),
        message: '实例更新：' + manifest.name + '（' + mc + (lt ? ' / ' + lt + ' ' + lv : '') + '）',
        onProgress: function (p) {
          if (p.phase === 'upload') {
            var ratio = p.ratio != null ? p.ratio : (p.index / Math.max(1, p.total));
            setBar(bar, ratio);
          } else if (p.phase === 'retry') {
            logTo(log, '分支已被更新，重新比对后重试：' + p.reason);
          }
        }
      });
      setBar(bar, 1);
      logTo(log, '完成：提交 ' + res.commitSha.slice(0, 10) + '，新上传 ' + res.uploaded + ' 个、复用 ' +
        res.reused + ' 个、发送 ' + fmtSize(res.bytesSent) + (res.retried ? '（重试 ' + res.retried + ' 轮）' : ''));
      logTo(log, '实例已发布。别的电脑打开本页即可同步。');
      await loadInstances();
      $('miSyncId').value = id;
    } catch (e) {
      logTo(log, '上传失败：' + errText(e));
    } finally {
      btn.disabled = false; show(cancel, false);
    }
  }

  /* ---------------- 同步 ---------------- */
  async function pickSyncDir() {
    var id = sanitizeId($('miSyncId').value || '');
    if (!id) { $('miSyncState').innerHTML = '<span class="mi-err">请先填写实例标识</span>'; return; }
    if (!connected) { $('miSyncState').innerHTML = '<span class="mi-err">请先连接 GitHub</span>'; return; }
    if (!window.showDirectoryPicker) { $('miSyncState').innerHTML = '<span class="mi-err">当前浏览器不支持目录写入，请使用 Chrome / Edge</span>'; return; }
    try {
      sy.dirHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
      sy.cfgId = id;
      await buildDiff();
    } catch (e) {
      if (e && e.name === 'AbortError') return;
      $('miSyncState').innerHTML = '<span class="mi-err">' + esc(errText(e)) + '</span>';
    }
  }

  async function buildDiff() {
    var state = $('miSyncState'), log = $('miSyncLog');
    clearLog(log);
    state.textContent = '正在读取云端清单…';
    show($('miSyncResult'), false);
    var id = sy.cfgId;

    try {
      var head = await McGh.getRef(token, cfg.owner, cfg.repo, cfg.branch);
      if (!head.exists) throw new McGh.GhError('E_NOT_FOUND', '分支不存在，仓库里还没有实例');
      var manifestRaw = await McGh.getContentJson(token, cfg.owner, cfg.repo, cfg.root + '/' + id + '/instance.json', cfg.branch);
      var manifest = typeof manifestRaw === 'string' ? JSON.parse(manifestRaw) : manifestRaw;
      McSync.validateManifest(manifest);
      sy.manifest = manifest;
      sy.commit = head.commitSha;
      sy.cfg = { owner: cfg.owner, repo: cfg.repo, id: id, root: cfg.root, branch: cfg.branch };

      state.textContent = '正在扫描本地目录…';
      var rules = McSync.compileRules();
      var localRaw = await McSync.readLocalIndex(sy.dirHandle, rules);
      var rec = McSync.getRecord({ owner: cfg.owner, repo: cfg.repo, id: id });
      var baseFiles = rec && rec.files || {};

      // 本地索引 → cid 映射（仅对“可能改动”的文件算哈希）
      var local = {};
      var paths = Object.keys(localRaw);
      for (var i = 0; i < paths.length; i++) {
        var p = paths[i], item = localRaw[p];
        var baseEntry = baseFiles[p];
        var same = baseEntry && baseEntry.size === item.size && baseEntry.mtime === item.mtime;
        if (same) { local[p] = { cid: baseEntry.cid, size: item.size, mtime: item.mtime, file: item.file }; continue; }
        var bytes = new Uint8Array(await item.file.arrayBuffer());
        var cid = await McGh.sha256(bytes);
        local[p] = { cid: cid, size: item.size, mtime: item.mtime, file: item.file };
      }

      var remote = {};
      (manifest.files || []).forEach(function (f) { remote[f.path] = { cid: f.cid, size: f.size, entry: f }; });

      sy.diff = McSync.diffThreeWay(local, baseFiles, remote, { protectWorlds: true });
      sy.local = local; sy.remote = remote; sy.rec = rec;
      renderDiff();
      show($('miSyncResult'), true);
      state.innerHTML = '<span class="mi-ok">已比对：' + id + ' · 云端版本 ' + esc(manifest.version.mc) + '</span>';
    } catch (e) {
      state.innerHTML = '<span class="mi-err">读取失败</span>';
      logTo(log, errText(e));
    }
  }

  function renderDiff() {
    var d = sy.diff;
    var sum = $('miSyncSummary');
    sum.innerHTML =
      '云端 <b>' + esc(sy.manifest.name || sy.cfgId) + '</b>（' + esc(sy.manifest.version.mc) + '）· ' +
      '待下载 <b>' + d.download.length + '</b> · 冲突 <b class="' + (d.conflict.length ? 'mi-warn' : '') + '">' + d.conflict.length + '</b> · ' +
      '本地修改 <b>' + d.keepLocal.length + '</b> · 待删除 <b>' + d.deleteLocal.length + '</b> · 无变化 <b>' + d.unchanged.length + '</b>';

    // 默认决策
    sy.rowChoice = {};
    d.conflict.forEach(function (row) {
      sy.rowChoice[row.path] = row.preferLocal ? 'local' : 'cloud';
    });

    Array.prototype.forEach.call($('miSyncTabs').querySelectorAll('button'), function (b) {
      var key = b.getAttribute('data-tab');
      var n = { conflict: d.conflict.length, download: d.download.length, keepLocal: d.keepLocal.length, deleteLocal: d.deleteLocal.length, unchanged: d.unchanged.length }[key] || 0;
      b.textContent = ({ conflict: '冲突', download: '待下载', keepLocal: '本地修改', deleteLocal: '待删除', unchanged: '无变化' })[key] + '（' + n + '）';
      b.classList.toggle('is-on', key === sy.tab);
    });
    renderDiffTable();
  }

  function renderDiffTable() {
    var t = $('miDiffTable');
    var d = sy.diff;
    if (!d) return;
    var rows = d[sy.tab] || [];
    if (!rows.length) {
      t.innerHTML = '<tr><td class="mi-empty">这一项为空。</td></tr>';
      return;
    }
    var head = '<tr><th>文件</th><th>本地</th><th>云端</th><th>处理</th></tr>';
    var body = rows.slice(0, 300).map(function (row) {
      var sizeLocal = row.local ? fmtSize(row.local.size) : '—';
      var sizeRemote = row.remote ? fmtSize(row.remote.size) : '—';
      var act = '—';
      if (sy.tab === 'conflict') {
        var cur = sy.rowChoice[row.path] || 'cloud';
        act = '<select data-path="' + esc(row.path) + '">' +
          '<option value="cloud"' + (cur === 'cloud' ? ' selected' : '') + '>使用云端</option>' +
          '<option value="local"' + (cur === 'local' ? ' selected' : '') + '>保留本地</option>' +
          '<option value="both"' + (cur === 'both' ? ' selected' : '') + '>两者都留</option>' +
          '</select>';
      } else if (sy.tab === 'download') act = '下载并覆盖';
      else if (sy.tab === 'keepLocal') act = '保留本地';
      else if (sy.tab === 'deleteLocal') act = '删除本地文件';
      else act = '跳过';
      return '<tr><td>' + esc(row.path) + (row.isWorld ? ' <span class="mi-badge">世界</span>' : '') + '</td>' +
        '<td>' + sizeLocal + (row.reason === 'local-modified' ? ' <span class="mi-warn">已改</span>' : '') + '</td>' +
        '<td>' + sizeRemote + '</td><td>' + act + '</td></tr>';
    }).join('');
    t.innerHTML = head + body + (rows.length > 300 ? '<tr><td colspan="4" class="mi-note">仅显示前 300 项，其余同样处理。</td></tr>' : '');
    Array.prototype.forEach.call(t.querySelectorAll('select'), function (s) {
      s.addEventListener('change', function () { sy.rowChoice[s.getAttribute('data-path')] = s.value; });
    });
  }

  async function applySync() {
    var d = sy.diff;
    if (!d) return;
    var log = $('miSyncLog'), bar = $('miDlBar');
    var btn = $('miApplyBtn'), cancel = $('miCancelSyncBtn');
    clearLog(log);
    sy.abort = new AbortController();
    btn.disabled = true; show(cancel, true); show(bar, true);

    var id = sy.cfgId;
    var manifest = sy.manifest;
    var remoteMap = {};
    (manifest.files || []).forEach(function (f) { remoteMap[f.path] = f; });
    var filesRec = Object.assign({}, (sy.rec && sy.rec.files) || {});
    var total = d.download.length;
    var done = 0;
    var failures = [];

    try {
      // 1) 下载
      for (var i = 0; i < d.download.length; i++) {
        if (sy.abort.signal.aborted) throw new McGh.GhError('E_ABORT', '已取消');
        var row = d.download[i];
        var entry = remoteMap[row.path];
        if (!entry) continue;
        logTo(log, '下载 ' + row.path + '（' + fmtSize(entry.size) + '）');
        var res = await McSync.fetchFile(sy.cfg, manifest, entry, sy.commit, {
          onProgress: function (p, a, b) { if (b) setBar(bar, (done + a / b) / Math.max(1, total)); }
        });
        await McSync.writeFileToDir(sy.dirHandle, row.path, res.blob);
        filesRec[row.path] = { cid: entry.cid, size: entry.size, mtime: Date.now() };
        done++;
        setBar(bar, done / Math.max(1, total));
      }

      // 2) 冲突：按选择执行
      for (var j = 0; j < d.conflict.length; j++) {
        var c = d.conflict[j];
        var choice = sy.rowChoice[c.path] || 'cloud';
        var rentry = remoteMap[c.path];
        if (choice === 'cloud' && rentry) {
          var r2 = await McSync.fetchFile(sy.cfg, manifest, rentry, sy.commit, {});
          await McSync.writeFileToDir(sy.dirHandle, c.path, r2.blob);
          filesRec[c.path] = { cid: rentry.cid, size: rentry.size, mtime: Date.now() };
          logTo(log, '冲突处理（用云端）：' + c.path);
        } else if (choice === 'both') {
          var lp = c.path + '.local-' + new Date().toISOString().replace(/[:.]/g, '-');
          if (c.local && c.local.file) {
            await McSync.writeFileToDir(sy.dirHandle, lp, c.local.file);
            logTo(log, '冲突备份为：' + lp);
          }
          if (rentry) {
            var r3 = await McSync.fetchFile(sy.cfg, manifest, rentry, sy.commit, {});
            await McSync.writeFileToDir(sy.dirHandle, c.path, r3.blob);
            filesRec[c.path] = { cid: rentry.cid, size: rentry.size, mtime: Date.now() };
          }
        } else {
          // 保留本地：基线记录为本地内容，后续上传时算作“本地修改”
          if (c.local) filesRec[c.path] = { cid: c.local.cid, size: c.local.size, mtime: c.local.mtime || Date.now() };
          logTo(log, '冲突处理（保留本地）：' + c.path);
        }
      }

      // 3) 删除
      for (var k = 0; k < d.deleteLocal.length; k++) {
        var del = d.deleteLocal[k];
        try {
          var seg = del.path.split('/'), name = seg.pop(), dir = sy.dirHandle;
          for (var s2 = 0; s2 < seg.length; s2++) dir = await dir.getDirectoryHandle(seg[s2]);
          await dir.removeEntry(name);
          delete filesRec[del.path];
          logTo(log, '已删除：' + del.path);
        } catch (e) {
          logTo(log, '删除失败（可能不存在）：' + del.path + ' — ' + (e.message || e));
        }
      }

      // 4) 其余文件写入基线
      Object.keys(sy.local || {}).forEach(function (p) {
        if (filesRec[p]) return;
        var l = sy.local[p];
        var r = remoteMap[p];
        if (r && l && r.cid === l.cid) filesRec[p] = { cid: l.cid, size: l.size, mtime: l.mtime || Date.now() };
      });

      // 5) 保存同步记录（下次三方比较的基线）
      var rec = McSync.getRecord({ owner: cfg.owner, repo: cfg.repo, id: id }) || {};
      rec.commit = sy.commit;
      rec.syncedAt = new Date().toISOString();
      rec.fingerprint = manifest.version.fingerprint;
      rec.files = filesRec;
      rec.launcher = { path: $('miSyncLauncher').value.trim() };
      McSync.saveRecord({ owner: cfg.owner, repo: cfg.repo, id: id }, rec);

      setBar(bar, 1);
      logTo(log, '同步完成：' + id + ' @ ' + sy.commit.slice(0, 10));
      if (failures.length) logTo(log, '有 ' + failures.length + ' 个文件失败，请重试。');
      show($('miLaunchCard'), true);
      $('miLaunchText').innerHTML = '实例已写入所选目录。版本 <b>' + esc(manifest.version.mc) + '</b>，加载器 ' +
        esc((manifest.version.loader && manifest.version.loader.type) || '原版') + '。' +
        '点「生成启动脚本」写入启动文件后，页面会自动检测本地服务并给出最快开玩入口。';
      $('miLaunchCard').dataset.id = id;
    } catch (e) {
      logTo(log, '同步中断：' + errText(e));
    } finally {
      btn.disabled = false; show(cancel, false);
    }
  }

  /* ---------------- 启动脚本 ---------------- */
  async function genScript() {
    var log = $('miLaunchLog');
    clearLog(log);
    var id = $('miLaunchCard').dataset.id || sy.cfgId;
    var manifest = sy.manifest || { id: id, name: id, version: { mc: '', loader: null }, launch: { memoryMB: 4096, jvmArgs: '' } };
    var launcherPath = $('miSyncLauncher').value.trim().replace(/^["']|["']$/g, '');
    var launcherType = launcherPath && /prism/i.test(launcherPath) ? 'prism' : 'custom';
    var plan = McSync.buildLaunchPlan(manifest, launcherPath ? { path: launcherPath, type: launcherType } : null);
    try {
      await McSync.writeFileToDir(sy.dirHandle, 'launch-plan.json', new Blob([JSON.stringify(plan, null, 2)], { type: 'application/json' }));
      var isWin = navigator.platform.toLowerCase().indexOf('win') >= 0;
      var script = McSync.buildLaunchScript(plan, isWin ? 'win' : 'unix');
      var name = isWin ? 'niao-launch.cmd' : 'niao-launch.sh';
      await McSync.writeFileToDir(sy.dirHandle, name, new Blob([script], { type: 'text/plain' }));
      logTo(log, '已写入 ' + name + ' 与 launch-plan.json 到实例目录。有本地服务时可在浏览器内直接启动，否则双击 ' + name + ' 用启动器打开。');
      logTo(log, '内存 ' + plan.memoryMB + ' MB，JVM 参数：' + (plan.jvmArgs || '默认'));
      $('miProtocolLaunch').hidden = false;
      $('miProtocolLaunch').href = 'niao-mc://launch?instance=' + encodeURIComponent(id);
      $('miProtocolLaunch').dataset.ready = '1';
      $('miProtocolLaunch').dataset.instance = id;
      // 本地服务在跑的话，按钮直接走浏览器内启动
      probeHost().then(function (info) {
        var btn = $('miProtocolLaunch');
        if (info && info.ok) {
          btn.dataset.host = '1';
          btn.textContent = '在浏览器内启动';
          logTo(log, '检测到本地服务 ' + info.base + '，点「在浏览器内启动」即可直接开玩（无需协议注册）。');
        } else {
          btn.dataset.host = '';
          btn.textContent = '启动实例';
        }
      });
    } catch (e) {
      logTo(log, '生成失败：' + errText(e));
    }
  }

  /* ---------------- 浏览器内启动 ---------------- */
  var HOST_KEY = 'niao.mc.host.v1';

  function hostBase() {
    try {
      var cfg = JSON.parse(localStorage.getItem(HOST_KEY) || '{}');
      return (cfg.url || 'http://127.0.0.1:8791').replace(/\/$/, '');
    } catch (e) {
      return 'http://127.0.0.1:8791';
    }
  }

  /** 探测本地常驻服务；浏览器只发 HTTP，不涉及执行本地程序 */
  function probeHost() {
    var base = hostBase();
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 1500);
    return fetch(base + '/health', { cache: 'no-store', signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { return j && j.ok ? { ok: true, base: base, health: j } : { ok: false, base: base }; })
      .catch(function () { return { ok: false, base: base }; })
      .then(function (v) { clearTimeout(timer); return v; });
  }

  function launchViaHost(instanceId) {
    var base = hostBase();
    return fetch(base + '/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instance: instanceId })
    }).then(function (r) { return r.json(); });
  }

  /** 一键开玩：本地服务在线就走服务，否则回退协议桥 */
  function playInstance(instanceId, logEl) {
    var log = logEl || $('miLaunchLog');
    logTo(log, '正在尝试浏览器内启动实例 ' + instanceId + '…');
    return probeHost().then(function (info) {
      if (info.ok) {
        logTo(log, '本地服务在线：' + info.base);
        return launchViaHost(instanceId).then(function (res) {
          if (res && res.ok) {
            logTo(log, '已启动实例 ' + instanceId + (res.pid ? '（进程 ' + res.pid + '）' : '') + '，游戏窗口正在打开。');
            return { ok: true, mode: 'host', res: res };
          }
          logTo(log, '启动被拒绝：' + ((res && res.message) || '未知原因'));
          return { ok: false, mode: 'host', res: res };
        });
      }
      logTo(log, '本地服务未运行，改用协议桥唤起本地启动器。注册过 niao-mc:// 时会直接生效。');
      try {
        window.location.href = 'niao-mc://launch?instance=' + encodeURIComponent(instanceId);
        return { ok: true, mode: 'protocol' };
      } catch (e) {
        logTo(log, '协议启动失败：' + errText(e));
        return { ok: false, mode: 'protocol' };
      }
    });
  }

  function downloadReg() {
    // 浏览器拿不到实例目录的绝对路径，这里写明确的占位，导入前必须改
    var placeholder = 'C:////////path////////to////////你的实例目录////////niao-launch.cmd';
    var reg = McSync.buildProtocolReg(placeholder);
    downloadText('niao-mc-protocol.reg', reg, 'application/octet-stream');
    var log = $('miLaunchLog');
    logTo(log, '已下载协议注册文件。请先用记事本把其中的占位路径改成：实例目录\\niao-launch.cmd 的完整路径，再双击导入。');
  }

  /* ---------------- 事件 ---------------- */
  function bind() {
    $('miConnectBtn').addEventListener('click', connect);
    $('miForgetBtn').addEventListener('click', function () {
      try { localStorage.removeItem(LS.TOKEN); sessionStorage.removeItem(LS.SESSION_TOKEN); } catch (e) {}
      token = ''; connected = false;
      $('miToken').value = ''; $('miRemember').checked = false;
      $('miConnState').textContent = '令牌已清除';
      $('miInstanceGrid').innerHTML = '<p class="mi-empty">连接 GitHub 后这里会列出仓库中的实例。</p>';
    });
    $('miRefreshBtn').addEventListener('click', loadInstances);

    $('miPickDirBtn').addEventListener('click', pickUploadDir);
    $('miDirInput').addEventListener('change', async function (e) {
      var list = Array.prototype.slice.call(e.target.files || []);
      if (!list.length) return;
      up.dirHandle = null;
      up.files = list.map(function (f) { return { path: f.webkitRelativePath || f.name, file: f }; });
      await scanUpload();
    });
    $('miDryRunBtn').addEventListener('click', dryRun);
    $('miPublishBtn').addEventListener('click', publish);
    $('miCancelBtn').addEventListener('click', function () { if (up.abort) up.abort.abort(); });

    $('miSyncPickBtn').addEventListener('click', pickSyncDir);
    $('miApplyBtn').addEventListener('click', applySync);
    $('miCancelSyncBtn').addEventListener('click', function () { if (sy.abort) sy.abort.abort(); });
    $('miSyncTabs').addEventListener('click', function (e) {
      var b = e.target.closest('button[data-tab]');
      if (!b) return;
      sy.tab = b.getAttribute('data-tab');
      renderDiff();
    });
    $('miInstanceGrid').addEventListener('click', async function (e) {
      var b = e.target.closest('button[data-sync]');
      if (b) {
        $('miSyncId').value = b.getAttribute('data-sync');
        document.getElementById('miSync').scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }
      var d = e.target.closest('button[data-detail]');
      if (d) {
        var id = d.getAttribute('data-detail');
        try {
          var m = await McGh.getContentJson(token, cfg.owner, cfg.repo, cfg.root + '/' + id + '/instance.json', cfg.branch);
          showDetail(id, typeof m === 'string' ? JSON.parse(m) : m);
        } catch (err) { alert(errText(err)); }
      }
    });
    $('miGenScriptBtn').addEventListener('click', genScript);
    $('miProtocolBtn').addEventListener('click', downloadReg);
    // 页面载入即探测本地服务，按钮文案随之切换
    probeHost().then(function (info) {
      var bar = $('miHostState');
      if (!bar) return;
      if (info.ok) {
        bar.hidden = false;
        bar.textContent = '本地服务在线（' + info.base + '）· 可直接在浏览器内启动实例，无需协议注册。';
        bar.dataset.on = '1';
      } else {
        bar.hidden = true;
        bar.dataset.on = '';
      }
    });
    $('miProtocolLaunch').addEventListener('click', function (e) {
      if (!this.dataset.ready) { e.preventDefault(); return; }
      // 本地服务在线时拦截默认跳转，直接在浏览器内启动
      if (this.dataset.host === '1') {
        e.preventDefault();
        playInstance(this.dataset.instance || sy.id);
      }
    });
    // 令牌与仓库改动即时保存（不触发网络）
    ['miOwner', 'miRepo', 'miBranch', 'miRoot'].forEach(function (id) { $(id).addEventListener('change', saveCfg); });
    $('miToken').addEventListener('change', saveToken);
  }

  function showDetail(id, m) {
    var wrap = document.createElement('div');
    wrap.className = 'mi-dialog';
    var mods = (m.mods || []).map(function (x) { return '<li>' + esc(x.name) + '（' + fmtSize(x.size) + '）</li>'; }).join('');
    var worlds = (m.worlds || []).map(function (w) { return '<li>' + esc(w) + '</li>'; }).join('');
    wrap.innerHTML = '<div class="mi-dialog__panel"><h4>' + esc(m.name || id) + '</h4>' +
      '<p class="mi-kv"><b>清单格式</b><span>' + esc(m.schema) + '</span></p>' +
      '<p class="mi-kv"><b>MC 版本</b><span>' + esc(m.version && m.version.mc) + '</span></p>' +
      '<p class="mi-kv"><b>加载器</b><span>' + esc(m.version && m.version.loader ? m.version.loader.type + ' ' + m.version.loader.version : '原版') + '</span></p>' +
      '<p class="mi-kv"><b>指纹</b><span>' + esc((m.version && m.version.fingerprint || '').slice(0, 24)) + '…</span></p>' +
      '<p class="mi-kv"><b>文件</b><span>' + ((m.stats && m.stats.fileCount) || 0) + ' 个 · ' + fmtSize((m.stats && m.stats.totalSize) || 0) + '</span></p>' +
      '<h4>世界</h4><ul class="mi-note">' + (worlds || '<li>无</li>') + '</ul>' +
      '<h4>模组（' + ((m.mods || []).length) + '）</h4><ul class="mi-note">' + (mods || '<li>无</li>') + '</ul>' +
      '<div class="mi-row" style="margin-top:16px;"><button class="btn" type="button">关闭</button></div></div>';
    wrap.addEventListener('click', function (e) {
      if (e.target === wrap || e.target.tagName === 'BUTTON') wrap.remove();
    });
    document.body.appendChild(wrap);
  }

  /* ---------------- 启动 ---------------- */
  function boot() {
    loadCfg();
    bind();
    // 缓存在页面展示一次，便于排查
    McSync.cacheStats().then(function (s) {
      if (s.count) {
        var el = $('miHeroStats');
        if (el) el.insertAdjacentHTML('beforeend', '<span class="chip">本地缓存 ' + s.count + ' 项 · ' + fmtSize(s.bytes) + '</span>');
      }
    });
    // 供自动化测试使用的只读接口
    window.NiaoInstance = {
      McGh: McGh, McSync: McSync,
      get cfg() { return cfg; },
      isConnected: function () { return connected; },
      probeHost: probeHost,
      playInstance: playInstance,
      hostBase: hostBase
    };
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
