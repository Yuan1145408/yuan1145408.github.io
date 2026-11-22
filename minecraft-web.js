/* ============================================================
   我的世界 · 网页版启动中心
   ------------------------------------------------------------
   - 版本清单：优先读取 Mojang 官方 version_manifest（允许跨域），
     失败或超时则回退到内置清单，保证离线/被墙时仍可用
   - 启动方式：浏览器网页版（Eaglercraft）/ 本地启动器 / 导出配置
   - Mod 启动器与 Mod 均为本地管理（localStorage），不涉及后端
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var Resolver = window.McResolver || null;
  var KEY = {
    SETTINGS: 'niao.mc.settings.v1',
    LAUNCHERS: 'niao.mc.launchers.v1',
    MODS: 'niao.mc.mods.v1',
    RECENT: 'niao.mc.recent.v1',
    MIGRATED: 'niao.mc.migrated.v1'
  };

  // 网页版（Eaglercraft）公开支持的版本 → 客户端地址
  var WEB_CLIENTS = {
    '1.5.2': 'https://eaglercraft.com/mc/1.5.2/',
    '1.8.8': 'https://eaglercraft.com/mc/1.8.8/'
  };

  var TYPE_LABEL = {
    release: '正式版',
    snapshot: '快照',
    old_beta: '旧版 Beta',
    old_alpha: '远古 Alpha'
  };

  /* ---------------- 内置数据 ---------------- */
  var BUILTIN_LAUNCHERS = [
    {
      id: 'prism', name: 'Prism Launcher', type: 'prism', builtin: true,
      path: 'https://github.com/PrismLauncher/PrismLauncher/releases',
      memory: 4096, jvm: '-XX:+UseG1GC -XX:MaxGCPauseMillis=50',
      gamedir: './instances/', extra: '',
      desc: '开源多实例启动器，支持 Fabric/Forge/NeoForge/Quilt 与 Modrinth 整合包。'
    },
    {
      id: 'hmcl', name: 'HMCL 启动器', type: 'hmcl', builtin: true,
      path: 'https://github.com/HMCL-dev/HMCL/releases',
      memory: 4096, jvm: '-XX:+UseG1GC',
      gamedir: './.minecraft/', extra: '',
      desc: '国人维护的跨平台启动器，自动补全 Java 与依赖，适合新手。'
    },
    {
      id: 'pcl2', name: 'PCL2 启动器', type: 'pcl2', builtin: true,
      path: 'https://github.com/Hex-Dragon/PCL2/releases',
      memory: 4096, jvm: '-XX:+UseG1GC',
      gamedir: './.minecraft/', extra: '',
      desc: 'Windows 上流行的启动器，整合包与模组安装比较省事。'
    },
    {
      id: 'official', name: '官方启动器', type: 'official', builtin: true,
      path: 'https://www.minecraft.net/zh-hans/download',
      memory: 2048, jvm: '-Xmx2G',
      gamedir: '%APPDATA%/.minecraft', extra: '',
      desc: '官方启动器，只支持原版与官方提供的版本，不支持第三方加载器。'
    }
  ];

  var SEED_MODS = [
    { id: 'sodium', name: 'Sodium（性能优化）', version: '0.6.x', loader: 'Fabric', mcver: '1.21.x', file: 'sodium-fabric-0.6.x.jar', note: '显著提升帧率', enabled: true },
    { id: 'iris', name: 'Iris Shaders（光影）', version: '1.8.x', loader: 'Fabric', mcver: '1.21.x', file: 'iris-1.8.x.jar', note: '需要 Sodium', enabled: false },
    { id: 'fabric-api', name: 'Fabric API', version: '0.115.x', loader: 'Fabric', mcver: '1.21.x', file: 'fabric-api-0.115.x.jar', note: '多数 Fabric 模组的依赖', enabled: true },
    { id: 'modmenu', name: 'Mod Menu（模组菜单）', version: '11.x', loader: 'Fabric', mcver: '1.21.x', file: 'modmenu-11.x.jar', note: '游戏内管理模组设置', enabled: true },
    { id: 'jei', name: 'JEI（物品配方查询）', version: '19.x', loader: 'Forge', mcver: '1.20.1', file: 'jei-1.20.1-19.x.jar', note: 'Forge 生态常用', enabled: false },
    { id: 'create', name: 'Create（机械动力）', version: '6.x', loader: 'Forge', mcver: '1.20.1', file: 'create-1.20.1-6.x.jar', note: '大型机械自动化模组', enabled: false }
  ];

  // 官方清单不可用时的回退版本（覆盖主流正式版 + 经典版本）
  var FALLBACK_VERSIONS = ('1.21.4 1.21.3 1.21.1 1.21 1.20.6 1.20.4 1.20.2 1.20.1 1.20 1.19.4 1.19.2 1.18.2 1.17.1 1.16.5 ' +
    '1.15.2 1.14.4 1.13.2 1.12.2 1.11.2 1.10.2 1.9.4 1.8.9 1.8.8 1.7.10 1.7.2 1.6.4 1.5.2').split(' ').map(function (v, i) {
    return { id: v, type: 'release', releaseTime: '', fallback: true };
  });

  /* ---------------- 存取 ---------------- */
  function load(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      if (!raw) return fallback;
      var v = JSON.parse(raw);
      return v == null ? fallback : v;
    } catch (e) { return fallback; }
  }
  function save(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) { /* 忽略配额错误 */ }
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function uid(prefix) { return prefix + '-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
  function fmtDate(s) {
    if (!s) return '—';
    try { return new Date(s).toLocaleDateString('zh-CN'); } catch (e) { return '—'; }
  }
  function copyText(text, done) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(); });
    } else { fallback(); }
    function fallback() {
      try {
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done();
      } catch (e) { done(false); }
    }
  }
  function download(name, text, mime) {
    var blob = new Blob([text], { type: mime || 'application/json;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  /* ---------------- 状态 ---------------- */
  var launchers = [];
  var mods = [];
  var recent = [];
  var settings = { version: '', mode: 'web', launcherId: '' };
  var state = {
    versions: [], filtered: [], version: null,
    type: 'release', q: '', mode: 'web', launcherId: '',
    enabled: {}, loading: true, source: 'manifest'
  };

  function initData() {
    launchers = load(KEY.LAUNCHERS, null);
    if (!Array.isArray(launchers) || !launchers.length) {
      launchers = JSON.parse(JSON.stringify(BUILTIN_LAUNCHERS));
      save(KEY.LAUNCHERS, launchers);
    }
    mods = load(KEY.MODS, null);
    if (!Array.isArray(mods)) {
      mods = JSON.parse(JSON.stringify(SEED_MODS));
      save(KEY.MODS, mods);
    }
    recent = load(KEY.RECENT, []);
    if (!Array.isArray(recent)) recent = [];
    var s = load(KEY.SETTINGS, null);
    if (s && typeof s === 'object') {
      settings.version = s.version || '';
      settings.mode = s.mode === 'launcher' || s.mode === 'export' ? s.mode : 'web';
      settings.launcherId = s.launcherId || '';
    }
    state.mode = settings.mode;
    state.launcherId = settings.launcherId || (launchers[0] && launchers[0].id) || '';
    mods.forEach(function (m) { if (m.enabled) state.enabled[m.id] = true; });
  }
  function persistSettings() {
    save(KEY.SETTINGS, { version: state.version ? state.version.id : '', mode: state.mode, launcherId: state.launcherId });
  }

  /* ---------------- 版本 ---------------- */
  function loadVersions() {
    var ctrl = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 6500);
    fetch('https://launchermeta.mojang.com/mc/game/version_manifest_v2.json', ctrl ? { signal: ctrl.signal, cache: 'no-store' } : { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        clearTimeout(timer);
        var list = (data && data.versions || []).map(function (v) {
          return { id: v.id, type: v.type, releaseTime: v.releaseTime || '' };
        });
        if (!list.length) throw new Error('empty');
        state.versions = list;
        state.source = 'manifest';
        state.loading = false;
        pickInitialVersion(data && data.latest && data.latest.release);
      })
      .catch(function (err) {
        clearTimeout(timer);
        state.versions = FALLBACK_VERSIONS.slice();
        state.source = 'fallback';
        state.loading = false;
        pickInitialVersion(settings.version);
        if (window.console && console.warn) console.warn('[我的世界网页版] 官方版本清单读取失败，使用内置清单：', err && err.message);
      });
  }

  function pickInitialVersion(prefer) {
    var want = settings.version || prefer || '';
    var hit = null;
    state.versions.forEach(function (v) { if (!hit && v.id === want) hit = v; });
    if (!hit) {
      // 优先正式版，其次清单第一条
      state.versions.forEach(function (v) { if (!hit && v.type === 'release') hit = v; });
    }
    if (!hit) hit = state.versions[0] || null;
    state.version = hit;
    state.type = hit && hit.type !== 'release' && hit.type !== 'snapshot' ? 'old' : 'release';
    if (hit && hit.type === 'snapshot') state.type = 'snapshot';
    var sel = $('mcwVersionType');
    if (sel) sel.value = state.type;
    renderVersions();
    renderSummary();
    renderModPick();
    renderLauncherPick();
    renderStats();
    updateStepState();
  }

  function matchType(v, type) {
    if (type === 'all') return true;
    if (type === 'old') return v.type === 'old_beta' || v.type === 'old_alpha';
    return v.type === type;
  }

  function renderVersions() {
    var box = $('mcwVersionList');
    if (!box) return;
    var q = state.q.trim().toLowerCase();
    state.filtered = state.versions.filter(function (v) {
      return matchType(v, state.type) && (!q || v.id.toLowerCase().indexOf(q) >= 0);
    });
    box.innerHTML = '';
    if (!state.filtered.length) {
      box.innerHTML = '<p class="mcw-empty">没有匹配的版本，换个关键词试试。</p>';
    } else {
      var frag = document.createDocumentFragment();
      state.filtered.forEach(function (v) {
        var b = document.createElement('button');
        b.type = 'button';
        b.setAttribute('role', 'option');
        var on = state.version && state.version.id === v.id;
        b.className = on ? 'is-on' : '';
        b.setAttribute('aria-selected', on ? 'true' : 'false');
        b.innerHTML = '<span>' + esc(v.id) + '</span><span class="vtype">' +
          esc(TYPE_LABEL[v.type] || v.type) + (v.releaseTime ? ' · ' + fmtDate(v.releaseTime) : '') + '</span>';
        b.addEventListener('click', function () {
          state.version = v;
          persistSettings();
          renderVersions(); renderSummary(); renderModPick(); renderLauncherPick(); updateStepState();
        });
        frag.appendChild(b);
      });
      box.appendChild(frag);
      var onEl = box.querySelector('.is-on');
      if (onEl && onEl.scrollIntoView) onEl.scrollIntoView({ block: 'nearest' });
    }
    var meta = $('mcwVersionMeta');
    if (meta) {
      var total = state.versions.length;
      meta.innerHTML = (state.source === 'manifest'
        ? '已从官方版本清单读取 <b>' + total + '</b> 个版本'
        : '官方清单不可用，使用内置 <b>' + total + '</b> 个常用版本') +
        '；当前筛选 <b>' + state.filtered.length + '</b> 个' +
        (state.version ? '，已选择 <b>' + esc(state.version.id) + '</b>' : '');
    }
  }

  /* ---------------- 启动方式 ---------------- */
  function readModeFromDOM() {
    var el = document.querySelector('input[name="mcwMode"]:checked');
    return el ? el.value : 'web';
  }

  function renderLauncherPick() {
    var wrap = $('mcwLauncherPick');
    var sel = $('mcwLauncherSelect');
    var meta = $('mcwLauncherMeta');
    var hint = $('mcwModeHint');
    if (!wrap || !sel) return;
    var isLauncher = state.mode === 'launcher';
    wrap.hidden = !isLauncher;
    if (isLauncher) {
      sel.innerHTML = launchers.map(function (l) {
        return '<option value="' + esc(l.id) + '">' + esc(l.name) + (l.builtin ? '（内置）' : '') + '</option>';
      }).join('');
      if (!launchers.some(function (l) { return l.id === state.launcherId; })) {
        state.launcherId = launchers[0] ? launchers[0].id : '';
      }
      sel.value = state.launcherId;
      var cur = launchers.filter(function (l) { return l.id === state.launcherId; })[0];
      if (meta) {
        meta.innerHTML = cur
          ? '路径：' + esc(cur.path || '未填写') + ' · 内存 ' + esc(cur.memory) + ' MB<br>JVM：' + esc(cur.jvm || '默认')
          : '还没有可用启动器，请先在下方添加。';
      }
    }
    if (hint) {
      if (state.mode === 'web') {
        var v = state.version ? state.version.id : '';
        hint.innerHTML = WEB_CLIENTS[v]
          ? '当前版本 <b>' + esc(v) + '</b> 有对应的网页版客户端，点击「开始启动」会在新标签页打开。'
          : '当前版本 <b>' + esc(v || '—') + '</b> 没有内置网页客户端：点击「开始启动」后会在后台按 ' +
            'HMCL 源 → PCL 源 → MC百科 → 官方源 的顺序自动获取客户端与依赖，校验通过后写入实例目录并启动，' +
            '不会跳转页面，也不会弹出下载窗口。';
      } else if (state.mode === 'launcher') {
        hint.textContent = '将按所选启动器的内存与 JVM 参数生成本次实例的配置摘要，复制到启动器中使用。';
      } else {
        hint.textContent = '将下载一份 JSON 实例配置，包含版本、加载器、内存、JVM 参数与已启用的 模组清单。';
      }
    }
  }

  /* ---------------- Mod 选择 ---------------- */
  function modsForPick() {
    return mods;
  }
  function renderModPick() {
    var box = $('mcwModPick');
    var sum = $('mcwModSummary');
    if (!box) return;
    var list = modsForPick();
    if (!list.length) {
      box.innerHTML = '<p class="mcw-empty">还没有添加模组，可到下方「模组管理」添加。</p>';
    } else {
      box.innerHTML = '';
      list.forEach(function (m) {
        var label = document.createElement('label');
        label.className = 'mcw-opt';
        label.style.marginBottom = '6px';
        var compatible = isCompatible(m, state.version && state.version.id);
        label.innerHTML =
          '<input type="checkbox" ' + (state.enabled[m.id] ? 'checked' : '') + ' />' +
          '<span><strong>' + esc(m.name) + (m.version ? ' · ' + esc(m.version) : '') + '</strong>' +
          '<small>' + esc(m.loader || '未标注加载器') + ' · 适用 ' + esc(m.mcver || '未标注版本') +
          (compatible ? '' : ' · <span style="color:var(--warn,#ffc457)">可能与当前版本不匹配</span>') + '</small></span>';
        var cb = label.querySelector('input');
        cb.addEventListener('change', function () {
          state.enabled[m.id] = cb.checked;
          // 同步到数据层
          mods.forEach(function (x) { if (x.id === m.id) x.enabled = cb.checked; });
          save(KEY.MODS, mods);
          renderModPick(); renderMods(); renderSummary(); renderStats();
        });
        box.appendChild(label);
      });
    }
    if (sum) {
      var on = list.filter(function (m) { return state.enabled[m.id]; });
      sum.textContent = list.length
        ? '共 ' + list.length + ' 个模组，本次启用 ' + on.length + ' 个' + (on.length ? '：' + on.map(function (m) { return m.name; }).join('、') : '')
        : '';
    }
  }
  function isCompatible(m, ver) {
    if (!m || !m.mcver || !ver) return true;
    var want = String(m.mcver).trim().toLowerCase();
    var v = String(ver).toLowerCase();
    if (!want || want === '全版本' || want === '通用') return true;
    if (want.indexOf('x') >= 0) {
      var prefix = want.replace(/\.?x+$/i, '').replace(/\.x$/i, '');
      return v === prefix || v.indexOf(prefix + '.') === 0;
    }
    return v === want;
  }

  /* ---------------- 摘要与启动 ---------------- */
  function enabledMods() { return mods.filter(function (m) { return state.enabled[m.id]; }); }

  function currentLauncher() {
    return launchers.filter(function (l) { return l.id === state.launcherId; })[0] || null;
  }

  function renderSummary() {
    var box = $('mcwSummary');
    var cmd = $('mcwCmdBox');
    var copyBtn = $('mcwCopyBtn');
    var exportBtn = $('mcwExportBtn');
    var launchBtn = $('mcwLaunchBtn');
    if (!box) return;
    var v = state.version ? state.version.id : '未选择';
    var l = currentLauncher();
    var on = enabledMods();
    var rows = [
      ['版本', v + (state.version ? '（' + (TYPE_LABEL[state.version.type] || state.version.type) + '）' : '')],
      ['启动方式', state.mode === 'web' ? '浏览器网页版' : (state.mode === 'launcher' ? '本地启动器' : '导出实例配置')]
    ];
    if (state.mode === 'launcher') {
      rows.push(['启动器', l ? l.name : '未配置']);
      rows.push(['内存', l ? l.memory + ' MB' : '—']);
      rows.push(['JVM 参数', (l && l.jvm) || '默认']);
      rows.push(['游戏目录', (l && l.gamedir) || '—']);
    }
    rows.push(['启用模组', on.length ? on.length + ' 个' : '无']);
    if (on.length) rows.push(['模组清单', on.map(function (m) { return m.name + (m.version ? '(' + m.version + ')' : ''); }).join('、')]);

    var html = rows.map(function (r) {
      return '<p class="mcw-kv"><b>' + esc(r[0]) + '</b><span>' + esc(r[1]) + '</span></p>';
    }).join('');

    var mismatch = on.filter(function (m) { return !isCompatible(m, state.version && state.version.id); });
    if (mismatch.length) {
      html += '<p class="mcw-note" style="color:var(--warn,#ffc457)">注意：' + mismatch.length + ' 个模组 标注的适用版本与当前版本不一致，启动后可能加载失败。</p>';
    }
    if (state.mode === 'web' && !WEB_CLIENTS[v]) {
      html += '<p class="mcw-note">该版本没有内置网页客户端，启动时将由后台自动获取客户端资源并完成配置（静默进行，不跳转）。</p>';
    }
    box.innerHTML = html;

    if (launchBtn) {
      var noWeb = state.mode === 'web' && state.version && !WEB_CLIENTS[state.version.id];
      launchBtn.textContent = state.mode === 'web'
        ? (noWeb ? '后台准备并启动' : '打开网页版客户端')
        : (state.mode === 'launcher' ? '生成启动参数' : '下载实例配置');
    }
    // 参数摘要：仅本地启动器模式展示
    if (cmd) {
      if (state.mode === 'launcher' && l) {
        cmd.hidden = false;
        cmd.textContent = buildInstanceText(v, l, on);
        if (copyBtn) copyBtn.hidden = false;
      } else if (state.mode === 'export') {
        cmd.hidden = false;
        cmd.textContent = JSON.stringify(buildInstanceJson(v, l, on), null, 2);
        if (copyBtn) copyBtn.hidden = false;
      } else {
        cmd.hidden = true;
        if (copyBtn) copyBtn.hidden = true;
      }
    }
    if (exportBtn) exportBtn.hidden = state.mode !== 'export';
  }

  function buildInstanceText(version, launcher, on) {
    return [
      '实例名称：鸟国网站-' + version,
      '游戏版本：' + version,
      '启动器：' + launcher.name,
      '内存：' + launcher.memory + ' MB',
      'JVM 参数：' + (launcher.jvm || '默认'),
      '游戏目录：' + (launcher.gamedir || '默认'),
      launcher.extra ? '附加参数：' + launcher.extra : '',
      '启用的模组：' + (on.length ? on.map(function (m) { return m.name + (m.version ? ' ' + m.version : ''); }).join('；') : '无'),
      '',
      '操作步骤：',
      '1) 打开 ' + launcher.name + '，新建一个实例并选择版本 ' + version + '；',
      '2) 按需安装加载器（Fabric / Forge / NeoForge），版本与 Mod 标注一致；',
      '3) 在实例设置里把内存改为 ' + launcher.memory + ' MB，JVM 参数填入上面的值；',
      '4) 把启用的模组 文件放进实例的 mods 目录后启动。'
    ].filter(Boolean).join('\n');
  }

  function buildInstanceJson(version, launcher, on) {
    return {
      format: 'niao-mc-instance/1',
      name: '鸟国网站-' + version,
      mcVersion: version,
      launchMode: state.mode,
      launcher: launcher ? { name: launcher.name, type: launcher.type, path: launcher.path } : null,
      memoryMB: launcher ? launcher.memory : 4096,
      jvmArgs: launcher ? launcher.jvm : '',
      gameDir: launcher ? launcher.gamedir : './instances/' + version,
      mods: on.map(function (m) {
        return { name: m.name, version: m.version, loader: m.loader, mcver: m.mcver, file: m.file, enabled: true };
      }),
      exportedAt: new Date().toISOString(),
      note: '此文件由鸟国网站生成，仅包含实例参数与 模组清单，不含游戏本体。'
    };
  }

  function pushRecent(entry) {
    recent.unshift(entry);
    recent = recent.slice(0, 8);
    save(KEY.RECENT, recent);
    renderRecent();
  }

  function renderRecent() {
    var box = $('mcwRecent');
    if (!box) return;
    if (!recent.length) { box.innerHTML = '<p class="mcw-note">还没有启动记录。</p>'; return; }
    box.innerHTML = '<h4>最近启动</h4>' + recent.map(function (r) {
      return '<p class="mcw-kv"><b>' + esc(r.time) + '</b><span>' + esc(r.version) + ' · ' +
        esc(r.mode === 'web' ? '网页版' : (r.mode === 'launcher' ? '本地启动器' : '导出配置')) +
        (r.launcher ? ' · ' + esc(r.launcher) : '') + ' · Mod ' + (r.modCount || 0) + ' 个</span></p>';
    }).join('');
  }

  function doLaunch() {
    var msg = $('mcwLaunchMsg');
    if (!state.version) { if (msg) msg.textContent = '请先选择一个版本。'; return; }
    var v = state.version.id;
    var on = enabledMods();
    var stamp = new Date().toLocaleString('zh-CN', { hour12: false });

    if (state.mode === 'web') {
      var url = WEB_CLIENTS[v] || (Resolver && Resolver.WEB_CLIENTS ? Resolver.WEB_CLIENTS[v] : null);
      if (!url) {
        // 该版本没有网页客户端：改为后台静默获取资源，并在浏览器内尽力启动
        provisionLaunch(v);
        return;
      }
      pushRecent({ time: stamp, version: v, mode: 'web', modCount: on.length });
      if (msg) msg.innerHTML = '正在新标签页打开 <b>' + esc(v) + '</b> 的网页版客户端（Eaglercraft）。' +
        (on.length ? '注意：网页版不支持加载本地模组，已启用清单仅作记录。' : '');
      window.open(url, '_blank', 'noopener');
      return;
    }

    if (state.mode === 'launcher') {
      var l = currentLauncher();
      if (!l) { if (msg) msg.textContent = '还没有启动器，请先在下方「Mod 启动器管理」添加。'; return; }
      var text = buildInstanceText(v, l, on);
      if (msg) msg.innerHTML = '已生成 <b>' + esc(l.name) + '</b> 的实例参数，点「复制参数」粘贴到启动器里即可。';
      pushRecent({ time: stamp, version: v, mode: 'launcher', launcher: l.name, modCount: on.length });
      copyText(text, function (ok) {
        if (msg) msg.innerHTML = ok === false ? '复制失败，请手动从上方文本框复制。' : '参数已复制到剪贴板，去启动器里新建实例吧。';
      });
      return;
    }

    var json = JSON.stringify(buildInstanceJson(v, currentLauncher(), on), null, 2);
    download('我的世界实例-' + v + '.json', json);
    pushRecent({ time: stamp, version: v, mode: 'export', modCount: on.length });
    if (msg) msg.textContent = '实例配置已下载，可归档或按需导入启动器。';
  }

  /* ---------------- 后台资源准备与静默启动 ----------------
     适用：所选版本没有内置网页客户端（非 1.5.2 / 1.8.8）。
     行为：按 HMCL → PCL → MC百科 → 官方源 逐级获取客户端/依赖/资源，
           校验通过后写入实例目录并尝试启动；任一步失败即写日志并阻止启动。
           全流程不发 window.open、不触发 <a download>，无页面跳转与下载窗口。
     -------------------------------------------------------- */
  var prov = { abort: null, running: false, dirHandle: null, plan: null, last: null };

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  function provEls() {
    return {
      box: $('mcwProvision'), bar: $('mcwProvBar'), stage: $('mcwProvStage'),
      meta: $('mcwProvMeta'), log: $('mcwProvLog'), title: $('mcwProvTitle')
    };
  }

  function provSetup(title) {
    var e = provEls();
    if (!e.box) return;
    e.box.hidden = false;
    if (e.log) e.log.textContent = '';
    if (e.bar) e.bar.style.width = '0%';
    if (e.stage) e.stage.textContent = '准备中…';
    if (e.meta) e.meta.textContent = '未开始';
    if (e.title) e.title.textContent = title || '后台准备客户端资源';
  }

  function provLog(line, kind) {
    var e = provEls();
    if (!e.log) return;
    var t = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    var span = document.createElement('span');
    if (kind) span.className = kind;
    span.textContent = '[' + t + '] ' + line + '\n';
    e.log.appendChild(span);
    e.log.scrollTop = e.log.scrollHeight;
  }

  function provProgress(p) {
    var e = provEls();
    if (!e) return;
    var pct = p.total ? Math.min(100, Math.round((p.done / p.total) * 100)) : 0;
    if (e.bar) e.bar.style.width = pct + '%';
    if (e.stage) e.stage.textContent = p.label + (p.total ? '（' + p.done + ' / ' + p.total + '）' : '');
    if (e.meta && p.bytes) e.meta.textContent = '已获取 ' + fmtBytes(p.bytes);
  }

  function provSetMsg(html, warn) {
    var msg = $('mcwLaunchMsg');
    if (!msg) return;
    msg.innerHTML = html;
    msg.style.color = warn ? 'var(--warn,#ffc457)' : '';
  }

  async function ensureInstanceDir() {
    if (prov.dirHandle) return prov.dirHandle;
    if (!Resolver) return null;
    var saved = await Resolver.loadDirHandle();
    if (saved) {
      var ok = await Resolver.ensurePermission(saved, 'readwrite').catch(function () { return false; });
      if (ok) { prov.dirHandle = saved; return saved; }
    }
    if (!window.showDirectoryPicker) return null;
    try {
      var h = await window.showDirectoryPicker({ mode: 'readwrite' });
      prov.dirHandle = h;
      await Resolver.saveDirHandle(h);
      return h;
    } catch (e) {
      return null; // 用户取消选择
    }
  }

  async function provisionLaunch(version) {
    if (prov.running) return;
    if (!Resolver) {
      provSetMsg('资源解析模块未加载，无法准备客户端。', true);
      return;
    }
    var btn = $('mcwLaunchBtn');
    prov.running = true;
    prov.abort = new AbortController();
    provSetup('后台准备 ' + version + ' 的客户端资源');
    provLog('任务启动：' + version + '（静默模式，不跳转、不弹下载）');

    if (btn) { btn.disabled = true; btn.textContent = '正在准备…'; }
    provSetMsg('正在后台获取 <b>' + esc(version) + '</b> 的客户端与依赖，页面不会跳转。');

    // 实例目录：优先复用已授权的目录句柄，否则请求一次选择
    var dir = await ensureInstanceDir();
    if (dir) provLog('实例目录：' + dir.name);
    else provLog('未选择实例目录：本次仅准备到浏览器缓存，无法写入本地实例', 'warn');

    var l = currentLauncher();
    var memory = l ? l.memory : 4096;

    try {
      var res = await Resolver.resolve(version, {
        signal: prov.abort.signal,
        memoryMB: memory,
        assets: 'sample',
        onLog: function (line) {
          var kind = '';
          if (/✗|失败|缺失|阻止|不可用/.test(line)) kind = 'err';
          else if (/✓|就绪|完成|通过/.test(line)) kind = 'ok';
          if (/跳过|降级|警告|提示/.test(line)) kind = 'warn';
          provLog(line, kind);
        },
        onProgress: provProgress
      });

      prov.last = res;
      provLog('资源获取与校验通过：' + fmtBytes(res.stats.bytes) + '，来源 ' + res.source, 'ok');

      // 自动完成配置
      if (l) {
        res.plan.launcher = { name: l.name, type: l.type, path: l.path };
        provLog('已绑定启动器：' + l.name + '（内存 ' + memory + ' MB）');
      } else {
        provLog('未配置启动器：启动脚本已生成，但需要手动指定启动器路径', 'warn');
      }
      save(KEY.SETTINGS, { version: state.version ? state.version.id : '', mode: state.mode, launcherId: state.launcherId });
      try { localStorage.setItem('niao.mc.plan.v1', JSON.stringify(res.plan)); } catch (e) { }

      // 写入本地实例目录
      var dirOk = false;
      if (dir) {
        var mat = await Resolver.materialize(res.plan, dir, { onLog: function (x) { provLog(x); } });
        dirOk = true;
        provLog('实例目录写入完成：' + mat.written + ' 个文件（' + mat.dirName + '）', 'ok');
      }

      // 确认资源可用后再启动
      var lr = await Resolver.launch(res.plan, { onLog: function (x) { provLog(x); } });
      var stamp = new Date().toLocaleString('zh-CN', { hour12: false });
      var modNote = enabledMods().length ? '（' + enabledMods().length + ' 个模组已记录，网页版不加载本地模组）' : '';

      if (lr.ok && lr.mode === 'webrun') {
        provLog('已在浏览器内打开网页客户端：' + version, 'ok');
        provSetMsg('已就绪，并在新标签页打开 <b>' + esc(version) + '</b> 的网页版客户端，关掉设置页即可开始游戏。' + modNote);
        pushRecent({ time: stamp, version: version, mode: 'web', modCount: enabledMods().length });
      } else if (lr.ok && lr.mode === 'host') {
        provLog('本地服务已启动实例：' + (lr.pid ? 'pid ' + lr.pid : res.plan.id), 'ok');
        provSetMsg('已就绪，本地服务已启动客户端 <b>' + esc(version) + '</b>。' + modNote);
        pushRecent({ time: stamp, version: version, mode: 'launcher', launcher: l ? l.name : '本地服务', modCount: enabledMods().length });
      } else if (lr.ok) {
        provLog('已通过本地协议桥请求启动客户端。', 'ok');
        provSetMsg('已就绪并发出启动请求：<b>' + esc(version) + '</b>' + modNote);
        pushRecent({ time: stamp, version: version, mode: 'launcher', launcher: l ? l.name : '', modCount: enabledMods().length });
      } else {
        provLog('[' + lr.code + '] ' + lr.message, 'err');
        // 兜底：资源已就绪但无本地通路时，至少给出浏览器内可玩的入口
        var actions = '';
        if (lr.webUrl) {
          actions += ' <a class="btn primary" href="' + esc(lr.webUrl) + '" target="_blank" rel="noopener">浏览器内开玩</a>';
        }
        var tail = dirOk
          ? '<br>实例已写入 <b>' + esc(dir.name) + '</b>，也可用本地启动器打开该目录运行。'
          : '<br>尚未选择实例目录：点「选择实例目录」后可把已校验的资源写入本地实例。';
        provSetMsg('资源已就绪，但没有可用的启动通路：' + esc(lr.message) + tail + actions, true);
      }
    } catch (e) {
      var code = e && e.code ? e.code : 'E_UNKNOWN';
      var message = e && e.message ? e.message : String(e);
      provLog('错误 [' + code + '] ' + message, 'err');
      if (e && e.detail && e.detail.length) {
        provLog('受影响文件：' + e.detail.slice(0, 8).join('、') + (e.detail.length > 8 ? ' 等' : ''), 'err');
      }
      provLog('已阻止启动：资源未就绪或配置失败。', 'err');
      if (e && e.code === 'E_ABORT') {
        provSetMsg('已取消本次资源准备，启动未执行。', true);
      } else {
        provSetMsg('启动已阻止：' + esc(message) + '（详细原因见上方日志）', true);
      }
    } finally {
      prov.running = false;
      prov.abort = null;
      if (btn) { btn.disabled = false; renderSummary(); }
      var e = provEls();
      if (e.stage) e.stage.textContent = '流程结束';
      // 成功时保留 100% 进度，失败时保留中断位置
      if (e.bar && prov.last) e.bar.style.width = '100%';
    }
  }

  /* ---------------- 启动器管理 ---------------- */
  var editingLauncher = null;
  function renderLaunchers() {
    var grid = $('mcwLauncherGrid');
    if (!grid) return;
    if (!launchers.length) { grid.innerHTML = '<p class="mcw-empty">还没有启动器，点右上角「添加启动器」。</p>'; return; }
    grid.innerHTML = launchers.map(function (l) {
      var isDefault = l.id === state.launcherId;
      return '<div class="card">' +
        '<div class="mcw-item">' +
          '<div class="mcw-item__main">' +
            '<h4>' + esc(l.name) + (isDefault ? ' <span class="chip">默认</span>' : '') + (l.builtin ? ' <span class="chip">内置</span>' : '') + '</h4>' +
            '<p style="margin-bottom:6px;">' + esc(l.desc || '自定义启动器') + '</p>' +
            '<p class="mcw-kv"><b>类型</b><span>' + esc(launcherTypeLabel(l.type)) + '</span></p>' +
            '<p class="mcw-kv"><b>路径</b><span style="word-break:break-all;">' + esc(l.path || '未填写') + '</span></p>' +
            '<p class="mcw-kv"><b>内存</b><span>' + esc(l.memory) + ' MB</span></p>' +
            '<p class="mcw-kv"><b>JVM</b><span style="word-break:break-all;">' + esc(l.jvm || '默认') + '</span></p>' +
          '</div>' +
          '<div class="mcw-item__btns">' +
            (isDefault ? '' : '<button class="btn" type="button" data-act="default" data-id="' + esc(l.id) + '">设为默认</button>') +
            '<button class="btn" type="button" data-act="edit" data-id="' + esc(l.id) + '">编辑</button>' +
            '<button class="btn" type="button" data-act="delete" data-id="' + esc(l.id) + '">删除</button>' +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }
  function launcherTypeLabel(t) {
    return { prism: 'Prism Launcher', hmcl: 'HMCL', pcl2: 'PCL2', official: '官方启动器', multimc: 'MultiMC', custom: '自定义' }[t] || t || '自定义';
  }
  function openLauncherForm(l) {
    var form = $('mcwLauncherForm');
    if (!form) return;
    editingLauncher = l || null;
    $('mcwLauncherFormTitle').textContent = l ? '编辑启动器' : '添加启动器';
    $('mcwLName').value = l ? l.name : '';
    $('mcwLType').value = l ? (l.type || 'custom') : 'custom';
    $('mcwLPath').value = l ? (l.path || '') : '';
    $('mcwLMem').value = l ? (l.memory || 4096) : 4096;
    $('mcwLGameDir').value = l ? (l.gamedir || '') : '';
    $('mcwLJvm').value = l ? (l.jvm || '') : '';
    $('mcwLExtra').value = l ? (l.extra || '') : '';
    form.hidden = false;
    form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('mcwLName').focus();
  }
  function saveLauncher(e) {
    e.preventDefault();
    var name = $('mcwLName').value.trim();
    if (!name) { $('mcwLName').focus(); return; }
    var item = {
      id: editingLauncher ? editingLauncher.id : uid('launcher'),
      name: name,
      type: $('mcwLType').value,
      path: $('mcwLPath').value.trim(),
      memory: Math.max(512, parseInt($('mcwLMem').value, 10) || 4096),
      gamedir: $('mcwLGameDir').value.trim(),
      jvm: $('mcwLJvm').value.trim(),
      extra: $('mcwLExtra').value.trim(),
      builtin: editingLauncher ? !!editingLauncher.builtin : false,
      desc: editingLauncher ? editingLauncher.desc : '自定义启动器'
    };
    if (editingLauncher) {
      launchers = launchers.map(function (l) { return l.id === item.id ? item : l; });
    } else {
      launchers.push(item);
    }
    save(KEY.LAUNCHERS, launchers);
    if (!state.launcherId) { state.launcherId = item.id; persistSettings(); }
    editingLauncher = null;
    $('mcwLauncherForm').hidden = true;
    renderLaunchers(); renderLauncherPick(); renderSummary(); renderStats();
  }

  /* ---------------- 模组管理 ---------------- */
  var editingMod = null;
  function renderMods() {
    var grid = $('mcwModGrid');
    var count = $('mcwModCount');
    if (!grid) return;
    var q = ($('mcwModSearch') && $('mcwModSearch').value || '').trim().toLowerCase();
    var loader = $('mcwModLoader') ? $('mcwModLoader').value : '';
    var st = $('mcwModState') ? $('mcwModState').value : '';
    var list = mods.filter(function (m) {
      if (loader && (m.loader || '') !== loader) return false;
      if (st === 'on' && !m.enabled) return false;
      if (st === 'off' && m.enabled) return false;
      if (!q) return true;
      return [m.name, m.version, m.file, m.note, m.loader, m.mcver].join(' ').toLowerCase().indexOf(q) >= 0;
    });
    if (count) count.innerHTML = '共 <b>' + mods.length + '</b> 个模组，已启用 <b>' + mods.filter(function (m) { return m.enabled; }).length + '</b> 个；当前筛选显示 <b>' + list.length + '</b> 个。';
    if (!list.length) {
      grid.innerHTML = '<p class="mcw-empty">' + (mods.length ? '没有匹配的模组。' : '还没有模组，点「添加模组」开始记录。') + '</p>';
      return;
    }
    grid.innerHTML = list.map(function (m) {
      var compat = isCompatible(m, state.version && state.version.id);
      return '<div class="card mcw-card' + (m.enabled ? '' : ' is-off') + '">' +
        '<div class="mcw-item">' +
          '<div class="mcw-item__main">' +
            '<h4>' + esc(m.name) + (m.version ? ' <span class="chip">' + esc(m.version) + '</span>' : '') + '</h4>' +
            '<p style="margin-bottom:6px;" class="mcw-kv"><b>加载器</b><span>' + esc(m.loader || '未标注') + '</span></p>' +
            '<p class="mcw-kv"><b>适用版本</b><span>' + esc(m.mcver || '未标注') + (compat ? '' : ' <span style="color:var(--warn,#ffc457)">（与当前所选版本不一致）</span>') + '</span></p>' +
            '<p class="mcw-kv"><b>文件</b><span style="word-break:break-all;">' + esc(m.file || '未填写') + '</span></p>' +
            (m.note ? '<p class="mcw-kv"><b>备注</b><span>' + esc(m.note) + '</span></p>' : '') +
          '</div>' +
          '<div class="mcw-item__btns" style="align-items:center;">' +
            '<label class="mcw-switch"><input type="checkbox" data-act="toggle" data-id="' + esc(m.id) + '" ' + (m.enabled ? 'checked' : '') + ' />' + (m.enabled ? '已启用' : '已禁用') + '</label>' +
            '<button class="btn" type="button" data-act="edit" data-id="' + esc(m.id) + '">编辑</button>' +
            '<button class="btn" type="button" data-act="delete" data-id="' + esc(m.id) + '">删除</button>' +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');
  }
  function openModForm(m) {
    var form = $('mcwModForm');
    if (!form) return;
    editingMod = m || null;
    $('mcwModFormTitle').textContent = m ? '编辑模组' : '添加模组';
    $('mcwMName').value = m ? m.name : '';
    $('mcwMVersion').value = m ? (m.version || '') : '';
    $('mcwMLoader').value = m ? (m.loader || 'Fabric') : 'Fabric';
    $('mcwMMcver').value = m ? (m.mcver || '') : '';
    $('mcwMFile').value = m ? (m.file || '') : '';
    $('mcwMNote').value = m ? (m.note || '') : '';
    form.hidden = false;
    form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('mcwMName').focus();
  }
  function saveMod(e) {
    e.preventDefault();
    var name = $('mcwMName').value.trim();
    if (!name) { $('mcwMName').focus(); return; }
    var item = {
      id: editingMod ? editingMod.id : uid('mod'),
      name: name,
      version: $('mcwMVersion').value.trim(),
      loader: $('mcwMLoader').value,
      mcver: $('mcwMMcver').value.trim(),
      file: $('mcwMFile').value.trim(),
      note: $('mcwMNote').value.trim(),
      enabled: editingMod ? !!editingMod.enabled : true
    };
    if (editingMod) mods = mods.map(function (m) { return m.id === item.id ? item : m; });
    else mods.push(item);
    if (item.enabled) state.enabled[item.id] = true;
    save(KEY.MODS, mods);
    editingMod = null;
    $('mcwModForm').hidden = true;
    renderMods(); renderModPick(); renderSummary(); renderStats();
  }

  /* ---------------- 步骤与统计 ---------------- */
  function updateStepState() {
    var v = state.version;
    var steps = document.querySelectorAll('.mcw-step');
    var done = { 1: !!v, 2: true, 3: true };
    steps.forEach(function (s) {
      var n = parseInt(s.getAttribute('data-step'), 10);
      s.classList.toggle('is-done', !!done[n]);
      s.classList.remove('is-on');
    });
  }
  function renderStats() {
    var box = $('mcwStats');
    if (!box) return;
    var onMods = mods.filter(function (m) { return m.enabled; }).length;
    box.innerHTML =
      '<span class="chip">可用版本 ' + state.versions.length + ' 个</span>' +
      '<span class="chip">启动器 ' + launchers.length + ' 个</span>' +
      '<span class="chip">模组 ' + mods.length + ' 个（启用 ' + onMods + '）</span>' +
      '<span class="chip">网页版支持 1.5.2 / 1.8.8</span>';
  }

  /* ---------------- 事件绑定 ---------------- */
  function bind() {
    // 版本筛选
    var vs = $('mcwVersionSearch');
    if (vs) vs.addEventListener('input', function () { state.q = vs.value || ''; renderVersions(); });
    var vt = $('mcwVersionType');
    if (vt) vt.addEventListener('change', function () { state.type = vt.value; renderVersions(); });

    // 启动方式
    Array.prototype.forEach.call(document.querySelectorAll('input[name="mcwMode"]'), function (r) {
      if (r.value === state.mode) r.checked = true;
      r.addEventListener('change', function () {
        state.mode = readModeFromDOM();
        persistSettings();
        renderLauncherPick(); renderSummary();
      });
    });
    var ls = $('mcwLauncherSelect');
    if (ls) ls.addEventListener('change', function () {
      state.launcherId = ls.value;
      persistSettings();
      renderLauncherPick(); renderSummary(); renderLaunchers();
    });

    // 启动
    var launchBtn = $('mcwLaunchBtn');
    if (launchBtn) launchBtn.addEventListener('click', doLaunch);

    // 后台资源准备面板
    var provCancel = $('mcwProvCancel');
    if (provCancel) provCancel.addEventListener('click', function () {
      if (prov.abort) { prov.abort.abort(); provLog('收到取消请求，正在中止…', 'warn'); }
    });
    var provDir = $('mcwProvDir');
    if (provDir) provDir.addEventListener('click', async function () {
      var h = await ensureInstanceDir();
      if (h) provLog('实例目录已选择：' + h.name);
      else provLog('未选择实例目录（浏览器可能不支持目录写入）', 'warn');
    });
    var copyBtn = $('mcwCopyBtn');
    if (copyBtn) copyBtn.addEventListener('click', function () {
      var box = $('mcwCmdBox');
      if (!box) return;
      copyText(box.textContent, function (ok) {
        copyBtn.textContent = ok === false ? '复制失败' : '已复制';
        setTimeout(function () { copyBtn.textContent = '复制参数'; }, 1400);
      });
    });
    var exportBtn = $('mcwExportBtn');
    if (exportBtn) exportBtn.addEventListener('click', function () {
      if (!state.version) return;
      download('我的世界实例-' + state.version.id + '.json',
        JSON.stringify(buildInstanceJson(state.version.id, currentLauncher(), enabledMods()), null, 2));
    });

    // 启动器
    var addL = $('mcwAddLauncher');
    if (addL) addL.addEventListener('click', function () { openLauncherForm(null); });
    var lForm = $('mcwLauncherForm');
    if (lForm) lForm.addEventListener('submit', saveLauncher);
    var lCancel = $('mcwLCancel');
    if (lCancel) lCancel.addEventListener('click', function () { editingLauncher = null; lForm.hidden = true; });
    var lGrid = $('mcwLauncherGrid');
    if (lGrid) lGrid.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('button[data-act]') : null;
      if (!b) return;
      var id = b.getAttribute('data-id');
      var it = launchers.filter(function (l) { return l.id === id; })[0];
      if (!it) return;
      var act = b.getAttribute('data-act');
      if (act === 'default') { state.launcherId = id; persistSettings(); renderLaunchers(); renderLauncherPick(); renderSummary(); }
      else if (act === 'edit') { openLauncherForm(it); }
      else if (act === 'delete') {
        if (!window.confirm('确定删除启动器「' + it.name + '」吗？')) return;
        launchers = launchers.filter(function (l) { return l.id !== id; });
        save(KEY.LAUNCHERS, launchers);
        if (state.launcherId === id) { state.launcherId = launchers[0] ? launchers[0].id : ''; persistSettings(); }
        renderLaunchers(); renderLauncherPick(); renderSummary(); renderStats();
      }
    });

    // Mod
    var addM = $('mcwAddMod');
    if (addM) addM.addEventListener('click', function () { openModForm(null); });
    var mForm = $('mcwModForm');
    if (mForm) mForm.addEventListener('submit', saveMod);
    var mCancel = $('mcwMCancel');
    if (mCancel) mCancel.addEventListener('click', function () { editingMod = null; mForm.hidden = true; });
    ['mcwModSearch', 'mcwModLoader', 'mcwModState'].forEach(function (id) {
      var el = $(id);
      if (!el) return;
      el.addEventListener(id === 'mcwModSearch' ? 'input' : 'change', renderMods);
    });
    var mGrid = $('mcwModGrid');
    if (mGrid) {
      mGrid.addEventListener('click', function (e) {
        var b = e.target.closest ? e.target.closest('button[data-act]') : null;
        if (!b) return;
        var id = b.getAttribute('data-id');
        var it = mods.filter(function (m) { return m.id === id; })[0];
        if (!it) return;
        var act = b.getAttribute('data-act');
        if (act === 'edit') openModForm(it);
        else if (act === 'delete') {
          if (!window.confirm('确定删除 Mod「' + it.name + '」吗？')) return;
          mods = mods.filter(function (m) { return m.id !== id; });
          delete state.enabled[id];
          save(KEY.MODS, mods);
          renderMods(); renderModPick(); renderSummary(); renderStats();
        }
      });
      mGrid.addEventListener('change', function (e) {
        var cb = e.target;
        if (!cb || cb.getAttribute('data-act') !== 'toggle') return;
        var id = cb.getAttribute('data-id');
        mods = mods.map(function (m) { return m.id === id ? Object.assign({}, m, { enabled: cb.checked }) : m; });
        if (cb.checked) state.enabled[id] = true; else delete state.enabled[id];
        save(KEY.MODS, mods);
        renderMods(); renderModPick(); renderSummary(); renderStats();
      });
    }
    var exportMods = $('mcwExportMods');
    if (exportMods) exportMods.addEventListener('click', function () {
      download('我的世界Mod清单.json', JSON.stringify({
        exportedAt: new Date().toISOString(),
        selectedVersion: state.version ? state.version.id : '',
        mods: mods
      }, null, 2));
    });
  }

  /* ---------------- 启动 ---------------- */
  function boot() {
    initData();
    renderStats();
    renderLaunchers();
    renderMods();
    renderRecent();
    renderLauncherPick();
    renderSummary();
    renderModPick();
    bind();
    loadVersions();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
