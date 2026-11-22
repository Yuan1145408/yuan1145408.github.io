/* ============================================================
   Mod 搜索与批量下载引擎
   ------------------------------------------------------------
   结构（与本文件内的分节注释一致）：
     1. 数据结构
     2. 搜索汇总流程（多来源并发、超时、部分结果、去重）
     3. 下载选择逻辑（依赖展开、必需/可选、去重、版本冲突、循环依赖）
     4. 下载与导入流程（流式进度、SHA-1 校验、jar 解析、写盘）
     5. 异常处理与状态反馈（错误码表、状态机、日志）
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  /* ============================================================
     1. 数据结构
     ============================================================ */

  // 下载状态机：idle → queued → downloading → done | failed
  //             unavailable（来源不提供文件）/ skipped（未勾选）
  var STATE_LABEL = {
    idle: '未开始',
    queued: '排队中',
    downloading: '下载中',
    done: '成功',
    failed: '失败',
    unavailable: '不可下载',
    skipped: '已跳过'
  };

  var ERR_TEXT = {
    E_ABORT: '操作已取消',
    E_TIMEOUT: '请求超时',
    E_NET: '网络失败或跨域被拦截',
    E_HTTP: '服务返回错误',
    E_PARSE: '返回内容无法解析',
    E_NO_VERSION: '没有适配当前版本/加载器的文件',
    E_DEP_MISSING: '依赖缺失',
    E_DEP_CYCLE: '存在循环依赖',
    E_CONFLICT: '版本冲突',
    E_INCOMPAT: '与当前版本不兼容',
    E_DOWNLOAD: '下载失败',
    E_HASH: '文件校验失败（可能已损坏）',
    E_SIZE: '文件大小不符',
    E_CORRUPT: '文件损坏（不是有效 jar）',
    E_FS_DENIED: '目录写入被拒绝',
    E_IMPORT_DUP: '模组 ID 重复',
    E_NO_DIR: '尚未选择游戏目录',
    E_UNKNOWN: '未知错误'
  };

  var LOADER_SET = { fabric: 1, forge: 1, neoforge: 1, quilt: 1 };

  function err(code, message, detail) {
    var e = new Error(message || ERR_TEXT[code] || code);
    e.code = code;
    e.detail = detail || '';
    return e;
  }

  /**
   * 统一记录结构（每个来源都必须映射成这个形状）
   * @typedef {Object} ModRecord
   * @property {string} key          唯一键 source:projectId
   * @property {string} source       modrinth | mcmod
   * @property {string} sourceLabel  展示名
   * @property {string} projectId    来源内的项目 ID
   * @property {string} name
   * @property {string} summary
   * @property {string} versionNumber 展示用版本（解析后填真实版本号）
   * @property {string[]} gameVersions
   * @property {string[]} loaders
   * @property {Array} dependencies   [{projectId, versionId, type, name}]
   * @property {string} state        STATE_LABEL 的键
   * @property {number} progress     0-100
   * @property {?string} error
   * @property {?Object} file        {url, filename, size, sha1}
   * @property {boolean} selected
   * @property {boolean} downloadable
   */
  function makeRecord(src) {
    return {
      key: src.key,
      source: src.source,
      sourceLabel: src.sourceLabel,
      projectId: src.projectId || '',
      slug: src.slug || '',
      name: src.name || '未命名',
      summary: src.summary || '',
      versionNumber: src.versionNumber || '',
      gameVersions: src.gameVersions || [],
      loaders: src.loaders || [],
      dependencies: src.dependencies || [],
      state: 'idle',
      progress: 0,
      error: null,
      file: null,
      selected: false,
      downloadable: src.downloadable !== false,
      iconUrl: src.iconUrl || '',
      url: src.url || '',
      downloads: src.downloads || 0,
      sources: src.sources || [src.sourceLabel]
    };
  }

  var state = {
    seq: 0,
    records: [],
    selected: new Set(),
    plan: null,
    optionalOn: new Set(),
    files: new Map(),      // key -> Blob（本次会话下载缓存）
    busy: false,
    abort: null,
    gameVersion: '1.20.1',
    loader: '',
    statuses: {},
    dropped: 0,
    dirHandle: null
  };

  /* ---------------- 基础工具 ---------------- */

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtSize(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function fmtBytes(n) { return fmtSize(n); }

  function normName(s) {
    return String(s || '')
      .toLowerCase()
      .replace(/\(.*?\)|\[.*?\]|（.*?）|【.*?】/g, '')
      .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, '');
  }

  function stripTags(s) {
    return String(s || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  }

  function log(msg, kind) {
    var box = $('msLog');
    var t = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    if (box) {
      var span = document.createElement('span');
      if (kind) span.className = kind;
      span.textContent = '[' + t + '] ' + msg + '\n';
      box.appendChild(span);
      box.scrollTop = box.scrollHeight;
    }
  }

  function setStats(html) {
    var box = $('msStats');
    if (box) box.innerHTML = html;
  }

  /* ---------------- 带超时 / 取消的网络请求 ---------------- */

  async function apiFetch(url, opts) {
    opts = opts || {};
    var timeout = opts.timeout || 10000;
    var outer = opts.signal;
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeout);
    function onOuter() { ctrl.abort(); }
    if (outer) {
      if (outer.aborted) { clearTimeout(timer); throw err('E_ABORT'); }
      outer.addEventListener('abort', onOuter, { once: true });
    }
    try {
      var res = await fetch(url, {
        signal: ctrl.signal,
        cache: 'no-store',
        headers: opts.headers || {}
      });
      if (!res.ok) throw err('E_HTTP', 'HTTP ' + res.status + ' ' + (opts.label || ''));
      if (opts.as === 'text') return await res.text();
      return await res.json();
    } catch (e) {
      if (e && e.code) throw e;
      if (e && e.name === 'AbortError') {
        throw err(outer && outer.aborted ? 'E_ABORT' : 'E_TIMEOUT',
          (outer && outer.aborted ? '已取消：' : '请求超时：') + (opts.label || url));
      }
      throw err('E_NET', '网络失败或跨域被拦截：' + (opts.label || url));
    } finally {
      clearTimeout(timer);
      if (outer) outer.removeEventListener('abort', onOuter);
    }
  }

  /* ============================================================
     2. 搜索汇总流程
     ============================================================ */

  function modrinthLoaders(hit) {
    var cats = (hit.categories || []).concat(hit.display_categories || []);
    return cats.filter(function (c) { return LOADER_SET[c]; })
      .filter(function (v, i, a) { return a.indexOf(v) === i; });
  }

  var SOURCES = [
    {
      id: 'modrinth',
      label: 'Modrinth',
      downloadable: true,
      async search(query, opts, signal) {
        var facets = [['project_type:mod']];
        if (opts.loader) facets.push(['categories:' + opts.loader]);
        if (opts.gameVersion) facets.push(['versions:' + opts.gameVersion]);
        var url = 'https://api.modrinth.com/v2/search?query=' + encodeURIComponent(query) +
          '&limit=' + (opts.limit || 20) + '&index=relevance&facets=' + encodeURIComponent(JSON.stringify(facets));
        var data = await apiFetch(url, { signal: signal, timeout: 9000, label: 'Modrinth 搜索' });
        var records = (data.hits || []).map(function (h) {
          return makeRecord({
            key: 'modrinth:' + h.project_id,
            source: 'modrinth',
            sourceLabel: 'Modrinth',
            projectId: h.project_id,
            slug: h.slug,
            name: h.title,
            summary: h.description,
            versionNumber: '',
            gameVersions: h.versions || [],
            loaders: modrinthLoaders(h),
            iconUrl: h.icon_url || '',
            url: 'https://modrinth.com/mod/' + (h.slug || h.project_id),
            downloads: h.downloads || 0,
            downloadable: true
          });
        });
        return { records: records, total: data.total_hits || records.length };
      },

      // 取适配当前游戏版本 + 加载器的最新文件
      async resolve(projectId, opts, signal) {
        var qs = [];
        if (opts.gameVersion) qs.push('game_versions=' + encodeURIComponent(JSON.stringify([opts.gameVersion])));
        if (opts.loader) qs.push('loaders=' + encodeURIComponent(JSON.stringify([opts.loader])));
        var base = 'https://api.modrinth.com/v2/project/' + projectId + '/version';
        var list = await apiFetch(base + (qs.length ? '?' + qs.join('&') : ''), {
          signal: signal, timeout: 9000, label: 'Modrinth 版本'
        });
        var fallback = false;
        if (!list.length && qs.length) {
          // 放宽筛选再试一次，用于给出"不兼容"的准确判断
          list = await apiFetch(base, { signal: signal, timeout: 9000, label: 'Modrinth 版本(全量)' });
          fallback = true;
        }
        if (!list.length) throw err('E_NO_VERSION', '该项目没有可用版本');
        var v = list[0];
        var file = (v.files || []).filter(function (f) { return f.primary; })[0] || (v.files || [])[0];
        if (!file) throw err('E_NO_VERSION', '该版本没有可下载文件');
        return {
          versionId: v.id,
          versionNumber: v.version_number,
          gameVersions: v.game_versions || [],
          loaders: v.loaders || [],
          datePublished: v.date_published || '',
          dependencies: (v.dependencies || []).map(function (d) {
            return {
              projectId: d.project_id || '',
              versionId: d.version_id || '',
              type: d.dependency_type || 'required'
            };
          }),
          file: {
            url: file.url,
            filename: file.filename,
            size: file.size,
            sha1: (file.hashes && file.hashes.sha1) || ''
          },
          incompatible: fallback && (opts.gameVersion || opts.loader)
        };
      },

      async projects(ids, signal) {
        if (!ids.length) return {};
        var data = await apiFetch('https://api.modrinth.com/v2/projects?ids=' +
          encodeURIComponent(JSON.stringify(ids)), { signal: signal, timeout: 9000, label: 'Modrinth 项目信息' });
        var map = {};
        (Array.isArray(data) ? data : []).forEach(function (p) {
          map[p.id] = { name: p.title, slug: p.slug, summary: p.description };
        });
        return map;
      }
    },
    {
      id: 'mcmod',
      label: 'MC百科',
      downloadable: false,  // 资料库：可用于发现，不提供直连文件
      async search(query, opts, signal) {
        var html = await apiFetch('https://search.mcmod.cn/s?key=' + encodeURIComponent(query), {
          signal: signal, timeout: 9000, as: 'text', label: 'MC百科 搜索'
        });
        var blocks = String(html).split('class="result-item"').slice(1, 9);
        var records = [];
        blocks.forEach(function (b) {
          // 注意：.head 里第一个 <a> 是分类图标链接，必须精确匹配 /class/<数字>.html
          var head = b.match(/<a[^>]*href="([^"]*\/class\/\d+\.html)"[^>]*>([\s\S]*?)<\/a>/);
          if (!head) return;
          var url = head[1].indexOf('//') === 0 ? 'https:' + head[1] : head[1];
          var name = stripTags(head[2]);
          if (!name) return;
          var body = b.match(/<div class="body">([\s\S]*?)<\/div>/);
          records.push(makeRecord({
            key: 'mcmod:' + url,
            source: 'mcmod',
            sourceLabel: 'MC百科',
            projectId: url,
            name: name,
            summary: body ? stripTags(body[1]).slice(0, 180) : '',
            versionNumber: '—',
            gameVersions: [],
            loaders: [],
            url: url,
            downloadable: false
          }));
        });
        return { records: records, total: records.length };
      }
    }
  ];

  function sourceById(id) {
    return SOURCES.filter(function (s) { return s.id === id; })[0];
  }

  function enabledSources() {
    var out = [];
    if ($('msSrcModrinth') && $('msSrcModrinth').checked) out.push(sourceById('modrinth'));
    if ($('msSrcMcmod') && $('msSrcMcmod').checked) out.push(sourceById('mcmod'));
    return out;
  }

  // 去重：同一来源按 projectId；跨来源按归一化名称
  function dedupe(records) {
    var byKey = new Map();
    var byName = new Map();
    var dropped = 0;

    records.forEach(function (r) {
      var existing = byKey.get(r.key);
      if (existing) {
        // 同源重复：合并更完整的一条
        if (r.summary.length > existing.summary.length) existing.summary = r.summary;
        if (r.loaders.length > existing.loaders.length) existing.loaders = r.loaders;
        dropped++;
        return;
      }
      byKey.set(r.key, r);
    });

    var out = [];
    byKey.forEach(function (r) {
      var n = normName(r.name);
      var twin = n ? byName.get(n) : null;
      if (twin) {
        // 跨源重复：保留可下载的、信息更全的，合并来源标记
        var keep = r.downloadable && !twin.downloadable ? r : twin;
        var other = keep === r ? twin : r;
        keep.sources = (keep.sources || []).concat(other.sources || [])
          .filter(function (v, i, a) { return a.indexOf(v) === i; });
        if (!keep.summary && other.summary) keep.summary = other.summary;
        if (!keep.loaders.length && other.loaders.length) keep.loaders = other.loaders;
        byName.set(n, keep);
        dropped++;
        return;
      }
      if (n) byName.set(n, r);
      out.push(r);
    });

    // 用 byName 的内容替换 out 里的旧对象
    out = out.map(function (r) {
      var n = normName(r.name);
      return (n && byName.get(n)) || r;
    }).filter(function (r, i, a) { return a.indexOf(r) === i; });

    return { records: out, dropped: dropped };
  }

  async function runSearch() {
    var q = ($('msQuery') && $('msQuery').value || '').trim();
    if (!q) { log('请输入关键词。', 'warn'); return; }
    if (state.busy) { log('已有任务在进行，请先等待或取消。', 'warn'); return; }

    var sources = enabledSources();
    if (!sources.length) { log('至少选择一个数据来源。', 'warn'); return; }

    state.gameVersion = ($('msGameVer') && $('msGameVer').value || '').trim();
    state.loader = ($('msLoader') && $('msLoader').value) || '';
    var seq = ++state.seq;
    state.records = [];
    state.selected.clear();
    state.plan = null;
    state.optionalOn.clear();
    state.files.clear();
    renderTable();
    renderPlan();
    setStats('<span class="ms-chip">搜索中…</span>');

    log('搜索 “' + q + '” · 来源：' + sources.map(function (s) { return s.label; }).join('、') +
      (state.loader ? ' · 加载器 ' + state.loader : '') +
      (state.gameVersion ? ' · 版本 ' + state.gameVersion : ''));

    var statuses = {};
    var collected = [];

    var tasks = sources.map(function (src) {
      var t0 = Date.now();
      statuses[src.id] = { label: src.label, state: 'loading', count: 0, ms: 0, error: '' };
      return src.search(q, { loader: state.loader, gameVersion: state.gameVersion, limit: 20 },
        state.abort ? state.abort.signal : null)
        .then(function (res) {
          statuses[src.id] = {
            label: src.label, state: 'ok', count: res.records.length,
            ms: Date.now() - t0, error: '', total: res.total
          };
          return res.records;
        })
        .catch(function (e) {
          statuses[src.id] = {
            label: src.label, state: e.code === 'E_ABORT' ? 'aborted' : 'error',
            count: 0, ms: Date.now() - t0, error: e.message, code: e.code
          };
          return [];
        })
        .then(function (recs) {
          if (seq !== state.seq) return;      // 旧请求：丢弃，避免覆盖新结果
          collected = collected.concat(recs);
          var merged = dedupe(collected);
          state.records = merged.records;
          renderTable();
          renderSearchStatus(statuses, merged.dropped);
        });
    });

    await Promise.all(tasks);
    if (seq !== state.seq) return;

    var final = dedupe(collected);
    state.records = final.records;
    if ($('msOnlyDl') && $('msOnlyDl').checked) {
      state.records = state.records.filter(function (r) { return r.downloadable; });
    }
    renderTable();
    renderSearchStatus(statuses, final.dropped);

    var failed = Object.keys(statuses).filter(function (k) { return statuses[k].state === 'error'; });
    log('搜索完成：' + state.records.length + ' 条结果' +
      (final.dropped ? '（合并重复 ' + final.dropped + ' 条）' : '') +
      (failed.length ? '；' + failed.length + ' 个来源失败，已展示其余来源的部分结果' : ''), failed.length ? 'warn' : 'ok');
  }

  function renderSearchStatus(statuses, dropped) {
    if (statuses && Object.keys(statuses).length) { state.statuses = statuses; state.dropped = dropped || 0; }
    statuses = state.statuses || {};
    dropped = state.dropped || 0;
    var parts = [];
    Object.keys(statuses).forEach(function (k) {
      var s = statuses[k];
      var cls = s.state === 'ok' ? 'ok' : (s.state === 'error' ? 'err' : 'warn');
      var text = s.label + ' ' + (s.state === 'ok' ? s.count + ' 条 · ' + s.ms + 'ms'
        : (s.state === 'loading' ? '查询中…' : (s.error || '已取消')));
      parts.push('<span class="ms-chip ' + cls + '" title="' + esc(s.error || '') + '">' + esc(text) + '</span>');
    });
    parts.unshift('<span class="ms-chip">结果 ' + state.records.length + ' 条</span>');
    if (dropped) parts.push('<span class="ms-chip warn">去重 ' + dropped + ' 条</span>');
    var sel = state.selected.size;
    if (sel) parts.push('<span class="ms-chip ok">已选 ' + sel + ' 个</span>');
    setStats(parts.join(''));
  }

  /* ============================================================
     3. 下载选择逻辑
     ============================================================ */

  function versionState(r) {
    if (!r.downloadable) return 'unavailable';
    return r.state;
  }

  function depsText(r) {
    if (!r.dependencies || !r.dependencies.length) return '<span class="muted">待解析</span>';
    var req = r.dependencies.filter(function (d) { return d.type === 'required'; }).length;
    var opt = r.dependencies.filter(function (d) { return d.type === 'optional'; }).length;
    var inc = r.dependencies.filter(function (d) { return d.type === 'incompatible'; }).length;
    return '必需 <b>' + req + '</b> · 可选 <b>' + opt + '</b>' + (inc ? ' · <span style="color:#ff6b6b">冲突 ' + inc + '</span>' : '');
  }

  /**
   * 展开依赖并生成安装计划
   * @returns {{order:Array, optional:Array, conflicts:Array, cycles:Array, missing:Array, blocked:Array}}
   */
  async function buildPlan(roots, opts) {
    var signal = opts.signal;
    var modrinth = sourceById('modrinth');
    var chosen = new Map();     // projectId -> item
    var optional = new Map();
    var conflicts = [];
    var cycles = [];
    var missing = [];
    var blocked = [];
    var visiting = new Set();
    var visited = new Set();
    var order = [];
    var nameCache = {};

    async function ensureNames(ids) {
      var need = ids.filter(function (id) { return id && !nameCache[id]; });
      if (!need.length) return;
      try {
        var map = await modrinth.projects(need, signal);
        Object.keys(map).forEach(function (id) { nameCache[id] = map[id]; });
      } catch (e) {
        log('依赖名称获取失败：' + e.message, 'warn');
      }
    }

    async function resolveItem(projectId, fallbackName) {
      // 已确定过的项目直接复用，避免重复请求
      if (chosen.has(projectId)) return chosen.get(projectId);
      await ensureNames([projectId]);
      var info = nameCache[projectId] || {};
      var ver;
      try {
        ver = await modrinth.resolve(projectId, opts, signal);
      } catch (e) {
        if (e.code === 'E_ABORT') throw e;
        missing.push({
          projectId: projectId,
          name: info.name || fallbackName || projectId,
          reason: e.code === 'E_NO_VERSION' ? '没有适配当前版本/加载器的文件' : e.message
        });
        return null;
      }
      var item = {
        key: 'modrinth:' + projectId,
        projectId: projectId,
        name: info.name || fallbackName || projectId,
        summary: info.summary || '',
        versionId: ver.versionId,
        versionNumber: ver.versionNumber,
        gameVersions: ver.gameVersions,
        loaders: ver.loaders,
        dependencies: ver.dependencies,
        file: ver.file,
        state: 'idle',
        progress: 0,
        error: null,
        kind: 'required',
        incompatible: ver.incompatible
      };
      chosen.set(projectId, item);
      return item;
    }

    // 根节点先去重：同一项目只保留一次
    var rootIds = [];
    roots.forEach(function (r) {
      if (rootIds.indexOf(r.projectId) < 0) rootIds.push(r.projectId);
    });

    var rootsResolved = [];
    for (var i = 0; i < rootIds.length; i++) {
      var id = rootIds[i];
      var r = roots.filter(function (x) { return x.projectId === id; })[0];
      var item = await resolveItem(id, r.name);
      if (!item) continue;
      item.kind = 'root';
      item.selectedRoot = true;
      item.summary = r.summary || item.summary;
      if (r.loaders && r.loaders.length) item.loaders = r.loaders;
      rootsResolved.push(item);
    }

    // 深度优先展开，同时检测环
    async function visit(item, stack) {
      if (visited.has(item.projectId)) return;
      if (visiting.has(item.projectId)) return;
      visiting.add(item.projectId);
      stack.push(item.projectId);

      var deps = (item.dependencies || []);
      await ensureNames(deps.map(function (d) { return d.projectId; }));

      for (var k = 0; k < deps.length; k++) {
        var dep = deps[k];
        if (!dep.projectId) continue;
        var depName = (nameCache[dep.projectId] && nameCache[dep.projectId].name) || dep.projectId;

        if (dep.type === 'incompatible') {
          blocked.push({ name: item.name, other: depName, reason: '声明与 ' + depName + ' 不兼容' });
          continue;
        }

        if (dep.type === 'optional') {
          if (!optional.has(dep.projectId) && !chosen.has(dep.projectId)) {
            optional.set(dep.projectId, {
              projectId: dep.projectId, name: depName,
              requiredBy: [item.name], type: 'optional', item: null
            });
          }
          continue;
        }

        // required
        if (visiting.has(dep.projectId)) {
          cycles.push(stack.slice().concat(dep.projectId));
          continue;
        }

        var existing = chosen.get(dep.projectId);
        if (existing) {
          if (dep.versionId && existing.versionId && dep.versionId !== existing.versionId &&
              existing.kind !== 'root') {
            conflicts.push({
              projectId: dep.projectId, name: existing.name,
              keep: existing.versionNumber, dropped: dep.versionId,
              reason: '不同依赖要求了不同版本，已保留较新的一个'
            });
          }
          await visit(existing, stack);
          continue;
        }

        var child = await resolveItem(dep.projectId, depName);
        if (!child) continue;
        child.kind = 'required';
        child.requiredBy = [item.name];
        await visit(child, stack);
      }

      visiting.delete(item.projectId);
      visited.add(item.projectId);
      stack.pop();
      order.push(item);   // 后序：依赖在前
    }

    for (var ri = 0; ri < rootsResolved.length; ri++) {
      await visit(rootsResolved[ri], []);
    }

    // 可选依赖：默认不下载，交由用户勾选
    for (var [, opt] of optional) {
      try {
        var it = await resolveItem(opt.projectId, opt.name);
        if (it) { opt.item = it; opt.item.kind = 'optional'; }
      } catch (e) { /* 可选依赖解析失败不影响主流程 */ }
    }

    return {
      order: order,
      roots: rootsResolved,
      optional: Array.from(optional.values()),
      conflicts: conflicts,
      cycles: cycles,
      missing: missing,
      blocked: blocked
    };
  }

  async function planSelected() {
    var selected = state.records.filter(function (r) { return state.selected.has(r.key) && r.downloadable; });
    if (!selected.length) { log('请先勾选要下载的 Mod。', 'warn'); return null; }
    if (state.busy) { log('已有任务在进行。', 'warn'); return null; }

    state.busy = true;
    state.abort = new AbortController();
    toggleBusy(true);
    log('开始解析依赖：' + selected.length + ' 个根节点…');

    try {
      var plan = await buildPlan(selected, {
        gameVersion: state.gameVersion,
        loader: state.loader,
        signal: state.abort.signal
      });
      state.plan = plan;

      // 回填搜索结果里的版本号与依赖信息
      plan.order.forEach(function (item) {
        var r = state.records.filter(function (x) { return x.projectId === item.projectId; })[0];
        if (!r) return;
        r.versionNumber = item.versionNumber;
        r.dependencies = item.dependencies;
      });

      log('依赖解析完成：共 ' + plan.order.length + ' 个待安装' +
        (plan.optional.length ? '，可选 ' + plan.optional.length + ' 个' : '') +
        (plan.missing.length ? '，缺失 ' + plan.missing.length + ' 个' : '') +
        (plan.cycles.length ? '，循环依赖 ' + plan.cycles.length + ' 处' : ''), 'ok');
      renderTable();
      renderPlan();
      renderSearchStatus({}, 0);
      return plan;
    } catch (e) {
      if (e.code === 'E_ABORT') log('依赖解析已取消。', 'warn');
      else log('[' + e.code + '] 依赖解析失败：' + e.message, 'err');
      return null;
    } finally {
      state.busy = false;
      state.abort = null;
      toggleBusy(false);
    }
  }

  function renderPlan() {
    var box = $('msDepBox');
    var sum = $('msDepSummary');
    var plan = state.plan;
    if (!box) return;
    if (!plan) {
      box.innerHTML = '<div class="ms-empty">暂无解析结果。</div>';
      if (sum) sum.textContent = '勾选 Mod 后点「解析依赖」。';
      return;
    }

    var html = '';
    html += '<p class="ms-kv" style="font-size:var(--fs-xs);color:var(--muted);">' +
      '安装顺序（依赖优先）：' + plan.order.map(function (i) { return esc(i.name); }).join(' → ') + '</p>';

    html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);">必需依赖（自动包含）</h5>';
    var required = plan.order.filter(function (i) { return i.kind !== 'root'; });
    if (!required.length) html += '<div class="ms-empty">没有额外必需依赖。</div>';
    required.forEach(function (i) {
      html += '<div class="ms-dep-item">' +
        '<input type="checkbox" checked disabled />' +
        '<span><strong>' + esc(i.name) + '</strong> <small>' + esc(i.versionNumber) +
        (i.requiredBy && i.requiredBy.length ? ' · 被 ' + esc(i.requiredBy.join('、')) + ' 需要' : '') +
        (i.incompatible ? ' · <span style="color:#ffc457">与当前版本不完全匹配</span>' : '') +
        '</small></span></div>';
    });

    html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);">可选依赖（按需勾选）</h5>';
    if (!plan.optional.length) html += '<div class="ms-empty">没有可选依赖。</div>';
    plan.optional.forEach(function (o) {
      var on = state.optionalOn.has(o.projectId);
      html += '<label class="ms-dep-item" style="cursor:pointer;">' +
        '<input type="checkbox" data-opt="' + esc(o.projectId) + '" ' + (on ? 'checked' : '') +
        (o.item ? '' : ' disabled') + ' />' +
        '<span><strong>' + esc(o.name) + '</strong> <small>' +
        (o.item ? esc(o.item.versionNumber) : '解析失败，无法下载') +
        ' · 由 ' + esc(o.requiredBy.join('、')) + ' 声明为可选</small></span></label>';
    });

    if (plan.conflicts.length) {
      html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);color:#ffc457;">版本冲突</h5>';
      plan.conflicts.forEach(function (c) {
        html += '<p class="ms-kv" style="font-size:var(--fs-xs);color:var(--muted);">' +
          esc(c.name) + '：保留 <b>' + esc(c.keep) + '</b>，忽略 ' + esc(c.dropped) + '（' + esc(c.reason) + '）</p>';
      });
    }
    if (plan.cycles.length) {
      html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);color:#ffc457;">循环依赖</h5>';
      plan.cycles.forEach(function (cy) {
        html += '<p class="ms-kv" style="font-size:var(--fs-xs);color:var(--muted);">检测到环：' +
          esc(cy.join(' → ')) + '（已断开，不会死循环）</p>';
      });
    }
    if (plan.missing.length) {
      html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);color:#ff6b6b;">缺失依赖</h5>';
      plan.missing.forEach(function (m) {
        html += '<p class="ms-kv" style="font-size:var(--fs-xs);color:#ff6b6b;">' +
          esc(m.name) + '：' + esc(m.reason) + '</p>';
      });
    }
    if (plan.blocked.length) {
      html += '<h5 style="margin:var(--sp-3) 0 4px;font-size:var(--fs-sm);color:#ff6b6b;">不兼容声明</h5>';
      plan.blocked.forEach(function (b) {
        html += '<p class="ms-kv" style="font-size:var(--fs-xs);color:#ff6b6b;">' +
          esc(b.name) + ' ' + esc(b.reason) + '</p>';
      });
    }

    box.innerHTML = html;
    if (sum) {
      sum.textContent = '安装 ' + plan.order.length + ' 个（必需）' +
        ' · 可选 ' + plan.optional.length + ' 个 · 冲突 ' + plan.conflicts.length +
        ' · 循环 ' + plan.cycles.length + ' · 缺失 ' + plan.missing.length;
    }

    box.querySelectorAll('input[data-opt]').forEach(function (cb) {
      cb.addEventListener('change', function () {
        var id = cb.getAttribute('data-opt');
        if (cb.checked) state.optionalOn.add(id); else state.optionalOn.delete(id);
        log((cb.checked ? '加入可选依赖：' : '移除可选依赖：') + id);
      });
    });
  }

  /* ============================================================
     4. 下载与导入
     ============================================================ */

  async function sha1Hex(buf) {
    var d = await crypto.subtle.digest('SHA-1', buf);
    return Array.prototype.map.call(new Uint8Array(d), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  async function fetchBlob(url, onProgress, signal) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 120000);
    function onOuter() { ctrl.abort(); }
    if (signal) {
      if (signal.aborted) { clearTimeout(timer); throw err('E_ABORT'); }
      signal.addEventListener('abort', onOuter, { once: true });
    }
    try {
      var res = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
      if (!res.ok) throw err('E_DOWNLOAD', 'HTTP ' + res.status);
      var total = Number(res.headers.get('content-length')) || 0;
      if (!res.body || !res.body.getReader) {
        var b0 = await res.blob();
        onProgress && onProgress(100, b0.size);
        return b0;
      }
      var reader = res.body.getReader();
      var chunks = [];
      var received = 0;
      while (true) {
        var step = await reader.read();
        if (step.done) break;
        chunks.push(step.value);
        received += step.value.length;
        if (onProgress) onProgress(total ? Math.min(99, Math.round(received / total * 100)) : 0, received);
      }
      var blob = new Blob(chunks, { type: 'application/java-archive' });
      onProgress && onProgress(100, blob.size);
      return blob;
    } catch (e) {
      if (e && e.code) throw e;
      if (e && e.name === 'AbortError') throw err(signal && signal.aborted ? 'E_ABORT' : 'E_TIMEOUT', '下载超时或已取消');
      throw err('E_DOWNLOAD', '网络失败');
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onOuter);
    }
  }

  // 轻量 ZIP 解析：读中央目录，按需解出指定条目文本
  async function openZip(blob) {
    var buf = new Uint8Array(await blob.arrayBuffer());
    if (buf.length < 22 || buf[0] !== 0x50 || buf[1] !== 0x4b) {
      throw err('E_CORRUPT', '不是有效的 jar（缺少 ZIP 头）');
    }
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var eocd = -1;
    var floor = Math.max(0, buf.length - 66000);
    for (var i = buf.length - 22; i >= floor; i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw err('E_CORRUPT', '不是有效的 jar（找不到中央目录）');
    var count = dv.getUint16(eocd + 10, true);
    var cd = dv.getUint32(eocd + 16, true);
    if (cd >= buf.length) throw err('E_CORRUPT', '中央目录偏移越界');
    var entries = [];
    var p = cd;
    for (var k = 0; k < count && p + 46 <= buf.length; k++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      var method = dv.getUint16(p + 10, true);
      var compSize = dv.getUint32(p + 20, true);
      var nameLen = dv.getUint16(p + 28, true);
      var extraLen = dv.getUint16(p + 30, true);
      var commLen = dv.getUint16(p + 32, true);
      var localOff = dv.getUint32(p + 42, true);
      var name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nameLen));
      entries.push({ name: name, method: method, compSize: compSize, localOff: localOff });
      p += 46 + nameLen + extraLen + commLen;
    }
    return { buf: buf, dv: dv, entries: entries };
  }

  async function zipText(zip, name) {
    var e = null;
    for (var i = 0; i < zip.entries.length; i++) {
      if (zip.entries[i].name === name) { e = zip.entries[i]; break; }
    }
    if (!e) return null;
    var p = e.localOff;
    if (p + 30 > zip.buf.length || zip.dv.getUint32(p, true) !== 0x04034b50) return null;
    var nameLen = zip.dv.getUint16(p + 26, true);
    var extraLen = zip.dv.getUint16(p + 28, true);
    var start = p + 30 + nameLen + extraLen;
    var data = zip.buf.subarray(start, start + e.compSize);
    if (e.method === 0) return new TextDecoder().decode(data);
    if (e.method === 8 && typeof DecompressionStream === 'function') {
      try {
        var ds = new DecompressionStream('deflate-raw');
        var stream = new Blob([data]).stream().pipeThrough(ds);
        return await new Response(stream).text();
      } catch (x) { return null; }
    }
    return null;
  }

  // 从 jar 里读模组元数据，用于去重与"文件损坏"判断
  async function readModMeta(blob) {
    var zip = await openZip(blob);
    var out = { id: '', name: '', version: '', loader: '' };
    var fj = await zipText(zip, 'fabric.mod.json');
    if (fj) {
      try {
        var j = JSON.parse(fj);
        out.id = j.id || '';
        out.name = j.name || '';
        out.version = j.version || '';
        out.loader = 'fabric';
        return out;
      } catch (e) { /* 继续尝试其他格式 */ }
    }
    var toml = await zipText(zip, 'META-INF/mods.toml') || await zipText(zip, 'mods.toml');
    if (toml) {
      var m = toml.match(/modId\s*=\s*"([^"]+)"/) || toml.match(/modId\s*=\s*'([^']+)'/);
      var v = toml.match(/version\s*=\s*"([^"]+)"/);
      if (m) out.id = m[1];
      if (v) out.version = v[1];
      out.loader = 'forge';
      return out;
    }
    var info = await zipText(zip, 'mcmod.info');
    if (info) {
      try {
        var arr = JSON.parse(info);
        var first = Array.isArray(arr) ? arr[0] : arr;
        out.id = first.modid || '';
        out.name = first.name || '';
        out.version = first.version || '';
        out.loader = 'legacy';
      } catch (e) { /* 忽略 */ }
    }
    return out;
  }

  async function downloadSelected() {
    if (!state.plan) {
      var p = await planSelected();
      if (!p) return;
    }
    if (state.busy) { log('已有任务在进行。', 'warn'); return; }
    var plan = state.plan;
    var queue = plan.order.slice();
    // 追加用户勾选的可选依赖
    plan.optional.forEach(function (o) {
      if (o.item && state.optionalOn.has(o.projectId)) queue.push(o.item);
    });
    if (!queue.length) { log('没有需要下载的项。', 'warn'); return; }

    state.busy = true;
    state.abort = new AbortController();
    toggleBusy(true);
    log('开始下载 ' + queue.length + ' 个文件（顺序按依赖拓扑）…');

    var okCount = 0, failCount = 0;
    for (var i = 0; i < queue.length; i++) {
      var item = queue[i];
      if (state.abort.signal.aborted) { log('下载已取消。', 'warn'); break; }
      if (state.files.has(item.key)) {
        item.state = 'done'; item.progress = 100;
        okCount++;
        continue;
      }
      var rec = state.records.filter(function (r) { return r.projectId === item.projectId; })[0];
      item.state = 'queued';
      if (rec) { rec.state = 'queued'; rec.progress = 0; }
      renderTable();

      try {
        item.state = 'downloading';
        if (rec) rec.state = 'downloading';
        var blob = await fetchBlob(item.file.url, function (pct) {
          item.progress = pct;
          if (rec) { rec.progress = pct; renderRow(rec); }
        }, state.abort.signal);

        // 完整性校验
        if (item.file.size && blob.size !== item.file.size) {
          throw err('E_SIZE', '大小不符（期望 ' + item.file.size + '，实际 ' + blob.size + '）');
        }
        if (item.file.sha1) {
          var got = await sha1Hex(await blob.arrayBuffer());
          if (got.toLowerCase() !== String(item.file.sha1).toLowerCase()) {
            throw err('E_HASH', 'SHA-1 校验失败');
          }
        }
        // jar 结构校验 + 元数据
        var meta = await readModMeta(blob);
        item.meta = meta;
        item.state = 'done';
        item.progress = 100;
        state.files.set(item.key, blob);
        if (rec) { rec.state = 'done'; rec.progress = 100; rec.error = null; rec.file = item.file; }
        okCount++;
        log('✓ ' + item.name + ' ' + item.versionNumber + '（' + fmtSize(blob.size) + '）' +
          (meta.id ? ' · modid=' + meta.id : ''), 'ok');
      } catch (e) {
        item.state = 'failed';
        item.error = (ERR_TEXT[e.code] || e.code) + (e.detail ? '：' + e.detail : '');
        if (rec) { rec.state = 'failed'; rec.error = item.error; }
        failCount++;
        log('✗ ' + item.name + '：' + item.error, 'err');
        if (e.code === 'E_ABORT') break;
      }
      renderTable();
      renderPlan();
    }

    state.busy = false;
    state.abort = null;
    toggleBusy(false);
    log('下载结束：成功 ' + okCount + ' 个，失败 ' + failCount + ' 个' +
      (failCount ? '（可重试：再次点击「下载选中」只补失败项）' : ''), failCount ? 'warn' : 'ok');
  }

  /* ---------------- 导入游戏 ---------------- */

  async function importToGame() {
    var plan = state.plan;
    if (!plan) { log('请先解析依赖并下载。', 'warn'); return; }
    var ready = plan.order.concat(plan.optional.filter(function (o) {
      return o.item && state.optionalOn.has(o.projectId);
    }).map(function (o) { return o.item; })).filter(function (i) {
      return state.files.has(i.key);
    });
    if (!ready.length) { log('没有已下载完成的文件（先点「下载选中」）。', 'warn'); return; }

    if (!window.showDirectoryPicker) { log('当前浏览器不支持目录写入，请使用 Chrome / Edge。', 'err'); return; }

    var dir = state.dirHandle;
    if (!dir) {
      try {
        dir = await window.showDirectoryPicker({ mode: 'readwrite' });
        state.dirHandle = dir;
      } catch (e) {
        log('已取消选择游戏目录。', 'warn');
        return;
      }
    }

    var modsDir;
    try {
      modsDir = await dir.getDirectoryHandle('mods', { create: true });
    } catch (e) {
      log('无法创建 mods 目录：' + e.message, 'err');
      return;
    }

    log('开始导入到 ' + dir.name + '/mods …');
    var results = [];
    var seenIds = new Map();

    for (var i = 0; i < ready.length; i++) {
      var item = ready[i];
      var blob = state.files.get(item.key);
      var res = { name: item.name, version: item.versionNumber, ok: false, reason: '' };
      try {
        if (!blob) throw err('E_DOWNLOAD', '本地缓存中没有该文件');
        var meta = item.meta || await readModMeta(blob);
        if (!meta || (!meta.id && !meta.version)) {
          // 结构校验：仍允许写入，但记录提示
          res.warning = '未能识别 modid / 版本，可能不是标准模组';
        }
        if (meta && meta.id) {
          if (seenIds.has(meta.id)) {
            throw err('E_IMPORT_DUP', '本批次已有相同 modid：' + seenIds.get(meta.id));
          }
          seenIds.set(meta.id, item.name);
        }
        var filename = (item.file && item.file.filename) || (item.name + '.jar');
        // 同名文件已存在：覆盖前记录，便于状态反馈
        var existed = false;
        try { await modsDir.getFileHandle(filename); existed = true; } catch (e) { existed = false; }
        var fh = await modsDir.getFileHandle(filename, { create: true });
        var w = await fh.createWritable();
        await w.write(blob);
        await w.close();
        // 回读校验写入大小
        var written = await (await fh.getFile()).size;
        if (written !== blob.size) throw err('E_UNKNOWN', '写入后大小不一致（' + written + ' ≠ ' + blob.size + '）');
        res.ok = true;
        res.file = filename;
        if (existed) { res.replaced = true; log('⚠ 已覆盖同名文件 ' + filename, 'warn'); }
        log('✓ 已导入 ' + filename, 'ok');
      } catch (e) {
        res.reason = (ERR_TEXT[e.code] || e.code) + (e.detail ? '：' + e.detail : (e.message ? '：' + e.message : ''));
        log('✗ 导入失败 ' + item.name + '：' + res.reason, 'err');
      }
      results.push(res);
    }

    renderImportResult(results, dir.name);
  }

  function renderImportResult(results, dirName) {
    var card = $('msImportCard');
    var box = $('msImportResult');
    if (!card || !box) return;
    var ok = results.filter(function (r) { return r.ok; }).length;
    var fail = results.length - ok;
    var html = '<p class="muted" style="margin-top:0;font-size:var(--fs-sm);">目标目录：<b>' +
      esc(dirName) + '/mods</b> · 成功 <b style="color:#4fd08a">' + ok + '</b> · 失败 <b style="color:#ff6b6b">' + fail + '</b></p>';
    html += '<div class="ms-table-wrap"><table class="ms-table"><thead><tr>' +
      '<th>模组</th><th style="width:110px;">版本</th><th style="width:90px;">结果</th><th>说明</th>' +
      '</tr></thead><tbody>';
    results.forEach(function (r) {
      html += '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.version || '—') + '</td>' +
        '<td class="ms-state ' + (r.ok ? 'done' : 'failed') + '">' + (r.ok ? '成功' : '失败') + '</td>' +
        '<td style="font-size:var(--fs-xs);color:var(--muted);">' +
        esc(r.ok ? (r.file || '已写入') + (r.replaced ? '（覆盖同名）' : '') + (r.warning ? '（' + r.warning + '）' : '') : r.reason) + '</td></tr>';
    });
    html += '</tbody></table></div>';
    box.innerHTML = html;
    card.hidden = false;
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ============================================================
     5. 状态反馈与渲染
     ============================================================ */

  function toggleBusy(busy) {
    ['msSearchBtn', 'msBtnPlan', 'msBtnDownload', 'msBtnImport'].forEach(function (id) {
      var el = $(id);
      if (el) el.disabled = !!busy;
    });
    var cancel = $('msBtnCancel');
    if (cancel) cancel.disabled = !busy;
  }

  function renderRow(r) {
    var tr = Array.prototype.filter.call(
      document.querySelectorAll('#msTable tr[data-key]'),
      function (el) { return el.getAttribute('data-key') === r.key; }
    )[0];
    if (!tr) return;
    var st = tr.querySelector('.ms-state');
    var label = STATE_LABEL[versionState(r)] || r.state;
    if (r.state === 'failed' && r.error) label += '：' + r.error;
    if (st) {
      st.className = 'ms-state ' + versionState(r);
      st.textContent = label;
      st.title = r.error || '';
    }
    var bar = tr.querySelector('.ms-bar i');
    if (bar) bar.style.width = (r.progress || 0) + '%';
  }

  function renderTable() {
    var tbody = $('msTable');
    if (!tbody) return;
    if (!state.records.length) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="ms-empty">没有结果。换个关键词，或检查来源是否可用。</div></td></tr>';
      return;
    }
    tbody.innerHTML = state.records.map(function (r) {
      var checked = state.selected.has(r.key) ? ' checked' : '';
      var disabled = r.downloadable ? '' : ' disabled';
      var ver = r.versionNumber || (r.gameVersions && r.gameVersions.length
        ? '支持至 ' + r.gameVersions[r.gameVersions.length - 1] : '—');
      var tags = (r.loaders || []).map(function (l) {
        return '<span class="ms-tag">' + esc(l) + '</span>';
      }).join('') + (r.sources && r.sources.length > 1
        ? '<span class="ms-tag">' + esc(r.sources.join(' / ')) + '</span>' : '');
      return '<tr data-key="' + esc(r.key) + '">' +
        '<td><input type="checkbox" data-sel="' + esc(r.key) + '"' + checked + disabled +
        ' style="width:15px;height:15px;accent-color:var(--primary);" /></td>' +
        '<td class="ms-name"><b>' + esc(r.name) + '</b><small>' + esc(r.summary || '无简介') + '</small>' +
        '<div class="ms-tags">' + tags + '</div></td>' +
        '<td>' + esc(ver) + '</td>' +
        '<td>' + esc(r.sourceLabel) + '</td>' +
        '<td class="ms-deps">' + depsText(r) + '</td>' +
        '<td><span class="ms-state ' + versionState(r) + '" title="' + esc(r.error || '') + '">' +
        esc(STATE_LABEL[versionState(r)] || r.state) + '</span>' +
        '<div class="ms-bar"><i style="width:' + (r.progress || 0) + '%"></i></div></td>' +
        '</tr>';
    }).join('');

    tbody.querySelectorAll('input[data-sel]').forEach(function (cb) {
      cb.addEventListener('change', function () {
        var key = cb.getAttribute('data-sel');
        if (cb.checked) state.selected.add(key); else state.selected.delete(key);
        renderSearchStatus({}, 0);
      });
    });
  }

  /* ---------------- 绑定 ---------------- */

  function bind() {
    var btn = $('msSearchBtn');
    if (btn) btn.addEventListener('click', runSearch);

    var input = $('msQuery');
    if (input) input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); runSearch(); }
    });

    var all = $('msSelectAll');
    if (all) all.addEventListener('change', function () {
      state.selected.clear();
      if (all.checked) {
        state.records.forEach(function (r) { if (r.downloadable) state.selected.add(r.key); });
        log('已全选 ' + state.selected.size + ' 个可下载项');
      }
      renderTable();
      renderSearchStatus({}, 0);
    });

    var planBtn = $('msBtnPlan');
    if (planBtn) planBtn.addEventListener('click', function () { planSelected(); });

    var dlBtn = $('msBtnDownload');
    if (dlBtn) dlBtn.addEventListener('click', function () { downloadSelected(); });

    var imBtn = $('msBtnImport');
    if (imBtn) imBtn.addEventListener('click', function () { importToGame(); });

    var cancel = $('msBtnCancel');
    if (cancel) cancel.addEventListener('click', function () {
      if (state.abort) { state.abort.abort(); log('已请求取消当前任务…', 'warn'); }
    });

    // 过滤"仅显示可下载"时即时刷新
    var onlyDl = $('msOnlyDl');
    if (onlyDl) onlyDl.addEventListener('change', function () {
      log(onlyDl.checked ? '仅显示可下载项（重新搜索后生效）' : '显示全部来源结果');
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();

  // 供自动化测试与调试使用
  window.ModSearch = {
    state: state,
    sources: SOURCES,
    search: runSearch,
    dedupe: dedupe,
    buildPlan: buildPlan,
    readModMeta: readModMeta,
    openZip: openZip,
    normalize: normName,
    errors: ERR_TEXT,
    _setGame: function (loader, ver) { state.loader = loader; state.gameVersion = ver; }
  };
})();
