/* ============================================================
   鸟国聚合搜索 · 前端主控
   ------------------------------------------------------------
   站内索引（search-index.json）+ 全网公开数据源（search-sources.js）
   能力：范围切换（全部/站内/全网）/ 分类筛选 / 来源筛选 / 关键词高亮 /
        搜索建议 / 最近搜索 / 键盘导航 / 分页 / 去重 + 相关性排序
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var PAGE_SIZE = 10;
  var RECENT_KEY = 'niao.search.recent';

  var CATS = [
    { key: 'all', label: '全部' },
    { key: 'software', label: '软件' },
    { key: 'tutorial', label: '教程' },
    { key: 'game', label: '游戏' },
    { key: 'os', label: '系统镜像' },
    { key: 'vm', label: '虚拟机' },
    { key: 'android', label: '安卓应用' },
    { key: 'page', label: '站内页面' }
  ];

  var SCOPES = [
    { key: 'all', label: '全部' },
    { key: 'site', label: '站内' },
    { key: 'web', label: '全网' }
  ];

  /* file:// 直开时浏览器会拦截 JSON 读取，这里给一份最小兜底，保证页面仍可用 */
  var FALLBACK_INDEX = [
    { title: '软件下载专区', url: 'downloads.html', desc: '聚合常用开发工具与浏览器的官方下载入口', kind: 'page', kindLabel: '站内页面', category: '下载', tags: [] },
    { title: '教程专区', url: 'tutorials.html', desc: '语言、框架与项目实战教程索引', kind: 'page', kindLabel: '站内页面', category: '教程', tags: [] },
    { title: '虚拟机专区', url: 'vm.html', desc: 'VirtualBox、VMware 等虚拟机工具', kind: 'page', kindLabel: '站内页面', category: '虚拟机', tags: [] },
    { title: '系统镜像专区', url: 'os.html', desc: 'Linux 发行版与 Windows 官方镜像入口', kind: 'page', kindLabel: '站内页面', category: '系统镜像', tags: [] },
    { title: '游戏专区', url: 'games.html', desc: '免费游戏与游戏平台整理', kind: 'page', kindLabel: '站内页面', category: '游戏', tags: [] },
    { title: '我的世界资源', url: 'minecraft.html', desc: '启动器、模组、光影与 MC 资料搜索入口', kind: 'page', kindLabel: '站内页面', category: '游戏', tags: ['Minecraft'] },
    { title: '安卓专区', url: 'android.html', desc: 'APK 资源与网页模式说明', kind: 'page', kindLabel: '站内页面', category: '安卓', tags: [] },
    { title: '任务中心', url: 'tasks.html', desc: '每日任务、积分与语言答题', kind: 'page', kindLabel: '站内页面', category: '任务', tags: [] },
    { title: '用户中心', url: 'user.html', desc: '登录注册、积分与资料绑定', kind: 'page', kindLabel: '站内页面', category: '账户', tags: [] }
  ];

  var state = {
    index: [], loaded: false,
    q: '', cat: 'all', scope: 'all', sourceFilter: 'all',
    busy: false, page: 0,
    siteAll: [],          // 站内全分类结果
    webResults: [],       // 全网结果
    statuses: [],         // 每个源的返回状态
    results: [],          // 合并后的最终列表
    relaxed: false, deduped: 0, webMs: 0,
    activeIdx: -1, treeKeys: [], lastElapsed: 0
  };

  /* ---------------- 工具 ---------------- */
  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(msg) {
    var el = $('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('is-on');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { el.classList.remove('is-on'); }, 1900);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy') ? resolve() : reject(new Error('copy failed')); }
      catch (e) { reject(e); }
      finally { document.body.removeChild(ta); }
    });
  }

  function absUrl(u) {
    try { return new URL(u, window.location.href).href; } catch (e) { return String(u || ''); }
  }
  function prettyUrl(u) {
    try { return decodeURI(absUrl(u)); } catch (e) { return absUrl(u); }
  }
  function hostOf(u) {
    try { return new URL(u, window.location.href).hostname.replace(/^www\./, ''); }
    catch (e) { return ''; }
  }
  function pathOf(u) {
    try {
      var url = new URL(u, window.location.href);
      var p = decodeURI(url.pathname + url.search);
      return p === '/' ? '' : p;
    } catch (e) { return ''; }
  }
  function canonical(u) {
    if (window.NiaoWeb && window.NiaoWeb.canonicalUrl) return window.NiaoWeb.canonicalUrl(u);
    return String(u || '').toLowerCase();
  }

  /* ---------------- 分词 / 高亮 ---------------- */
  function tokenize(q) {
    var s = String(q || '').toLowerCase().trim();
    if (!s) return [];
    var out = [];
    (s.match(/[a-z0-9][a-z0-9+#._-]*/g) || []).forEach(function (w) { if (w) out.push(w); });
    (s.match(/[\u4e00-\u9fa5]+/g) || []).forEach(function (seg) {
      out.push(seg);
      if (seg.length >= 4) {
        for (var i = 0; i + 2 <= seg.length; i++) out.push(seg.slice(i, i + 2));
      }
    });
    return out.filter(function (v, i, arr) { return v && arr.indexOf(v) === i; });
  }

  function highlight(text, tokens) {
    var safe = esc(text);
    if (!tokens.length) return safe;
    var re = tokens.slice()
      .sort(function (a, b) { return b.length - a.length; })
      .map(function (t) { return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); })
      .map(esc).filter(Boolean).join('|');
    if (!re) return safe;
    try { return safe.replace(new RegExp('(' + re + ')', 'gi'), '<mark>$1</mark>'); }
    catch (e) { return safe; }
  }

  /* ---------------- 站内索引 ---------------- */
  function normalize(item) {
    var tags = Array.isArray(item.tags) ? item.tags : [];
    return {
      title: item.title || '未命名',
      url: item.url || 'index.html',
      desc: item.desc || '',
      kind: item.kind || 'page',
      kindLabel: item.kindLabel || '站内页面',
      category: item.category || '',
      tags: tags,
      _title: String(item.title || '').toLowerCase(),
      _desc: String(item.desc || '').toLowerCase(),
      _tags: (tags.join(' ') + ' ' + String(item.category || '') + ' ' + String(item.kindLabel || '')).toLowerCase(),
      _kw: String(item.keywords || '').toLowerCase()
    };
  }

  function loadIndex() {
    return fetch('search-index.json', { cache: 'no-cache' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        var items = Array.isArray(data) ? data : (data && data.items) || [];
        if (!items.length) throw new Error('empty index');
        state.index = items.map(normalize);
        state.loaded = true;
        return { count: state.index.length, fallback: false };
      })
      .catch(function (e) {
        console.warn('[search] 索引加载失败，使用内置兜底索引：', e && e.message);
        state.index = FALLBACK_INDEX.map(normalize);
        state.loaded = true;
        return { count: state.index.length, fallback: true };
      });
  }

  function scoreItem(item, tokens) {
    var score = 0, matched = 0;
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i], s = 0;
      if (item._title === t) s = 60;
      else if (item._title.indexOf(t) === 0) s = 34;
      else if (item._title.indexOf(t) >= 0) s = 20;
      if (item._tags.indexOf(t) >= 0) s += 9;
      if (item._desc.indexOf(t) >= 0) s += 7;
      if (item._kw.indexOf(t) >= 0) s += 5;
      if (s > 0) { score += s; matched++; }
    }
    return { score: score, matched: matched };
  }

  function searchLocal(q, cat) {
    var tokens = tokenize(q);
    if (!tokens.length) return [];
    var pool = state.index.filter(function (it) { return cat === 'all' || it.kind === cat; });

    var scored = [];
    pool.forEach(function (it) {
      var r = scoreItem(it, tokens);
      if (r.score > 0) scored.push({ item: it, score: r.score, matched: r.matched });
    });

    var full = scored.filter(function (x) { return x.matched === tokens.length; });
    var relaxed = !full.length && scored.length > 0;
    var list = full.length ? full : scored;
    list.sort(function (a, b) {
      if (relaxed && b.matched !== a.matched) return b.matched - a.matched;
      if (b.score !== a.score) return b.score - a.score;
      return a.item.title.length - b.item.title.length;
    });
    list.relaxed = relaxed;
    return list;
  }

  /* 站内结果 -> 统一结果结构 */
  function siteToUnified(entry, idx) {
    var it = entry.item;
    return {
      title: it.title,
      snippet: it.desc,
      url: absUrl(it.url),
      sourceId: 'site',
      sourceName: '站内',
      sourceShort: '站',
      sourceBadge: '站',
      group: it.kind,
      host: hostOf(it.url) || location.hostname,
      badges: [it.kindLabel].concat(it.category ? [it.category] : []).concat(it.tags.slice(0, 1)),
      // 站内条目经过人工整理，给一个固定加成，避免被同名噪声压过
      score: entry.score + 12 + Math.max(0, 10 - idx),
      origin: 'site'
    };
  }

  /* ---------------- 合并：站内 + 全网，去重排序 ---------------- */
  function mergeAll() {
    var siteItems = (state.scope === 'web' ? [] : state.siteAll.map(siteToUnified));
    if (state.cat !== 'all') siteItems = siteItems.filter(function (it) { return it.group === state.cat; });

    var web = (state.scope === 'site' ? [] : state.webResults).slice();

    // 来源筛选
    if (state.sourceFilter !== 'all') {
      var want = state.sourceFilter;
      siteItems = want === 'site' ? siteItems : [];
      web = web.filter(function (r) { return r.sourceId === want; });
    }

    var merged = [];
    var seen = {};
    var dup = 0;

    siteItems.concat(web).forEach(function (item) {
      var key = canonical(item.url);
      var prev = seen[key];
      if (prev) {
        dup++;
        if (item.score > prev.score) {
          // 站内命中优先保留来源说明
          if (prev.origin === 'site') item.badges = prev.badges.concat(item.badges);
          seen[key] = item;
          merged[merged.indexOf(prev)] = item;
        }
        return;
      }
      seen[key] = item;
      merged.push(item);
    });

    merged.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      if (a.origin !== b.origin) return a.origin === 'site' ? -1 : 1;
      return String(a.title).length - String(b.title).length;
    });
    merged.dupRemoved = dup;
    return merged;
  }

  /* ---------------- 渲染 ---------------- */
  function kindClass(kind) {
    if (kind === 'software') return 'tag--fast';
    if (kind === 'tutorial') return 'tag--local';
    if (kind === 'game') return 'tag--clean';
    if (kind === 'android') return 'tag--safe';
    if (kind === 'os' || kind === 'vm') return 'tag--proxy';
    return 'tag--local';
  }

  function cardNode(item, idx, tokens) {
    var el = document.createElement('article');
    el.className = 'result is-in';
    el.setAttribute('role', 'listitem');
    el.dataset.idx = String(idx);
    el.dataset.source = item.sourceId;
    el.style.animationDelay = (idx % PAGE_SIZE) * 45 + 'ms';

    var url = absUrl(item.url);
    var isSite = item.origin === 'site';
    var badge = isSite ? '站' : String(item.sourceBadge || item.sourceShort || '网').slice(0, 3);
    var badgeCls = isSite ? ' result__badge--site' : ' result__badge--g-' + (item.group || 'web');

    var tags = ['<span class="tag tag--src">' + esc(item.sourceName) + '</span>'];
    (item.badges || []).slice(0, 3).forEach(function (t, i) {
      if (!t) return;
      tags.push('<span class="tag ' + (i === 0 && isSite ? kindClass(item.group) : 'tag--clean') + '">' + esc(t) + '</span>');
    });

    el.innerHTML =
      '<div class="result__top">' +
        '<span class="result__badge' + badgeCls + '" title="' + esc(item.sourceName) + '">' + esc(badge) + '</span>' +
        '<h3 class="result__title"><a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' +
          highlight(item.title, tokens) + '</a></h3>' +
        '<div class="tags">' + tags.join('') + '</div>' +
      '</div>' +
      '<p class="result__url">' +
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10 14a4 4 0 0 1 0-5.7l2.3-2.3a4 4 0 0 1 5.7 5.7L16.6 13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M14 10a4 4 0 0 1 0 5.7l-2.3 2.3a4 4 0 0 1-5.7-5.7L7.4 11" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>' +
        '<span class="result__host">' + esc(hostOf(url) || '本站') + '</span>' +
        '<span class="result__path">' + esc(pathOf(url)) + '</span>' +
      '</p>' +
      (item.snippet ? '<p class="result__desc">' + highlight(item.snippet, tokens) + '</p>' : '') +
      '<div class="result__actions">' +
        '<button class="act" type="button" data-copy="' + esc(url) + '">' +
          '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="9" y="9" width="10" height="10" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M15 6.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>' +
          '<span>复制链接</span>' +
        '</button>' +
        '<a class="act act--primary" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' +
          '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M14 5h5v5M19 5l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M18.5 14.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V7A1.5 1.5 0 0 1 6 5.5h3.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>' +
          '<span>打开</span>' +
        '</a>' +
      '</div>';
    return el;
  }

  function renderFilters(counts) {
    var wrap = $('filterChips');
    if (!wrap) return;
    if (state.scope === 'web') { wrap.hidden = true; wrap.innerHTML = ''; return; }
    wrap.hidden = false;
    wrap.innerHTML = CATS.map(function (c) {
      var n = c.key === 'all' ? counts.all : (counts[c.key] || 0);
      var disabled = c.key !== 'all' && n === 0;
      return '<button class="filter' + (state.cat === c.key ? ' is-on' : '') + '" type="button" role="tab"' +
        ' aria-selected="' + (state.cat === c.key ? 'true' : 'false') + '" data-cat="' + c.key + '"' +
        (disabled ? ' disabled' : '') + '>' + esc(c.label) +
        (n ? '<span class="filter__num">' + n + '</span>' : '') + '</button>';
    }).join('');
  }

  var STATE_LABEL = { ok: '正常', empty: '无结果', timeout: '超时', error: '失败' };

  function renderSourceChips() {
    var wrap = $('sourceChips');
    if (!wrap) return;
    var list = state.statuses || [];
    if (state.scope === 'site' || !list.length) { wrap.hidden = true; wrap.innerHTML = ''; return; }

    var ok = list.filter(function (s) { return s.state === 'ok'; });
    var bad = list.filter(function (s) { return s.state !== 'ok'; });
    var total = ok.reduce(function (n, s) { return n + s.count; }, 0);
    if (state.scope !== 'web') total += state.siteAll.length;

    var chips = ['<button class="source-chip' + (state.sourceFilter === 'all' ? ' is-on' : '') +
      '" type="button" data-source="all">全部来源<span class="source-chip__n">' + total + '</span></button>'];

    ok.sort(function (a, b) { return b.count - a.count; }).forEach(function (s) {
      chips.push('<button class="source-chip' + (state.sourceFilter === s.id ? ' is-on' : '') +
        '" type="button" data-source="' + esc(s.id) + '" title="' + esc(s.name + ' · ' + s.ms + 'ms' +
        (s.via !== 'direct' ? ' · 代理：' + s.via : '')) + '">' +
        esc(s.short || s.name) + '<span class="source-chip__n">' + s.count + '</span></button>');
    });
    bad.forEach(function (s) {
      chips.push('<span class="source-chip source-chip--bad" title="' + esc(s.name + '：' + (s.error || STATE_LABEL[s.state])) +
        '">' + esc(s.short || s.name) + '<em>' + STATE_LABEL[s.state] + '</em></span>');
    });
    if (state.scope !== 'web') {
      chips.unshift('<button class="source-chip' + (state.sourceFilter === 'site' ? ' is-on' : '') +
        '" type="button" data-source="site">站内<span class="source-chip__n">' + state.siteAll.length + '</span></button>');
    }

    wrap.innerHTML = chips.join('');
    wrap.hidden = false;
  }

  function paintResults() {
    var list = $('resultList');
    if (!list) return;
    var tokens = tokenize(state.q);
    var shown = state.results.slice(0, (state.page + 1) * PAGE_SIZE);
    list.innerHTML = '';
    shown.forEach(function (r, i) { list.appendChild(cardNode(r, i, tokens)); });

    var moreWrap = $('loadMoreWrap');
    if (moreWrap) moreWrap.hidden = shown.length >= state.results.length;

    if ($('resultCount')) $('resultCount').textContent = String(state.results.length);

    var meta = ['关键词「' + state.q + '」'];
    if (state.scope === 'site') meta.push('范围：站内');
    else if (state.scope === 'web') meta.push('范围：全网');
    if (state.cat !== 'all') {
      var cur = CATS.filter(function (c) { return c.key === state.cat; })[0];
      meta.push('分类：' + (cur ? cur.label : state.cat));
    }
    if (state.sourceFilter !== 'all') {
      var src = (state.statuses || []).filter(function (s) { return s.id === state.sourceFilter; })[0];
      meta.push('来源：' + (state.sourceFilter === 'site' ? '站内' : (src ? src.name : state.sourceFilter)));
    }
    if (state.webMs) meta.push('全网 ' + state.webResults.length + ' 条 / ' + state.webMs + 'ms');
    if (state.deduped) meta.push('已合并重复 ' + state.deduped + ' 条');
    if (state.relaxed) meta.push('已放宽为部分匹配');
    if ($('resultMeta')) $('resultMeta').textContent = meta.join(' · ');

    var empty = $('resultEmpty');
    if (empty) {
      empty.hidden = state.results.length > 0;
      if (!state.results.length) {
        $('emptyDesc').textContent = '没有找到匹配「' + state.q + '」的内容，可以换个关键词、减少关键词数量，或用下方搜索引擎继续查找。';
        renderEmptyChips();
      }
    }

    // “继续搜索”始终可用：站内没命中时，它是最实际的下一步
    var ext = $('externalWrap');
    if (ext) {
      ext.hidden = false;
      renderExternal(state.q);
    }

    var failed = (state.statuses || []).filter(function (s) { return s.state !== 'ok' && s.state !== 'empty'; }).length;
    var status = $('sourceStatus');
    if (status) {
      status.textContent = (state.statuses || []).length
        ? '已查询 ' + state.statuses.length + ' 个数据源' + (failed ? '，' + failed + ' 个不可用（见下方来源条）' : '')
        : '';
    }

    state.activeIdx = -1;
  }

  var HOT_WORDS = ['python', '虚拟机', 'linux 镜像', '编辑器', '我的世界', 'sodium 模组'];

  function renderEmptyChips() {
    var wrap = $('emptyChips');
    if (!wrap) return;
    // 用固定的热门词兜底，避免推荐出与搜索词毫不相关的内容
    wrap.innerHTML = HOT_WORDS.filter(function (t) {
      return t.toLowerCase() !== String(state.q || '').toLowerCase();
    }).slice(0, 4).map(function (t) {
      return '<button class="chip chip--soft" type="button" data-kw="' + esc(t) + '">' + esc(t) + '</button>';
    }).join('');
  }

  var EXTERNAL = [
    { name: 'Bing', tpl: 'https://www.bing.com/search?q={q}' },
    { name: 'Google', tpl: 'https://www.google.com/search?q={q}' },
    { name: '百度', tpl: 'https://www.baidu.com/s?wd={q}' },
    { name: 'DuckDuckGo', tpl: 'https://duckduckgo.com/?q={q}' },
    { name: 'GitHub', tpl: 'https://github.com/search?q={q}&type=repositories' }
  ];

  function renderExternal(q) {
    var wrap = $('externalList');
    if (!wrap) return;
    wrap.innerHTML = EXTERNAL.map(function (s) {
      return '<a class="external__link" href="' + esc(s.tpl.replace('{q}', encodeURIComponent(q))) +
        '" target="_blank" rel="noopener noreferrer">' + esc(s.name) +
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M14 5h5v5M19 5l-8 8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M18.5 14.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V7A1.5 1.5 0 0 1 6 5.5h3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg></a>';
    }).join('');
  }

  /* ---------------- 树状拓扑动画 ---------------- */
  var treeEl = $('tree');
  var treeHint = $('treeHint');

  function renderTree(labels) {
    if (!treeEl) return;
    var all = (labels || []).slice();
    state.treeKeys = all;
    var compact = window.innerWidth < 760;
    var W = compact ? 400 : 860, H = compact ? 258 : 400;
    var parts = [];

    parts.push(
      '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" role="img" aria-label="检索拓扑示意">',
      '<defs>',
      '<radialGradient id="nodeGrad" cx="50%" cy="50%" r="60%"><stop offset="0%" stop-color="#eaf6ff"/><stop offset="55%" stop-color="#8ec8ff"/><stop offset="100%" stop-color="#4d7dff"/></radialGradient>',
      '<radialGradient id="rootGrad" cx="50%" cy="50%" r="60%"><stop offset="0%" stop-color="#ffffff"/><stop offset="60%" stop-color="#bfe6ff"/><stop offset="100%" stop-color="#7b8cff"/></radialGradient>',
      '<filter id="softGlow" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>',
      '</defs>'
    );

    function node(x, y, label, r, labelY) {
      return '<g class="tree-node tree-node--q node-blink" style="animation-delay:' + (Math.random() * 1.2).toFixed(2) + 's">' +
        '<circle class="halo" cx="' + x + '" cy="' + y + '" r="' + (r + 3) + '"/>' +
        '<circle cx="' + x + '" cy="' + y + '" r="' + r + '" fill="url(#nodeGrad)"/>' +
        '<text class="tree-q" x="' + x + '" y="' + (y + 3.6) + '" text-anchor="middle"' + (compact ? ' style="font-size:9.5px"' : '') + '>?</text>' +
        '<text class="tree-label" x="' + x + '" y="' + (labelY || (y - r - 7)) + '" text-anchor="middle">' + esc(label) + '</text>' +
        '</g>';
    }

    if (compact) {
      var cx = W / 2, cy = 210, R = 152;
      var picked = all.slice(0, 6);
      picked.forEach(function (label, i) {
        var a = Math.PI * (1.06 + (0.88 * i) / Math.max(1, picked.length - 1));
        var x = cx + Math.cos(a) * R;
        var y = Math.max(46, cy + Math.sin(a) * (R * 0.82));
        parts.push('<line class="tree-line" x1="' + cx + '" y1="' + (cy - 12) + '" x2="' + x + '" y2="' + (y + 8) + '"/>');
        parts.push(node(x, y, label, 9, y - 16));
      });
      parts.push(
        '<g class="tree-node tree-node--root" filter="url(#softGlow)"><circle class="halo" cx="' + cx + '" cy="' + cy + '" r="16"/><circle cx="' + cx + '" cy="' + cy + '" r="13" fill="url(#rootGrad)"/></g>',
        '<text class="tree-root-label" x="' + cx + '" y="' + (cy + 32) + '" text-anchor="middle">当前查询</text>'
      );
    } else {
      var rx = 96, ry = H / 2;
      var l1 = all.slice(0, 4), l2 = all.slice(4, 12);
      var l1pos = l1.map(function (label, i) {
        return { label: label, x: 380, y: ry + (i - (l1.length - 1) / 2) * 78 };
      });
      l1pos.forEach(function (p) {
        parts.push('<line class="tree-line" x1="' + (rx + 16) + '" y1="' + ry + '" x2="' + (p.x - 13) + '" y2="' + p.y + '"/>');
      });
      l1pos.forEach(function (p, i) {
        parts.push(
          '<g class="tree-node tree-node--q node-blink" style="animation-delay:' + (i * 0.18) + 's">',
          '<circle class="halo" cx="' + p.x + '" cy="' + p.y + '" r="14"/>',
          '<circle cx="' + p.x + '" cy="' + p.y + '" r="11" fill="url(#nodeGrad)"/>',
          '<text class="tree-q" x="' + p.x + '" y="' + (p.y + 4) + '" text-anchor="middle">?</text>',
          '<text class="tree-label" x="' + p.x + '" y="' + (p.y - 18) + '" text-anchor="middle">' + esc(p.label) + '</text>',
          '</g>'
        );
      });
      l1pos.forEach(function (p, idx) {
        l2.slice(idx * 2, idx * 2 + 2).forEach(function (label, j) {
          var x = 640 + (j % 2) * 118;
          var y = Math.max(40, Math.min(H - 40, p.y + (j - 0.5) * 44));
          parts.push('<line class="tree-line" x1="' + (p.x + 13) + '" y1="' + p.y + '" x2="' + (x - 12) + '" y2="' + y + '"/>');
          parts.push(node(x, y, label, 8.5));
        });
      });
      parts.push(
        '<g class="tree-node tree-node--root" filter="url(#softGlow)"><circle class="halo" cx="' + rx + '" cy="' + ry + '" r="16"/><circle cx="' + rx + '" cy="' + ry + '" r="13" fill="url(#rootGrad)"/></g>',
        '<text class="tree-root-label" x="' + rx + '" y="' + (ry + 34) + '" text-anchor="middle">当前查询</text>'
      );
    }

    parts.push('</svg>');
    treeEl.innerHTML = parts.join('');
    if (treeHint && !state.busy) {
      treeHint.textContent = '等待输入关键词 · 站内索引 ' + state.index.length + ' 条 + 全网 ' + sourceCount() + ' 个源';
    }
  }

  function sourceCount() {
    return (window.NIAO_SEARCH_SOURCES || []).length;
  }

  function treeLabels() {
    var srcs = window.NIAO_SEARCH_SOURCES || [];
    var labels = ['站内索引', 'MC百科', 'Minecraft Wiki'];
    srcs.forEach(function (s) {
      if (labels.length >= 10) return;
      if (['mcmod', 'mcwiki-zh', 'mcwiki-en'].indexOf(s.id) >= 0) return;
      labels.push(s.short || s.name);
    });
    return labels.slice(0, 10);
  }

  /* ---------------- 主流程 ---------------- */
  function setBusy(on) {
    state.busy = on;
    var btn = $('searchBtn');
    if (!btn) return;
    btn.disabled = on;
    var label = btn.querySelector('.btn-search__label');
    if (label) label.textContent = on ? '检索中' : '搜索';
  }

  function pushRecent(q) {
    if (!q) return;
    var list = [];
    try { list = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]') || []; } catch (e) { list = []; }
    if (!Array.isArray(list)) list = [];
    list = list.filter(function (x) { return x && x !== q; });
    list.unshift(q);
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 6))); } catch (e) {}
    renderRecent();
  }

  function renderRecent() {
    var wrap = $('recentWrap'), holder = $('recentList');
    if (!wrap || !holder) return;
    var list = [];
    try { list = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]') || []; } catch (e) { list = []; }
    if (!Array.isArray(list) || !list.length) { wrap.hidden = true; holder.innerHTML = ''; return; }
    wrap.hidden = false;
    holder.innerHTML = list.map(function (q) {
      return '<button class="chip chip--soft" type="button" data-kw="' + esc(q) + '">' + esc(q) + '</button>';
    }).join('');
  }

  function setScope(scope) {
    if (!SCOPES.some(function (s) { return s.key === scope; })) return;
    state.scope = scope;
    var bar = $('scopeBar');
    if (bar) {
      Array.prototype.forEach.call(bar.querySelectorAll('.scope-btn'), function (b) {
        var on = b.getAttribute('data-scope') === scope;
        b.classList.toggle('is-on', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
      });
    }
    var hint = $('scopeHint');
    if (hint) {
      hint.textContent = scope === 'site' ? '仅检索站内索引' : (scope === 'web'
        ? '并发检索 ' + sourceCount() + ' 个公开数据源'
        : '站内索引 + 全网 ' + sourceCount() + ' 个源，统一去重排序');
    }
  }

  function webSourceNames() {
    return (window.NIAO_SEARCH_SOURCES || []).map(function (s) { return s.short || s.name; });
  }

  function finishSearch(t0) {
    state.results = mergeAll();
    state.page = 0;
    state.lastElapsed = Math.max(1, Math.round(performance.now() - t0));

    var counts = { all: state.siteAll.length };
    state.siteAll.forEach(function (r) { counts[r.item.kind] = (counts[r.item.kind] || 0) + 1; });
    renderFilters(counts);
    renderSourceChips();

    var panel = $('results');
    if (panel) panel.hidden = false;
    paintResults();

    var lat = $('metricLatency');
    if (lat) lat.innerHTML = (state.lastElapsed / 1000).toFixed(2) + '<em>s</em>';

    setBusy(false);
    pushRecent(state.q);

    var stageEl = $('stage');
    if (stageEl && state.results.length) {
      stageEl.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    }
  }

  function hideBusyUI() {
    var treePanel = $('treePanel');
    var scanning = $('scanning');
    if (treeEl) treeEl.classList.remove('is-searching');
    if (treePanel) treePanel.classList.add('is-fading');
    setTimeout(function () {
      if (treePanel) treePanel.hidden = true;
      if (scanning) scanning.hidden = true;
    }, reduceMotion ? 0 : 260);
  }

  function runSearch(rawQ, cat) {
    var input = $('q');
    var q = String(rawQ == null ? (input ? input.value : '') : rawQ).trim();

    if (!q) {
      var form = $('searchForm');
      if (form) {
        form.classList.add('is-shaking');
        setTimeout(function () { form.classList.remove('is-shaking'); }, 480);
      }
      toast('请输入要搜索的关键词');
      if (input) input.focus();
      return;
    }

    state.q = q;
    state.cat = CATS.some(function (c) { return c.key === cat; }) ? cat : 'all';
    state.page = 0;
    state.sourceFilter = 'all';
    state.webResults = [];
    state.statuses = [];
    state.webMs = 0;
    state.deduped = 0;
    setBusy(true);
    hideSuggest();

    try {
      var u = new URL(window.location.href);
      u.searchParams.set('q', q);
      if (state.cat !== 'all') u.searchParams.set('c', state.cat); else u.searchParams.delete('c');
      if (state.scope !== 'all') u.searchParams.set('s', state.scope); else u.searchParams.delete('s');
      history.replaceState(null, '', u.toString());
    } catch (e) {}

    var treePanel = $('treePanel');
    if (treePanel) { treePanel.hidden = false; treePanel.classList.remove('is-fading'); }
    if (treeEl) treeEl.classList.add('is-searching');

    // 全网模式下分类筛选无意义，立即隐藏，避免上一次的筛选条残留
    if (state.scope === 'web') {
      var f0 = $('filterChips');
      if (f0) { f0.hidden = true; f0.innerHTML = ''; }
    }

    var scanning = $('scanning'), fill = $('scanningFill'), countEl = $('scanningCount'), textEl = $('scanningText');
    var t0 = performance.now();
    var done = 0, total = 0, okCount = 0;

    // 站内：同步毫秒级
    state.siteAll = state.scope === 'web' ? [] : searchLocal(q, 'all');
    state.relaxed = !!state.siteAll.relaxed;

    if (state.scope === 'site' || !window.NiaoWeb) {
      state.results = mergeAll();
      finishSearch(t0);
      hideBusyUI();
      return;
    }

    total = sourceCount();
    if (scanning) scanning.hidden = false;
    if (fill) fill.style.width = '6%';
    if (countEl) countEl.textContent = '0/' + total;
    if (textEl) textEl.textContent = '并发查询 ' + total + ' 个公开数据源…';
    if (treeHint) treeHint.textContent = '正在检索 · ' + q;

    // 先展示站内结果，减少空等
    state.results = mergeAll();
    if (state.results.length) {
      renderFilters((function () {
        var c = { all: state.siteAll.length };
        state.siteAll.forEach(function (r) { c[r.item.kind] = (c[r.item.kind] || 0) + 1; });
        return c;
      })());
      var panel = $('results');
      if (panel) panel.hidden = false;
      paintResults();
    }

    window.NiaoWeb.search(q, {
      groups: ['all'],
      onSource: function (st) {
        done++;
        if (st.state === 'ok') okCount++;
        if (fill) fill.style.width = Math.min(96, 6 + Math.round((done / total) * 90)) + '%';
        if (countEl) countEl.textContent = done + '/' + total;
        if (textEl) {
          textEl.textContent = '已完成 ' + done + '/' + total + ' 个源 · 命中 ' + okCount + ' 个' +
            (st.state === 'ok' ? ' · 最新：' + st.name + ' ' + st.count + ' 条' : '');
        }
      }
    }).then(function (out) {
      state.webResults = out.results;
      state.statuses = out.statuses;
      state.webMs = out.ms;
      state.deduped = out.removed;
      if (fill) fill.style.width = '100%';
      if (countEl) countEl.textContent = '100%';
      if (textEl) textEl.textContent = '检索完成 · ' + total + ' 个源';
      finishSearch(t0);
      hideBusyUI();
    }).catch(function (err) {
      console.warn('[search] 全网检索失败：', err);
      toast('全网检索失败，已保留站内结果');
      state.statuses = [];
      finishSearch(t0);
      hideBusyUI();
    });
  }

  /* ---------------- 搜索建议 ---------------- */
  var suggestTimer = null;
  var suggestItems = [];
  var suggestActive = -1;

  function hideSuggest() {
    var p = $('suggestPanel');
    if (!p) return;
    p.hidden = true;
    p.innerHTML = '';
    suggestActive = -1;
    if ($('q')) $('q').setAttribute('aria-expanded', 'false');
  }

  function buildSuggest(q) {
    var panel = $('suggestPanel');
    if (!panel) return;
    var kw = String(q || '').trim().toLowerCase();
    if (!kw || !state.index.length) { hideSuggest(); return; }

    var hits = state.index.filter(function (it) {
      return it._title.indexOf(kw) >= 0 || it._tags.indexOf(kw) >= 0 || it._desc.indexOf(kw) >= 0;
    }).slice(0, 6);

    if (!hits.length) { hideSuggest(); return; }

    suggestItems = hits;
    suggestActive = -1;
    var tokens = tokenize(kw);
    panel.innerHTML = hits.map(function (it, i) {
      return '<button class="suggest-item" type="button" role="option" data-idx="' + i + '">' +
        '<span class="suggest-item__label">' + highlight(it.title, tokens) + '</span>' +
        '<span class="suggest-item__kind">' + esc(it.kindLabel) + '</span>' +
        '</button>';
    }).join('');
    panel.hidden = false;
    $('q').setAttribute('aria-expanded', 'true');
  }

  function moveSuggest(delta) {
    var panel = $('suggestPanel');
    if (!panel || panel.hidden || !suggestItems.length) return;
    var nodes = Array.prototype.slice.call(panel.querySelectorAll('.suggest-item'));
    suggestActive = (suggestActive + delta + nodes.length) % nodes.length;
    nodes.forEach(function (n, i) { n.classList.toggle('is-active', i === suggestActive); });
  }

  function applySuggest(idx) {
    var it = suggestItems[idx];
    if (!it) return;
    if ($('q')) $('q').value = it.title;
    hideSuggest();
    runSearch(it.title, state.cat);
  }

  /* ---------------- 事件 ---------------- */
  function bindEvents() {
    var form = $('searchForm');
    var input = $('q');
    var catSel = $('category');

    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        runSearch(input ? input.value : '', catSel ? catSel.value : 'all');
      });
    }

    if (catSel) {
      catSel.addEventListener('change', function () {
        state.cat = catSel.value;
        if (state.q) runSearch(state.q, catSel.value);
      });
    }

    // 范围切换
    var scopeBar = $('scopeBar');
    if (scopeBar) {
      scopeBar.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('.scope-btn') : null;
        if (!btn) return;
        var next = btn.getAttribute('data-scope');
        if (next === state.scope) return;
        setScope(next);
        if (state.q) runSearch(state.q, state.cat);
      });
    }

    if (input) {
      input.addEventListener('input', function () {
        clearTimeout(suggestTimer);
        var v = input.value;
        suggestTimer = setTimeout(function () { buildSuggest(v); }, 120);
      });
      input.addEventListener('focus', function () { if (input.value.trim()) buildSuggest(input.value); });
      input.addEventListener('keydown', function (e) {
        var panel = $('suggestPanel');
        var open = panel && !panel.hidden;
        if (e.key === 'ArrowDown' && open) { e.preventDefault(); moveSuggest(1); return; }
        if (e.key === 'ArrowUp' && open) { e.preventDefault(); moveSuggest(-1); return; }
        if (e.key === 'Enter' && open && suggestActive >= 0) { e.preventDefault(); applySuggest(suggestActive); return; }
        if (e.key === 'Escape') {
          if (open) { hideSuggest(); return; }
          if (input.value) input.value = '';
        }
      });
    }

    // 点击建议 / 点击外部关闭
    document.addEventListener('click', function (e) {
      var panel = $('suggestPanel');
      if (panel && !panel.hidden) {
        var item = e.target.closest ? e.target.closest('.suggest-item') : null;
        if (item) { applySuggest(parseInt(item.dataset.idx, 10) || 0); return; }
        if (!panel.contains(e.target) && e.target !== input) hideSuggest();
      }
    });

    // 关键词 chips
    document.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('[data-kw]') : null;
      if (!chip) return;
      var kw = chip.getAttribute('data-kw');
      if (input) input.value = kw;
      runSearch(kw, catSel ? catSel.value : 'all');
    });

    // 分类筛选
    var filters = $('filterChips');
    if (filters) {
      filters.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('.filter') : null;
        if (!btn || btn.disabled) return;
        var cat = btn.getAttribute('data-cat');
        if (cat === state.cat) return;
        state.cat = cat;
        if (catSel) catSel.value = cat;
        state.results = mergeAll();
        state.page = 0;
        renderFilters((function () {
          var c = { all: state.siteAll.length };
          state.siteAll.forEach(function (r) { c[r.item.kind] = (c[r.item.kind] || 0) + 1; });
          return c;
        })());
        paintResults();
      });
    }

    // 来源筛选
    var srcWrap = $('sourceChips');
    if (srcWrap) {
      srcWrap.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('[data-source]') : null;
        if (!btn) return;
        var id = btn.getAttribute('data-source');
        if (id === state.sourceFilter) return;
        state.sourceFilter = id;
        state.results = mergeAll();
        state.page = 0;
        renderSourceChips();
        paintResults();
      });
    }

    var moreBtn = $('loadMoreBtn');
    if (moreBtn) {
      moreBtn.addEventListener('click', function () {
        state.page += 1;
        paintResults();
      });
    }

    var clearBtn = $('clearRecent');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        try { localStorage.removeItem(RECENT_KEY); } catch (e) {}
        renderRecent();
        toast('已清空最近搜索');
      });
    }

    document.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-copy]') : null;
      if (!btn) return;
      copyText(btn.getAttribute('data-copy')).then(function () {
        btn.classList.add('is-copied');
        var span = btn.querySelector('span');
        var old = span ? span.textContent : '';
        if (span) span.textContent = '已复制';
        toast('链接已复制到剪贴板');
        setTimeout(function () {
          btn.classList.remove('is-copied');
          if (span) span.textContent = old || '复制链接';
        }, 1600);
      }).catch(function () { toast('复制失败，请手动选择链接'); });
    });

    // 快捷键
    document.addEventListener('keydown', function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement && document.activeElement.tagName) || '');
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) { e.preventDefault(); if (input) input.focus(); return; }
      if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) { e.preventDefault(); if (input) input.focus(); return; }
      if (e.key === 'Escape') hideSuggest();
    });

    // 结果键盘导航
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Enter') return;
      var panel = $('suggestPanel');
      if (panel && !panel.hidden) return;
      if (/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement && document.activeElement.tagName) || '')) return;
      var cards = Array.prototype.slice.call(document.querySelectorAll('#resultList .result'));
      if (!cards.length) return;
      if (e.key === 'Enter') {
        var cur = document.querySelector('#resultList .result.is-active a.act--primary');
        if (cur) { e.preventDefault(); cur.click(); }
        return;
      }
      e.preventDefault();
      state.activeIdx += (e.key === 'ArrowDown' ? 1 : -1);
      if (state.activeIdx < 0) state.activeIdx = cards.length - 1;
      if (state.activeIdx >= cards.length) state.activeIdx = 0;
      cards.forEach(function (c, i) { c.classList.toggle('is-active', i === state.activeIdx); });
      cards[state.activeIdx].scrollIntoView({ block: 'nearest', behavior: reduceMotion ? 'auto' : 'smooth' });
    });

    // 右下角快捷进入
    var dockBtn = $('dockBtn'), dockPanel = $('dockPanel');
    if (dockBtn && dockPanel) {
      dockBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        var open = dockPanel.hidden;
        dockPanel.hidden = !open;
        dockBtn.setAttribute('aria-expanded', String(open));
      });
      document.addEventListener('click', function (e) {
        if (dockPanel.hidden) return;
        if (!dockPanel.contains(e.target) && !dockBtn.contains(e.target)) {
          dockPanel.hidden = true;
          dockBtn.setAttribute('aria-expanded', 'false');
        }
      });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !dockPanel.hidden) {
          dockPanel.hidden = true;
          dockBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    // 跨断点重排拓扑图
    var rt;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () {
        var results = $('results');
        if (!results || results.hidden) renderTree(state.treeKeys);
      }, 220);
    });
  }

  /* ---------------- 启动 ---------------- */
  function init() {
    renderTree(treeLabels());
    bindEvents();
    renderRecent();

    var params = new URLSearchParams(window.location.search);
    var scopeParam = params.get('s');
    if (scopeParam && SCOPES.some(function (s) { return s.key === scopeParam; })) {
      setScope(scopeParam);
    } else {
      setScope('all');
    }

    var srcMetric = $('metricSources');
    if (srcMetric) srcMetric.textContent = String(sourceCount());

    loadIndex().then(function (info) {
      var stats = $('indexStats');
      if (stats) {
        stats.textContent = info.fallback
          ? '本地模式 · 索引 ' + info.count + ' 条（用 python serve.py 启动可启用完整索引）'
          : '站内索引 ' + info.count + ' 条 · 全网 ' + sourceCount() + ' 个公开数据源';
      }
      // 指标展示“数据源个数”，站内索引条数在顶部 eyebrow 里单独说明
      var metric = $('metricSources');
      if (metric) metric.textContent = String(sourceCount());
      if (treeHint) treeHint.textContent = '等待输入关键词 · 站内 ' + info.count + ' 条 + 全网 ' + sourceCount() + ' 个源';

      var q = params.get('q');
      var c = params.get('c');
      if (c && CATS.some(function (x) { return x.key === c; })) {
        state.cat = c;
        if ($('category')) $('category').value = c;
      }
      if (q) {
        if ($('q')) $('q').value = q;
        runSearch(q, state.cat);
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
