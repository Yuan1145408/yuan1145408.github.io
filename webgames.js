/* ============================================================
   网页游戏 · 3A 网页化入口
   ------------------------------------------------------------
   - 数据在 webgames.json，页面只负责渲染与筛选
   - 分类 tab / 关键词过滤 / URL 参数同步 / 复制链接
   - 每个条目区分「免安装 / 需自备游戏文件 / 需账号」三种门槛
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var DATA = null;
  var state = { cat: 'all', q: '' };

  var NEED = {
    instant: { label: '免安装', cls: 'is-ok', title: '打开页面就能玩，无需额外文件' },
    files: { label: '需自备游戏文件', cls: 'warn', title: '浏览器只提供运行器，需要使用你自己购买的正版游戏文件' },
    account: { label: '需账号 / 订阅', cls: 'chip--soft', title: '需要注册账号、开通会员或订阅对应服务' },
    free: { label: '开源免费', cls: 'is-ok', title: '开源项目，可自由下载、编译与二次开发' }
  };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function safeUrl(u) {
    return /^https?:\/\//i.test(String(u || '')) ? u : '';
  }

  function hostOf(u) {
    try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
  }

  var CAT_META = {};

  function cardNode(it) {
    var need = NEED[it.need] || NEED.instant;
    var flags = ['<span class="chip ' + need.cls + '" title="' + esc(need.title) + '">' + esc(need.label) + '</span>'];
    if (it.region === 'cn') flags.push('<span class="chip is-ok">国内直连</span>');
    else if (it.region === 'global') flags.push('<span class="chip chip--soft">境外节点</span>');
    if (it.mobile) flags.push('<span class="chip chip--soft">手机可玩</span>');

    var tags = (it.tags || []).map(function (t) {
      return '<span class="wg-tag">' + esc(t) + '</span>';
    }).join('');

    var play = safeUrl(it.play);
    var repo = safeUrl(it.repo);
    var dl = safeUrl(it.dl);

    var actions = [];
    if (play && it.embeddable) {
      actions.push('<button class="btn primary wg-btn" type="button" data-wg-play="' + esc(it.id) + '" title="在站内播放器中直接游玩">本站畅玩</button>');
    }
    if (play) {
      actions.push('<a class="btn primary wg-btn" href="' + esc(play) + '" target="_blank" rel="noopener noreferrer">' +
        (it.cat === 'cloud' ? '打开平台' : '立即游玩') + '</a>');
    }
    if (repo) {
      actions.push('<a class="btn wg-btn" href="' + esc(repo) + '" target="_blank" rel="noopener noreferrer">源码</a>');
    }
    if (dl) {
      actions.push('<a class="btn wg-btn" href="' + esc(dl) + '" target="_blank" rel="noopener noreferrer" title="下载源码压缩包">下载</a>');
    }
    var copyTarget = play || repo || dl;
    if (copyTarget) {
      actions.push('<button class="btn wg-btn wg-copy" type="button" data-url="' + esc(copyTarget) + '">复制链接</button>');
    }

    var host = play ? hostOf(play) : (repo ? hostOf(repo) : '');

    var el = document.createElement('article');
    el.className = 'wg-card';
    el.setAttribute('data-cat', it.cat || '');
    el.innerHTML =
      '<div class="wg-card__head">' +
        '<h4 class="wg-card__title">' + esc(it.name) + '</h4>' +
        '<div class="wg-card__flags">' + flags.join('') + '</div>' +
      '</div>' +
      '<p class="wg-card__desc">' + esc(it.desc) + '</p>' +
      (tags ? '<div class="wg-card__tags">' + tags + '</div>' : '') +
      '<div class="wg-card__foot">' +
        '<span class="wg-card__host" title="' + esc(copyTarget || '') + '">' + esc(host) + '</span>' +
        '<div class="wg-card__actions">' + actions.join('') + '</div>' +
      '</div>';
    return el;
  }

  function matches(it) {
    if (state.cat !== 'all' && it.cat !== state.cat) return false;
    var q = state.q.trim().toLowerCase();
    if (!q) return true;
    var hay = [it.name, it.desc, (it.tags || []).join(' '), it.cat, it.need]
      .join(' ').toLowerCase();
    // 多关键词任意命中即可，符合“边打边筛”的预期
    return q.split(/\s+/).some(function (w) { return w && hay.indexOf(w) >= 0; });
  }

  function render() {
    var grid = $('wgGrid');
    if (!grid || !DATA) return;
    var list = DATA.items.filter(matches);

    grid.innerHTML = '';
    if (!list.length) {
      $('wgEmpty').hidden = false;
    } else {
      $('wgEmpty').hidden = true;
      var frag = document.createDocumentFragment();
      list.forEach(function (it) { frag.appendChild(cardNode(it)); });
      grid.appendChild(frag);
    }

    var count = $('wgCount');
    if (count) {
      count.textContent = state.q
        ? '「' + state.q + '」命中 ' + list.length + ' / ' + DATA.items.length + ' 个'
        : '共 ' + list.length + ' 个入口';
    }
    renderTabs(list.length);
  }

  function renderTabs() {
    var wrap = $('wgTabs');
    if (!wrap || !DATA) return;
    var counts = { all: DATA.items.length };
    DATA.items.forEach(function (it) { counts[it.cat] = (counts[it.cat] || 0) + 1; });

    var tabs = [{ key: 'all', label: '全部' }].concat(DATA.categories || []);
    wrap.innerHTML = tabs.map(function (c) {
      var n = counts[c.key] || 0;
      return '<button class="wg-tab' + (state.cat === c.key ? ' is-on' : '') + '" type="button"' +
        ' role="tab" aria-selected="' + (state.cat === c.key ? 'true' : 'false') + '"' +
        ' data-cat="' + esc(c.key) + '" title="' + esc(c.desc || '') + '">' +
        esc(c.label) + '<span class="wg-tab__n">' + n + '</span></button>';
    }).join('');
  }

  function syncUrl() {
    try {
      var u = new URL(window.location.href);
      if (state.cat === 'all') u.searchParams.delete('cat');
      else u.searchParams.set('cat', state.cat);
      if (state.q) u.searchParams.set('q', state.q);
      else u.searchParams.delete('q');
      window.history.replaceState(null, '', u.pathname + (u.search ? u.search : '') + u.hash);
    } catch (e) { /* 忽略 */ }
  }

  function initTabs() {
    var wrap = $('wgTabs');
    if (!wrap) return;
    wrap.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('.wg-tab') : null;
      if (!btn) return;
      state.cat = btn.getAttribute('data-cat') || 'all';
      syncUrl();
      render();
      var grid = $('wgGrid');
      if (grid && state.cat !== 'all') {
        // 切换分类后回到列表顶部，避免停在上一屏空白处
        var top = grid.getBoundingClientRect().top + window.scrollY - 120;
        if (window.scrollY > top) window.scrollTo({ top: top, behavior: 'smooth' });
      }
    });
  }

  function initSearch() {
    var input = $('wgSearch');
    if (!input) return;
    var timer = 0;
    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        state.q = input.value || '';
        syncUrl();
        render();
      }, 120);
    });
  }

  function initCopy() {
    document.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('.wg-copy') : null;
      if (!btn) return;
      var url = btn.getAttribute('data-url');
      if (!url) return;
      var done = function () {
        var old = btn.textContent;
        btn.textContent = '已复制';
        btn.classList.add('is-ok');
        setTimeout(function () { btn.textContent = old; btn.classList.remove('is-ok'); }, 1400);
        if (window.Niao && typeof window.Niao.toast === 'function') window.Niao.toast('链接已复制');
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done, function () { fallbackCopy(url, done); });
      } else {
        fallbackCopy(url, done);
      }
    });
  }

  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      done();
    } catch (e) {
      if (window.Niao && typeof window.Niao.toast === 'function') window.Niao.toast('复制失败，请手动选择链接', 'err');
    }
  }

  /* ---------------- 站内播放器 ---------------- */
  var playerState = { id: null };

  function openPlayer(id) {
    if (!DATA) return;
    var it = null;
    DATA.items.forEach(function (x) { if (x.id === id) it = x; });
    var play = it && safeUrl(it.play);
    if (!play) return;
    var sec = $('wgPlayerSec');
    var frame = $('wgPlayerFrame');
    if (!sec || !frame) return;
    playerState.id = id;
    $('wgPlayerTitle').textContent = it.name + ' · 站内畅玩';
    $('wgPlayerNewTab').href = play;
    frame.src = play;
    sec.hidden = false;
    try {
      var u = new URL(window.location.href);
      u.searchParams.set('play', id);
      window.history.replaceState(null, '', u.pathname + (u.search ? u.search : '') + u.hash);
    } catch (e) { /* 忽略 */ }
    var top = sec.getBoundingClientRect().top + window.scrollY - 80;
    if (window.scrollY > top || sec.getBoundingClientRect().top < 0) {
      window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  function closePlayer() {
    var frame = $('wgPlayerFrame');
    if (frame) frame.src = 'about:blank';
    playerState.id = null;
    var sec = $('wgPlayerSec');
    if (sec) sec.hidden = true;
    try {
      var u = new URL(window.location.href);
      u.searchParams.delete('play');
      window.history.replaceState(null, '', u.pathname + (u.search ? u.search : '') + u.hash);
    } catch (e) { /* 忽略 */ }
  }

  function initPlayer() {
    var btn = document.getElementById('wgPlayerClose');
    if (btn) btn.addEventListener('click', closePlayer);
    // 卡片上的「本站畅玩」按钮（事件委托，列表重渲染也有效）
    document.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-wg-play]') : null;
      if (t) { e.preventDefault(); openPlayer(t.getAttribute('data-wg-play')); }
    });
  }

  function renderStats() {
    var wrap = $('wgStats');
    if (!wrap || !DATA) return;
    var counts = { cloud: 0, browser: 0, source: 0 };
    DATA.items.forEach(function (it) { if (counts[it.cat] != null) counts[it.cat]++; });
    wrap.innerHTML = [
      ['<b>' + DATA.items.length + '</b> 个入口', ''],
      ['<b>' + counts.cloud + '</b> 个云平台', ''],
      ['<b>' + counts.browser + '</b> 个直玩移植', ''],
      ['<b>' + counts.source + '</b> 个开源项目', '']
    ].map(function (x) { return '<span class="wg-stat">' + x[0] + '</span>'; }).join('');
  }

  function boot() {
    // URL 带入的分类 / 关键词
    try {
      var u = new URL(window.location.href);
      var c = u.searchParams.get('cat');
      if (c) state.cat = c;
      var q = u.searchParams.get('q');
      if (q) {
        state.q = q;
        if ($('wgSearch')) $('wgSearch').value = q;
      }
      state.playId = u.searchParams.get('play');
    } catch (e) { /* 忽略 */ }

    fetch('webgames.json', { cache: 'no-cache' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        DATA = data;
        CAT_META = {};
        (data.categories || []).forEach(function (c) { CAT_META[c.key] = c; });
        renderStats();
        // 分类不在数据里时回落到全部，避免空白页
        if (state.cat !== 'all' && !CAT_META[state.cat]) state.cat = 'all';
        render();
        // URL 带入 play= 时自动打开站内播放器（支持从游戏专区跳转过来）
        if (state.playId) { openPlayer(state.playId); state.playId = null; }
      })
      .catch(function (err) {
        console.warn('[webgames] 数据加载失败：', err && err.message);
        var grid = $('wgGrid');
        if (grid) {
          grid.innerHTML = '<p class="wg-loading">入口列表加载失败（' + esc(err && err.message) + '）。' +
            '如果你是用 file:// 直接打开的，请改用本地服务器或访问线上版本。</p>';
        }
      });

    initTabs();
    initSearch();
    initCopy();
    initPlayer();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
