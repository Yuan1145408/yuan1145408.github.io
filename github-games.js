/* ============================================================
   开源网页游戏库（GitHub 聚合）
   ------------------------------------------------------------
   - 数据在 github-games.json，纯静态渲染
   - 分类 tab / 关键词 / 可玩方式 / 排序，四者叠加过滤
   - 卡片 → 详情弹窗 → 站内 iframe 试玩或新窗口跳转
   - 嵌入失败 / 超时给出明确提示与替代路径
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var DATA = null;
  var state = { cat: 'all', q: '', access: 'all', sort: 'curated' };
  var player = { id: null, timer: 0, lastFocus: null };

  var ACCESS = {
    instant: { label: '即开即玩', cls: 'is-ok', title: '打开页面就能玩，无需注册或自备文件' },
    account: { label: '需账号', cls: 'is-account', title: '需要注册或登录后才能进入游戏' },
    selfhost: { label: '需自建', cls: 'is-self', title: '需要自己部署服务或准备游戏文件' },
    down: { label: '链接异常', cls: 'is-warn', title: '最近一次检测未能连通，详见详情说明' }
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

  function fmtStars(n) {
    n = Number(n) || 0;
    if (n >= 1000) {
      var k = n / 1000;
      return (k >= 10 ? Math.round(k) : Math.round(k * 10) / 10) + 'k';
    }
    return String(n);
  }

  function cards() {
    var map = {};
    (DATA.items || []).forEach(function (it) { map[it.id] = it; });
    return map;
  }

  function catLabel(key) {
    var hit = (DATA.categories || []).filter(function (c) { return c.key === key; })[0];
    return hit ? hit.label : key;
  }

  /* ---------------- 过滤与排序 ---------------- */

  function matches(it) {
    if (state.cat !== 'all' && it.cat !== state.cat) return false;
    if (state.access === 'embed' && !it.embed) return false;
    if (state.access === 'link' && it.embed) return false;
    if (state.access === 'account' && it.access !== 'account') return false;
    if (state.access === 'selfhost' && it.access !== 'selfhost') return false;
    var q = state.q.trim().toLowerCase();
    if (!q) return true;
    var hay = [
      it.name, it.desc, it.note, it.run, it.repo, it.cat, catLabel(it.cat),
      (it.tags || []).join(' '), (it.tech || []).join(' ')
    ].join(' ').toLowerCase();
    // 多关键词：全部命中更精准，先按全命中，再退化为任意命中
    var words = q.split(/\s+/).filter(Boolean);
    if (words.every(function (w) { return hay.indexOf(w) >= 0; })) return true;
    return words.some(function (w) { return hay.indexOf(w) >= 0; });
  }

  function sortList(list) {
    var arr = list.slice();
    if (state.sort === 'stars') {
      arr.sort(function (a, b) { return (b.stars || 0) - (a.stars || 0); });
    } else if (state.sort === 'name') {
      arr.sort(function (a, b) { return a.name.localeCompare(b.name, 'zh-Hans-CN'); });
    } else if (state.sort === 'cat') {
      var order = {};
      (DATA.categories || []).forEach(function (c, i) { order[c.key] = i; });
      arr.sort(function (a, b) {
        var d = (order[a.cat] || 0) - (order[b.cat] || 0);
        return d !== 0 ? d : (b.stars || 0) - (a.stars || 0);
      });
    }
    // curated：保持 JSON 里的推荐顺序
    return arr;
  }

  /* ---------------- 卡片 ---------------- */

  function badgeOf(it) {
    if (it.status === 'down') return ACCESS.down;
    return ACCESS[it.access] || ACCESS.instant;
  }

  function cardNode(it) {
    var b = badgeOf(it);
    var flags = ['<span class="gg-badge ' + b.cls + '" title="' + esc(b.title) + '">' + esc(b.label) + '</span>'];
    flags.push(it.embed
      ? '<span class="gg-badge is-ok" title="页面未禁止嵌入，可直接在站内试玩">可站内试玩</span>'
      : '<span class="gg-badge is-link" title="对方站点禁止被 iframe 嵌入，只能新窗口打开">仅跳转</span>');
    if (it.mobile) flags.push('<span class="gg-badge is-soft">手机可玩</span>');

    var tags = (it.tags || []).map(function (t) {
      return '<span class="gg-tag">' + esc(t) + '</span>';
    }).join('');

    var play = safeUrl(it.play);
    var repo = safeUrl(it.repo ? 'https://github.com/' + it.repo : '');

    var actions = [];
    if (play && it.embed) {
      actions.push('<button class="btn primary gg-btn" type="button" data-gg-play="' + esc(it.id) + '">站内试玩</button>');
    }
    if (play) {
      actions.push('<a class="btn' + (it.embed ? '' : ' primary') + ' gg-btn" href="' + esc(play) +
        '" target="_blank" rel="noopener noreferrer">在线游玩</a>');
    }
    if (repo) {
      actions.push('<a class="btn gg-btn" href="' + esc(repo) + '" target="_blank" rel="noopener noreferrer">源码</a>');
    }
    actions.push('<button class="btn gg-btn gg-detail" type="button" data-gg-detail="' + esc(it.id) + '">详情</button>');

    var el = document.createElement('article');
    el.className = 'gg-card';
    el.setAttribute('data-id', it.id);
    el.innerHTML =
      '<div class="gg-card__head">' +
        '<h3 class="gg-card__title">' + esc(it.name) + '</h3>' +
        '<span class="gg-card__stars" title="GitHub Star 数">★ ' + esc(fmtStars(it.stars)) + '</span>' +
      '</div>' +
      '<div class="gg-card__badges">' + flags.join('') + '</div>' +
      '<p class="gg-card__desc">' + esc(it.desc) + '</p>' +
      (tags ? '<div class="gg-card__tags">' + tags + '</div>' : '') +
      '<p class="gg-card__run"><span>怎么玩</span>' + esc(it.run) + '</p>' +
      '<div class="gg-card__foot">' +
        '<span class="gg-card__host" title="' + esc(play) + '">' + esc(hostOf(play)) + '</span>' +
        '<div class="gg-card__actions">' + actions.join('') + '</div>' +
      '</div>';
    return el;
  }

  /* ---------------- 列表渲染 ---------------- */

  function render() {
    var grid = $('ggGrid');
    if (!grid || !DATA) return;
    var list = sortList(DATA.items.filter(matches));

    grid.innerHTML = '';
    if (!list.length) {
      $('ggEmpty').hidden = false;
    } else {
      $('ggEmpty').hidden = true;
      var frag = document.createDocumentFragment();
      list.forEach(function (it) { frag.appendChild(cardNode(it)); });
      grid.appendChild(frag);
    }

    var count = $('ggCount');
    if (count) {
      var bits = [];
      if (state.q) bits.push('「' + state.q + '」');
      bits.push(list.length + ' / ' + DATA.items.length + ' 款');
      count.textContent = bits.join(' ');
    }
    renderTabs();
  }

  function renderTabs() {
    var wrap = $('ggTabs');
    if (!wrap || !DATA) return;
    var counts = { all: DATA.items.length };
    DATA.items.forEach(function (it) { counts[it.cat] = (counts[it.cat] || 0) + 1; });
    var tabs = [{ key: 'all', label: '全部', desc: '所有收录的游戏' }].concat(DATA.categories || []);

    wrap.innerHTML = tabs.map(function (c) {
      var on = state.cat === c.key;
      return '<button class="gg-tab' + (on ? ' is-on' : '') + '" type="button" role="tab"' +
        ' aria-selected="' + (on ? 'true' : 'false') + '" data-cat="' + esc(c.key) + '"' +
        ' title="' + esc(c.desc || '') + '">' + esc(c.label) +
        '<span class="gg-tab__n">' + (counts[c.key] || 0) + '</span></button>';
    }).join('');
  }

  function renderStats() {
    var wrap = $('ggStats');
    if (!wrap || !DATA) return;
    var embed = 0;
    var stars = 0;
    var heroN = $('ggHeroN');
    if (heroN) heroN.textContent = DATA.items.length;
    DATA.items.forEach(function (it) {
      if (it.embed) embed++;
      stars += it.stars || 0;
    });
    wrap.innerHTML = [
      '<b>' + DATA.items.length + '</b> 款游戏',
      '<b>' + embed + '</b> 款可站内试玩',
      '<b>' + (DATA.categories || []).length + '</b> 个分类',
      '<b>' + (DATA.checkedAt || DATA.updated || '—') + '</b> 链接检测'
    ].map(function (s) { return '<span class="gg-stat">' + s + '</span>'; }).join('');
    var n = $('ggExcludedN');
    if (n) n.textContent = (DATA.excluded || []).length;
  }

  function renderExcluded() {
    var ul = $('ggExcludedList');
    if (!ul) return;
    var list = DATA.excluded || [];
    if (!list.length) { ul.innerHTML = '<li>暂无排除记录。</li>'; return; }
    ul.innerHTML = list.map(function (x) {
      var repo = x.repo ? ' <a href="https://github.com/' + esc(x.repo) + '" target="_blank" rel="noopener noreferrer">' +
        esc(x.repo) + '</a>' : '';
      return '<li><b>' + esc(x.name) + '</b>' + repo + '：' + esc(x.reason) + '</li>';
    }).join('');
  }

  /* ---------------- URL 同步 ---------------- */

  function syncUrl(extra) {
    try {
      var u = new URL(window.location.href);
      if (state.cat === 'all') u.searchParams.delete('cat');
      else u.searchParams.set('cat', state.cat);
      if (state.q) u.searchParams.set('q', state.q);
      else u.searchParams.delete('q');
      if (state.access !== 'all') u.searchParams.set('access', state.access);
      else u.searchParams.delete('access');
      if (state.sort !== 'curated') u.searchParams.set('sort', state.sort);
      else u.searchParams.delete('sort');
      if (extra && extra.id) u.searchParams.set('id', extra.id);
      else if (extra && extra.clearId) u.searchParams.delete('id');
      window.history.replaceState(null, '', u.pathname + u.search + u.hash);
    } catch (e) { /* 忽略 */ }
  }

  function scrollToList() {
    var grid = $('ggGrid');
    if (!grid) return;
    var top = grid.getBoundingClientRect().top + window.scrollY - 90;
    if (window.scrollY > top) window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
  }

  /* ---------------- 详情弹窗 ---------------- */

  function metaRow(label, value) {
    return '<div class="gg-meta__row"><dt>' + esc(label) + '</dt><dd>' + value + '</dd></div>';
  }

  function openDetail(id, silent) {
    if (!DATA) return;
    var it = cards()[id];
    if (!it) return;

    var play = safeUrl(it.play);
    var repo = safeUrl(it.repo ? 'https://github.com/' + it.repo : '');
    var b = badgeOf(it);

    $('ggModalCat').textContent = catLabel(it.cat);
    $('ggModalTitle').textContent = it.name;

    var rows = [
      metaRow('仓库', repo ? '<a href="' + esc(repo) + '" target="_blank" rel="noopener noreferrer">' + esc(it.repo) + '</a>' : '—'),
      metaRow('在线入口', play ? '<a href="' + esc(play) + '" target="_blank" rel="noopener noreferrer">' + esc(play) + '</a>' : '无公开入口'),
      metaRow('运行方式', esc(it.run)),
      metaRow('可用性',
        '<span class="gg-badge ' + b.cls + '">' + esc(b.label) + '</span> ' +
        '<span class="gg-badge ' + (it.embed ? 'is-ok' : 'is-link') + '">' + (it.embed ? '可站内试玩' : '仅跳转') + '</span>'),
      metaRow('分类', esc(catLabel(it.cat))),
      metaRow('技术栈', (it.tech || []).map(function (t) {
        return '<span class="gg-tag">' + esc(t) + '</span>';
      }).join(' ') || '—'),
      metaRow('Star', '★ ' + esc(fmtStars(it.stars))),
      metaRow('最近检测', esc(DATA.checkedAt || DATA.updated || '—') + '（HTTP 状态与嵌入策略）')
    ];

    $('ggModalBody').innerHTML =
      '<p class="gg-modal__desc">' + esc(it.desc) + '</p>' +
      ((it.tags || []).length ? '<div class="gg-modal__tags">' + it.tags.map(function (t) {
        return '<span class="gg-tag">' + esc(t) + '</span>';
      }).join('') + '</div>' : '') +
      '<div class="gg-modal__note ' + (it.status === 'down' ? 'is-warn' : '') + '">' +
        '<b>可用性说明</b><p>' + esc(it.note || '未记录额外限制。') + '</p>' +
      '</div>' +
      '<dl class="gg-meta">' + rows.join('') + '</dl>' +
      '<details class="gg-trouble"><summary>打不开怎么办？</summary>' +
        '<ol>' +
          '<li>先确认能打开 <a href="' + esc(repo || play) + '" target="_blank" rel="noopener noreferrer">GitHub 仓库</a>，仓库在、演示站挂了通常只是临时故障。</li>' +
          '<li>境外站点加载慢或超时，换网络/开代理再试；部分站点依赖 Google 街景、第三方 CDN。</li>' +
          '<li>被嵌入限制的条目请直接点「在线游玩」在新窗口打开，不要在站内播放器里反复刷新。</li>' +
          '<li>确实失效就复制下面的信息去反馈，方便下次批量修正。</li>' +
        '</ol>' +
        '<button class="btn" type="button" data-gg-report="' + esc(it.id) + '">复制失效反馈信息</button>' +
      '</details>';

    var foot = [];
    if (play && it.embed) foot.push('<button class="btn primary" type="button" data-gg-play="' + esc(it.id) + '">站内试玩</button>');
    if (play) foot.push('<a class="btn' + (it.embed ? '' : ' primary') + '" href="' + esc(play) + '" target="_blank" rel="noopener noreferrer">在线游玩</a>');
    if (repo) foot.push('<a class="btn" href="' + esc(repo) + '" target="_blank" rel="noopener noreferrer">查看源码</a>');
    foot.push('<button class="btn" type="button" data-gg-copy="' + esc(play || repo) + '">复制入口链接</button>');
    $('ggModalFoot').innerHTML = foot.join('');

    player.lastFocus = document.activeElement;
    var modal = $('ggModal');
    modal.hidden = false;
    document.body.classList.add('gg-no-scroll');
    var panel = modal.querySelector('.gg-modal__panel');
    if (panel) panel.focus();
    if (!silent) syncUrl({ id: it.id });
  }

  function closeDetail(opts) {
    var modal = $('ggModal');
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    document.body.classList.remove('gg-no-scroll');
    if (!(opts && opts.keepId)) syncUrl({ clearId: true });
    if (player.lastFocus && player.lastFocus.focus) player.lastFocus.focus();
  }

  /* ---------------- 站内播放器 ---------------- */

  function openPlayer(id) {
    if (!DATA) return;
    var it = cards()[id];
    var play = it && safeUrl(it.play);
    if (!play) return;
    var sec = $('ggPlayerSec');
    var frame = $('ggPlayerFrame');
    if (!sec || !frame) return;

    player.id = id;
    $('ggPlayerTitle').textContent = it.name;
    $('ggPlayerSub').textContent = '站内试玩 · ' + hostOf(play) + ' · 按 ESC 关闭';
    $('ggPlayerNewTab').href = play;
    $('ggPlayerFallbackOpen').href = play;
    $('ggPlayerDetail').setAttribute('data-gg-detail', id);
    $('ggPlayerFallback').hidden = true;

    frame.src = play;
    sec.hidden = false;
    syncUrl({ id: id });

    clearTimeout(player.timer);
    player.timer = setTimeout(function () {
      var fb = $('ggPlayerFallback');
      if (fb) fb.hidden = false;
    }, 9000);

    var top = sec.getBoundingClientRect().top + window.scrollY - 80;
    if (window.scrollY > top) window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });

    if (window.Niao && typeof window.Niao.toast === 'function') {
      window.Niao.toast('已在站内打开，若空白请点「新窗口打开」');
    }
  }

  function closePlayer() {
    var frame = $('ggPlayerFrame');
    if (frame) frame.src = 'about:blank';
    clearTimeout(player.timer);
    player.id = null;
    var sec = $('ggPlayerSec');
    if (sec) sec.hidden = true;
    syncUrl({ clearId: true });
  }

  function initPlayer() {
    var frame = $('ggPlayerFrame');
    if (frame) {
      frame.addEventListener('load', function () {
        if (frame.src && frame.src !== 'about:blank') {
          // 加载完成不代表一定渲染成功（可能被 XFO 拦截），保留提示但不再强行显示
          clearTimeout(player.timer);
        }
      });
    }
    var close = $('ggPlayerClose');
    if (close) close.addEventListener('click', closePlayer);
    var copy = $('ggPlayerFallbackCopy');
    if (copy) {
      copy.addEventListener('click', function () {
        var it = cards()[player.id];
        if (it) copyText(it.play, copy);
      });
    }
  }

  /* ---------------- 复制 / 反馈 ---------------- */

  function copyText(text, btn) {
    var done = function () {
      if (btn) {
        var old = btn.textContent;
        btn.textContent = '已复制';
        btn.classList.add('is-ok');
        setTimeout(function () { btn.textContent = old; btn.classList.remove('is-ok'); }, 1400);
      }
      if (window.Niao && typeof window.Niao.toast === 'function') window.Niao.toast('已复制到剪贴板');
    };
    var fail = function () {
      if (window.Niao && typeof window.Niao.toast === 'function') window.Niao.toast('复制失败，请手动选中链接', 'err');
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done, fail); });
    } else {
      fallbackCopy(text, done, fail);
    }
  }

  function fallbackCopy(text, done, fail) {
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
    } catch (e) { fail(); }
  }

  function reportText(it) {
    return [
      '【开源游戏库 · 链接反馈】',
      '游戏：' + it.name + '（' + it.id + '）',
      '仓库：https://github.com/' + it.repo,
      '在线入口：' + (it.play || '无'),
      '检测日期：' + (DATA.checkedAt || DATA.updated || ''),
      '问题描述：在线入口无法打开 / 页面报错 / 内容已变更（请补充截图与所在网络）'
    ].join('\n');
  }

  /* ---------------- 事件 ---------------- */

  function initEvents() {
    var tabs = $('ggTabs');
    if (tabs) {
      tabs.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('.gg-tab');
        if (!btn) return;
        state.cat = btn.getAttribute('data-cat') || 'all';
        syncUrl();
        render();
        scrollToList();
      });
    }

    var input = $('ggSearch');
    if (input) {
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

    var access = $('ggAccess');
    if (access) {
      access.addEventListener('change', function () {
        state.access = access.value;
        syncUrl();
        render();
      });
    }

    var sort = $('ggSort');
    if (sort) {
      sort.addEventListener('change', function () {
        state.sort = sort.value;
        syncUrl();
        render();
      });
    }

    var reset = $('ggReset');
    if (reset) {
      reset.addEventListener('click', function () {
        state = { cat: 'all', q: '', access: 'all', sort: 'curated' };
        if (input) input.value = '';
        if (access) access.value = 'all';
        if (sort) sort.value = 'curated';
        syncUrl();
        render();
      });
    }

    document.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target : null;
      if (!t) return;

      var playBtn = t.closest('[data-gg-play]');
      if (playBtn) {
        e.preventDefault();
        var pid = playBtn.getAttribute('data-gg-play');
        closeDetail({ keepId: true });
        openPlayer(pid);
        return;
      }

      var detailBtn = t.closest('[data-gg-detail]');
      if (detailBtn) {
        e.preventDefault();
        openDetail(detailBtn.getAttribute('data-gg-detail'));
        return;
      }

      var copyBtn = t.closest('[data-gg-copy]');
      if (copyBtn) {
        e.preventDefault();
        var url = copyBtn.getAttribute('data-gg-copy');
        if (url) copyText(url, copyBtn);
        return;
      }

      var reportBtn = t.closest('[data-gg-report]');
      if (reportBtn) {
        e.preventDefault();
        var it = cards()[reportBtn.getAttribute('data-gg-report')];
        if (it) copyText(reportText(it), reportBtn);
        return;
      }

      var close = t.closest('[data-gg-close]');
      if (close) { e.preventDefault(); closeDetail(); return; }

      var modalClose = t.closest('#ggModalClose');
      if (modalClose) { e.preventDefault(); closeDetail(); }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      var modal = $('ggModal');
      if (modal && !modal.hidden) { closeDetail(); return; }
      var sec = $('ggPlayerSec');
      if (sec && !sec.hidden) closePlayer();
    });

    // 站内播放器被滚出视口后，用户按返回键/回列表时不自动卸载，交给关闭按钮
  }

  /* ---------------- 启动 ---------------- */

  function boot() {
    try {
      var u = new URL(window.location.href);
      var c = u.searchParams.get('cat');
      if (c) state.cat = c;
      var q = u.searchParams.get('q');
      if (q) {
        state.q = q;
        if ($('ggSearch')) $('ggSearch').value = q;
      }
      var a = u.searchParams.get('access');
      if (a) {
        state.access = a;
        if ($('ggAccess')) $('ggAccess').value = a;
      }
      var s = u.searchParams.get('sort');
      if (s) {
        state.sort = s;
        if ($('ggSort')) $('ggSort').value = s;
      }
      state.openId = u.searchParams.get('id');
      state.openPlay = u.searchParams.get('play');
    } catch (e) { /* 忽略 */ }

    initEvents();
    initPlayer();

    fetch('github-games.json', { cache: 'no-cache' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        DATA = data;
        var meta = {};
        (data.categories || []).forEach(function (c) { meta[c.key] = c; });
        if (state.cat !== 'all' && !meta[state.cat]) state.cat = 'all';
        renderStats();
        renderExcluded();
        render();

        if (state.openPlay) {
          openPlayer(state.openPlay);
          state.openPlay = null;
        } else if (state.openId) {
          openDetail(state.openId, true);
          state.openId = null;
        }
      })
      .catch(function (err) {
        console.warn('[open-games] 数据加载失败：', err && err.message);
        var grid = $('ggGrid');
        if (grid) {
          grid.innerHTML = '<p class="gg-loading">游戏清单加载失败（' + esc(err && err.message) + '）。' +
            '如果你是直接双击打开的本地文件，请用本地服务器访问，或刷新页面重试。</p>';
        }
      });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
