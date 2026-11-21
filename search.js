/* ============================================================
   鸟国聚合搜索 · 纯原生 JS
   - 站内索引（读取站点自身的 JSON）+ 外部多源检索入口
   - 无任何外部依赖，file:// 直开或线上部署行为一致
   ============================================================ */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------------- 数据源定义 ---------------- */
  var SRC = {
    google:    { name: 'Google',        short: 'G',  tpl: 'https://www.google.com/search?q={q}',                      tags: ['安全', '极速'], desc: '全球最大索引，技术与英文资料覆盖最好' },
    bing:      { name: 'Bing',          short: 'B',  tpl: 'https://www.bing.com/search?q={q}',                        tags: ['安全', '极速'], desc: '索引更新快，中文匹配稳定，国内可直连' },
    bingcn:    { name: '必应中国',       short: 'B',  tpl: 'https://cn.bing.com/search?q={q}',                         tags: ['安全', '极速'], desc: '必应中国节点，访问延迟更低' },
    ddg:       { name: 'DuckDuckGo',    short: 'D',  tpl: 'https://duckduckgo.com/?q={q}',                            tags: ['安全', '无广告'], desc: '不做用户画像，结果无个性化气泡' },
    brave:     { name: 'Brave Search',  short: 'Br', tpl: 'https://search.brave.com/search?q={q}',                    tags: ['安全', '无广告'], desc: '独立索引，不依赖其它引擎转售' },
    startpage: { name: 'Startpage',     short: 'SP', tpl: 'https://www.startpage.com/sp/search?query={q}',             tags: ['安全', '无广告'], desc: '代理 Google 结果并剥离追踪参数' },
    qwant:     { name: 'Qwant',         short: 'Q',  tpl: 'https://www.qwant.com/?q={q}',                             tags: ['安全', '无广告'], desc: '欧洲隐私优先索引' },
    ecosia:    { name: 'Ecosia',        short: 'E',  tpl: 'https://www.ecosia.org/search?q={q}',                       tags: ['安全', '无广告'], desc: '基于 Bing 索引的公益搜索引擎' },
    mojeek:    { name: 'Mojeek',        short: 'M',  tpl: 'https://www.mojeek.com/search?q={q}',                       tags: ['安全', '无广告'], desc: '自有爬虫的独立索引' },
    wiki:      { name: '维基百科',       short: 'W',  tpl: 'https://zh.wikipedia.org/w/index.php?search={q}',           tags: ['安全', '无广告'], desc: '概念、术语与背景知识首选' },
    github:    { name: 'GitHub',        short: 'GH', tpl: 'https://github.com/search?q={q}&type=repositories',         tags: ['安全', '极速'], desc: '开源仓库、示例代码与工程实现' },
    gitee:     { name: 'Gitee',         short: 'GE', tpl: 'https://search.gitee.com/?q={q}&type=repository',           tags: ['安全', '极速'], desc: '国内代码托管，克隆速度更快' },
    stack:     { name: 'Stack Overflow', short: 'SO', tpl: 'https://stackoverflow.com/search?q={q}',                   tags: ['安全', '无广告'], desc: '报错信息与疑难问题的高命中地' },
    npm:       { name: 'npm',           short: 'N',  tpl: 'https://www.npmjs.com/search?q={q}',                         tags: ['安全', '极速'], desc: 'Node 生态包与版本信息' },
    pypi:      { name: 'PyPI',          short: 'P',  tpl: 'https://pypi.org/search/?q={q}',                             tags: ['安全', '极速'], desc: 'Python 包检索与元数据' },
    archive:   { name: 'Archive.org',   short: 'A',  tpl: 'https://archive.org/search?query={q}',                       tags: ['安全', '免费'], desc: '网页存档与公开数字资源' },
    bilibili:  { name: '哔哩哔哩',       short: 'B',  tpl: 'https://search.bilibili.com/all?keyword={q}',                tags: ['安全', '无广告'], desc: '视频教程与实操演示' },
    zhihu:     { name: '知乎',          short: '知', tpl: 'https://www.zhihu.com/search?type=content&q={q}',            tags: ['安全'], desc: '中文经验帖与踩坑记录' },
    csdn:      { name: 'CSDN',          short: 'C',  tpl: 'https://so.csdn.net/so/search?q={q}',                        tags: ['极速'], desc: '中文技术博客聚合' },
    baidu:     { name: '百度',          short: '百', tpl: 'https://www.baidu.com/s?wd={q}',                             tags: ['安全', '极速'], desc: '中文网页与百科结果最全' },
    sogou:     { name: '搜狗',          short: '搜', tpl: 'https://www.sogou.com/web?query={q}',                        tags: ['极速'], desc: '微信内容与知乎结果可直接检索' },
    so360:     { name: '360 搜索',      short: '360', tpl: 'https://www.so.com/s?q={q}',                                tags: ['极速'], desc: '国内备用检索入口' },
    yahoojp:   { name: 'Yahoo! JAPAN',  short: 'Y',  tpl: 'https://search.yahoo.co.jp/search?p={q}',                    tags: ['安全', '极速'], desc: '日本本地结果覆盖最好' },
    naver:     { name: 'Naver',         short: 'N',  tpl: 'https://search.naver.com/search.naver?query={q}',            tags: ['安全'], desc: '韩国主流入口，博客与知识人问答' },
    daum:      { name: 'Daum',          short: 'Da', tpl: 'https://search.daum.net/search?q={q}',                       tags: ['极速'], desc: '韩国备用入口' },
    reddit:    { name: 'Reddit',        short: 'R',  tpl: 'https://www.reddit.com/search/?q={q}',                       tags: ['安全', '无广告'], desc: '真实用户讨论与横向对比' },
    hn:        { name: 'Hacker News',   short: 'HN', tpl: 'https://hn.algolia.com/?q={q}',                              tags: ['安全', '极速'], desc: '开发者社区高质量讨论' }
  };

  /* ---------------- 地区配置 ---------------- */
  var REGIONS = {
    global: { label: '全球',       list: ['google', 'bing', 'ddg', 'brave', 'github', 'stack', 'npm', 'pypi', 'wiki', 'archive', 'bilibili', 'zhihu'] },
    cn:     { label: '中国大陆',   list: ['baidu', 'bingcn', 'sogou', 'so360', 'zhihu', 'bilibili', 'csdn', 'gitee', 'github', 'npm', 'pypi', 'wiki'] },
    hk:     { label: '中国香港',   list: ['google', 'bing', 'ddg', 'wiki', 'github', 'stack', 'npm', 'pypi', 'archive', 'bilibili', 'zhihu', 'brave'] },
    tw:     { label: '中国台湾',   list: ['google', 'bing', 'ddg', 'wiki', 'github', 'stack', 'npm', 'pypi', 'archive', 'bilibili', 'zhihu', 'brave'] },
    jp:     { label: '日本',       list: ['google', 'yahoojp', 'bing', 'ddg', 'wiki', 'github', 'stack', 'npm', 'pypi', 'archive', 'brave', 'hn'] },
    kr:     { label: '韩国',       list: ['google', 'naver', 'daum', 'bing', 'ddg', 'wiki', 'github', 'stack', 'npm', 'pypi', 'archive', 'hn'] },
    sg:     { label: '新加坡',     list: ['google', 'bing', 'ddg', 'brave', 'github', 'stack', 'npm', 'pypi', 'wiki', 'archive', 'hn', 'reddit'] },
    us:     { label: '美国',       list: ['google', 'bing', 'ddg', 'brave', 'github', 'stack', 'npm', 'pypi', 'wiki', 'archive', 'reddit', 'hn'] },
    eu:     { label: '欧洲',       list: ['google', 'startpage', 'qwant', 'ecosia', 'mojeek', 'bing', 'ddg', 'wiki', 'github', 'stack', 'npm', 'pypi'] }
  };

  /* ---------------- 站内索引 ---------------- */
  var localIndex = [];

  function fetchJSON(path) {
    return fetch(path, { cache: 'no-cache' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  function asList(data, key) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data[key])) return data[key];
    return [];
  }

  function buildLocalIndex() {
    return Promise.all([
      fetchJSON('./tutorials-extra.json'),
      fetchJSON('./softwares-extra.json'),
      fetchJSON('./games-extra.json'),
      fetchJSON('./downloads-extra.json')
    ]).then(function (res) {
      var items = [];

      asList(res[0], 'tutorials').forEach(function (d) {
        items.push({
          title: d.name || '未命名教程',
          url: d.local || d.website || 'tutorials.html',
          desc: d.desc || '',
          group: '教程',
          tags: (d.tags || []).concat(d.category ? [d.category] : [])
        });
      });

      asList(res[1], 'software').forEach(function (d) {
        items.push({
          title: d.name || '未命名软件',
          url: d.website || d.direct || 'downloads.html',
          desc: d.desc || '',
          group: '软件',
          tags: (d.tags || []).concat(d.category ? [d.category] : [])
        });
      });

      asList(res[2], 'games').forEach(function (d) {
        items.push({
          title: d.name || '未命名游戏',
          url: d.website || d.play || 'games.html',
          desc: d.desc || '',
          group: '游戏',
          tags: (d.tags || []).concat(d.category ? [d.category] : [])
        });
      });

      var dl = res[3] || {};
      ['vm', 'os'].forEach(function (kind) {
        (Array.isArray(dl[kind]) ? dl[kind] : []).forEach(function (d) {
          items.push({
            title: d.name || '未命名资源',
            url: d.website || d.direct || (kind === 'vm' ? 'vm.html' : 'os.html'),
            desc: d.desc || '',
            group: kind === 'vm' ? '虚拟机' : '系统镜像',
            tags: d.tags || []
          });
        });
      });

      localIndex = items.filter(function (it) { return it.title; });
    });
  }

  function searchLocal(q) {
    var kw = q.toLowerCase().trim();
    if (!kw) return [];
    var words = kw.split(/\s+/).filter(Boolean);
    var scored = [];

    localIndex.forEach(function (it) {
      var name = String(it.title).toLowerCase();
      var desc = String(it.desc).toLowerCase();
      var tags = (it.tags || []).join(' ').toLowerCase();
      var score = 0;
      words.forEach(function (w) {
        if (name.indexOf(w) >= 0) score += 6;
        if (tags.indexOf(w) >= 0) score += 3;
        if (desc.indexOf(w) >= 0) score += 2;
        if (it.group.indexOf(w) >= 0) score += 1;
      });
      if (score > 0) scored.push({ item: it, score: score });
    });

    scored.sort(function (a, b) { return b.score - a.score; });
    return scored.slice(0, 4).map(function (s) { return s.item; });
  }

  /* ---------------- 工具 ---------------- */
  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function buildUrl(tpl, q) {
    return tpl.replace('{q}', encodeURIComponent(q));
  }

  function prettyUrl(u) {
    try { return decodeURI(u); } catch (e) { return u; }
  }

  function hostOf(u) {
    try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
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
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy') ? resolve() : reject(new Error('copy failed'));
      } catch (e) {
        reject(e);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  /* ---------------- 树状拓扑动画 ---------------- */
  var treeEl = $('tree');
  var treeHint = $('treeHint');

  function renderTree(keys) {
    if (!treeEl) return;
    var all = (keys || []).slice();
    state.treeKeys = all;

    var compact = window.innerWidth < 760;
    var parts = [];
    var W, H;

    parts.push(
      '<svg viewBox="0 0 ' + (compact ? 400 : 860) + ' ' + (compact ? 258 : 400) + '" preserveAspectRatio="xMidYMid meet" role="img" aria-label="检索拓扑示意">',
      '<defs>',
      '<radialGradient id="nodeGrad" cx="50%" cy="50%" r="60%">',
      '<stop offset="0%" stop-color="#eaf6ff"/><stop offset="55%" stop-color="#8ec8ff"/><stop offset="100%" stop-color="#4d7dff"/>',
      '</radialGradient>',
      '<radialGradient id="rootGrad" cx="50%" cy="50%" r="60%">',
      '<stop offset="0%" stop-color="#ffffff"/><stop offset="60%" stop-color="#bfe6ff"/><stop offset="100%" stop-color="#7b8cff"/>',
      '</radialGradient>',
      '<filter id="softGlow" x="-80%" y="-80%" width="260%" height="260%">',
      '<feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>',
      '</filter>',
      '</defs>'
    );

    function nodeMarkup(x, y, label, r, labelY) {
      return '<g class="tree-node tree-node--q node-blink" style="animation-delay:' + (Math.random() * 1.2).toFixed(2) + 's">' +
        '<circle class="halo" cx="' + x + '" cy="' + y + '" r="' + (r + 3) + '"/>' +
        '<circle cx="' + x + '" cy="' + y + '" r="' + r + '" fill="url(#nodeGrad)"/>' +
        '<text class="tree-q" x="' + x + '" y="' + (y + 3.6) + '" text-anchor="middle"' + (compact ? ' style="font-size:9.5px"' : '') + '>?</text>' +
        '<text class="tree-label" x="' + x + '" y="' + (labelY || (y - r - 7)) + '" text-anchor="middle">' + esc(label) + '</text>' +
        '</g>';
    }

    if (compact) {
      // 窄屏：单层扇形发散，只保留 6 个节点，保证文字可读
      W = 400; H = 258;
      var cx = W / 2, cy = 210, R = 152;
      var picked = all.slice(0, 6);
      picked.forEach(function (k, i) {
        var a = Math.PI * (1.06 + (0.88 * i) / Math.max(1, picked.length - 1));
        var x = cx + Math.cos(a) * R;
        var y = Math.max(46, cy + Math.sin(a) * (R * 0.82));
        parts.push('<line class="tree-line" x1="' + cx + '" y1="' + (cy - 12) + '" x2="' + x + '" y2="' + (y + 8) + '"/>');
        parts.push(nodeMarkup(x, y, SRC[k] ? SRC[k].name : k, 9, y - 16));
      });
      parts.push(
        '<g class="tree-node tree-node--root" filter="url(#softGlow)">',
        '<circle class="halo" cx="' + cx + '" cy="' + cy + '" r="16"/>',
        '<circle cx="' + cx + '" cy="' + cy + '" r="13" fill="url(#rootGrad)"/>',
        '</g>',
        '<text class="tree-root-label" x="' + cx + '" y="' + (cy + 32) + '" text-anchor="middle">当前查询</text>'
      );
    } else {
      // 宽屏：根部向左、两级发散
      W = 860; H = 400;
      var rx = 96, ry = H / 2;
      var l1 = all.slice(0, 4);
      var l2 = all.slice(4, 12);

      var l1pos = l1.map(function (k, i) {
        return { key: k, x: 380, y: ry + (i - (l1.length - 1) / 2) * 78 };
      });

      l1pos.forEach(function (p) {
        parts.push('<line class="tree-line" x1="' + (rx + 16) + '" y1="' + ry + '" x2="' + (p.x - 13) + '" y2="' + p.y + '"/>');
      });

      l1pos.forEach(function (p, i) {
        var label = SRC[p.key] ? SRC[p.key].name : p.key;
        parts.push(
          '<g class="tree-node tree-node--q node-blink" style="animation-delay:' + (i * 0.18) + 's">',
          '<circle class="halo" cx="' + p.x + '" cy="' + p.y + '" r="14"/>',
          '<circle cx="' + p.x + '" cy="' + p.y + '" r="11" fill="url(#nodeGrad)"/>',
          '<text class="tree-q" x="' + p.x + '" y="' + (p.y + 4) + '" text-anchor="middle">?</text>',
          '<text class="tree-label" x="' + p.x + '" y="' + (p.y - 18) + '" text-anchor="middle">' + esc(label) + '</text>',
          '</g>'
        );
      });

      l1pos.forEach(function (p, idx) {
        l2.slice(idx * 2, idx * 2 + 2).forEach(function (k, j) {
          var x = 640 + (j % 2) * 118;
          var y = Math.max(40, Math.min(H - 40, p.y + (j - 0.5) * 44));
          parts.push('<line class="tree-line" x1="' + (p.x + 13) + '" y1="' + p.y + '" x2="' + (x - 12) + '" y2="' + y + '"/>');
          parts.push(nodeMarkup(x, y, SRC[k] ? SRC[k].name : k, 8.5));
        });
      });

      parts.push(
        '<g class="tree-node tree-node--root" filter="url(#softGlow)">',
        '<circle class="halo" cx="' + rx + '" cy="' + ry + '" r="16"/>',
        '<circle cx="' + rx + '" cy="' + ry + '" r="13" fill="url(#rootGrad)"/>',
        '</g>',
        '<text class="tree-root-label" x="' + rx + '" y="' + (ry + 34) + '" text-anchor="middle">当前查询</text>'
      );
    }

    parts.push('</svg>');
    treeEl.innerHTML = parts.join('');

    if (treeHint) {
      treeHint.textContent = '等待输入关键词 · ' + all.length + ' 个数据源已就绪';
    }
  }

  /* ---------------- 渲染结果 ---------------- */
  function tagClass(tag) {
    if (tag === '安全') return 'tag--safe';
    if (tag === '极速') return 'tag--fast';
    if (tag === '无广告' || tag === '纯净') return 'tag--clean';
    if (tag === '代理' || tag === '免费') return 'tag--proxy';
    return 'tag--local';
  }

  function resultCard(item, index) {
    var el = document.createElement('article');
    el.className = 'result is-in';
    el.style.animationDelay = (index * 55) + 'ms';

    var isLocal = item.kind === 'local';
    var url = String(item.url || '');
    // 统一转成绝对地址：站内相对路径也展示成完整 https 链接，复制后可直接分享
    var absUrl = url;
    try { absUrl = new URL(url, window.location.href).href; } catch (e) { /* 保留原值 */ }
    var tags = (item.tags || []).slice(0, 3).map(function (t) {
      return '<span class="tag ' + tagClass(t) + '">' + esc(t) + '</span>';
    }).join('');

    el.innerHTML =
      '<div class="result__top">' +
        '<span class="result__badge' + (isLocal ? ' result__badge--local' : '') + '">' + esc(item.short || (isLocal ? '站' : hostOf(url).slice(0, 2).toUpperCase())) + '</span>' +
        '<h3 class="result__title"><a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(item.title) + '</a></h3>' +
        '<div class="tags">' + tags + '</div>' +
      '</div>' +
      '<p class="result__url">' +
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10 14a4 4 0 0 1 0-5.7l2.3-2.3a4 4 0 0 1 5.7 5.7L16.6 13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M14 10a4 4 0 0 1 0 5.7l-2.3 2.3a4 4 0 0 1-5.7-5.7L7.4 11" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>' +
        '<span>' + esc(prettyUrl(absUrl)) + '</span>' +
      '</p>' +
      (item.desc ? '<p class="result__desc">' + esc(item.desc) + '</p>' : '') +
      '<div class="result__actions">' +
        '<button class="act" type="button" data-copy="' + esc(absUrl) + '">' +
          '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="9" y="9" width="10" height="10" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M15 6.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>' +
          '<span>复制链接</span>' +
        '</button>' +
        '<a class="act act--primary" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' +
          '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M14 5h5v5M19 5l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M18.5 14.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V7A1.5 1.5 0 0 1 6 5.5h3.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>' +
          '<span>' + (isLocal ? '前往站内页' : '访问') + '</span>' +
        '</a>' +
      '</div>';

    return el;
  }

  function renderResults(localHits, regionKey, q, elapsed) {
    var region = REGIONS[regionKey] || REGIONS.global;
    var list = $('resultList');
    var panel = $('results');
    list.innerHTML = '';

    var nodes = [];

    localHits.forEach(function (it) {
      nodes.push({
        kind: 'local',
        short: '站',
        title: it.title,
        url: it.url,
        desc: (it.group ? '[' + it.group + '] ' : '') + (it.desc || ''),
        tags: ['站内命中'].concat((it.tags || []).slice(0, 2))
      });
    });

    region.list.forEach(function (k) {
      var s = SRC[k];
      if (!s) return;
      nodes.push({
        kind: 'external',
        short: s.short,
        title: s.name + ' · ' + q,
        url: buildUrl(s.tpl, q),
        desc: s.desc,
        tags: s.tags || []
      });
    });

    nodes.forEach(function (n, i) { list.appendChild(resultCard(n, i)); });

    $('resultCount').textContent = String(nodes.length);
    $('resultMeta').textContent = region.label + ' · ' + region.list.length + ' 个数据源 · ' +
      (localHits.length ? '站内命中 ' + localHits.length + ' 条 · ' : '') +
      (elapsed / 1000).toFixed(2) + 's';

    var lat = $('metricLatency');
    if (lat) lat.innerHTML = (elapsed / 1000).toFixed(2) + '<em>s</em>';

    $('resultEmpty').hidden = localHits.length > 0;
    panel.hidden = false;
  }

  /* ---------------- 搜索主流程 ---------------- */
  var state = { busy: false, lastQ: '', lastRegion: 'global' };

  function setBusy(on) {
    state.busy = on;
    var btn = $('searchBtn');
    if (!btn) return;
    btn.disabled = on;
    var label = btn.querySelector('.btn-search__label');
    if (label) label.textContent = on ? '检索中' : '搜索';
  }

  function runSearch(rawQ, regionKey) {
    if (state.busy) return;
    var q = String(rawQ || '').trim();
    var form = $('searchForm');

    if (!q) {
      form.classList.add('is-shaking');
      setTimeout(function () { form.classList.remove('is-shaking'); }, 480);
      toast('请输入关键词');
      $('q').focus();
      return;
    }

    var region = REGIONS[regionKey] ? regionKey : 'global';
    state.lastQ = q;
    state.lastRegion = region;
    setBusy(true);

    // 同步到地址栏，便于分享/刷新
    try {
      var u = new URL(window.location.href);
      u.searchParams.set('q', q);
      u.searchParams.set('r', region);
      history.replaceState(null, '', u.toString());
    } catch (e) { /* file:// 下可能不可用，忽略 */ }

    // 1) 拓扑动画进入检索态
    var treePanel = $('treePanel');
    treePanel.hidden = false;
    treePanel.classList.remove('is-fading');
    if (treeEl) treeEl.classList.add('is-searching');
    if (treeHint) treeHint.textContent = '正在并发检索 · ' + q;

    var scanning = $('scanning');
    var fill = $('scanningFill');
    var countEl = $('scanningCount');
    var textEl = $('scanningText');
    scanning.hidden = false;
    fill.style.width = '0%';

    var sources = REGIONS[region].list;
    var total = sources.length + 1; // +1 = 站内索引
    var done = 0;
    var t0 = performance.now();

    var tickTimer = setInterval(function () {
      done = Math.min(total - 1, done + 1);
      var pct = Math.round((done / total) * 100);
      fill.style.width = pct + '%';
      countEl.textContent = done + '/' + total;
      var key = done === 0 ? null : sources[done - 1];
      textEl.textContent = key && SRC[key]
        ? '正在查询 ' + SRC[key].name + '…'
        : '正在扫描站内索引…';
    }, 65);

    var localHits = searchLocal(q);
    var minDelay = reduceMotion ? 260 : 880;

    setTimeout(function () {
      clearInterval(tickTimer);
      done = total;
      fill.style.width = '100%';
      countEl.textContent = total + '/' + total;
      textEl.textContent = '检索完成 · 共 ' + (localHits.length + sources.length) + ' 条结果';

      var elapsed = performance.now() - t0;

      // 2) 拓扑淡出，结果进入
      if (treeEl) treeEl.classList.remove('is-searching');
      treePanel.classList.add('is-fading');
      setTimeout(function () { treePanel.hidden = true; scanning.hidden = true; }, reduceMotion ? 0 : 320);

      renderResults(localHits, region, q, elapsed);
      setBusy(false);

      var stage = $('stage');
      if (stage) stage.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    }, minDelay);
  }

  /* ---------------- 事件绑定 ---------------- */
  function bindEvents() {
    var form = $('searchForm');
    var regionSel = $('region');

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      runSearch($('q').value, regionSel.value);
    });

    regionSel.addEventListener('change', function () {
      var r = regionSel.value;
      renderTree(REGIONS[r].list);
      toast('已切换到 ' + REGIONS[r].label);
      if (state.lastQ && !$('results').hidden) {
        // 已有结果时，切地区直接按新地区重检
        runSearch(state.lastQ, r);
      }
    });

    document.querySelectorAll('[data-kw]').forEach(function (b) {
      b.addEventListener('click', function () {
        $('q').value = b.getAttribute('data-kw');
        runSearch($('q').value, regionSel.value);
      });
    });

    // 复制按钮（事件委托）
    document.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-copy]') : null;
      if (!btn) return;
      var text = btn.getAttribute('data-copy');
      copyText(text).then(function () {
        btn.classList.add('is-copied');
        var span = btn.querySelector('span');
        var old = span ? span.textContent : '';
        if (span) span.textContent = '已复制';
        toast('链接已复制到剪贴板');
        setTimeout(function () {
          btn.classList.remove('is-copied');
          if (span) span.textContent = old || '复制链接';
        }, 1600);
      }).catch(function () {
        toast('复制失败，请手动选择链接');
      });
    });

    // 右下角快捷进入
    var dockBtn = $('dockBtn');
    var dockPanel = $('dockPanel');
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

    // “/” 聚焦搜索框
    document.addEventListener('keydown', function (e) {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      var tag = (document.activeElement && document.activeElement.tagName) || '';
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) return;
      e.preventDefault();
      $('q').focus();
    });

    // 视口跨断点变化时重排拓扑图（宽屏两级发散 / 窄屏单层扇形）
    var rt;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () {
        var results = $('results');
        if (!results || results.hidden) renderTree(state.treeKeys || REGIONS.global.list);
      }, 220);
    });
  }

  /* ---------------- 启动 ---------------- */
  function init() {
    renderTree(REGIONS.global.list);
    bindEvents();

    var m = $('metricSources');
    if (m) m.textContent = String(REGIONS.global.list.length);

    buildLocalIndex().then(function () {
      var hint = $('treeHint');
      if (hint && !state.busy) {
        if (localIndex.length) {
          hint.textContent = '等待输入关键词 · 站内索引 ' + localIndex.length + ' 条已就绪';
        } else if (window.location.protocol === 'file:') {
          // file:// 直开时浏览器会拦截 JSON 读取，此时仅外部源可用
          hint.textContent = '等待输入关键词 · 外部源已就绪（本地建议用 python serve.py 启动以启用站内索引）';
        } else {
          hint.textContent = '等待输入关键词 · 数据源已就绪';
        }
      }
      // 支持从 URL 直接带参数打开
      var params = new URLSearchParams(window.location.search);
      var q = params.get('q');
      var r = params.get('r');
      if (r && REGIONS[r]) {
        $('region').value = r;
        renderTree(REGIONS[r].list);
      }
      if (q) {
        $('q').value = q;
        runSearch(q, r && REGIONS[r] ? r : 'global');
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
