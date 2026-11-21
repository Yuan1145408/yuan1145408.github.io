/* ============================================================
   鸟国聚合搜索 · 全网检索引擎
   ------------------------------------------------------------
   - 并发请求 search-sources.js 中配置的全部公开数据源
   - 统一归一化为 {title, snippet, url, sourceId, sourceName, badges, score}
   - 去重（URL 规范化 + 标题同站判重）+ 相关性排序
   - 单源失败/超时不影响整体；被墙源自动切换公共代理重试
   - 不依赖任何后端与 API Key
   ============================================================ */
(function () {
  'use strict';

  var SOURCES = window.NIAO_SEARCH_SOURCES || [];
  var GROUPS = window.NIAO_SEARCH_GROUPS || [];
  var PROXIES = window.NIAO_SEARCH_PROXIES || [];

  var DEFAULT_TIMEOUT = 6000;   // 单源直连超时
  var PROXY_TIMEOUT = 2600;     // 单条代理尝试超时（代理普遍不稳，给短一点）
  var DEADLINE = 5500;          // 整体上限：超过该时间未返回的源按超时处理
  /* 公共代理健康度：连续失败 3 次后本次会话不再尝试，避免每次搜索都白等 2.6s */
  var proxyHealth = { fails: 0, next: 0 };

  /* ---------------- 工具 ---------------- */
  function stripTags(html) {
    var d = document.createElement('div');
    d.innerHTML = String(html || '');
    return (d.textContent || '').replace(/\s+/g, ' ').trim();
  }
  function clamp(s, n) {
    s = String(s || '').replace(/\s+/g, ' ').trim();
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
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

  /* ---------------- 查询扩展 ----------------
     纯中文查询交给英文源时基本零命中，这里映射到常用英文说法。
     只对纯中文查询生效，命中后英文源用扩展词、中文源仍用原词。 */
  var EXPAND = {
    '显卡驱动': 'graphics driver', '声卡驱动': 'audio driver', '驱动': 'driver',
    '剪映': 'capcut video editor', '剪辑': 'video editor', '录屏': 'screen recorder',
    '截图': 'screenshot tool', '解压': 'unzip tool', '压缩': 'compression tool',
    '我的世界': 'minecraft', '模组': 'minecraft mod', '光影': 'minecraft shader',
    '启动器': 'launcher', '虚拟机': 'virtual machine', '系统镜像': 'iso image',
    '浏览器': 'web browser', '输入法': 'input method', '杀毒': 'antivirus',
    '办公软件': 'office suite', '看图': 'image viewer', '播放器': 'media player',
    '机器学习': 'machine learning', '深度学习': 'deep learning',
    '神经网络': 'neural network', '爬虫': 'web scraping', '数据库': 'database',
    '面试': 'interview questions', '算法': 'algorithm', '操作系统': 'operating system',
    '网络协议': 'network protocol', '正则': 'regular expression', '并发': 'concurrency',
    '装饰器': 'decorator', '闭包': 'closure', '指针': 'pointer', '内存泄漏': 'memory leak'
  };
  var ZH_SOURCES = { 'csdn': 1, 'mcmod': 1, 'gamer520': 1, 'wikipedia-zh': 1, 'mcwiki-zh': 1 };

  /* 纯中文（没有拉丁字母）才需要扩展 */
  function expandQuery(q) {
    var s = String(q || '').trim().toLowerCase();
    if (!s || /[a-z]/i.test(s)) return '';
    if (EXPAND[s]) return EXPAND[s];
    var keys = Object.keys(EXPAND).sort(function (a, b) { return b.length - a.length; });
    for (var i = 0; i < keys.length; i++) {
      if (s.indexOf(keys[i]) >= 0) {
        var rest = s.replace(keys[i], ' ').replace(/\s+/g, ' ').trim();
        // 残留的中文词对英文源没意义，直接丢掉，避免 "minecraft 钠" 这种混合查询
        if (/[\u4e00-\u9fa5]/.test(rest)) rest = '';
        return (EXPAND[keys[i]] + (rest ? ' ' + rest : '')).trim();
      }
    }
    return '';
  }

  /* URL 规范化：用于去重（不同源的同一页面只保留一条） */
  function canonicalUrl(u) {
    try {
      var url = new URL(u, window.location.href);
      var host = url.hostname.replace(/^www\./, '').toLowerCase();
      var path = url.pathname.replace(/\/+$/, '');
      var keep = [];
      url.searchParams.forEach(function (v, k) {
        if (/^(utm_|ops_|ref$|ref_|source$|spm|from$|share_|fbclid|gclid)/i.test(k)) return;
        keep.push(k + '=' + v);
      });
      keep.sort();
      return host + path + (keep.length ? '?' + keep.join('&') : '');
    } catch (e) {
      return String(u || '').toLowerCase();
    }
  }

  function hostOf(u) {
    try { return new URL(u, window.location.href).hostname.replace(/^www\./, ''); }
    catch (e) { return ''; }
  }

  /* ---------------- 带超时的 fetch ---------------- */
  function fetchText(url, timeout) {
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, timeout || DEFAULT_TIMEOUT);
    var opts = { mode: 'cors', credentials: 'omit', cache: 'no-store' };
    if (ctrl) opts.signal = ctrl.signal;
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    }).then(function (text) {
      clearTimeout(timer);
      return text;
    }, function (err) {
      clearTimeout(timer);
      throw err;
    });
  }

  function parsePayload(src, text, q) {
    if (src.kind === 'html' || typeof src.parseText === 'function') {
      var doc = new DOMParser().parseFromString(text, 'text/html');
      return (src.parseText ? src.parseText(doc, q) : []) || [];
    }
    var data = JSON.parse(text);
    return (src.parse(data, q) || []);
  }

  /* ---------------- 相关性打分 ----------------
     多词查询不能靠“token 数量”堆分：搜「剪映」时标题完全命中的中文结果，
     不该被搜「capcut video editor」时零散命中三个词的英文结果压下去。
     所以主体分取“最强命中”，其余命中按 0.4 累加，再给完整短语额外加成。 */
  function scoreOf(item, tokens, weight, rank, query) {
    var title = String(item.title || '').toLowerCase();
    var snippet = String(item.snippet || '').toLowerCase();
    var host = hostOf(item.url).toLowerCase();
    var badges = (item.badges || []).join(' ').toLowerCase();
    var phrase = String(query || '').trim().toLowerCase();
    var sum = 0, best = 0;

    // 标题命中：整词 > 前缀 > 子串（避免 Pythongirl 压过 Python 教程）
    function titleHit(t) {
      var idx = title.indexOf(t);
      if (idx < 0) return 0;
      if (title === t) return 60;
      var beforeOk = idx === 0 || !/[a-z0-9]/i.test(title.charAt(idx - 1));
      var end = idx + t.length;
      var afterOk = end >= title.length || !/[a-z0-9]/i.test(title.charAt(end));
      var decay = 1 - Math.min(0.38, (idx / Math.max(1, title.length)) * 0.5);
      if (beforeOk && afterOk) return 42 * decay;
      if (idx === 0) return 26;
      return 16 * decay;
    }

    tokens.forEach(function (t) {
      if (!t) return;
      var s = titleHit(t);
      var inSnippet = snippet.indexOf(t) >= 0;
      var inBadge = badges.indexOf(t) >= 0;
      if (inSnippet) s += 7;
      if (inBadge) s += 4;
      if (host.indexOf(t) >= 0) s += 10;
      // 完全没命中的关键词要扣分：只擦边命中一个字的条目（如搜“钠”出来的钠电池文章）会被压下去
      if (!s) s -= 7;
      sum += s;
      if (s > best) best = s;
    });

    var score = best + Math.max(0, sum - best) * 0.4;

    // 完整查询串出现在标题里（含中文单词查询），可信度最高
    if (phrase) {
      if (title.indexOf(phrase) >= 0) score += 40;
      else if (snippet.indexOf(phrase) >= 0) score += 10;
    }

    // 源内排名只给很小的加成：跨源排序应以标题/摘要命中为主，
    // 否则某个源返回顺序会压过其它源更准确的标题
    score += Math.max(0, 6 - (rank || 0) * 1.5);

    // 标题过短/过长做轻微修正，避免「首页」「登录」这类噪声
    if (title.length <= 3) score -= 6;
    if (title.length > 90) score -= 4;

    return Math.round(score * (weight || 1) * 10) / 10;
  }

  /* ---------------- 单一数据源 ---------------- */
  function runSource(src, q, opts) {
    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    // 中文源用原词，其余源在纯中文查询下改用扩展词，避免“中文查英文库”零命中
    var query = (opts.qEn && !ZH_SOURCES[src.id]) ? opts.qEn : q;
    var tokens = tokenize(query);
    var url = src.build(query);
    var timeout = opts.timeout || DEFAULT_TIMEOUT;
    // 学术 / 图书源对生活类中文查询价值低，降权而不是直接删掉
    var weight = src.weight || 1;
    if (opts.qEn && (src.group === 'academic' || src.group === 'book')) weight *= 0.55;

    function done(list, via) {
      var ms = Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0);
      var results = (list || []).map(function (it, i) {
        var url2 = it.url;
        if (!url2) return null;
        return {
          title: clamp(it.title || '未命名结果', 140),
          snippet: clamp(it.snippet || '', 260),
          url: url2,
          sourceId: src.id,
          sourceName: src.name,
          sourceShort: src.short || src.name,
          sourceBadge: src.badge || String(src.short || src.name).slice(0, 1),
          group: src.group,
          host: hostOf(url2),
          badges: (it.badges || []).filter(Boolean).slice(0, 3),
          score: scoreOf(it, tokens, weight, i, query),
          origin: 'web',
          via: via || 'direct'
        };
      }).filter(Boolean);

      return {
        id: src.id, name: src.name, short: src.short || src.name,
        state: results.length ? 'ok' : 'empty',
        count: results.length, ms: ms, via: via || 'direct',
        query: query !== q ? query : '',
        results: results
      };
    }

    function attempt() {
      if (src.forceProxy) return Promise.reject(new Error('force proxy'));
      // 已知被墙的源给更短的直连超时，失败后立刻交给代理，不拖慢整体
      var base = src.proxyable ? Math.min(timeout, 4200) : timeout;
      if (src.directTimeout) base = Math.min(base, src.directTimeout);
      function once() {
        return fetchText(url, base).then(function (text) {
          return done(parsePayload(src, text, query), 'direct');
        });
      }
      // 少数国内接口偶发抽风，允许一次短重试（仅对声明了 retry 的源）
      return once().catch(function (e) {
        if (!src.retry) throw e;
        return new Promise(function (r) { setTimeout(r, 450); }).then(once);
      });
    }

    function withProxy() {
      if ((!src.proxyable && !src.forceProxy) || !PROXIES.length || opts.noProxy) {
        return Promise.reject(new Error('skip proxy'));
      }
      // 代理整体不可用时直接放弃，省掉每条 2.6s 的等待
      if (proxyHealth.fails >= 3) return Promise.reject(new Error('proxy unavailable'));
      var proxy = PROXIES[proxyHealth.next % PROXIES.length];
      proxyHealth.next++;
      return fetchText(proxy.wrap(url), PROXY_TIMEOUT).then(function (text) {
        proxyHealth.fails = 0;
        return done(parsePayload(src, text, query), proxy.name);
      }).catch(function (e) {
        proxyHealth.fails++;
        throw e;
      });
    }

    return attempt().catch(function (err) {
      if ((!src.proxyable && !src.forceProxy) || opts.noProxy) throw err;
      // 直连失败（多为网络不可达），走公共代理再试一次
      return withProxy().catch(function () { throw err; });
    }).catch(function (err) {
      var ms = Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0);
      var timeoutLike = /abort|timeout/i.test(String(err && (err.name + ' ' + err.message)));
      return {
        id: src.id, name: src.name, short: src.short || src.name,
        state: timeoutLike ? 'timeout' : 'error',
        count: 0, ms: ms, error: String(err && err.message || err),
        fallback: typeof src.fallback === 'function' ? src.fallback(q) : '',
        results: []
      };
    });
  }

  /* ---------------- 去重 ---------------- */
  function dedupe(list) {
    var byUrl = {};
    var order = [];
    var removed = 0;

    list.forEach(function (r) {
      var key = canonicalUrl(r.url);
      var prev = byUrl[key];
      if (!prev) {
        byUrl[key] = r;
        order.push(key);
        return;
      }
      removed++;
      // 合并：保留分数高的，来源记为多个
      var winner = prev.score >= r.score ? prev : r;
      var loser = winner === prev ? r : prev;
      winner.sourceName = prev.sourceName === r.sourceName
        ? prev.sourceName
        : prev.sourceName + ' / ' + r.sourceName;
      winner.badges = (winner.badges || []).concat(loser.badges || [])
        .filter(function (v, i, a) { return v && a.indexOf(v) === i; }).slice(0, 3);
      if (!winner.snippet && loser.snippet) winner.snippet = loser.snippet;
      byUrl[key] = winner;
    });

    var out = order.map(function (k) { return byUrl[k]; });
    out.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      return String(a.title).length - String(b.title).length;
    });
    out.removed = removed;
    return out;
  }

  /* ---------------- 对外接口 ---------------- */
  function pick(groups) {
    if (!groups || groups.indexOf('all') >= 0) return SOURCES.slice();
    return SOURCES.filter(function (s) { return groups.indexOf(s.group) >= 0; });
  }

  function search(q, options) {
    var opts = options || {};
    var query = String(q || '').trim();
    if (!query) return Promise.resolve({ results: [], statuses: [], ms: 0, removed: 0 });

    var tokens = tokenize(query);
    var qEn = expandQuery(query);
    var list = pick(opts.groups);
    if (opts.ids && opts.ids.length) {
      list = list.filter(function (s) { return opts.ids.indexOf(s.id) >= 0; });
    }
    if (!list.length) return Promise.resolve({ results: [], statuses: [], ms: 0, removed: 0 });

    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    var ctx = { tokens: tokens, qEn: qEn, timeout: opts.timeout, noProxy: opts.noProxy };

    var pending = list.map(function (src) {
      var p = runSource(src, query, ctx);
      // 整体上限：到点仍未返回的源直接标记超时，避免拖慢页面
      p = Promise.race([p, new Promise(function (resolve) {
        setTimeout(function () {
          resolve({ id: src.id, name: src.name, short: src.short || src.name, state: 'timeout',
            count: 0, ms: (opts.deadline || DEADLINE),
            fallback: typeof src.fallback === 'function' ? src.fallback(query) : '',
            results: [] });
        }, (opts.deadline || DEADLINE) + 50);
      })]);
      if (typeof opts.onSource === 'function') {
        p.then(function (st) { try { opts.onSource(st); } catch (e) {} });
      }
      return p;
    });

    return Promise.all(pending).then(function (statuses) {
      var all = [];
      statuses.forEach(function (st) { all = all.concat(st.results); });
      var merged = dedupe(all);

      // 噪声过滤：丢掉与查询几乎无关的尾巴（例如中文生活词在论文库里命中的条目）
      var top = merged.length ? merged[0].score : 0;
      var floor = Math.max(4, top * 0.12);
      var kept = merged.filter(function (r) { return r.score >= floor; });
      if (kept.length < 8) kept = merged.slice(0, Math.max(8, kept.length));

      // 单一来源最多 6 条，避免某个源把整页刷满
      var per = {}, capped = [];
      kept.forEach(function (r) {
        var n = per[r.sourceId] || 0;
        if (n >= 6) return;
        per[r.sourceId] = n + 1;
        capped.push(r);
      });
      capped.removed = merged.removed || 0;

      var ms = Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0);
      return {
        results: capped,
        statuses: statuses,
        ms: ms,
        removed: capped.removed,
        expanded: qEn || ''
      };
    });
  }

  window.NiaoWeb = {
    sources: SOURCES,
    groups: GROUPS,
    search: search,
    tokenize: tokenize,
    canonicalUrl: canonicalUrl,
    hostOf: hostOf
  };
})();
