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
  var PROXY_TIMEOUT = 6000;     // 代理重试超时
  var DEADLINE = 7500;          // 整体上限：超过该时间未返回的源按超时处理（结果仍可稍后补）

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

  /* URL 规范化：用于去重（不同源的同一页面只保留一条） */
  function canonicalUrl(u) {
    try {
      var url = new URL(u, window.location.href);
      var host = url.hostname.replace(/^www\./, '').toLowerCase();
      var path = url.pathname.replace(/\/+$/, '');
      var keep = [];
      url.searchParams.forEach(function (v, k) {
        if (/^(utm_|ref$|ref_|source$|spm|from$|share_|fbclid|gclid)/i.test(k)) return;
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

  /* ---------------- 相关性打分 ---------------- */
  function scoreOf(item, tokens, weight, rank) {
    var title = String(item.title || '').toLowerCase();
    var snippet = String(item.snippet || '').toLowerCase();
    var host = hostOf(item.url).toLowerCase();
    var badges = (item.badges || []).join(' ').toLowerCase();
    var phrase = tokens.join(' ');
    var score = 0;

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
      score += titleHit(t);
      if (snippet.indexOf(t) >= 0) score += 7;
      if (badges.indexOf(t) >= 0) score += 4;
      if (host.indexOf(t) >= 0) score += 10;
    });
    // 完整短语命中标题，明显更相关
    if (tokens.length > 1 && title.indexOf(phrase) >= 0) score += 26;

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
    var tokens = opts.tokens;
    var url = src.build(q);
    var timeout = opts.timeout || DEFAULT_TIMEOUT;

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
          score: scoreOf(it, tokens, src.weight, i),
          origin: 'web',
          via: via || 'direct'
        };
      }).filter(Boolean);

      return {
        id: src.id, name: src.name, short: src.short || src.name,
        state: results.length ? 'ok' : 'empty',
        count: results.length, ms: ms, via: via || 'direct',
        results: results
      };
    }

    function attempt() {
      if (src.forceProxy) return Promise.reject(new Error('force proxy'));
      var t = src.proxyable ? Math.min(timeout, 4200) : timeout;
      return fetchText(url, t).then(function (text) {
        return done(parsePayload(src, text, q), 'direct');
      });
    }

    function withProxy() {
      if ((!src.proxyable && !src.forceProxy) || !PROXIES.length || opts.noProxy) {
        return Promise.reject(new Error('skip proxy'));
      }
      // 依次尝试多条公共代理线路，任意一条成功即可
      var i = 0;
      function next() {
        if (i >= PROXIES.length) return Promise.reject(new Error('all proxies failed'));
        var proxy = PROXIES[i++];
        return fetchText(proxy.wrap(url), PROXY_TIMEOUT).then(function (text) {
          return done(parsePayload(src, text, q), proxy.name);
        }).catch(function (e) { return next(); });
      }
      return next();
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
    var list = pick(opts.groups);
    if (opts.ids && opts.ids.length) {
      list = list.filter(function (s) { return opts.ids.indexOf(s.id) >= 0; });
    }
    if (!list.length) return Promise.resolve({ results: [], statuses: [], ms: 0, removed: 0 });

    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    var ctx = { tokens: tokens, timeout: opts.timeout, noProxy: opts.noProxy };

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
      var ms = Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0);
      return {
        results: merged,
        statuses: statuses,
        ms: ms,
        removed: merged.removed || 0
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
