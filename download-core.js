/* ============================================================
   鸟国站 · 下载核心
   ------------------------------------------------------------
   1) 链接解析：直链 / 网盘分享链接（提取分享地址与提取码）
   2) 远端探测：大小、是否支持 Range、文件名（Content-Disposition）
   3) 多线程下载：按 Range 分片并发，失败可重试，支持暂停/继续/取消
   4) 降级：不支持 Range 或跨域受限时退回单流，再退回浏览器直接下载
   对外：window.NiaoDownloader
   ============================================================ */
(function () {
  'use strict';

  /* ---------------- 网盘规则 ---------------- */
  var NETDISK = [
    {
      id: 'baidu', name: '百度网盘', host: /pan\.baidu\.com/i,
      parse: function (url, text) {
        var pwd = (url.match(/[?&]pwd=([a-z0-9]{4})/i) || [])[1] ||
                  (text.match(/(?:提取码|密码|pwd)[：:\s]*([a-z0-9]{4})/i) || [])[1] || '';
        return { pwd: pwd, needsLogin: true, resolver: false };
      }
    },
    {
      id: 'quark', name: '夸克网盘', host: /pan\.quark\.cn/i,
      parse: function (url, text) {
        var pwd = (url.match(/[?&]pwd=([a-z0-9]{4})/i) || [])[1] ||
                  (text.match(/(?:提取码|密码)[：:\s]*([a-z0-9]{4})/i) || [])[1] || '';
        return { pwd: pwd, needsLogin: true, resolver: false };
      }
    },
    {
      id: 'lanzou', name: '蓝奏云', host: /(lanzou[a-z]?\.com|lanzn\.com|lanzoui\.com|lanzoux\.com)/i,
      parse: function (url, text) {
        var pwd = (url.match(/[?&]pwd=([a-z0-9]{4})/i) || [])[1] ||
                  (text.match(/(?:提取码|密码)[：:\s]*([a-z0-9]{4})/i) || [])[1] || '';
        return { pwd: pwd, needsLogin: false, resolver: true };
      }
    },
    {
      id: '123pan', name: '123 云盘', host: /(123pan\.com|123684\.com|123865\.com)/i,
      parse: function (url, text) {
        var pwd = (url.match(/[?&]pwd=([a-z0-9]{4})/i) || [])[1] ||
                  (text.match(/(?:提取码|密码)[：:\s]*([a-z0-9]{4})/i) || [])[1] || '';
        return { pwd: pwd, needsLogin: true, resolver: false };
      }
    },
    {
      id: 'aliyun', name: '阿里云盘', host: /(aliyundrive\.com|alipan\.com)/i,
      parse: function (url, text) {
        var pwd = (url.match(/[?&]pwd=([a-z0-9]{4})/i) || [])[1] ||
                  (text.match(/(?:提取码|密码)[：:\s]*([a-z0-9]{4})/i) || [])[1] || '';
        return { pwd: pwd, needsLogin: true, resolver: false };
      }
    }
  ];

  function hostOf(u) { try { return new URL(u).hostname; } catch (e) { return ''; } }

  function isUrl(u) { return /^https?:\/\//i.test(String(u || '').trim()); }

  /* 从一段文本里挑出第一个链接（分享文案常见形式） */
  function pickUrl(text) {
    var m = String(text || '').match(/https?:\/\/[^\s"'<>）)]+/i);
    return m ? m[0] : '';
  }

  /* ---------------- 链接解析 ---------------- */
  function parseLink(input) {
    var text = String(input || '').trim();
    var url = isUrl(text) ? text : pickUrl(text);
    if (!url) return { ok: false, msg: '没有识别到链接，请粘贴 http(s) 地址或网盘分享文案' };

    var host = hostOf(url);
    var rule = NETDISK.filter(function (r) { return r.host.test(host); })[0];
    if (rule) {
      var info = rule.parse(url, text);
      return {
        ok: true,
        kind: 'netdisk',
        provider: rule.id,
        providerName: rule.name,
        url: url,
        host: host,
        pwd: info.pwd || '',
        needsLogin: !!info.needsLogin,
        canResolve: !!info.resolver,
        note: info.needsLogin
          ? '该网盘需要登录后才能获取真实下载地址，浏览器内无法绕过授权，请打开网盘页面保存到自己的空间再下载。'
          : '将尝试解析出直链；若页面结构变化或需要验证码，请手动打开页面。'
      };
    }

    // 非网盘链接一律按“待探测”的直链处理，由探测结果决定是文件还是网页
    var guess = '';
    try { guess = decodeURIComponent(new URL(url).pathname.split('/').pop() || ''); } catch (e) {}
    return { ok: true, kind: 'file', pending: true, url: url, host: host, name: guess };
  }

  /* ---------------- 探测 ---------------- */
  function filenameFrom(resp, url) {
    var cd = resp.headers.get('content-disposition') || '';
    var m = cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
    if (m) { try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; } }
    try { return decodeURIComponent(new URL(url).pathname.split('/').pop() || '') || 'download'; }
    catch (e) { return 'download'; }
  }

  function probe(url, timeout) {
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, timeout || 8000);
    var opts = { method: 'GET', headers: { Range: 'bytes=0-0' }, cache: 'no-store', credentials: 'omit' };
    if (ctrl) opts.signal = ctrl.signal;
    return fetch(url, opts).then(function (r) {
      clearTimeout(timer);
      if (!r.ok && r.status !== 206) throw new Error('HTTP ' + r.status);
      var cr = r.headers.get('content-range') || '';
      var total = 0;
      var m = cr.match(/bytes\s+\d+-\d+\/(\d+)/i);
      if (m) total = parseInt(m[1], 10) || 0;
      if (!total) total = parseInt(r.headers.get('content-length') || '0', 10) || 0;
      // 主动丢弃这一字节的响应体
      try { if (r.body && r.body.cancel) r.body.cancel(); } catch (e) {}
      return {
        ok: true,
        size: total,
        ranges: r.status === 206 || /bytes/i.test(r.headers.get('accept-ranges') || ''),
        type: r.headers.get('content-type') || '',
        name: filenameFrom(r, url)
      };
    }).catch(function (e) {
      clearTimeout(timer);
      return { ok: false, error: String(e && e.message || e) };
    });
  }

  /* ---------------- 多线程下载 ---------------- */
  function createTask(opts) {
    var url = opts.url;
    var concurrency = Math.max(1, Math.min(8, parseInt(opts.concurrency, 10) || 1));
    var chunkSize = Math.max(256 * 1024, (parseInt(opts.chunkMB, 10) || 4) * 1024 * 1024);
    var retry = Math.max(0, Math.min(6, parseInt(opts.retry, 10) || 0));
    var onProgress = opts.onProgress || function () {};

    var state = {
      url: url, total: 0, received: 0, mode: 'probe', status: 'idle',
      name: opts.name || '', startedAt: 0, chunks: [], controllers: [], error: ''
    };

    function emit() {
      var pct = state.total ? Math.min(100, (state.received / state.total) * 100) : 0;
      var secs = state.startedAt ? (Date.now() - state.startedAt) / 1000 : 0;
      var speed = secs > 0.3 ? state.received / secs : 0;
      onProgress({
        percent: pct, received: state.received, total: state.total,
        speed: speed, status: state.status, mode: state.mode, name: state.name,
        eta: speed > 0 && state.total ? Math.max(0, (state.total - state.received) / speed) : 0,
        chunks: state.chunks.map(function (c) { return c.received / (c.end - c.start + 1); }),
        error: state.error
      });
    }

    function abortAll() {
      state.controllers.forEach(function (c) { try { c.abort(); } catch (e) {} });
      state.controllers = [];
    }

    function readStream(resp, onBytes, ctrl) {
      if (!resp.body || !resp.body.getReader) {
        return resp.arrayBuffer().then(function (buf) {
          onBytes(new Uint8Array(buf));
          return new Uint8Array(buf);
        });
      }
      var reader = resp.body.getReader();
      var parts = [];
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) {
            var len = parts.reduce(function (n, p) { return n + p.length; }, 0);
            var out = new Uint8Array(len);
            var off = 0;
            parts.forEach(function (p) { out.set(p, off); off += p.length; });
            return out;
          }
          parts.push(r.value);
          onBytes(r.value);
          return pump();
        });
      }
      return pump();
    }

    function fetchRange(chunk) {
      var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      if (ctrl) state.controllers.push(ctrl);
      var headers = {};
      if (state.mode === 'multi') headers.Range = 'bytes=' + (chunk.start + chunk.received) + '-' + chunk.end;
      var init = { headers: headers, cache: 'no-store', credentials: 'omit' };
      if (ctrl) init.signal = ctrl.signal;

      return fetch(url, init).then(function (resp) {
        if (!resp.ok && resp.status !== 206) throw new Error('HTTP ' + resp.status);
        return readStream(resp, function (bytes) {
          chunk.received += bytes.length;
          state.received += bytes.length;
          emit();
        }, ctrl).then(function (buf) {
          chunk.data = buf;
          return chunk;
        });
      }).catch(function (err) {
        if (state.status === 'canceled' || state.status === 'paused') throw err;
        if (chunk.attempts < retry) {
          chunk.attempts++;
          return new Promise(function (r) { setTimeout(r, 400 * chunk.attempts); }).then(function () { return fetchRange(chunk); });
        }
        throw err;
      }).then(function (c) {
        try { if (ctrl) ctrl.abort(); } catch (e) {}
        return c;
      });
    }

    function assemble() {
      var total = state.chunks.reduce(function (n, c) { return n + (c.data ? c.data.length : 0); }, 0);
      var out = new Uint8Array(total);
      var off = 0;
      state.chunks.forEach(function (c) {
        if (c.data) { out.set(c.data, off); off += c.data.length; }
      });
      return new Blob([out], { type: 'application/octet-stream' });
    }

    function run() {
      state.status = 'probing';
      emit();
      return probe(url).then(function (info) {
        state.name = state.name || (info && info.name) || 'download';
        if (!info || !info.ok) {
          // 探测失败不放弃：交给浏览器直接下载
          throw new Error('无法读取文件信息（可能是跨域限制）：' + ((info && info.error) || 'unknown'));
        }
        state.total = info.size;
        var canMulti = info.ranges && info.size > chunkSize && concurrency > 1;
        state.mode = canMulti ? 'multi' : 'single';
        state.status = 'downloading';
        state.startedAt = Date.now();

        if (!canMulti) {
          var one = { start: 0, end: Math.max(0, info.size - 1), received: 0, attempts: 0, data: null };
          state.chunks = [one];
          return fetchRange(one).then(function () {
            if (!state.total && one.data) {
              state.total = one.data.length;
              state.received = one.data.length;
            }
            state.status = 'done';
            emit();
            return { blob: assemble(), mode: 'single', name: state.name, total: state.total };
          });
        }

        var list = [];
        for (var s = 0; s < info.size; s += chunkSize) {
          list.push({ start: s, end: Math.min(info.size - 1, s + chunkSize - 1), received: 0, attempts: 0, data: null });
        }
        state.chunks = list;

        var cursor = 0;
        function worker() {
          if (state.status === 'canceled') return Promise.resolve();
          var c = list[cursor++];
          if (!c) return Promise.resolve();
          return fetchRange(c).then(worker);
        }
        var workers = [];
        for (var i = 0; i < Math.min(concurrency, list.length); i++) workers.push(worker());
        return Promise.all(workers).then(function () {
          if (state.status === 'canceled') return null;
          state.status = 'done';
          emit();
          return { blob: assemble(), mode: 'multi', name: state.name, total: state.total };
        });
      }).catch(function (err) {
        if (state.status !== 'canceled') {
          state.status = 'error';
          state.error = String(err && err.message || err);
        }
        emit();
        throw err;
      });
    }

    return {
      state: state,
      start: run,
      pause: function () {
        if (state.status !== 'downloading' && state.status !== 'probing') return;
        state.status = 'paused';
        abortAll();
        emit();
      },
      resume: function () {
        if (state.status !== 'paused') return;
        state.status = 'downloading';
        // 断点续传：只补未完成的分片
        var pending = state.chunks.filter(function (c) { return !c.data; });
        var cursor = 0;
        function worker() {
          if (state.status === 'canceled') return Promise.resolve();
          var c = pending[cursor++];
          if (!c) return Promise.resolve();
          return fetchRange(c).then(worker);
        }
        var workers = [];
        for (var i = 0; i < Math.min(concurrency, pending.length); i++) workers.push(worker());
        return Promise.all(workers).then(function () {
          state.status = 'done';
          emit();
          return { blob: assemble(), mode: state.mode, name: state.name, total: state.total };
        });
      },
      cancel: function () {
        state.status = 'canceled';
        abortAll();
        emit();
      }
    };
  }

  window.NiaoDownloader = {
    parseLink: parseLink,
    probe: probe,
    createTask: createTask,
    providers: NETDISK.map(function (r) { return r.id; })
  };
})();
