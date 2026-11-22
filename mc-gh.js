/* ============================================================
   鸟国网站 · GitHub 实例存储客户端
   ------------------------------------------------------------
   只做与 GitHub REST / Git Data API 的交互：
   - PAT 校验、仓库权限校验
   - blob / tree / commit / ref 读写
   - git blob SHA 计算（用于和大仓库存量内容做零请求去重）
   - 大文件分块上传（GitHub 单文件硬上限 100MB）
   - 限流、超时、指数退避重试、错误分类
   不涉及本地文件系统，也不涉及界面。
   ============================================================ */
(function (global) {
  'use strict';

  var API = 'https://api.github.com';
  var RAW = 'https://raw.githubusercontent.com';
  var UA = 'niao-mc-instance/1';
  var CHUNK_SIZE = 16 * 1024 * 1024;   // 单块 16MB（base64 后约 21MB，留足余量）
  var HARD_FILE_LIMIT = 100 * 1024 * 1024;

  /* ---------------- 错误 ---------------- */
  function GhError(code, message, meta) {
    this.name = 'GhError';
    this.code = code;
    this.message = message;
    this.meta = meta || {};
    this.retryable = !!this.meta.retryable;
  }
  GhError.prototype = Object.create(Error.prototype);
  GhError.prototype.constructor = GhError;

  var CODE_HINT = {
    E_AUTH: '令牌无效或已过期。请重新生成 GitHub 细粒度令牌（仅勾选目标仓库的 Contents: Read and write）。',
    E_SCOPE: '令牌没有该仓库的写入权限。请确认令牌已授权此仓库，且 Contents 权限为读写。',
    E_NOT_FOUND: '仓库或分支不存在。请检查所有者 / 仓库名 / 分支名，或先在 GitHub 上创建一次提交。',
    E_RATELIMIT: '触发了 GitHub 接口限流。等待重置时间后重试，或换用访问频率更低的令牌。',
    E_NET: '网络请求失败。请检查网络或代理后重试。',
    E_TIMEOUT: '请求超时。网络较慢或文件较大时可以调大超时再试。',
    E_TOO_LARGE: '文件超过 GitHub 单文件上限（100MB）。请把该文件移出实例目录，或改用其他存储。',
    E_REPO_LIMIT: '实例体积超出仓库建议容量。请精简实例（例如排除 libraries/assets/versions）。',
    E_CONFLICT: '仓库在你上传期间被其他提交更新，已自动重试仍失败。请刷新后重新上传。',
    E_FORBIDDEN: 'GitHub 拒绝了本次操作（403）。可能是令牌权限不足，或该仓库启用了分支保护。',
    E_QUOTA: '浏览器本地存储配额不足。请清理本站缓存后重试。',
    E_FS_DENIED: '没有获得目录写入权限。请在弹窗中允许本站读写该文件夹。',
    E_FS_LOCKED: '目标文件被占用（游戏可能正在运行）。请先退出游戏/启动器再同步。',
    E_HASH: '文件校验不一致（下载内容与清单不符）。已自动重试一次。',
    E_SCHEMA: '实例清单格式不受支持。请使用本页上传的实例，或升级清单版本。',
    E_ABORT: '操作已取消。',
    E_UNKNOWN: '未知错误。请展开详情查看原始信息。'
  };

  function hintFor(code) { return CODE_HINT[code] || CODE_HINT.E_UNKNOWN; }

  function mapHttpError(res, body) {
    var code, retryable = false, reset = null;
    var remain = res.headers.get('x-ratelimit-remaining');
    var rlReset = res.headers.get('x-ratelimit-reset');
    if (res.status === 401) code = 'E_AUTH';
    else if (res.status === 403) {
      if (remain === '0') { code = 'E_RATELIMIT'; retryable = true; reset = rlReset ? parseInt(rlReset, 10) * 1000 : null; }
      else code = 'E_SCOPE';
    } else if (res.status === 404) code = 'E_NOT_FOUND';
    else if (res.status === 409 || res.status === 422) { code = 'E_CONFLICT'; retryable = true; }
    else if (res.status === 413) code = 'E_TOO_LARGE';
    else if (res.status === 429) { code = 'E_RATELIMIT'; retryable = true; reset = rlReset ? parseInt(rlReset, 10) * 1000 : null; }
    else if (res.status >= 500) { code = 'E_NET'; retryable = true; }
    else code = 'E_FORBIDDEN';
    var msg = (body && body.message) || res.statusText || ('HTTP ' + res.status);
    return new GhError(code, 'GitHub 返回 HTTP ' + res.status + '：' + msg, {
      status: res.status, retryable: retryable, resetAt: reset, body: body, hint: hintFor(code)
    });
  }

  /* ---------------- 基础工具 ---------------- */
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function hex(buf) {
    var b = new Uint8Array(buf), out = '';
    for (var i = 0; i < b.length; i++) out += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return out;
  }

  function utf8(s) { return new TextEncoder().encode(s); }

  // Git 的 blob 标识：sha1("blob " + 长度 + "\0" + 内容)
  // 与仓库中已有 blob 的 sha 可直接比对，实现“未改动文件零请求跳过”
  async function gitBlobSha(bytes) {
    var head = utf8('blob ' + bytes.length + '\u0000');
    var all = new Uint8Array(head.length + bytes.length);
    all.set(head, 0); all.set(bytes, head.length);
    return hex(await crypto.subtle.digest('SHA-1', all));
  }

  async function sha256(bytes) {
    return hex(await crypto.subtle.digest('SHA-256', bytes));
  }

  function toBase64(bytes) {
    var out = '';
    var CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return btoa(out);
  }

  /* ---------------- 请求层 ---------------- */
  async function request(path, opts) {
    opts = opts || {};
    var token = opts.token || '';
    var url = /^https?:/.test(path) ? path : API + path;
    var headers = Object.assign({
      'Accept': opts.accept || 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    }, opts.headers || {});
    if (token) headers['Authorization'] = 'Bearer ' + token;

    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, opts.timeout || 60000);
    if (opts.signal) {
      if (opts.signal.aborted) ctrl.abort();
      else opts.signal.addEventListener('abort', function () { ctrl.abort(); }, { once: true });
    }

    var res;
    try {
      res = await fetch(url, {
        method: opts.method || 'GET',
        headers: headers,
        body: opts.body,
        signal: ctrl.signal,
        cache: 'no-store'
      });
    } catch (e) {
      clearTimeout(timer);
      if (e && e.name === 'AbortError') {
        if (opts.signal && opts.signal.aborted) throw new GhError('E_ABORT', '操作已取消');
        throw new GhError('E_TIMEOUT', '请求超时（' + Math.round((opts.timeout || 60000) / 1000) + ' 秒）', { retryable: true });
      }
      throw new GhError('E_NET', '网络请求失败：' + (e && e.message), { retryable: true });
    }
    clearTimeout(timer);

    if (!res.ok) {
      var body = null;
      try { body = await res.json(); } catch (_) { /* 非 JSON 响应 */ }
      throw mapHttpError(res, body);
    }
    if (opts.raw) return res;
    if (res.status === 204) return null;
    var text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  // 指数退避：仅对可重试错误生效；限流则等到 reset
  async function withRetry(fn, opt) {
    opt = opt || {};
    var retries = opt.retries == null ? 3 : opt.retries;
    var attempt = 0;
    for (;;) {
      try {
        return await fn(attempt);
      } catch (e) {
        var isGh = e instanceof GhError;
        var canRetry = isGh ? e.retryable : false;
        if (!canRetry || attempt >= retries) throw e;
        var wait;
        if (isGh && e.code === 'E_RATELIMIT' && e.meta.resetAt) {
          wait = Math.max(1000, Math.min(e.meta.resetAt - Date.now() + 1500, 60000));
        } else {
          wait = Math.min(8000, 500 * Math.pow(2, attempt)) + Math.random() * 300;
        }
        attempt++;
        if (opt.onRetry) opt.onRetry(attempt, e, wait);
        await sleep(wait);
      }
    }
  }

  /* ---------------- 高层 API ---------------- */
  async function getUser(token) {
    return withRetry(function () { return request('/user', { token: token, timeout: 20000 }); }, { retries: 1 });
  }

  async function getRepo(token, owner, repo) {
    return withRetry(function () {
      return request('/repos/' + owner + '/' + repo, { token: token, timeout: 20000 });
    }, { retries: 1 });
  }

  async function getRef(token, owner, repo, branch) {
    try {
      var d = await withRetry(function () {
        return request('/repos/' + owner + '/' + repo + '/git/ref/heads/' + encodeURIComponent(branch), { token: token });
      }, { retries: 2 });
      return { commitSha: d.object.sha, exists: true };
    } catch (e) {
      if (e.code === 'E_NOT_FOUND') return { commitSha: null, exists: false };
      throw e;
    }
  }

  async function getCommit(token, owner, repo, sha) {
    return withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/commits/' + sha, { token: token });
    }, { retries: 2 });
  }

  async function getTree(token, owner, repo, sha) {
    var d = await withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/trees/' + sha + '?recursive=1', { token: token, timeout: 90000 });
    }, { retries: 2 });
    return d.tree || [];
  }

  async function createBlob(token, owner, repo, bytes, signal) {
    if (bytes.length > HARD_FILE_LIMIT) {
      throw new GhError('E_TOO_LARGE', '文件 ' + bytes.length + ' 字节，超过 GitHub 100MB 上限');
    }
    var body = JSON.stringify({ content: toBase64(bytes), encoding: 'base64' });
    var d = await withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/blobs', {
        token: token, method: 'POST', body: body, signal: signal, timeout: 300000
      });
    }, { retries: 2 });
    return d.sha;
  }

  async function createTree(token, owner, repo, entries, baseTree) {
    var body = JSON.stringify({ tree: entries, base_tree: baseTree || undefined });
    var d = await withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/trees', {
        token: token, method: 'POST', body: body, timeout: 120000
      });
    }, { retries: 2 });
    return d.sha;
  }

  async function createCommit(token, owner, repo, message, treeSha, parents) {
    var body = JSON.stringify({ message: message, tree: treeSha, parents: parents || [] });
    var d = await withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/commits', {
        token: token, method: 'POST', body: body, timeout: 60000
      });
    }, { retries: 2 });
    return d.sha;
  }

  async function updateRef(token, owner, repo, branch, commitSha, force) {
    return withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/refs/heads/' + encodeURIComponent(branch), {
        token: token, method: 'PATCH', body: JSON.stringify({ sha: commitSha, force: !!force })
      });
    }, { retries: 0 });
  }

  async function createRef(token, owner, repo, branch, commitSha) {
    return withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/git/refs', {
        token: token, method: 'POST', body: JSON.stringify({ ref: 'refs/heads/' + branch, sha: commitSha })
      });
    }, { retries: 0 });
  }

  async function getContentJson(token, owner, repo, path, ref) {
    var d = await withRetry(function () {
      return request('/repos/' + owner + '/' + repo + '/contents/' + encodeURI(path) + '?ref=' + encodeURIComponent(ref || 'HEAD'), {
        token: token, headers: { 'Accept': 'application/vnd.github.raw+json' }
      });
    }, { retries: 2 });
    return d;
  }

  async function listDir(token, owner, repo, path, ref) {
    try {
      var d = await withRetry(function () {
        return request('/repos/' + owner + '/' + repo + '/contents/' + encodeURI(path) + '?ref=' + encodeURIComponent(ref || 'HEAD'), { token: token });
      }, { retries: 2 });
      return Array.isArray(d) ? d : [];
    } catch (e) {
      if (e.code === 'E_NOT_FOUND') return [];
      throw e;
    }
  }

  // 提交历史：用于“云端更新了什么”提示
  async function listCommits(token, owner, repo, path, perPage) {
    try {
      return await withRetry(function () {
        return request('/repos/' + owner + '/' + repo + '/commits?path=' + encodeURI(path) +
          '&per_page=' + (perPage || 5), { token: token });
      }, { retries: 1 });
    } catch (e) { return []; }
  }

  /* ---------------- 发布实例（核心） ---------------- */
  /**
   * entries: [{ path, bytes, size, gitSha, chunked, parts:[{path,bytes,size,gitSha}] }]
   *   - path 为仓库内相对路径（可含子目录）
   *   - chunked 为 true 时用 parts 逐块上传（每块已是独立路径）
   * manifestJson: 实例清单对象（会写入 <root>/<id>/instance.json）
   * 返回 { commitSha, uploaded, reused, deleted, bytesSent }
   */
  async function publish(opts) {
    var token = opts.token, owner = opts.owner, repo = opts.repo, branch = opts.branch;
    var root = (opts.root || '.mc-instances').replace(/^\/+|\/+$/g, '');
    var id = opts.id;
    var entries = opts.entries || [];
    var deletedPaths = opts.deletedPaths || [];
    var onProgress = opts.onProgress || function () {};
    var signal = opts.signal;

    var maxAttempts = 2;
    var lastErr = null;

    for (var attempt = 0; attempt < maxAttempts; attempt++) {
      var head = await getRef(token, owner, repo, branch);
      if (!head.exists && !opts.initEmptyRepo) {
        throw new GhError('E_NOT_FOUND', '分支 ' + branch + ' 不存在。请先初始化仓库（创建 README 提交），或勾选“仓库为空时初始化”。', {
          hint: '也可以在 GitHub 网页上手动创建分支后重试。'
        });
      }

      var treeSha = null, treeEntries = [];
      if (head.exists) {
        var commit = await getCommit(token, owner, repo, head.commitSha);
        treeSha = commit.tree.sha;
        treeEntries = await getTree(token, owner, repo, treeSha);
      }

      // 仓库内已有 path → blob sha 映射（只关心本实例子树）
      var prefix = root + '/' + id + '/';
      var existing = {};
      treeEntries.forEach(function (e) {
        if (e.type === 'blob' && e.path.indexOf(prefix) === 0) existing[e.path] = e.sha;
      });

      var uploaded = 0, reused = 0, bytesSent = 0;
      var newEntries = [];

      for (var i = 0; i < entries.length; i++) {
        if (signal && signal.aborted) throw new GhError('E_ABORT', '操作已取消');
        var ent = entries[i];
        var repoPath = prefix + ent.path;
        onProgress({ phase: 'upload', index: i, total: entries.length, path: ent.path, size: ent.size });

        if (ent.chunked) {
          var allBytes = ent.bytes;
          if (!allBytes && ent.file) allBytes = new Uint8Array(await ent.file.arrayBuffer());
          if (!allBytes) throw new GhError('E_UNKNOWN', '缺少文件内容：' + ent.path);
          var cs = ent.chunkSize || CHUNK_SIZE;
          var slug = 'parts/' + ent.path.replace(/[^\w.\-\/]/g, '_') + '.part';
          var partEntries = [];
          var partNo = 0;
          for (var off = 0; off < allBytes.length; off += cs) {
            if (signal && signal.aborted) throw new GhError('E_ABORT', '操作已取消');
            var slice = allBytes.subarray(off, Math.min(off + cs, allBytes.length));
            var partRepoPath = prefix + slug + String(partNo).padStart(3, '0');
            var sliceGit = await gitBlobSha(slice);
            var partSha = existing[partRepoPath];
            if (partSha && partSha === sliceGit) {
              reused++;
            } else {
              partSha = await createBlob(token, owner, repo, slice, signal);
              uploaded++; bytesSent += slice.length;
            }
            partEntries.push({ path: partRepoPath, mode: '100644', type: 'blob', sha: partSha });
            partNo++;
            onProgress({
              phase: 'upload', index: i, total: entries.length, path: ent.path, size: ent.size,
              ratio: (i + partNo / Math.ceil(allBytes.length / cs)) / entries.length
            });
          }
          newEntries = newEntries.concat(partEntries);
          continue;
        }

        var sha = existing[repoPath];
        if (sha && sha === ent.gitSha) {
          reused++;
        } else {
          var fbytes = ent.bytes || (ent.file ? new Uint8Array(await ent.file.arrayBuffer()) : null);
          if (!fbytes) throw new GhError('E_UNKNOWN', '缺少文件内容：' + ent.path);
          sha = await createBlob(token, owner, repo, fbytes, signal);
          uploaded++; bytesSent += fbytes.length;
        }
        newEntries.push({ path: repoPath, mode: '100644', type: 'blob', sha: sha });
      }

      // 清单文件
      var manifestBytes = utf8(JSON.stringify(opts.manifestJson, null, 2));
      var manifestPath = prefix + 'instance.json';
      var mSha = existing[manifestPath];
      var mGitSha = await gitBlobSha(manifestBytes);
      if (!mSha || mSha !== mGitSha) {
        mSha = await createBlob(token, owner, repo, manifestBytes, signal);
        uploaded++;
      } else {
        reused++;
      }
      newEntries.push({ path: manifestPath, mode: '100644', type: 'blob', sha: mSha });

      // 删除项：base_tree 下必须显式给出 sha:null 才会删
      deletedPaths.forEach(function (dp) {
        newEntries.push({ path: prefix + dp, mode: '100644', type: 'blob', sha: null });
      });

      var newTree = await createTree(token, owner, repo, newEntries, treeSha);
      var message = opts.message || ('更新实例：' + id + '（' + (opts.versionLabel || '未知版本') + '）');
      var newCommit = await createCommit(token, owner, repo, message, newTree, head.exists ? [head.commitSha] : []);

      try {
        if (head.exists) await updateRef(token, owner, repo, branch, newCommit, false);
        else await createRef(token, owner, repo, branch, newCommit);
        return {
          commitSha: newCommit, uploaded: uploaded, reused: reused,
          deleted: deletedPaths.length, bytesSent: bytesSent, retried: attempt
        };
      } catch (e) {
        lastErr = e;
        if (e.code === 'E_CONFLICT' && attempt < maxAttempts - 1) {
          onProgress({ phase: 'retry', reason: '分支已被更新，重新比对后重试' });
          continue; // 重新取 head 再走一遍
        }
        throw e;
      }
    }
    throw lastErr || new GhError('E_CONFLICT', '提交冲突，重试后仍失败');
  }

  /* ---------------- 下载 ---------------- */
  function rawUrl(owner, repo, commitSha, path) {
    return RAW + '/' + owner + '/' + repo + '/' + commitSha + '/' + path.split('/').map(encodeURIComponent).join('/');
  }

  async function downloadBytes(url, opts) {
    opts = opts || {};
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, opts.timeout || 180000);
    var res;
    try {
      res = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
    } catch (e) {
      clearTimeout(timer);
      throw new GhError('E_NET', '下载失败：' + (e && e.message), { retryable: true, url: url });
    }
    clearTimeout(timer);
    if (!res.ok) throw new GhError(res.status === 404 ? 'E_NOT_FOUND' : 'E_NET', '下载返回 HTTP ' + res.status, { retryable: res.status >= 500 });

    var total = parseInt(res.headers.get('content-length') || '0', 10);
    if (!res.body || !res.body.getReader) return new Uint8Array(await res.arrayBuffer());

    var reader = res.body.getReader();
    var chunks = [], received = 0;
    for (;;) {
      var step = await reader.read();
      if (step.done) break;
      chunks.push(step.value);
      received += step.value.length;
      if (opts.onProgress) opts.onProgress(received, total);
    }
    var out = new Uint8Array(received), off = 0;
    chunks.forEach(function (c) { out.set(c, off); off += c.length; });
    return out;
  }

  global.McGh = {
    API: API, CHUNK_SIZE: CHUNK_SIZE, HARD_FILE_LIMIT: HARD_FILE_LIMIT,
    GhError: GhError, hintFor: hintFor,
    gitBlobSha: gitBlobSha, sha256: sha256, toBase64: toBase64, utf8: utf8,
    request: request, withRetry: withRetry,
    getUser: getUser, getRepo: getRepo, getRef: getRef, getCommit: getCommit,
    getTree: getTree, createBlob: createBlob, createTree: createTree,
    createCommit: createCommit, updateRef: updateRef, createRef: createRef,
    getContentJson: getContentJson, listDir: listDir, listCommits: listCommits,
    publish: publish, rawUrl: rawUrl, downloadBytes: downloadBytes
  };
})(window);
