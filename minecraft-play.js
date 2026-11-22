/* ============================================================
   我的世界网页版 · 直接开玩（本地实例）
   ------------------------------------------------------------
   - 浏览器不能执行本地程序，但可以向本机常驻服务发 HTTP 请求
   - 服务：niao-host.js 监听 http://127.0.0.1:8791（仅本机）
   - 本文件只负责：探测服务、启动/结束实例、显示模式、画面共享与窗口对齐
   - 没有服务时按钮保持禁用，并给出准确的启动命令，不假装成功
   ============================================================ */
(function () {
  'use strict';

  // 服务地址：默认 127.0.0.1:8791；可用 ?host=http://127.0.0.1:8792 临时切换并记住
  var BASE = (function () {
    var fallback = 'http://127.0.0.1:8791';
    try {
      var q = new URL(window.location.href).searchParams.get('host');
      if (q && /^https?:\/\//.test(q)) {
        // 只记当前标签页，避免一次手滑把地址永久改错
        sessionStorage.setItem('niao.mc.host', q);
        return q.replace(/\/+$/, '');
      }
      var saved = sessionStorage.getItem('niao.mc.host');
      if (saved) return saved.replace(/\/+$/, '');
    } catch (e) { /* 忽略 */ }
    return fallback;
  })();
  var DEFAULT_INSTANCE = '26';
  var LS_KEY = 'niao.mc.playInstance';

  var $ = function (id) { return document.getElementById(id); };
  var stage = $('mcwPlayStage');
  if (!stage) return; // 页面没有该区块时直接退出

  var video = $('mcwPlayVideo');
  var phTitle = $('mcwPlayPhTitle');
  var phNote = $('mcwPlayPhNote');
  var stateChip = $('mcwPlayState');
  var startBtn = $('mcwPlayStart');
  var stopBtn = $('mcwPlayStop');
  var shareBtn = $('mcwPlayShare');
  var fullBtn = $('mcwPlayFull');
  var instInput = $('mcwPlayInstance');
  var instList = $('mcwPlayInstanceList');
  var cmdBox = $('mcwPlayCmd');
  var logBox = $('mcwPlayLog');
  var localLink = $('mcwPlayLocal');
  if (localLink) localLink.href = BASE + '/play';

  var online = false;
  var running = false;
  var sharing = false;
  var displayMode = 'embedded';
  var probeTimer = 0;
  var statusTimer = 0;
  var logLines = [];

  function say(msg) {
    var t = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    logLines.push('[' + t + '] ' + msg);
    if (logLines.length > 60) logLines = logLines.slice(-60);
    logBox.textContent = logLines.join('\n');
    logBox.scrollTop = logBox.scrollHeight;
  }

  function instanceName() {
    var v = (instInput && instInput.value || '').trim();
    return v || DEFAULT_INSTANCE;
  }

  function paintCmd() {
    if (cmdBox) {
      cmdBox.textContent = 'node niao-host.js --instance ' + instanceName() + ' --root "D:\\"';
    }
  }

  /* ---------------- 请求封装 ---------------- */

  function api(path, opts, timeoutMs) {
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, timeoutMs || 6000);
    var o = Object.assign({ cache: 'no-store' }, opts || {});
    if (ctrl) o.signal = ctrl.signal;
    return fetch(BASE + path, o)
      .then(function (r) { return r.json(); })
      .then(function (j) { clearTimeout(timer); return j; })
      .catch(function (e) { clearTimeout(timer); throw e; });
  }

  /* ---------------- 状态 ---------------- */

  function setOnline(ok, info) {
    online = ok;
    if (stateChip) {
      stateChip.className = 'chip ' + (ok ? 'is-ok' : 'is-error');
      stateChip.textContent = ok ? '本地服务在线' : '未连上本机服务';
      stateChip.title = ok
        ? '已连上 ' + BASE + '（端口 ' + (info && info.port || 8791) + '）'
        : '两种可能：① niao-host.js 没启动；② 浏览器拦下了本地网络访问（可在地址栏提示里允许，或点「本机游玩页」）';
    }
    syncButtons();
    if (!ok) {
      running = false;
      stopSharing();
      phTitle.textContent = '本地服务未运行';
      phNote.textContent = '服务没启动，或浏览器拦下了「本地网络访问」——可点「本机游玩页」直接在本机打开';
      say('未连上 ' + BASE + '（服务未启动，或被浏览器拦下本地网络访问）');
    }
  }

  function syncButtons() {
    if (startBtn) startBtn.disabled = !online || running;
    if (stopBtn) stopBtn.disabled = !online || !running;
    if (shareBtn) shareBtn.disabled = !online || !running;
  }

  function probe(silent) {
    return api('/health', null, 1800)
      .then(function (j) {
        var ok = !!(j && j.ok);
        var was = online;
        setOnline(ok, j);
        if (ok && !was && !silent) say('本地服务已连接（' + (j.instancesRoot || '实例根目录未提供') + '）');
        if (ok) {
          loadInstances();
          loadSettings();
          refreshStatus();
        }
        return ok;
      })
      .catch(function () {
        setOnline(false);
        return false;
      });
  }

  function loadInstances() {
    api('/instances', null, 4000).then(function (res) {
      var items = (res && res.items) || [];
      if (!instList) return;
      instList.innerHTML = items.map(function (it) {
        return '<option value="' + String(it.id).replace(/"/g, '&quot;') + '"></option>';
      }).join('');
      var saved = instInput && instInput.value.trim();
      if (!saved && res && res.defaultInstance) instInput.value = res.defaultInstance;
      if (items.length) say('发现 ' + items.length + ' 个实例：' + items.map(function (x) { return x.id; }).join(', '));
    }).catch(function () { /* 无实例列表不影响主流程 */ });
  }

  function loadSettings() {
    api('/settings', null, 4000).then(function (res) {
      if (res && res.ok && res.display) paintMode(res.display, true);
    }).catch(function () { });
  }

  function paintMode(mode, silent) {
    displayMode = mode === 'desktop' ? 'desktop' : 'embedded';
    var radios = document.querySelectorAll('input[name="mcwPlayDisplay"]');
    for (var i = 0; i < radios.length; i++) {
      radios[i].checked = radios[i].value === displayMode;
    }
    if (!silent) {
      api('/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display: displayMode })
      }, 4000).then(function (res) {
        if (res && res.ok) {
          say('显示模式：' + (displayMode === 'embedded' ? '浏览器内嵌' : '桌面独立窗口') +
            (running ? '（下次启动生效）' : ''));
        } else {
          say('保存显示模式失败：' + ((res && res.message) || '未知原因'));
        }
      }).catch(function (e) {
        say('保存显示模式失败：' + (e && e.message || e));
      });
    }
  }

  function refreshStatus() {
    if (!online) return;
    api('/status', null, 4000).then(function (res) {
      var list = (res && res.running) || [];
      var id = instanceName();
      var mine = list.filter(function (x) { return String(x.instance) === id; })[0];
      var changed = running !== !!mine;
      running = !!mine;
      syncButtons();
      if (running) {
        phTitle.textContent = '游戏运行中';
        if (displayMode === 'embedded') {
          phNote.textContent = sharing ? '已接入画面，点小窗即可操作' : '点「在浏览器中显示画面」把它框进这里';
          if (fullBtn) fullBtn.hidden = !sharing;
        } else {
          phNote.textContent = '已在桌面窗口运行，可自由拖动缩放';
          if (fullBtn) fullBtn.hidden = true;
        }
      } else {
        phTitle.textContent = '游戏尚未启动';
        phNote.textContent = online ? '点「启动游戏」拉起实例 ' + id : '先在本机启动服务，再点「启动游戏」';
        stopSharing();
      }
      if (changed) say('实例 ' + id + (running ? ' 正在运行' : ' 已停止'));
    }).catch(function () { });
  }

  /* ---------------- 启动 / 结束 ---------------- */

  function startGame() {
    if (!online) { say('本地服务未运行，先执行命令再试'); return; }
    var id = instanceName();
    startBtn.disabled = true;
    say('正在启动实例 ' + id + '…');
    phTitle.textContent = '正在启动…';
    phNote.textContent = '首次启动会准备客户端资源，慢的话等一分钟';
    api('/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instance: id, display: displayMode })
    }, 30000).then(function (res) {
      if (res && res.ok) {
        running = true;
        say('已启动（进程 ' + (res.pid || '?') + '，模式：' + (res.display === 'desktop' ? '桌面窗口' : '浏览器内嵌') + '）');
        if (res.display === 'desktop') {
          phTitle.textContent = '游戏已在桌面窗口运行';
          phNote.textContent = '想嵌回页面就切到「浏览器内嵌」再重新启动';
        } else {
          phTitle.textContent = '游戏运行中';
          phNote.textContent = '点「在浏览器中显示画面」，选中 Minecraft 窗口即可';
        }
        syncButtons();
        refreshStatus();
      } else {
        say('启动失败：' + ((res && res.message) || '未知原因'));
        startBtn.disabled = false;
        phTitle.textContent = '启动失败';
        phNote.textContent = (res && res.message) || '看下方日志定位原因';
      }
    }).catch(function (e) {
      say('启动请求失败：' + (e && e.message || e));
      startBtn.disabled = false;
      phTitle.textContent = '启动请求失败';
      phNote.textContent = '检查本地服务是否还在运行';
    });
  }

  function stopGame() {
    var id = instanceName();
    say('结束实例 ' + id + '…');
    api('/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instance: id })
    }, 8000).then(function (res) {
      if (res && res.ok) { say('已结束'); }
      else { say('结束失败：' + ((res && res.message) || '未知原因')); }
      running = false;
      stopSharing();
      syncButtons();
      if (phTitle) phTitle.textContent = '游戏尚未启动';
      if (phNote) phNote.textContent = '点「启动游戏」再开一局';
    }).catch(function (e) {
      say('结束请求失败：' + (e && e.message || e));
    });
  }

  /* ---------------- 画面共享 ---------------- */

  function stopSharing() {
    sharing = false;
    if (video && video.srcObject) {
      video.srcObject.getTracks().forEach(function (t) { try { t.stop(); } catch (e) { } });
      video.srcObject = null;
    }
    if (stage) stage.classList.remove('is-live');
    if (shareBtn) shareBtn.textContent = '在浏览器中显示画面';
    if (fullBtn) fullBtn.hidden = true;
  }

  function alignWindow() {
    if (!stage || !sharing) return;
    var r = stage.getBoundingClientRect();
    api('/window/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance: instanceName(),
        x: Math.round(r.left), y: Math.round(r.top),
        w: Math.round(r.width), h: Math.round(r.height)
      })
    }, 5000).then(function (res) {
      if (res && res.ok) { /* 对齐成功不刷日志，避免噪音 */ }
      else { say('窗口对齐失败：' + ((res && res.message) || '未知原因')); }
    }).catch(function () { });
  }

  function startShare() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      say('当前浏览器不支持画面共享，请改用桌面窗口模式');
      return;
    }
    navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 60 } }, audio: false })
      .then(function (stream) {
        sharing = true;
        video.srcObject = stream;
        stage.classList.add('is-live');
        shareBtn.textContent = '停止共享画面';
        if (fullBtn) fullBtn.hidden = false;
        stream.getVideoTracks()[0].addEventListener('ended', function () {
          stopSharing();
          say('画面共享已停止');
        });
        say('画面已接入：点小窗接管鼠标，键盘需先点一下窗口获取焦点');
        alignWindow();
      })
      .catch(function (e) {
        say('没有选择窗口：' + (e && e.message || e) + '（请在弹窗里选 Minecraft 窗口）');
      });
  }

  /* ---------------- 事件 ---------------- */

  var probeBtn = $('mcwPlayProbe');
  if (probeBtn) {
    probeBtn.addEventListener('click', function () {
      probeBtn.disabled = true;
      say('手动检测本地服务…');
      probe().then(function (ok) {
        say(ok ? '检测完成：服务在线' : '检测完成：仍未连上 ' + BASE);
        probeBtn.disabled = false;
      });
    });
  }

  if (startBtn) startBtn.addEventListener('click', startGame);
  if (stopBtn) stopBtn.addEventListener('click', stopGame);
  if (shareBtn) {
    shareBtn.addEventListener('click', function () {
      if (sharing) { stopSharing(); say('已停止共享，游戏窗口恢复可见'); }
      else startShare();
    });
  }
  if (fullBtn) {
    fullBtn.addEventListener('click', function () {
      if (document.fullscreenElement) document.exitFullscreen();
      else if (stage.requestFullscreen) stage.requestFullscreen();
    });
    document.addEventListener('fullscreenchange', function () {
      setTimeout(alignWindow, 300);
    });
  }
  window.addEventListener('resize', function () {
    if (sharing) setTimeout(alignWindow, 250);
  });
  window.addEventListener('pagehide', stopSharing);

  if (instInput) {
    try {
      var saved = localStorage.getItem(LS_KEY);
      if (saved) instInput.value = saved;
    } catch (e) { /* 忽略 */ }
    instInput.addEventListener('input', function () {
      paintCmd();
      try { localStorage.setItem(LS_KEY, instInput.value); } catch (e) { }
      if (online) refreshStatus();
    });
  }

  var radios = document.querySelectorAll('input[name="mcwPlayDisplay"]');
  for (var i = 0; i < radios.length; i++) {
    radios[i].addEventListener('change', function () {
      if (this.checked) paintMode(this.value);
    });
  }

  /* ---------------- 启动 ---------------- */

  paintCmd();
  say('准备就绪，正在检测本地服务…');
  probe().then(function (ok) {
    if (!ok) {
      phTitle.textContent = '未连上本机服务';
      phNote.textContent = '先运行下方命令；如果服务已经在跑，说明浏览器拦下了本地网络访问，点「本机游玩页」即可绕过';
    }
    // 在线时每 3s 刷新运行状态；离线时每 6s 重新探测
    statusTimer = setInterval(function () {
      if (online) refreshStatus();
    }, 3000);
    probeTimer = setInterval(function () {
      if (!online) probe(true);
    }, 6000);
  });
})();
