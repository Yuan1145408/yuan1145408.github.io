/*!
 * mc-online.js — 网页版我的世界（Eaglercraft 嵌入播放器）
 *
 * 做三件事：
 *   1. 版本切换：不同版本对应不同的公开客户端地址，切换时重建 iframe；
 *   2. 载入状态：iframe 跨域，只能用 load 事件 + 超时判断「还在下载 / 已就绪 / 大概失败」；
 *   3. 播放入口：聚焦、全屏、重新载入、新窗口兜底。
 *
 * 不托管任何游戏资源，客户端由第三方公开部署提供。
 */
(function () {
  'use strict';

  // 版本清单：key 用于 URL（?v=），src 是公开客户端地址
  var VERSIONS = [
    {
      key: '1.8.8',
      name: '1.8.8',
      sub: '服务器最多',
      tag: '推荐',
      page: 'https://eaglercraft.playclassicgame.com/en/games/1.8.8.html',
      src: 'https://eaglercraft.playclassicgame.com/games/1.8.8/hicraft_1.8.8.html?v=20261030-03',
      note: 'PvP、小游戏、生存服基本都跑这个版本，性能最好。'
    },
    {
      key: '1.5.2',
      name: '1.5.2',
      sub: '最轻',
      page: 'https://eaglercraft.playclassicgame.com/en/games/1.5.2.html',
      src: 'https://eaglercraft.playclassicgame.com/games/1.5.2/hicraft_1.5.2.html?v=20261030-03',
      note: '老版本，加载最快，低配机器和手机更稳。'
    },
    {
      key: '26.3',
      name: '26.3',
      sub: '最新',
      page: 'https://eaglercraft.playclassicgame.com/en/games/26.3.html',
      src: 'https://eaglercraft.playclassicgame.com/games/26.3/hicraft_26.3.html?v=20261030-03',
      note: '最新构建，单人内容最全，能连的公开服务器较少。'
    },
    {
      key: '26.2',
      name: '26.2',
      sub: '稳定',
      page: 'https://eaglercraft.playclassicgame.com/en/games/26.2.html',
      src: 'https://eaglercraft.playclassicgame.com/games/26.2/hicraft_26.2.html?v=20261030-03',
      note: '26.x 系列里相对稳的一版，适合单人开荒。'
    }
  ];

  var LOAD_TIMEOUT = 90000; // 90s 还没 load 就当网络有问题，给兜底入口

  var $ = function (id) { return document.getElementById(id); };

  var frame = $('mcoFrame');
  var veil = $('mcoVeil');
  var veilTitle = $('mcoVeilTitle');
  var veilNote = $('mcoVeilNote');
  var startBtn = $('mcoStart');
  var veilNew = $('mcoVeilNew');
  var stateEl = $('mcoState');
  var versionsBox = $('mcoVersions');
  var openLink = $('mcoOpen');

  var current = VERSIONS[0];
  var timer = null;
  var loaded = false;

  function setState(text) {
    if (stateEl) stateEl.textContent = text;
  }

  // 舞台底部的一次性提示条
  var hintEl = null;
  var hintTimer = null;
  function hint(text) {
    var stage = $('mcoStage');
    if (!stage) return;
    if (!hintEl) {
      hintEl = document.createElement('div');
      hintEl.className = 'mco-hint';
      stage.appendChild(hintEl);
    }
    hintEl.textContent = text;
    hintEl.classList.add('is-on');
    clearTimeout(hintTimer);
    hintTimer = setTimeout(function () { hintEl.classList.remove('is-on'); }, 6000);
  }

  function showVeil(title, note, opts) {
    if (!veil) return;
    veil.hidden = false;
    veil.classList.toggle('is-ready', !!(opts && opts.ready));
    veilTitle.textContent = title;
    veilNote.innerHTML = note;
    startBtn.hidden = !(opts && opts.ready);
    var canFallback = !!(opts && (opts.failed || opts.ready));
    veilNew.hidden = !canFallback;
    veilNew.textContent = (opts && opts.failed) ? '新窗口打开' : '打不开？新窗口打开';
  }

  function renderVersions() {
    if (!versionsBox) return;
    versionsBox.innerHTML = VERSIONS.map(function (v) {
      return '<button class="mco-ver" type="button" role="tab" data-v="' + v.key + '"' +
        ' aria-selected="' + (v.key === current.key) + '">' +
        '<span>' + v.name + '</span><small>' + v.sub + '</small>' +
        (v.tag ? '<span class="mco-ver__tag">' + v.tag + '</span>' : '') +
        '</button>';
    }).join('');
  }

  function markActive() {
    if (!versionsBox) return;
    var btns = versionsBox.querySelectorAll('.mco-ver');
    for (var i = 0; i < btns.length; i++) {
      var on = btns[i].getAttribute('data-v') === current.key;
      btns[i].classList.toggle('is-on', on);
      btns[i].setAttribute('aria-selected', on ? 'true' : 'false');
    }
  }

  function syncUrl() {
    try {
      var u = new URL(window.location.href);
      u.searchParams.set('v', current.key);
      history.replaceState(null, '', u.toString());
    } catch (e) { /* 老浏览器忽略 */ }
  }

  function loadVersion(v, pushState) {
    current = v;
    loaded = false;
    markActive();
    if (pushState !== false) syncUrl();
    if (openLink) openLink.href = v.page;

    showVeil('正在载入 ' + v.name + ' 客户端…',
      '首次打开要下载约 4 MB 客户端代码，慢的时候 20–60 秒。<br />' +
      '载入完成后这里会变成「点我开始」。' + (v.note ? '<br /><span class="muted">' + v.note + '</span>' : ''),
      {});
    setState('载入中 · ' + v.name);

    // 立刻开始计时，避免 iframe 缓存直接命中时错过状态
    clearTimeout(timer);
    timer = setTimeout(function () {
      if (loaded) return;
      showVeil('还没载入完成',
        '已经等了 90 秒。可能是网络太慢，或者 WebAssembly 被网络策略拦住了。<br />' +
        '可以先「新窗口打开」确认客户端本身能跑，再回来重试。',
        { failed: true });
      setState('载入超时 · ' + v.name);
    }, LOAD_TIMEOUT);

    frame.src = v.src;
  }

  function onFrameLoad() {
    if (loaded) return;
    loaded = true;
    clearTimeout(timer);
    // 留一点时间让 Eaglercraft 自己进到 BIOS/主菜单界面
    setTimeout(function () {
      showVeil('客户端已就绪',
        '点一下下面的按钮把键盘交给游戏，然后按任意键（或回车）通过开机界面。',
        { ready: true });
      setState('已就绪 · 等你自己点开始');
    }, 600);
  }

  function begin() {
    veil.hidden = true;
    try { frame.focus(); } catch (e) { /* 忽略 */ }
    setState('游戏进行中 · 按 Esc 打开游戏菜单');
    hint('先按一下键盘（任意键）通过开机界面，再按 Esc 进游戏菜单');
    // 全屏的主动权在用户手势里，这里不自动全屏，避免被拦
  }

  function toggleFull() {
    var el = $('mcoStage');
    if (!el) return;
    var doc = document;
    if (doc.fullscreenElement || doc.webkitFullscreenElement) {
      (doc.exitFullscreen || doc.webkitExitFullscreen).call(doc);
      return;
    }
    var fn = el.requestFullscreen || el.webkitRequestFullscreen;
    if (fn) {
      var p = fn.call(el);
      if (p && p.catch) p.catch(function () { /* 用户拒绝或不支持 */ });
    }
  }

  function bind() {
    if (versionsBox) {
      versionsBox.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('.mco-ver') : null;
        if (!btn) return;
        var key = btn.getAttribute('data-v');
        var v = VERSIONS.filter(function (x) { return x.key === key; })[0];
        if (v && v.key !== current.key) loadVersion(v);
      });
    }

    if (frame) frame.addEventListener('load', onFrameLoad);
    if (startBtn) startBtn.addEventListener('click', begin);
    if (veilNew) {
      veilNew.addEventListener('click', function () {
        window.open(current.page, '_blank', 'noopener');
      });
    }

    var play = $('mcoPlay');
    if (play) {
      play.addEventListener('click', function () {
        if (!loaded) {
          showVeil('还在载入…', '客户端还没下载完，再等一会儿。等不及可以先「新窗口打开」。', {});
          return;
        }
        begin();
      });
    }

    var full = $('mcoFull');
    if (full) full.addEventListener('click', toggleFull);

    var reload = $('mcoReload');
    if (reload) {
      reload.addEventListener('click', function () {
        // 加时间戳强制绕过缓存，等于重新下一次
        var u = current.src + (current.src.indexOf('?') >= 0 ? '&' : '?') + '_r=' + Date.now();
        loaded = false;
        showVeil('正在重新载入 ' + current.name + '…', '重新下载客户端代码，大概需要 20–60 秒。', {});
        setState('重新载入 · ' + current.name);
        clearTimeout(timer);
        timer = setTimeout(function () {
          if (loaded) return;
          showVeil('重新载入仍然超时', '建议先「新窗口打开」验证网络，或换一个版本。', { failed: true });
          setState('载入超时 · ' + current.name);
        }, LOAD_TIMEOUT);
        frame.src = u;
      });
    }

    // 从 URL 读版本
    var want = null;
    try { want = new URL(window.location.href).searchParams.get('v'); } catch (e) { /* 忽略 */ }
    if (want) {
      var hit = VERSIONS.filter(function (x) { return x.key === want; })[0];
      if (hit) current = hit;
    }
  }

  function init() {
    renderVersions();
    bind();
    loadVersion(current, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
