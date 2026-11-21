/* ============================================================
   鸟国站 · 全站设置（localStorage 持久化）
   ------------------------------------------------------------
   任何页面都可以读写：
     NiaoSettings.get()              读取全部
     NiaoSettings.set({ ... })       合并保存（会派发 niao:settings 事件）
     NiaoSettings.get('download.concurrency')
     NiaoSettings.reset()
   设置项按「下载 / 安装 / 搜索」三组组织，键名与设置页表单一致。
   ============================================================ */
(function () {
  'use strict';

  var KEY = 'niao.settings.v1';

  var DEFAULTS = {
    // 下载
    'download.concurrency': 4,      // 并发分片数 1-8
    'download.chunkMB': 4,          // 单分片大小（MB）
    'download.retry': 2,            // 分片失败重试次数
    'download.autoStart': true,     // 解析成功后自动开始
    'download.saveMode': 'blob',    // blob=内存合并后保存 / stream=直接交给浏览器
    // 安装
    'install.mode': 'auto',         // auto=可下载则下载，否则新标签打开 / browser=交给浏览器 / open=新标签打开
    'install.checkFile': true,      // 安装前检查是否为可执行文件
    'install.remember': true,       // 记住上次选择的安装方式
    // 搜索
    'search.scope': 'all',          // 默认范围 all|site|web
    'search.pageSize': 10,          // 每页条数
    'search.proxy': true,           // 允许使用公共代理兜底
    'search.disabledSources': []    // 停用的源 id
  };

  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  function read() {
    var out = clone(DEFAULTS);
    try {
      var raw = localStorage.getItem(KEY);
      if (!raw) return out;
      var saved = JSON.parse(raw);
      if (!saved || typeof saved !== 'object') return out;
      Object.keys(DEFAULTS).forEach(function (k) {
        if (Object.prototype.hasOwnProperty.call(saved, k)) out[k] = saved[k];
      });
    } catch (e) {}
    return out;
  }

  var state = read();

  function get(key) {
    if (!key) return clone(state);
    return Object.prototype.hasOwnProperty.call(state, key) ? state[key] : undefined;
  }

  function set(patch) {
    if (!patch || typeof patch !== 'object') return get();
    Object.keys(patch).forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(DEFAULTS, k)) state[k] = patch[k];
    });
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
    try {
      window.dispatchEvent(new CustomEvent('niao:settings', { detail: clone(state) }));
    } catch (e) {}
    return clone(state);
  }

  function reset() {
    state = clone(DEFAULTS);
    try { localStorage.removeItem(KEY); } catch (e) {}
    try {
      window.dispatchEvent(new CustomEvent('niao:settings', { detail: clone(state) }));
    } catch (e) {}
    return clone(state);
  }

  function onChange(fn) {
    if (typeof fn !== 'function') return;
    window.addEventListener('niao:settings', function (e) { fn(e.detail); });
  }

  window.NiaoSettings = {
    DEFAULTS: clone(DEFAULTS),
    get: get,
    set: set,
    reset: reset,
    onChange: onChange,
    KEY: KEY
  };
})();
