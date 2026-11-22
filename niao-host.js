#!/usr/bin/env node
/**
 * 鸟国 · 我的世界 本地常驻服务（niao-mc host）
 * ------------------------------------------------------------
 * 浏览器不能执行本地程序，但可以发 HTTP 请求。
 * 本服务常驻 127.0.0.1，页面只负责「发请求」，由本进程启动客户端，
 * 体验等同网页游戏：点按钮 → 游戏起来。
 *
 * 用法：
 *   node niao-host.js                     # 默认端口 8791、实例 26
 *   node niao-host.js --port 8791 --instance 26
 *   node niao-host.js --install           # 注册开机自启（Windows）
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// 显示模式：desktop = 独立游戏窗口；embedded = 渲染进浏览器页面里的小窗口（默认）
const DISPLAY_MODES = ['embedded', 'desktop'];

function parseArgs(argv) {
  const out = {
    port: 8791, instance: '26', root: path.join(__dirname, 'instances'),
    install: false, uninstall: false, display: null
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port') out.port = parseInt(argv[++i], 10) || 8791;
    else if (a === '--instance') out.instance = argv[++i] || '26';
    else if (a === '--root') out.root = argv[++i] || out.root;
    else if (a === '--display') out.display = argv[++i] || null;
    else if (a === '--install') out.install = true;
    else if (a === '--uninstall') out.uninstall = true;
  }
  return out;
}

const cfg = parseArgs(process.argv);
const LOG = path.join(__dirname, 'niao-host.log');
const SETTINGS_FILE = path.join(__dirname, 'niao-host.settings.json');

/** 用户设置（持久化到 niao-host.settings.json） */
const settings = { display: 'embedded' };
(function loadSettings() {
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    if (raw && DISPLAY_MODES.indexOf(raw.display) >= 0) settings.display = raw.display;
  } catch (e) { /* 首次运行，用默认值 */ }
  if (cfg.display && DISPLAY_MODES.indexOf(cfg.display) >= 0) settings.display = cfg.display;
})();

function saveSettings() {
  try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8'); } catch (e) { }
}

function log(msg) {
  const line = '[' + new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '] ' + msg;
  console.log(line);
  try { fs.appendFileSync(LOG, line + '\n', 'utf8'); } catch (e) { /* 忽略 */ }
}

function instanceDir(id) {
  const safe = String(id || cfg.instance).replace(/[^A-Za-z0-9_.-]/g, '') || String(cfg.instance);
  return path.join(cfg.root, safe);
}

const JAVA_FLAGS = ['-XX:+UseG1GC', '-XX:MaxGCPauseMillis=50'];

/** 正在运行的实例：id -> {pid, startedAt, log, display} */
const running = new Map();

/**
 * 窗口控制：Windows 下用 P/Invoke 找游戏窗口并改成无边框子窗口，
 * 让页面可以把它「框」进浏览器里播放。其他平台退回桌面窗口。
 */
function win32(script) {
  if (process.platform !== 'win32') return Promise.resolve({ ok: false, code: 'E_PLATFORM', message: '仅 Windows 支持窗口嵌入' });
  return new Promise((resolve) => {
    const ps = spawn('powershell', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let err = '';
    ps.stdout.on('data', (c) => { out += c; });
    ps.stderr.on('data', (c) => { err += c; });
    ps.on('error', (e) => resolve({ ok: false, code: 'E_PS', message: e.message }));
    ps.on('close', (code) => {
      const text = out.trim();
      try {
        const j = JSON.parse(text.split('\n').filter(Boolean).pop() || '{}');
        resolve(Object.assign({ ok: code === 0 }, j, err && !j.ok ? { message: err.trim().slice(0, 400) } : {}));
      } catch (e) {
        resolve({ ok: false, code: 'E_PARSE', message: (err || text).trim().slice(0, 400) });
      }
    });
  });
}

const PS_WIN_LIB = [
  'Add-Type -Name W -Namespace N -MemberDefinition @\'',
  '[DllImport("user32.dll")] public static extern IntPtr FindWindow(null, string c);',
  '[DllImport("user32.dll")] public static extern IntPtr FindWindowEx(IntPtr p, IntPtr a, string cls, string t);',
  '[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);',
  '[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);',
  '[DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int cx, int cy, bool r);',
  '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);',
  '[DllImport("user32.dll")] public static extern int SetWindowLong(IntPtr h, int i, int v);',
  '[DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i);',
  'public struct RECT { public int L, T, R, B; }',
  '\'@'
].join(' ');

/** 找到 Minecraft 游戏窗口（GLFW 32 窗口） */
function findGameWindow() {
  const s = PS_WIN_LIB + '; $h = [IntPtr]::Zero; ' +
    'foreach ($c in @("GLFW30","LWJGL","SunAwtFrame")) { if ($h -eq [IntPtr]::Zero) { $h = [N.W]::FindWindow($c, $null) } }; ' +
    'if ($h -eq [IntPtr]::Zero) { $h = [N.W]::FindWindow($null, "Minecraft* 1.20.1") }; ' +
    'if ($h -eq [IntPtr]::Zero) { $h = [N.W]::FindWindowEx([IntPtr]::Zero, [IntPtr]::Zero, $null, "Minecraft*") }; ' +
    'if ($h -eq [IntPtr]::Zero) { @{ find = $false } | ConvertTo-Json -Compress } else { ' +
    '$r = New-Object N.W+RECT; [void][N.W]::GetWindowRect($h, [ref]$r); ' +
    '@{ find = $true; handle = $h.ToInt64(); x = $r.L; y = $r.T; w = ($r.R - $r.L); hgt = ($r.B - $r.T) } | ConvertTo-Json -Compress }';
  return win32(s);
}

/** 用 launch-plan.json 直接拉起 JVM（不依赖任何启动器 GUI） */
function startInstance(id) {
  const dir = instanceDir(id);
  if (!fs.existsSync(dir)) {
    return { ok: false, code: 'E_NO_INSTANCE', message: '实例目录不存在：' + dir };
  }

  const planPath = path.join(dir, 'launch-plan.json');
  let plan = null;
  try {
    plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
  } catch (e) {
    return { ok: false, code: 'E_NO_PLAN', message: '实例缺少可用的 launch-plan.json：' + e.message };
  }

  // classpath：绝对化，兼容 Windows 分隔符
  const cp = (plan.classpath || [])
    .map((f) => path.resolve(dir, f))
    .join(path.delimiter);
  if (!cp) {
    return { ok: false, code: 'E_NO_CLASSPATH', message: 'launch-plan.json 里没有 classpath' };
  }

  const args = [];
  args.push('-Xmx' + (plan.memoryMB || 4096) + 'M');
  args.push('-Xms1024M');
  args.push('-Djava.library.path=' + path.resolve(dir, plan.natives || 'natives'));
  args.push('-Dminecraft.launcher.brand=niao-web-host');
  args.push(...JAVA_FLAGS);
  args.push('-cp', cp);
  args.push(plan.mainClass || 'net.minecraft.client.main.Main');

  // 游戏参数：兼容 gameArgs / args 两种字段名，占位符替换成安全值，
  // 相对路径（--gameDir . / --assetsDir assets）统一转成绝对路径
  const gameArgs = (plan.gameArgs || plan.args || []).map((a) =>
    String(a).replace(/\$\{clientid\}/g, '0').replace(/\$\{auth_xuid\}/g, '0')
  );
  for (let i = 0; i < gameArgs.length - 1; i++) {
    if (gameArgs[i] === '--gameDir' || gameArgs[i] === '--assetsDir') {
      gameArgs[i + 1] = path.resolve(dir, gameArgs[i + 1]);
    }
  }
  args.push(...gameArgs);

  // Minecraft 启动时不会自动建这些目录，缺了会在日志/存档/崩溃报告处直接失败
  for (const sub of ['logs', 'crash-reports', 'saves', 'resourcepacks', 'screenshots', 'config', 'mods']) {
    try { fs.mkdirSync(path.join(dir, sub), { recursive: true }); } catch (e) { }
  }

  const logPath = path.join(__dirname, 'niao-host-' + path.basename(dir) + '.log');
  let outFd = null;
  try { outFd = fs.openSync(logPath, 'a'); } catch (e) { outFd = null; }

  log('启动实例 ' + id + '：' + (plan.mcVersion || '?') + '，内存 ' + (plan.memoryMB || 4096) + 'MB');
  const child = spawn('java', args, {
    cwd: dir,
    detached: true,
    stdio: ['ignore', outFd || 'ignore', outFd || 'ignore'],
    windowsHide: false
  });
  child.on('error', (e) => log('启动失败（Java 不可用？）：' + e.message));
  if (outFd !== null) { try { fs.closeSync(outFd); } catch (e) { } }

  child.on('exit', (code, sig) => {
    running.delete(String(id));
    try { clearInterval(finder); } catch (e) { }
    log('实例 ' + id + ' 进程结束：code=' + code + ' signal=' + sig + (code !== 0 ? '（详情见 ' + logPath + '）' : ''));
  });
  child.unref();

  const entry = {
    pid: child.pid || null, startedAt: Date.now(), log: logPath,
    version: plan.mcVersion || null, display: settings.display, handle: null
  };
  running.set(String(id), entry);

  // 等窗口出来再套用样式：embedded 去边框、desktop 用普通窗口
  const wantEmbedded = settings.display === 'embedded';
  let tries = 0;
  const finder = setInterval(async () => {
    tries++;
    if (tries > 40 || !running.has(String(id))) { clearInterval(finder); return; }
    const win = await findGameWindow();
    if (win && win.find) {
      clearInterval(finder);
      entry.handle = win.handle;
      entry.window = { x: win.x, y: win.y, w: win.w, h: win.hgt };
      const r = await applyWindowMode(win.handle, settings.display);
      log('实例 ' + id + ' 窗口已就绪：' + (wantEmbedded ? '浏览器内嵌模式（无边框）' : '桌面窗口模式') +
        (r.ok ? '' : '（样式设置失败：' + (r.message || r.code) + '）'));
    }
  }, 1500);
  finder.unref();

  return { ok: true, pid: child.pid || null, instance: id, dir: dir, version: plan.mcVersion || null, log: logPath, display: settings.display };
}

/** 资源补全进度 */
const assetJob = { running: false, done: 0, total: 0, failed: 0, startedAt: 0, finishedAt: 0, error: null };

const ASSET_HOSTS = [
  'https://resources.download.minecraft.net',
  'https://launcher.mojang.com/v1/objects',
  'https://bmclapi2.bangbang93.com/assets'
];

function fetchBuffer(url, redirects) {
  redirects = redirects == null ? 3 : redirects;
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: 20000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(fetchBuffer(new URL(res.headers.location, url).href, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + res.statusCode));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
  });
}

/** 按 indexes/<id>.json 把缺失的资源对象下载到 assets/objects/<前2位>/<hash> */
async function completeAssets(dir, indexId, onProgress) {
  const idxPath = path.join(dir, 'assets', 'indexes', (indexId || '5') + '.json');
  const index = JSON.parse(fs.readFileSync(idxPath, 'utf8'));
  const entries = Object.entries(index.objects || {});
  assetJob.running = true;
  assetJob.total = entries.length;
  assetJob.done = 0;
  assetJob.failed = 0;
  assetJob.startedAt = Date.now();
  assetJob.error = null;
  log('开始补全资源：' + entries.length + ' 个对象');

  const CONCURRENCY = 12;
  let cursor = 0;

  async function worker() {
    while (cursor < entries.length) {
      const [name, info] = entries[cursor++];
      const hash = info.hash;
      const sub = hash.slice(0, 2);
      const destDir = path.join(dir, 'assets', 'objects', sub);
      const dest = path.join(destDir, hash);
      if (fs.existsSync(dest)) { assetJob.done++; continue; }
      try { fs.mkdirSync(destDir, { recursive: true }); } catch (e) { }
      let ok = false;
      let lastErr = null;
      for (const host of ASSET_HOSTS) {
        try {
          const buf = await fetchBuffer(host + '/' + sub + '/' + hash);
          fs.writeFileSync(dest, buf);
          ok = true;
          break;
        } catch (e) { lastErr = e; }
      }
      if (ok) { assetJob.done++; } else {
        assetJob.failed++;
        if (assetJob.failed <= 5) log('资源下载失败 ' + name + '：' + (lastErr && lastErr.message));
      }
      if ((assetJob.done + assetJob.failed) % 200 === 0) {
        log('资源进度 ' + (assetJob.done + assetJob.failed) + '/' + entries.length + '，失败 ' + assetJob.failed);
      }
      if (onProgress) onProgress(assetJob.done + assetJob.failed, entries.length);
    }
  }

  const workers = [];
  for (let i = 0; i < CONCURRENCY; i++) workers.push(worker());
  await Promise.all(workers);

  assetJob.running = false;
  assetJob.finishedAt = Date.now();
  log('资源补全完成：成功 ' + assetJob.done + '，失败 ' + assetJob.failed);
  return assetJob;
}

const WS_POPUP = 0x80000000;
const WS_CHILD = 0x40000000;
const WS_CAPTION = 0x00C00000;
const WS_THICKFRAME = 0x00040000;
const WS_SYSMENU = 0x00080000;
const WS_MINIMIZEBOX = 0x00020000;
const WS_MAXIMIZEBOX = 0x00010000;
const GWL_STYLE = -16;
const SW_HIDE = 0;
const SW_SHOW = 5;
const SWP_NOZORDER = 0x0004;
const SWP_FRAMECHANGED = 0x0020;

/** 应用窗口样式：embedded = 无边框（便于页面框选），desktop = 普通窗口 */
function applyWindowMode(handle, display, parentHandle) {
  const frameBits = WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
  let script;
  if (display === 'embedded') {
    // 去掉标题栏/边框 → 只剩画面；页面用磁贴盖住
    script = PS_WIN_LIB + '; $h=[IntPtr]' + handle + '; ' +
      '$st=[N.W]::GetWindowLong($h, -16); ' +
      '$st = $st -band (-bnot ' + (frameBits >>> 0) + '); ' +
      '[void][N.W]::SetWindowLong($h, -16, $st); ' +
      '[void][N.W]::SetWindowPos($h, [IntPtr]::Zero, 0, 0, 0, 0, 0x0027); ' +
      '@{ ok = $true; mode = "embedded" } | ConvertTo-Json -Compress';
  } else {
    script = PS_WIN_LIB + '; $h=[IntPtr]' + handle + '; ' +
      '$st=[N.W]::GetWindowLong($h, -16); ' +
      '$st = $st -bor (' + (frameBits >>> 0) + '); ' +
      '[void][N.W]::SetWindowLong($h, -16, $st); ' +
      '[void][N.W]::SetWindowPos($h, [IntPtr]::Zero, 60, 60, 1280, 720, 0x0024); ' +
      '@{ ok = $true; mode = "desktop" } | ConvertTo-Json -Compress';
  }
  return win32(script);
}

/** 把无边框游戏窗口挪到屏幕外/盖住，避免和页面重叠 */
function moveWindow(handle, x, y, w, h) {
  return win32(PS_WIN_LIB + '; $h=[IntPtr]' + handle + '; ' +
    '[void][N.W]::MoveWindow($h, ' + (x | 0) + ', ' + (y | 0) + ', ' + (w | 0) + ', ' + (h | 0) + ', $true); ' +
    '@{ ok = $true } | ConvertTo-Json -Compress');
}

function json(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    // 关键：https 页面（如 GitHub Pages）访问 127.0.0.1 会触发 Private Network Access 预检
    'Access-Control-Allow-Private-Network': 'true',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch (e) { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const p = url.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Private-Network': 'true'
    });
    return res.end();
  }

  try {
    if (p === '/' || p === '/play' || p === '/play/') {
      // 以本机同源方式提供游玩页，绕开 https 站点访问 loopback 的网络权限限制
      let page = '';
      try { page = fs.readFileSync(path.join(__dirname, 'mc-play.html'), 'utf8'); } catch (e) { page = ''; }
      if (!page) return json(res, 500, { ok: false, code: 'E_NO_PAGE', message: 'mc-play.html 不存在，请与 niao-host.js 放在同一目录' });
      page = page.replace(/var INSTANCE = '[^']*';/, "var INSTANCE = '" + cfg.instance + "';")
                 .replace(/<title>[^<]*<\/title>/, '<title>实例 ' + cfg.instance + ' · 我的世界</title>');
      const html = Buffer.from(page, 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': html.length,
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
      });
      return res.end(html);
    }
    if (p === '/health') {
      return json(res, 200, { ok: true, service: 'niao-mc-host', port: cfg.port, instancesRoot: cfg.root, defaultInstance: cfg.instance, version: '1.0.0' });
    }
    if (p === '/instances') {
      // 只列真正像 Minecraft 实例的目录，避免把根目录下的系统文件夹全扫出来
      let items = [];
      try {
        items = fs.readdirSync(cfg.root, { withFileTypes: true })
          .filter((d) => d.isDirectory())
          .map((d) => {
            const full = path.join(cfg.root, d.name);
            const hasScript = fs.existsSync(path.join(full, process.platform === 'win32' ? 'niao-launch.cmd' : 'niao-launch.sh'));
            const hasPlan = fs.existsSync(path.join(full, 'launch-plan.json'));
            // versions/ 必须真的含 <版本>/<版本>.json，否则像 QQBoot 这种同名目录会被误判成实例
            let hasVersions = false;
            try {
              const vdir = path.join(full, 'versions');
              hasVersions = fs.readdirSync(vdir, { withFileTypes: true })
                .some((v) => v.isDirectory() && fs.existsSync(path.join(vdir, v.name, v.name + '.json')));
            } catch (e) { hasVersions = false; }
            return { id: d.name, hasScript: hasScript, hasPlan: hasPlan, isInstance: hasScript || hasPlan || hasVersions };
          })
          .filter((it) => it.isInstance);
      } catch (e) { items = []; }
      return json(res, 200, { ok: true, count: items.length, items: items });
    }
    if (p === '/stop' && req.method === 'POST') {
      const body = await readBody(req);
      const id = String(body.instance || cfg.instance);
      const entry = running.get(id);
      if (!entry) return json(res, 404, { ok: false, code: 'E_NOT_RUNNING', message: '实例 ' + id + ' 未在运行' });
      try { process.kill(entry.pid); } catch (e) { }
      running.delete(id);
      log('已结束实例 ' + id);
      return json(res, 200, { ok: true, instance: id });
    }
    if (p === '/settings') {
      if (req.method === 'POST') {
        const body = await readBody(req);
        if (body.display && DISPLAY_MODES.indexOf(body.display) >= 0) {
          settings.display = body.display;
          saveSettings();
          log('显示模式已切换为：' + settings.display);
        }
      }
      return json(res, 200, Object.assign({ ok: true, modes: DISPLAY_MODES }, settings));
    }
    if (p === '/window/sync' && req.method === 'POST') {
      // 页面把 <video>/磁贴的位置发过来，让无边框游戏窗口贴上去对齐
      const body = await readBody(req);
      const entry = running.get(String(body.instance || cfg.instance));
      if (!entry || !entry.handle) {
        return json(res, 404, { ok: false, code: 'E_NO_WINDOW', message: '游戏窗口尚未就绪' });
      }
      const r = await moveWindow(entry.handle, body.x, body.y, body.w, body.h);
      return json(res, r.ok ? 200 : 500, r);
    }
    if (p === '/window') {
      const list = [];
      for (const [id, info] of running) {
        list.push({ instance: id, pid: info.pid, handle: info.handle, display: info.display, window: info.window || null });
      }
      return json(res, 200, { ok: true, windows: list });
    }
    if (p === '/assets') {
      return json(res, 200, Object.assign({ ok: true }, assetJob));
    }
    if (p === '/assets/complete' && req.method === 'POST') {
      if (assetJob.running) return json(res, 200, { ok: true, already: true, done: assetJob.done, total: assetJob.total });
      const body = await readBody(req);
      const id = body.instance || cfg.instance;
      completeAssets(instanceDir(id), body.index || '5').catch((e) => {
        assetJob.running = false;
        assetJob.error = e.message;
        log('资源补全出错：' + e.message);
      });
      return json(res, 202, { ok: true, started: true, total: 0 });
    }
    if (p === '/status') {
      const list = [];
      for (const [id, info] of running) {
        let alive = false;
        try { process.kill(info.pid, 0); alive = true; } catch (e) { alive = false; }
        list.push({ instance: id, pid: info.pid, alive: alive, startedAt: info.startedAt, version: info.version });
      }
      return json(res, 200, { ok: true, running: list });
    }
    if (p === '/launch' && req.method === 'POST') {
      const body = await readBody(req);
      const result = startInstance(body.instance || cfg.instance);
      return json(res, result.ok ? 200 : 400, result);
    }
    return json(res, 404, { ok: false, code: 'E_NOT_FOUND', message: p });
  } catch (e) {
    log('请求异常：' + e.message);
    return json(res, 500, { ok: false, code: 'E_HOST', message: e.message });
  }
});

if (cfg.install || cfg.uninstall) {
  const { execSync } = require('child_process');
  if (process.platform !== 'win32') {
    console.error('开机自启仅支持 Windows');
    process.exit(1);
  }
  if (cfg.uninstall) {
    try { execSync('schtasks /delete /tn NiaoMcHost /f', { stdio: 'inherit' }); } catch (e) { }
    log('已移除开机自启任务 NiaoMcHost');
    process.exit(0);
  }
  const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + __filename + '" --port ' + cfg.port + ' --instance ' + cfg.instance;
  try {
    execSync('schtasks /create /tn NiaoMcHost /tr "' + cmd.replace(/"/g, '\\"') + '" /sc onlogon /f', { stdio: 'inherit' });
    log('已注册开机自启：NiaoMcHost（端口 ' + cfg.port + '）');
  } catch (e) {
    log('注册失败：' + e.message);
  }
  process.exit(0);
}

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    log('端口 ' + cfg.port + ' 已被占用：本地服务可能已在运行。');
  } else {
    log('监听失败：' + e.message);
  }
  process.exit(1);
});

server.listen(cfg.port, '127.0.0.1', () => {
  log('本地服务已启动：http://127.0.0.1:' + cfg.port + '/  （默认实例 ' + cfg.instance + '）');
});
