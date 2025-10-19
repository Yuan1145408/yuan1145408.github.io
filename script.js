(function(){
  'use strict';
  // 静态模式辅助：从全局配置读取
  const isStatic = () => {
    try { return !!(window.Niao && window.Niao.config && window.Niao.config.static); } catch(_) { return true; }
  };

  // 渲染镜像入口（仅 Netlify 主入口）
  const mirrorsContainer = document.getElementById('mirrorsContainer');
  // 判断链接是否很可能是“文件下载”而非网页
  function isLikelyFileUrl(u){
    try{
      const url = String(u||'');
      const noQuery = url.split('?')[0].split('#')[0];
      return /\.(exe|msi|iso|zip|7z|rar|dmg|pkg|gz|bz2|xz|tgz|tar|deb|rpm|apk)$/i.test(noQuery);
    }catch(_){ return false; }
  }
  function suggestFileNameFrom(d, url){
    const base = String(d.name || d.id || 'download').replace(/\s+/g,'-');
    const noQuery = String(url||'').split('?')[0].split('#')[0];
    const extMatch = noQuery.match(/\.([a-z0-9]+)$/i);
    const ext = extMatch ? ('.' + extMatch[1].toLowerCase()) : '';
    return (base + ext) || 'download';
  }
  async function loadMirrors() {
    try {
      const resp = await fetch('./mirrors.json', { cache: 'no-cache' });
      const data = await resp.json();
      return Array.isArray(data.mirrors) ? data.mirrors : [];
    } catch (e) {
      console.error('loadMirrors failed', e);
      return [];
    }
  }
  async function renderMirrors() {
    if (!mirrorsContainer) return;
    const list = await loadMirrors();
    if (!list.length) {
      mirrorsContainer.innerHTML = '<p>暂无镜像数据或加载失败</p>';
      return;
    }
    const html = list.map(m => `<a class="btn" href="${m.url}" target="_blank" rel="noopener noreferrer">${m.name || 'Netlify 主入口'}</a>`).join('');
    mirrorsContainer.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;">${html}</div>`;
  }

  // 教程专区：加载 tutorials-extra.json 并渲染
  const tutorialGrid = document.getElementById('tutorialGrid');
  async function loadExtraTutorials() {
    try {
      const resp = await fetch('./tutorials-extra.json', { cache: 'no-cache' });
      const data = await resp.json();
      if (Array.isArray(data)) return data;
      if (data && Array.isArray(data.tutorials)) return data.tutorials;
      return [];
    } catch (e) {
      console.error('loadExtraTutorials failed', e);
      return [];
    }
  }
  function renderTutorials(items) {
    if (!tutorialGrid) return;
    tutorialGrid.innerHTML = '';
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const websiteBtn = d.website ? `<a class="btn" href="${d.website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const localBtn = d.local ? `<a class="btn primary" href="${encodeURI(d.local)}" target="_blank" rel="noopener noreferrer">本地教程</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名教程'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <span class="chip">${d.category || 'docs'}</span>
          ${websiteBtn}
          ${localBtn}
          ${tagsChips}
        </div>
      `;
      tutorialGrid.appendChild(el);
    });
  }

  // 官方站点快捷跳转：从 mirrors.json 取主入口
  const officialGrid = document.getElementById('officialGrid');
  async function loadOfficial() {
    try {
      const resp = await fetch('./mirrors.json', { cache: 'no-cache' });
      const data = await resp.json();
      const mirrors = Array.isArray(data.mirrors) ? data.mirrors : [];
      return mirrors.map(m => ({ name: m.name || 'Netlify 主入口', url: m.url }));
    } catch (e) {
      console.error('loadOfficial failed', e);
      return [];
    }
  }
  async function renderOfficial() {
    if (!officialGrid) return;
    const items = await loadOfficial();
    officialGrid.innerHTML = '';
    if (!items.length) {
      officialGrid.innerHTML = '<p>暂无官方链接</p>';
      return;
    }
    const html = items.map(d => `<a class="btn" href="${d.url}" target="_blank" rel="noopener noreferrer">${d.name}</a>`).join('');
    officialGrid.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;">${html}</div>`;
  }

  // 软件下载：加载 softwares-extra.json 并渲染（支持搜索与标签筛选）
  const downloadGrid = document.getElementById('downloadGrid');
  const browserGrid = document.getElementById('browserGrid');
  const filterSelect = document.getElementById('filterSelect');
  const tagSelect = document.getElementById('tagSelect');
  const searchInput = document.getElementById('searchInput');
  async function loadExtraSoftware() {
    try {
      const resp = await fetch('./softwares-extra.json', { cache: 'no-cache' });
      const data = await resp.json();
      if (Array.isArray(data)) return data;
      if (data && Array.isArray(data.software)) return data.software;
      return [];
    } catch (e) {
      console.error('loadExtraSoftware failed', e);
      return [];
    }
  }
  function sanitizeUrl(u){
    try { return String(u || '').replace(/`/g, '').trim(); } catch(_) { return ''; }
  }
  function renderDownloadCards(items){
    if (!downloadGrid) return;
    downloadGrid.innerHTML = '';
    if (!items || !items.length){
      downloadGrid.innerHTML = '<p>暂无软件数据</p>';
      return;
    }
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const direct = sanitizeUrl(d.direct);
      const websiteBtn = website ? `<a class="btn" href="${website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      // 付费软件支持兑换与密钥文件下载（静态模式下不启用兑换）
      const isPaid = ((d.category || '').toLowerCase() === 'paid');
      const costVal = isPaid ? (parseInt(d.cost || 500, 10) || 500) : (parseInt(d.cost || 0, 10) || 0);
      const costChip = isPaid ? `<span class="chip">需积分：${costVal}</span>` : '';
      let redeemAttrs = '';
      const rid = String(d.redeemId || ('software-' + (d.id || (String(d.name||'').toLowerCase().replace(/\s+/g,'-')))));
      const bonusFilename = String(d.bonusFilename || '').replace(/`/g,'');
      const bonusContent = String(d.bonusContent || '');
      if (!isStatic() && (isPaid || d.cost)) {
        redeemAttrs = ` data-action="redeem" data-redeem-id="${rid}" data-redeem-cost="${String(costVal || d.cost || 500)}" data-bonus-filename="${bonusFilename}" data-bonus-content="${bonusContent}"`;
      }
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${direct}" ${(!isPaid && isStatic() && isLikelyFileUrl(direct)) ? `download="${suggestFileNameFrom(d, direct)}"` : ''} rel="noopener noreferrer"${redeemAttrs}>${(!isPaid && isLikelyFileUrl(direct))?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名软件'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${websiteBtn}
          ${directBtn}
          ${costChip}
          ${tagsChips}
        </div>
      `;
      downloadGrid.appendChild(el);
    });
  }
  function renderBrowserCards(items){
    if (!browserGrid) return;
    browserGrid.innerHTML = '';
    if (!items || !items.length){
      browserGrid.innerHTML = '<p>暂无浏览器数据</p>';
      return;
    }
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const direct = sanitizeUrl(d.direct);
      const websiteBtn = website ? `<a class="btn" href="${website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${direct}" ${ (isStatic() && isLikelyFileUrl(direct)) ? `download="${suggestFileNameFrom(d, direct)}"` : '' } rel="noopener noreferrer">${isLikelyFileUrl(direct)?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名软件'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${websiteBtn}
          ${directBtn}
          ${tagsChips}
        </div>
      `;
      browserGrid.appendChild(el);
    });
  }
  function setupDownloadFilters(list){
    if (!filterSelect || !tagSelect || !searchInput) return;
    // 分类下拉（按 category 汇总，排除 browser 类目，浏览器单独分区显示）
    const cats = Array.from(new Set(list.filter(x => (x.category || 'software') !== 'browser').map(x => x.category || 'software')));
    filterSelect.innerHTML = '<option value="all">全部</option>' + cats.map(c => `<option value="${c}">${c}</option>`).join('');
    // 标签下拉
    const tags = Array.from(new Set(list.filter(x => (x.category || 'software') !== 'browser').flatMap(x => Array.isArray(x.tags) ? x.tags : [])));
    tagSelect.innerHTML = '<option value="all">全部</option>' + tags.map(t => `<option value="${t}">${t}</option>`).join('');
  }
  function applyDownloadFilters(list){
    if (!downloadGrid) return;
    let q = (searchInput && searchInput.value || '').toLowerCase();
    let cat = (filterSelect && filterSelect.value) || 'all';
    let tag = (tagSelect && tagSelect.value) || 'all';
    const filtered = list.filter(x => {
      if ((x.category || 'software') === 'browser') return false; // 浏览器不在主分区显示
      const matchQ = !q || (String(x.name || '').toLowerCase().includes(q) || String(x.desc || '').toLowerCase().includes(q));
      const matchCat = (cat === 'all') || ((x.category || 'software') === cat);
      const matchTag = (tag === 'all') || (Array.isArray(x.tags) && x.tags.includes(tag));
      return matchQ && matchCat && matchTag;
    });
    renderDownloadCards(filtered);
  }
  function wireDownloadControls(list){
    if (!filterSelect || !tagSelect || !searchInput) return;
    ['change','input'].forEach(ev => {
      filterSelect.addEventListener(ev, () => applyDownloadFilters(list));
      tagSelect.addEventListener(ev, () => applyDownloadFilters(list));
      searchInput.addEventListener(ev, () => applyDownloadFilters(list));
    });
  }

  // 游戏专区：加载 games-extra.json 并按类别渲染
  const gameGridPlatforms = document.getElementById('gameGridPlatforms');
  const gameGridShooter = document.getElementById('gameGridShooter');
  const gameGridPaid = document.getElementById('gameGridPaid');
  const gameGridCard = document.getElementById('gameGridCard');
  const gameGridRPG = document.getElementById('gameGridRPG');
  const gameGridSandbox = document.getElementById('gameGridSandbox');
  async function loadExtraGames() {
    try {
      const resp = await fetch('./games-extra.json', { cache: 'no-cache' });
      const data = await resp.json();
      if (Array.isArray(data)) return data;
      if (data && Array.isArray(data.games)) return data.games;
      return [];
    } catch (e) {
      console.error('loadExtraGames failed', e);
      return [];
    }
  }
  function inferGenre(d) {
    if (d.genre) return d.genre;
    const tags = Array.isArray(d.tags) ? d.tags.map(t => String(t).toLowerCase()) : [];
    if (tags.includes('fps') || tags.includes('射击')) return 'shooter';
    if (tags.includes('卡牌') || tags.includes('card')) return 'card';
    if (tags.includes('rpg') || tags.includes('mmorpg') || tags.includes('mmo') || tags.includes('角色扮演')) return 'rpg';
    if (tags.includes('sandbox') || tags.includes('沙盒') || tags.includes('开放世界') || String(d.name||'').toLowerCase().includes('minecraft')) return 'sandbox';
    return 'other';
  }
  function renderGameList(gridEl, items) {
    if (!gridEl) return;
    gridEl.innerHTML = '';
    if (!items || !items.length) {
      gridEl.innerHTML = '<p>暂无该类别的游戏</p>';
      return;
    }
    // 为防止数据中包含反引号或多余空格，清洗 URL
    const sanitizeUrl = (u) => {
      try {
        return String(u || '').replace(/`/g, '').trim();
      } catch (_) {
        return '';
      }
    };
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const direct = sanitizeUrl(d.direct);
      const websiteBtn = website ? `<a class="btn" href="${website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const local = sanitizeUrl(d.local);
      const localBtn = local ? `<a class="btn primary" href="${local}" target="_blank" rel="noopener noreferrer">本网资源</a>` : '';
      // 付费项显示所需积分（默认500），并为有直链的付费项自动接入兑换
      const isPaid = ((d.category || '').toLowerCase() === 'paid');
      const costVal = isPaid ? (parseInt(d.cost || 500, 10) || 500) : (parseInt(d.cost || 0, 10) || 0);
      const costChip = isPaid ? `<span class="chip">需积分：${costVal}</span>` : '';
      let redeemAttrs = '';
      if (direct) {
        const rid = String(d.redeemId || ('game-' + (d.id || (String(d.name||'').toLowerCase().replace(/\s+/g,'-')))));
        const bonusFilename = d.bonusFilename || (d.id === 'rdr2' ? '荒野大镖客-密钥215448.txt' : '兑换密钥.txt');
        const bonusContent = d.bonusContent || (d.id === 'rdr2' ? '密钥215448' : '');
        if (!isStatic() && (isPaid || d.cost)) {
          redeemAttrs = ` data-action="redeem" data-redeem-id="${rid}" data-redeem-cost="${String(costVal || d.cost || 500)}" data-bonus-filename="${bonusFilename}" data-bonus-content="${bonusContent}"`;
        }
      }
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${direct}" rel="noopener noreferrer"${redeemAttrs}>直接安装</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名游戏'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${costChip}
          ${websiteBtn}
          ${localBtn}
          ${directBtn}
          ${tagsChips}
        </div>
      `;
      gridEl.appendChild(el);
    });
  }
  function renderGames(items) {
    const platforms = items.filter(d => (d.category || '').toLowerCase() === 'platform');
    const paid = items.filter(d => (d.category || '').toLowerCase() === 'paid');
    const shooter = items.filter(d => inferGenre(d) === 'shooter');
    const card = items.filter(d => inferGenre(d) === 'card');
    const rpg = items.filter(d => inferGenre(d) === 'rpg');
    const sandbox = items.filter(d => inferGenre(d) === 'sandbox');
    renderGameList(gameGridPlatforms, platforms);
    renderGameList(gameGridPaid, paid);
    renderGameList(gameGridShooter, shooter);
    renderGameList(gameGridCard, card);
    renderGameList(gameGridRPG, rpg);
    renderGameList(gameGridSandbox, sandbox);
  }

  // 虚拟机与系统镜像：加载 downloads-extra.json 并渲染
  const vmGrid = document.getElementById('vmGrid');
  const osGrid = document.getElementById('osGrid');
  async function loadDownloadsExtra() {
    try {
      const resp = await fetch('./downloads-extra.json', { cache: 'no-cache' });
      const data = await resp.json();
      if (Array.isArray(data)) {
        return { vm: data.filter(x => x.category === 'vm'), os: data.filter(x => x.category === 'os') };
      }
      return { vm: Array.isArray(data.vm) ? data.vm : [], os: Array.isArray(data.os) ? data.os : [] };
    } catch (e) {
      console.error('loadDownloadsExtra failed', e);
      return { vm: [], os: [] };
    }
  }
  function renderVMZone(items) {
    if (!vmGrid) return;
    vmGrid.innerHTML = '';
    if (!items || !items.length) {
      vmGrid.innerHTML = '<p>暂无虚拟机数据</p>';
      return;
    }
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const websiteBtn = d.website ? `<a class="btn" href="${d.website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const directBtn = d.direct ? `<a class="btn ${isStatic()?'':'requires-auth'}" href="${d.direct}" ${ (isStatic() && isLikelyFileUrl(d.direct)) ? `download="${suggestFileNameFrom(d, d.direct)}"` : '' } rel="noopener noreferrer">${isLikelyFileUrl(d.direct)?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${websiteBtn}
          ${directBtn}
          ${tagsChips}
        </div>
      `;
      vmGrid.appendChild(el);
    });
  }
  function renderOSZone(items) {
    if (!osGrid) return;
    osGrid.innerHTML = '';
    if (!items || !items.length) {
      osGrid.innerHTML = '<p>暂无系统镜像数据</p>';
      return;
    }
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const websiteBtn = d.website ? `<a class="btn" href="${d.website}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const directBtn = d.direct ? `<a class="btn ${isStatic()?'':'requires-auth'}" href="${d.direct}" ${ (isStatic() && isLikelyFileUrl(d.direct)) ? `download="${suggestFileNameFrom(d, d.direct)}"` : '' } rel="noopener noreferrer">${isLikelyFileUrl(d.direct)?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${t}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${d.name || '未命名'}</h4>
        <p>${d.desc || ''}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${websiteBtn}
          ${directBtn}
          ${tagsChips}
        </div>
      `;
      osGrid.appendChild(el);
    });
  }

  // 初始化：按模块依次恢复
  (async function init(){
    await renderMirrors();
    const tutorials = await loadExtraTutorials();
    renderTutorials(tutorials);
    await renderOfficial();
    // 软件下载（仅在 downloads.html 存在容器时生效）
    const software = await loadExtraSoftware();
    const browsers = software.filter(x => (x.category || 'software') === 'browser');
    const others = software.filter(x => (x.category || 'software') !== 'browser');
    setupDownloadFilters(others);
    wireDownloadControls(others);
    applyDownloadFilters(others);
    renderBrowserCards(browsers);
    const games = await loadExtraGames();
    renderGames(games);
    const dl = await loadDownloadsExtra();
    renderVMZone(dl.vm);
    renderOSZone(dl.os);
  })();
})();

// 全局用户系统与每日任务（本地演示版，可接入后端）
;(function(){
  'use strict';
  // 静态模式：不依赖后端 API，所有下载/安装不再需要登录或积分兑换。
  // 通过 window.Niao.config.static 控制；默认启用静态模式。
  const isStatic = () => {
    try { return !!(window.Niao && window.Niao.config && window.Niao.config.static); } catch(_) { return true; }
  };
  const dayKey = () => new Date().toISOString().slice(0,10); // UTC 日期，简单可靠
  const KEYS = {
    USERS: 'niao.auth.users',
    SESSION: 'niao.auth.sessionUser',
    POINTS_PREFIX: 'niao.points.',
    DAILY_PROGRESS_PREFIX: 'niao.daily.progress.', // 按天计秒：progress.<YYYY-MM-DD> = sec
    DAILY_COMPLETED_PREFIX: 'niao.daily.completed.' // 按用户+天：completed.<user>.<YYYY-MM-DD> = 1
  };

  function readJSON(key, def){
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : def; } catch(_) { return def; }
  }
  function writeJSON(key, val){ try { localStorage.setItem(key, JSON.stringify(val)); } catch(_){} }
  function readRaw(key, def){ const v = localStorage.getItem(key); return v == null ? def : v; }
  function writeRaw(key, val){ try { localStorage.setItem(key, String(val)); } catch(_){} }

  const API_BASE = (window.Niao && window.Niao.config && window.Niao.config.apiBase) || 'http://localhost:5050';
  const Auth = {
    async register(u, p){
      u = String(u||'').trim(); p = String(p||'');
      if (!u || !p) return false;
      // 静态模式：将账号信息保存在浏览器本地（LocalStorage）
      if (isStatic()) {
        const users = readJSON(KEYS.USERS, {});
        if (users[u]) return false; // 已存在
        users[u] = { pass: p };
        writeJSON(KEYS.USERS, users);
        return true;
      }
      try {
        const resp = await fetch(API_BASE + '/api/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u, password: p }) });
        const data = await resp.json(); return !!data.ok;
      } catch(_) { return false; }
    },
    async login(u, p){
      u = String(u||'').trim(); p = String(p||'');
      // 静态模式：本地校验
      if (isStatic()) {
        const users = readJSON(KEYS.USERS, {});
        if (users[u] && String(users[u].pass||'') === p) {
          writeRaw('niao.auth.token', 'local');
          writeRaw(KEYS.SESSION, u);
          return true;
        }
        return false;
      }
      try {
        const resp = await fetch(API_BASE + '/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u, password: p }) });
        const data = await resp.json();
        if (data && data.ok && data.token) {
          writeRaw('niao.auth.token', data.token);
          writeRaw(KEYS.SESSION, data.username || u);
          return true;
        }
        return false;
      } catch(_) { return false; }
    },
    logout(){ writeRaw('niao.auth.token', ''); writeRaw(KEYS.SESSION, ''); },
    getSessionUser(){ return String(readRaw(KEYS.SESSION, '') || ''); },
    getToken(){ return String(readRaw('niao.auth.token', '') || ''); },
    async getPoints(u){
      if (isStatic()) {
        const key = KEYS.POINTS_PREFIX + String(u||'');
        return parseInt(readRaw(key, '0'), 10) || 0;
      }
      const token = this.getToken(); if (!token) return 0;
      try { const resp = await fetch(API_BASE + '/api/points?token=' + encodeURIComponent(token)); const d = await resp.json(); return d.points || 0; } catch(_) { return 0; }
    },
    async addPoints(u, n, reason){
      if (isStatic()) {
        u = String(u||'');
        const key = KEYS.POINTS_PREFIX + u;
        const cur = parseInt(readRaw(key, '0'), 10) || 0;
        const next = (cur + (n||0));
        writeRaw(key, String(Math.max(0, next)));
        return;
      }
      const token = this.getToken(); if (!token) return;
      try { await fetch(API_BASE + '/api/points/add', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token, amount: n||0, reason: reason||'manual' }) }); } catch(_) {}
    }
  };

  const Daily = {
    DURATION_SEC: 15 * 60,
    INTERVAL_MS: 1000,
    ui: { barEl: null, textEl: null, pointsEl: null },
    bindUI({ barEl, textEl, pointsEl }){
      this.ui = { barEl: barEl || null, textEl: textEl || null, pointsEl: pointsEl || null };
      this.updateUI();
    },
    getProgressSec(){ return parseInt(readRaw(KEYS.DAILY_PROGRESS_PREFIX + dayKey(), '0'), 10) || 0; },
    setProgressSec(sec){ writeRaw(KEYS.DAILY_PROGRESS_PREFIX + dayKey(), String(sec)); },
    isCompletedFor(user){ user = String(user||''); if (!user) return false; return readRaw(KEYS.DAILY_COMPLETED_PREFIX + user + '.' + dayKey(), '') === '1'; },
    markCompleted(user){ user = String(user||''); if (!user) return; writeRaw(KEYS.DAILY_COMPLETED_PREFIX + user + '.' + dayKey(), '1'); },
    tick(){
      const sec = this.getProgressSec();
      if (sec >= this.DURATION_SEC) {
        const u = Auth.getSessionUser();
        if (u && !this.isCompletedFor(u)) { this.markCompleted(u); Auth.addPoints(u, 5, 'daily5min'); }
        this.updateUI();
        return;
      }
      const next = sec + 1;
      this.setProgressSec(next);
      const u = Auth.getSessionUser();
      if (next >= this.DURATION_SEC && u) {
        if (!this.isCompletedFor(u)) { this.markCompleted(u); Auth.addPoints(u, 5, 'daily5min'); }
      }
      this.updateUI();
    },
    start(){
      // 页面可见时才计时
      const tickVisible = () => { if (document.visibilityState === 'visible') this.tick(); };
      setInterval(tickVisible, this.INTERVAL_MS);
      window.addEventListener('storage', (e) => {
        if (!e) return;
        const key = e.key || '';
        if (key && (key.startsWith(KEYS.DAILY_PROGRESS_PREFIX) || key.startsWith(KEYS.DAILY_COMPLETED_PREFIX) || key.startsWith(KEYS.POINTS_PREFIX))) {
          this.updateUI();
        }
        if (key === KEYS.SESSION) Gate.update();
      });
      this.updateUI();
    },
    updateUI(){
      const sec = this.getProgressSec();
      const pct = Math.min(100, Math.floor(sec * 100 / this.DURATION_SEC));
      const mins = Math.floor(sec / 60);
      const u = Auth.getSessionUser();
      const done = !!(u && this.isCompletedFor(u));
      if (this.ui.barEl) this.ui.barEl.style.width = pct + '%';
      if (this.ui.textEl) this.ui.textEl.textContent = `今日进度：${mins} / ${Math.floor(this.DURATION_SEC/60)} 分钟${done ? '（已领取 +5 积分）' : ''}`;
      // 异步获取积分，避免显示 [object Promise]
      if (this.ui.pointsEl) {
        if (u) {
          Auth.getPoints(u)
            .then(p => { this.ui.pointsEl.textContent = String(p || 0); })
            .catch(() => { this.ui.pointsEl.textContent = '0'; });
        } else {
          this.ui.pointsEl.textContent = '0';
        }
      }
    }
  };

  const Gate = {
    overlayId: 'niao-auth-overlay',
    ensure(){
      if (document.getElementById(this.overlayId)) return;
      const div = document.createElement('div');
      div.id = this.overlayId;
      div.className = 'auth-overlay';
      div.innerHTML = `
        <div class="panel" role="dialog" aria-modal="true">
          <div style="text-align:right">
            <button id="modalCloseBtn" class="btn" aria-label="关闭登录面板">关闭</button>
          </div>
          <h4>${isStatic() ? '账户（本地演示）' : '登录后使用功能'}</h4>
          <p style="color:var(--muted)">${isStatic() ? '当前为静态模式：下载与安装无需登录；登录仅用于本地积分演示（保存在浏览器）。' : '请先登录才能使用站内全部功能（包括下载、任务与积分）。'}</p>
          <div style="margin-top:8px;text-align:left">
            <label>用户名：<input id="modalLoginUser" type="text" placeholder="请输入用户名" /></label>
            <label>密码：<input id="modalLoginPass" type="password" placeholder="请输入密码" /></label>
            <div style="display:flex;gap:10px;margin-top:8px;align-items:center;flex-wrap:wrap;">
              <button id="modalLoginBtn" class="btn primary">登录</button>
              <button id="modalLogoutBtn" class="btn">退出登录</button>
              <span id="modalStatus" class="chip">未登录</span>
            </div>
            <p style="margin-top:8px;color:var(--muted);">
              还没有账号？<a href="#" id="modalToggleRegister" style="color:var(--primary);text-decoration:none;">注册</a>
            </p>
            <div id="modalRegisterCard" style="display:none;">
              <label>用户名：<input id="modalRegUser" type="text" placeholder="设置一个用户名" /></label>
              <label>密码：<input id="modalRegPass" type="password" placeholder="设置密码" /></label>
              <label>确认密码：<input id="modalRegPass2" type="password" placeholder="再次输入密码" /></label>
              <div style="display:flex;gap:10px;margin-top:8px;flex-wrap:wrap;">
                <button id="modalRegBtn" class="btn">注册</button>
                <button id="modalCancelReg" class="btn">取消</button>
              </div>
              <p id="modalRegStatus" style="margin-top:8px;color:var(--muted);"></p>
            </div>
          </div>
        </div>`;
      document.body.appendChild(div);
      // 绑定事件
      const closeBtn = document.getElementById('modalCloseBtn');
      const loginUser = document.getElementById('modalLoginUser');
      const loginPass = document.getElementById('modalLoginPass');
      const loginBtn = document.getElementById('modalLoginBtn');
      const logoutBtn = document.getElementById('modalLogoutBtn');
      const loginStatus = document.getElementById('modalStatus');
      const toggleRegister = document.getElementById('modalToggleRegister');
      const registerCard = document.getElementById('modalRegisterCard');
      const regUser = document.getElementById('modalRegUser');
      const regPass = document.getElementById('modalRegPass');
      const regPass2 = document.getElementById('modalRegPass2');
      const regBtn = document.getElementById('modalRegBtn');
      const cancelRegBtn = document.getElementById('modalCancelReg');
      const regStatus = document.getElementById('modalRegStatus');
      function renderModalSession(){
        const u = Auth.getSessionUser();
        loginStatus.textContent = u ? '已登录' : '未登录';
      }
      // 关闭面板（按钮 / Esc / 点击空白处）
      closeBtn && closeBtn.addEventListener('click', () => { Gate.remove(); });
      div.addEventListener('click', (e) => { if (e.target && e.target.id === Gate.overlayId) { Gate.remove(); } });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && document.getElementById(Gate.overlayId)) Gate.remove(); });
      loginBtn.addEventListener('click', async () => {
        const u = (loginUser.value||'').trim();
        const p = loginPass.value||'';
        const ok = await Auth.login(u,p);
        loginStatus.textContent = ok ? '登录成功' : '用户名或密码错误';
        Gate.update();
      });
      logoutBtn.addEventListener('click', () => { Auth.logout(); loginStatus.textContent = '已退出登录'; Gate.update(); });
      toggleRegister.addEventListener('click', (e) => { e.preventDefault(); registerCard.style.display = 'block'; });
      cancelRegBtn.addEventListener('click', () => { registerCard.style.display = 'none'; });
      regBtn.addEventListener('click', async () => {
        const u = (regUser.value||'').trim();
        const p = regPass.value||'';
        const p2 = regPass2.value||'';
        if (!u || !p) { regStatus.textContent = '请输入用户名与密码'; return; }
        if (p !== p2) { regStatus.textContent = '两次密码不一致'; return; }
        const ok = await Auth.register(u,p);
        regStatus.textContent = ok ? '注册成功，请登录' : '该用户已存在或注册失败';
      });
      renderModalSession();
    },
    remove(){ const el = document.getElementById(this.overlayId); if (el) el.remove(); },
    open(){ this.ensure(); },
    update(){
      const u = Auth.getSessionUser();
      // 登录时自动关闭面板；未登录时不要自动强制打开，仅在用户操作时打开
      if (u) { this.remove(); }
    }
  };
  // 顶栏登录按钮接入与动态注入
  document.addEventListener('DOMContentLoaded', () => {
    const nav = document.querySelector('.site-nav');
    // 主题切换：默认深色，可切换为浅色（文字/背景互换）
    const root = document.documentElement;
    function applyTheme(t){
      try { root.setAttribute('data-theme', t); localStorage.setItem('niao.theme', t); }
      catch(_) { root.setAttribute('data-theme', t); }
    }
    function getTheme(){
      try { return localStorage.getItem('niao.theme') || 'dark'; }
      catch(_) { return 'dark'; }
    }
    let currentTheme = getTheme();
    applyTheme(currentTheme);
    if (nav && !document.getElementById('navTheme')){
      const themeLink = document.createElement('a');
      themeLink.href = '#';
      themeLink.id = 'navTheme';
      themeLink.textContent = currentTheme === 'dark' ? '浅色' : '深色';
      nav.prepend(themeLink);
      themeLink.addEventListener('click', (e) => {
        e.preventDefault();
        currentTheme = (currentTheme === 'dark' ? 'light' : 'dark');
        applyTheme(currentTheme);
        themeLink.textContent = currentTheme === 'dark' ? '浅色' : '深色';
      });
    }
    // 全站返回键：优先插入到导航栏最前；若无导航则创建浮动返回按钮
    const goBack = () => {
      try {
        if (window.history && window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = 'index.html';
        }
      } catch(_) { window.location.href = 'index.html'; }
    };
    if (nav && !document.getElementById('navBack')) {
      const back = document.createElement('a');
      back.href = '#';
      back.id = 'navBack';
      back.textContent = '返回';
      nav.prepend(back);
      back.addEventListener('click', (e) => { e.preventDefault(); goBack(); });
    } else if (!document.getElementById('navBack')) {
      const backFloat = document.createElement('a');
      backFloat.href = '#';
      backFloat.className = 'btn back-floating';
      backFloat.id = 'navBack';
      backFloat.textContent = '返回';
      backFloat.addEventListener('click', (e) => { e.preventDefault(); goBack(); });
      document.body.appendChild(backFloat);
    }

    if (nav && !document.getElementById('navLogin')) {
      const a = document.createElement('a');
      a.href = '#';
      a.id = 'navLogin';
      a.textContent = '登录';
      nav.appendChild(a);
    }
    const navLogin = document.getElementById('navLogin');
    function updateNavLogin(){
      const u = Auth.getSessionUser();
      if (!navLogin) return;
      if (u) { navLogin.textContent = '登出'; navLogin.setAttribute('data-mode','logout'); }
      else { navLogin.textContent = '登录'; navLogin.setAttribute('data-mode','login'); }
    }
    updateNavLogin();
    if (navLogin) navLogin.addEventListener('click', (e) => {
      e.preventDefault();
      const mode = navLogin.getAttribute('data-mode');
      if (mode === 'logout') { Auth.logout(); updateNavLogin(); Gate.update(); }
      else { Gate.open(); }
    });
    window.addEventListener('storage', (e) => { if (e && e.key === 'niao.auth.sessionUser') { updateNavLogin(); updateRedeemButtonStates(); } });

    // 根据当前积分预先标记付费直装按钮是否可用（静态模式下跳过）
    async function updateRedeemButtonStates(){
      if (isStatic()) return;
      const anchors = Array.from(document.querySelectorAll('.requires-auth[data-action="redeem"]'));
      if (!anchors.length) return;
      const u = Auth.getSessionUser();
      if (!u){
        anchors.forEach(a => { a.removeAttribute('data-disabled'); a.style.opacity=''; const orig=a.getAttribute('data-label-orig'); if (orig) a.textContent = orig; });
        return;
      }
      const pts = await Auth.getPoints(u);
      anchors.forEach(a => {
        const cost = parseInt(a.getAttribute('data-redeem-cost')||'0',10)||0;
        const labelBackup = a.getAttribute('data-label-orig') || a.textContent;
        a.setAttribute('data-label-orig', labelBackup);
        if ((pts||0) < cost){
          a.setAttribute('data-disabled','insufficient');
          a.setAttribute('aria-disabled','true');
          a.textContent = '积分不足';
          a.style.opacity = '0.7';
        } else {
          a.removeAttribute('data-disabled');
          a.setAttribute('aria-disabled','false');
          a.textContent = labelBackup;
          a.style.opacity = '';
        }
      });
    }
    // 初始状态尝试更新一次（若未登录则显示默认文案）
    updateRedeemButtonStates();

    // 拦截需要登录/兑换的直接下载/安装操作
    if (!isStatic()) {
      document.addEventListener('click', async (e) => {
        const target = e.target;
        const el = target.closest && target.closest('.requires-auth');
        if (el) {
          const u = Auth.getSessionUser();
          if (!u) {
            e.preventDefault();
            Gate.open();
          } else {
          // 检查是否为积分兑换模式
          const mode = el.getAttribute('data-action') || '';
          const cost = parseInt(el.getAttribute('data-redeem-cost') || '0', 10) || 0;
          const rid = (el.getAttribute('data-redeem-id') || '').trim();
          if (mode === 'redeem' && rid && cost > 0) {
            e.preventDefault();
            if (el.getAttribute('data-disabled') === 'insufficient'){
              alert('积分不足，无法兑换该资源。');
              return;
            }
            const token = Auth.getToken();
            if (!token) { Gate.open(); return; }
            // 兑换记录改为“按用户+资源”存储，避免不同用户共用一条记录导致无积分也能跳转
            const redeemedKey = 'niao.redeemed.' + rid + '.' + u;
            const already = readRaw(redeemedKey, '');
            // 兼容旧版（历史上使用全局而非按用户记录），仅在开发者账号下放行
            const legacyKey = 'niao.redeemed.' + rid;
            const legacy = readRaw(legacyKey, '');
            const href = el.getAttribute('href') || '';
            const openTarget = () => { try { window.open(href, '_blank'); } catch(_) { window.location.href = href; } };
            const makeBonusDoc = () => {
              try {
                const fname = el.getAttribute('data-bonus-filename') || '兑换密钥.txt';
                const content = el.getAttribute('data-bonus-content') || '';
                if (!content) return; // 无内容则跳过本地生成
                const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = fname;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 800);
              } catch(_) {}
            };
            const tryServerKeyDownload = () => {
              try {
                const API_BASE = (window.Niao && window.Niao.config && window.Niao.config.apiBase) || 'http://localhost:5050';
                const href = API_BASE + '/api/key-file?token=' + encodeURIComponent(token) + '&rid=' + encodeURIComponent(rid);
                const a = document.createElement('a');
                a.href = href; a.rel = 'noopener noreferrer';
                // 同源时可用 download 属性，跨域依靠 Content-Disposition
                try { if (new URL(href).origin === window.location.origin) a.setAttribute('download', ''); } catch(_) {}
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { a.remove(); }, 500);
              } catch(_) {
                // 失败则退回本地生成
                makeBonusDoc();
              }
            };
            if (already === '1' || (legacy === '1' && u === 'Yuan')) { openTarget(); return; }
            // 查询当前积分
            const pts = await Auth.getPoints(u);
            if ((pts||0) < cost) {
              alert(`积分不足，当前 ${pts||0}，需要 ${cost} 积分。请先通过每日任务等方式获取积分。`);
              updateRedeemButtonStates();
              return;
            }
            const ok = confirm(`购买前确认：需要消耗 ${cost} 积分进行兑换并跳转，是否确认？`);
            if (!ok) return;
            // 扣减积分并记录兑换
            await Auth.addPoints(u, -cost, 'redeem:' + rid);
            writeRaw(redeemedKey, '1');
            // 优先尝试从服务端下载密钥文件，失败时降级为本地生成
            tryServerKeyDownload();
            openTarget();
            // 兑换后刷新按钮状态（可能积分已变化）
            setTimeout(updateRedeemButtonStates, 500);
          }
        }
      }
      }, { capture: true });
    }
  });

  // 导出到全局并启动
  window.Niao = window.Niao || {};
  window.Niao.config = window.Niao.config || {};
  // 默认启用静态模式；如需接入后端可在页面中覆盖为 { static:false, apiBase:'https://your-domain' }
  if (typeof window.Niao.config.static === 'undefined') window.Niao.config.static = true;
  if (typeof window.Niao.config.apiBase === 'undefined') window.Niao.config.apiBase = '';
  window.Niao.auth = Auth;
  window.Niao.daily = Daily;
  window.Niao.gate = Gate;
  Gate.update();
  Daily.start();
})();
