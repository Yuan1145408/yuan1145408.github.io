(function(){
  'use strict';

  // ---- 公共配置与工具（全站唯一实现，避免各渲染函数重复定义） ----
  const isStatic = () => {
    try { return !!(window.Niao && window.Niao.config && window.Niao.config.static); } catch(_) { return true; }
  };
  // HTML 文本转义：数据文件中的名称/描述可能含 < > &，直接拼进 innerHTML 会破坏结构
  function esc(v){
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  // URL 清洗：去掉反引号与首尾空白，作为属性值使用时再转义
  function sanitizeUrl(u){
    try { return String(u || '').replace(/`/g, '').trim(); } catch(_) { return ''; }
  }
  // 属性值统一出口：清洗 + 转义
  function attrUrl(u){ return esc(sanitizeUrl(u)); }

  // ---- 统一 JSON 加载：同一文件只请求一次，页面初始化并发执行 ----
  const jsonCache = new Map();
  function loadJSON(path){
    if (!jsonCache.has(path)) {
      const p = fetch(path, { cache: 'no-cache' })
        .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .catch(e => { console.error('load failed:', path, e); return null; });
      jsonCache.set(path, p);
    }
    return jsonCache.get(path);
  }
  async function loadList(path, key){
    const data = await loadJSON(path);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data[key])) return data[key];
    return [];
  }

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
    const list = await loadList('./mirrors.json', 'mirrors');
    return list.map(m => ({ name: m.name || 'Netlify 主入口', url: sanitizeUrl(m.url) })).filter(m => m.url);
  }
  function renderMirrorsList(list) {
    if (!mirrorsContainer) return;
    if (!list.length) {
      mirrorsContainer.innerHTML = '<p>暂无镜像数据或加载失败</p>';
      return;
    }
    const html = list.map(m => `<a class="btn" href="${attrUrl(m.url)}" target="_blank" rel="noopener noreferrer">${esc(m.name)}</a>`).join('');
    mirrorsContainer.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;">${html}</div>`;
  }

  // 教程专区：加载 tutorials-extra.json 并渲染
  const tutorialGrid = document.getElementById('tutorialGrid');
  async function loadExtraTutorials() {
    return loadList('./tutorials-extra.json', 'tutorials');
  }
  function renderTutorials(items) {
    if (!tutorialGrid) return;
    tutorialGrid.innerHTML = '';
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const local = sanitizeUrl(d.local);
      const websiteBtn = website ? `<a class="btn" href="${attrUrl(website)}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const localBtn = local ? `<a class="btn primary" href="${attrUrl(local)}" target="_blank" rel="noopener noreferrer">本地教程</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${esc(d.name || '未命名教程')}</h4>
        <p>${esc(d.desc || '')}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <span class="chip">${esc(d.category || 'docs')}</span>
          ${websiteBtn}
          ${localBtn}
          ${tagsChips}
        </div>
      `;
      tutorialGrid.appendChild(el);
    });
  }

  // 官方站点快捷跳转：复用 mirrors.json 的同一份数据（不再重复请求）
  const officialGrid = document.getElementById('officialGrid');
  function renderOfficialList(items) {
    if (!officialGrid) return;
    officialGrid.innerHTML = '';
    if (!items.length) {
      officialGrid.innerHTML = '<p>暂无官方链接</p>';
      return;
    }
    const html = items.map(d => `<a class="btn" href="${attrUrl(d.url)}" target="_blank" rel="noopener noreferrer">${esc(d.name)}</a>`).join('');
    officialGrid.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;">${html}</div>`;
  }

  // 软件下载：加载 softwares-extra.json 并渲染（支持搜索与标签筛选）
  const downloadGrid = document.getElementById('downloadGrid');
  const browserGrid = document.getElementById('browserGrid');
  const filterSelect = document.getElementById('filterSelect');
  const tagSelect = document.getElementById('tagSelect');
  const searchInput = document.getElementById('searchInput');
  async function loadExtraSoftware() {
    return loadList('./softwares-extra.json', 'software');
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
      const websiteBtn = website ? `<a class="btn" href="${attrUrl(website)}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      // 付费软件支持兑换与密钥文件下载（静态模式下不启用兑换）
      const isPaid = ((d.category || '').toLowerCase() === 'paid');
      const costVal = isPaid ? (parseInt(d.cost || 500, 10) || 500) : (parseInt(d.cost || 0, 10) || 0);
      const costChip = isPaid ? `<span class="chip">需积分：${costVal}</span>` : '';
      let redeemAttrs = '';
      const rid = String(d.redeemId || ('software-' + (d.id || (String(d.name||'').toLowerCase().replace(/\s+/g,'-')))));
      const bonusFilename = String(d.bonusFilename || '').replace(/`/g,'');
      const bonusContent = String(d.bonusContent || '');
      if (!isStatic() && (isPaid || d.cost)) {
        redeemAttrs = ` data-action="redeem" data-redeem-id="${esc(rid)}" data-redeem-cost="${String(costVal || d.cost || 500)}" data-bonus-filename="${esc(bonusFilename)}" data-bonus-content="${esc(bonusContent)}"`;
      }
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${attrUrl(direct)}" ${(!isPaid && isStatic() && isLikelyFileUrl(direct)) ? `download="${esc(suggestFileNameFrom(d, direct))}"` : ''} rel="noopener noreferrer"${redeemAttrs}>${(!isPaid && isLikelyFileUrl(direct))?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${esc(d.name || '未命名软件')}</h4>
        <p>${esc(d.desc || '')}</p>
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
      const websiteBtn = website ? `<a class="btn" href="${attrUrl(website)}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${attrUrl(direct)}" ${ (isStatic() && isLikelyFileUrl(direct)) ? `download="${esc(suggestFileNameFrom(d, direct))}"` : '' } rel="noopener noreferrer">${isLikelyFileUrl(direct)?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${esc(d.name || '未命名软件')}</h4>
        <p>${esc(d.desc || '')}</p>
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
    filterSelect.innerHTML = '<option value="all">全部</option>' + cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
    // 标签下拉
    const tags = Array.from(new Set(list.filter(x => (x.category || 'software') !== 'browser').flatMap(x => Array.isArray(x.tags) ? x.tags : [])));
    tagSelect.innerHTML = '<option value="all">全部</option>' + tags.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
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
    // 下拉框只需要 change；搜索框才需要逐次 input（原来对三个控件同时绑定两种事件，多出 3 个无效监听）
    filterSelect.addEventListener('change', () => applyDownloadFilters(list));
    tagSelect.addEventListener('change', () => applyDownloadFilters(list));
    searchInput.addEventListener('input', () => applyDownloadFilters(list));
  }

  // 游戏专区：加载 games-extra.json 并按类别渲染
  const gameGridPlatforms = document.getElementById('gameGridPlatforms');
  const gameGridShooter = document.getElementById('gameGridShooter');
  const gameGridPaid = document.getElementById('gameGridPaid');
  const gameGridCard = document.getElementById('gameGridCard');
  const gameGridRPG = document.getElementById('gameGridRPG');
  const gameGridSandbox = document.getElementById('gameGridSandbox');
  const gameGridMini = document.getElementById('gameGridMini');
  async function loadExtraGames() {
    return loadList('./games-extra.json', 'games');
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
    // 数据中的 URL 统一走公共 sanitizeUrl / attrUrl，不再重复定义局部函数
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const direct = sanitizeUrl(d.direct);
      const playUrl = sanitizeUrl(d.play);
      const websiteBtn = website ? `<a class="btn" href="${attrUrl(website)}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const isMini = ((d.category || '').toLowerCase() === 'minigame');
      const local = sanitizeUrl(d.local);
      const play1p = sanitizeUrl(d.play1p);
      const play2p = sanitizeUrl(d.play2p);
      const localBtn = (local && !(isMini && local === play1p)) ? `<a class="btn primary" href="${attrUrl(local)}" target="_blank" rel="noopener noreferrer">本网资源</a>` : '';
      // 小游戏：统一渲染「单人模式 / 双人模式」入口（站内 arcade.html 或外站）
      let modeBtns = '';
      let modeChips = '';
      if (isMini) {
        const modes = Array.isArray(d.modes) ? d.modes : (play2p ? ['1p', '2p'] : ['1p']);
        modeChips = modes.map(m => `<span class="chip">${m === '2p' ? '双人' : '单人'}</span>`).join('');
        if (play1p) modeBtns += `<a class="btn primary" href="${attrUrl(play1p)}">单人模式</a>`;
        if (play2p) modeBtns += `<a class="btn" href="${attrUrl(play2p)}">双人模式</a>`;
        const extPlay = sanitizeUrl(d.play);
        if (!play1p && extPlay) modeBtns += `<a class="btn primary" href="${attrUrl(extPlay)}" target="_blank" rel="noopener noreferrer">开始游戏</a>`;
      }
      // 非 minigame：同源内嵌不再显示「本站游玩」按钮；跨域 embed 保留「云玩」
      const effectivePlay = isMini ? '' : (sanitizeUrl(d.embedUrl) || playUrl);
      let cloudBtn = '';
      if (effectivePlay) {
        try {
          const u = new URL(effectivePlay, window.location.href);
          if (u.origin !== window.location.origin) {
            cloudBtn = `<button class="btn" data-play="${attrUrl(effectivePlay)}" data-play-name="${esc(d.name||'云玩')}" ${ (d.embed || d.embedUrl) ? 'data-play-embed="1"' : '' }>云玩</button>`;
          }
        } catch (_) {}
      }
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
          redeemAttrs = ` data-action="redeem" data-redeem-id="${esc(rid)}" data-redeem-cost="${String(costVal || d.cost || 500)}" data-bonus-filename="${esc(bonusFilename)}" data-bonus-content="${esc(bonusContent)}"`;
        }
      }
      const directBtn = direct ? `<a class="btn primary ${isStatic()?'':'requires-auth'}" href="${attrUrl(direct)}" rel="noopener noreferrer"${redeemAttrs}>直接安装</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${esc(d.name || '未命名游戏')}</h4>
        <p>${esc(d.desc || '')}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${costChip}
          ${websiteBtn}
          ${localBtn}
          ${modeBtns}
          ${cloudBtn}
          ${directBtn}
          ${tagsChips}
          ${modeChips}
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
    const mini = items.filter(d => (d.category || '').toLowerCase() === 'minigame');
    renderGameList(gameGridPlatforms, platforms);
    renderGameList(gameGridPaid, paid);
    renderGameList(gameGridShooter, shooter);
    renderGameList(gameGridCard, card);
    renderGameList(gameGridRPG, rpg);
    renderGameList(gameGridSandbox, sandbox);
    renderGameList(gameGridMini, mini);
  }

  // 虚拟机与系统镜像：加载 downloads-extra.json 并渲染
  const vmGrid = document.getElementById('vmGrid');
  const osGrid = document.getElementById('osGrid');
  async function loadDownloadsExtra() {
    const data = await loadJSON('./downloads-extra.json');
    if (Array.isArray(data)) {
      return { vm: data.filter(x => x.category === 'vm'), os: data.filter(x => x.category === 'os') };
    }
    return { vm: data && Array.isArray(data.vm) ? data.vm : [], os: data && Array.isArray(data.os) ? data.os : [] };
  }
  // 虚拟机 / 系统镜像两个区块结构完全一致，合并为一个渲染函数
  function renderZone(gridEl, items, emptyText) {
    if (!gridEl) return;
    gridEl.innerHTML = '';
    if (!items || !items.length) {
      gridEl.innerHTML = `<p>${esc(emptyText)}</p>`;
      return;
    }
    items.forEach(d => {
      const el = document.createElement('div');
      el.className = 'card';
      const website = sanitizeUrl(d.website);
      const direct = sanitizeUrl(d.direct);
      const websiteBtn = website ? `<a class="btn" href="${attrUrl(website)}" target="_blank" rel="noopener noreferrer">官网</a>` : '';
      const directBtn = direct ? `<a class="btn ${isStatic()?'':'requires-auth'}" href="${attrUrl(direct)}" ${ (isStatic() && isLikelyFileUrl(direct)) ? `download="${esc(suggestFileNameFrom(d, direct))}"` : '' } rel="noopener noreferrer">${isLikelyFileUrl(direct)?'直接下载':'直接安装'}</a>` : '';
      const tagsChips = Array.isArray(d.tags) ? d.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      el.innerHTML = `
        <h4>${esc(d.name || '未命名')}</h4>
        <p>${esc(d.desc || '')}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          ${websiteBtn}
          ${directBtn}
          ${tagsChips}
        </div>
      `;
      gridEl.appendChild(el);
    });
  }
  function renderVMZone(items) { renderZone(vmGrid, items, '暂无虚拟机数据'); }
  function renderOSZone(items) { renderZone(osGrid, items, '暂无系统镜像数据'); }

  // 网页游戏精选：webgames.json 中允许 iframe 嵌入的条目，整合进游戏专区
  async function loadWebgames() {
    try {
      const r = await fetch('./webgames.json', { cache: 'no-cache' });
      if (!r.ok) return null;
      return await r.json();
    } catch (_) { return null; }
  }
  function renderWebgamesPicks(data) {
    const grid = document.getElementById('webgamesGrid');
    if (!grid || !data || !Array.isArray(data.items)) return;
    const picks = data.items.filter(x => x.embeddable && x.play);
    grid.innerHTML = '';
    if (!picks.length) { grid.innerHTML = '<p>暂无可站内畅玩的网页游戏</p>'; return; }
    picks.forEach(it => {
      const el = document.createElement('div');
      el.className = 'card';
      const tags = Array.isArray(it.tags) ? it.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('') : '';
      const need = it.need === 'files' ? '<span class="chip">需自备游戏文件</span>' : '';
      el.innerHTML = `
        <h4>${esc(it.name)}</h4>
        <p>${esc(it.desc || '')}</p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <a class="btn primary" href="webgames.html?play=${encodeURIComponent(it.id)}">本站开玩</a>
          <a class="btn" href="${attrUrl(it.play)}" target="_blank" rel="noopener noreferrer">原始页面</a>
          ${need}
          ${tags}
        </div>
      `;
      grid.appendChild(el);
    });
  }

  // 初始化：所有数据源并发请求（原来 6 次串行 await，首屏会明显变慢）
  (async function init(){
    const [mirrorList, tutorials, software, games, dl, wg] = await Promise.all([
      loadMirrors(),
      loadExtraTutorials(),
      loadExtraSoftware(),
      loadExtraGames(),
      loadDownloadsExtra(),
      loadWebgames()
    ]);

    renderMirrorsList(mirrorList);
    renderTutorials(tutorials);
    renderOfficialList(mirrorList);

    // 软件下载（仅在 downloads.html 存在容器时生效）
    const browsers = software.filter(x => (x.category || 'software') === 'browser');
    const others = software.filter(x => (x.category || 'software') !== 'browser');
    setupDownloadFilters(others);
    wireDownloadControls(others);
    applyDownloadFilters(others);
    renderBrowserCards(browsers);

    renderGames(games);
    renderWebgamesPicks(wg);
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
  // 本地日期（YYYY-MM-DD）。原来用 toISOString() 取的是 UTC 日期，
  // 在东八区会导致每日任务直到早上 8 点才重置，与“今天”的直觉不符。
  const dayKey = () => {
    const d = new Date();
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  };
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
  /* ===================== 用户系统（本地版） =====================
     本站是纯静态站点，没有服务端。账号只保存在当前浏览器的 localStorage。
     密码以 PBKDF2-SHA256（随机盐 + 12 万次迭代）摘要后存储，不保存明文；
     这只是提高本地查看成本，不等同于服务端认证的安全性。
     加密不可用时（例如 file:// 非安全上下文）自动降级为弱摘要，并在账号记录中标记。
  ============================================================ */
  const ALGO_STRONG = 'PBKDF2-SHA256-120k';
  const ALGO_WEAK = 'WEAK-FNV';
  const SESSION_TTL_REMEMBER = 30 * 24 * 3600 * 1000; // 记住我：30 天
  const SESSION_TTL_DEFAULT = 12 * 3600 * 1000;       // 默认：12 小时
  const MAX_FAILS = 5;
  const LOCK_MS = 60 * 1000;
  const AUTH_EVENT = 'niao:authchange';

  function emitAuth(user){
    try { window.dispatchEvent(new CustomEvent(AUTH_EVENT, { detail: { user: user || '' } })); } catch(_) {}
  }

  function randomHex(bytes){
    const arr = new Uint8Array(bytes);
    if (window.crypto && crypto.getRandomValues) {
      crypto.getRandomValues(arr);
    } else {
      for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // 弱摘要仅用于无 WebCrypto 的降级场景
  function weakDigest(str){
    let h1 = 0x811c9dc5, h2 = 0x1000193;
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      h1 = ((h1 ^ c) * 16777619) >>> 0;
      h2 = ((h2 * 33) ^ c) >>> 0;
    }
    return ('00000000' + h1.toString(16)).slice(-8) + ('00000000' + h2.toString(16)).slice(-8);
  }

  async function digestPassword(password, salt, algo){
    if (algo === ALGO_WEAK || !(window.crypto && crypto.subtle && crypto.subtle.importKey)) {
      return { hash: weakDigest(salt + '::' + password), algo: ALGO_WEAK };
    }
    try {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: enc.encode(salt), iterations: 120000, hash: 'SHA-256' },
        keyMaterial, 256
      );
      return {
        hash: Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join(''),
        algo: ALGO_STRONG
      };
    } catch(_) {
      return { hash: weakDigest(salt + '::' + password), algo: ALGO_WEAK };
    }
  }

  function safeEqual(a, b){
    a = String(a || ''); b = String(b || '');
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  const RULES = {
    username(v){
      v = String(v || '');
      if (!v) return '请输入用户名';
      if (v.length < 2) return '用户名至少 2 个字符';
      if (v.length > 20) return '用户名不能超过 20 个字符';
      if (!/^[A-Za-z0-9_\u4e00-\u9fa5]+$/.test(v)) return '用户名只能包含字母、数字、下划线或中文';
      return '';
    },
    password(v){
      v = String(v || '');
      if (!v) return '请输入密码';
      if (v.length < 6) return '密码至少 6 位';
      if (v.length > 64) return '密码不能超过 64 位';
      return '';
    }
  };

  function readUsers(){
    const u = readJSON(KEYS.USERS, {});
    return (u && typeof u === 'object' && !Array.isArray(u)) ? u : {};
  }
  function guardKey(u){ return 'niao.auth.guard.' + String(u || '').toLowerCase(); }
  function readGuard(u){
    const g = readJSON(guardKey(u), { fails: 0, until: 0 });
    return { fails: parseInt(g && g.fails, 10) || 0, until: parseInt(g && g.until, 10) || 0 };
  }
  function writeGuard(u, val){ writeJSON(guardKey(u), val); }

  const Auth = {
    lastError: null,

    /** 读取当前会话对象（内部使用，自动处理过期） */
    session(){
      const raw = readRaw(KEYS.SESSION, '');
      if (!raw) return null;
      if (raw.charAt(0) === '{') {
        try { return JSON.parse(raw); } catch(_) { return null; }
      }
      // 兼容旧版本：键里直接存的是用户名
      return { u: raw, ts: 0, exp: 0 };
    },

    getSessionUser(){
      const s = this.session();
      if (!s || !s.u) return '';
      if (s.exp && Date.now() > s.exp) {
        this.logout({ silent: true, reason: 'expired' });
        return '';
      }
      return String(s.u);
    },

    /** 是否已登录，并返回剩余有效时长（毫秒） */
    sessionInfo(){
      const s = this.session();
      if (!s || !s.u) return { user: '', expiresIn: 0, remember: false };
      const left = s.exp ? Math.max(0, s.exp - Date.now()) : 0;
      return { user: String(s.u), expiresIn: left, remember: !!s.remember };
    },

    /** 注册：返回 { ok, code, msg } */
    async registerEx(username, password, confirmPassword){
      const u = String(username || '').trim();
      const p = String(password || '');
      const p2 = confirmPassword == null ? p : String(confirmPassword);

      const errU = RULES.username(u);
      if (errU) return { ok: false, code: 'INVALID_USERNAME', msg: errU };
      const errP = RULES.password(p);
      if (errP) return { ok: false, code: 'INVALID_PASSWORD', msg: errP };
      if (p !== p2) return { ok: false, code: 'PASSWORD_MISMATCH', msg: '两次输入的密码不一致' };

      if (isStatic()) {
        const users = readUsers();
        if (users[u]) return { ok: false, code: 'USER_EXISTS', msg: '该用户名已被注册，请直接登录' };
        const salt = randomHex(16);
        const d = await digestPassword(p, salt);
        users[u] = { v: 2, salt: salt, hash: d.hash, algo: d.algo, createdAt: Date.now() };
        writeJSON(KEYS.USERS, users);
        return { ok: true, code: 'OK', msg: '注册成功，正在为你登录…', user: u };
      }

      try {
        const resp = await fetch(API_BASE + '/api/register', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p })
        });
        const data = await resp.json().catch(() => ({}));
        return data && data.ok
          ? { ok: true, code: 'OK', msg: '注册成功，请登录' }
          : { ok: false, code: 'SERVER', msg: (data && data.msg) || '注册失败，请稍后重试' };
      } catch(_) {
        return { ok: false, code: 'NETWORK', msg: '网络异常，无法连接服务端' };
      }
    },

    /** 登录：返回 { ok, code, msg, user } */
    async loginEx(username, password, opts){
      const u = String(username || '').trim();
      const p = String(password || '');
      const remember = !!(opts && opts.remember);

      const errU = RULES.username(u);
      if (errU) return { ok: false, code: 'INVALID_USERNAME', msg: errU };
      if (!p) return { ok: false, code: 'INVALID_PASSWORD', msg: '请输入密码' };

      const g = readGuard(u);
      if (g.until > Date.now()) {
        const left = Math.ceil((g.until - Date.now()) / 1000);
        return { ok: false, code: 'LOCKED', msg: `尝试次数过多，请 ${left} 秒后再试` };
      }

      const fail = (code, msg) => {
        const fails = g.fails + 1;
        const until = fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0;
        writeGuard(u, { fails: until ? 0 : fails, until: until });
        const left = MAX_FAILS - fails;
        return {
          ok: false, code: code,
          msg: until ? `尝试次数过多，已锁定 ${LOCK_MS / 1000} 秒` : (left > 0 ? msg + `（还可尝试 ${left} 次）` : msg)
        };
      };

      if (isStatic()) {
        const users = readUsers();
        const rec = users[u];
        if (!rec) return fail('USER_NOT_FOUND', '该用户名尚未注册');

        // 旧版本明文记录：校验通过后自动升级为摘要存储
        if (rec.pass != null) {
          if (String(rec.pass) !== p) return fail('BAD_CREDENTIALS', '密码不正确');
          const salt = randomHex(16);
          const d = await digestPassword(p, salt);
          users[u] = { v: 2, salt: salt, hash: d.hash, algo: d.algo, createdAt: rec.createdAt || Date.now() };
          writeJSON(KEYS.USERS, users);
        } else {
          const d = await digestPassword(p, rec.salt || '', rec.algo || ALGO_STRONG);
          if (!safeEqual(d.hash, rec.hash)) return fail('BAD_CREDENTIALS', '密码不正确');
        }

        writeGuard(u, { fails: 0, until: 0 });
        const ttl = remember ? SESSION_TTL_REMEMBER : SESSION_TTL_DEFAULT;
        writeJSON(KEYS.SESSION, { u: u, ts: Date.now(), exp: Date.now() + ttl, remember: remember });
        writeRaw('niao.auth.token', 'local');
        emitAuth(u);
        return { ok: true, code: 'OK', msg: '登录成功', user: u };
      }

      try {
        const resp = await fetch(API_BASE + '/api/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p })
        });
        const data = await resp.json().catch(() => ({}));
        if (data && data.ok && data.token) {
          writeRaw('niao.auth.token', data.token);
          writeJSON(KEYS.SESSION, { u: data.username || u, ts: Date.now(), exp: Date.now() + SESSION_TTL_DEFAULT, remember: remember });
          writeGuard(u, { fails: 0, until: 0 });
          emitAuth(data.username || u);
          return { ok: true, code: 'OK', msg: '登录成功', user: data.username || u };
        }
        return fail('BAD_CREDENTIALS', '用户名或密码错误');
      } catch(_) {
        return { ok: false, code: 'NETWORK', msg: '网络异常，无法连接服务端' };
      }
    },

    /** 兼容旧调用方：返回布尔值 */
    async register(u, p){
      const r = await this.registerEx(u, p);
      this.lastError = r.ok ? null : r;
      return !!r.ok;
    },
    async login(u, p, opts){
      const r = await this.loginEx(u, p, opts);
      this.lastError = r.ok ? null : r;
      return !!r.ok;
    },

    logout(opts){
      const wasLoggedIn = !!this.getSessionUser();
      writeRaw('niao.auth.token', '');
      try { localStorage.removeItem(KEYS.SESSION); } catch(_) {}
      if (!(opts && opts.silent)) emitAuth('');
      return wasLoggedIn;
    },

    getToken(){ return String(readRaw('niao.auth.token', '') || ''); },
    isDev(u){ u = String(u || this.getSessionUser() || ''); return u === 'Yuan' || u === 'niaoguo'; },

    async getPoints(u){
      if (isStatic()) {
        const key = KEYS.POINTS_PREFIX + String(u || '');
        return parseInt(readRaw(key, '0'), 10) || 0;
      }
      const token = this.getToken(); if (!token) return 0;
      try {
        const resp = await fetch(API_BASE + '/api/points?token=' + encodeURIComponent(token));
        const d = await resp.json();
        return d.points || 0;
      } catch(_) { return 0; }
    },

    async addPoints(u, n, reason){
      if (isStatic()) {
        u = String(u || '');
        const key = KEYS.POINTS_PREFIX + u;
        const cur = parseInt(readRaw(key, '0'), 10) || 0;
        const next = (cur + (n || 0));
        writeRaw(key, String(Math.max(0, next)));
        return;
      }
      const token = this.getToken(); if (!token) return;
      try { await fetch(API_BASE + '/api/points/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, amount: n || 0, reason: reason || 'manual' }) }); } catch(_) {}
    },

    async redeem(rid, cost){
      rid = String(rid || '');
      cost = parseInt(cost || 0, 10) || 0;
      if (!rid || cost <= 0) return false;
      if (isStatic()) {
        const u = this.getSessionUser();
        if (!u) return false;
        const key = KEYS.POINTS_PREFIX + u;
        const cur = parseInt(readRaw(key, '0'), 10) || 0;
        if (cur < cost) return false;
        writeRaw(key, String(cur - cost));
        return true;
      }
      const token = this.getToken(); if (!token) return false;
      try {
        const resp = await fetch(API_BASE + '/api/redeem', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, rid, cost }) });
        const data = await resp.json();
        return !!(data && data.ok);
      } catch(_) { return false; }
    },

    async redeemCode(code){
      code = String(code || '').trim();
      if (!code) return { ok: false, msg: '请输入兑换码' };
      if (isStatic()) return { ok: false, msg: '当前为静态模式，暂不支持兑换码' };
      const token = this.getToken();
      if (!token) return { ok: false, msg: '请先登录' };
      try {
        const resp = await fetch(API_BASE + '/api/redeem-code', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, code }) });
        const data = await resp.json();
        if (data && data.ok) {
          return { ok: true, msg: data.msg || '兑换成功', pointsAdded: data.pointsAdded || 0, points: data.points, ridGranted: data.ridGranted || '' };
        }
        return { ok: false, msg: (data && data.msg) || '兑换失败' };
      } catch(_) {
        return { ok: false, msg: '网络错误' };
      }
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
    // 进度按“用户 + 天”记录：同一浏览器切换账号时不会互相占用当天的 5 积分
    progressKey(){ const u = Auth.getSessionUser(); return u ? (KEYS.DAILY_PROGRESS_PREFIX + u + '.' + dayKey()) : (KEYS.DAILY_PROGRESS_PREFIX + dayKey()); },
    getProgressSec(){ return parseInt(readRaw(this.progressKey(), '0'), 10) || 0; },
    setProgressSec(sec){ writeRaw(this.progressKey(), String(sec)); },
    isCompletedFor(user){ user = String(user||''); if (!user) return false; return readRaw(KEYS.DAILY_COMPLETED_PREFIX + user + '.' + dayKey(), '') === '1'; },
    markCompleted(user){ user = String(user||''); if (!user) return; writeRaw(KEYS.DAILY_COMPLETED_PREFIX + user + '.' + dayKey(), '1'); },
    tick(){
      const u = Auth.getSessionUser();
      // 未登录不计时：原来会先把时长累计进去，任何新账号登录后立刻白拿 5 积分
      if (!u) { this.updateUI(); return; }
      const sec = this.getProgressSec();
      if (sec >= this.DURATION_SEC) { this.updateUI(); return; }
      const next = Math.min(this.DURATION_SEC, sec + 1);
      this.setProgressSec(next);
      if (next >= this.DURATION_SEC && !this.isCompletedFor(u)) {
        this.markCompleted(u);
        Auth.addPoints(u, 5, 'daily5min');
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

  /* ===================== 登录 / 注册弹窗 ===================== */
  const Gate = {
    overlayId: 'niao-auth-overlay',
    mode: 'login',
    _busy: false,

    ensure(){
      if (document.getElementById(this.overlayId)) return;
      const div = document.createElement('div');
      div.id = this.overlayId;
      div.className = 'auth-overlay';
      div.innerHTML = `
        <div class="auth-modal" role="dialog" aria-modal="true" aria-labelledby="authTitle">
          <button class="auth-close" id="authClose" type="button" aria-label="关闭">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          </button>

          <div class="auth-head">
            <span class="auth-logo" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none"><path d="M12 3.2c3.1 0 5.6 2.4 5.6 5.4 0 2-1 3.7-2.6 4.7l1.6 6.4-4.6-2.6-4.6 2.6 1.6-6.4A5.5 5.5 0 0 1 6.4 8.6C6.4 5.6 8.9 3.2 12 3.2Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><circle cx="9.9" cy="8.3" r=".9" fill="currentColor"/></svg>
            </span>
            <h3 class="auth-title" id="authTitle">登录鸟国账号</h3>
            <p class="auth-sub" id="authSub">登录后可累计积分、记录搜索与任务进度</p>
          </div>

          <div class="auth-tabs" role="tablist" aria-label="登录或注册">
            <button class="auth-tab is-on" type="button" data-mode="login" role="tab" aria-selected="true">登录</button>
            <button class="auth-tab" type="button" data-mode="register" role="tab" aria-selected="false">注册</button>
            <span class="auth-tab__indicator" id="authTabBar" aria-hidden="true"></span>
          </div>

          <form class="auth-form" id="authForm" novalidate>
            <label class="field">
              <span class="field__label">用户名</span>
              <input class="field__input" id="authUser" name="username" type="text" autocomplete="username"
                     placeholder="2-20 位，字母 / 数字 / 下划线 / 中文" maxlength="20" />
            </label>

            <label class="field">
              <span class="field__label">密码</span>
              <span class="field__wrap">
                <input class="field__input" id="authPass" name="password" type="password" autocomplete="current-password"
                       placeholder="至少 6 位" maxlength="64" />
                <button class="field__eye" id="authEye" type="button" aria-label="显示密码">显示</button>
              </span>
            </label>

            <label class="field" id="authConfirmField" hidden>
              <span class="field__label">确认密码</span>
              <input class="field__input" id="authPass2" name="password2" type="password" autocomplete="new-password"
                     placeholder="再输入一次密码" maxlength="64" />
            </label>

            <label class="check" id="authRememberRow">
              <input type="checkbox" id="authRemember" checked />
              <span>30 天内保持登录</span>
            </label>

            <p class="auth-err" id="authErr" role="alert" aria-live="assertive" hidden></p>

            <button class="btn primary auth-submit" id="authSubmit" type="submit">
              <span class="auth-submit__text">登录</span>
              <span class="auth-submit__spin" aria-hidden="true"></span>
            </button>
          </form>

          <div class="auth-account" id="authAccount" hidden>
            <div class="auth-account__row">
              <span class="auth-account__avatar" id="authAvatar">U</span>
              <div class="auth-account__meta">
                <p class="auth-account__name" id="authAccountName">未登录</p>
                <p class="auth-account__sub" id="authAccountSub"></p>
              </div>
              <span class="auth-account__points" id="authAccountPoints">0<em>积分</em></span>
            </div>
            <div class="auth-account__actions">
              <a class="btn" href="user.html">用户中心</a>
              <button class="btn" id="authLogout" type="button">退出登录</button>
            </div>
          </div>

          <p class="auth-foot">纯静态站点：账号与积分仅保存在当前浏览器，不会上传到任何服务器。</p>
        </div>`;
      document.body.appendChild(div);

      this.bind();
      this.render();
    },

    bind(){
      const q = (id) => document.getElementById(id);
      const overlay = document.getElementById(this.overlayId);
      const form = q('authForm');
      const err = q('authErr');
      const submit = q('authSubmit');
      const pass = q('authPass');
      const pass2 = q('authPass2');
      const user = q('authUser');
      const rememberRow = q('authRememberRow');
      const confirmField = q('authConfirmField');

      q('authClose').addEventListener('click', () => this.remove());
      overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) this.remove(); });

      if (!Gate._escBound) {
        Gate._escBound = true;
        document.addEventListener('keydown', (e) => {
          if (e.key === 'Escape' && document.getElementById(Gate.overlayId)) Gate.remove();
        });
      }

      overlay.querySelectorAll('.auth-tab').forEach((tab) => {
        tab.addEventListener('click', () => this.setMode(tab.getAttribute('data-mode')));
      });

      q('authEye').addEventListener('click', () => {
        const show = pass.type === 'password';
        pass.type = show ? 'text' : 'password';
        q('authEye').textContent = show ? '隐藏' : '显示';
        q('authEye').setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
      });

      [user, pass, pass2].forEach((el) => {
        el.addEventListener('input', () => {
          err.hidden = true;
          el.removeAttribute('aria-invalid');
        });
      });

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        this.submit();
      });

      q('authLogout').addEventListener('click', () => {
        Auth.logout();
        this.toast('已退出登录');
        this.render();
      });
    },

    setMode(mode){
      this.mode = mode === 'register' ? 'register' : 'login';
      const isReg = this.mode === 'register';
      const q = (id) => document.getElementById(id);
      document.getElementById(this.overlayId).querySelectorAll('.auth-tab').forEach((t) => {
        const on = t.getAttribute('data-mode') === this.mode;
        t.classList.toggle('is-on', on);
        t.setAttribute('aria-selected', String(on));
      });
      const bar = q('authTabBar');
      if (bar) bar.style.transform = isReg ? 'translateX(100%)' : 'translateX(0)';
      q('authConfirmField').hidden = !isReg;
      q('authRememberRow').hidden = isReg;
      q('authTitle').textContent = isReg ? '注册新账号' : '登录鸟国账号';
      q('authSub').textContent = isReg ? '账号保存在当前浏览器，不会上传到服务器' : '登录后可累计积分、记录搜索与任务进度';
      q('authSubmit').querySelector('.auth-submit__text').textContent = isReg ? '注册并登录' : '登录';
      q('authPass').setAttribute('autocomplete', isReg ? 'new-password' : 'current-password');
      q('authPass').placeholder = isReg ? '设置密码，至少 6 位' : '至少 6 位';
      q('authErr').hidden = true;
      const first = q('authUser');
      if (first) setTimeout(() => first.focus(), 60);
    },

    showError(msg, fieldId){
      const err = document.getElementById('authErr');
      if (!err) return;
      err.textContent = msg;
      err.hidden = false;
      if (fieldId) {
        const f = document.getElementById(fieldId);
        if (f) { f.setAttribute('aria-invalid', 'true'); f.focus(); }
      }
    },

    setBusy(on){
      this._busy = on;
      const btn = document.getElementById('authSubmit');
      if (!btn) return;
      btn.disabled = on;
      btn.classList.toggle('is-loading', on);
    },

    async submit(){
      if (this._busy) return;
      const q = (id) => document.getElementById(id);
      const u = q('authUser').value.trim();
      const p = q('authPass').value;
      const p2 = q('authPass2').value;
      const remember = q('authRemember').checked;

      // 前端先做一轮校验，避免无意义请求
      const errU = (u.length < 2) ? '请输入用户名（至少 2 个字符）'
        : (/^[A-Za-z0-9_\u4e00-\u9fa5]+$/.test(u) ? '' : '用户名只能包含字母、数字、下划线或中文');
      if (errU) return this.showError(errU, 'authUser');
      if (!p) return this.showError('请输入密码', 'authPass');
      if (p.length < 6) return this.showError('密码至少 6 位', 'authPass');
      if (this.mode === 'register' && p !== p2) return this.showError('两次输入的密码不一致', 'authPass2');

      this.setBusy(true);
      try {
        let res;
        if (this.mode === 'register') {
          res = await Auth.registerEx(u, p, p2);
          if (res.ok) {
            // 注册成功后直接登录，减少一次操作
            const login = await Auth.loginEx(u, p, { remember: true });
            res = login;
            if (login.ok) this.toast('注册成功，已自动登录');
          }
        } else {
          res = await Auth.loginEx(u, p, { remember: remember });
        }

        if (!res.ok) {
          const field = res.code === 'INVALID_USERNAME' ? 'authUser'
            : (res.code === 'INVALID_PASSWORD' || res.code === 'BAD_CREDENTIALS') ? 'authPass' : null;
          this.showError(res.msg || '操作失败，请重试', field);
          return;
        }

        this.toast(res.msg || '登录成功');
        this.render();
        setTimeout(() => { if (Auth.getSessionUser()) this.remove(); }, 420);
      } catch(e) {
        this.showError('操作失败：' + (e && e.message ? e.message : '未知错误'));
      } finally {
        this.setBusy(false);
      }
    },

    toast(msg){
      if (window.Niao && window.Niao.toast) { window.Niao.toast(msg); return; }
      let el = document.getElementById('niao-toast');
      if (!el) {
        el = document.createElement('div');
        el.id = 'niao-toast';
        el.className = 'niao-toast';
        document.body.appendChild(el);
      }
      el.textContent = msg;
      el.classList.add('is-on');
      clearTimeout(Gate._toastTimer);
      Gate._toastTimer = setTimeout(() => el.classList.remove('is-on'), 2200);
    },

    render(){
      const modal = document.getElementById(this.overlayId);
      if (!modal) return;
      const user = Auth.getSessionUser();
      const form = document.getElementById('authForm');
      const account = document.getElementById('authAccount');
      const tabs = modal.querySelector('.auth-tabs');

      if (user) {
        form.hidden = true;
        tabs.hidden = true;
        account.hidden = false;
        const titleEl = document.getElementById('authTitle');
        const subEl = document.getElementById('authSub');
        if (titleEl) titleEl.textContent = '我的账号';
        if (subEl) subEl.textContent = '登录状态、积分与本地数据都保存在当前浏览器';
        document.getElementById('authAccountName').textContent = user;
        const info = Auth.sessionInfo();
        const hours = info.expiresIn ? Math.max(1, Math.round(info.expiresIn / 3600000)) : 0;
        document.getElementById('authAccountSub').textContent =
          info.expiresIn ? `本次登录有效期剩余约 ${hours} 小时${info.remember ? '（已记住登录）' : ''}` : '本地账号';
        document.getElementById('authAvatar').textContent = user.slice(0, 1).toUpperCase();
        Auth.getPoints(user).then((p) => {
          const el = document.getElementById('authAccountPoints');
          if (el) el.innerHTML = String(p || 0) + '<em>积分</em>';
        }).catch(() => {});
      } else {
        form.hidden = false;
        tabs.hidden = false;
        account.hidden = true;
        this.setMode(this.mode);
      }
    },

    remove(){ const el = document.getElementById(this.overlayId); if (el) el.remove(); },

    open(mode){
      this.ensure();
      if (mode) this.setMode(mode);
      this.render();
      const modal = document.querySelector('.auth-modal');
      if (modal) {
        modal.classList.remove('is-in');
        void modal.offsetWidth;
        modal.classList.add('is-in');
      }
      const first = document.getElementById('authUser');
      if (first && !document.getElementById('authForm').hidden) setTimeout(() => first.focus(), 80);
    },

    update(){
      if (Auth.getSessionUser() && document.getElementById(this.overlayId)) this.render();
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
    // 主题切换放在顶栏右侧的独立操作位，不占用导航项，避免各页导航位置漂移
    if (!document.getElementById('navTheme')){
      const host = document.querySelector('.site-header .header-inner') || nav;
      if (host) {
        const themeLink = document.createElement('a');
        themeLink.href = '#';
        themeLink.id = 'navTheme';
        themeLink.className = 'nav-theme-toggle';
        themeLink.textContent = currentTheme === 'dark' ? '浅色' : '深色';
        themeLink.setAttribute('aria-label', '切换深色 / 浅色主题');
        host.appendChild(themeLink);
        themeLink.addEventListener('click', (e) => {
          e.preventDefault();
          currentTheme = (currentTheme === 'dark' ? 'light' : 'dark');
          applyTheme(currentTheme);
          themeLink.textContent = currentTheme === 'dark' ? '浅色' : '深色';
        });
      }
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

    // 顶栏登录态：未登录显示“登录”，已登录显示用户名（点击进入账号面板）
    function updateNavLogin(){
      const u = Auth.getSessionUser();
      if (!navLogin) return;
      navLogin.textContent = u || '登录';
      navLogin.setAttribute('data-mode', u ? 'account' : 'login');
      navLogin.setAttribute('title', u ? '账号与退出登录' : '登录 / 注册');
      navLogin.classList.toggle('is-authed', !!u);
      if (u) navLogin.setAttribute('aria-label', `已登录：${u}，点击查看账号`);
      else navLogin.removeAttribute('aria-label');
    }
    updateNavLogin();

    if (navLogin) navLogin.addEventListener('click', (e) => {
      e.preventDefault();
      const logged = !!Auth.getSessionUser();
      Gate.open(logged ? null : 'login');
      updateNavLogin();
    });

    // 登录状态变化（本页内 / 其它标签页）
    window.addEventListener('niao:authchange', () => {
      updateNavLogin();
      Gate.update();
      updateRedeemButtonStates();
    });
    window.addEventListener('storage', (e) => {
      if (e && (e.key === 'niao.auth.sessionUser' || !e.key)) {
        updateNavLogin();
        Gate.update();
        updateRedeemButtonStates();
      }
    });

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

    // 开发者 Alt+Ctrl 悬停重命名：在鼠标指向安装/下载按钮时按 Alt+Ctrl 设置文件名
    let __hoveredInstallEl = null;
    document.addEventListener('mouseover', (e) => {
      const el = e.target && e.target.closest ? e.target.closest('a.btn, a.requires-auth') : null;
      if (el) { __hoveredInstallEl = el; }
    });
    document.addEventListener('keydown', (e) => {
      if (!(e.ctrlKey && e.altKey)) return;
      const u = Auth.getSessionUser();
      if (!Auth.isDev(u)) return;
      const el = __hoveredInstallEl;
      if (!el) return;
      e.preventDefault();
      // 1) 文件名重命名（仅当前端、同源下载可直接生效）
      let curName = el.getAttribute('data-dev-rename') || el.getAttribute('download') || el.getAttribute('data-bonus-filename') || '';
      curName = curName || '兑换密钥.txt';
      const name = prompt('开发者重命名：输入新的安装文件名（仅文件名，不含路径）', curName);
      if (name) {
        // 简单清洗，移除路径分隔符与非法字符
        let safe = String(name).replace(/\\/g,'/').split('/').pop().trim();
        safe = safe.replace(/[\r\n\t\0]/g, '').replace(/^\.+/, '').slice(0, 80);
        if (safe) {
          el.setAttribute('data-dev-rename', safe);
          // 同源下载可直接设置 download 属性
          try { const href0 = el.getAttribute('href') || ''; if (href0 && new URL(href0).origin === window.location.origin) { el.setAttribute('download', safe); } } catch(_) {}
        }
      }
      // 2) 覆盖安装链接（全局生效，其他设备刷新后同步）
      const rid = (el.getAttribute('data-redeem-id') || '').trim();
      const currentHref = el.getAttribute('href') || '';
      const newHref = prompt('开发者覆盖安装链接（支持 http/https 或同源相对路径）。留空则不修改。', currentHref);
      if (newHref) {
        if (!rid) { alert('该按钮缺少资源 ID（data-redeem-id），暂不支持跨设备覆盖'); return; }
        const token = Auth.getToken();
        if (!token) { alert('请先登录开发者账号'); return; }
        const API_BASE = (window.Niao && window.Niao.config && window.Niao.config.apiBase) || 'http://localhost:5050';
        const payload = { token, rid, href: newHref, filename: (el.getAttribute('data-dev-rename') || ''), scope: 'global' };
        fetch(API_BASE + '/api/override/link', {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
        }).then(r => r.json()).then(d => {
          if (d && d.ok) {
            el.setAttribute('href', newHref);
            // 同源直接设置 download 名称
            try { const u0 = new URL(newHref, window.location.href); if (u0.origin === window.location.origin) {
              const rename = el.getAttribute('data-dev-rename') || '';
              if (rename) el.setAttribute('download', rename);
            }} catch(_) {}
            alert('已保存并应用到当前页面；其他设备刷新后生效');
          } else {
            alert('保存失败：' + (d && d.msg ? d.msg : '未知错误'));
          }
        }).catch(() => alert('网络错误，未能保存覆盖'));
      }
    });

    // 拉取并应用服务器端覆盖（跨设备生效）
    (async function fetchAndApplyOverrides(){
      try {
        const API_BASE = (window.Niao && window.Niao.config && window.Niao.config.apiBase) || 'http://localhost:5050';
        const token = Auth.getToken() || '';
        const url = API_BASE + '/api/overrides' + (token ? ('?token=' + encodeURIComponent(token)) : '');
        const r = await fetch(url);
        const d = await r.json();
        if (!d || !d.ok) return;
        const map = d.overrides || {};
        const anchors = Array.from(document.querySelectorAll('a.requires-auth[data-redeem-id]'));
        anchors.forEach(el => {
          const rid = (el.getAttribute('data-redeem-id') || '').trim();
          const ov = map[rid];
          if (ov && ov.href) {
            el.setAttribute('href', ov.href);
            if (ov.filename) el.setAttribute('data-bonus-filename', ov.filename);
            // 同源可立即设置 download
            try { const u1 = new URL(ov.href, window.location.href); if (u1.origin === window.location.origin && ov.filename) el.setAttribute('download', ov.filename); } catch(_) {}
          }
        });
      } catch(_) {}
    })();

    // 云玩：站内播放（优先在站内 iframe 打开，失败时回退新窗口）
    function ensurePlayModal(){
      if (document.getElementById('playModalBackdrop')) return;
      const backdrop = document.createElement('div');
      backdrop.id = 'playModalBackdrop';
      backdrop.className = 'play-modal-backdrop';
      const modal = document.createElement('div');
      modal.id = 'playModal';
      modal.className = 'play-modal';
      const header = document.createElement('div');
      header.className = 'play-modal-header';
      const title = document.createElement('span'); title.id='playModalTitle'; title.textContent='云玩';
      const actions = document.createElement('div'); actions.style.display='flex'; actions.style.gap='10px';
      const msg = document.createElement('span'); msg.id='playModalMsg'; msg.className='muted'; msg.style.fontSize='12px'; msg.style.flex='1'; msg.style.textAlign='center'; msg.style.margin='0 10px';
      const openNew = document.createElement('a'); openNew.href='#'; openNew.textContent='新窗口打开'; openNew.id='playModalOpenNew';
      const closeBtn = document.createElement('button'); closeBtn.className='btn'; closeBtn.id='playModalClose'; closeBtn.textContent='关闭';
      header.appendChild(title); header.appendChild(msg); header.appendChild(actions); actions.appendChild(openNew); actions.appendChild(closeBtn);
      const body = document.createElement('div'); body.className='play-modal-body';
      const iframe = document.createElement('iframe'); iframe.id='playIframe'; iframe.setAttribute('allowfullscreen',''); iframe.setAttribute('referrerpolicy','no-referrer');
      body.appendChild(iframe);
      modal.appendChild(header); modal.appendChild(body);
      backdrop.appendChild(modal);
      document.body.appendChild(backdrop);
      // 关闭与新开事件
      closeBtn.addEventListener('click', () => { try { iframe.src='about:blank'; } catch(_){} backdrop.style.display='none'; const m = document.getElementById('playModalMsg'); if (m) m.textContent=''; });
      openNew.addEventListener('click', (e) => {
        e.preventDefault(); const src = iframe.getAttribute('src')||''; if (!src) return;
        try { window.open(src, '_blank', 'noopener'); } catch(_) { window.location.href = src; }
      });
      // Esc 关闭
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { try { iframe.src='about:blank'; } catch(_){} backdrop.style.display='none'; const m = document.getElementById('playModalMsg'); if (m) m.textContent=''; }});
    }

    // 在站内游玩弹窗打开时，取消空格与上下键对网站的默认行为（防滚动/防页面动作）
    function isPlayModalVisible(){
      const backdrop = document.getElementById('playModalBackdrop');
      return !!(backdrop && window.getComputedStyle(backdrop).display !== 'none');
    }
    function blockSiteHotkeys(ev){
      if (!isPlayModalVisible()) return;
      const k = ev.key;
      if (k === ' ' || k === 'Spacebar' || k === 'ArrowUp' || k === 'Up' || k === 'ArrowDown' || k === 'Down'){
        ev.preventDefault();
        ev.stopPropagation();
      }
    }
    document.addEventListener('keydown', blockSiteHotkeys, { capture: true });
    document.addEventListener('keyup', blockSiteHotkeys, { capture: true });
    function openPlayModal(url, name){
      ensurePlayModal();
      const backdrop = document.getElementById('playModalBackdrop');
      const title = document.getElementById('playModalTitle');
      const iframe = document.getElementById('playIframe');
      const msg = document.getElementById('playModalMsg');
      try { title.textContent = String(name||'云玩'); } catch(_){}
      if (msg) msg.textContent = '正在尝试站内播放，如无法加载，请点击右上角“新窗口打开”。';
      backdrop.style.display = 'block';
      let loaded = false;
      const fallback = (reason) => {
        if (loaded) return;
        if (msg) msg.textContent = '该站点不允许内嵌，已为你在新窗口打开。';
        try { window.open(url, '_blank', 'noopener'); } catch(_) { window.location.href = url; }
        backdrop.style.display='none';
        try { iframe.src='about:blank'; } catch(_){}
      };
      iframe.addEventListener('load', () => { loaded = true; if (msg) msg.textContent = ''; });
      iframe.addEventListener('error', () => { fallback('error'); }, { once: true });
      setTimeout(() => { if (!loaded) fallback('timeout'); }, 3800);
      try { iframe.src = url; } catch(_) { fallback('exception'); }
    }
    document.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('button[data-play]') : null;
      if (!btn) return;
      e.preventDefault();
      const url = btn.getAttribute('data-play') || '';
      const name = btn.getAttribute('data-play-name') || '';
      const embed = btn.hasAttribute('data-play-embed');
      if (!url) return;
      if (embed) { openPlayModal(url, name); }
      else { try { window.open(url, '_blank', 'noopener'); } catch(_) { window.location.href = url; } }
    });

    // 跨域直链安装：转到下载中心，由多线程下载器接管（可显示进度、可暂停）
    document.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('a.btn[href]') : null;
      if (!a) return;
      var href = a.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) return;
      if (!/\.(exe|msi|zip|7z|rar|apk|iso|dmg|pkg|deb|rpm|appimage|tar\.gz|tgz)(\?|#|$)/i.test(href)) return;
      var settings = (window.NiaoSettings && window.NiaoSettings.get) ? window.NiaoSettings.get() : {};
      if (settings['install.mode'] && settings['install.mode'] !== 'auto') return;
      var same = false;
      try { same = new URL(href).origin === window.location.origin; } catch (_) {}
      if (same) return; // 同源文件浏览器可直接下载
      e.preventDefault();
      var target = 'download.html?url=' + encodeURIComponent(href) +
        '&name=' + encodeURIComponent(a.getAttribute('download') || '');
      window.open(target, '_blank', 'noopener');
    }, true);

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
                const devRename = Auth.isDev(u) ? (el.getAttribute('data-dev-rename') || '') : '';
                const fname = devRename || el.getAttribute('data-bonus-filename') || '兑换密钥.txt';
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
                const devRename = Auth.isDev(u) ? (el.getAttribute('data-dev-rename') || '') : '';
                const href = API_BASE + '/api/key-file?token=' + encodeURIComponent(token) + '&rid=' + encodeURIComponent(rid) + (devRename ? ('&filename=' + encodeURIComponent(devRename)) : '');
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
            if (already === '1' || (legacy === '1' && Auth.isDev(u))) { openTarget(); return; }
            // 查询当前积分
            const pts = await Auth.getPoints(u);
            if ((pts||0) < cost) {
              alert(`积分不足，当前 ${pts||0}，需要 ${cost} 积分。请先通过每日任务等方式获取积分。`);
              updateRedeemButtonStates();
              return;
            }
            const ok = confirm(`购买前确认：需要消耗 ${cost} 积分进行兑换并跳转，是否确认？`);
            if (!ok) return;
            // 调用统一兑换接口（服务端校验余额并记录兑换）
            const okRedeem = await Auth.redeem(rid, cost);
            if (!okRedeem) {
              alert('兑换失败：积分不足或未登录。');
              updateRedeemButtonStates();
              return;
            }
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
  /* 全站统一的轻量反馈：任何页面都可以调用 Niao.toast('已保存','ok') */
  window.Niao.toast = function (msg, type) {
    var el = document.getElementById('niao-toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'niao-toast';
      document.body.appendChild(el);
    }
    el.className = 'niao-toast' + (type ? ' niao-toast--' + type : '');
    el.textContent = String(msg == null ? '' : msg);
    // 先移除再加类，保证连续提示也能重播过渡
    el.classList.remove('is-on');
    void el.offsetWidth;
    el.classList.add('is-on');
    clearTimeout(window.Niao._toastTimer);
    window.Niao._toastTimer = setTimeout(function () { el.classList.remove('is-on'); }, 2400);
  };

  /* 统一的按钮忙碌态：Niao.ui.busy(btn, true) / Niao.ui.busy(btn, false, '已保存') */
  window.Niao.ui = {
    toast: window.Niao.toast,
    busy: function (btn, on, text) {
      if (!btn) return;
      if (on) {
        if (!btn.dataset.idleText) btn.dataset.idleText = btn.textContent.trim();
        btn.classList.add('is-loading');
        btn.disabled = true;
        if (text) btn.textContent = text;
      } else {
        btn.classList.remove('is-loading');
        btn.disabled = false;
        if (text) btn.textContent = text;
        else if (btn.dataset.idleText) btn.textContent = btn.dataset.idleText;
      }
    }
  };

  window.Niao.auth = Auth;
  window.Niao.daily = Daily;
  window.Niao.gate = Gate;
  Gate.update();
  Daily.start();
})();

/* ============================================================
   全站动效层
   - 元素入场：IntersectionObserver 增量观察，动态渲染的卡片也能生效
   - 页面切换：站内 HTML 链接点击时先淡出再跳转
   - 性能：只用 opacity/transform，元素进入后立即 unobserve
   - 无障碍：prefers-reduced-motion 下完全跳过
   ============================================================ */
;(function(){
  'use strict';

  var reduce = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  var SELECTOR = '.card';
  var io = null;
  var raf = 0;
  var queue = [];
  var revealed = new WeakSet();

  function markVisible(el){
    if (!el || revealed.has(el)) return;
    revealed.add(el);
    el.classList.add('is-visible');
    if (io) io.unobserve(el);
  }

  function flush(){
    raf = 0;
    var batch = queue.splice(0, queue.length);
    batch.forEach(function(el, i){
      if (!el || revealed.has(el)) return;
      // 同屏元素错峰入场，最多 8 档，避免长延迟
      el.style.transitionDelay = Math.min(i % 8, 7) * 45 + 'ms';
      if (io) io.observe(el);
      else markVisible(el);
    });
  }

  function push(el){
    if (!el || revealed.has(el) || queue.indexOf(el) >= 0) return;
    if (el.nodeType !== 1) return;
    queue.push(el);
    if (!raf) raf = requestAnimationFrame(flush);
  }

  function collect(root){
    if (!root || root.nodeType !== 1) return;
    if (root.matches && root.matches(SELECTOR)) push(root);
    var nodes = root.querySelectorAll ? root.querySelectorAll(SELECTOR) : [];
    for (var i = 0; i < nodes.length; i++) push(nodes[i]);
  }

  function initReveal(){
    if (reduce) return;
    if (!('IntersectionObserver' in window)) return;

    document.documentElement.classList.add('js-motion');

    io = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if (!entry.isIntersecting) return;
        var el = entry.target;
        // 延迟归零，避免后续交互（如 hover）被 transition-delay 拖慢
        setTimeout(function(){ el.style.transitionDelay = ''; }, 600);
        markVisible(el);
      });
    }, { rootMargin: '0px 0px -6% 0px', threshold: 0.06 });

    collect(document);

    if ('MutationObserver' in window) {
      var mo = new MutationObserver(function(records){
        for (var i = 0; i < records.length; i++) {
          var added = records[i].addedNodes;
          for (var j = 0; j < added.length; j++) collect(added[j]);
        }
      });
      mo.observe(document.body, { childList: true, subtree: true });
    }

    // 兜底：任何原因导致观察未触发时，1.5s 后强制显示，避免内容不可见
    setTimeout(function(){
      document.querySelectorAll(SELECTOR).forEach(function(el){
        if (!revealed.has(el)) markVisible(el);
      });
    }, 1500);
  }

  function initPageTransition(){
    if (reduce) return;
    document.addEventListener('click', function(e){
      if (e.defaultPrevented || e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      var a = e.target && e.target.closest ? e.target.closest('a') : null;
      if (!a) return;
      if (a.target && a.target !== '_self') return;
      if (a.hasAttribute('download')) return;

      var href = a.getAttribute('href') || '';
      if (!href || href.charAt(0) === '#' || /^(javascript|mailto|tel):/i.test(href)) return;
      if (!/\.html(\?|#|$)/i.test(href)) return;

      var url;
      try { url = new URL(href, window.location.href); } catch(_) { return; }
      if (url.origin !== window.location.origin) return;
      if (url.pathname === window.location.pathname && url.search === window.location.search) return;

      e.preventDefault();
      document.documentElement.classList.add('is-leaving');
      setTimeout(function(){ window.location.href = url.href; }, 150);
    }, true);

    // 从缓存返回时恢复显示（bfcache）
    window.addEventListener('pageshow', function(){
      document.documentElement.classList.remove('is-leaving');
    });
  }

  function boot(){
    initReveal();
    initPageTransition();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();

/* ============================================================
   国内模式 · 本地代理设置（downloads.html）
   - 之前只有静态控件、没有绑定，按钮点了没反应
   - 这里补上保存 / 回填 / 状态反馈，复用全站设置存储 niao.settings.v1
   ============================================================ */
;(function () {
  'use strict';

  var SETTINGS_KEY = 'niao.settings.v1';
  var LEGACY_KEY = 'niao.proxy';

  function readAll() {
    try { return JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {}; } catch (_) { return {}; }
  }

  function writePatch(patch) {
    var all = readAll();
    Object.keys(patch).forEach(function (k) { all[k] = patch[k]; });
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(all)); return true; }
    catch (_) { return false; }
  }

  function readProxy() {
    var all = readAll();
    var on = all['download.proxyOn'];
    var url = all['download.proxyUrl'];
    if (on === undefined || url === undefined) {
      try {
        var legacy = JSON.parse(localStorage.getItem(LEGACY_KEY) || 'null');
        if (legacy) {
          if (on === undefined) on = !!legacy.on;
          if (url === undefined) url = legacy.url || '';
        }
      } catch (_) {}
    }
    return { on: !!on, url: url || '' };
  }

  function hostOf(url) {
    try { return new URL(url).host; } catch (_) { return String(url).slice(0, 24); }
  }

  function toast(msg, type) {
    if (window.Niao && typeof window.Niao.toast === 'function') window.Niao.toast(msg, type || 'ok');
  }

  function init() {
    var toggle = document.getElementById('cnModeToggle');
    var input = document.getElementById('proxyInput');
    var save = document.getElementById('proxySaveBtn');
    var status = document.getElementById('proxyStatus');
    if (!toggle || !input || !save || !status) return;
    if (save.getAttribute('data-bound') === '1') return;
    save.setAttribute('data-bound', '1');

    function setStatus(text, tone) {
      status.textContent = text;
      status.classList.remove('is-ok', 'is-error', 'warn');
      if (tone === 'ok') status.classList.add('is-ok');
      else if (tone === 'err') status.classList.add('is-error');
      else if (tone === 'warn') status.classList.add('warn');
    }

    function render() {
      var cfg = readProxy();
      toggle.checked = cfg.on;
      if (!input.value) input.value = cfg.url;
      if (!cfg.url) setStatus('代理未设置', 'warn');
      else if (cfg.on) setStatus('已启用 · ' + hostOf(cfg.url), 'ok');
      else setStatus('已保存，未启用 · ' + hostOf(cfg.url), null);
    }

    function validUrl(v) {
      return /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(v);
    }

    save.addEventListener('click', function () {
      var url = input.value.trim();
      if (url && !validUrl(url)) {
        setStatus('地址格式无效', 'err');
        toast('代理地址需以 http:// 或 https:// 开头', 'err');
        input.focus();
        return;
      }
      var on = url ? !!toggle.checked : false;
      var ok = writePatch({ 'download.proxyUrl': url, 'download.proxyOn': on });
      if (!ok) {
        setStatus('保存失败：本地存储不可用', 'err');
        toast('保存失败，请检查浏览器存储设置', 'err');
        return;
      }
      if (!url) {
        setStatus('代理未设置', 'warn');
        toast('已清空代理地址', 'ok');
      } else {
        setStatus(on ? '已启用 · ' + hostOf(url) : '已保存，未启用 · ' + hostOf(url), on ? 'ok' : null);
        toast(on ? '代理已保存并启用' : '代理地址已保存', 'ok');
      }
      save.classList.add('is-flash');
      setTimeout(function () { save.classList.remove('is-flash'); }, 500);
    });

    toggle.addEventListener('change', function () {
      var url = input.value.trim();
      if (toggle.checked && !url) {
        setStatus('先填写代理地址再启用', 'warn');
        toast('请先填写代理地址', 'err');
        input.focus();
        return;
      }
      writePatch({ 'download.proxyOn': !!toggle.checked, 'download.proxyUrl': url });
      render();
    });

    input.addEventListener('input', function () {
      if (!input.value.trim()) setStatus('代理未设置', 'warn');
      else setStatus(toggle.checked ? '待保存 · ' + hostOf(input.value.trim()) : '待保存', 'warn');
    });

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
