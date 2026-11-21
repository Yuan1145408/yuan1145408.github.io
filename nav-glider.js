/* ============================================================
   顶栏导航滑动指示条（nav glider）
   - 支持两套导航：.site-nav（主站） / .topnav（聚合搜索页）
   - 初始定位不做动画，之后切换/悬停平滑滑动
   - 悬停预览 + 点击先行反馈；键盘 Tab 聚焦也会跟随
   - 页面无 active 标记时退化为“仅悬停显示”，不会乱指
   - 尺寸变化（字体加载、用户名变长、窗口缩放）自动重算
   - prefers-reduced-motion 下保留状态但不做滑动动画
   零依赖，直接 <script src="nav-glider.js"></script> 引入即可。
   ============================================================ */
;(function () {
  'use strict';

  var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  var canHover = !(window.matchMedia && window.matchMedia('(hover: none)').matches);
  var NAVS = '.site-nav, .topnav';
  var LINK_SEL = 'a[href]';

  function fileOf(href) {
    try {
      var u = new URL(href, window.location.href);
      return u.pathname.split('/').pop() || 'index.html';
    } catch (_) {
      return '';
    }
  }

  function linksOf(nav) {
    return Array.prototype.slice.call(nav.querySelectorAll(LINK_SEL)).filter(function (a) {
      var h = a.getAttribute('href') || '';
      return h && h.charAt(0) !== '#';
    });
  }

  /* 当前页面对应的导航项：先看显式标记，再按文件名 / 前缀兜底 */
  function pickActive(nav) {
    var marked = nav.querySelector('a.active, a[aria-current="page"], a.is-active');
    if (marked) return marked;

    var here = window.location.pathname.split('/').pop() || 'index.html';
    var links = linksOf(nav);
    var i;

    for (i = 0; i < links.length; i++) {
      if (fileOf(links[i].getAttribute('href')) === here) return links[i];
    }
    // 子页面兜底：tutorial-*.html → 教程专区；minecraft.html → 游戏专区
    var fallback = /^tutorial-/.test(here) ? 'tutorials.html' : (/^minecraft\.html$/.test(here) ? 'games.html' : '');
    if (fallback) {
      for (i = 0; i < links.length; i++) {
        if (fileOf(links[i].getAttribute('href')) === fallback) return links[i];
      }
    }
    return null;
  }

  function setup(nav) {
    if (!nav || nav.getAttribute('data-glider') === '1') return;
    var active = pickActive(nav); // 可能为 null：该页无对应导航项

    nav.setAttribute('data-glider', '1');
    nav.classList.add('has-glider');

    var bar = document.createElement('span');
    bar.className = 'nav-glider';
    bar.setAttribute('aria-hidden', 'true');
    bar.appendChild(document.createElement('i'));
    nav.insertBefore(bar, nav.firstChild);

    var hovering = false;
    var rafId = 0;

    function paint(el, instant) {
      if (!el) return;
      var w = el.offsetWidth;
      var h = el.offsetHeight;
      if (!w || !h) return;
      if (instant) bar.classList.add('is-instant');
      bar.style.width = w + 'px';
      bar.style.height = h + 'px';
      bar.style.transform = 'translate3d(' + el.offsetLeft + 'px,' + el.offsetTop + 'px,0)';
      if (instant) {
        void bar.offsetWidth; // 强制回流，让过渡从新位置开始生效
        requestAnimationFrame(function () {
          requestAnimationFrame(function () { bar.classList.remove('is-instant'); });
        });
      }
    }

    function show() { bar.classList.add('is-on'); }
    function hide() { bar.classList.remove('is-on'); bar.classList.remove('is-preview'); }

    /* 初始：同步定位一次，避免滑块从左上角“飞”过来 */
    if (active) {
      bar.classList.add('is-instant');
      paint(active, false);
      nav.classList.add('is-ready');
      show();
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { bar.classList.remove('is-instant'); });
      });

      /* 导航初始滚动位置固定在最左：切页时上栏位置不跳，横向滚动交给用户 */
      nav.scrollLeft = 0;
    }

    function goTo(el, preview) {
      if (!el) return;
      bar.classList.toggle('is-preview', !!preview);
      paint(el, false);
      show();
    }

    function rest() {
      hovering = false;
      if (active) goTo(active, false);
      else hide();
    }

    function schedule() {
      if (rafId) return;
      rafId = requestAnimationFrame(function () {
        rafId = 0;
        if (hovering) paint(bar.classList.contains('is-preview') ? hoveredEl : active, false);
        else if (active) paint(active, false);
      });
    }

    var hoveredEl = null;

    /* 悬停预览：只在支持 hover 的设备上启用，触屏仍以选中态为准 */
    if (canHover) {
      nav.addEventListener('pointerover', function (e) {
        var a = e.target && e.target.closest ? e.target.closest(LINK_SEL) : null;
        if (!a || a.parentNode !== nav) return;
        hovering = true;
        hoveredEl = a;
        goTo(a, a !== active);
      });
      nav.addEventListener('pointerleave', rest);
    }

    /* 点击先行反馈：页面淡出前滑块先滑过去 */
    nav.addEventListener('pointerdown', function (e) {
      var a = e.target && e.target.closest ? e.target.closest(LINK_SEL) : null;
      if (!a || a.parentNode !== nav) return;
      if (a.getAttribute('href') === '#' || a.hasAttribute('download')) return;
      goTo(a, false);
    }, { passive: true });

    /* 键盘导航跟随焦点 */
    nav.addEventListener('focusin', function (e) {
      var a = e.target && e.target.closest ? e.target.closest(LINK_SEL) : null;
      if (a && a.parentNode === nav) goTo(a, false);
    });
    nav.addEventListener('focusout', function () { rest(); });

    window.addEventListener('resize', schedule, { passive: true });

    if (window.ResizeObserver) {
      var ro = new ResizeObserver(schedule);
      ro.observe(nav);
      if (active) ro.observe(active);
      // 登录后用户名可能变长，文字宽度变化也要跟随
      linksOf(nav).forEach(function (a) { ro.observe(a); });
    }

    /* 字体加载完成后文字宽度会变，补一次校准 */
    if (document.fonts && document.fonts.ready && document.fonts.ready.then) {
      document.fonts.ready.then(function () { if (active) paint(active, true); });
    }
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) schedule();
    });
  }

  function boot() {
    var navs = document.querySelectorAll(NAVS);
    for (var i = 0; i < navs.length; i++) setup(navs[i]);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
