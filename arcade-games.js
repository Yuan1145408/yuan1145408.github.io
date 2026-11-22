/* ============================================================
   站内小游戏 · 扩展包（单人 / 双人模式）
   ------------------------------------------------------------
   由 arcade.html 的 switchGame 调度：
   - window.ArcadeGames[key] = { modes, help, init(mode), stop() }
   - 通过 window.ArcadeAPI 与 arcade.html 主逻辑通信
     （得分、暂停、遮罩层、键盘 / 触屏输入转发）
   - 1p：与内置 AI 对战；2p：同屏双人（本地对战，不联网）
   ============================================================ */
(function () {
  'use strict';

  var api = null;
  function bind(a) { api = a; }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  /* ---------------- 双人贪吃蛇 snake2 ---------------- */
  var snake2 = {
    modes: ['2p'],
    help: '双人同屏：<kbd>W</kbd><kbd>A</kbd><kbd>S</kbd><kbd>D</kbd> 控制 1P（蓝蛇），方向键控制 2P（橙蛇）。撞墙、撞蛇或头对头相撞即输。',
    timer: null,
    init: function () { this.stop(); startSnake2(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startSnake2() {
    var cv = el('canvas');
    cv.width = 400; cv.height = 400;
    cv.id = 'snake2Canvas';
    cv.style.cssText = 'width:min(400px,84vw);height:auto;border-radius:12px;background:#0b1220;';
    api.stage().appendChild(cv);
    var ctx = cv.getContext('2d');
    var A = { body: [{x:5,y:10},{x:4,y:10},{x:3,y:10}], dir:{x:1,y:0}, pend:[], score:0, col:'#7cc4ff', dead:false };
    var B = { body: [{x:14,y:10},{x:15,y:10},{x:16,y:10}], dir:{x:-1,y:0}, pend:[], score:0, col:'#ffc457', dead:false };
    var food = null, over = false;

    function placeFood() {
      var taken = A.body.concat(B.body);
      do { food = { x: Math.floor(Math.random()*20), y: Math.floor(Math.random()*20) }; }
      while (taken.some(function(s){ return s.x===food.x && s.y===food.y; }));
    }
    function turn(p, dx, dy) {
      if (p.pend.length >= 2) return;
      var last = p.pend.length ? p.pend[p.pend.length-1] : p.dir;
      if (last.x === -dx && last.y === -dy) return;
      p.pend.push({x:dx, y:dy});
    }
    function step() {
      if (api.isPaused() || over) return;
      [A, B].forEach(function(p){
        if (p.pend.length) { p.dir = p.pend.shift(); }
        var head = { x: p.body[0].x + p.dir.x, y: p.body[0].y + p.dir.y };
        var all = A.body.concat(B.body);
        if (head.x<0 || head.y<0 || head.x>=20 || head.y>=20 ||
            all.some(function(s){ return s.x===head.x && s.y===head.y; })) {
          p.dead = true;
        } else {
          p.body.unshift(head);
          if (head.x===food.x && head.y===food.y) {
            p.score += 10;
            placeFood();
          } else {
            p.body.pop();
          }
        }
      });
      if (A.dead || B.dead) {
        over = true;
        snake2.stop();
        var msg = A.dead && B.dead ? '头对头相撞，平局！' : (A.dead ? '2P 获胜！' : '1P 获胜！');
        api.state('已结束');
        api.overlay(msg, '1P ' + A.score + ' 分 · 2P ' + B.score + ' 分', '再来一局', function(){ snake2.init(); });
        api.setScore(Math.max(A.score, B.score), 'snake2');
        api.best('snake2', Math.max(A.score, B.score));
      }
      draw();
    }
    function draw() {
      ctx.fillStyle = '#0b1220';
      ctx.fillRect(0,0,400,400);
      ctx.strokeStyle = 'rgba(120,160,255,.08)';
      for (var i=0;i<=20;i++){
        ctx.beginPath(); ctx.moveTo(i*20,0); ctx.lineTo(i*20,400); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0,i*20); ctx.lineTo(400,i*20); ctx.stroke();
      }
      ctx.fillStyle = '#ffd34d';
      ctx.beginPath();
      ctx.arc(food.x*20+10, food.y*20+10, 7, 0, Math.PI*2);
      ctx.fill();
      [A,B].forEach(function(p){
        p.body.forEach(function(s, i){
          ctx.fillStyle = i===0 ? p.col : (p.col === '#7cc4ff' ? 'rgba(77,163,255,'+Math.max(0.35,1-i*0.05)+')' : 'rgba(255,170,60,'+Math.max(0.35,1-i*0.05)+')');
          ctx.fillRect(s.x*20+1, s.y*20+1, 18, 18);
        });
      });
    }
    placeFood();
    api.state('进行中');
    api.setScore(0, 'snake2');
    api.overlayHide();
    snake2._key = function(e, k) {
      var m = { w:[0,-1], s:[0,1], a:[-1,0], d:[1,0] };
      if (m[k]) { turn(A, m[k][0], m[k][1]); return true; }
      if (k.indexOf('arrow') === 0) {
        var d = { arrowup:[0,-1], arrowdown:[0,1], arrowleft:[-1,0], arrowright:[1,0] }[k];
        turn(B, d[0], d[1]);
        return true;
      }
      return false;
    };
    snake2.timer = setInterval(step, 130);
    draw();
  }

  /* ---------------- 乒乓 Pong ---------------- */
  var pong = {
    modes: ['1p', '2p'],
    help: '单人：你控左板（<kbd>W</kbd>/<kbd>S</kbd> 或触屏上下），右侧是 AI。双人：左板 <kbd>W</kbd>/<kbd>S</kbd>，右板方向键。先得 7 分者胜。',
    timer: null,
    init: function (mode) { this.stop(); startPong(mode === '2p'); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startPong(twoP) {
    var cv = el('canvas');
    cv.width = 400; cv.height = 260;
    cv.style.cssText = 'width:min(400px,84vw);height:auto;border-radius:12px;background:#0b1220;';
    api.stage().appendChild(cv);
    var ctx = cv.getContext('2d');
    var PH = 56, PW = 8;
    var L = { y: 102, score: 0 }, R = { y: 102, score: 0 };
    var ball = { x: 200, y: 130, vx: 3.4, vy: 1.6 };
    var WIN = 7, over = false, keys = { up:false, down:false, w:false, s:false };

    function serve(dir) { ball.x = 200; ball.y = 130; ball.vx = 3.4 * dir; ball.vy = (Math.random()*3 - 1.5) || 1.2; }
    function step() {
      if (api.isPaused() || over) { draw(); return; }
      if (keys.w || keys.up) L.y -= 5;
      if (keys.s || keys.down) L.y += 5;
      L.y = Math.max(0, Math.min(260 - PH, L.y));
      if (twoP) {
        if (keys.up) R.y -= 5;
        if (keys.down) R.y += 5;
      } else {
        // AI：追球，速度略低于球垂直分量，留有失误空间
        var target = ball.vy > 0 ? ball.y : 130;
        if (R.y + PH/2 < target - 8) R.y += 4.2;
        else if (R.y + PH/2 > target + 8) R.y -= 4.2;
      }
      R.y = Math.max(0, Math.min(260 - PH, R.y));
      ball.x += ball.vx; ball.y += ball.vy;
      if (ball.y < 4 || ball.y > 256) { ball.vy = -ball.vy; ball.y = Math.max(4, Math.min(256, ball.y)); }
      // 碰板
      if (ball.vx < 0 && ball.x < 14+PW && ball.x > 10 && ball.y > L.y-6 && ball.y < L.y+PH+6) {
        ball.vx = -ball.vx * 1.03; ball.vy += (ball.y - (L.y + PH/2)) * 0.06;
      }
      if (ball.vx > 0 && ball.x > 386-PW && ball.x < 390 && ball.y > R.y-6 && ball.y < R.y+PH+6) {
        ball.vx = -ball.vx * 1.03; ball.vy += (ball.y - (R.y + PH/2)) * 0.06;
      }
      if (ball.x < -8) { R.score++; check(); serve(1); }
      if (ball.x > 408) { L.score++; check(); serve(-1); }
      api.setScore(L.score, 'pong');
      draw();
    }
    function check() {
      if (L.score >= WIN || R.score >= WIN) {
        over = true; pong.stop();
        var msg = twoP ? (L.score > R.score ? '1P 获胜！' : '2P 获胜！') : (L.score > R.score ? '你赢了！' : 'AI 获胜！');
        api.state('已结束');
        api.overlay(msg, '比分 ' + L.score + ' : ' + R.score, '再来一局', function(){ pong.init(twoP ? '2p' : '1p'); });
        api.best('pong', Math.max(L.score, R.score) * 10 + Math.min(L.score, R.score));
      } else {
        api.state('进行中 · ' + L.score + ' : ' + R.score);
      }
    }
    function draw() {
      ctx.fillStyle = '#0b1220'; ctx.fillRect(0,0,400,260);
      ctx.setLineDash([6, 8]); ctx.strokeStyle = 'rgba(255,255,255,.18)';
      ctx.beginPath(); ctx.moveTo(200, 0); ctx.lineTo(200, 260); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#7cc4ff'; ctx.fillRect(10, L.y, PW, PH);
      ctx.fillStyle = twoP ? '#ffc457' : '#9aa7b8'; ctx.fillRect(382, R.y, PW, PH);
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(ball.x, ball.y, 5, 0, Math.PI*2); ctx.fill();
      ctx.font = 'bold 26px sans-serif'; ctx.fillStyle = 'rgba(255,255,255,.25)';
      ctx.fillText(String(L.score), 170, 34); ctx.fillText(String(R.score), 218, 34);
    }
    serve(Math.random() < 0.5 ? 1 : -1);
    api.state('进行中 · 0 : 0');
    api.setScore(0, 'pong');
    api.overlayHide();
    pong._key = function (e, k) {
      if (k === 'w') { keys.w = e.type === 'keydown'; return true; }
      if (k === 's') { keys.s = e.type === 'keydown'; return true; }
      if (k === 'arrowup') { keys.up = e.type === 'keydown'; return true; }
      if (k === 'arrowdown') { keys.down = e.type === 'keydown'; return true; }
      return false;
    };
    pong.timer = setInterval(step, 16);
    draw();
  }

  /* ---------------- 井字棋 Tic-Tac-Toe ---------------- */
  var ttt = {
    modes: ['1p', '2p'],
    help: '单人：你执 × 先手，对战 AI。双人：同屏轮流落子。三点连成一线即胜。',
    init: function (mode) { startTTT(mode === '2p'); },
    stop: function () {}
  };

  function startTTT(twoP) {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(3,96px);gap:8px;';
    api.stage().appendChild(wrap);
    var bd = new Array(9).fill('');
    var turn = 'X', over = false, cells = [];
    var LINE = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
    function winner(b) {
      for (var i = 0; i < LINE.length; i++) {
        var l = LINE[i];
        if (b[l[0]] && b[l[0]] === b[l[1]] && b[l[1]] === b[l[2]]) return { p: b[l[0]], line: l };
      }
      return b.indexOf('') < 0 ? { p: 'draw' } : null;
    }
    function minimax(b, cur, me) {
      var w = winner(b);
      if (w) return { v: w.p === 'draw' ? 0 : (w.p === me ? 10 : -10) };
      var best = cur === me ? { v: -99 } : { v: 99 };
      for (var i = 0; i < 9; i++) {
        if (b[i]) continue;
        b[i] = cur;
        var r = minimax(b, cur === 'X' ? 'O' : 'X', me);
        b[i] = '';
        if (cur === me) { if (r.v > best.v) best = { v: r.v, i: i }; }
        else { if (r.v < best.v) best = { v: r.v, i: i }; }
      }
      return best;
    }
    function finish(w) {
      over = true;
      api.state('已结束');
      if (w.p === 'draw') {
        api.overlay('平局', '棋逢对手', '再来一局', function(){ ttt.init(twoP ? '2p' : '1p'); });
      } else {
        w.line.forEach(function(i){ cells[i].style.background = 'var(--primary-soft, #e9eefb)'; });
        var meWin = !twoP && w.p === 'X';
        if (meWin) { var cur = api.best('ttt') || 0; api.best('ttt', cur + 1); }
        api.overlay((twoP ? (w.p === 'X' ? '1P（×）' : '2P（○）') : (w.p === 'X' ? '你' : 'AI')) + ' 获胜！',
          twoP ? '' : (meWin ? '累计胜场 +1' : '再试一次，AI 不留情面'), '再来一局', function(){ ttt.init(twoP ? '2p' : '1p'); });
        api.setScore(api.best('ttt') || 0, 'ttt');
      }
    }
    function play(i) {
      if (over || bd[i]) return;
      if (!twoP && turn === 'O') return;
      bd[i] = turn;
      render();
      var w = winner(bd);
      if (w) { finish(w); return; }
      turn = turn === 'X' ? 'O' : 'X';
      api.state('轮到 ' + (twoP ? (turn === 'X' ? '1P（×）' : '2P（○）') : (turn === 'X' ? '你（×）' : 'AI（○）')));
      if (!twoP && turn === 'O') {
        setTimeout(function () {
          if (over) return;
          var mv = minimax(bd.slice(), 'O', 'O').i;
          if (mv != null) { bd[mv] = 'O'; render(); }
          var w2 = winner(bd);
          if (w2) { finish(w2); return; }
          turn = 'X';
          api.state('轮到 你（×）');
        }, 320);
      }
    }
    function render() {
      for (var i = 0; i < 9; i++) cells[i].textContent = bd[i];
    }
    for (var i = 0; i < 9; i++) {
      (function (i) {
        var c = el('button', 'ttt-cell');
        c.type = 'button';
        c.style.cssText = 'aspect-ratio:1;font-size:30px;font-weight:700;border:1px solid var(--border-soft);border-radius:10px;background:var(--card-2);color:var(--text);cursor:pointer;min-height:76px;';
        c.addEventListener('click', function(){ play(i); });
        cells.push(c); wrap.appendChild(c);
      })(i);
    }
    api.state('轮到 ' + (twoP ? '1P（×）' : '你（×）'));
    api.setScore(api.best('ttt') || 0, 'ttt');
    api.overlayHide();
  }

  /* ---------------- 四子棋 Connect Four ---------------- */
  var c4 = {
    modes: ['1p', '2p'],
    help: '点击一列落子，先连成四子者胜。单人模式下 AI 会堵你的必胜点，别想轻松赢。',
    init: function (mode) { startC4(mode === '2p'); },
    stop: function () {}
  };

  function startC4(twoP) {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(7,46px);gap:4px;';
    api.stage().appendChild(wrap);
    var COLS = 7, ROWS = 6;
    var bd = new Array(COLS * ROWS).fill(0); // 0 空 1 玩家 2 对手
    var turn = 1, over = false, cells = [];
    function idx(c, r) { return r * COLS + c; }
    function dropRow(c) { for (var r = ROWS - 1; r >= 0; r--) if (!bd[idx(c, r)]) return r; return -1; }
    function winLine(p) {
      var dirs = [[1,0],[0,1],[1,1],[1,-1]];
      for (var r = 0; r < ROWS; r++) for (var c = 0; c < COLS; c++) for (var d = 0; d < dirs.length; d++) {
        var dx = dirs[d][0], dy = dirs[d][1], n = 0;
        while (n < 4) {
          var cc = c + dx*n, rr = r + dy*n;
          if (cc < 0 || cc >= COLS || rr < 0 || rr >= ROWS || bd[idx(cc, rr)] !== p) break;
          n++;
        }
        if (n === 4) return [[c,r],[c+dx,r+dy],[c+dx*2,r+dy*2],[c+dx*3,r+dy*3]];
      }
      return null;
    }
    function finish(p) {
      over = true;
      api.state('已结束');
      var line = winLine(p);
      if (line) line.forEach(function(pos){ var cell = cells[idx(pos[0], pos[1])]; if (cell) cell.style.outline = '3px solid var(--primary)'; });
      api.overlay((twoP ? (p === 1 ? '1P 获胜！' : '2P 获胜！') : (p === 1 ? '你赢了！' : 'AI 获胜！')), '', '再来一局', function(){ c4.init(twoP ? '2p' : '1p'); });
      if (!twoP && p === 1) api.best('c4', 1);
    }
    function aiMove() {
      // 1. 自己能赢就赢 2. 对手能赢就堵 3. 中心优先
      var cands = [];
      for (var c = 0; c < COLS; c++) if (dropRow(c) >= 0) cands.push(c);
      function tryWin(p) {
        for (var i = 0; i < cands.length; i++) {
          var c = cands[i], r = dropRow(c);
          bd[idx(c, r)] = p;
          var w = winLine(p);
          bd[idx(c, r)] = 0;
          if (w) return c;
        }
        return -1;
      }
      var m = tryWin(2); if (m < 0) m = tryWin(1);
      if (m < 0) {
        var center = [3, 2, 4, 5, 1, 0, 6].filter(function(c){ return cands.indexOf(c) >= 0; });
        m = center[Math.floor(Math.random() * center.length)] != null ? center[0] : cands[0];
      }
      return m;
    }
    function play(c) {
      if (over) return;
      if (!twoP && turn === 2) return;
      var r = dropRow(c);
      if (r < 0) return;
      bd[idx(c, r)] = turn;
      render();
      if (winLine(turn)) { finish(turn); return; }
      if (bd.every(function(v){ return v; })) { over = true; api.overlay('棋盘满了，平局', '', '再来一局', function(){ c4.init(twoP ? '2p' : '1p'); }); return; }
      turn = turn === 1 ? 2 : 1;
      api.state('轮到 ' + (twoP ? (turn === 1 ? '1P' : '2P') : (turn === 1 ? '你' : 'AI')));
      if (!twoP && turn === 2) {
        setTimeout(function () {
          if (over) return;
          var c2 = aiMove();
          var r2 = dropRow(c2);
          bd[idx(c2, r2)] = 2;
          render();
          if (winLine(2)) { finish(2); return; }
          turn = 1;
          api.state('轮到 你');
        }, 380);
      }
    }
    function render() {
      for (var i = 0; i < bd.length; i++) {
        var v = bd[i];
        cells[i].style.background = v === 0 ? 'var(--card-2)' : (v === 1 ? '#4da3ff' : '#ffb347');
        cells[i].style.color = 'transparent';
      }
    }
    for (var r = 0; r < ROWS; r++) for (var c = 0; c < COLS; c++) {
      (function (c) {
        var cell = el('button', 'c4-cell');
        cell.type = 'button';
        cell.title = '第 ' + (c + 1) + ' 列';
        cell.style.cssText = 'aspect-ratio:1;border-radius:50%;border:1px solid var(--border-soft);cursor:pointer;min-width:44px;';
        cell.addEventListener('click', function(){ play(c); });
        cells[idx(c, r)] = cell;
        wrap.appendChild(cell);
      })(c);
    }
    api.state('轮到 ' + (twoP ? '1P' : '你'));
    api.setScore(0, 'c4');
    api.overlayHide();
    render();
  }

  /* ---------------- 黑白棋 Reversi ---------------- */
  var reversi = {
    modes: ['1p', '2p'],
    help: '夹住对方棋子即可翻转。无子可下自动换手，双方都无法落子时子多者胜。单人模式你执黑先手。',
    init: function (mode) { startReversi(mode === '2p'); },
    stop: function () {}
  };

  function startReversi(twoP) {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(8,42px);gap:3px;';
    api.stage().appendChild(wrap);
    var N = 8;
    var bd = new Array(64).fill(0); // 0 空 1 黑 2 白
    bd[27] = 2; bd[28] = 1; bd[35] = 1; bd[36] = 2;
    var turn = 1, over = false, cells = [];
    function flipsAt(i, p) {
      var x = i % N, y = Math.floor(i / N), out = [];
      if (bd[i]) return out;
      var dirs = [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]];
      for (var d = 0; d < dirs.length; d++) {
        var dx = dirs[d][0], dy = dirs[d][1], line = [], cx = x + dx, cy = y + dy;
        while (cx >= 0 && cx < N && cy >= 0 && cy < N) {
          var v = bd[cy*N + cx];
          if (v === 0) { line = []; break; }
          if (v === p) break;
          line.push(cy*N + cx);
          cx += dx; cy += dy;
        }
        if (cx >= 0 && cx < N && cy >= 0 && cy < N && bd[cy*N + cx] === p && line.length) out = out.concat(line);
      }
      return out;
    }
    function legal(p) {
      var out = [];
      for (var i = 0; i < 64; i++) if (flipsAt(i, p).length) out.push(i);
      return out;
    }
    function counts() {
      var b = 0, w = 0;
      bd.forEach(function(v){ if (v === 1) b++; else if (v === 2) w++; });
      return { b: b, w: w };
    }
    function finish() {
      over = true;
      var c = counts();
      api.state('已结束');
      api.setScore(c.b, 'reversi');
      var msg = c.b > c.w ? '黑方胜 ' + c.b + ' : ' + c.w : (c.w > c.b ? '白方胜 ' + c.b + ' : ' + c.w : '平局 ' + c.b + ' : ' + c.w);
      api.overlay('终局', msg, '再来一局', function(){ reversi.init(twoP ? '2p' : '1p'); });
      if (!twoP) api.best('reversi', c.b);
    }
    function passIfNeeded() {
      if (legal(turn).length) return true;
      turn = turn === 1 ? 2 : 1;
      if (legal(turn).length) return true;
      finish();
      return false;
    }
    function render() {
      for (var i = 0; i < 64; i++) {
        var v = bd[i];
        var cell = cells[i];
        cell.style.background = 'var(--card-2)';
        cell.textContent = '';
        if (v) {
          var d = el('span');
          d.style.cssText = 'width:26px;height:26px;border-radius:50%;display:block;' + (v === 1 ? 'background:#1b2433;' : 'background:#f2f5fa;border:1px solid #c9d2de;');
          cell.appendChild(d);
        } else if (!over && flipsAt(i, turn).length) {
          cell.style.background = 'color-mix(in oklab, var(--primary) 14%, var(--card-2))';
        }
      }
      var c = counts();
      api.setScore(c.b, 'reversi');
      api.state('黑 ' + c.b + ' : 白 ' + c.w + ' · 轮到 ' + (twoP ? (turn === 1 ? '1P（黑）' : '2P（白）') : (turn === 1 ? '你（黑）' : 'AI（白）')));
    }
    function play(i) {
      if (over) return;
      if (!twoP && turn === 2) return;
      var fl = flipsAt(i, turn);
      if (!fl.length) return;
      bd[i] = turn;
      fl.forEach(function(j){ bd[j] = turn; });
      turn = turn === 1 ? 2 : 1;
      render();
      if (!passIfNeeded()) return;
      if (!twoP && turn === 2) {
        setTimeout(function () {
          if (over) return;
          // AI：优先角，其次翻子最多
          var leg = legal(2);
          if (!leg.length) { turn = 1; if (!passIfNeeded()) return; render(); return; }
          var bestI = leg[0], bestN = -1;
          leg.forEach(function(j){
            var x = j % N, y = Math.floor(j / N);
            var w = (x === 0 || x === 7) && (y === 0 || y === 7) ? 100 : 0;
            var n = flipsAt(j, 2).length + w;
            if (n > bestN) { bestN = n; bestI = j; }
          });
          var fl2 = flipsAt(bestI, 2);
          bd[bestI] = 2;
          fl2.forEach(function(j){ bd[j] = 2; });
          turn = 1;
          render();
          if (!passIfNeeded()) return;
          render();
        }, 420);
      } else {
        render();
      }
    }
    for (var i = 0; i < 64; i++) {
      (function (i) {
        var cell = el('button', 'rv-cell');
        cell.type = 'button';
        cell.style.cssText = 'aspect-ratio:1;border:1px solid var(--border-soft);border-radius:6px;background:var(--card-2);cursor:pointer;display:grid;place-items:center;min-width:36px;';
        cell.addEventListener('click', function(){ play(i); });
        cells.push(cell); wrap.appendChild(cell);
      })(i);
    }
    api.setScore(2, 'reversi');
    api.overlayHide();
    render();
  }

  /* ---------------- 记忆翻牌 Memory ---------------- */
  var memory = {
    modes: ['1p'],
    help: '点击翻牌，找出所有相同的图标的配对。翻得越少步数越少，得分越高。',
    init: function () { startMemory(); },
    stop: function () {}
  };

  function startMemory() {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(4,74px);gap:8px;';
    api.stage().appendChild(wrap);
    var ICONS = ['♠', '♥', '♦', '♣', '★', '●', '▲', '■'];
    var deck = ICONS.concat(ICONS).sort(function(){ return Math.random() - 0.5; });
    var open = [], matched = 0, steps = 0, lock = false, cells = [];
    function render() {
      cells.forEach(function (c, i) {
        c.textContent = c._open || c._done ? deck[i] : '';
        c.style.background = c._done ? 'color-mix(in oklab, var(--ok, #3ddc97) 22%, var(--card-2))' : 'var(--card-2)';
      });
    }
    api.state('步数 0 · 配对 0/8');
    api.setScore(0, 'memory');
    api.overlayHide();
    deck.forEach(function (_, i) {
      (function (i) {
        var c = el('button', 'mem-cell');
        c.type = 'button';
        c.style.cssText = 'aspect-ratio:1;font-size:26px;font-weight:700;border:1px solid var(--border-soft);border-radius:10px;cursor:pointer;color:var(--text);min-height:64px;';
        c.addEventListener('click', function () {
          if (lock || c._open || c._done) return;
          c._open = true; steps++;
          open.push(i);
          render();
          api.state('步数 ' + steps + ' · 配对 ' + matched + '/8');
          if (open.length === 2) {
            lock = true;
            var a = open[0], b = open[1];
            if (deck[a] === deck[b]) {
              cells[a]._done = cells[b]._done = true;
              cells[a]._open = cells[b]._open = false;
              matched++;
              open = []; lock = false;
              api.setScore(matched * 10, 'memory');
              api.state('步数 ' + steps + ' · 配对 ' + matched + '/8');
              if (matched === 8) {
                var sc = Math.max(1, 100 - steps * 2);
                api.best('memory', sc);
                api.state('已通关');
                api.overlay('全部配对！', '共用 ' + steps + ' 步，得分 ' + sc, '再来一局', function(){ startMemory(); });
              }
            } else {
              setTimeout(function () {
                cells[a]._open = cells[b]._open = false;
                open = []; lock = false;
                render();
                api.state('步数 ' + steps + ' · 配对 ' + matched + '/8');
              }, 750);
            }
          }
        });
        cells.push(c); wrap.appendChild(c);
      })(i);
    });
    render();
  }

  /* ---------------- 打砖块 Breakout ---------------- */
  var breakout = {
    modes: ['1p'],
    help: '鼠标左右移动或 <kbd>←</kbd><kbd>→</kbd> 控制挡板接球，清光所有砖块即胜。漏球 3 次结束。',
    timer: null,
    init: function () { this.stop(); startBreakout(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startBreakout() {
    var cv = el('canvas');
    cv.width = 400; cv.height = 300;
    cv.style.cssText = 'width:min(400px,84vw);height:auto;border-radius:12px;background:#0b1220;';
    api.stage().appendChild(cv);
    var ctx = cv.getContext('2d');
    var PW = 64, px = 168, ball = { x: 200, y: 220, vx: 3, vy: -3.2 };
    var COLS = 8, ROWS = 5, BW = 46, BH = 16, GAP = 3, OX = 9, OY = 34;
    var bricks = [], lives = 3, score = 0, over = false, keys = { l: false, r: false };
    for (var r = 0; r < ROWS; r++) for (var c = 0; c < COLS; c++) bricks.push({ c: c, r: r, alive: true });
    var COLORS = ['#ff8f6b', '#ffc457', '#3ddc97', '#62a6ff', '#b98bff'];
    function step() {
      if (api.isPaused() || over) { draw(); return; }
      if (keys.l) px -= 6;
      if (keys.r) px += 6;
      px = Math.max(0, Math.min(400 - PW, px));
      ball.x += ball.vx; ball.y += ball.vy;
      if (ball.x < 5 || ball.x > 395) ball.vx = -ball.vx;
      if (ball.y < 5) ball.vy = -ball.vy;
      if (ball.vy > 0 && ball.y > 278 && ball.y < 292 && ball.x > px && ball.x < px + PW) {
        ball.vy = -Math.abs(ball.vy);
        ball.vx += (ball.x - (px + PW/2)) * 0.04;
      }
      if (ball.y > 305) {
        lives--;
        if (lives <= 0) {
          over = true; breakout.stop();
          api.state('已结束');
          api.overlay('漏了 3 球', '得分 ' + score, '再来一局', function(){ breakout.init(); });
          api.best('breakout', score);
          return;
        }
        ball.x = 200; ball.y = 220; ball.vx = 3; ball.vy = -3.2;
      }
      for (var i = 0; i < bricks.length; i++) {
        var b = bricks[i];
        if (!b.alive) continue;
        var bx = OX + b.c * (BW + GAP), by = OY + b.r * (BH + GAP);
        if (ball.x > bx - 4 && ball.x < bx + BW + 4 && ball.y > by - 4 && ball.y < by + BH + 4) {
          b.alive = false;
          score += 10;
          api.setScore(score, 'breakout');
          ball.vy = -ball.vy;
          break;
        }
      }
      if (bricks.every(function(b){ return !b.alive; })) {
        over = true; breakout.stop();
        api.state('已通关');
        api.overlay('清屏成功！', '得分 ' + score, '再来一局', function(){ breakout.init(); });
        api.best('breakout', score);
        return;
      }
      draw();
    }
    function draw() {
      ctx.fillStyle = '#0b1220'; ctx.fillRect(0, 0, 400, 300);
      bricks.forEach(function (b) {
        if (!b.alive) return;
        ctx.fillStyle = COLORS[b.r % COLORS.length];
        ctx.fillRect(OX + b.c * (BW + GAP), OY + b.r * (BH + GAP), BW, BH);
      });
      ctx.fillStyle = '#7cc4ff';
      ctx.fillRect(px, 282, PW, 8);
      ctx.fillStyle = '#fff';
      ctx.beginPath(); ctx.arc(ball.x, ball.y, 5, 0, Math.PI*2); ctx.fill();
      ctx.font = '12px sans-serif'; ctx.fillStyle = 'rgba(255,255,255,.5)';
      ctx.fillText('生命 ' + lives, 8, 16);
    }
    api.setScore(0, 'breakout');
    api.state('进行中');
    api.overlayHide();
    breakout._key = function (e, k) {
      if (k === 'arrowleft') { keys.l = e.type === 'keydown'; return true; }
      if (k === 'arrowright') { keys.r = e.type === 'keydown'; return true; }
      return false;
    };
    breakout._mouse = function (rectX) {
      px = Math.max(0, Math.min(400 - PW, rectX));
    };
    cv.addEventListener('mousemove', function (e) {
      var rect = cv.getBoundingClientRect();
      breakout._mouse((e.clientX - rect.left) / rect.width * 400);
    });
    breakout.timer = setInterval(step, 16);
    draw();
  }

  /* ---------------- 十五拼图 15 Puzzle ---------------- */
  var fifteen = {
    modes: ['1p'],
    help: '点击空格旁边的数字块滑动，把 1-15 按顺序排好即通关。',
    init: function () { startFifteen(); },
    stop: function () {}
  };

  function startFifteen() {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(4,72px);gap:6px;';
    api.stage().appendChild(wrap);
    var bd, moves;
    function solved(b) {
      for (var i = 0; i < 15; i++) if (b[i] !== i + 1) return false;
      return true;
    }
    function shuffle() {
      bd = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0];
      // 从终态随机走 300 步保证有解
      var blank = 15;
      for (var k = 0; k < 300; k++) {
        var x = blank % 4, y = Math.floor(blank / 4);
        var opts = [];
        if (x > 0) opts.push(blank - 1);
        if (x < 3) opts.push(blank + 1);
        if (y > 0) opts.push(blank - 4);
        if (y < 3) opts.push(blank + 4);
        var pick = opts[Math.floor(Math.random() * opts.length)];
        bd[blank] = bd[pick]; bd[pick] = 0; blank = pick;
      }
      if (solved(bd)) shuffle();
    }
    function render() {
      for (var i = 0; i < 16; i++) {
        cells[i].textContent = bd[i] || '';
        cells[i].style.visibility = bd[i] ? 'visible' : 'hidden';
        cells[i].style.background = 'var(--card-2)';
      }
      api.state('步数 ' + moves);
    }
    function play(i) {
      var blank = bd.indexOf(0);
      var xi = i % 4, yi = Math.floor(i / 4), xb = blank % 4, yb = Math.floor(blank / 4);
      if (Math.abs(xi - xb) + Math.abs(yi - yb) !== 1) return;
      bd[blank] = bd[i]; bd[i] = 0;
      moves++;
      api.setScore(0, 'fifteen');
      render();
      if (solved(bd)) {
        var sc = Math.max(1, 1000 - moves * 5);
        api.best('fifteen', sc);
        api.state('已通关');
        api.overlay('拼好了！', '共 ' + moves + ' 步，得分 ' + sc, '再来一局', function(){ startFifteen(); });
      }
    }
    var cells = [];
    shuffle();
    moves = 0;
    for (var i = 0; i < 16; i++) {
      (function (i) {
        var c = el('button', 'fp-cell');
        c.type = 'button';
        c.style.cssText = 'aspect-ratio:1;font-size:24px;font-weight:700;border:1px solid var(--border-soft);border-radius:10px;color:var(--text);cursor:pointer;min-height:60px;';
        c.addEventListener('click', function(){ play(i); });
        cells.push(c); wrap.appendChild(c);
      })(i);
    }
    api.setScore(0, 'fifteen');
    api.overlayHide();
    render();
  }


  /* ---------------- 画布小工具 ---------------- */
  function mkCanvas(w, h) {
    var cv = el('canvas');
    cv.width = w; cv.height = h;
    cv.style.cssText = 'width:min(' + w + 'px,88vw);height:auto;border-radius:12px;background:#0b1220;display:block;';
    api.stage().appendChild(cv);
    return cv;
  }

  /* ---------------- 俄罗斯方块 Tetris ---------------- */
  var tetris = {
    modes: ['1p'],
    help: '<kbd>←</kbd><kbd>→</kbd> 左右移动，<kbd>↑</kbd> 旋转，<kbd>↓</kbd> 加速下落，<kbd>空格</kbd> 直接落底。消满一行得分，速度会越来越快。',
    timer: null,
    init: function () { this.stop(); startTetris(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startTetris() {
    var COLS = 10, ROWS = 20, S = 26;
    var cv = mkCanvas(COLS * S, ROWS * S);
    cv.style.width = 'min(' + (COLS * S) + 'px,80vw)';
    var ctx = cv.getContext('2d');
    var SHAPES = [
      [[1,1,1,1]],
      [[1,1],[1,1]],
      [[0,1,0],[1,1,1]],
      [[1,0,0],[1,1,1]],
      [[0,0,1],[1,1,1]],
      [[1,1,0],[0,1,1]],
      [[0,1,1],[1,1,0]]
    ];
    var COLORS = ['#62d0ff', '#ffd34d', '#c08bff', '#62a6ff', '#ff9c5b', '#3ddc97', '#ff6b78'];
    var board = [], cur = null, over = false, score = 0, lines = 0, tick = 520;
    for (var r = 0; r < ROWS; r++) board.push(new Array(COLS).fill(0));

    function spawn() {
      var i = Math.floor(Math.random() * SHAPES.length);
      cur = { m: SHAPES[i].map(function (row) { return row.slice(); }), c: i + 1, x: Math.floor((COLS - SHAPES[i][0].length) / 2), y: 0 };
      if (hit(cur.m, cur.x, cur.y)) { over = true; finish(); }
    }
    function hit(m, ox, oy) {
      for (var r = 0; r < m.length; r++) for (var c = 0; c < m[r].length; c++) {
        if (!m[r][c]) continue;
        var x = ox + c, y = oy + r;
        if (x < 0 || x >= COLS || y >= ROWS) return true;
        if (y >= 0 && board[y][x]) return true;
      }
      return false;
    }
    function rotate() {
      var m = cur.m, n = m[0].length, out = [];
      for (var c = 0; c < n; c++) {
        var row = [];
        for (var r = m.length - 1; r >= 0; r--) row.push(m[r][c]);
        out.push(row);
      }
      if (!hit(out, cur.x, cur.y)) cur.m = out;
      else if (!hit(out, cur.x - 1, cur.y)) { cur.m = out; cur.x--; }
      else if (!hit(out, cur.x + 1, cur.y)) { cur.m = out; cur.x++; }
    }
    function lock() {
      for (var r = 0; r < cur.m.length; r++) for (var c = 0; c < cur.m[r].length; c++) {
        if (cur.m[r][c] && cur.y + r >= 0) board[cur.y + r][cur.x + c] = cur.c;
      }
      var cleared = 0;
      for (var y = ROWS - 1; y >= 0; y--) {
        if (board[y].every(function (v) { return v; })) {
          board.splice(y, 1);
          board.unshift(new Array(COLS).fill(0));
          cleared++; y++;
        }
      }
      if (cleared) {
        lines += cleared;
        score += [0, 100, 300, 500, 800][cleared] || 800;
        api.setScore(score, 'tetris');
        api.state('消行 ' + lines + ' · 得分 ' + score);
        tick = Math.max(120, 520 - lines * 18);
        clearInterval(tetris.timer);
        tetris.timer = setInterval(step, tick);
      }
      spawn();
    }
    function drop() {
      if (over) return;
      if (!hit(cur.m, cur.x, cur.y + 1)) cur.y++;
      else lock();
      draw();
    }
    function step() {
      if (api.isPaused() || over) return;
      drop();
    }
    function finish() {
      tetris.stop();
      api.state('已结束');
      api.best('tetris', score);
      api.overlay('堆到顶了', '消行 ' + lines + ' · 得分 ' + score, '再来一局', function () { tetris.init(); });
    }
    function draw() {
      ctx.fillStyle = '#0b1220'; ctx.fillRect(0, 0, cv.width, cv.height);
      ctx.strokeStyle = 'rgba(120,160,255,.07)';
      for (var i = 0; i <= COLS; i++) { ctx.beginPath(); ctx.moveTo(i * S, 0); ctx.lineTo(i * S, ROWS * S); ctx.stroke(); }
      for (var j = 0; j <= ROWS; j++) { ctx.beginPath(); ctx.moveTo(0, j * S); ctx.lineTo(COLS * S, j * S); ctx.stroke(); }
      function block(x, y, c) {
        ctx.fillStyle = COLORS[c - 1];
        ctx.fillRect(x * S + 1, y * S + 1, S - 2, S - 2);
        ctx.fillStyle = 'rgba(255,255,255,.18)';
        ctx.fillRect(x * S + 1, y * S + 1, S - 2, 4);
      }
      board.forEach(function (row, y) { row.forEach(function (v, x) { if (v) block(x, y, v); }); });
      if (cur) cur.m.forEach(function (row, r) { row.forEach(function (v, c) { if (v) block(cur.x + c, cur.y + r, cur.c); }); });
    }
    tetris._key = function (e, k) {
      if (e.type !== 'keydown' || over) return false;
      if (k === 'arrowleft') { if (!hit(cur.m, cur.x - 1, cur.y)) cur.x--; draw(); return true; }
      if (k === 'arrowright') { if (!hit(cur.m, cur.x + 1, cur.y)) cur.x++; draw(); return true; }
      if (k === 'arrowup') { rotate(); draw(); return true; }
      if (k === 'arrowdown') { drop(); return true; }
      if (k === ' ' || k === 'spacebar') { while (!hit(cur.m, cur.x, cur.y + 1)) cur.y++; lock(); draw(); return true; }
      return false;
    };
    api.setScore(0, 'tetris');
    api.state('消行 0 · 得分 0');
    api.overlayHide();
    spawn(); draw();
    tetris.timer = setInterval(step, tick);
  }

  /* ---------------- 吃豆人 Pac-Man ---------------- */
  var pacman = {
    modes: ['1p'],
    help: '方向键或 <kbd>W</kbd><kbd>A</kbd><kbd>S</kbd><kbd>D</kbd> 控制吃豆人，吃光所有豆子过关；被幽灵碰到即结束。',
    timer: null,
    init: function () { this.stop(); startPacman(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startPacman() {
    var MAP = [
      '#####################',
      '#.........#.........#',
      '#.###.###.#.###.###.#',
      '#o###.###.#.###.###o#',
      '#...................#',
      '#.###.#.#####.#.###.#',
      '#.....#...#...#.....#',
      '#####.### # ###.#####',
      '    #.#       #.#    ',
      '#####.# ##-## #.#####',
      '     .  #GGG#  .     ',
      '#####.# ##### #.#####',
      '    #.#       #.#    ',
      '#####.# ##### #.#####',
      '#.........#.........#',
      '#.###.###.#.###.###.#',
      '#o..#.....P.....#..o#',
      '###.#.#.#####.#.#.###',
      '#.....#...#...#.....#',
      '#.#######.#.#######.#',
      '#...................#',
      '#####################'
    ];
    var ROWS = MAP.length, COLS = MAP[0].length, S = 18;
    var cv = mkCanvas(COLS * S, ROWS * S);
    cv.style.width = 'min(' + (COLS * S) + 'px,92vw)';
    var ctx = cv.getContext('2d');
    var grid = [], dots = 0, eaten = 0, score = 0, over = false;
    var pac = { x: 1, y: 1, dx: 0, dy: 0, want: null, mouth: 0 };
    var ghosts = [];
    for (var r = 0; r < ROWS; r++) {
      grid.push([]);
      for (var c = 0; c < COLS; c++) {
        var ch = MAP[r][c];
        grid[r].push(ch === '#' ? 1 : 0);
        if (ch === '.') dots++;
        if (ch === 'o') { dots++; grid[r][c] = 2; }
        if (ch === 'P') { pac.x = c; pac.y = r; }
        if (ch === 'G') ghosts.push({ x: c, y: r, dx: 0, dy: -1, col: '#ff6b78' });
        if (ch === '-' || ch === 'G' || ch === ' ' ) grid[r][c] = grid[r][c] || 0;
      }
    }
    var keys = {};

    function canGo(x, y) { return x >= 0 && y >= 0 && x < COLS && y < ROWS && !grid[y][x]; }
    function tickMove() {
      if (api.isPaused() || over) return;
      // 吃豆人：优先按意图方向，撞墙则停下
      var want = keys.__want;
      if (want) {
        var nx = pac.x + want[0], ny = pac.y + want[1];
        if (canGo(nx, ny)) { pac.dx = want[0]; pac.dy = want[1]; keys.__want = null; }
      }
      if (pac.dx || pac.dy) {
        var px = pac.x + pac.dx, py = pac.y + pac.dy;
        if (canGo(px, py)) { pac.x = px; pac.y = py; } else { pac.dx = 0; pac.dy = 0; }
      }
      // 吃豆
      if (grid[pac.y][pac.x] === 1) { grid[pac.y][pac.x] = 0; eaten++; score += 10; }
      else if (grid[pac.y][pac.x] === 2) { grid[pac.y][pac.x] = 0; eaten++; score += 50; }
      api.setScore(score, 'pacman');
      // 幽灵：贪心朝玩家，偶尔随机
      ghosts.forEach(function (g) {
        var opts = [];
        [[1,0],[-1,0],[0,1],[0,-1]].forEach(function (d) {
          if (canGo(g.x + d[0], g.y + d[1]) && !(d[0] === -g.dx && d[1] === -g.dy)) opts.push(d);
        });
        if (!opts.length) opts.push([-g.dx, -g.dy]);
        var pick = opts[0];
        if (Math.random() < 0.72) {
          opts.sort(function (a, b) {
            var da = Math.abs(g.x + a[0] - pac.x) + Math.abs(g.y + a[1] - pac.y);
            var db = Math.abs(g.x + b[0] - pac.x) + Math.abs(g.y + b[1] - pac.y);
            return da - db;
          });
          pick = opts[0];
        } else {
          pick = opts[Math.floor(Math.random() * opts.length)];
        }
        g.dx = pick[0]; g.dy = pick[1];
        g.x += g.dx; g.y += g.dy;
        if (g.x === pac.x && g.y === pac.y) {
          over = true; pacman.stop();
          api.state('已结束');
          api.best('pacman', score);
          api.overlay('被幽灵抓住了', '得分 ' + score + ' · 吃掉 ' + eaten + ' 颗豆', '再来一局', function () { pacman.init(); });
        }
      });
      if (eaten >= dots && !over) {
        over = true; pacman.stop();
        api.state('已通关');
        api.best('pacman', score + 200);
        api.overlay('豆浆喝完了！', '得分 ' + (score + 200), '再来一局', function () { pacman.init(); });
      }
      draw();
    }
    function draw() {
      ctx.fillStyle = '#0b1220'; ctx.fillRect(0, 0, cv.width, cv.height);
      for (var y = 0; y < ROWS; y++) for (var x = 0; x < COLS; x++) {
        var v = grid[y][x];
        if (v === 1) { ctx.fillStyle = '#25314a'; ctx.fillRect(x * S, y * S, S, S); }
        else if (v === 2) { ctx.fillStyle = '#ffd34d'; ctx.beginPath(); ctx.arc(x * S + S / 2, y * S + S / 2, 5, 0, Math.PI * 2); ctx.fill(); }
        else if (MAP[y][x] === '.') { ctx.fillStyle = '#e8eefc'; ctx.beginPath(); ctx.arc(x * S + S / 2, y * S + S / 2, 2.2, 0, Math.PI * 2); ctx.fill(); }
      }
      // 吃豆人
      var cx = pac.x * S + S / 2, cy = pac.y * S + S / 2;
      var ang = Math.atan2(pac.dy, pac.dx);
      if (!pac.dx && !pac.dy) ang = 0;
      pac.mouth = (pac.mouth + 1) % 8;
      var open = Math.abs(pac.mouth - 4) / 4 * 0.5 + 0.06;
      ctx.fillStyle = '#ffd34d';
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, S * 0.42, ang + open, ang - open + Math.PI * 2);
      ctx.closePath(); ctx.fill();
      ghosts.forEach(function (g) {
        ctx.fillStyle = g.col;
        ctx.beginPath();
        ctx.arc(g.x * S + S / 2, g.y * S + S / 2 - 2, S * 0.36, Math.PI, 0);
        ctx.lineTo(g.x * S + S * 0.86, g.y * S + S * 0.82);
        ctx.lineTo(g.x * S + S * 0.14, g.y * S + S * 0.82);
        ctx.closePath(); ctx.fill();
        ctx.fillStyle = '#0b1220';
        ctx.beginPath(); ctx.arc(g.x * S + S * 0.36, g.y * S + S * 0.46, 2.4, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.arc(g.x * S + S * 0.64, g.y * S + S * 0.46, 2.4, 0, Math.PI * 2); ctx.fill();
      });
    }
    pacman._key = function (e, k) {
      if (e.type !== 'keydown') return false;
      var m = { arrowleft: [-1, 0], arrowright: [1, 0], arrowup: [0, -1], arrowdown: [0, 1], a: [-1, 0], d: [1, 0], w: [0, -1], s: [0, 1] };
      if (!m[k]) return false;
      keys.__want = m[k];
      return true;
    };
    api.setScore(0, 'pacman');
    api.state('豆子 ' + eaten + ' / ' + dots);
    api.overlayHide();
    draw();
    pacman.timer = setInterval(tickMove, 165);
  }

  /* ---------------- 像素鸟 Flappy Bird ---------------- */
  var flappy = {
    modes: ['1p'],
    help: '按 <kbd>空格</kbd>、<kbd>↑</kbd> 或点击画面让小鸟上升，穿过管道缝隙得分。撞到管道或地面即结束。',
    timer: null,
    init: function () { this.stop(); startFlappy(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startFlappy() {
    var W = 400, H = 320;
    var cv = mkCanvas(W, H);
    var ctx = cv.getContext('2d');
    var bird = { y: H / 2, v: 0, r: 11 }, pipes = [], score = 0, over = false, started = false, frame = 0;
    var GAP = 118, PW = 52, SPEED = 2.4;

    function flap() {
      if (over) return;
      if (!started) { started = true; api.state('进行中'); }
      bird.v = -5.6;
    }
    function loop() {
      if (api.isPaused() || over) { draw(); return; }
      frame++;
      if (!started) { draw(); return; } // 未开始时悬停，等玩家第一次点击/按键
      bird.v += 0.36;
      bird.y += bird.v;
      if (bird.y > H - 24) { bird.y = H - 24; dead(); }
      if (bird.y < 12) { bird.y = 12; bird.v = 0; }
      if (frame % 88 === 0 || pipes.length === 0) {
        var top = 40 + Math.random() * (H - GAP - 100);
        pipes.push({ x: W + PW, top: top, passed: false });
      }
      pipes.forEach(function (p) { p.x -= SPEED; });
      pipes = pipes.filter(function (p) { return p.x > -PW - 10; });
      pipes.forEach(function (p) {
        if (!p.passed && p.x + PW < 40) { p.passed = true; score += 10; api.setScore(score, 'flappy'); }
        var bx = 40 + bird.r, by = bird.y;
        if (bx > p.x && bx < p.x + PW && (by - bird.r < p.top || by + bird.r > p.top + GAP)) dead();
        if (bx + bird.r > p.x && bx - bird.r < p.x + PW && (by - bird.r < p.top || by + bird.r > p.top + GAP)) dead();
      });
      draw();
    }
    function dead() {
      if (over) return;
      over = true; flappy.stop();
      api.state('已结束');
      api.best('flappy', score);
      api.overlay('撞上了', '得分 ' + score, '再来一局', function () { flappy.init(); });
    }
    function draw() {
      ctx.fillStyle = '#122033'; ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = '#1a2b45';
      for (var i = 0; i < 5; i++) {
        ctx.beginPath();
        ctx.arc(((i * 97 + frame * 0.25) % (W + 90)) - 45, 70 + (i % 3) * 34, 34, 0, Math.PI * 2);
        ctx.fill();
      }
      pipes.forEach(function (p) {
        ctx.fillStyle = '#3ddc97';
        ctx.fillRect(p.x, 0, PW, p.top);
        ctx.fillRect(p.x, p.top + GAP, PW, H - p.top - GAP);
        ctx.fillStyle = 'rgba(0,0,0,.18)';
        ctx.fillRect(p.x + PW - 8, 0, 8, p.top);
        ctx.fillRect(p.x + PW - 8, p.top + GAP, 8, H - p.top - GAP);
      });
      ctx.fillStyle = '#8a5a2b'; ctx.fillRect(0, H - 14, W, 14);
      ctx.fillStyle = '#ffd34d';
      ctx.beginPath(); ctx.arc(40, bird.y, bird.r, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = '#ff9c5b';
      ctx.beginPath(); ctx.moveTo(50, bird.y); ctx.lineTo(62, bird.y + 3); ctx.lineTo(50, bird.y + 7); ctx.closePath(); ctx.fill();
      ctx.fillStyle = '#0b1220';
      ctx.beginPath(); ctx.arc(46, bird.y - 4, 2.2, 0, Math.PI * 2); ctx.fill();
      ctx.font = 'bold 14px sans-serif'; ctx.fillStyle = 'rgba(255,255,255,.7)';
      ctx.fillText('得分 ' + score, 12, 24);
      if (!started) { ctx.fillStyle = 'rgba(255,255,255,.75)'; ctx.font = '14px sans-serif'; ctx.fillText('按空格或点击开始', 132, H / 2 + 62); }
    }
    cv.addEventListener('pointerdown', function (e) { e.preventDefault(); flap(); });
    flappy._key = function (e, k) {
      if (e.type !== 'keydown') return false;
      if (k === ' ' || k === 'spacebar' || k === 'arrowup' || k === 'w') { flap(); return true; }
      return false;
    };
    api.setScore(0, 'flappy');
    api.state('按空格或点击开始');
    api.overlayHide();
    draw();
    flappy.timer = setInterval(loop, 16);
  }

  /* ---------------- 太空侵略者 Space Invaders ---------------- */
  var spaceinvaders = {
    modes: ['1p'],
    help: '<kbd>←</kbd><kbd>→</kbd> 移动炮台，<kbd>空格</kbd> 射击。消灭全部外星人过关，被击中或漏过底线 3 次结束。',
    timer: null,
    init: function () { this.stop(); startInvaders(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startInvaders() {
    var W = 400, H = 320;
    var cv = mkCanvas(W, H);
    var ctx = cv.getContext('2d');
    var ship = { x: 188, w: 34 }, bullets = [], bombs = [], aliens = [];
    var dir = 1, score = 0, lives = 3, over = false, frame = 0, keys = {};
    var COLS = 8, ROWS = 4;
    for (var r = 0; r < ROWS; r++) for (var c = 0; c < COLS; c++) {
      aliens.push({ x: 30 + c * 44, y: 26 + r * 32, alive: true, row: r });
    }
    function resetBullets() { bullets = []; }
    function loop() {
      if (api.isPaused() || over) { draw(); return; }
      frame++;
      if (keys.left) ship.x -= 4;
      if (keys.right) ship.x += 4;
      ship.x = Math.max(6, Math.min(W - ship.w - 6, ship.x));
      // 外星人整体移动
      var aliveAliens = aliens.filter(function (a) { return a.alive; });
      if (aliveAliens.length) {
        var minX = Math.min.apply(null, aliveAliens.map(function (a) { return a.x; }));
        var maxX = Math.max.apply(null, aliveAliens.map(function (a) { return a.x + 22; }));
        if ((dir > 0 && maxX + 12 > W) || (dir < 0 && minX - 12 < 0)) {
          dir = -dir;
          aliveAliens.forEach(function (a) { a.y += 14; });
        } else if (frame % 6 === 0) {
          aliveAliens.forEach(function (a) { a.x += dir * 8; });
        }
        if (aliveAliens.some(function (a) { return a.y > H - 46; })) lose('外星人突破防线');
        // 外星人随机投弹
        if (frame % 34 === 0 && aliveAliens.length) {
          var shooter = aliveAliens[Math.floor(Math.random() * aliveAliens.length)];
          bombs.push({ x: shooter.x + 11, y: shooter.y + 22 });
        }
      } else {
        over = true; spaceinvaders.stop();
        api.state('已通关');
        api.best('spaceinvaders', score);
        api.overlay('全部击落！', '得分 ' + score, '再来一局', function () { spaceinvaders.init(); });
      }
      // 子弹
      bullets.forEach(function (b) { b.y -= 7; });
      bullets = bullets.filter(function (b) { return b.y > -8; });
      bullets.forEach(function (b) {
        aliens.forEach(function (a) {
          if (a.alive && b.x > a.x && b.x < a.x + 22 && b.y > a.y && b.y < a.y + 20) {
            a.alive = false; b.y = -99; score += 10;
            api.setScore(score, 'spaceinvaders');
          }
        });
      });
      bombs.forEach(function (b) { b.y += 2.4; });
      bombs = bombs.filter(function (b) { return b.y < H; });
      bombs.forEach(function (b) {
        if (b.y > H - 26 && b.x > ship.x && b.x < ship.x + ship.w) {
          b.y = H + 99; lives--;
          api.state('生命 ' + lives);
          if (lives <= 0) lose('被击中了');
        }
      });
      draw();
    }
    function lose(why) {
      if (over) return;
      over = true; spaceinvaders.stop();
      api.state('已结束');
      api.best('spaceinvaders', score);
      api.overlay(why, '得分 ' + score, '再来一局', function () { spaceinvaders.init(); });
    }
    function draw() {
      ctx.fillStyle = '#0b1220'; ctx.fillRect(0, 0, W, H);
      aliens.forEach(function (a) {
        if (!a.alive) return;
        ctx.fillStyle = ['#ff6b78', '#ffd34d', '#62a6ff', '#3ddc97'][a.row];
        ctx.fillRect(a.x, a.y, 22, 14);
        ctx.fillStyle = '#0b1220';
        ctx.fillRect(a.x + 4, a.y + 4, 4, 4);
        ctx.fillRect(a.x + 14, a.y + 4, 4, 4);
      });
      ctx.fillStyle = '#7cc4ff';
      ctx.fillRect(ship.x, H - 24, ship.w, 10);
      ctx.fillRect(ship.x + ship.w / 2 - 3, H - 32, 6, 8);
      ctx.fillStyle = '#ffd34d';
      bullets.forEach(function (b) { ctx.fillRect(b.x - 1, b.y, 3, 10); });
      ctx.fillStyle = '#ff9c5b';
      bombs.forEach(function (b) { ctx.fillRect(b.x - 2, b.y, 4, 9); });
      ctx.font = '12px sans-serif'; ctx.fillStyle = 'rgba(255,255,255,.55)';
      ctx.fillText('生命 ' + lives + ' · 得分 ' + score, 10, 16);
    }
    spaceinvaders._key = function (e, k) {
      var down = e.type === 'keydown';
      if (k === 'arrowleft' || k === 'a') { keys.left = down; return true; }
      if (k === 'arrowright' || k === 'd') { keys.right = down; return true; }
      if (down && (k === ' ' || k === 'spacebar')) {
        if (bullets.length < 3) bullets.push({ x: ship.x + ship.w / 2, y: H - 34 });
        return true;
      }
      return false;
    };
    api.setScore(0, 'spaceinvaders');
    api.state('生命 3');
    api.overlayHide();
    draw();
    spaceinvaders.timer = setInterval(loop, 16);
  }

  /* ---------------- 恐龙跑酷 Dino Run ---------------- */
  var dino = {
    modes: ['1p'],
    help: '按 <kbd>空格</kbd>、<kbd>↑</kbd> 或点击画面跳跃，躲开仙人掌。跑得越远分越高。',
    timer: null,
    init: function () { this.stop(); startDino(); },
    stop: function () { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  };

  function startDino() {
    var W = 400, H = 210, GROUND = H - 34;
    var cv = mkCanvas(W, H);
    var ctx = cv.getContext('2d');
    var d = { x: 46, y: GROUND, v: 0, duck: false }, obstacles = [], clouds = [];
    var score = 0, over = false, started = false, frame = 0, speed = 4.2, lastSpawn = 0;

    function jump() {
      if (over) return;
      if (!started) { started = true; api.state('进行中'); }
      if (d.y >= GROUND - 1) { d.v = -8.2; }
    }
    function loop() {
      if (api.isPaused() || over) { draw(); return; }
      frame++;
      if (!started) { draw(); return; }
      speed = 4.2 + Math.min(4, score / 120);
      d.v += 0.62;
      d.y += d.v;
      if (d.y > GROUND) { d.y = GROUND; d.v = 0; }
      if (frame - lastSpawn > Math.max(46, 96 - score / 24)) {
        lastSpawn = frame;
        var h = Math.random() < 0.3 ? 42 : 26;
        obstacles.push({ x: W + 20, w: Math.random() < 0.35 ? 30 : 18, h: h });
      }
      obstacles.forEach(function (o) { o.x -= speed; });
      obstacles = obstacles.filter(function (o) { return o.x > -40; });
      score += 0.6;
      api.setScore(Math.floor(score), 'dino');
      if (frame % 160 === 0) clouds.push({ x: W + 30, y: 30 + Math.random() * 50 });
      clouds.forEach(function (c) { c.x -= 0.6; });
      clouds = clouds.filter(function (c) { return c.x > -40; });
      // 碰撞（恐龙的脚部矩形）
      var bx = d.x + 4, by = d.y - 34, bw = 26, bh = 34;
      obstacles.forEach(function (o) {
        if (bx < o.x + o.w && bx + bw > o.x && by + bh > GROUND - o.h && by < GROUND) {
          over = true; dino.stop();
          api.state('已结束');
          api.best('dino', Math.floor(score));
          api.overlay('撞到仙人掌了', '跑了 ' + Math.floor(score) + ' 米', '再来一局', function () { dino.init(); });
        }
      });
      draw();
    }
    function draw() {
      var sky = 'linear-gradient' in ctx ? '#0e1725' : '#0e1725';
      ctx.fillStyle = sky; ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = 'rgba(255,255,255,.06)';
      clouds.forEach(function (c) {
        ctx.beginPath(); ctx.arc(c.x, c.y, 12, 0, Math.PI * 2);
        ctx.arc(c.x + 14, c.y + 4, 9, 0, Math.PI * 2);
        ctx.arc(c.x - 14, c.y + 5, 8, 0, Math.PI * 2); ctx.fill();
      });
      ctx.strokeStyle = 'rgba(255,255,255,.22)';
      ctx.beginPath(); ctx.moveTo(0, GROUND + 2); ctx.lineTo(W, GROUND + 2); ctx.stroke();
      ctx.fillStyle = '#ff9c5b';
      obstacles.forEach(function (o) {
        ctx.fillRect(o.x, GROUND - o.h, 8, o.h);
        ctx.fillRect(o.x + 7, GROUND - o.h + 8, 6, o.h - 8);
        if (o.w > 24) ctx.fillRect(o.x + 12, GROUND - o.h + 2, 7, o.h - 2);
      });
      ctx.fillStyle = '#e8eefc';
      ctx.fillRect(d.x + 2, d.y - 22, 24, 20);
      ctx.fillRect(d.x, d.y - 12, 8, 10);
      ctx.fillRect(d.x + 22, d.y - 26, 12, 12);
      ctx.fillStyle = '#0e1725';
      ctx.fillRect(d.x + 28, d.y - 23, 3, 3);
      ctx.fillStyle = '#e8eefc';
      var legPhase = Math.floor(frame / 6) % 2;
      ctx.fillRect(d.x + 4, d.y - 2, 5, 8 - legPhase * 3);
      ctx.fillRect(d.x + 17, d.y - 2, 5, 5 + legPhase * 3);
      ctx.font = 'bold 13px monospace'; ctx.fillStyle = 'rgba(255,255,255,.65)';
      ctx.fillText(String(Math.floor(score)).padStart(5, '0'), W - 66, 22);
      if (!started) { ctx.fillStyle = 'rgba(255,255,255,.7)'; ctx.font = '13px sans-serif'; ctx.fillText('按空格或点击开始', 128, 92); }
    }
    cv.addEventListener('pointerdown', function (e) { e.preventDefault(); jump(); });
    dino._key = function (e, k) {
      if (e.type !== 'keydown') return false;
      if (k === ' ' || k === 'spacebar' || k === 'arrowup' || k === 'w') { jump(); return true; }
      return false;
    };
    api.setScore(0, 'dino');
    api.state('按空格或点击开始');
    api.overlayHide();
    draw();
    dino.timer = setInterval(loop, 16);
  }


  /* ---------------- 数独 Sudoku ---------------- */
  var sudoku = {
    modes: ['1p'],
    help: '点击格子后用下方数字键填入，点「擦除」清空。行列宫都不能重复；全部填对即通关。',
    init: function () { startSudoku(); },
    stop: function () {}
  };

  function startSudoku() {
    var wrap = el('div');
    wrap.style.cssText = 'display:flex;flex-direction:column;gap:10px;align-items:center;';
    api.stage().appendChild(wrap);
    var boardEl = el('div');
    boardEl.style.cssText = 'display:grid;grid-template-columns:repeat(9,40px);gap:0;border:2px solid var(--border);border-radius:8px;overflow:hidden;background:var(--border-soft);';
    var padEl = el('div');
    padEl.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;justify-content:center;max-width:400px;';
    wrap.appendChild(boardEl); wrap.appendChild(padEl);

    var solution = [], puzzle = [], cells = [], sel = -1;

    function solve(g) {
      for (var i = 0; i < 81; i++) {
        if (!g[i]) {
          var nums = [1,2,3,4,5,6,7,8,9].sort(function () { return Math.random() - 0.5; });
          for (var k = 0; k < 9; k++) {
            if (ok(g, i, nums[k])) { g[i] = nums[k]; if (solve(g)) return true; g[i] = 0; }
          }
          return false;
        }
      }
      return true;
    }
    function ok(g, i, v) {
      var x = i % 9, y = Math.floor(i / 9);
      for (var k = 0; k < 9; k++) {
        if (g[y * 9 + k] === v || g[k * 9 + x] === v) return false;
      }
      var bx = Math.floor(x / 3) * 3, by = Math.floor(y / 3) * 3;
      for (var r = 0; r < 3; r++) for (var c = 0; c < 3; c++) {
        if (g[(by + r) * 9 + bx + c] === v) return false;
      }
      return true;
    }
    function render() {
      cells.forEach(function (c, i) {
        var v = puzzle[i];
        c.textContent = v || '';
        c.style.color = v === 0 ? 'var(--muted)' : (puzzle.given && puzzle.given[i] ? 'var(--text)' : 'var(--primary)');
        c.style.fontWeight = puzzle.given && puzzle.given[i] ? '700' : '500';
        c.style.background = i === sel ? 'color-mix(in oklab, var(--primary) 22%, var(--card))' : 'var(--card)';
        c.style.outline = 'none';
        var bad = false;
        if (v) {
          for (var k = 0; k < 81; k++) {
            if (k === i || puzzle[k] !== v) continue;
            var x1 = i % 9, y1 = Math.floor(i / 9), x2 = k % 9, y2 = Math.floor(k / 9);
            if (x1 === x2 || y1 === y2 || (Math.floor(x1/3) === Math.floor(x2/3) && Math.floor(y1/3) === Math.floor(y2/3))) bad = true;
          }
        }
        if (bad) c.style.color = 'var(--err, #ff6b78)';
      });
    }
    function checkDone() {
      for (var i = 0; i < 81; i++) if (!puzzle[i]) return;
      var wrong = 0;
      for (var j = 0; j < 81; j++) if (puzzle[j] !== solution[j]) wrong++;
      if (wrong === 0) {
        api.state('已通关');
        api.best('sudoku', 100);
        api.overlay('全部填对！', '这一局数独完成', '再来一局', function () { startSudoku(); });
      } else {
        api.state('还有 ' + wrong + ' 格不正确');
      }
    }

    function newGame() {
      solution = new Array(81).fill(0);
      solve(solution);
      puzzle = solution.slice();
      puzzle.given = new Array(81).fill(true);
      var blanks = 46, tries = 0;
      while (blanks > 0 && tries < 500) {
        tries++;
        var i = Math.floor(Math.random() * 81);
        if (!puzzle[i]) continue;
        puzzle[i] = 0; puzzle.given[i] = false; blanks--;
      }
      sel = -1;
      boardEl.innerHTML = ''; cells = [];
      for (var i2 = 0; i2 < 81; i2++) {
        (function (i2) {
          var c = el('button');
          c.type = 'button';
          var right = (i2 % 3 === 2 && i2 % 9 !== 8) ? 2 : 1;
          var bottom = (Math.floor(i2 / 9) % 3 === 2 && i2 < 72) ? 2 : 1;
          c.style.cssText = 'width:40px;height:40px;font-size:18px;border:0;border-right:' + right + 'px solid var(--border);border-bottom:' + bottom + 'px solid var(--border);cursor:pointer;background:var(--card);';
          c.addEventListener('click', function () { sel = i2; render(); });
          cells.push(c); boardEl.appendChild(c);
        })(i2);
      }
      padEl.innerHTML = '';
      for (var n = 1; n <= 9; n++) {
        (function (n) {
          var b = el('button', 'btn', String(n));
          b.type = 'button';
          b.addEventListener('click', function () {
            if (sel < 0 || (puzzle.given && puzzle.given[sel])) return;
            puzzle[sel] = n;
            render(); checkDone();
            api.state('已填 ' + puzzle.filter(Boolean).length + ' / 81');
          });
          padEl.appendChild(b);
        })(n);
      }
      var del = el('button', 'btn', '擦除');
      del.type = 'button';
      del.addEventListener('click', function () {
        if (sel < 0 || (puzzle.given && puzzle.given[sel])) return;
        puzzle[sel] = 0; render();
      });
      padEl.appendChild(del);
      render();
      api.setScore(0, 'sudoku');
      api.state('已填 ' + puzzle.filter(Boolean).length + ' / 81');
      api.overlayHide();
    }
    newGame();
  }

  /* ---------------- 国际象棋 Chess ---------------- */
  var chess = {
    modes: ['1p', '2p'],
    help: '点击自己的棋子，再点绿点落子。单人模式你执白先手，对战简单 AI；双人模式同屏轮流。不含王车易位与吃过路兵。',
    init: function (mode) { startChess(mode === '2p'); },
    stop: function () {}
  };

  function startChess(twoP) {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(8,46px);gap:2px;';
    api.stage().appendChild(wrap);
    var FILES = ['a','b','c','d','e','f','g','h'];
    var GLYPH = { wK:'♔', wQ:'♕', wR:'♖', wB:'♗', wN:'♘', wP:'♙', bK:'♚', bQ:'♛', bR:'♜', bB:'♝', bN:'♞', bP:'♟' };
    var VAL = { P:1, N:3, B:3, R:5, Q:9, K:0 };
    var board = 'bR bN bB bQ bK bB bN bR bP bP bP bP bP bP bP bP . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . wP wP wP wP wP wP wP wP wR wN wB wQ wK wB wN wR'.split(' ');
    var turn = 'w', sel = -1, moves = [], over = false, score = 0, cells = [];

    function color(p) { return p === '.' ? '' : p[0]; }
    function type(p) { return p === '.' ? '' : p[1]; }
    function inside(x, y) { return x >= 0 && x < 8 && y >= 0 && y < 8; }
    function at(x, y) { return board[y * 8 + x]; }

    function pseudo(from, c) {
      var x = from % 8, y = Math.floor(from / 8), p = board[from], out = [];
      if (!p || p === '.' || color(p) !== c) return out;
      var t = type(p);
      function push(nx, ny) {
        if (!inside(nx, ny)) return false;
        var q = at(nx, ny);
        if (q !== '.' && color(q) === c) return false;
        out.push(ny * 8 + nx);
        return q === '.';
      }
      if (t === 'P') {
        var dir = c === 'w' ? -1 : 1;
        var startY = c === 'w' ? 6 : 1;
        if (inside(x, y + dir) && at(x, y + dir) === '.') {
          out.push((y + dir) * 8 + x);
          if (y === startY && at(x, y + dir * 2) === '.') out.push((y + dir * 2) * 8 + x);
        }
        [[-1, dir], [1, dir]].forEach(function (d) {
          var nx = x + d[0], ny = y + d[1];
          if (inside(nx, ny) && at(nx, ny) !== '.' && color(at(nx, ny)) !== c) out.push(ny * 8 + nx);
        });
      } else if (t === 'N') {
        [[1,2],[2,1],[-1,2],[-2,1],[1,-2],[2,-1],[-1,-2],[-2,-1]].forEach(function (d) { push(x + d[0], y + d[1]); });
      } else if (t === 'K') {
        [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]].forEach(function (d) { push(x + d[0], y + d[1]); });
      } else {
        var dirs = t === 'R' ? [[1,0],[-1,0],[0,1],[0,-1]]
          : t === 'B' ? [[1,1],[1,-1],[-1,1],[-1,-1]]
          : [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]];
        dirs.forEach(function (d) {
          var nx = x + d[0], ny = y + d[1];
          while (inside(nx, ny)) {
            var q = at(nx, ny);
            if (q !== '.') {
              if (color(q) !== c) out.push(ny * 8 + nx);
              break;
            }
            out.push(ny * 8 + nx);
            nx += d[0]; ny += d[1];
          }
        });
      }
      return out;
    }
    function kingPos(c) {
      for (var i = 0; i < 64; i++) if (board[i] === c + 'K') return i;
      return -1;
    }
    function attacked(i, by) {
      for (var k = 0; k < 64; k++) {
        var p = board[k];
        if (p !== '.' && color(p) === by && type(p) !== 'K' && pseudo(k, by).indexOf(i) >= 0) return true;
      }
      var kp = kingPos(by);
      if (kp >= 0) {
        var kx = kp % 8, ky = Math.floor(kp / 8), x = i % 8, y = Math.floor(i / 8);
        if (Math.abs(kx - x) <= 1 && Math.abs(ky - y) <= 1) return true;
      }
      return false;
    }
    function legal(from, c) {
      return pseudo(from, c).filter(function (to) {
        var save = board[to];
        board[to] = board[from]; board[from] = '.';
        var bad = attacked(kingPos(c), c === 'w' ? 'b' : 'w');
        board[from] = board[to]; board[to] = save;
        return !bad;
      });
    }
    function allLegal(c) {
      var out = [];
      for (var i = 0; i < 64; i++) if (board[i] !== '.' && color(board[i]) === c) {
        legal(i, c).forEach(function (to) { out.push({ from: i, to: to }); });
      }
      return out;
    }
    function render() {
      for (var i = 0; i < 64; i++) {
        var x = i % 8, y = Math.floor(i / 8), c = cells[i];
        c.style.background = (x + y) % 2 ? '#3a4a5e' : '#e6ecf5';
        c.textContent = GLYPH[board[i]] || '';
        c.style.color = board[i] === '.' ? '' : (color(board[i]) === 'w' ? '#ffffff' : '#111820');
        c.style.textShadow = color(board[i]) === 'w' ? '0 0 2px #0b1220' : 'none';
        c.style.outline = i === sel ? '2px solid var(--primary)' : 'none';
        var dot = moves.indexOf(i) >= 0;
        if (dot) {
          c.textContent = (GLYPH[board[i]] || '') + '';
          c.style.boxShadow = 'inset 0 0 0 3px rgba(61,220,151,.85)';
        } else {
          c.style.boxShadow = 'none';
        }
      }
      var cnt = 0;
      for (var j = 0; j < 64; j++) if (board[j] !== '.') {
        var t = type(board[j]);
        if (t !== 'K' && t !== 'P') cnt += VAL[t];
      }
      api.setScore(twoP ? 0 : cnt, 'chess');
    }
    function endGame(winner) {
      over = true;
      api.state('已结束');
      var msg = winner === 'w' ? (twoP ? '白方（1P）获胜' : '你赢了！') : (twoP ? '黑方（2P）获胜' : 'AI 获胜');
      api.overlay('将死', msg, '再来一局', function () { chess.init(twoP ? '2p' : '1p'); });
    }
    function doMove(from, to) {
      var captured = board[to];
      board[to] = board[from]; board[from] = '.';
      if (type(board[to]) === 'P' && (Math.floor(to / 8) === 0 || Math.floor(to / 8) === 7)) {
        board[to] = color(board[to]) + 'Q';
      }
      sel = -1; moves = [];
      turn = turn === 'w' ? 'b' : 'w';
      render();
      var opp = turn, oppMoves = allLegal(opp), inCheck = attacked(kingPos(opp), opp === 'w' ? 'b' : 'w');
      if (!oppMoves.length) {
        if (inCheck) endGame(opp === 'w' ? 'b' : 'w');
        else { over = true; api.overlay('逼和', '双方都没有合法走法', '再来一局', function () { chess.init(twoP ? '2p' : '1p'); }); }
        return;
      }
      api.state((twoP ? (turn === 'w' ? '白方（1P）' : '黑方（2P）') : (turn === 'w' ? '你（白）' : 'AI（黑）')) + (inCheck ? ' · 将军！' : ' · 走棋'));
      if (!twoP && turn === 'b') setTimeout(aiMove, 380);
    }
    function aiMove() {
      if (over) return;
      var list = allLegal('b');
      if (!list.length) return;
      var scored = list.map(function (m) {
        var cap = board[m.to] === '.' ? 0 : VAL[type(board[m.to])];
        var center = 3.5 - (Math.abs(m.to % 8 - 3.5) + Math.abs(Math.floor(m.to / 8) - 3.5)) / 8;
        var risk = 0;
        var save = board[m.to];
        board[m.to] = board[m.from]; board[m.from] = '.';
        if (attacked(m.to, 'w')) risk = VAL[type(board[m.to])] * 0.9;
        board[m.from] = board[m.to]; board[m.to] = save;
        return { m: m, v: cap * 10 + center - risk + Math.random() * 0.6 };
      });
      scored.sort(function (a, b) { return b.v - a.v; });
      var pick = scored[0].m;
      doMove(pick.from, pick.to);
    }
    for (var i = 0; i < 64; i++) {
      (function (i) {
        var c = el('button');
        c.type = 'button';
        c.style.cssText = 'width:46px;height:46px;border:0;border-radius:4px;font-size:30px;line-height:1;cursor:pointer;display:grid;place-items:center;';
        c.title = FILES[i % 8] + (8 - Math.floor(i / 8));
        c.addEventListener('click', function () {
          if (over) return;
          if (sel >= 0 && moves.indexOf(i) >= 0) { doMove(sel, i); return; }
          if (board[i] !== '.' && color(board[i]) === turn) {
            if (turn === 'b' && !twoP) return;
            sel = i; moves = legal(i, turn); render();
          } else { sel = -1; moves = []; render(); }
        });
        cells.push(c); wrap.appendChild(c);
      })(i);
    }
    api.setScore(0, 'chess');
    api.state(twoP ? '白方（1P）走棋' : '你执白，先走');
    api.overlayHide();
    render();
  }

  /* ---------------- 西洋跳棋 Checkers ---------------- */
  var checkers = {
    modes: ['1p', '2p'],
    help: '点击棋子再点目标格斜走一格；能跳就跳（连续跳会保持选中）。走到对方底线升王。单人模式你执深色棋。',
    init: function (mode) { startCheckers(mode === '2p'); },
    stop: function () {}
  };

  function startCheckers(twoP) {
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(8,44px);gap:2px;';
    api.stage().appendChild(wrap);
    // 1 = 深色（玩家，向上），2 = 浅色（AI，向下），3/4 = 王
    var board = new Array(64).fill(0), turn = 1, sel = -1, moves = [], over = false, cells = [];
    for (var i = 0; i < 64; i++) {
      var x = i % 8, y = Math.floor(i / 8);
      if ((x + y) % 2 === 1) {
        if (y < 3) board[i] = 2;
        if (y > 4) board[i] = 1;
      }
    }
    function side(v) { return v === 0 ? 0 : (v <= 2 ? v : v - 2); }
    function isKing(v) { return v > 2; }
    function inside(x, y) { return x >= 0 && x < 8 && y >= 0 && y < 8; }
    function movesFor(i) {
      var out = [], v = board[i], s = side(v), king = isKing(v);
      var dirs = king ? [-1, 1] : (s === 1 ? [-1] : [1]);
      var x = i % 8, y = Math.floor(i / 8);
      dirs.forEach(function (dy) {
        [-1, 1].forEach(function (dx) {
          var nx = x + dx, ny = y + dy;
          if (!inside(nx, ny)) return;
          var to = ny * 8 + nx;
          if (!board[to]) out.push({ to: to, cap: -1 });
          else if (side(board[to]) !== s) {
            var jx = x + dx * 2, jy = y + dy * 2;
            if (inside(jx, jy) && !board[jy * 8 + jx]) out.push({ to: jy * 8 + jx, cap: to });
          }
        });
      });
      var caps = out.filter(function (m) { return m.cap >= 0; });
      return caps.length ? caps : out; // 强制吃子
    }
    function allMoves(s) {
      var out = [];
      for (var i = 0; i < 64; i++) if (board[i] && side(board[i]) === s) {
        movesFor(i).forEach(function (m) { out.push({ from: i, to: m.to, cap: m.cap }); });
      }
      var caps = out.filter(function (m) { return m.cap >= 0; });
      return caps.length ? caps : out;
    }
    function render() {
      for (var i = 0; i < 64; i++) {
        var c = cells[i], x = i % 8, y = Math.floor(i / 8);
        c.style.background = (x + y) % 2 ? '#2b3a4d' : '#dde5f0';
        c.innerHTML = '';
        var v = board[i];
        if (v) {
          var d = el('span');
          var kingMark = isKing(v) ? '♛' : '';
          d.textContent = kingMark;
          d.style.cssText = 'width:30px;height:30px;border-radius:50%;display:grid;place-items:center;font-size:14px;' +
            (side(v) === 1 ? 'background:#22303f;color:#ffd34d;border:2px solid #45596f;' : 'background:#e8d3b0;color:#8a5a2b;border:2px solid #b99a6b;');
          c.appendChild(d);
        }
        c.style.outline = i === sel ? '3px solid var(--primary)' : 'none';
        if (moves.some(function (m) { return m.to === i; })) c.style.boxShadow = 'inset 0 0 0 3px rgba(61,220,151,.8)';
        else c.style.boxShadow = 'none';
      }
      var mine = 0, theirs = 0;
      board.forEach(function (v) { if (side(v) === 1) mine++; else if (side(v) === 2) theirs++; });
      api.setScore(mine, 'checkers');
      api.state('你 ' + mine + ' 子 · 对手 ' + theirs + ' 子' + (twoP ? '' : '') + ' · ' + (turn === 1 ? (twoP ? '1P' : '你') : (twoP ? '2P' : '对手')) + '走');
    }
    function finish(winner) {
      over = true;
      api.state('已结束');
      api.overlay('对局结束', winner === 1 ? (twoP ? '1P 获胜' : '你赢了！') : (twoP ? '2P 获胜' : '对手获胜'),
        '再来一局', function () { checkers.init(twoP ? '2p' : '1p'); });
    }
    function apply(m) {
      board[m.to] = board[m.from]; board[m.from] = 0;
      if (m.cap >= 0) board[m.cap] = 0;
      var y = Math.floor(m.to / 8), v = board[m.to];
      if (!isKing(v) && ((side(v) === 1 && y === 0) || (side(v) === 2 && y === 7))) board[m.to] = v + 2;
      return m.cap >= 0;
    }
    function play(from, to) {
      var m = movesFor(from).filter(function (x) { return x.to === to; })[0];
      if (!m) return;
      var jump = apply(m);
      sel = -1; moves = [];
      render();
      // 连跳：吃到子后若同一棋子还能吃，保持选中
      if (jump && movesFor(to).some(function (x) { return x.cap >= 0; })) {
        sel = to; moves = movesFor(to); render(); return;
      }
      turn = turn === 1 ? 2 : 1;
      if (!allMoves(turn).length) { finish(turn === 1 ? 2 : 1); return; }
      render();
      if (!twoP && turn === 2) setTimeout(aiTurn, 420);
    }
    function aiTurn() {
      if (over) return;
      var list = allMoves(2);
      if (!list.length) { finish(1); return; }
      list.sort(function (a, b) { return (b.cap >= 0 ? 1 : 0) - (a.cap >= 0 ? 1 : 0) + (Math.random() - 0.5) * 0.4; });
      var m = list[0];
      var again = apply(m);
      if (again && movesFor(m.to).some(function (x) { return x.cap >= 0; })) {
        // 简化：AI 连跳只走一步，避免无限循环
      }
      turn = 1;
      if (!allMoves(1).length) { finish(2); return; }
      render();
    }
    for (var i2 = 0; i2 < 64; i2++) {
      (function (i2) {
        var c = el('button');
        c.type = 'button';
        c.style.cssText = 'width:44px;height:44px;border:0;border-radius:6px;cursor:pointer;display:grid;place-items:center;';
        c.addEventListener('click', function () {
          if (over) return;
          if (sel >= 0 && moves.some(function (m) { return m.to === i2; })) { play(sel, i2); return; }
          if (board[i2] && side(board[i2]) === turn) {
            if (turn === 2 && !twoP) return;
            sel = i2; moves = movesFor(i2); render();
          } else { sel = -1; moves = []; render(); }
        });
        cells.push(c); wrap.appendChild(c);
      })(i2);
    }
    api.setScore(12, 'checkers');
    api.state('你 12 子 · 对手 12 子 · ' + (twoP ? '1P' : '你') + '走');
    api.overlayHide();
    render();
  }

  /* ---------------- 接龙 Solitaire ---------------- */
  var solitaire = {
    modes: ['1p'],
    help: '点击牌堆发牌；点一张牌选中、再点目标位置移动。桌牌需红黑交替、点数递减，空列只能放 K；右侧四个基座按花色从 A 往上叠。清空全部牌即胜。',
    init: function () { startSolitaire(); },
    stop: function () {}
  };

  function startSolitaire() {
    var wrap = el('div');
    wrap.style.cssText = 'display:inline-block;';
    api.stage().appendChild(wrap);
    var SUITS = ['♠', '♥', '♦', '♣'];
    var RED = { '♥': 1, '♦': 1 };
    var RANKS = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
    var deck = [];
    SUITS.forEach(function (s) { RANKS.forEach(function (r, i) { deck.push({ s: s, r: i + 1, up: false }); }); });
    deck.sort(function () { return Math.random() - 0.5; });
    var cols = [[], [], [], [], [], [], []], found = { '♠': [], '♥': [], '♦': [], '♣': [] }, stock = [], waste = [];
    for (var i = 0; i < 7; i++) for (var j = 0; j <= i; j++) {
      var card = deck.pop(); card.up = j === i; cols[i].push(card);
    }
    while (deck.length) stock.push(deck.pop());
    var sel = null, over = false, moves = 0;

    function cardEl(card, faceUp) {
      var d = el('div');
      var size = 'width:54px;height:74px;';
      d.style.cssText = size + 'border-radius:6px;display:grid;place-items:center;font-size:13px;font-weight:700;' +
        (faceUp ? ('background:' + (RED[card.s] ? '#fff5f5' : '#f4f7fb') + ';color:' + (RED[card.s] ? '#c0392b' : '#1b2433') + ';border:1px solid #c9d2de;') : 'background:linear-gradient(135deg,#2a5c8f,#1b3b5c);border:1px solid #3a6f9f;color:transparent;');
      if (faceUp) d.innerHTML = '<span>' + card.r + '</span><span style="font-size:16px">' + card.s + '</span>';
      return d;
    }
    function topOf(a) { return a.length ? a[a.length - 1] : null; }
    function canStack(card, onto) {
      if (!onto) return card.r === 13;
      return RED[card.s] !== RED[onto.s] && card.r === onto.r - 1;
    }
    function canFound(card, pile) {
      if (!pile.length) return card.r === 1;
      var t = pile[pile.length - 1];
      return t.s === card.s && card.r === t.r + 1;
    }
    function render() {
      wrap.innerHTML = '';
      var top = el('div');
      top.style.cssText = 'display:flex;gap:8px;margin-bottom:12px;align-items:flex-start;';
      // 牌堆
      var stockBox = el('div');
      stockBox.style.cssText = 'width:54px;height:74px;border-radius:6px;border:1px dashed var(--border);display:grid;place-items:center;cursor:pointer;background:var(--card-2);color:var(--muted);font-size:12px;';
      stockBox.textContent = stock.length ? String(stock.length) : '空';
      stockBox.title = '点击发牌';
      stockBox.addEventListener('click', function () {
        if (!stock.length) {
          while (waste.length) { var c = waste.pop(); c.up = false; stock.push(c); }
        } else {
          var c2 = stock.pop(); c2.up = true; waste.push(c2);
        }
        sel = null; render();
      });
      top.appendChild(stockBox);
      // waste
      var wasteBox = el('div');
      wasteBox.style.cssText = 'width:54px;height:74px;position:relative;';
      var wTop = topOf(waste);
      if (wTop) {
        var we = cardEl(wTop, true);
        we.style.cursor = 'pointer';
        we.style.outline = sel && sel.kind === 'waste' ? '2px solid var(--primary)' : 'none';
        we.addEventListener('click', function () { sel = { kind: 'waste' }; render(); });
        wasteBox.appendChild(we);
      }
      top.appendChild(wasteBox);
      // foundations
      SUITS.forEach(function (s) {
        var f = el('div');
        f.style.cssText = 'width:54px;height:74px;border-radius:6px;border:1px dashed var(--border);background:var(--card-2);display:grid;place-items:center;font-size:20px;color:var(--muted);position:relative;cursor:pointer;';
        var p = found[s];
        if (p.length) {
          var ce = cardEl(topOf(p), true);
          ce.style.position = 'absolute'; ce.style.inset = '0';
          f.appendChild(ce);
        } else { f.textContent = s; }
        f.addEventListener('click', function () { tryDrop({ kind: 'found', suit: s }); });
        top.appendChild(f);
      });
      wrap.appendChild(top);

      var row = el('div');
      row.style.cssText = 'display:grid;grid-template-columns:repeat(7,54px);gap:8px;align-items:start;';
      cols.forEach(function (col, ci) {
        var cbox = el('div');
        cbox.style.cssText = 'min-height:120px;position:relative;';
        if (!col.length) {
          cbox.style.cssText += 'height:74px;border:1px dashed var(--border);border-radius:6px;background:color-mix(in oklab,var(--card-2) 60%, transparent);cursor:pointer;';
          cbox.addEventListener('click', function () { tryDrop({ kind: 'col', index: ci }); });
        }
        col.forEach(function (card, idx) {
          var ce = cardEl(card, card.up);
          ce.style.position = 'absolute';
          ce.style.top = (idx * 22) + 'px';
          ce.style.zIndex = idx;
          if (sel && sel.kind === 'col' && sel.index === ci && sel.idx === idx) ce.style.outline = '2px solid var(--primary)';
          ce.addEventListener('click', function (e) {
            e.stopPropagation();
            if (!card.up) return;
            if (sel) {
              if (sel.kind === 'col' && sel.index === ci && sel.idx === idx) { sel = null; render(); return; }
              tryDrop({ kind: 'col', index: ci, fromCol: true });
            } else {
              sel = { kind: 'col', index: ci, idx: idx };
              render();
            }
          });
          cbox.appendChild(ce);
        });
        // 列尾空白区域也接受落牌
        cbox.addEventListener('click', function (e) {
          if (e.target === cbox) tryDrop({ kind: 'col', index: ci });
        });
        row.appendChild(cbox);
      });
      wrap.appendChild(row);
      api.state('移动 ' + moves + ' 次 · 基座 ' + SUITS.reduce(function (n, s) { return n + found[s].length; }, 0) + ' / 52');
      api.setScore(SUITS.reduce(function (n, s) { return n + found[s].length; }, 0) * 10, 'solitaire');
    }
    function takeFromSel() { return sel; }
    function tryDrop(target) {
      if (!sel) return;
      var moving = null;
      if (sel.kind === 'waste') {
        var w = topOf(waste);
        if (w) moving = [w];
      } else if (sel.kind === 'col') {
        var col = cols[sel.index];
        if (sel.idx < col.length && col[sel.idx].up) moving = col.slice(sel.idx);
      }
      if (!moving || !moving.length) { sel = null; render(); return; }
      if (target.kind === 'found') {
        if (moving.length !== 1) { sel = null; render(); return; }
        if (canFound(moving[0], found[target.suit])) {
          if (sel.kind === 'waste') waste.pop(); else cols[sel.index].pop();
          found[target.suit].push(moving[0]);
          moves++;
          // 翻出桌牌
          if (sel.kind === 'col') {
            var c2 = cols[sel.index];
            if (c2.length && !c2[c2.length - 1].up) c2[c2.length - 1].up = true;
          }
          sel = null; checkWin(); render(); return;
        }
        sel = null; render(); return;
      }
      if (target.kind === 'col') {
        var dest = cols[target.index];
        var destTop = topOf(dest);
        if (sel.kind === 'col' && sel.index === target.index) { sel = null; render(); return; }
        if (canStack(moving[0], destTop)) {
          if (sel.kind === 'waste') waste.pop();
          else cols[sel.index].splice(sel.idx);
          moving.forEach(function (c3) { dest.push(c3); });
          moves++;
          if (sel.kind === 'col') {
            var c4 = cols[sel.index];
            if (c4.length && !c4[c4.length - 1].up) c4[c4.length - 1].up = true;
          }
          sel = null; checkWin(); render(); return;
        }
      }
      sel = null; render();
    }
    function checkWin() {
      var total = SUITS.reduce(function (n, s) { return n + found[s].length; }, 0);
      if (total === 52 && !over) {
        over = true;
        api.state('已通关');
        api.best('solitaire', 520);
        api.overlay('接龙完成！', '共用 ' + moves + ' 次移动', '再来一局', function () { startSolitaire(); });
      }
    }
    api.setScore(0, 'solitaire');
    render();
    api.overlayHide();
  }

  /* ---------------- 麻将连连看 Mahjong ---------------- */
  var mahjong = {
    modes: ['1p'],
    help: '点击两张相同的牌即可消除（直线、一个折角或两个折角相连，路径上不能有牌）。全部消完即通关。',
    init: function () { startMahjong(); },
    stop: function () {}
  };

  function startMahjong() {
    var COLS = 8, ROWS = 6, PAD = 1;
    var W = COLS + PAD * 2, H = ROWS + PAD * 2;
    var wrap = el('div');
    wrap.style.cssText = 'display:grid;grid-template-columns:repeat(' + COLS + ',40px);gap:4px;';
    api.stage().appendChild(wrap);
    var ICONS = ['🀇', '🀙', '🀐', '🀁', '🀚', '🀑', '🀃', '🀜', '🀓'];
    var grid, cells, sel = -1, left = 0, moves = 0;

    function build() {
      var pairs = (COLS * ROWS) / 2;
      var pool = [];
      for (var i = 0; i < pairs; i++) {
        var ic = ICONS[i % ICONS.length];
        pool.push(ic, ic);
      }
      pool.sort(function () { return Math.random() - 0.5; });
      grid = [];
      for (var y = 0; y < H; y++) {
        grid.push([]);
        for (var x = 0; x < W; x++) grid[y].push(0);
      }
      var k = 0;
      for (var r = 0; r < ROWS; r++) for (var c = 0; c < COLS; c++) {
        var id = k + 1;
        grid[r + PAD][c + PAD] = { id: id, icon: pool[k] };
        k++;
      }
      left = COLS * ROWS;
      sel = -1; moves = 0;
    }
    function emptyCell(x, y) {
      if (x < 0 || y < 0 || x >= W || y >= H) return false;
      return grid[y][x] === 0;
    }
    function lineClear(x1, y1, x2, y2) {
      if (x1 === x2) {
        var s = Math.min(y1, y2), e = Math.max(y1, y2);
        for (var y = s + 1; y < e; y++) if (grid[y][x1] !== 0) return false;
        return true;
      }
      if (y1 === y2) {
        var s2 = Math.min(x1, x2), e2 = Math.max(x1, x2);
        for (var x = s2 + 1; x < e2; x++) if (grid[y1][x] !== 0) return false;
        return true;
      }
      return false;
    }
    function connectable(a, b) {
      var ax = a.x, ay = a.y, bx = b.x, by = b.y;
      // 直线
      if ((ax === bx || ay === by) && lineClear(ax, ay, bx, by)) return true;
      // 一个折角
      if (emptyCell(bx, ay) && lineClear(ax, ay, bx, ay) && lineClear(bx, ay, bx, by)) return true;
      if (emptyCell(ax, by) && lineClear(ax, ay, ax, by) && lineClear(ax, by, bx, by)) return true;
      // 两个折角：沿行
      for (var x = 0; x < W; x++) {
        if (x === ax || x === bx) continue;
        if (emptyCell(x, ay) && emptyCell(x, by) &&
            lineClear(ax, ay, x, ay) && lineClear(x, ay, x, by) && lineClear(x, by, bx, by)) return true;
      }
      // 两个折角：沿列
      for (var y = 0; y < H; y++) {
        if (y === ay || y === by) continue;
        if (emptyCell(ax, y) && emptyCell(bx, y) &&
            lineClear(ax, ay, ax, y) && lineClear(ax, y, bx, y) && lineClear(bx, y, bx, by)) return true;
      }
      return false;
    }
    function render() {
      cells.forEach(function (c, i) {
        var x = i % COLS, y = Math.floor(i / COLS);
        var v = grid[y + PAD][x + PAD];
        c.textContent = v ? v.icon : '';
        c.style.background = v ? 'var(--card-2)' : 'transparent';
        c.style.border = v ? '1px solid var(--border)' : '1px dashed color-mix(in oklab, var(--border) 40%, transparent)';
        c.style.outline = (sel === i) ? '3px solid var(--primary)' : 'none';
        c.style.opacity = v ? '1' : '0.25';
      });
      api.state('剩余 ' + left + ' 张 · 已消 ' + (moves / 2) + ' 对');
      api.setScore((COLS * ROWS - left) * 5, 'mahjong');
    }
    function click(i) {
      var x = i % COLS, y = Math.floor(i / COLS);
      var v = grid[y + PAD][x + PAD];
      if (!v) return;
      if (sel === i) { sel = -1; render(); return; }
      if (sel < 0) { sel = i; render(); return; }
      var sx = sel % COLS, sy = Math.floor(sel / COLS);
      var sv = grid[sy + PAD][sx + PAD];
      if (!sv) { sel = i; render(); return; }
      if (sv.icon !== v.icon) { sel = i; render(); return; }
      if (!connectable({ x: sx + PAD, y: sy + PAD }, { x: x + PAD, y: y + PAD })) {
        api.state('这两张牌连不上（路径被挡住了）');
        sel = i; render(); return;
      }
      grid[sy + PAD][sx + PAD] = 0;
      grid[y + PAD][x + PAD] = 0;
      left -= 2; moves += 1;
      sel = -1;
      render();
      if (left === 0) {
        api.state('已通关');
        api.best('mahjong', 300);
        api.overlay('全部消除！', '用了 ' + moves + ' 次配对', '再来一局', function () { startMahjong(); });
      }
    }
    build();
    cells = [];
    for (var i = 0; i < COLS * ROWS; i++) {
      (function (i) {
        var c = el('button');
        c.type = 'button';
        c.style.cssText = 'width:40px;height:44px;border-radius:6px;font-size:20px;cursor:pointer;display:grid;place-items:center;background:var(--card-2);';
        c.addEventListener('click', function () { click(i); });
        cells.push(c); wrap.appendChild(c);
      })(i);
    }
    render();
    api.overlayHide();
  }

  window.ArcadeGames = {
    snake2: snake2,
    pong: pong,
    ttt: ttt,
    c4: c4,
    reversi: reversi,
    memory: memory,
    breakout: breakout,
    fifteen: fifteen,
    tetris: tetris,
    pacman: pacman,
    flappy: flappy,
    sudoku: sudoku,
    chess: chess,
    checkers: checkers,
    spaceinvaders: spaceinvaders,
    dino: dino,
    solitaire: solitaire,
    mahjong: mahjong,
    _bind: bind
  };

  // 绑定主逻辑暴露的桥接接口，再补启挂起的扩展游戏
  if (window.ArcadeAPI) bind(window.ArcadeAPI);
  if (typeof window.ArcadeBoot === 'function') window.ArcadeBoot();
})();

/* ============================================================
   开源网页游戏整合：把网页游戏栏目中可嵌入的条目
   统一展示在小游戏大厅，复用 webgames.html 的站内播放器
   ============================================================ */
(function () {
  'use strict';
  var grid = document.getElementById('arcadeWebGames');
  if (!grid) return;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function safe(u) { return /^https?:\/\//i.test(String(u || '')) ? u : ''; }

  fetch('webgames.json', { cache: 'no-cache' })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (data) {
      var picks = (data.items || []).filter(function (x) { return x.embeddable && safe(x.play); });
      if (!picks.length) { grid.innerHTML = '<p class="muted">暂无可站内畅玩的网页游戏。</p>'; return; }
      grid.innerHTML = picks.map(function (it) {
        var tags = (it.tags || []).slice(0, 2).map(function (t) {
          return '<span class="chip">' + esc(t) + '</span>';
        }).join('');
        return '<div class="card">' +
          '<h4>' + esc(it.name) + '</h4>' +
          '<p>' + esc(it.desc || '') + '</p>' +
          '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">' +
            '<a class="btn primary" href="webgames.html?play=' + encodeURIComponent(it.id) + '">站内开玩</a>' +
            '<a class="btn" href="' + esc(safe(it.play)) + '" target="_blank" rel="noopener noreferrer">原页面</a>' +
            tags +
          '</div>' +
        '</div>';
      }).join('') +
        '<div class="card" style="display:grid;place-items:center;">' +
          '<h4>还有更多</h4><p>云游戏平台与源码项目都在网页游戏栏目。</p>' +
          '<a class="btn" href="webgames.html">查看全部入口</a>' +
        '</div>';
    })
    .catch(function () {
      grid.innerHTML = '<p class="muted">入口列表读取失败，可前往 <a href="webgames.html">网页游戏栏目</a> 查看。</p>';
    });
})();
