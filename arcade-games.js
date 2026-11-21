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

  window.ArcadeGames = {
    snake2: snake2,
    pong: pong,
    ttt: ttt,
    c4: c4,
    reversi: reversi,
    memory: memory,
    breakout: breakout,
    fifteen: fifteen,
    _bind: bind
  };

  // 绑定主逻辑暴露的桥接接口，再补启挂起的扩展游戏
  if (window.ArcadeAPI) bind(window.ArcadeAPI);
  if (typeof window.ArcadeBoot === 'function') window.ArcadeBoot();
})();
