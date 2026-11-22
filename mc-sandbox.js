/* ============================================================
   网页版方块世界（mc-sandbox）
   ------------------------------------------------------------
   纯前端体素沙盒，不依赖后端与任何游戏客户端：
   - 地形：种子 + 多层值噪声，草地/沙地/水面/树
   - 渲染：按 16×16 区块合并面（隐藏内部面），顶点色 + 平面法线
   - 物理：AABB 逐轴碰撞、重力、跳跃
   - 交互：指针锁定 + DDA 射线拾取，左键挖、右键放
   - 存档：只存被改动过的方块（localStorage: niao.mc.sandbox.v1）
   ============================================================ */
(function () {
  'use strict';

  var stage = document.getElementById('sbxStage');
  if (!stage) return;

  var overlay = document.getElementById('sbxOverlay');
  var hotbarEl = document.getElementById('sbxHotbar');
  var posEl = document.getElementById('sbxPos');
  var fpsEl = document.getElementById('sbxFps');
  var stateEl = document.getElementById('sbxState');
  var startBtn = document.getElementById('sbxStart');

  if (!window.THREE) {
    stage.innerHTML = '<div class="sbx-fallback"><h3>渲染库未加载</h3><p>请检查 vendor/three.min.js 是否随页面一起部署。</p></div>';
    return;
  }

  /* ---------------- 常量 ---------------- */
  var W = 64, H = 32, D = 64;          // 世界尺寸
  var CHUNK = 16;                       // 区块边长
  var SEA = 10;                         // 水面高度
  var SAVE_KEY = 'niao.mc.sandbox.v1';
  var REACH = 6;

  var AIR = 0, GRASS = 1, DIRT = 2, STONE = 3, SAND = 4, WOOD = 5, LEAVES = 6, WATER = 7, BEDROCK = 8;

  // 每种方块的六面色（顶 / 侧 / 底），数字为十六进制
  var BLOCKS = {
    1: { name: '草方块', top: 0x74c04a, side: 0x6f8f4a, bottom: 0x8a6a4a },
    2: { name: '泥土', top: 0x8a6a4a, side: 0x846444, bottom: 0x846444 },
    3: { name: '石头', top: 0xa2aab2, side: 0x97a0a8, bottom: 0x8d949b },
    4: { name: '沙子', top: 0xe8ddb2, side: 0xded2a4, bottom: 0xd6ca9c },
    5: { name: '木头', top: 0xa8814f, side: 0x6b4a2c, bottom: 0xa8814f },
    6: { name: '树叶', top: 0x4f9e53, side: 0x468f4a, bottom: 0x3d8043 },
    7: { name: '水', top: 0x3f7fc0, side: 0x3a76b4, bottom: 0x356aa4 },
    8: { name: '基岩', top: 0x4a4f55, side: 0x444a50, bottom: 0x3e4349 }
  };

  var HOTBAR = [GRASS, DIRT, STONE, SAND, WOOD, LEAVES];

  /* ---------------- 地形数据 ---------------- */
  var world = new Uint8Array(W * H * D);
  var edits = Object.create(null);   // "x,y,z" -> type
  var seed = 20261122;
  var selected = GRASS;

  function idx(x, y, z) { return (y * D + z) * W + x; }

  function inside(x, y, z) { return x >= 0 && x < W && y >= 0 && y < H && z >= 0 && z < D; }

  function getBlock(x, y, z) {
    if (!inside(x, y, z)) return AIR;
    return world[idx(x, y, z)];
  }

  function isSolid(t) { return t !== AIR && t !== WATER; }

  function solidAt(x, y, z) { return isSolid(getBlock(x, y, z)); }

  /* ---------------- 随机与噪声 ---------------- */
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // 预生成噪声表，双线性插值成连续地形
  var noiseTable = null;
  function buildNoise(rnd) {
    var n = 32;
    var table = new Float32Array(n * n);
    for (var i = 0; i < table.length; i++) table[i] = rnd();
    return { n: n, t: table };
  }

  function smooth(t) { return t * t * (3 - 2 * t); }

  function sampleNoise(nz, x, z, scale) {
    var n = nz.n;
    var fx = (x / scale) % n, fz = (z / scale) % n;
    if (fx < 0) fx += n;
    if (fz < 0) fz += n;
    var x0 = Math.floor(fx), z0 = Math.floor(fz);
    var x1 = (x0 + 1) % n, z1 = (z0 + 1) % n;
    var tx = smooth(fx - x0), tz = smooth(fz - z0);
    var a = nz.t[z0 * n + x0], b = nz.t[z0 * n + x1];
    var c = nz.t[z1 * n + x0], d = nz.t[z1 * n + x1];
    return (a * (1 - tx) + b * tx) * (1 - tz) + (c * (1 - tx) + d * tx) * tz;
  }

  function heightAt(nz, x, z) {
    var h = sampleNoise(nz, x, z, 16) * 0.60
          + sampleNoise(nz, x + 77, z + 13, 8) * 0.28
          + sampleNoise(nz, x + 31, z + 91, 4) * 0.12;
    return Math.round(5 + h * 11);   // 5 ~ 16
  }

  function generate(sd) {
    world.fill(AIR);
    edits = Object.create(null);
    var rnd = mulberry32(sd >>> 0);
    var nz = buildNoise(rnd);

    for (var x = 0; x < W; x++) {
      for (var z = 0; z < D; z++) {
        var h = heightAt(nz, x, z);
        if (h > H - 6) h = H - 6;
        var beach = h <= SEA;
        for (var y = 0; y <= h; y++) {
          var t;
          if (y === 0) t = BEDROCK;
          else if (y === h) t = beach ? SAND : GRASS;
          else if (y > h - 4) t = beach ? SAND : DIRT;
          else t = STONE;
          world[idx(x, y, z)] = t;
        }
        // 水面填到海平面
        for (var wy = h + 1; wy <= SEA; wy++) world[idx(x, wy, z)] = WATER;
      }
    }

    // 种树：只长在高于水面的草地上
    for (var i = 0; i < 90; i++) {
      var tx = 3 + Math.floor(rnd() * (W - 6));
      var tz = 3 + Math.floor(rnd() * (D - 6));
      var th = heightAt(nz, tx, tz);
      if (th <= SEA + 1) continue;
      if (getBlock(tx, th, tz) !== GRASS) continue;
      var trunk = 3 + Math.floor(rnd() * 3);
      for (var ty = 1; ty <= trunk; ty++) {
        if (th + ty < H) world[idx(tx, th + ty, tz)] = WOOD;
      }
      var top = th + trunk;
      for (var ox = -2; ox <= 2; ox++) {
        for (var oz = -2; oz <= 2; oz++) {
          for (var oy = -1; oy <= 1; oy++) {
            var dist = Math.abs(ox) + Math.abs(oz) + Math.abs(oy);
            if (dist > 3) continue;
            var px = tx + ox, py = top + oy, pz = tz + oz;
            if (!inside(px, py, pz)) continue;
            if (getBlock(px, py, pz) !== AIR) continue;
            world[idx(px, py, pz)] = LEAVES;
          }
        }
      }
    }
  }

  /* ---------------- Three.js 场景 ---------------- */
  var renderer, scene, camera;
  var chunkMeshes = [];
  var waterMeshes = [];

  try {
    renderer = new THREE.WebGLRenderer({ antialias: false, powerPreference: 'high-performance' });
  } catch (e) {
    stage.innerHTML = '<div class="sbx-fallback"><h3>当前浏览器不支持 WebGL</h3><p>换 Chrome / Edge / Firefox 较新版本再试。</p></div>';
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(stage.clientWidth, stage.clientHeight || 480);
  stage.insertBefore(renderer.domElement, stage.firstChild);

  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x9ed0ef);
  scene.fog = new THREE.Fog(0x9ed0ef, 46, 96);

  camera = new THREE.PerspectiveCamera(72, (stage.clientWidth || 960) / (stage.clientHeight || 540), 0.1, 260);

  scene.add(new THREE.HemisphereLight(0xffffff, 0x6d7f8f, 0.95));
  var sun = new THREE.DirectionalLight(0xffffff, 0.55);
  sun.position.set(40, 90, 20);
  scene.add(sun);

  // 用基础材质 + 顶点色：面明暗已经在 FACES.shade 里算好，避免叠加光照把亮色冲成纯白
  var matOpaque = new THREE.MeshBasicMaterial({ vertexColors: true, fog: true });
  var matWater = new THREE.MeshBasicMaterial({ vertexColors: true, fog: true, transparent: true, opacity: 0.74, depthWrite: false });

  /* ---------------- 网格生成 ---------------- */
  var FACES = [
    { dir: [0, 1, 0], corn: [[0, 1, 0], [0, 1, 1], [1, 1, 1], [1, 1, 0]], shade: 1.0 },
    { dir: [0, -1, 0], corn: [[0, 0, 0], [1, 0, 0], [1, 0, 1], [0, 0, 1]], shade: 0.55 },
    { dir: [1, 0, 0], corn: [[1, 0, 0], [1, 1, 0], [1, 1, 1], [1, 0, 1]], shade: 0.86 },
    { dir: [-1, 0, 0], corn: [[0, 0, 1], [0, 1, 1], [0, 1, 0], [0, 0, 0]], shade: 0.86 },
    { dir: [0, 0, 1], corn: [[1, 0, 1], [1, 1, 1], [0, 1, 1], [0, 0, 1]], shade: 0.75 },
    { dir: [0, 0, -1], corn: [[0, 0, 0], [0, 1, 0], [1, 1, 0], [1, 0, 0]], shade: 0.75 }
  ];

  function faceColor(type, faceIdx) {
    var b = BLOCKS[type];
    if (!b) return null;
    var base = faceIdx === 0 ? b.top : (faceIdx === 1 ? b.bottom : b.side);
    var shade = FACES[faceIdx].shade;
    var r = ((base >> 16) & 255) / 255 * shade;
    var g = ((base >> 8) & 255) / 255 * shade;
    var bl = (base & 255) / 255 * shade;
    return [r, g, bl];
  }

  function buildChunk(cx, cz) {
    var pos = [], col = [], wpos = [], wcol = [];
    var x0 = cx * CHUNK, z0 = cz * CHUNK;

    for (var x = x0; x < x0 + CHUNK; x++) {
      for (var z = z0; z < z0 + CHUNK; z++) {
        for (var y = 0; y < H; y++) {
          var t = getBlock(x, y, z);
          if (t === AIR) continue;
          var isWater = (t === WATER);
          var target = isWater ? { p: wpos, c: wcol } : { p: pos, c: col };

          for (var f = 0; f < 6; f++) {
            var d = FACES[f].dir;
            var nt = getBlock(x + d[0], y + d[1], z + d[2]);
            var neighborBlocks;
            if (isWater) neighborBlocks = (nt !== AIR);          // 水只画外露面
            else neighborBlocks = isSolid(nt);                    // 实体被水/空气/树叶旁的面都要画
            if (neighborBlocks) continue;

            var c = faceColor(t, f);
            var corners = FACES[f].corn;
            var a = corners[0], b2 = corners[1], c3 = corners[2], d3 = corners[3];
            // 两个三角形：0-1-2 / 0-2-3
            var quad = [a, b2, c3, a, c3, d3];
            for (var q = 0; q < 6; q++) {
              var v = quad[q];
              target.p.push(x + v[0], y + v[1], z + v[2]);
              target.c.push(c[0], c[1], c[2]);
            }
          }
        }
      }
    }

    function mkMesh(arrPos, arrCol, material) {
      if (!arrPos.length) return null;
      var g = new THREE.BufferGeometry();
      g.setAttribute('position', new THREE.Float32BufferAttribute(arrPos, 3));
      g.setAttribute('color', new THREE.Float32BufferAttribute(arrCol, 3));
      g.computeVertexNormals();
      var m = new THREE.Mesh(g, material);
      m.frustumCulled = true;
      return m;
    }

    return {
      solid: mkMesh(pos, col, matOpaque),
      water: mkMesh(wpos, wcol, matWater)
    };
  }

  function rebuildAll() {
    for (var i = 0; i < chunkMeshes.length; i++) {
      if (chunkMeshes[i]) { scene.remove(chunkMeshes[i]); chunkMeshes[i].geometry.dispose(); }
      if (waterMeshes[i]) { scene.remove(waterMeshes[i]); waterMeshes[i].geometry.dispose(); }
    }
    chunkMeshes = [];
    waterMeshes = [];

    var nx = Math.ceil(W / CHUNK), nz = Math.ceil(D / CHUNK);
    for (var cx = 0; cx < nx; cx++) {
      for (var cz = 0; cz < nz; cz++) {
        var built = buildChunk(cx, cz);
        var i2 = cx * nz + cz;
        chunkMeshes[i2] = built.solid;
        waterMeshes[i2] = built.water;
        if (built.solid) scene.add(built.solid);
        if (built.water) scene.add(built.water);
      }
    }
  }

  function rebuildAt(x, z) {
    var nx = Math.ceil(W / CHUNK), nz = Math.ceil(D / CHUNK);
    var cx = Math.floor(x / CHUNK), cz = Math.floor(z / CHUNK);
    var i = cx * nz + cz;
    if (chunkMeshes[i]) { scene.remove(chunkMeshes[i]); chunkMeshes[i].geometry.dispose(); }
    if (waterMeshes[i]) { scene.remove(waterMeshes[i]); waterMeshes[i].geometry.dispose(); }
    var built = buildChunk(cx, cz);
    chunkMeshes[i] = built.solid;
    waterMeshes[i] = built.water;
    if (built.solid) scene.add(built.solid);
    if (built.water) scene.add(built.water);
  }

  /* ---------------- 玩家 ---------------- */
  var player = {
    x: W / 2 + 0.5, y: 0, z: D / 2 + 0.5,
    vy: 0, yaw: 0, pitch: 0,
    onGround: false
  };

  var EYE = 1.62, RADIUS = 0.3, TALL = 1.8;
  var GRAVITY = 30, JUMP = 8.6, SPEED = 4.8, SPRINT = 7.6;

  function spawn() {
    // 优先落在中心附近的草地上，避免一睁眼就是沙滩或水下
    var best = null;
    var cx = Math.floor(W / 2), cz = Math.floor(D / 2);
    for (var r = 0; r < 22 && !best; r++) {
      for (var dx = -r; dx <= r && !best; dx++) {
        for (var dz = -r; dz <= r && !best; dz++) {
          var sx = cx + dx, sz = cz + dz;
          if (sx < 2 || sz < 2 || sx > W - 3 || sz > D - 3) continue;
          var top = H - 1;
          while (top > 0 && !solidAt(sx, top, sz)) top--;
          if (top <= SEA + 1) continue;
          if (getBlock(sx, top, sz) !== GRASS) continue;
          best = { x: sx, z: sz, y: top };
        }
      }
    }
    if (!best) {
      var sx2 = cx, sz2 = cz, y2 = H - 1;
      while (y2 > 0 && !solidAt(sx2, y2, sz2)) y2--;
      best = { x: sx2, z: sz2, y: y2 };
    }
    player.x = best.x + 0.5; player.z = best.z + 0.5; player.y = best.y + 1.02;
    player.vy = 0; player.yaw = 0; player.pitch = -0.08;
  }

  function collides(px, py, pz) {
    var minX = Math.floor(px - RADIUS), maxX = Math.floor(px + RADIUS);
    var minY = Math.floor(py + 0.001), maxY = Math.floor(py + TALL - 0.001);
    var minZ = Math.floor(pz - RADIUS), maxZ = Math.floor(pz + RADIUS);
    for (var y = minY; y <= maxY; y++) {
      for (var z = minZ; z <= maxZ; z++) {
        for (var x = minX; x <= maxX; x++) {
          if (solidAt(x, y, z)) return true;
        }
      }
    }
    return false;
  }

  var keys = Object.create(null);

  function updatePlayer(dt) {
    var fwd = 0, side = 0;
    if (keys['w'] || keys['arrowup']) fwd += 1;
    if (keys['s'] || keys['arrowdown']) fwd -= 1;
    if (keys['a'] || keys['arrowleft']) side -= 1;
    if (keys['d'] || keys['arrowright']) side += 1;

    var speed = (keys['shift'] ? SPRINT : SPEED);
    var len = Math.hypot(fwd, side) || 1;
    var sin = Math.sin(player.yaw), cos = Math.cos(player.yaw);
    // 前方 = (-sin, -cos)，右方 = (cos, -sin)
    var dx = (-sin * fwd + cos * side) / len * speed * dt;
    var dz = (-cos * fwd - sin * side) / len * speed * dt;

    player.vy -= GRAVITY * dt;
    if (player.vy < -40) player.vy = -40;

    // 逐轴移动 + 碰撞
    var nx = player.x + dx;
    if (!collides(nx, player.y, player.z)) player.x = nx;
    var nz = player.z + dz;
    if (!collides(player.x, player.y, nz)) player.z = nz;

    var ny = player.y + player.vy * dt;
    if (!collides(player.x, ny, player.z)) {
      player.y = ny;
      player.onGround = false;
    } else {
      if (player.vy < 0) {
        player.y = Math.floor(ny) + 1.0001;
        player.onGround = true;
      } else {
        player.y = Math.ceil(ny + TALL) - TALL - 0.0001;
      }
      player.vy = 0;
    }

    if (player.y < -8) spawn();

    // 边界
    player.x = Math.max(0.4, Math.min(W - 0.4, player.x));
    player.z = Math.max(0.4, Math.min(D - 0.4, player.z));
  }

  /* ---------------- 射线拾取 ---------------- */
  function raycast() {
    var dirX = -Math.sin(player.yaw) * Math.cos(player.pitch);
    var dirY = Math.sin(player.pitch);
    var dirZ = -Math.cos(player.yaw) * Math.cos(player.pitch);

    var ox = player.x, oy = player.y + EYE, oz = player.z;

    var x = Math.floor(ox), y = Math.floor(oy), z = Math.floor(oz);
    var stepX = dirX > 0 ? 1 : -1, stepY = dirY > 0 ? 1 : -1, stepZ = dirZ > 0 ? 1 : -1;
    var tDeltaX = Math.abs(1 / (dirX || 1e-9));
    var tDeltaY = Math.abs(1 / (dirY || 1e-9));
    var tDeltaZ = Math.abs(1 / (dirZ || 1e-9));
    var tMaxX = ((dirX > 0 ? (x + 1 - ox) : (ox - x)) || 1e-9) * tDeltaX;
    var tMaxY = ((dirY > 0 ? (y + 1 - oy) : (oy - y)) || 1e-9) * tDeltaY;
    var tMaxZ = ((dirZ > 0 ? (z + 1 - oz) : (oz - z)) || 1e-9) * tDeltaZ;

    var face = [0, 0, 0];
    for (var i = 0; i < REACH * 4; i++) {
      var t = getBlock(x, y, z);
      if (t !== AIR && t !== WATER) {
        return { x: x, y: y, z: z, nx: face[0], ny: face[1], nz: face[2], type: t };
      }
      if (tMaxX < tMaxY && tMaxX < tMaxZ) {
        if (tMaxX > REACH) break;
        x += stepX; tMaxX += tDeltaX; face = [-stepX, 0, 0];
      } else if (tMaxY < tMaxZ) {
        if (tMaxY > REACH) break;
        y += stepY; tMaxY += tDeltaY; face = [0, -stepY, 0];
      } else {
        if (tMaxZ > REACH) break;
        z += stepZ; tMaxZ += tDeltaZ; face = [0, 0, -stepZ];
      }
    }
    return null;
  }

  /* ---------------- 编辑 ---------------- */
  var saveTimer = 0;
  function persist() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      try { localStorage.setItem(SAVE_KEY, JSON.stringify({ seed: seed, edits: edits })); }
      catch (e) { /* 配额不足时忽略 */ }
    }, 400);
  }

  function setBlock(x, y, z, type, skipSave) {
    if (!inside(x, y, z)) return false;
    world[idx(x, y, z)] = type;
    edits[x + ',' + y + ',' + z] = type;
    rebuildAt(x, z);
    if (!skipSave) persist();
    return true;
  }

  function breakBlock() {
    var hit = raycast();
    if (!hit || hit.type === BEDROCK) return;
    setBlock(hit.x, hit.y, hit.z, AIR);
    // 上面是水就一起收掉，避免悬空水柱
    if (getBlock(hit.x, hit.y + 1, hit.z) === WATER) setBlock(hit.x, hit.y + 1, hit.z, AIR, true);
    persist();
  }

  function placeBlock() {
    var hit = raycast();
    if (!hit) return;
    var x = hit.x + hit.nx, y = hit.y + hit.ny, z = hit.z + hit.nz;
    if (!inside(x, y, z)) return;
    var cur = getBlock(x, y, z);
    if (cur !== AIR && cur !== WATER) return;
    // 不能放在自己身上
    var px = player.x, py = player.y, pz = player.z;
    if (x + 1 > px - RADIUS && x < px + RADIUS &&
        y + 1 > py && y < py + TALL &&
        z + 1 > pz - RADIUS && z < pz + RADIUS) return;
    setBlock(x, y, z, selected);
  }

  /* ---------------- 输入 ---------------- */
  var locked = false;

  function onKeyDown(e) {
    var k = e.key.toLowerCase();
    keys[k] = true;
    if (locked && (k === ' ' || k.indexOf('arrow') === 0)) e.preventDefault();
    if (k >= '1' && k <= '6') {
      selected = HOTBAR[parseInt(k, 10) - 1];
      paintHotbar();
    }
    if (k === ' ') { e.preventDefault(); }
    if (k === ' ' && player.onGround) { player.vy = JUMP; player.onGround = false; }
  }

  function onKeyUp(e) { keys[e.key.toLowerCase()] = false; }

  function onMouseMove(e) {
    if (!locked) return;
    player.yaw -= e.movementX * 0.0026;
    player.pitch -= e.movementY * 0.0024;
    var lim = Math.PI / 2 - 0.02;
    if (player.pitch > lim) player.pitch = lim;
    if (player.pitch < -lim) player.pitch = -lim;
  }

  function onMouseDown(e) {
    if (!locked) return;
    if (e.button === 0) breakBlock();
    else if (e.button === 2) placeBlock();
  }

  function onWheel(e) {
    if (!locked) return;
    e.preventDefault();
    var i = HOTBAR.indexOf(selected);
    i = (i + (e.deltaY > 0 ? 1 : -1) + HOTBAR.length) % HOTBAR.length;
    selected = HOTBAR[i];
    paintHotbar();
  }

  function lock() {
    if (stage.requestPointerLock) stage.requestPointerLock();
  }

  document.addEventListener('pointerlockchange', function () {
    locked = document.pointerLockElement === stage;
    document.body.classList.toggle('sbx-started', locked);
    stage.classList.toggle('sbx-started', locked);
    if (overlay) overlay.hidden = locked;
    if (stateEl) stateEl.textContent = locked ? '已进入世界 · Esc 释放鼠标' : '已暂停 · 点画面继续';
  });

  stage.addEventListener('click', function (e) {
    if (!locked && e.target === renderer.domElement) lock();
  });
  if (startBtn) startBtn.addEventListener('click', lock);

  document.addEventListener('keydown', onKeyDown);
  document.addEventListener('keyup', onKeyUp);
  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mousedown', onMouseDown);
  document.addEventListener('contextmenu', function (e) {
    if (locked) e.preventDefault();
  });
  document.addEventListener('wheel', onWheel, { passive: false });

  /* ---------------- UI ---------------- */
  function hex(c) { return '#' + ('000000' + c.toString(16)).slice(-6); }

  function paintHotbar() {
    if (!hotbarEl) return;
    hotbarEl.innerHTML = HOTBAR.map(function (t, i) {
      var b = BLOCKS[t];
      return '<button class="sbx-slot' + (t === selected ? ' is-on' : '') + '" type="button" data-t="' + t + '" title="' + b.name + '（' + (i + 1) + '）">' +
        '<b>' + (i + 1) + '</b><i style="background:' + hex(b.top) + '"></i></button>';
    }).join('');
  }

  if (hotbarEl) {
    hotbarEl.addEventListener('click', function (e) {
      var btn = e.target.closest('.sbx-slot');
      if (!btn) return;
      selected = parseInt(btn.getAttribute('data-t'), 10);
      paintHotbar();
    });
  }

  /* ---------------- 主循环 ---------------- */
  var last = performance.now();
  var fpsAcc = 0, fpsN = 0, hudTimer = 0;

  function loop(now) {
    var dt = Math.min((now - last) / 1000, 0.05);
    last = now;

    if (locked) updatePlayer(dt);

    camera.position.set(player.x, player.y + EYE, player.z);
    camera.rotation.order = 'YXZ';
    camera.rotation.y = player.yaw;
    camera.rotation.x = player.pitch;

    renderer.render(scene, camera);

    fpsAcc += dt; fpsN++;
    hudTimer += dt;
    if (hudTimer > 0.25) {
      if (posEl) posEl.textContent = 'x ' + player.x.toFixed(1) + ' · y ' + player.y.toFixed(1) + ' · z ' + player.z.toFixed(1);
      if (fpsEl) fpsEl.textContent = (fpsN / Math.max(fpsAcc, 0.001)).toFixed(0) + ' fps';
      fpsAcc = 0; fpsN = 0; hudTimer = 0;
    }
    requestAnimationFrame(loop);
  }

  /* ---------------- 尺寸与按钮 ---------------- */
  function resize() {
    var w = stage.clientWidth, h = stage.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);

  var regenBtn = document.getElementById('sbxRegen');
  if (regenBtn) {
    regenBtn.addEventListener('click', function () {
      seed = (Math.random() * 1e9) | 0;
      generate(seed);
      rebuildAll();
      spawn();
      try { localStorage.setItem(SAVE_KEY, JSON.stringify({ seed: seed, edits: {} })); } catch (e) { }
      if (stateEl) stateEl.textContent = '已生成新世界 · 种子 ' + seed;
    });
  }

  var clearBtn = document.getElementById('sbxClear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      try { localStorage.removeItem(SAVE_KEY); } catch (e) { }
      generate(seed);
      rebuildAll();
      spawn();
      if (stateEl) stateEl.textContent = '存档已清空，回到初始地形';
    });
  }

  var fullBtn = document.getElementById('sbxFull');
  var wrap = document.getElementById('sbxWrap');
  if (fullBtn && wrap) {
    fullBtn.addEventListener('click', function () {
      if (document.fullscreenElement) document.exitFullscreen();
      else if (wrap.requestFullscreen) wrap.requestFullscreen();
    });
    document.addEventListener('fullscreenchange', function () { setTimeout(resize, 120); });
  }

  /* ---------------- 启动 ---------------- */
  var saved = null;
  try { saved = JSON.parse(localStorage.getItem(SAVE_KEY) || 'null'); } catch (e) { saved = null; }

  if (saved && typeof saved.seed === 'number') {
    seed = saved.seed;
    generate(seed);
    if (saved.edits) {
      edits = Object.create(null);
      Object.keys(saved.edits).forEach(function (k) {
        var p = k.split(',');
        var x = +p[0], y = +p[1], z = +p[2];
        if (!inside(x, y, z)) return;
        world[idx(x, y, z)] = saved.edits[k];
        edits[k] = saved.edits[k];
      });
    }
  } else {
    generate(seed);
  }

  spawn();
  rebuildAll();
  paintHotbar();
  resize();
  requestAnimationFrame(function (t) { last = t; loop(t); });

  if (stateEl) stateEl.textContent = saved ? '已载入上次存档 · 点画面继续' : '点「开始游戏」进入世界';

  // 调试 / 二次开发入口：控制台可直接读写方块与玩家位置
  window.NiaoSandbox = {
    player: player,
    world: world,
    getBlock: getBlock,
    setBlock: setBlock,
    raycast: raycast,
    rebuild: rebuildAll,
    seed: function () { return seed; },
    reseed: function (sd) { seed = sd >>> 0; generate(seed); rebuildAll(); spawn(); }
  };
})();
