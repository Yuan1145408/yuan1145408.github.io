/* ============================================================
   鸟国聚合搜索 · 搜索源配置
   ------------------------------------------------------------
   每个源都是「纯前端可跨域访问的公开接口」，无需任何 API Key。
   新增一个源只需在 SOURCES 里追加一个对象，字段说明见 README。

   必需字段：
     id        唯一标识（用于 URL 参数、筛选、缓存）
     name      展示名
     short     徽标用的短名（1-4 字）
     group     分组 key（见 GROUPS）
     weight    基础权重（0.5 ~ 1.4，越大越靠前）
     build(q)  返回请求 URL
     parse     解析函数：JSON 源接收 (data, q)，HTML 源用 parseText(doc, q)
   可选字段：
     kind      'json'（默认）| 'html'
     home      站点首页（结果卡片上的来源链接）
     proxyable 直连失败时是否允许走公共 CORS 代理（针对被墙站点）
     note      展示在来源提示里的说明
   ============================================================ */
(function () {
  'use strict';

  var enc = encodeURIComponent;

  /* ---------- 通用小工具 ---------- */
  function stripTags(html) {
    if (!html) return '';
    var d = document.createElement('div');
    d.innerHTML = String(html);
    return (d.textContent || '').replace(/\s+/g, ' ').trim();
  }
  function clamp(s, n) {
    s = String(s || '').replace(/\s+/g, ' ').trim();
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
  /* MC百科正文里带 [h1=标题]、[mark:title_menu] 之类的编辑器标记，需要清理 */
  function cleanMcmod(t) {
    return String(t || '')
      .replace(/\[(?:h[1-6](?:=[^\]]*)?|mark:[^\]]*|ban:[^\]]*|img[^\]]*|url(?:=[^\]]*)?|\/?(?:b|i|u|s|code|quote|table|tr|td|th))\]/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function wikiTitleToUrl(base, title) {
    return base + encodeURIComponent(String(title).replace(/ /g, '_'));
  }

  /* MediaWiki 搜索接口（维基百科 / Minecraft Wiki / 萌娘百科 通用） */
  function mediawikiSource(cfg) {
    return {
      id: cfg.id,
      name: cfg.name,
      short: cfg.short,
      badge: cfg.badge || String(cfg.short || '').slice(0, 1),
      group: cfg.group || 'wiki',
      weight: cfg.weight,
      home: cfg.home,
      proxyable: !!cfg.proxyable,
      note: cfg.note || '',
      build: function (q) {
        return cfg.api + '?action=query&list=search&srsearch=' + enc(q) +
          '&srlimit=' + (cfg.limit || 8) + '&srprop=snippet|wordcount&format=json&origin=*';
      },
      parse: function (data) {
        var list = (data && data.query && data.query.search) || [];
        return list.map(function (it) {
          return {
            title: String(it.title || '').replace(/_/g, ' '),
            snippet: clamp(stripTags(it.snippet), 220),
            url: wikiTitleToUrl(cfg.wiki, it.title),
            badges: [cfg.group === 'minecraft' ? 'Wiki' : '百科']
          };
        });
      }
    };
  }

  /* OpenAlex 的摘要以倒排索引返回，这里还原成正常语序 */
  function openAlexAbstract(inv) {
    if (!inv) return '';
    var pos = [];
    Object.keys(inv).forEach(function (word) {
      (inv[word] || []).forEach(function (i) { pos[i] = word; });
    });
    return pos.filter(Boolean).join(' ');
  }

  var SOURCES = [
    /* ---------------- 百科 / 通用知识 ---------------- */
    mediawikiSource({
      id: 'wikipedia-zh', name: '维基百科（中文）', short: '维基', badge: 'W', weight: 1.25,
      api: 'https://zh.wikipedia.org/w/api.php', wiki: 'https://zh.wikipedia.org/wiki/',
      home: 'https://zh.wikipedia.org', proxyable: true, limit: 8,
      note: '国内网络需代理，失败会自动换线路'
    }),
    mediawikiSource({
      id: 'wikipedia-en', name: 'Wikipedia（English）', short: 'EN', badge: 'W', weight: 1.2,
      api: 'https://en.wikipedia.org/w/api.php', wiki: 'https://en.wikipedia.org/wiki/',
      home: 'https://en.wikipedia.org', proxyable: true, limit: 6
    }),
    mediawikiSource({
      id: 'mcwiki-zh', name: 'Minecraft Wiki（中文）', short: 'MCWiki', badge: 'W', weight: 1.05,
      group: 'minecraft',
      api: 'https://zh.minecraft.wiki/api.php', wiki: 'https://zh.minecraft.wiki/w/',
      home: 'https://zh.minecraft.wiki', proxyable: true, limit: 8
    }),
    mediawikiSource({
      id: 'mcwiki-en', name: 'Minecraft Wiki（English）', short: 'MCW', badge: 'W', weight: 1.0,
      group: 'minecraft',
      api: 'https://minecraft.wiki/api.php', wiki: 'https://minecraft.wiki/w/',
      home: 'https://minecraft.wiki', proxyable: true, limit: 6
    }),

    /* ---------------- 我的世界：MC百科（HTML 解析） ---------------- */
    {
      id: 'mcmod', name: 'MC百科', short: 'MC百科', badge: 'MC', group: 'minecraft', weight: 1.05,
      kind: 'html', home: 'https://www.mcmod.cn',
      note: 'MOD / 整合包 / 教程的中文资料库',
      build: function (q) { return 'https://search.mcmod.cn/s?key=' + enc(q); },
      parseText: function (doc) {
        var items = doc.querySelectorAll('.result-item');
        var out = [];
        for (var i = 0; i < items.length && out.length < 8; i++) {
          var item = items[i];
          var a = item.querySelector('.head > a');
          if (!a) continue;
          var href = a.getAttribute('href') || '';
          if (!href || href.indexOf('mcmod.cn') < 0) continue;
          var body = item.querySelector('.body');
          var title = cleanMcmod(a.textContent);
          // 标题形如「钠 (Sodium)」「模组 - [MC] 我的世界原版」，副标题单独作为徽标更省空间
          var short = title.split(/\s+[-–—]\s+/)[0];
          out.push({
            title: title,
            snippet: clamp(cleanMcmod(stripTags(body ? body.innerHTML : '')), 200),
            url: href,
            badges: short && short !== title ? [short] : []
          });
        }
        return out;
      }
    },

    /* ---------------- 代码 / 包 ---------------- */
    {
      id: 'github', name: 'GitHub 仓库', short: 'GitHub', badge: 'GH', group: 'code', weight: 1.15,
      home: 'https://github.com',
      build: function (q) {
        return 'https://api.github.com/search/repositories?q=' + enc(q) + '&per_page=6&sort=stars&order=desc';
      },
      parse: function (d) {
        return ((d && d.items) || []).map(function (r) {
          var badges = [];
          if (r.language) badges.push(r.language);
          if (r.stargazers_count) badges.push('★ ' + r.stargazers_count);
          return {
            title: r.full_name,
            snippet: clamp(r.description || '（该仓库没有填写简介）', 220),
            url: r.html_url,
            badges: badges
          };
        });
      }
    },
    {
      id: 'npm', name: 'npm 包', short: 'npm', badge: 'N', group: 'code', weight: 1.0,
      home: 'https://www.npmjs.com',
      build: function (q) {
        return 'https://registry.npmjs.org/-/v1/search?text=' + enc(q) + '&size=5';
      },
      parse: function (d) {
        return ((d && d.objects) || []).map(function (o) {
          var p = o.package || {};
          return {
            title: p.name + (p.version ? ' @' + p.version : ''),
            snippet: clamp(p.description || '（无描述）', 200),
            url: (p.links && (p.links.npm || p.links.homepage)) || ('https://www.npmjs.com/package/' + p.name),
            badges: ['npm'].concat((p.keywords || []).slice(0, 2))
          };
        });
      }
    },
    {
      id: 'modrinth', name: 'Modrinth（Minecraft 模组）', short: 'Modrinth', badge: 'R', group: 'minecraft', weight: 1.05,
      home: 'https://modrinth.com',
      build: function (q) {
        return 'https://api.modrinth.com/v2/search?query=' + enc(q) + '&limit=6&index=relevance';
      },
      parse: function (d) {
        return ((d && d.hits) || []).map(function (h) {
          return {
            title: h.title,
            snippet: clamp(h.description || '', 220),
            url: 'https://modrinth.com/' + (h.project_type || 'mod') + '/' + (h.slug || h.project_id),
            badges: ['Modrinth'].concat((h.categories || []).slice(0, 2))
          };
        });
      }
    },

    /* ---------------- 游戏下载（HTML 解析 + 代理） ---------------- */
    {
      id: 'gamer520', name: 'gamer520 游戏下载', short: 'G520', badge: 'G',
      group: 'game', weight: 1.15, kind: 'html', forceProxy: true,
      home: 'https://www.gamer520.com',
      note: 'PC 游戏下载站，页面含网盘直链，需代理读取',
      fallback: function (q) { return 'https://www.gamer520.com/?s=' + enc(q); },
      build: function (q) { return 'https://www.gamer520.com/?s=' + enc(q); },
      parseText: function (doc) {
        var arts = doc.querySelectorAll('article');
        var out = [];
        for (var i = 0; i < arts.length && out.length < 8; i++) {
          var a = arts[i].querySelector('.entry-title a');
          if (!a) continue;
          var href = a.getAttribute('href') || '';
          if (href.indexOf('gamer520.com') < 0) continue;
          var title = (a.getAttribute('title') || a.textContent || '').replace(/\s+/g, ' ').trim();
          var cat = arts[i].querySelector('.meta-category a');
          var date = arts[i].querySelector('.meta-date time');
          var bits = [];
          if (cat) bits.push(cat.textContent.trim());
          if (date) bits.push(date.textContent.trim());
          out.push({
            title: clamp(title, 110),
            snippet: bits.length ? bits.join(' · ') + '｜点击进入详情页获取网盘下载地址' : '点击进入详情页获取网盘下载地址',
            url: href,
            badges: ['游戏']
          });
        }
        return out;
      }
    },

    /* ---------------- 问答 / 社区 ---------------- */
    {
      id: 'stackoverflow', name: 'Stack Overflow', short: 'SO', badge: 'S', group: 'qa', weight: 1.2,
      home: 'https://stackoverflow.com',
      build: function (q) {
        return 'https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q=' +
          enc(q) + '&site=stackoverflow&pagesize=5&filter=withbody';
      },
      parse: function (d) {
        return ((d && d.items) || []).map(function (it) {
          return {
            title: stripTags(it.title),
            snippet: clamp(stripTags(it.body || ''), 220),
            url: it.link,
            badges: ['SO', '✓ ' + (it.score || 0)]
          };
        });
      }
    },
    {
      id: 'superuser', name: 'Super User', short: 'SU', badge: 'SU', group: 'qa', weight: 0.95,
      home: 'https://superuser.com',
      build: function (q) {
        return 'https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q=' +
          enc(q) + '&site=superuser&pagesize=4&filter=withbody';
      },
      parse: function (d) {
        return ((d && d.items) || []).map(function (it) {
          return {
            title: stripTags(it.title),
            snippet: clamp(stripTags(it.body || ''), 200),
            url: it.link,
            badges: ['SU', '✓ ' + (it.score || 0)]
          };
        });
      }
    },
    {
      id: 'askubuntu', name: 'Ask Ubuntu', short: 'AU', badge: 'AU', group: 'qa', weight: 0.9,
      home: 'https://askubuntu.com',
      build: function (q) {
        return 'https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q=' +
          enc(q) + '&site=askubuntu&pagesize=4&filter=withbody';
      },
      parse: function (d) {
        return ((d && d.items) || []).map(function (it) {
          return {
            title: stripTags(it.title),
            snippet: clamp(stripTags(it.body || ''), 200),
            url: it.link,
            badges: ['AU', '✓ ' + (it.score || 0)]
          };
        });
      }
    },
    {
      id: 'hn', name: 'Hacker News', short: 'HN', badge: 'H', group: 'qa', weight: 1.0,
      home: 'https://news.ycombinator.com',
      build: function (q) {
        return 'https://hn.algolia.com/api/v1/search?query=' + enc(q) + '&tags=story&hitsPerPage=5';
      },
      parse: function (d) {
        return ((d && d.hits) || []).map(function (h) {
          return {
            title: h.title || (h.story_title || 'Hacker News 讨论'),
            snippet: clamp(stripTags(h.story_text || h.comment_text || '') ||
              (h.points || 0) + ' 分 · ' + (h.author || '匿名') + ' · ' + String(h.created_at || '').slice(0, 10), 200),
            url: h.url || ('https://news.ycombinator.com/item?id=' + h.objectID),
            badges: ['HN']
          };
        });
      }
    },

    /* ---------------- 学术 ---------------- */
    {
      id: 'crossref', name: 'Crossref 论文', short: 'Crossref', badge: 'C', group: 'academic', weight: 0.95,
      home: 'https://www.crossref.org',
      build: function (q) {
        return 'https://api.crossref.org/works?query=' + enc(q) +
          '&rows=5&select=title,URL,DOI,abstract,container-title,issued,author';
      },
      parse: function (d) {
        var items = (d && d.message && d.message.items) || [];
        return items.map(function (it) {
          var authors = (it.author || []).slice(0, 3).map(function (a) {
            return a.family || a.name || '';
          }).filter(Boolean).join(', ');
          var year = (it.issued && it.issued['date-parts'] && it.issued['date-parts'][0] || [])[0];
          return {
            title: (it.title && it.title[0]) || '未命名论文',
            snippet: clamp(stripTags(it.abstract || '') ||
              [authors, (it['container-title'] || [])[0], year].filter(Boolean).join(' · '), 220),
            url: it.URL || (it.DOI ? 'https://doi.org/' + it.DOI : 'https://www.crossref.org'),
            badges: ['论文'].concat(year ? [String(year)] : [])
          };
        });
      }
    },
    {
      id: 'openalex', name: 'OpenAlex 学术', short: 'OpenAlex', badge: 'O', group: 'academic', weight: 0.95,
      home: 'https://openalex.org',
      build: function (q) {
        return 'https://api.openalex.org/works?search=' + enc(q) + '&per-page=5';
      },
      parse: function (d) {
        return ((d && d.results) || []).map(function (w) {
          var loc = w.primary_location || {};
          return {
            title: w.display_name || '未命名',
            snippet: clamp(openAlexAbstract(w.abstract_inverted_index) || '（无摘要）', 220),
            url: loc.landing_page_url || w.doi || ('https://openalex.org/' + (w.id || '').split('/').pop()),
            badges: ['学术'].concat(w.publication_year ? [String(w.publication_year)] : [])
          };
        });
      }
    },

    /* ---------------- 图书（被墙，走代理） ---------------- */
    {
      id: 'openlibrary', name: 'Open Library 图书', short: '图书', badge: 'B', group: 'book', weight: 0.9,
      home: 'https://openlibrary.org', proxyable: true,
      build: function (q) { return 'https://openlibrary.org/search.json?q=' + enc(q) + '&limit=5'; },
      parse: function (d) {
        return ((d && d.docs) || []).map(function (b) {
          return {
            title: b.title + (b.first_publish_year ? '（' + b.first_publish_year + '）' : ''),
            snippet: clamp([(b.author_name || []).slice(0, 2).join(', '),
              b.first_publish_year ? '首次出版 ' + b.first_publish_year : '',
              (b.subject || []).slice(0, 3).join(' / ')].filter(Boolean).join(' · '), 200),
            url: 'https://openlibrary.org' + b.key,
            badges: ['图书']
          };
        });
      }
    }
  ];

  var GROUPS = [
    { key: 'all', label: '全部' },
    { key: 'wiki', label: '百科' },
    { key: 'code', label: '代码 / 包' },
    { key: 'qa', label: '问答' },
    { key: 'academic', label: '学术' },
    { key: 'book', label: '图书' },
    { key: 'game', label: '游戏下载' },
    { key: 'minecraft', label: '我的世界' }
  ];

  /* 公共 CORS 代理：仅在源标记 proxyable 且直连失败时使用 */
  var PROXIES = [
    { name: 'allorigins', wrap: function (u) { return 'https://api.allorigins.win/raw?url=' + enc(u); } },
    { name: 'codetabs', wrap: function (u) { return 'https://api.codetabs.com/v1/proxy?quest=' + enc(u); } },
    { name: 'cors.eu.org', wrap: function (u) { return 'https://cors.eu.org/' + u; } }
  ];

  window.NIAO_SEARCH_SOURCES = SOURCES;
  window.NIAO_SEARCH_GROUPS = GROUPS;
  window.NIAO_SEARCH_PROXIES = PROXIES;
})();
