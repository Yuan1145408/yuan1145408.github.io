#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构建站内搜索索引：search-index.json

数据来源（全部为仓库内已有内容，不请求任何外部接口）：
  1) 站点页面：*.html 的 <title> / meta description / h1-h3
  2) 资源数据：softwares / games / tutorials / downloads(vm,os) / android 的 JSON

用法：
  python build_search_index.py
内容更新后重新执行即可；search.js 只读取生成的 search-index.json。
"""

import os
import re
import json
import html
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "search-index.json")

# 页面文件名 -> (分类标签, 归属大类)
PAGE_RULES = [
    ("tutorial-", "教程", "tutorial"),
    ("index", "首页", "page"),
    ("downloads", "下载", "page"),
    ("games", "游戏", "page"),
    ("tutorials", "教程", "page"),
    ("features", "功能", "page"),
    ("vm", "虚拟机", "page"),
    ("os", "系统镜像", "page"),
    ("android", "安卓", "page"),
    ("official", "官方", "page"),
    ("tasks", "任务", "page"),
    ("user", "账户", "page"),
    ("minecraft", "游戏", "page"),
    ("search", "搜索", "page"),
]

# 这些页面不作为搜索结果（工具页/部署说明/404）
EXCLUDE_PAGES = {"404.html", "search.html", "deploy.html", "analysis-exe.html", "report.html"}

KIND_LABEL = {
    "software": "软件",
    "game": "游戏",
    "tutorial": "教程",
    "vm": "虚拟机",
    "os": "系统镜像",
    "android": "安卓应用",
    "page": "站内页面",
}


def clean(text, limit=None):
    if text is None:
        return ""
    s = html.unescape(str(text))
    s = re.sub(r"<script[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<style[\s\S]*?</style>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if limit and len(s) > limit:
        s = s[:limit].rstrip() + "…"
    return s


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def load_json(name):
    p = os.path.join(ROOT, name)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("  [warn] 解析失败", name, e)
        return None


def as_list(data, *keys):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    for k in keys:
        if isinstance(data.get(k), list):
            return data[k]
    return []


def tags_of(item):
    t = item.get("tags")
    if isinstance(t, list):
        return [clean(x, 20) for x in t if str(x).strip()]
    if isinstance(t, str):
        return [clean(x, 20) for x in re.split(r"[,，\s]+", t) if x.strip()]
    return []


def page_kind(fname):
    for prefix, label, kind in PAGE_RULES:
        if fname.startswith(prefix):
            return label, kind
    return "站内页面", "page"


def build_pages():
    items = []
    merged_targets = set()
    for name in sorted(os.listdir(ROOT)):
        if not name.endswith(".html") or name in EXCLUDE_PAGES:
            continue
        src = read(os.path.join(ROOT, name))
        title = re.search(r"<title[^>]*>([\s\S]*?)</title>", src, re.I)
        title = clean(title.group(1)) if title else name
        title = re.sub(r"\s*[-|—｜]\s*(鸟国网站|摸金小助手).*$", "", title).strip()
        # "AI 与大模型 | 摸金小助手" 这类拼接标题，只保留主标题
        if "|" in title:
            head, _, tail = title.partition("|")
            if len(head.strip()) >= 2 and len(tail.strip()) <= 12:
                title = head.strip()
        title = title.strip() or name

        desc = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']',
            src,
            re.I,
        )
        desc_text = clean(desc.group(1), 90) if desc else ""

        heads = re.findall(r"<h[123][^>]*>([\s\S]*?)</h[123]>", src, re.I)
        NAV_WORDS = {"首页", "返回", "登录", "注册", "鸟国网站", "功能分类", "教程专区", "软件下载",
                     "虚拟机专区", "系统镜像专区", "游戏专区", "官方跳转", "快速入口", "关于本站"}
        heads = [clean(h) for h in heads if clean(h)]
        heads = [h for h in heads
                 if h and h not in NAV_WORDS and h != title and 2 <= len(h) < 40]
        heads = list(dict.fromkeys(heads))[:8]
        if not desc_text:
            paras = re.findall(r"<p[^>]*>([\s\S]*?)</p>", src, re.I)
            for para in paras:
                t = clean(para, 90)
                if t and t not in NAV_WORDS and len(t) > 8:
                    desc_text = t
                    break
        if not desc_text:
            desc_text = " / ".join(heads[:2])

        label, kind = page_kind(name)
        keywords = " ".join(dict.fromkeys(heads))
        items.append(
            {
                "id": "page:" + name,
                "url": name,
                "title": title,
                "desc": desc_text,
                "kind": kind,
                "kindLabel": KIND_LABEL[kind],
                "category": label,
                "tags": [],
                "keywords": keywords,
            }
        )
        merged_targets.add(name)

        # 章节级索引：让“装饰器”“闭包”这类具体问题也能命中对应小节
        items.extend(build_sections(name, src, title, label, kind))
    return items, merged_targets


SEC_RE = re.compile(r"<h([23])\b([^>]*)>([\s\S]*?)</h\1>", re.I)
SKIP_HEAD = {
    "首页", "返回", "登录", "注册", "鸟国网站", "目录", "相关推荐", "参考链接",
    # 通用收尾小节：标题本身没有检索价值，留着只会占满建议列表
    "下一步", "参考资源", "延伸阅读", "扩展阅读", "相关资源", "小结", "总结",
    "常见问题", "写在最后", "前言", "简介", "概述", "示例", "代码示例",
}


def build_sections(name, src, page_title, label, kind):
    """把 h2/h3 拆成独立条目：标题 + 该小节正文摘要，url 带锚点。"""
    heads = list(SEC_RE.finditer(src))
    out = []
    for i, m in enumerate(heads):
        idm = re.search(r'id="([^"]+)"', m.group(2))
        if not idm:
            continue
        text = clean(m.group(3), 60)
        if not text or len(text) < 2 or text in SKIP_HEAD or text == page_title:
            continue
        start = m.end()
        end = heads[i + 1].start() if i + 1 < len(heads) else len(src)
        body = src[start:end]
        body = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", body, flags=re.I)
        body = re.sub(r"</(p|li|pre|div|tr|h[1-6])>", " ", body, flags=re.I)
        body = re.sub(r"<[^>]+>", " ", body)
        body = re.sub(r"\s+", " ", html.unescape(body)).strip()
        if len(body) < 12:
            continue
        out.append(
            {
                "id": f"sec:{name}#{idm.group(1)}",
                "url": f"{name}#{idm.group(1)}",
                "title": text,
                "desc": body[:120].rstrip() + ("…" if len(body) > 120 else ""),
                "kind": kind,
                "kindLabel": KIND_LABEL[kind],
                "category": label,
                "tags": [page_title],
                "keywords": "",
                "section": page_title,
            }
        )
    return out


def build_resources(page_urls):
    items = []

    def add(kind, name, desc, url, tags, category, extra=None):
        if not name:
            return
        rid = f"{kind}:{extra.get('id') or name}" if extra else f"{kind}:{name}"
        items.append(
            {
                "id": rid,
                "url": url or "",
                "title": clean(name, 60),
                "desc": clean(desc, 90),
                "kind": kind,
                "kindLabel": KIND_LABEL.get(kind, "资源"),
                "category": clean(category, 20) or KIND_LABEL.get(kind, ""),
                "tags": tags[:4],
                "keywords": "",
            }
        )

    software = as_list(load_json("softwares-extra.json"), "software")
    for d in software:
        add(
            "software",
            d.get("name"),
            d.get("desc"),
            d.get("website") or d.get("direct"),
            tags_of(d),
            d.get("category") or "软件",
            d,
        )

    games = as_list(load_json("games-extra.json"), "games")
    for d in games:
        add(
            "game",
            d.get("name"),
            d.get("desc"),
            d.get("website") or d.get("play"),
            tags_of(d),
            d.get("category") or "游戏",
            d,
        )

    tutorials = as_list(load_json("tutorials-extra.json"), "tutorials")
    for d in tutorials:
        local = d.get("local")
        url = local if local else (d.get("website") or "tutorials.html")
        add(
            "tutorial",
            d.get("name"),
            d.get("desc"),
            url,
            tags_of(d),
            d.get("category") or "教程",
            d,
        )
        if local in page_urls:
            # 已有更完整的页面记录时保留一份页面条目，避免重复标题
            pass

    dl = load_json("downloads-extra.json") or {}
    for kind, key in (("vm", "vm"), ("os", "os")):
        for d in as_list(dl, key, "items"):
            if str(d.get("category", "")) not in (kind, ""):
                continue
            add(
                kind,
                d.get("name"),
                d.get("desc"),
                d.get("website") or d.get("direct"),
                tags_of(d),
                "虚拟机" if kind == "vm" else "系统镜像",
                d,
            )

    android = as_list(load_json("android-extra.json"))
    for d in android:
        add(
            "android",
            d.get("name"),
            d.get("desc"),
            d.get("homepage") or "android.html",
            [d.get("category", ""), d.get("pkg", "")],
            d.get("category") or "安卓",
            d if isinstance(d, dict) else None,
        )
    return items


def _pick_title(page, res):
    """优先用资源标题；资源标题带“（本地）”这类占位时改用页面标题。"""
    t = res.get("title") or ""
    if ("（本地）" in t) or ("(本地)" in t) or len(t) <= 3:
        return page.get("title") or t
    return t


def dedupe(items):
    """按 URL 合并页面条目与资源条目：资源提供标题/标签，页面补充正文关键词。"""
    merged = {}
    order = []
    for it in items:
        url = it.get("url") or ""
        if url not in merged:
            merged[url] = dict(it)
            order.append(url)
            continue

        prev = merged[url]
        page = prev if prev["kind"] == "page" else it
        res = it if prev["kind"] == "page" else prev
        if page is res:  # 两条同类型，按描述长度保留更完整的一条
            keep, drop = (prev, it) if len(prev.get("desc") or "") >= len(it.get("desc") or "") else (it, prev)
            out = dict(keep)
            out["keywords"] = ((keep.get("keywords") or "") + " " + (drop.get("keywords") or "")).strip()
            merged[url] = out
            continue

        out = dict(res)
        out["title"] = _pick_title(page, res)
        if len(page.get("desc") or "") > len(out.get("desc") or ""):
            out["desc"] = page["desc"]
        out["keywords"] = ((res.get("keywords") or "") + " " + (page.get("keywords") or "")).strip()
        out["tags"] = list(dict.fromkeys((res.get("tags") or []) + (page.get("tags") or [])))[:4]
        merged[url] = out

    return [merged[k] for k in order]


def main():
    print("[1/3] 扫描页面…")
    pages, page_urls = build_pages()
    print(f"  {len(pages)} 个页面")

    print("[2/3] 读取资源数据…")
    resources = build_resources(page_urls)
    print(f"  {len(resources)} 条资源")

    items = dedupe(resources + pages)

    # 站内链接统一成相对路径，运行时由 search.js 拼成绝对地址
    for it in items:
        u = (it.get("url") or "").strip()
        if u.startswith("./"):
            it["url"] = u[2:]
        if not it["url"]:
            it["url"] = "index.html"

    items.sort(key=lambda x: (x["kind"] == "page", x["title"]))
    payload = {
        "version": 1,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(items),
        "items": items,
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))

    size = os.path.getsize(OUT) / 1024
    print(f"[3/3] 已写入 {os.path.basename(OUT)}：{len(items)} 条，{size:.1f} KB")

    from collections import Counter

    print("  分类分布：", dict(Counter(i["kindLabel"] for i in items)))


if __name__ == "__main__":
    main()
