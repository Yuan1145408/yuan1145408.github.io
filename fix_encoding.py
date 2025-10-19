import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET_EXTS = {'.html', '.md', '.css'}

# 常见“乱码”特征字符集合（GBK 被当成 UTF-8 显示时常见）
GARBLED_CHARS = set(list('鍏锛鏁绉浼鐢瀛鐞姣鍒鍝鍚锲銆娴瀹涓鍗鏋鍙缁'))

# 记录日志
LOG_PATH = os.path.join(ROOT, 'latest.log')
log_lines = []

def score_garbled(text: str) -> int:
    return sum(1 for ch in text if ch in GARBLED_CHARS)

def try_decode(data: bytes, enc: str) -> str:
    try:
        return data.decode(enc)
    except Exception:
        return ''

def ensure_html_lang(content: str) -> str:
    # 给 <html> 添加 lang="zh-CN"
    def add_lang(m):
        tag = m.group(0)
        if 'lang=' not in tag:
            # 在 <html 之后插入 lang
            return tag.replace('<html', '<html lang="zh-CN"', 1)
        return tag
    return re.sub(r'<html[^>]*>', add_lang, content, count=1, flags=re.IGNORECASE)

def fix_asset_paths(content: str) -> str:
    # 将 assets/ 路径改为根目录文件（本仓库资源均在根目录）
    content = re.sub(r'(src|href)\s*=\s*"assets/', r'\1="', content)
    # favicon 兼容
    content = content.replace('href="assets/favicon.svg"', 'href="favicon.svg"')
    return content

def fix_specific_css_garbled(content: str) -> str:
    # 定点替换已知的乱码注释
    content = content.replace('/* 宸茬Щ闄ゅ紑鍙戣€呮ā寮忔牱寮?*/', '/* 开发者模式样式 */')
    return content

def process_file(path: str):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        utf8_text = try_decode(data, 'utf-8')
        gb_text = try_decode(data, 'gb18030')  # 覆盖 GBK/GB2312
        if not utf8_text and not gb_text:
            log_lines.append(f'[skip] {path}: 无法解码')
            return
        s_utf8 = score_garbled(utf8_text) if utf8_text else 10**9
        s_gb = score_garbled(gb_text) if gb_text else 10**9
        chosen = None
        # 判定策略：若 utf-8 的乱码分高且 gb18030 更优，则用 gb18030
        if gb_text and (s_utf8 > 5) and (s_gb * 2 <= s_utf8):
            chosen = gb_text
            log_lines.append(f'[convert] {path}: utf8_score={s_utf8}, gb_score={s_gb} -> 使用 gb18030 转 UTF-8')
        else:
            chosen = utf8_text or gb_text
            log_lines.append(f'[keep] {path}: utf8_score={s_utf8}, gb_score={s_gb} -> 保持现有编码')
        # HTML：增强 lang 与资源路径
        ext = os.path.splitext(path)[1].lower()
        if ext == '.html':
            chosen = ensure_html_lang(chosen)
            chosen = fix_asset_paths(chosen)
        # CSS：修复已知乱码注释
        if ext == '.css':
            chosen = fix_specific_css_garbled(chosen)
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(chosen)
    except Exception as e:
        log_lines.append(f'[error] {path}: {e}')


def main():
    changed = 0
    for root, dirs, files in os.walk(ROOT):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in TARGET_EXTS:
                process_file(os.path.join(root, name))
                changed += 1
    with open(LOG_PATH, 'w', encoding='utf-8') as logf:
        logf.write('\n'.join(log_lines))
    print(f'Done. processed={changed}, log={LOG_PATH}')

if __name__ == '__main__':
    main()