import sys, re
from pathlib import Path

ROOT = Path(__file__).parent
TARGET_EXTS = {'.html', '.md'}

# 常见乱码字符集合（UTF-8 被当作 GBK/GB18030 误解码后出现的字符）
GARBLED_CHARS = set(list('鍏锛鏁绉浼鐢瀛鐞姣鍒鍝鍚锲銆娴瀹涓鍗鏋鍙缁鎯鐞鏍瀵銇缂璁纰鐩鏈瑙闃'))

BAD_TOKENS = [
    '鍏', '锛', '鏁', '涔', '缂', '绠', '鐢', '瀛', '鏌', '鍙', '缁', '绛', '鎴', '闂', '瑙', '銆',
]

LOG = []

def looks_like_mojibake(text: str) -> int:
    return sum(text.count(tok) for tok in BAD_TOKENS)


def try_fix(text: str):
    # 尝试两种回滚方案：假设当前文本是 utf-8 字节被错误地以 gbk/gb18030 解码
    # 则将当前文本重新按 gbk/gb18030 编码，再按 utf-8 解码，尽可能还原
    for enc in ('gbk', 'gb18030'):
        try:
            b = text.encode(enc)
            fixed = b.decode('utf-8')
            return fixed, enc
        except Exception:
            continue
    return None, None


def process_file(p: Path):
    try:
        raw = p.read_text(encoding='utf-8', errors='strict')
    except Exception:
        raw = p.read_text(encoding='utf-8', errors='ignore')

    before = looks_like_mojibake(raw)
    if before < 6:
        LOG.append(f"[skip] {p}: garble_count={before}")
        return False

    fixed, enc_used = try_fix(raw)
    if not fixed:
        LOG.append(f"[fail] {p}: unable_to_fix")
        return False

    after = looks_like_mojibake(fixed)

    # 只有明显降低才写回（避免误伤）
    if after <= max(1, before // 8):
        # 保证 HTML 元信息正确
        if p.suffix == '.html':
            fixed = re.sub(r'<meta charset=["\']?[^"\']+["\']?\s*/?>', '<meta charset="utf-8" />', fixed, flags=re.I)
            fixed = re.sub(r'<html[^>]*lang=["\']?[^"\']+["\']?[^>]*>', lambda m: re.sub(r'lang=["\']?[^"\']+["\']?', 'lang="zh-CN"', m.group(0), flags=re.I), fixed, flags=re.I)
        p.write_text(fixed, encoding='utf-8')
        LOG.append(f"[fixed] {p}: {enc_used} -> utf-8; {before} -> {after}")
        return True
    else:
        LOG.append(f"[keep] {p}: {before} -> {after} (not improved)")
        return False


def main():
    files = [p for p in ROOT.iterdir() if p.suffix in TARGET_EXTS]
    changed = 0
    for p in files:
        if process_file(p):
            changed += 1
    log_path = ROOT / 'mojibake_fix.log'
    log_path.write_text('\n'.join(LOG), encoding='utf-8')
    print(f"done. changed={changed}, total={len(files)}; log={log_path}")

if __name__ == '__main__':
    main()