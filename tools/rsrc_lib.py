"""Parse and patch STRING / MENU / DIALOG(EX) resource blobs.
Patching only replaces text; geometry, styles, IDs and control order are copied byte-for-byte,
so button positions never change."""
import struct

RT_MENU, RT_DIALOG, RT_STRING = 4, 5, 6


def u16(d, o): return struct.unpack_from('<H', d, o)[0]
def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def enc(s): return s.encode('utf-16le') + b'\0\0'
def align4(o): return (o + 3) & ~3


def wstr(d, o):
    s = o
    while u16(d, o) != 0:
        o += 2
    return d[s:o].decode('utf-16le'), o + 2


def sz_or_ord(d, o):
    """returns (kind, value, new_offset); kind in 'ord','str','none'"""
    w = u16(d, o)
    if w == 0xFFFF:
        return 'ord', u16(d, o + 2), o + 4
    if w == 0:
        return 'none', None, o + 2
    s, n = wstr(d, o)
    return 'str', s, n


# ---------- STRING ----------
def parse_strings(block_id, data):
    out, o = {}, 0
    for i in range(16):
        n = u16(data, o); o += 2
        if n:
            out[(block_id - 1) * 16 + i] = data[o:o + n * 2].decode('utf-16le')
            o += n * 2
    return out


def build_strings(block_id, table):
    """table: {string_id: text} for ids in this block"""
    out = bytearray()
    for i in range(16):
        s = table.get((block_id - 1) * 16 + i, '')
        out += struct.pack('<H', len(s)) + s.encode('utf-16le')
    return bytes(out)


# ---------- MENU (classic) ----------
def _menu_walk(data):
    """yield (idx, str_start, str_end, text) for each entry"""
    if u16(data, 0) != 0:
        return
    o = 4 + u16(data, 2)
    idx = 0
    while o < len(data):
        flags = u16(data, o); o += 2
        if not flags & 0x10:
            o += 2
        s0 = o
        s, o = wstr(data, o)
        yield idx, s0, o, s
        idx += 1


def parse_menu(data):
    return [{'idx': i, 'text': s} for i, _, _, s in _menu_walk(data) if s]


def patch_menu(data, tr):
    """tr: {idx(int): text}"""
    out, last = bytearray(), 0
    for idx, s0, s1, s in _menu_walk(data):
        if s and idx in tr:
            out += data[last:s0] + enc(tr[idx])
            last = s1
    out += data[last:]
    return bytes(out)


# ---------- DIALOG / DIALOGEX ----------
def _dlg_walk(d):
    """returns dict with spans:
       cap=(s0,s1,text), hdr_end (offset after font), items=[(start, t0, t1, kind, value, end)]"""
    ex = u16(d, 2) == 0xFFFF
    if ex:
        style = u32(d, 12); cnt = u16(d, 16); o = 26
    else:
        style = u32(d, 0); cnt = u16(d, 8); o = 18
    _, _, o = sz_or_ord(d, o)
    _, _, o = sz_or_ord(d, o)
    c0 = o
    cap, o = wstr(d, o)
    cap_span = (c0, o, cap)
    font_span = None
    if style & 0x40:
        f0 = o
        o += 2 + (4 if ex else 0)
        _, o = wstr(d, o)
        font_span = (f0, o, ex)
    hdr_end = o
    items = []
    for _ in range(cnt):
        o = align4(o)
        start = o
        o += 24 if ex else 18
        _, _, o = sz_or_ord(d, o)  # class
        t0 = o
        kind, val, o = sz_or_ord(d, o)
        t1 = o
        extra = u16(d, o); o += 2 + extra
        items.append((start, t0, t1, kind, val, o))
    return {'cap': cap_span, 'hdr_end': hdr_end, 'items': items, 'font': font_span}


def parse_dialog(d):
    w = _dlg_walk(d)
    res = {'caption': w['cap'][2], 'controls': []}
    for i, (_, _, _, kind, val, _) in enumerate(w['items']):
        if kind == 'str' and val.strip():
            res['controls'].append({'i': i, 'text': val})
    return res


def patch_dialog(d, caption=None, controls=None, font=None):
    """controls: {index(int): text}"""
    controls = controls or {}
    w = _dlg_walk(d)
    c0, c1, _ = w['cap']
    out = bytearray(d[:c0])
    out += enc(caption) if caption is not None else d[c0:c1]
    if font and w['font']:
        f0, f1, ex = w['font']
        pt, face = font
        out += d[c1:f0]
        out += struct.pack('<H', pt) + (struct.pack('<HBB', 400, d[f0 + 4], d[f0 + 5]) if ex else b'') + enc(face)
        out += d[f1:w['hdr_end']]
    else:
        out += d[c1:w['hdr_end']]
    for i, (start, t0, t1, kind, val, end) in enumerate(w['items']):
        while len(out) % 4:
            out += b'\0'
        out += d[start:t0]
        out += enc(controls[i]) if (i in controls and kind == 'str') else d[t0:t1]
        out += d[t1:end]
    return bytes(out)
