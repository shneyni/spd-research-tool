"""Pure-Python PE resource rewriter (works on any OS, no Windows API).

rewrite_resources(path, repl)
    repl = {(type_id, name_id, lang): bytes | None}   (None = delete that entry)
Reads the full resource tree, applies the replacements, serialises a brand new resource tree into a NEW
section appended to the file and points the resource data-directory at it. The old .rsrc stays as dead
data (harmless). Everything outside the resource directory is untouched. The Authenticode signature (if any)
is dropped because it would be invalid after any modification anyway."""
import os
import struct
import pefile


def _align(v, a): return (v + a - 1) // a * a


def _key(e):
    if e.name is not None:
        n = e.name
        return n.decode('utf-16le') if isinstance(n, (bytes, bytearray)) else str(n)
    return e.id


def read_tree(pe):
    tree = {}
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tn = tree.setdefault(_key(t), {})
        for n in t.directory.entries:
            ln = tn.setdefault(_key(n), {})
            for l in n.directory.entries:
                d = l.data.struct
                ln[_key(l)] = (pe.get_data(d.OffsetToData, d.Size), d.CodePage)
    return tree


def apply_repl(tree, repl):
    for (t, n, l), data in repl.items():
        if data is None:
            tree.get(t, {}).get(n, {}).pop(l, None)
        else:
            old = tree.get(t, {}).get(n, {}).get(l)
            cp = old[1] if old else 0
            tree.setdefault(t, {}).setdefault(n, {})[l] = (bytes(data), cp)
    # prune empties
    for t in list(tree):
        for n in list(tree[t]):
            if not tree[t][n]: del tree[t][n]
        if not tree[t]: del tree[t]
    return tree


def _sorted_keys(d):
    named = sorted([k for k in d if isinstance(k, str)], key=str.lower)
    ids = sorted([k for k in d if not isinstance(k, str)])
    return named + ids


def build_rsrc(tree, base_rva):
    leaf = lambda data, cp: {'data': data, 'cp': cp}
    root = {'e': []}
    for t in _sorted_keys(tree):
        tn = {'e': []}
        for n in _sorted_keys(tree[t]):
            ln = {'e': []}
            for l in _sorted_keys(tree[t][n]):
                data, cp = tree[t][n][l]
                ln['e'].append((l, leaf(data, cp)))
            tn['e'].append((n, ln))
        root['e'].append((t, tn))
    dirs, leaves, queue = [], [], [root]
    while queue:
        node = queue.pop(0)
        dirs.append(node)
        for k, c in node['e']:
            if 'e' in c: queue.append(c)
            else: leaves.append(c)
    pos = 0
    for d in dirs:
        d['off'] = pos; pos += 16 + 8 * len(d['e'])
    for lf in leaves:
        lf['deoff'] = pos; pos += 16
    names = {}
    for d in dirs:
        for k, _ in d['e']:
            if isinstance(k, str) and k not in names:
                names[k] = pos; pos += _align(2 + 2 * len(k), 2)
    pos = _align(pos, 4)
    for lf in leaves:
        lf['doff'] = pos; pos += _align(len(lf['data']), 4)
    out = bytearray(pos)
    for d in dirs:
        named = [k for k, _ in d['e'] if isinstance(k, str)]
        struct.pack_into('<IIHHHH', out, d['off'], 0, 0, 4, 0, len(named), len(d['e']) - len(named))
        o = d['off'] + 16
        for k, c in d['e']:
            f0 = (0x80000000 | names[k]) if isinstance(k, str) else k
            f1 = (0x80000000 | c['off']) if 'e' in c else c['deoff']
            struct.pack_into('<II', out, o, f0, f1); o += 8
    for k, off in names.items():
        struct.pack_into('<H', out, off, len(k)); out[off + 2:off + 2 + 2 * len(k)] = k.encode('utf-16le')
    for lf in leaves:
        struct.pack_into('<IIII', out, lf['deoff'], base_rva + lf['doff'], len(lf['data']), lf['cp'], 0)
        out[lf['doff']:lf['doff'] + len(lf['data'])] = lf['data']
    return bytes(out)


def rewrite_resources(path, repl, out_path=None):
    raw = bytearray(open(path, 'rb').read())
    pe = pefile.PE(data=bytes(raw), fast_load=True)
    pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    tree = apply_repl(read_tree(pe), repl) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else apply_repl({}, repl)

    e_lfanew = struct.unpack_from('<I', raw, 0x3c)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', raw, coff + 2)[0]
    optsz = struct.unpack_from('<H', raw, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', raw, opt)[0]
    ddir = opt + (96 if magic == 0x10B else 112)
    sec_align, file_align = struct.unpack_from('<II', raw, opt + 32)
    size_of_headers = struct.unpack_from('<I', raw, opt + 60)[0]
    sec_tab = opt + optsz
    new_hdr = sec_tab + 40 * nsec
    if new_hdr + 40 > size_of_headers:
        raise RuntimeError('no room for an extra section header in ' + path)

    last_end = 0
    for i in range(nsec):
        vsz, va = struct.unpack_from('<II', raw, sec_tab + 40 * i + 8)
        last_end = max(last_end, va + max(vsz, struct.unpack_from('<I', raw, sec_tab + 40 * i + 16)[0]))
    new_va = _align(last_end, sec_align)
    blob = build_rsrc(tree, new_va)
    new_raw_off = _align(len(raw), file_align)
    raw += b'\0' * (new_raw_off - len(raw))
    raw_size = _align(len(blob), file_align)
    raw += blob + b'\0' * (raw_size - len(blob))

    struct.pack_into('<8sIIIIIIHHI', raw, new_hdr, b'.rsrcn', len(blob), new_va, raw_size, new_raw_off, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', raw, coff + 2, nsec + 1)
    size_init = struct.unpack_from('<I', raw, opt + 8)[0]
    struct.pack_into('<I', raw, opt + 8, size_init + raw_size)
    struct.pack_into('<I', raw, opt + 56, _align(new_va + len(blob), sec_align))   # SizeOfImage
    struct.pack_into('<I', raw, opt + 64, 0)                                       # CheckSum
    struct.pack_into('<II', raw, ddir + 2 * 8, new_va, len(blob))                  # resource directory
    struct.pack_into('<II', raw, ddir + 4 * 8, 0, 0)                               # drop signature
    target = out_path or path
    tmp = target + '.new'
    with open(tmp, 'wb') as fh:
        fh.write(raw)
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(target, 0x80)   # FILE_ATTRIBUTE_NORMAL
    os.replace(tmp, target)
