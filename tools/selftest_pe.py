#!/usr/bin/env python3
"""selftest_pe.py <tool-dir> : applies the real translation to a temp copy and verifies
 (1) PE re-parses, (2) every untouched resource is byte-identical, (3) changed ones equal intended,
 (4) deleted ones are gone, (5) section table / SizeOfImage sane."""
import sys, os, glob, shutil, tempfile, struct
import pefile
sys.path.insert(0, os.path.dirname(__file__))
import apply_resources as A
from rsrc_pe import read_tree, rewrite_resources

def main(src, font=None):
    if font: pt, face = font.split(',', 1); A.FONT = (int(pt), face)
    idt = A.id_text_map(src); tmp = tempfile.mkdtemp(); fails = 0
    for f in sorted(glob.glob(os.path.join(src, '*.exe')) + glob.glob(os.path.join(src, '*.dll'))):
        ops = A.build_ops(f, idt, [])
        if not ops: continue
        out = os.path.join(tmp, os.path.basename(f)); shutil.copy(f, out)
        rewrite_resources(out, {(t, i, l): d for t, i, l, d in ops})
        pe0 = pefile.PE(data=open(f, 'rb').read(), fast_load=True); pe0.parse_data_directories([2]); t0 = read_tree(pe0)
        pe1 = pefile.PE(data=open(out, 'rb').read(), fast_load=True); pe1.parse_data_directories([2]); t1 = read_tree(pe1)
        want = {(t, i, l): d for t, i, l, d in ops}
        for t, nm in t0.items():
            for n, ls in nm.items():
                for l, (d, cp) in ls.items():
                    k = (t, n, l)
                    if k in want:
                        if want[k] is None:
                            if l in t1.get(t, {}).get(n, {}): print('NOT DELETED', f, k); fails += 1
                        elif t1[t][n][l][0] != want[k]: print('MISMATCH', f, k); fails += 1
                    elif t1.get(t, {}).get(n, {}).get(l, (None,))[0] != d: print('CHANGED', f, k); fails += 1
        for k, d in want.items():
            if d is not None and t1.get(k[0], {}).get(k[1], {}).get(k[2], (None,))[0] != d: print('MISSING', f, k); fails += 1
        # header sanity
        raw = open(out, 'rb').read(); pe = pefile.PE(data=raw)
        last = pe.sections[-1]
        assert last.Name.rstrip(b'\0') == b'.rsrcn'
        assert pe.OPTIONAL_HEADER.SizeOfImage % pe.OPTIONAL_HEADER.SectionAlignment == 0
        assert pe.OPTIONAL_HEADER.SizeOfImage >= last.VirtualAddress + last.Misc_VirtualSize
        assert last.PointerToRawData % pe.OPTIONAL_HEADER.FileAlignment == 0 and last.PointerToRawData + last.SizeOfRawData == len(raw)
        print(f'OK {os.path.basename(f)}: {len(ops)} ops, {os.path.getsize(f)} -> {len(raw)} bytes')
    shutil.rmtree(tmp); print('FAILURES:', fails); sys.exit(1 if fails else 0)
if __name__ == '__main__': main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
