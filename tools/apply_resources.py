#!/usr/bin/env python3
"""Translate resources of every PE in <dir> using translations/he_glossary.py.
  --dry-run : (any OS) build + re-parse + coverage report, writes nothing
  default   : rewrite PE resources in place with pure Python (lang 1033 = Hebrew text, 2052 copies removed)
Layout (geometry/styles/IDs) is never changed -> button positions stay identical."""
import sys, os, glob, re, json
import pefile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'translations'))
from rsrc_lib import *
from he_glossary import G

RLM = '\u200f'
FONT = None  # (points, face) set from --font
MANIFEST = os.path.join(os.path.dirname(__file__), '..', 'assets', 'app.manifest')
HEB = re.compile('[\u0590-\u05ff]')
def norm(s): return ' '.join(s.split())

def fix_rtl(t):
    # trailing punctuation would otherwise render on the wrong side in an LTR dialog
    out = []
    for line in t.split('\n'):
        if HEB.search(line) and line and line[-1] in ':.!?' :
            line += RLM
        out.append(line)
    return '\n'.join(out)

def lookup(text, alt_text=None):
    for t in (text, alt_text):
        if t is None: continue
        n = norm(t)
        if n in G: return fix_rtl(G[n])
    return None

def load_pe(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    return pe

def entries(pe):
    best = {}; langs = {}
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if t.id not in (RT_MENU, RT_DIALOG, RT_STRING): continue
        for n in t.directory.entries:
            for l in n.directory.entries:
                data = pe.get_data(l.data.struct.OffsetToData, l.data.struct.Size)
                k = (t.id, n.id); langs.setdefault(k, set()).add(l.id)
                if k not in best or l.id == 1033: best[k] = data
    return best, langs

def build_ops(path, id_text, report):
    pe = load_pe(path)
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'): return []
    best, langs = entries(pe)
    name = os.path.basename(path); ops = []
    for (t, i), data in sorted(best.items()):
        new = None
        if t == RT_STRING:
            tbl = parse_strings(i, data); out = {}; changed = False
            for sid, s in tbl.items():
                h = lookup(s)
                if h is None and sid in id_text and re.search('[\u4e00-\u9fff]', s):
                    h = lookup(id_text[sid])  # Chinese MFC string -> reuse Hebrew of same MFC id
                if h is not None and h != s: out[sid] = h; changed = True
                else:
                    out[sid] = s
                    if s.strip() and not re.fullmatch(r'[\W\d_]*', s): report.append((name, f'STR {sid}', s))
            if changed: new = build_strings(i, out)
        elif t == RT_MENU:
            tr = {}
            for m in parse_menu(data):
                h = lookup(m['text'])
                if h: tr[m['idx']] = h
                else: report.append((name, f'MENU {i}', m['text']))
            if tr: new = patch_menu(data, tr)
        elif t == RT_DIALOG:
            d = parse_dialog(data); cap = lookup(d['caption']) if d['caption'].strip() else None
            tr = {}
            for c in d['controls']:
                h = lookup(c['text'])
                if h: tr[c['i']] = h
                elif not re.fullmatch(r'[\W\d_]*|List1|Static|Root', c['text'].strip()) and not re.search(r'\(\d+ - \d+\)|^(CLK|DDR|DCDC)', c['text'].strip()):
                    report.append((name, f'DLG {i}', c['text']))
            if cap or tr or FONT:
                new = patch_dialog(data, cap, tr, FONT)
                # validate: structure re-parses and control count is unchanged
                chk = parse_dialog(new)
                assert len(chk['controls']) == len(d['controls']), (name, i)
        if new is not None:
            ops.append((t, i, 1033, new))
            for l in langs[(t, i)]:
                if l != 1033: ops.append((t, i, l, None))
    if name == 'ResearchDownload.exe' and os.path.exists(MANIFEST):
        for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if t.id == 24:
                for n in t.directory.entries:
                    for l in n.directory.entries:
                        ops.append((24, n.id, l.id, open(MANIFEST, 'rb').read()))
    return ops

def id_text_map(src):
    m = {}
    pe = load_pe(os.path.join(src, 'ResearchDownload.exe')); best, _ = entries(pe)
    for (t, i), d in best.items():
        if t == RT_STRING: m.update(parse_strings(i, d))
    return m

def apply_pe(path, ops):
    from rsrc_pe import rewrite_resources
    rewrite_resources(path, {(t, i, l): d for t, i, l, d in ops})

def main(src, dry):
    global FONT
    if '--font' in sys.argv:
        pt, face = sys.argv[sys.argv.index('--font') + 1].split(',', 1); FONT = (int(pt), face)
    idt = id_text_map(src); report = []; total = 0
    for f in sorted(glob.glob(os.path.join(src, '*.exe')) + glob.glob(os.path.join(src, '*.dll'))):
        ops = build_ops(f, idt, report)
        n = sum(1 for o in ops if o[3] is not None); total += n
        print(f'{os.path.basename(f)}: {n} resources translated')
        if ops and not dry: apply_pe(f, ops)
    print('TOTAL translated resources:', total)
    left = sorted(set((a, c) for a, b, c in report))
    print('Left untranslated (review):', len(left))
    for a, c in left[:60]: print('  ', a, repr(c))
if __name__ == '__main__': main(sys.argv[1], '--dry-run' in sys.argv)
