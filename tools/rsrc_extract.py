#!/usr/bin/env python3
"""Extract translatable resources from PE files. Prefers lang 1033, falls back to 2052.
Usage: rsrc_extract.py <dir-with-binaries> <out.json> [--selftest]"""
import pefile, sys, json, os, glob
from rsrc_lib import *

def walk(pe):
    """yield (type, id, lang, data)"""
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if t.id not in (RT_MENU, RT_DIALOG, RT_STRING): continue
        for n in t.directory.entries:
            for l in n.directory.entries:
                yield t.id, n.id, l.id, pe.get_data(l.data.struct.OffsetToData, l.data.struct.Size)

def pick(pe):
    best = {}
    for t, i, lang, data in walk(pe):
        k = (t, i)
        if k not in best or (lang == 1033 and best[k][0] != 1033) or (best[k][0] not in (1033,) and lang == 2052 and best[k][0] != 2052 and False):
            best[k] = (lang, data)
        elif k in best and best[k][0] not in (1033, 2052):
            best[k] = (lang, data)
    return best

def main(src, out, selftest=False):
    result, bad = {}, 0
    for f in sorted(glob.glob(os.path.join(src, '*.exe')) + glob.glob(os.path.join(src, '*.dll'))):
        pe = pefile.PE(f, fast_load=True)
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'): continue
        e = {'strings': {}, 'menus': {}, 'dialogs': {}, 'src_lang': {}}
        for (t, i), (lang, data) in pick(pe).items():
            try:
                if t == RT_STRING:
                    e['strings'].update({str(k): v for k, v in parse_strings(i, data).items()})
                    e['src_lang'][f'6:{i}'] = lang
                    if selftest:
                        tb = parse_strings(i, data)
                        if build_strings(i, tb) != data.rstrip(b'\0') and build_strings(i, tb) != data: bad += 1; print('RT-FAIL string', f, i)
                elif t == RT_MENU:
                    m = parse_menu(data); e['menus'][str(i)] = m; e['src_lang'][f'4:{i}'] = lang
                    if selftest and patch_menu(data, {x['idx']: x['text'] for x in m}) != data: bad += 1; print('RT-FAIL menu', f, i)
                elif t == RT_DIALOG:
                    dd = parse_dialog(data); e['dialogs'][str(i)] = dd; e['src_lang'][f'5:{i}'] = lang
                    if selftest:
                        p = patch_dialog(data, dd['caption'], {c['i']: c['text'] for c in dd['controls']})
                        if p != data and p != data.rstrip(b'\0'): bad += 1; print('RT-FAIL dialog', f, i, len(p), len(data))
            except Exception as ex:
                print('WARN', os.path.basename(f), t, i, repr(ex), file=sys.stderr)
        e['dialogs'] = {k: v for k, v in e['dialogs'].items()}
        if e['strings'] or e['menus'] or e['dialogs']: result[os.path.basename(f)] = e
    json.dump(result, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    for k, v in result.items():
        print(f"{k}: strings={len(v['strings'])} menu_items={sum(map(len, v['menus'].values()))} dlg_ctrls={sum(len(x['controls']) for x in v['dialogs'].values())} lang2052={sum(1 for x in v['src_lang'].values() if x==2052)}")
    if selftest: print('ROUNDTRIP FAILURES:', bad)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], '--selftest' in sys.argv)
