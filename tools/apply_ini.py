#!/usr/bin/env python3
"""Translate BMError.ini descriptions. Written as UTF-16LE+BOM (the tool reads INIs with the *W APIs,
so Hebrew works on any system locale). Usage: apply_ini.py <tool-dir>"""
import sys, os, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'translations'))
from he_glossary import BMERROR

def main(d):
    p = os.path.join(d, 'BMError.ini')
    raw = open(p, 'rb').read().decode('utf-8', 'replace')
    out, n = [], 0
    for line in raw.splitlines():
        m = re.match(r'^(\d+)=(.*)$', line)
        if m and int(m.group(1)) in BMERROR:
            line = f'{m.group(1)}={BMERROR[int(m.group(1))]}'; n += 1
        out.append(line)
    open(p, 'wb').write(b'\xff\xfe' + '\r\n'.join(out).encode('utf-16le') + '\r\n'.encode('utf-16le'))
    print(f'BMError.ini: {n} messages translated')
if __name__ == '__main__': main(sys.argv[1])
