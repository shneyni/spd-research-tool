#!/usr/bin/env python3
"""make_payload.py <tool-dir> <drivers-dir> <out.zip>  -> zip with app/... and drivers/... (posix paths)"""
import sys, os, zipfile
tool, drv, out = sys.argv[1:4]
DRV_KEEP = ('.inf', '.cat', '.sys', '.dll')
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for base, prefix, keep in ((tool, 'app/', None), (drv, 'drivers/', DRV_KEEP)):
        for r, _, fs in os.walk(base):
            for f in fs:
                if keep and not f.lower().endswith(keep): continue
                p = os.path.join(r, f)
                z.write(p, prefix + os.path.relpath(p, base).replace(os.sep, '/'))
print('payload', out, round(os.path.getsize(out) / 1e6, 1), 'MB')
