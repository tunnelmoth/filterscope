# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — single-file console binary. Run from the repo root:
#   pyinstaller packaging/filterscope.spec
import os
from PyInstaller.utils.hooks import collect_all, collect_data_files

root = os.path.abspath(os.path.join(SPECPATH, ".."))

datas, binaries, hiddenimports = [], [], []
for pkg in ("textual", "rich", "dns", "certifi"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
datas += collect_data_files("filterscope", includes=["scripts/*.sh"])
hiddenimports += ["filterscope.tui", "filterscope.wgcheck", "filterscope.warp",
                  "filterscope.htmlreport", "filterscope.compare", "filterscope.history"]

a = Analysis(
    [os.path.join(root, "packaging", "entry.py")],
    pathex=[root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "PyQt5", "PyQt6", "PySide2", "PySide6", "matplotlib", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas,
    [],
    name="filterscope",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
