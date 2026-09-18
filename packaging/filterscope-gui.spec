# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — windowed desktop build (no console). Run from the repo root:
#   pyinstaller packaging/filterscope-gui.spec
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files

root = os.path.abspath(os.path.join(SPECPATH, ".."))
icon = os.path.join(root, "filterscope", "assets", "filterscope.ico")

datas, binaries, hiddenimports = [], [], []
for pkg in ("rich", "dns", "certifi", "PIL"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
datas += collect_data_files("filterscope", includes=["scripts/*.sh", "assets/*"])
hiddenimports += ["filterscope.gui", "filterscope.htmlreport", "filterscope.history", "filterscope.analysis",
                  "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"]

a = Analysis(
    [os.path.join(root, "packaging", "entry_gui.py")],
    pathex=[root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["textual", "PyQt5", "PyQt6", "PySide2", "PySide6", "matplotlib", "numpy", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="filterscope-gui",
    debug=False, strip=False, upx=False,
    console=False,
    icon=icon if os.path.exists(icon) else None,
)
if sys.platform == "darwin":
    app = BUNDLE(exe, name="filterscope.app", icon=None, bundle_identifier="org.tunnelmoth.filterscope",
                 info_plist={"CFBundleShortVersionString": "3.4.116", "NSHighResolutionCapable": True})
