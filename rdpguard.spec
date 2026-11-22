# Build on Windows x64 with Python 3.12. One shared dependency directory, three entrypoints.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hidden = collect_submodules('rdp_guard') + [
    'win32timezone', 'win32evtlog', 'win32ts', 'win32pipe', 'win32security',
    'win32service', 'win32serviceutil', 'servicemanager', 'win32com.client',
    'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan.on',
]
a = Analysis(['scripts/entry.py'], pathex=['src'], binaries=[],
             datas=collect_data_files('rdp_guard'), hiddenimports=hidden,
             hookspath=[], runtime_hooks=[], excludes=['tkinter'], noarchive=False)
pyz = PYZ(a.pure)
executables = [EXE(pyz, a.scripts, [], exclude_binaries=True, name=name,
                   debug=False, bootloader_ignore_signals=False, strip=False,
                   upx=False, console=True, uac_admin=False)
               for name in ('rdpguard', 'guardservice', 'webservice')]
coll = COLLECT(*executables, a.binaries, a.datas, strip=False, upx=False, name='RDPGuard')
