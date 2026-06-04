# -*- mode: python ; coding: utf-8 -*-
"""
NovaSentinel.spec — Optimized PyInstaller Build Configuration (v4.3)

Optimizations vs v4.2:
  - Dynamic Python DLL name in UPX exclude list (works with any Python version)
  - nvidia-ml-py and hypothesis added to excludes (not needed at runtime)
  - xgboost/lightgbm remain excluded (model training only, not runtime)
  - Target size: < 400 MB folder build
"""

import sys
import os

# ── Resolve project root ───────────────────────────────────────────────────────
block_cipher = None

# ── Collect datas needed by the application ───────────────────────────────────
datas = []

def _add_if_exists(src, dst):
    """Add (src, dst) to datas only if src exists."""
    if os.path.exists(src):
        datas.append((src, dst))
    else:
        print(f"[spec] WARNING: data path not found, skipping: {src}")

_add_if_exists('sentinelcore.db', '.')
_add_if_exists('quarantine.key', '.')
_add_if_exists('config', 'config')
_add_if_exists('themes', 'themes')
_add_if_exists('models', 'models')
_add_if_exists('ml', 'ml')
_add_if_exists('quarantine', 'quarantine')
_add_if_exists('quarantine_vault', 'quarantine_vault')
_add_if_exists('encrypted', 'encrypted')
_add_if_exists('assets', 'assets')
_add_if_exists('metadata', 'metadata')
# NOTE: 'sandbox' deliberately excluded — it contains user-dropped files that
#       should NOT be bundled into the EXE (could add 100s of MB of random files).
#       The app creates the sandbox/ directory at runtime if missing.
# NOTE: 'cache' deliberately excluded — runtime-generated, not needed in dist

# ── Hidden imports ─────────────────────────────────────────────────────────────
hidden_imports = [
    # PyQt6 core modules
    'PyQt6',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.QtNetwork',
    'PyQt6.QtPrintSupport',
    'PyQt6.sip',

    # pyqtgraph — modular; PyInstaller misses many sub-imports
    'pyqtgraph',
    'pyqtgraph.graphicsItems',
    'pyqtgraph.graphicsItems.PlotDataItem',
    'pyqtgraph.graphicsItems.BarGraphItem',
    'pyqtgraph.graphicsItems.InfiniteLine',
    'pyqtgraph.graphicsItems.ViewBox',
    'pyqtgraph.graphicsItems.AxisItem',
    'pyqtgraph.widgets',
    'pyqtgraph.widgets.PlotWidget',
    'pyqtgraph.widgets.GraphicsLayoutWidget',

    # Machine Learning (sklearn only — scipy/pandas excluded to save ~40 MB)
    'sklearn',
    'sklearn.ensemble',
    'sklearn.ensemble._forest',
    'sklearn.tree',
    'sklearn.tree._classes',
    'sklearn.preprocessing',
    'sklearn.preprocessing._label',
    'sklearn.utils',
    'sklearn.utils._bunch',
    'joblib',
    'threadpoolctl',

    # Cryptography
    'cryptography',
    'cryptography.fernet',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.backends',
    'cryptography.hazmat.backends.openssl',

    # System / Process monitoring
    'psutil',
    'psutil._pswindows',
    'pefile',

    # Network & HTTP
    'requests',
    'requests.adapters',
    'urllib3',
    'certifi',

    # File monitoring
    'watchdog',
    'watchdog.observers',
    'watchdog.observers.winapi',
    'watchdog.events',

    # Numpy (required by sklearn and pyqtgraph)
    'numpy',
    'numpy.core',
    'numpy.core._multiarray_umath',

    # Database
    'sqlite3',

    # Optional — Windows-specific (soft — app works without them)
    'wmi',
    'win32api',
    'win32con',

    # Optional — Security
    'yara',

    # Standard library (sometimes missed with optimize=1)
    'logging.handlers',
    'logging.config',
    'threading',
    'queue',
    'collections',
    'collections.abc',
    'importlib',
    'importlib.util',
    'math',
    'json',
    'hashlib',
    'hmac',
    'base64',
    'struct',

    # Application modules (ensure all sub-packages are bundled)
    'core',
    'core.security_core',
    'core.telemetry_manager',
    'core.process_manager',
    'core.intelligence_hub',
    'core.exception_handler',
    'core.quarantine_manager',
    'core.realtime_monitor',
    'core.scheduler',
    'core.threat_manager',
    'core.notification_manager',
    'engines',
    'engines.novasentinel_engine',
    'engines.ai_manager',
    'engines.phishing_detector',
    'engines.sandbox_engine',
    'engines.file_engine',
    'engines.monitor_engine',
    'engines.ai_engine',
    'engines.defense_engine',
    'engines.risk_engine',
    'engines.trust_engine',
    'engines.network_detector',
    'engines.ransomware_detector',
    'engines.injection_detector',
    'database',
    'database.init_db',
    'gui',
    'gui.app',
    'gui.core_bridge',
    'gui.main_window',
    'gui.theme_manager',
    'gui.widgets.splash_screen',
]

# ── Exclusions (reduce bundle size significantly) ──────────────────────────────
excludes = [
    'tkinter',
    'unittest',
    'test',
    'tests',
    # Large data-science libs not directly used by the app
    'matplotlib',
    'scipy',          # Saves ~40 MB of OpenBLAS DLLs
    'pandas',         # Not used in any engine
    'IPython',
    'jupyter',
    'notebook',
    'PIL',
    'cv2',
    # Heavy ML frameworks (Ollama handles AI inference)
    'torch',
    'tensorflow',
    'keras',
    'xgboost',
    'lightgbm',
    # GPU monitoring — only needed optionally at runtime
    'nvidia_ml_py',
    'pynvml',
    # Testing frameworks — never needed in packaged app
    'hypothesis',
    'pytest',
    'pytest_timeout',
    # Qt modules we don't use
    'PyQt6.QtBluetooth',
    'PyQt6.QtMultimedia',
    'PyQt6.QtOpenGL',
    'PyQt6.QtSql',
    'PyQt6.QtTest',
    'PyQt6.QtXml',
    'PyQt6.QtWebEngineWidgets',
    'PyQt6.QtWebEngine',
    'PyQt6.QtWebChannel',
    # Other unused stdlib
    'doctest',
    'pdb',
    'profile',
    'cProfile',
    'difflib',
    'email',
    'html',
    'http.server',
    'ftplib',
    'imaplib',
    'smtplib',
    'telnetlib',
    'xmlrpc',
    'xml.etree.ElementTree',
    'distutils',
    'ensurepip',
    'turtle',
    'curses',
    'antigravity',
]

# ── Check for icon ─────────────────────────────────────────────────────────────
icon_path = None
for candidate in [
    'assets/novasentinel.ico',
    'assets/icon.ico',
]:
    if os.path.exists(candidate):
        icon_path = candidate
        break

# ── Version file ───────────────────────────────────────────────────────────────
version_file = None
if os.path.exists('build/version_info.txt'):
    version_file = 'build/version_info.txt'

# ── Analysis ───────────────────────────────────────────────────────────────────
a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=1,   # Strips docstrings; saves ~5-10%
)

pyz = PYZ(a.pure)

# ── One-Directory Build (recommended: faster startup, < 400 MB) ────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NovaSentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                     # No terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
    version=version_file,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    # Skip UPX on already-compressed or Qt DLLs (UPX can corrupt them)
    upx_exclude=[
        'Qt6Core.dll',
        'Qt6Gui.dll',
        'Qt6Widgets.dll',
        'Qt6Network.dll',
        'Qt6PrintSupport.dll',
        'libcrypto-3.dll',
        'libssl-3.dll',
        'opengl32sw.dll',
        'VCRUNTIME140.dll',
        'VCRUNTIME140_1.dll',
        'mfc140u.dll',
        # Dynamic: skip UPX on the Python runtime DLL for this Python version
        f'python{sys.version_info.major}{sys.version_info.minor}.dll',
    ],
    name='NovaSentinel',
)
