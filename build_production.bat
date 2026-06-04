@echo off
REM ============================================================
REM  NovaSentinel — Production Build Script (v4.2)
REM  Changes from v4.1:
REM    - Deletes oversized log backup before build
REM    - Removes stray .exe files from dist/_internal
REM    - Prints final size report
REM    - Generates all branding assets before build
REM    - Cleans __pycache__ across entire project
REM ============================================================

echo.
echo  ==========================================
echo   NovaSentinel Production Build v4.2
echo  ==========================================
echo.

REM -- 1. Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Please install Python 3.11+ and retry.
    pause
    exit /b 1
)

REM -- 2. Check PyInstaller is available (install if needed)
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

REM -- 3. Ensure Pillow is available (for asset generation)
python -c "import PIL" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing Pillow for asset generation...
    pip install Pillow
)

REM -- 4. Clean up large log files (don't bundle 50 MB logs)
echo [CLEAN] Removing large log backups...
if exist "sentinelcore.log.1" (
    echo   Deleting sentinelcore.log.1 ^(log backup^)...
    del /f /q "sentinelcore.log.1"
)
if exist "sentinelcore.log.2" del /f /q "sentinelcore.log.2"
if exist "sentinelcore.log.3" del /f /q "sentinelcore.log.3"
if exist "live_scan_console.txt" del /f /q "live_scan_console.txt"
if exist "live_scan_report.txt" del /f /q "live_scan_report.txt"
if exist "build_output.log" del /f /q "build_output.log"
if exist "build_output2.log" del /f /q "build_output2.log"

REM -- 5. Clean __pycache__ directories
echo [CLEAN] Clearing __pycache__ directories...
for /d /r . %%d in (__pycache__) do (
    if exist "%%d" rmdir /s /q "%%d" 2>nul
)

REM -- 6. Generate branding assets
echo [ASSETS] Generating NovaSentinel branding assets...
python scripts/generate_assets.py
if errorlevel 1 (
    echo [WARNING] Asset generation failed. Using existing assets if available.
)

REM -- 7. Ensure assets directory exists
if not exist "assets" mkdir assets

REM -- 8. Clean previous build artifacts
echo [BUILD] Cleaning previous builds...
if exist "build\NovaSentinel" rmdir /s /q "build\NovaSentinel"
if exist "dist\NovaSentinel" rmdir /s /q "dist\NovaSentinel"
if exist "dist\NovaSentinel_Portable.exe" del /f /q "dist\NovaSentinel_Portable.exe"

REM -- 9. Run PyInstaller with the optimized spec
echo [BUILD] Running PyInstaller (this may take 3-10 minutes)...
python -m PyInstaller NovaSentinel.spec --clean --noconfirm

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build FAILED. Check output above for details.
    pause
    exit /b 1
)

REM -- 10. Post-build: Remove accidentally included installer/setup EXE files
echo [POST] Removing stray installer EXE files from dist...
for /r "dist\NovaSentinel\_internal" %%f in (*Setup*.exe *Install*.exe *Cursor*.exe *setup-x64*.exe) do (
    echo   Removing: %%f
    del /f /q "%%f"
)

REM -- 11. Verify output and print size report
echo.
if exist "dist\NovaSentinel\NovaSentinel.exe" (
    echo  ==========================================
    echo   BUILD SUCCESSFUL!
    echo  ==========================================
    echo.
    echo   Output: dist\NovaSentinel\NovaSentinel.exe
    echo.

    REM Calculate folder size using PowerShell
    echo [SIZE] Calculating build size...
    powershell -NoProfile -Command ^
        "$size = (Get-ChildItem -Recurse 'dist\NovaSentinel' | Where-Object {!$_.PSIsContainer} | Measure-Object -Property Length -Sum).Sum / 1MB; " ^
        "$files = (Get-ChildItem -Recurse 'dist\NovaSentinel' | Where-Object {!$_.PSIsContainer}).Count; " ^
        "$status = if ($size -le 500) { 'PASS' } else { 'FAIL (over 500 MB target)' }; " ^
        "Write-Host (''); " ^
        "Write-Host ('  Build Size Report'); " ^
        "Write-Host ('  -----------------'); " ^
        "Write-Host ('  Total Size : ' + [math]::Round($size, 1) + ' MB'); " ^
        "Write-Host ('  File Count : ' + $files + ' files'); " ^
        "Write-Host ('  Status     : ' + $status); " ^
        "Write-Host (''); " ^
        "Write-Host ('  Top 10 largest files:'); " ^
        "Get-ChildItem -Recurse 'dist\NovaSentinel' | Where-Object {!$_.PSIsContainer} | Sort-Object Length -Descending | Select-Object -First 10 | ForEach-Object { Write-Host ('    ' + [math]::Round($_.Length/1MB,2) + ' MB  ' + $_.Name) }"

    echo.
    echo   To launch: dist\NovaSentinel\NovaSentinel.exe
    echo.
    echo   GitHub Release: Zip the dist\NovaSentinel\ folder and upload as a Release Asset.
    echo.
) else (
    echo.
    echo [WARNING] Build completed but NovaSentinel.exe not found in expected location.
    echo          Check dist\ directory manually.
    echo.
)

pause
