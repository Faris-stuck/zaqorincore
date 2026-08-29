@echo off
REM ===================================================================
REM  ZaqorinCore Agent — Windows uninstall script
REM
REM  Run as Administrator:
REM     uninstall.cmd
REM
REM  This script:
REM    1. Stops the service if it is running
REM    2. Uninstalls the service via WinSW
REM    3. Removes the install directory (C:\Program Files\ZaqorinCore)
REM    4. Optionally removes the data directory
REM       (C:\ProgramData\ZaqorinCore) — prompts first
REM ===================================================================

setlocal EnableDelayedExpansion

set "INSTALL_DIR=%ProgramFiles%\ZaqorinCore"
set "DATA_DIR=%ProgramData%\ZaqorinCore"
set "SERVICE_EXE=zaqorin-agent-service.exe"

echo.
echo === ZaqorinCore Agent Windows uninstall ===
echo Install directory: %INSTALL_DIR%
echo Data directory:    %DATA_DIR%
echo.

REM --- 1. Stop the service ---
if exist "%INSTALL_DIR%\%SERVICE_EXE%" (
    "%INSTALL_DIR%\%SERVICE_EXE%" stop
    if errorlevel 1 (
        echo Service stop returned non-zero (may already be stopped).
    )
    REM --- 2. Uninstall the service ---
    "%INSTALL_DIR%\%SERVICE_EXE%" uninstall
    if errorlevel 1 (
        echo Service uninstall returned non-zero.
    )
) else (
    echo WinSW wrapper not found; nothing to stop/uninstall.
)

REM --- 3. Remove install directory ---
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%"
    echo Removed %INSTALL_DIR%.
)

REM --- 4. Optionally remove data directory ---
if exist "%DATA_DIR%" (
    set /p REMOVE_DATA="Remove %DATA_DIR% too? This deletes logs and state. [y/N] "
    if /i "!REMOVE_DATA!"=="y" (
        rmdir /S /Q "%DATA_DIR%"
        echo Removed %DATA_DIR%.
    ) else (
        echo Kept %DATA_DIR%.
    )
)

echo.
echo === Uninstall complete ===
endlocal
