@echo off
REM ===================================================================
REM  ZaqorinCore Agent — Windows install script
REM
REM  Run as Administrator:
REM     powershell -ExecutionPolicy Bypass -File install.ps1
REM
REM  This script:
REM    1. Creates the install directory (C:\Program Files\ZaqorinCore)
REM    2. Creates the data directory (C:\ProgramData\ZaqorinCore)
REM    3. Copies the agent binary, the WinSW wrapper, and the XML
REM    4. Installs the service via WinSW
REM    5. Starts the service
REM
REM  To uninstall: run uninstall.cmd as Administrator.
REM ===================================================================

setlocal EnableDelayedExpansion

set "INSTALL_DIR=%ProgramFiles%\ZaqorinCore"
set "DATA_DIR=%ProgramData%\ZaqorinCore"
set "BINARY=zaqorin-agent.exe"
set "SERVICE_EXE=zaqorin-agent-service.exe"
set "SERVICE_XML=zaqorin-agent-service.xml"

echo.
echo === ZaqorinCore Agent Windows install ===
echo Install directory: %INSTALL_DIR%
echo Data directory:    %DATA_DIR%
echo.

REM --- 1. Create install directory ---
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo Created %INSTALL_DIR%.
)

REM --- 2. Create data directory tree ---
if not exist "%DATA_DIR%\logs" mkdir "%DATA_DIR%\logs"
if not exist "%DATA_DIR%\state" mkdir "%DATA_DIR%\state"
echo Created %DATA_DIR% tree.

REM --- 3. Copy binaries and service XML ---
if not exist "%BINARY%" (
    echo ERROR: %BINARY% not found in current directory.
    echo Run this script from the directory containing the agent binary.
    exit /b 1
)
copy /Y "%BINARY%" "%INSTALL_DIR%\%BINARY%" >nul
echo Copied %BINARY%.

if exist "%SERVICE_EXE%" (
    copy /Y "%SERVICE_EXE%" "%INSTALL_DIR%\%SERVICE_EXE%" >nul
    echo Copied %SERVICE_EXE%.
) else (
    echo WARNING: %SERVICE_EXE% not found. Download it from
    echo   https://github.com/winsw/winsw/releases
    echo and place it in the same directory as this script before running.
)

if exist "%SERVICE_XML%" (
    copy /Y "%SERVICE_XML%" "%INSTALL_DIR%\%SERVICE_XML%" >nul
    echo Copied %SERVICE_XML%.
) else (
    echo ERROR: %SERVICE_XML% not found.
    exit /b 1
)

REM --- 4. Drop a starter config if one is not present ---
if not exist "%DATA_DIR%\agent.toml" (
    if exist "agent.example.toml" (
        copy /Y "agent.example.toml" "%DATA_DIR%\agent.toml" >nul
        echo Created %DATA_DIR%\agent.toml from agent.example.toml.
        echo IMPORTANT: edit it with your server URL and auth token.
    ) else (
        echo WARNING: agent.example.toml not found.
        echo You must create %DATA_DIR%\agent.toml manually.
    )
)

REM --- 5. Install + start the service ---
if exist "%INSTALL_DIR%\%SERVICE_EXE%" (
    "%INSTALL_DIR%\%SERVICE_EXE%" install
    if errorlevel 1 (
        echo ERROR: service install failed.
        exit /b 1
    )
    "%INSTALL_DIR%\%SERVICE_EXE%" start
    echo Service installed and started.
    echo Verify with:  sc query ZaqorinCoreAgent
) else (
    echo Skipped service install (WinSW wrapper missing).
    echo You can run the agent directly:
    echo   "%INSTALL_DIR%\%BINARY%" --config "%DATA_DIR%\agent.toml"
)

echo.
echo === Install complete ===
endlocal
