@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo Compiling Malware Telemetry Engine (C++20 / Windows)
echo =======================================================

if not exist bin (
    mkdir bin
)

echo Compiling source files with g++...
g++ -std=c++20 -O2 -Wall -Wextra -Iinclude ^
    src\main.cpp ^
    src\privilege.cpp ^
    src\process_collector.cpp ^
    src\memory_scanner.cpp ^
    src\network_mapper.cpp ^
    src\json_serializer.cpp ^
    -lws2_32 -liphlpapi -lpsapi -ladvapi32 ^
    -o bin\telemetry_engine.exe

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Binary created at bin\telemetry_engine.exe
    echo Run as Administrator for full SeDebugPrivilege access:
    echo   bin\telemetry_engine.exe -o telemetry.json
) else (
    echo.
    echo [FAILURE] Compilation failed with error code %ERRORLEVEL%.
)
