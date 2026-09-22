# Malware Analysis Data Collection Engine (Phase 1)

A high-performance, modular **C++20 Windows Console Application** designed for Phase 1 of Malware Analysis and Host Forensics. The engine collects low-level system telemetry—including running processes, thread IDs, loaded modules, unbacked executable memory pages (with Shannon entropy calculation), and active network sockets—and serializes them into a structured Graph JSON schema (`Nodes` and `Edges`).

---

## Features

1. **Privilege Elevation & Token Check (`privilege.cpp`)**:
   - Queries `TOKEN_ELEVATION` to inspect administrative token status.
   - Dynamically requests and enables `SeDebugPrivilege` via `AdjustTokenPrivileges`.
   - Gracefully reports elevation status without terminating on standard user sessions.

2. **Process, Thread & Module Enumeration (`process_collector.cpp`)**:
   - Captures real-time process and thread snapshots using `CreateToolhelp32Snapshot`.
   - Extracts PID, Parent PID (PPID), process executable name, and full image path.
   - Maps Thread IDs (TIDs) into their owning processes.
   - Enumerates loaded 32-bit and 64-bit DLL modules using `EnumProcessModulesEx` and `GetModuleInformation`.

3. **Virtual Memory Forensics & Shannon Entropy (`memory_scanner.cpp`)**:
   - Queries address space via `VirtualQueryEx`.
   - Identifies committed, unbacked private executable memory pages (`MEM_COMMIT`, `MEM_PRIVATE`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`, etc.) indicative of injected shellcode, Cobalt Strike beacons, or JIT buffers.
   - Calculates **Shannon Entropy** ($H(X) \in [0.0, 8.0]$) to detect encrypted payloads, packed code, or NOP sleds.

4. **Network Socket Mapping (`network_mapper.cpp`)**:
   - Maps active IPv4 and IPv6 TCP connections via `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`).
   - Maps active IPv4 and IPv6 UDP endpoints via `GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`).
   - Translates binary IP addresses, port numbers, and TCP states (e.g. `LISTENING`, `ESTABLISHED`, `CLOSE_WAIT`) and binds them to owning PIDs.

5. **Graph JSON Serialization (`json_serializer.cpp`)**:
   - Lightweight, zero-dependency C++20 JSON serializer.
   - Properly escapes control characters, quotes, and Windows file path backslashes.
   - Structures telemetry into **Nodes** (`processes`, `memory_regions`, `sockets`) and **Edges** (`spawns`, `has_memory`, `connected_to`).

---

## Directory Structure

```
.
├── CMakeLists.txt              # Standard CMake build configuration
├── Makefile                    # MinGW makefile
├── build.bat                   # 1-click batch compilation script
├── include/
│   ├── privilege.hpp           # SeDebugPrivilege and token inspection
│   ├── process_collector.hpp   # Process, thread, and module collection
│   ├── memory_scanner.hpp      # Virtual memory scanning and Shannon entropy
│   ├── network_mapper.hpp      # Extended TCP/UDP socket mapping
│   ├── telemetry_model.hpp     # Strongly-typed graph model definitions
│   └── json_serializer.hpp     # JSON formatting & file writer
├── src/
│   ├── privilege.cpp
│   ├── process_collector.cpp
│   ├── memory_scanner.cpp
│   ├── network_mapper.cpp
│   ├── json_serializer.cpp
│   └── main.cpp               # CLI orchestration & benchmark output
└── bin/
    └── telemetry_engine.exe    # Compiled binary
```

---

## Compilation Guide

### Option 1: Quick Build with `build.bat` (MinGW / GCC 14+)
If you have `g++` (MinGW-w64 / MSYS2) in your PATH:
```cmd
build.bat
```
The executable will be generated at `bin\telemetry_engine.exe`.

### Option 2: Build with `mingw32-make`
```cmd
mingw32-make
```

### Option 3: Standard CMake (MSVC, Ninja, Clang)
```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Option 4: Visual Studio IDE
1. Open Visual Studio.
2. Select **File > Open > CMake...** and select the root directory containing `CMakeLists.txt`.
3. Select `x64-Release` or `x64-Debug` configuration.
4. Press `Ctrl + Shift + B` to build.

---

## How to Run as Administrator

To inspect the virtual memory of elevated processes (services, antivirus, system brokers) and acquire `SeDebugPrivilege`, the executable must be run with elevated privileges.

### Step 1: Open an Elevated Prompt
- Press `Win + X` and select **Terminal (Admin)** or **PowerShell (Admin)** or **Command Prompt (Admin)**.
- Or search for `cmd` / `powershell` in the Start menu, right-click, and select **"Run as administrator"**.

### Step 2: Navigate to Project Directory & Execute
```powershell
cd "c:\Users\swast\OneDrive\Desktop\My Folder\VIT ENGENEERING\SEM 3\IDP"

# Run data collection and save to JSON
.\bin\telemetry_engine.exe -o telemetry.json
```

### CLI Command Options
```
Usage: telemetry_engine.exe [options]

Options:
  -o, --output <file>    Specify output JSON file path (default: telemetry.json)
  -s, --stdout           Stream complete JSON directly to standard output
  -q, --quiet            Suppress banner and scan logs
  -h, --help             Display help menu
```

---

## JSON Graph Output Format

```json
{
  "metadata": {
    "timestamp_utc": "2026-09-22T15:02:30.304Z",
    "scan_duration_ms": 17882.53,
    "os_version": "Windows 10.0 (Build 26200)",
    "running_as_admin": true,
    "sedebugprivilege_enabled": true,
    "total_processes": 335,
    "total_threads": 6458,
    "total_memory_regions": 20336,
    "unbacked_executable_regions": 447,
    "total_sockets": 175
  },
  "nodes": {
    "processes": [
      {
        "pid": 4820,
        "ppid": 1120,
        "executable_name": "svchost.exe",
        "executable_path": "C:\\Windows\\System32\\svchost.exe",
        "access_denied": false,
        "threads": [4824, 4828, 4832],
        "modules": [
          {
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "base_address": "0x7FF700000000",
            "size": 65536
          }
        ]
      }
    ],
    "memory_regions": [
      {
        "id": "mem_4820_7ffef8c60000",
        "pid": 4820,
        "base_address": "0x7FFEF8C60000",
        "region_size": 65536,
        "state": "MEM_COMMIT",
        "protect": "PAGE_EXECUTE_READWRITE",
        "type": "MEM_PRIVATE",
        "is_executable": true,
        "is_unbacked": true,
        "entropy_calculated": true,
        "shannon_entropy": 7.4218
      }
    ],
    "sockets": [
      {
        "id": "sock_tcp4_4820_0.0.0.0_135_0.0.0.0_0",
        "pid": 4820,
        "protocol": "TCP",
        "local_address": "0.0.0.0",
        "local_port": 135,
        "remote_address": "0.0.0.0",
        "remote_port": 0,
        "state": "LISTENING"
      }
    ]
  },
  "edges": {
    "spawns": [
      {"parent_pid": 1120, "child_pid": 4820}
    ],
    "has_memory": [
      {"pid": 4820, "memory_id": "mem_4820_7ffef8c60000"}
    ],
    "connected_to": [
      {"pid": 4820, "socket_id": "sock_tcp4_4820_0.0.0.0_135_0.0.0.0_0"}
    ]
  }
}
```
