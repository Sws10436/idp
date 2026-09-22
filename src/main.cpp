#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_set>

#include "privilege.hpp"
#include "process_collector.hpp"
#include "memory_scanner.hpp"
#include "network_mapper.hpp"
#include "json_serializer.hpp"

namespace {

std::string GetCurrentUtcIso8601() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << "T"
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds << "Z";
    return oss.str();
}

std::string GetOsVersionString() {
    OSVERSIONINFOEXW osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    // Call RtlGetVersion via ntdll to bypass Windows 10/11 version manifest shims
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOEXW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pfn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(hNtdll, "RtlGetVersion")));
        if (pfn && pfn(&osvi) == 0) {
            std::ostringstream oss;
            oss << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
                << " (Build " << osvi.dwBuildNumber << ")";
            return oss.str();
        }
    }
    return "Microsoft Windows";
}

void PrintBanner() {
    std::cerr << "=================================================================\n";
    std::cerr << "  Windows Telemetry & Memory Forensics Engine (Phase 1)\n";
    std::cerr << "=================================================================\n";
}

void PrintUsage(const char* exeName) {
    std::cout << "Usage: " << exeName << " [options]\n\n"
              << "Options:\n"
              << "  -o, --output <file>    Specify output JSON path (default: telemetry.json)\n"
              << "  -s, --stdout           Print complete JSON to standard output\n"
              << "  -q, --quiet            Suppress console status messages\n"
              << "  -h, --help             Show this help menu\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string outputFile = "telemetry.json";
    bool printStdout = false;
    bool quiet = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            } else {
                std::cerr << "Error: --output requires a file path argument.\n";
                return 1;
            }
        } else if (arg == "-s" || arg == "--stdout") {
            printStdout = true;
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (!quiet) {
        PrintBanner();
    }

    auto startTime = std::chrono::high_resolution_clock::now();

    // 1. Privilege Elevation & SeDebugPrivilege Request
    auto privStatus = telemetry::ConfigurePrivileges();
    if (!quiet) {
        std::cerr << "[+] Token Check: " << (privStatus.is_admin ? "Administrator" : "Standard User") << "\n";
        std::cerr << "[+] SeDebugPrivilege: " << (privStatus.sedebug_enabled ? "ENABLED" : "DISABLED") << "\n";
        if (!privStatus.sedebug_enabled) {
            std::cerr << "    [*] Note: " << privStatus.message << "\n";
            std::cerr << "    [*] Tip: For full access to elevated processes, run terminal as Administrator.\n";
        }
    }

    telemetry::TelemetryGraph graph;
    graph.metadata.timestamp_utc = GetCurrentUtcIso8601();
    graph.metadata.os_version = GetOsVersionString();
    graph.metadata.running_as_admin = privStatus.is_admin;
    graph.metadata.sedebugprivilege_enabled = privStatus.sedebug_enabled;

    // 2. Process & Thread Enumeration
    if (!quiet) {
        std::cerr << "[*] Enumerating processes, threads, and modules...\n";
    }
    telemetry::ProcessCollector procCollector;
    graph.processes = procCollector.CollectProcesses();

    std::unordered_set<uint32_t> validPids;
    size_t totalThreads = 0;
    for (const auto& p : graph.processes) {
        validPids.insert(p.pid);
        totalThreads += p.thread_ids.size();
    }

    // Build spawn tree edges (PPID -> PID)
    for (const auto& p : graph.processes) {
        if (p.pid != 0 && p.pid != p.ppid && validPids.contains(p.ppid)) {
            graph.spawns.push_back({p.ppid, p.pid});
        }
    }

    // 3. Virtual Memory Scanning & Shannon Entropy
    if (!quiet) {
        std::cerr << "[*] Scanning virtual memory for unbacked executable regions...\n";
    }
    telemetry::MemoryScanner memScanner;
    size_t unbackedCount = 0;

    for (const auto& p : graph.processes) {
        if (p.pid == 0 || p.pid == 4) continue;

        auto regions = memScanner.ScanProcess(p.pid);
        for (auto& r : regions) {
            if (r.is_unbacked) {
                unbackedCount++;
            }
            // Link Process -> Memory Region Edge
            graph.has_memory.push_back({p.pid, r.id});
            graph.memory_regions.push_back(std::move(r));
        }
    }

    // 4. Network Socket Mapping
    if (!quiet) {
        std::cerr << "[*] Mapping active TCP/UDP connections...\n";
    }
    telemetry::NetworkMapper netMapper;
    graph.sockets = netMapper.CollectSockets();

    // Link Process -> Socket Edge
    for (const auto& s : graph.sockets) {
        graph.connected_to.push_back({s.pid, s.id});
    }

    // 5. Finalize Metadata & Timings
    auto endTime = std::chrono::high_resolution_clock::now();
    double durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    graph.metadata.scan_duration_ms = durationMs;
    graph.metadata.total_processes = graph.processes.size();
    graph.metadata.total_threads = totalThreads;
    graph.metadata.total_memory_regions = graph.memory_regions.size();
    graph.metadata.unbacked_executable_regions = unbackedCount;
    graph.metadata.total_sockets = graph.sockets.size();

    // 6. JSON Serialization & Output
    std::string jsonOutput = telemetry::JsonSerializer::Serialize(graph, true);

    if (!outputFile.empty()) {
        if (telemetry::JsonSerializer::SaveToFile(jsonOutput, outputFile)) {
            if (!quiet) {
                std::cerr << "[+] Telemetry graph successfully written to: " << outputFile << "\n";
            }
        } else {
            std::cerr << "[-] Error: Failed to write output file: " << outputFile << "\n";
        }
    }

    if (printStdout) {
        std::cout << jsonOutput << "\n";
    }

    // Summary statistics
    if (!quiet) {
        std::cerr << "-----------------------------------------------------------------\n";
        std::cerr << " Scan Summary:\n";
        std::cerr << "  - Elapsed Time: " << std::fixed << std::setprecision(1) << durationMs << " ms\n";
        std::cerr << "  - Processes Enumerated: " << graph.metadata.total_processes << "\n";
        std::cerr << "  - Threads Tracked:      " << graph.metadata.total_threads << "\n";
        std::cerr << "  - Executable Regions:   " << graph.metadata.total_memory_regions << "\n";
        std::cerr << "  - Unbacked Regions:     " << graph.metadata.unbacked_executable_regions
                  << (unbackedCount > 0 ? " [FLAGGED - Potential Shellcode/JIT]" : "") << "\n";
        std::cerr << "  - Sockets Mapped:       " << graph.metadata.total_sockets << "\n";
        std::cerr << "  - Spawn Edges:          " << graph.spawns.size() << "\n";
        std::cerr << "=================================================================\n";
    }

    return 0;
}
