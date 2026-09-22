#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace telemetry {

// Loaded dynamic-link library metadata
struct ModuleInfo {
    std::wstring module_name;
    std::wstring module_path;
    uint64_t base_address = 0;
    uint32_t module_size = 0;
};

// Process node representing a running process on the Windows system
struct ProcessNode {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::wstring executable_name;
    std::wstring executable_path;
    std::vector<uint32_t> thread_ids;
    std::vector<ModuleInfo> modules;
    bool is_elevated = false;
    bool access_denied = false;
};

// Memory region node representing committed memory pages
struct MemoryRegionNode {
    std::string id;            // Unique identifier: "mem_<pid>_<hex_addr>"
    uint32_t pid = 0;
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint32_t state = 0;        // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    uint32_t protect = 0;      // e.g. PAGE_EXECUTE_READWRITE
    uint32_t type = 0;         // MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE
    std::string state_str;
    std::string protect_str;
    std::string type_str;
    bool is_executable = false;
    bool is_unbacked = false;  // MEM_PRIVATE + Executable (potential injected shellcode/hook)
    double shannon_entropy = 0.0;
    bool entropy_calculated = false;
};

// Network socket node representing an active network endpoint
struct SocketNode {
    std::string id;            // Unique identifier: "sock_<pid>_<proto>_<lport>_<rport>"
    uint32_t pid = 0;
    std::string protocol;      // "TCP" or "UDP"
    std::string local_address;
    uint16_t local_port = 0;
    std::string remote_address;
    uint16_t remote_port = 0;
    std::string state;         // e.g., "ESTABLISHED", "LISTENING", "*"
};

// Edge representing a spawn relationship (PPID -> PID)
struct SpawnEdge {
    uint32_t parent_pid = 0;
    uint32_t child_pid = 0;
};

// Edge representing a process possessing a memory region
struct HasMemoryEdge {
    uint32_t pid = 0;
    std::string memory_id;
};

// Edge representing a process owning a network socket
struct ConnectedToEdge {
    uint32_t pid = 0;
    std::string socket_id;
};

// Graph metadata summary
struct ScanMetadata {
    std::string timestamp_utc;
    double scan_duration_ms = 0.0;
    std::string os_version;
    bool running_as_admin = false;
    bool sedebugprivilege_enabled = false;
    size_t total_processes = 0;
    size_t total_threads = 0;
    size_t total_memory_regions = 0;
    size_t unbacked_executable_regions = 0;
    size_t total_sockets = 0;
};

// Full Telemetry Graph combining nodes and edges
struct TelemetryGraph {
    ScanMetadata metadata;

    // Nodes
    std::vector<ProcessNode> processes;
    std::vector<MemoryRegionNode> memory_regions;
    std::vector<SocketNode> sockets;

    // Edges
    std::vector<SpawnEdge> spawns;
    std::vector<HasMemoryEdge> has_memory;
    std::vector<ConnectedToEdge> connected_to;
};

} // namespace telemetry
