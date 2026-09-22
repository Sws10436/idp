#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "memory_scanner.hpp"
#include <windows.h>
#include <cmath>
#include <array>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>

namespace telemetry {

namespace {

struct HandleCloser {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
};
using ScopedHandle = std::unique_ptr<void, HandleCloser>;
} // anonymous namespace

bool MemoryScanner::IsExecutableProtection(uint32_t protect) {
    // Strip modifier flags like PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE
    uint32_t baseProtect = protect & 0xFF;
    return (baseProtect == PAGE_EXECUTE ||
            baseProtect == PAGE_EXECUTE_READ ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY);
}

std::string MemoryScanner::ProtectionToString(uint32_t protect) {
    std::string str;
    uint32_t base = protect & 0xFF;

    switch (base) {
        case PAGE_NOACCESS:          str = "PAGE_NOACCESS"; break;
        case PAGE_READONLY:          str = "PAGE_READONLY"; break;
        case PAGE_READWRITE:         str = "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY:         str = "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE:           str = "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ:      str = "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: str = "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: str = "PAGE_EXECUTE_WRITECOPY"; break;
        default:                     str = "UNKNOWN"; break;
    }

    if (protect & PAGE_GUARD)        str += " | PAGE_GUARD";
    if (protect & PAGE_NOCACHE)      str += " | PAGE_NOCACHE";
    if (protect & PAGE_WRITECOMBINE)  str += " | PAGE_WRITECOMBINE";

    return str;
}

std::string MemoryScanner::StateToString(uint32_t state) {
    switch (state) {
        case MEM_COMMIT:  return "MEM_COMMIT";
        case MEM_RESERVE: return "MEM_RESERVE";
        case MEM_FREE:    return "MEM_FREE";
        default:          return "UNKNOWN";
    }
}

std::string MemoryScanner::TypeToString(uint32_t type) {
    switch (type) {
        case MEM_PRIVATE: return "MEM_PRIVATE";
        case MEM_MAPPED:  return "MEM_MAPPED";
        case MEM_IMAGE:   return "MEM_IMAGE";
        default:          return "UNKNOWN";
    }
}

double MemoryScanner::CalculateShannonEntropy(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return 0.0;
    }

    std::array<size_t, 256> frequencies{};
    for (size_t i = 0; i < length; ++i) {
        frequencies[data[i]]++;
    }

    double entropy = 0.0;
    const double len_d = static_cast<double>(length);
    const double inv_log2 = 1.0 / std::log(2.0);

    for (size_t count : frequencies) {
        if (count > 0) {
            double p = static_cast<double>(count) / len_d;
            entropy -= p * (std::log(p) * inv_log2);
        }
    }

    return entropy;
}

std::vector<MemoryRegionNode> MemoryScanner::ScanProcess(uint32_t pid) {
    std::vector<MemoryRegionNode> regions;

    // Skip pseudo and idle PIDs
    if (pid == 0 || pid == 4) {
        return regions;
    }

    ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!hProcess) {
        return regions;
    }

    unsigned char* pAddress = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};

    constexpr size_t MAX_SCAN_BYTES_PER_REGION = 1024 * 1024; // 1 MB sample limit per region
    std::vector<uint8_t> readBuffer;

    while (VirtualQueryEx(hProcess.get(), pAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        bool isCommitted = (mbi.State == MEM_COMMIT);
        bool isExecutable = IsExecutableProtection(mbi.Protect);
        bool isPrivate = (mbi.Type == MEM_PRIVATE);

        // Filter for unbacked executable regions or executable regions in general
        if (isCommitted && isExecutable) {
            MemoryRegionNode node;
            uint64_t baseAddr = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            node.pid = pid;
            node.base_address = baseAddr;
            node.region_size = mbi.RegionSize;
            node.state = mbi.State;
            node.protect = mbi.Protect;
            node.type = mbi.Type;
            node.state_str = StateToString(mbi.State);
            node.protect_str = ProtectionToString(mbi.Protect);
            node.type_str = TypeToString(mbi.Type);
            node.is_executable = true;
            node.is_unbacked = isPrivate; // Private memory with executable rights (no backing PE image)

            // Construct unique ID for graph referencing
            std::ostringstream idStream;
            idStream << "mem_" << pid << "_" << std::hex << baseAddr;
            node.id = idStream.str();

            // Compute Shannon entropy if readable
            size_t bytesToRead = static_cast<size_t>(std::min<uint64_t>(mbi.RegionSize, MAX_SCAN_BYTES_PER_REGION));
            if (bytesToRead > 0) {
                readBuffer.resize(bytesToRead);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess.get(), mbi.BaseAddress, readBuffer.data(), bytesToRead, &bytesRead) && bytesRead > 0) {
                    node.shannon_entropy = CalculateShannonEntropy(readBuffer.data(), bytesRead);
                    node.entropy_calculated = true;
                }
            }

            regions.push_back(std::move(node));
        }

        // Advance to next region, checking for 64-bit address wraparound
        uintptr_t nextAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextAddr <= reinterpret_cast<uintptr_t>(mbi.BaseAddress)) {
            break; // Address space wrapped around
        }
        pAddress = reinterpret_cast<unsigned char*>(nextAddr);
    }

    return regions;
}

} // namespace telemetry
