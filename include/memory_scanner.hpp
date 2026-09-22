#pragma once

#include "telemetry_model.hpp"
#include <vector>
#include <cstdint>

namespace telemetry {

class MemoryScanner {
public:
    MemoryScanner() = default;

    // Scan the virtual memory space of a specified process for suspicious executable regions
    std::vector<MemoryRegionNode> ScanProcess(uint32_t pid);

    // Compute Shannon Entropy on a byte buffer (returns value between 0.0 and 8.0)
    static double CalculateShannonEntropy(const uint8_t* data, size_t length);

    // Helper functions to convert Windows memory constants to descriptive strings
    static std::string ProtectionToString(uint32_t protect);
    static std::string StateToString(uint32_t state);
    static std::string TypeToString(uint32_t type);
    static bool IsExecutableProtection(uint32_t protect);
};

} // namespace telemetry
