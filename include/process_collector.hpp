#pragma once

#include "telemetry_model.hpp"
#include <vector>
#include <unordered_map>

namespace telemetry {

class ProcessCollector {
public:
    ProcessCollector() = default;

    // Collect all running processes, their threads, and their loaded modules
    std::vector<ProcessNode> CollectProcesses();

private:
    // Helper to collect threads and map them by Process ID
    std::unordered_map<uint32_t, std::vector<uint32_t>> CollectThreads();

    // Helper to query loaded modules for a given process handle
    std::vector<ModuleInfo> CollectModulesForProcess(void* hProcess);
};

} // namespace telemetry
