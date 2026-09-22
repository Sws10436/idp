#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "process_collector.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <memory>

namespace telemetry {

namespace {

// RAII wrapper for Windows HANDLE
struct HandleCloser {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
};
using ScopedHandle = std::unique_ptr<void, HandleCloser>;

} // anonymous namespace

std::unordered_map<uint32_t, std::vector<uint32_t>> ProcessCollector::CollectThreads() {
    std::unordered_map<uint32_t, std::vector<uint32_t>> process_threads;

    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        return process_threads;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot.get(), &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
                process_threads[te.th32OwnerProcessID].push_back(te.th32ThreadID);
            }
            te.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(snapshot.get(), &te));
    }

    return process_threads;
}

std::vector<ModuleInfo> ProcessCollector::CollectModulesForProcess(void* hProcess) {
    std::vector<ModuleInfo> modules;
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    // Use LIST_MODULES_ALL to capture both 32-bit and 64-bit modules
    if (EnumProcessModulesEx(static_cast<HANDLE>(hProcess), hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            ModuleInfo mod;
            mod.base_address = reinterpret_cast<uint64_t>(hMods[i]);

            WCHAR modName[MAX_PATH] = {0};
            if (GetModuleBaseNameW(static_cast<HANDLE>(hProcess), hMods[i], modName, MAX_PATH)) {
                mod.module_name = modName;
            }

            WCHAR modPath[MAX_PATH * 2] = {0};
            if (GetModuleFileNameExW(static_cast<HANDLE>(hProcess), hMods[i], modPath, MAX_PATH * 2)) {
                mod.module_path = modPath;
            }

            MODULEINFO mi{};
            if (GetModuleInformation(static_cast<HANDLE>(hProcess), hMods[i], &mi, sizeof(mi))) {
                mod.module_size = mi.SizeOfImage;
            }

            modules.push_back(std::move(mod));
        }
    }
    return modules;
}

std::vector<ProcessNode> ProcessCollector::CollectProcesses() {
    std::vector<ProcessNode> processes;
    auto thread_map = CollectThreads();

    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot.get(), &pe)) {
        do {
            ProcessNode proc;
            proc.pid = pe.th32ProcessID;
            proc.ppid = pe.th32ParentProcessID;
            proc.executable_name = pe.szExeFile;

            // Associate collected thread IDs
            auto it = thread_map.find(proc.pid);
            if (it != thread_map.end()) {
                proc.thread_ids = it->second;
            }

            // Attempt to open process for further details (modules & path)
            // Skip PID 0 (System Idle Process) and PID 4 (System) to prevent unnecessary errors
            if (proc.pid != 0 && proc.pid != 4) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
                if (hProc) {
                    ScopedHandle procHandle(hProc);
                    
                    // Retrieve full image path
                    WCHAR fullPath[MAX_PATH * 2] = {0};
                    DWORD pathSize = MAX_PATH * 2;
                    if (QueryFullProcessImageNameW(procHandle.get(), 0, fullPath, &pathSize)) {
                        proc.executable_path = fullPath;
                    }

                    // Enumerate loaded modules
                    proc.modules = CollectModulesForProcess(procHandle.get());
                    proc.access_denied = false;
                } else {
                    // Try with limited query information if full query was denied
                    HANDLE hLimited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.pid);
                    if (hLimited) {
                        ScopedHandle limitedHandle(hLimited);
                        WCHAR fullPath[MAX_PATH * 2] = {0};
                        DWORD pathSize = MAX_PATH * 2;
                        if (QueryFullProcessImageNameW(limitedHandle.get(), 0, fullPath, &pathSize)) {
                            proc.executable_path = fullPath;
                        }
                    }
                    proc.access_denied = true;
                }
            }

            processes.push_back(std::move(proc));
            pe.dwSize = sizeof(PROCESSENTRY32W);
        } while (Process32NextW(snapshot.get(), &pe));
    }

    return processes;
}

} // namespace telemetry
