#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "json_serializer.hpp"
#include <windows.h>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace telemetry {

std::string JsonSerializer::WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) {
        return "";
    }
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) {
        return "";
    }
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &str[0], sizeNeeded, nullptr, nullptr);
    return str;
}

std::string JsonSerializer::EscapeJsonString(const std::string& input) {
    std::ostringstream ss;
    for (unsigned char c : input) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (c < 0x20) {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
                break;
        }
    }
    return ss.str();
}

std::string JsonSerializer::Serialize(const TelemetryGraph& graph, bool pretty) {
    std::ostringstream out;
    const std::string nl = pretty ? "\n" : "";
    const std::string ind1 = pretty ? "  " : "";
    const std::string ind2 = pretty ? "    " : "";
    const std::string ind3 = pretty ? "      " : "";
    const std::string ind4 = pretty ? "        " : "";

    out << "{" << nl;

    // Metadata
    out << ind1 << "\"metadata\": {" << nl;
    out << ind2 << "\"timestamp_utc\": \"" << EscapeJsonString(graph.metadata.timestamp_utc) << "\"," << nl;
    out << ind2 << "\"scan_duration_ms\": " << std::fixed << std::setprecision(2) << graph.metadata.scan_duration_ms << "," << nl;
    out << ind2 << "\"os_version\": \"" << EscapeJsonString(graph.metadata.os_version) << "\"," << nl;
    out << ind2 << "\"running_as_admin\": " << (graph.metadata.running_as_admin ? "true" : "false") << "," << nl;
    out << ind2 << "\"sedebugprivilege_enabled\": " << (graph.metadata.sedebugprivilege_enabled ? "true" : "false") << "," << nl;
    out << ind2 << "\"total_processes\": " << graph.metadata.total_processes << "," << nl;
    out << ind2 << "\"total_threads\": " << graph.metadata.total_threads << "," << nl;
    out << ind2 << "\"total_memory_regions\": " << graph.metadata.total_memory_regions << "," << nl;
    out << ind2 << "\"unbacked_executable_regions\": " << graph.metadata.unbacked_executable_regions << "," << nl;
    out << ind2 << "\"total_sockets\": " << graph.metadata.total_sockets << nl;
    out << ind1 << "}," << nl;

    // Nodes
    out << ind1 << "\"nodes\": {" << nl;

    // Nodes -> Processes
    out << ind2 << "\"processes\": [" << nl;
    for (size_t i = 0; i < graph.processes.size(); ++i) {
        const auto& p = graph.processes[i];
        out << ind3 << "{" << nl;
        out << ind4 << "\"pid\": " << p.pid << "," << nl;
        out << ind4 << "\"ppid\": " << p.ppid << "," << nl;
        out << ind4 << "\"executable_name\": \"" << EscapeJsonString(WideToUtf8(p.executable_name)) << "\"," << nl;
        out << ind4 << "\"executable_path\": \"" << EscapeJsonString(WideToUtf8(p.executable_path)) << "\"," << nl;
        out << ind4 << "\"access_denied\": " << (p.access_denied ? "true" : "false") << "," << nl;

        // Threads
        out << ind4 << "\"threads\": [";
        for (size_t t = 0; t < p.thread_ids.size(); ++t) {
            out << p.thread_ids[t] << (t + 1 < p.thread_ids.size() ? ", " : "");
        }
        out << "]," << nl;

        // Modules
        out << ind4 << "\"modules\": [" << nl;
        for (size_t m = 0; m < p.modules.size(); ++m) {
            const auto& mod = p.modules[m];
            out << ind4 << "  {" << nl;
            out << ind4 << "    \"name\": \"" << EscapeJsonString(WideToUtf8(mod.module_name)) << "\"," << nl;
            out << ind4 << "    \"path\": \"" << EscapeJsonString(WideToUtf8(mod.module_path)) << "\"," << nl;
            out << ind4 << "    \"base_address\": \"0x" << std::hex << std::uppercase << mod.base_address << std::dec << "\"," << nl;
            out << ind4 << "    \"size\": " << mod.module_size << nl;
            out << ind4 << "  }" << (m + 1 < p.modules.size() ? "," : "") << nl;
        }
        out << ind4 << "]" << nl;

        out << ind3 << "}" << (i + 1 < graph.processes.size() ? "," : "") << nl;
    }
    out << ind2 << "]," << nl;

    // Nodes -> Memory Regions
    out << ind2 << "\"memory_regions\": [" << nl;
    for (size_t i = 0; i < graph.memory_regions.size(); ++i) {
        const auto& r = graph.memory_regions[i];
        out << ind3 << "{" << nl;
        out << ind4 << "\"id\": \"" << EscapeJsonString(r.id) << "\"," << nl;
        out << ind4 << "\"pid\": " << r.pid << "," << nl;
        out << ind4 << "\"base_address\": \"0x" << std::hex << std::uppercase << r.base_address << std::dec << "\"," << nl;
        out << ind4 << "\"region_size\": " << r.region_size << "," << nl;
        out << ind4 << "\"state\": \"" << EscapeJsonString(r.state_str) << "\"," << nl;
        out << ind4 << "\"protect\": \"" << EscapeJsonString(r.protect_str) << "\"," << nl;
        out << ind4 << "\"type\": \"" << EscapeJsonString(r.type_str) << "\"," << nl;
        out << ind4 << "\"is_executable\": " << (r.is_executable ? "true" : "false") << "," << nl;
        out << ind4 << "\"is_unbacked\": " << (r.is_unbacked ? "true" : "false") << "," << nl;
        out << ind4 << "\"entropy_calculated\": " << (r.entropy_calculated ? "true" : "false") << "," << nl;
        out << ind4 << "\"shannon_entropy\": " << std::fixed << std::setprecision(4) << r.shannon_entropy << nl;
        out << ind3 << "}" << (i + 1 < graph.memory_regions.size() ? "," : "") << nl;
    }
    out << ind2 << "]," << nl;

    // Nodes -> Sockets
    out << ind2 << "\"sockets\": [" << nl;
    for (size_t i = 0; i < graph.sockets.size(); ++i) {
        const auto& s = graph.sockets[i];
        out << ind3 << "{" << nl;
        out << ind4 << "\"id\": \"" << EscapeJsonString(s.id) << "\"," << nl;
        out << ind4 << "\"pid\": " << s.pid << "," << nl;
        out << ind4 << "\"protocol\": \"" << EscapeJsonString(s.protocol) << "\"," << nl;
        out << ind4 << "\"local_address\": \"" << EscapeJsonString(s.local_address) << "\"," << nl;
        out << ind4 << "\"local_port\": " << s.local_port << "," << nl;
        out << ind4 << "\"remote_address\": \"" << EscapeJsonString(s.remote_address) << "\"," << nl;
        out << ind4 << "\"remote_port\": " << s.remote_port << "," << nl;
        out << ind4 << "\"state\": \"" << EscapeJsonString(s.state) << "\"" << nl;
        out << ind3 << "}" << (i + 1 < graph.sockets.size() ? "," : "") << nl;
    }
    out << ind2 << "]" << nl;
    out << ind1 << "}," << nl;

    // Edges
    out << ind1 << "\"edges\": {" << nl;

    // Edges -> Spawns
    out << ind2 << "\"spawns\": [" << nl;
    for (size_t i = 0; i < graph.spawns.size(); ++i) {
        const auto& e = graph.spawns[i];
        out << ind3 << "{\"parent_pid\": " << e.parent_pid << ", \"child_pid\": " << e.child_pid << "}"
            << (i + 1 < graph.spawns.size() ? "," : "") << nl;
    }
    out << ind2 << "]," << nl;

    // Edges -> HasMemory
    out << ind2 << "\"has_memory\": [" << nl;
    for (size_t i = 0; i < graph.has_memory.size(); ++i) {
        const auto& e = graph.has_memory[i];
        out << ind3 << "{\"pid\": " << e.pid << ", \"memory_id\": \"" << EscapeJsonString(e.memory_id) << "\"}"
            << (i + 1 < graph.has_memory.size() ? "," : "") << nl;
    }
    out << ind2 << "]," << nl;

    // Edges -> ConnectedTo
    out << ind2 << "\"connected_to\": [" << nl;
    for (size_t i = 0; i < graph.connected_to.size(); ++i) {
        const auto& e = graph.connected_to[i];
        out << ind3 << "{\"pid\": " << e.pid << ", \"socket_id\": \"" << EscapeJsonString(e.socket_id) << "\"}"
            << (i + 1 < graph.connected_to.size() ? "," : "") << nl;
    }
    out << ind2 << "]" << nl;

    out << ind1 << "}" << nl;
    out << "}" << nl;

    return out.str();
}

bool JsonSerializer::SaveToFile(const std::string& json_str, const std::string& filepath) {
    std::ofstream file(filepath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << json_str;
    return file.good();
}

} // namespace telemetry
