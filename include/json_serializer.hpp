#pragma once

#include "telemetry_model.hpp"
#include <string>

namespace telemetry {

class JsonSerializer {
public:
    // Serialize the full TelemetryGraph into formatted JSON string
    static std::string Serialize(const TelemetryGraph& graph, bool pretty = true);

    // Save JSON string to a local file
    static bool SaveToFile(const std::string& json_str, const std::string& filepath);

    // Convert wide UTF-16 string (Windows API) to UTF-8 string
    static std::string WideToUtf8(const std::wstring& wstr);

    // Escape string for valid JSON format (quotes, backslashes, control characters)
    static std::string EscapeJsonString(const std::string& input);
};

} // namespace telemetry
