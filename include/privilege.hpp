#pragma once

#include <string>

namespace telemetry {

// Structure holding privilege verification and acquisition results
struct PrivilegeStatus {
    bool is_admin = false;
    bool sedebug_enabled = false;
    std::string message;
};

// Check if current process has elevated administrator token
bool IsProcessElevated();

// Attempt to enable SeDebugPrivilege on current process token
PrivilegeStatus ConfigurePrivileges();

} // namespace telemetry
