#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "privilege.hpp"
#include <windows.h>
#include <sstream>

namespace telemetry {

bool IsProcessElevated() {
    bool elevated = false;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation{};
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            elevated = (elevation.TokenIsElevated != 0);
        }
        CloseHandle(hToken);
    }
    return elevated;
}

PrivilegeStatus ConfigurePrivileges() {
    PrivilegeStatus status;
    status.is_admin = IsProcessElevated();

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "Failed to open process token for adjustment. Error: " << err;
        status.message = oss.str();
        return status;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "Failed to lookup SE_DEBUG_NAME privilege. Error: " << err;
        status.message = oss.str();
        CloseHandle(hToken);
        return status;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "AdjustTokenPrivileges call failed. Error: " << err;
        status.message = oss.str();
        CloseHandle(hToken);
        return status;
    }

    DWORD lastErr = GetLastError();
    if (lastErr == ERROR_NOT_ALL_ASSIGNED) {
        status.sedebug_enabled = false;
        status.message = "SeDebugPrivilege not assigned to current token. Run as Administrator.";
    } else {
        status.sedebug_enabled = true;
        status.message = "SeDebugPrivilege successfully acquired.";
    }

    CloseHandle(hToken);
    return status;
}

} // namespace telemetry
