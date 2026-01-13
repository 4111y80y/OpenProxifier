#pragma once
// IFEOManager.h
// Manages Image File Execution Options registry entries for automatic DLL injection

#include <windows.h>
#include <string>
#include <vector>

namespace MiniProxifier {

struct IFEORule {
    std::wstring exeName;      // e.g., "curl.exe"
    std::wstring injectorPath; // Full path to ProxifierInjector
    bool enabled;
};

class IFEOManager {
public:
    // Get the singleton instance
    static IFEOManager& Instance();

    // Check if running as administrator
    static bool IsRunningAsAdmin();

    // Request elevation (restart as admin)
    static bool RequestElevation();

    // Add IFEO rule for an executable
    bool AddRule(const std::wstring& exeName);

    // Remove IFEO rule for an executable
    bool RemoveRule(const std::wstring& exeName);

    // Check if an executable has IFEO rule set
    bool HasRule(const std::wstring& exeName);

    // Get all configured rules
    std::vector<IFEORule> GetAllRules();

    // Get the injector path
    std::wstring GetInjectorPath() const;

    // Get last error message
    std::wstring GetLastError() const { return m_lastError; }

private:
    IFEOManager();
    ~IFEOManager() = default;

    std::wstring GetIFEOKeyPath(const std::wstring& exeName);
    std::wstring m_injectorPath;
    std::wstring m_lastError;

    static const wchar_t* IFEO_BASE_PATH;
};

} // namespace MiniProxifier
