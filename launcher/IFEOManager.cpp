// IFEOManager.cpp
// Implementation of IFEO registry management

#include "IFEOManager.h"
#include <shlwapi.h>
#include <shellapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace MiniProxifier {

const wchar_t* IFEOManager::IFEO_BASE_PATH =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

IFEOManager::IFEOManager() {
    // Get the path to ProxifierInjector (same directory as this exe)
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    // Replace exe name with ProxifierInjector
    PathRemoveFileSpecW(path);
#ifdef _WIN64
    PathAppendW(path, L"ProxifierInjector_x64.exe");
#else
    PathAppendW(path, L"ProxifierInjector_x86.exe");
#endif
    m_injectorPath = path;
}

IFEOManager& IFEOManager::Instance() {
    static IFEOManager instance;
    return instance;
}

bool IFEOManager::IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

bool IFEOManager::RequestElevation() {
    if (IsRunningAsAdmin()) {
        return true; // Already admin
    }

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteExW(&sei)) {
        return false;
    }

    // Exit current process, elevated one will take over
    ExitProcess(0);
    return true;
}

std::wstring IFEOManager::GetIFEOKeyPath(const std::wstring& exeName) {
    return std::wstring(IFEO_BASE_PATH) + L"\\" + exeName;
}

std::wstring IFEOManager::GetInjectorPath() const {
    return m_injectorPath;
}

bool IFEOManager::AddRule(const std::wstring& exeName) {
    if (!IsRunningAsAdmin()) {
        m_lastError = L"Administrator privileges required";
        return false;
    }

    std::wstring keyPath = GetIFEOKeyPath(exeName);
    HKEY hKey;

    // Create or open the key
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        m_lastError = L"Failed to create registry key, error: " + std::to_wstring(result);
        return false;
    }

    // Set the Debugger value to our injector path
    result = RegSetValueExW(
        hKey,
        L"Debugger",
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(m_injectorPath.c_str()),
        static_cast<DWORD>((m_injectorPath.length() + 1) * sizeof(wchar_t))
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        m_lastError = L"Failed to set Debugger value, error: " + std::to_wstring(result);
        return false;
    }

    return true;
}

bool IFEOManager::RemoveRule(const std::wstring& exeName) {
    if (!IsRunningAsAdmin()) {
        m_lastError = L"Administrator privileges required";
        return false;
    }

    std::wstring keyPath = GetIFEOKeyPath(exeName);
    HKEY hKey;

    // Open the key
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        0,
        KEY_WRITE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        if (result == ERROR_FILE_NOT_FOUND) {
            return true; // Key doesn't exist, nothing to remove
        }
        m_lastError = L"Failed to open registry key, error: " + std::to_wstring(result);
        return false;
    }

    // Delete the Debugger value
    result = RegDeleteValueW(hKey, L"Debugger");
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        m_lastError = L"Failed to delete Debugger value, error: " + std::to_wstring(result);
        return false;
    }

    // Try to delete the key if it's empty (optional, ignore errors)
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());

    return true;
}

bool IFEOManager::HasRule(const std::wstring& exeName) {
    std::wstring keyPath = GetIFEOKeyPath(exeName);
    HKEY hKey;

    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        0,
        KEY_READ,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        return false;
    }

    // Check if Debugger value exists and matches our injector
    wchar_t value[MAX_PATH];
    DWORD valueSize = sizeof(value);
    DWORD valueType;

    result = RegQueryValueExW(
        hKey,
        L"Debugger",
        NULL,
        &valueType,
        reinterpret_cast<BYTE*>(value),
        &valueSize
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || valueType != REG_SZ) {
        return false;
    }

    // Check if it's our injector
    std::wstring debuggerPath(value);
    return debuggerPath.find(L"ProxifierInjector") != std::wstring::npos;
}

std::vector<IFEORule> IFEOManager::GetAllRules() {
    std::vector<IFEORule> rules;
    HKEY hBaseKey;

    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        IFEO_BASE_PATH,
        0,
        KEY_READ,
        &hBaseKey
    );

    if (result != ERROR_SUCCESS) {
        return rules;
    }

    // Enumerate subkeys
    wchar_t keyName[256];
    DWORD keyNameSize;
    DWORD index = 0;

    while (true) {
        keyNameSize = sizeof(keyName) / sizeof(wchar_t);
        result = RegEnumKeyExW(hBaseKey, index++, keyName, &keyNameSize, NULL, NULL, NULL, NULL);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (result != ERROR_SUCCESS) {
            continue;
        }

        // Check if this key has our Debugger set
        std::wstring exeName(keyName);
        if (HasRule(exeName)) {
            IFEORule rule;
            rule.exeName = exeName;
            rule.injectorPath = m_injectorPath;
            rule.enabled = true;
            rules.push_back(rule);
        }
    }

    RegCloseKey(hBaseKey);
    return rules;
}

} // namespace MiniProxifier
