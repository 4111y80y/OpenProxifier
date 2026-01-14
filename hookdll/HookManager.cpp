#include "HookManager.h"
#include "WinsockHooks.h"
#include "Socks5Client.h"
#include "ProxyConfig.h"
#include "Logger.h"
#include <windows.h>
#include <detours/detours.h>
#include <cstdio>

// External debug log function (defined in dllmain.cpp)
extern void DebugLogExternal(const char* format, ...);

// Helper function to write to temp debug log
static void WriteDebugLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    // Also write to temp log file
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%shookdll_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "%s\n", buffer);
            fclose(f);
        }
    }
}

// Helper macro for debug logging
#define DEBUG_LOG(...) WriteDebugLog(__VA_ARGS__)

namespace MiniProxifier {

bool HookManager::s_initialized = false;
ProxyConfig HookManager::s_cachedConfig;
HANDLE HookManager::s_hMapFile = NULL;
ProxyConfig* HookManager::s_pLiveConfig = nullptr;

const ProxyConfig& HookManager::GetCachedConfig() {
    return s_cachedConfig;
}

bool HookManager::IsProxyEnabled() {
    // Check live config from shared memory
    if (s_pLiveConfig && s_pLiveConfig->isValid()) {
        return s_pLiveConfig->enabled != 0;
    }
    // Fallback to cached config
    return s_cachedConfig.enabled != 0;
}

bool HookManager::CreateSharedMemoryForProcess(DWORD processId) {
    // Format shared memory name for the child process
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    DEBUG_LOG("CreateSharedMemoryForProcess: Creating shared memory for PID %d: %ls", processId, sharedMemName);

    // Create file mapping
    HANDLE hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        static_cast<DWORD>(SHARED_MEM_SIZE),
        sharedMemName);

    if (!hMapFile) {
        DEBUG_LOG("CreateSharedMemoryForProcess: CreateFileMappingW failed: %d", GetLastError());
        return false;
    }

    // Map view and write config
    LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE);
    if (!pBuf) {
        DEBUG_LOG("CreateSharedMemoryForProcess: MapViewOfFile failed: %d", GetLastError());
        CloseHandle(hMapFile);
        return false;
    }

    // Copy cached config to shared memory
    memcpy(pBuf, &s_cachedConfig, sizeof(ProxyConfig));
    UnmapViewOfFile(pBuf);

    // Don't close hMapFile - keep it open so the shared memory persists
    // It will be closed when this process exits
    DEBUG_LOG("CreateSharedMemoryForProcess: Shared memory created successfully for PID %d", processId);
    return true;
}

bool HookManager::Initialize() {
    if (s_initialized) {
        return true;
    }

    // Load proxy configuration from shared memory
    if (!LoadProxyConfig()) {
        LOG("Warning: Failed to load proxy config, using default");
    }

    // Install Winsock hooks
    if (!InstallHooks()) {
        LOG("Failed to install hooks");
        return false;
    }

    s_initialized = true;
    return true;
}

bool HookManager::Shutdown() {
    if (!s_initialized) {
        return true;
    }

    if (!RemoveHooks()) {
        LOG("Failed to remove hooks");
        return false;
    }

    s_initialized = false;
    return true;
}

bool HookManager::InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach Winsock hooks
    if (!WinsockHooks::AttachHooks()) {
        DetourTransactionAbort();
        return false;
    }

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG("DetourTransactionCommit failed: %ld", error);
        return false;
    }

    return true;
}

bool HookManager::RemoveHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Detach Winsock hooks
    WinsockHooks::DetachHooks();

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG("DetourTransactionCommit failed during removal: %ld", error);
        return false;
    }

    return true;
}

bool HookManager::LoadProxyConfig() {
    // Get current process ID
    DWORD pid = GetCurrentProcessId();

    // Format shared memory name
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, pid);

    DEBUG_LOG("LoadProxyConfig: Looking for shared memory: %ls", sharedMemName);
    LOG("LoadProxyConfig: Looking for shared memory with PID %d", pid);

    // Open shared memory with read/write access for live updates
    s_hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedMemName);
    if (!s_hMapFile) {
        DWORD err = GetLastError();
        DEBUG_LOG("LoadProxyConfig: OpenFileMappingW failed, error=%d", err);
        LOG("Failed to open shared memory: %s (error: %d)",
            "shared memory not found", err);
        return false;
    }

    DEBUG_LOG("LoadProxyConfig: Shared memory opened successfully");

    // Map view and keep it open for live access
    s_pLiveConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(s_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE));
    if (!s_pLiveConfig) {
        DEBUG_LOG("LoadProxyConfig: MapViewOfFile failed");
        LOG("Failed to map view of shared memory");
        CloseHandle(s_hMapFile);
        s_hMapFile = NULL;
        return false;
    }

    DEBUG_LOG("LoadProxyConfig: Config magic=0x%08X, version=%d, enabled=%d",
        s_pLiveConfig->magic, s_pLiveConfig->version, s_pLiveConfig->enabled);

    // Validate config
    if (!s_pLiveConfig->isValid()) {
        DEBUG_LOG("LoadProxyConfig: Invalid config!");
        LOG("Invalid proxy config (magic: 0x%08X, version: %d)",
            s_pLiveConfig->magic, s_pLiveConfig->version);
        UnmapViewOfFile(s_pLiveConfig);
        s_pLiveConfig = nullptr;
        CloseHandle(s_hMapFile);
        s_hMapFile = NULL;
        return false;
    }

    // Cache the config for child process injection
    memcpy(&s_cachedConfig, s_pLiveConfig, sizeof(ProxyConfig));
    DEBUG_LOG("LoadProxyConfig: Config cached for child process injection");

    // Set proxy in Socks5Client
    Socks5Client::ProxyInfo proxy;
    proxy.serverIp = s_pLiveConfig->proxyIp;
    proxy.serverPort = s_pLiveConfig->proxyPort;
    proxy.authRequired = s_pLiveConfig->authRequired != 0;
    if (proxy.authRequired) {
        proxy.username = s_pLiveConfig->username;
        proxy.password = s_pLiveConfig->password;
    }
    Socks5Client::SetProxy(proxy);

    DEBUG_LOG("LoadProxyConfig: Proxy set to %d.%d.%d.%d:%d",
        (s_pLiveConfig->proxyIp >> 0) & 0xFF,
        (s_pLiveConfig->proxyIp >> 8) & 0xFF,
        (s_pLiveConfig->proxyIp >> 16) & 0xFF,
        (s_pLiveConfig->proxyIp >> 24) & 0xFF,
        ntohs(s_pLiveConfig->proxyPort));

    LOG("Proxy config loaded: %d.%d.%d.%d:%d",
        (s_pLiveConfig->proxyIp >> 0) & 0xFF,
        (s_pLiveConfig->proxyIp >> 8) & 0xFF,
        (s_pLiveConfig->proxyIp >> 16) & 0xFF,
        (s_pLiveConfig->proxyIp >> 24) & 0xFF,
        ntohs(s_pLiveConfig->proxyPort));

    // Note: Keep s_hMapFile and s_pLiveConfig open for live enabled flag checking
    return true;
}

} // namespace MiniProxifier

