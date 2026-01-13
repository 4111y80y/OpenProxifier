#include "HookManager.h"
#include "WinsockHooks.h"
#include "Socks5Client.h"
#include "ProxyConfig.h"
#include "Logger.h"
#include <windows.h>
#include <detours/detours.h>

namespace MiniProxifier {

bool HookManager::s_initialized = false;

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

    // Open shared memory
    HANDLE hMapFile = OpenFileMappingW(FILE_MAP_READ, FALSE, sharedMemName);
    if (!hMapFile) {
        LOG("Failed to open shared memory: %s (error: %d)",
            "shared memory not found", GetLastError());
        return false;
    }

    // Map view
    ProxyConfig* pConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, SHARED_MEM_SIZE));
    if (!pConfig) {
        LOG("Failed to map view of shared memory");
        CloseHandle(hMapFile);
        return false;
    }

    // Validate and copy config
    if (!pConfig->isValid()) {
        LOG("Invalid proxy config (magic: 0x%08X, version: %d)",
            pConfig->magic, pConfig->version);
        UnmapViewOfFile(pConfig);
        CloseHandle(hMapFile);
        return false;
    }

    // Set proxy in Socks5Client
    Socks5Client::ProxyInfo proxy;
    proxy.serverIp = pConfig->proxyIp;
    proxy.serverPort = pConfig->proxyPort;
    proxy.authRequired = pConfig->authRequired != 0;
    if (proxy.authRequired) {
        proxy.username = pConfig->username;
        proxy.password = pConfig->password;
    }
    Socks5Client::SetProxy(proxy);

    LOG("Proxy config loaded: %d.%d.%d.%d:%d",
        (pConfig->proxyIp >> 0) & 0xFF,
        (pConfig->proxyIp >> 8) & 0xFF,
        (pConfig->proxyIp >> 16) & 0xFF,
        (pConfig->proxyIp >> 24) & 0xFF,
        ntohs(pConfig->proxyPort));

    UnmapViewOfFile(pConfig);
    CloseHandle(hMapFile);
    return true;
}

} // namespace MiniProxifier
