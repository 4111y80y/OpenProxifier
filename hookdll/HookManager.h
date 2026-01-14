#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <windows.h>
#include "ProxyConfig.h"

namespace MiniProxifier {

class HookManager {
public:
    // Initialize all hooks
    static bool Initialize();

    // Remove all hooks and cleanup
    static bool Shutdown();

    // Get cached proxy config for child process injection
    static const ProxyConfig& GetCachedConfig();

    // Create shared memory for a child process
    static bool CreateSharedMemoryForProcess(DWORD processId);

    // Check if proxy is currently enabled (reads from shared memory)
    static bool IsProxyEnabled();

private:
    static bool InstallHooks();
    static bool RemoveHooks();
    static bool LoadProxyConfig();

    static bool s_initialized;
    static ProxyConfig s_cachedConfig;
    static HANDLE s_hMapFile;
    static ProxyConfig* s_pLiveConfig;  // Live pointer to shared memory
};

} // namespace MiniProxifier

#endif // HOOK_MANAGER_H

