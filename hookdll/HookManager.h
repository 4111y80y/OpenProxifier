#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

namespace MiniProxifier {

class HookManager {
public:
    // Initialize all hooks
    static bool Initialize();

    // Remove all hooks and cleanup
    static bool Shutdown();

private:
    static bool InstallHooks();
    static bool RemoveHooks();
    static bool LoadProxyConfig();

    static bool s_initialized;
};

} // namespace MiniProxifier

#endif // HOOK_MANAGER_H
