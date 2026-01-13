#include <windows.h>
#include "HookManager.h"
#include "Logger.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);

            // Initialize logger
            wchar_t logPath[MAX_PATH];
            GetModuleFileNameW(hModule, logPath, MAX_PATH);
            wchar_t* lastSlash = wcsrchr(logPath, L'\\');
            if (lastSlash) {
                wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - logPath + 1), L"hookdll.log");
            }
            MiniProxifier::Logger::getInstance().init(logPath);

            LOG("DLL_PROCESS_ATTACH - MiniProxifierHook loaded");
            LOG("Process ID: %d", GetCurrentProcessId());

            // Initialize hooks
            if (!MiniProxifier::HookManager::Initialize()) {
                LOG("Failed to initialize hooks");
                return FALSE;
            }
            LOG("Hooks initialized successfully");
        }
        break;

    case DLL_PROCESS_DETACH:
        LOG("DLL_PROCESS_DETACH - Shutting down");
        MiniProxifier::HookManager::Shutdown();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
