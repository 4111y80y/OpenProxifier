#include <windows.h>
#include "HookManager.h"
#include "Logger.h"
#include <cstdio>
#include <shlobj.h>

// Get log file path in user's temp directory
static void GetDebugLogPath(char* path, size_t pathSize) {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        snprintf(path, pathSize, "%shookdll_debug.log", tempPath);
    } else {
        // Fallback to current directory
        snprintf(path, pathSize, "hookdll_debug.log");
    }
}

// Simple debug output function
static void DebugLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    // Write to temp directory (guaranteed to exist)
    char logPath[MAX_PATH];
    GetDebugLogPath(logPath, MAX_PATH);

    FILE* f = nullptr;
    fopen_s(&f, logPath, "a");
    if (f) {
        fprintf(f, "%s\n", buffer);
        fclose(f);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);

            // Write debug log immediately (non-blocking)
            DebugLog("=== MiniProxifierHook DLL Loaded ===");
            DebugLog("Process ID: %d", GetCurrentProcessId());

            // Initialize logger
            wchar_t dllLogPath[MAX_PATH];
            GetModuleFileNameW(hModule, dllLogPath, MAX_PATH);
            DebugLog("DLL Path: %ls", dllLogPath);

            wchar_t* lastSlash = wcsrchr(dllLogPath, L'\\');
            if (lastSlash) {
                wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - dllLogPath + 1), L"hookdll.log");
            }
            DebugLog("Log Path: %ls", dllLogPath);

            MiniProxifier::Logger::getInstance().init(dllLogPath);

            LOG("DLL_PROCESS_ATTACH - MiniProxifierHook loaded");
            LOG("Process ID: %d", GetCurrentProcessId());

            // Initialize hooks
            if (!MiniProxifier::HookManager::Initialize()) {
                LOG("Failed to initialize hooks");
                DebugLog("ERROR: Failed to initialize hooks");
                return FALSE;
            }
            LOG("Hooks initialized successfully");
            DebugLog("Hooks initialized successfully");
        }
        break;

    case DLL_PROCESS_DETACH:
        DebugLog("DLL_PROCESS_DETACH - Shutting down");
        LOG("DLL_PROCESS_DETACH - Shutting down");
        MiniProxifier::HookManager::Shutdown();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}


