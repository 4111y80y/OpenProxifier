#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include <string>
#include "ProxyConfig.h"

class Injector {
public:
    struct InjectResult {
        bool success;
        DWORD processId;
        std::wstring errorMessage;

        InjectResult() : success(false), processId(0) {}
    };

    // Launch a process and inject DLL
    static InjectResult LaunchAndInject(
        const std::wstring& exePath,
        const std::wstring& dllPath,
        const std::wstring& commandLine,
        const ProxyConfig& config
    );

    // Check if a process is 64-bit
    static bool IsProcess64Bit(HANDLE hProcess);

private:
    // Inject DLL into a suspended process
    static bool InjectDll(HANDLE hProcess, const std::wstring& dllPath, std::wstring& errorOut);

    // Create shared memory with proxy config
    static bool CreateSharedMemory(DWORD processId, const ProxyConfig& config, HANDLE& hMapFile);

    // Get last error as string
    static std::wstring GetLastErrorString();
};

#endif // INJECTOR_H
