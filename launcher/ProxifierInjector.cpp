// ProxifierInjector.cpp
// A command-line tool that launches an exe with DLL injection
// Used with Image File Execution Options (IFEO) for transparent proxification

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <cstdio>
#include "ProxyConfig.h"

#pragma comment(lib, "ws2_32.lib")

// Debug log function
static void DebugLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%sinjector_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "[Injector] %s\n", buffer);
            fclose(f);
        }
    }
}

// Get the directory of this executable
std::wstring GetOwnDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring dir(path);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        dir = dir.substr(0, pos);
    }
    return dir;
}

// Create shared memory with proxy config
bool CreateProxySharedMemory(DWORD processId, uint32_t proxyIp, uint16_t proxyPort) {
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    HANDLE hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        SHARED_MEM_SIZE,
        sharedMemName
    );

    if (!hMapFile) {
        DebugLog("Failed to create shared memory, error: %d", GetLastError());
        return false;
    }

    ProxyConfig* pConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE)
    );

    if (!pConfig) {
        CloseHandle(hMapFile);
        DebugLog("Failed to map view of file");
        return false;
    }

    memset(pConfig, 0, sizeof(ProxyConfig));
    pConfig->magic = ProxyConfig::MAGIC;
    pConfig->version = ProxyConfig::VERSION;
    pConfig->proxyIp = proxyIp;
    pConfig->proxyPort = proxyPort;

    UnmapViewOfFile(pConfig);
    // Don't close hMapFile - needs to stay open for target process

    DebugLog("Created shared memory for PID %d", processId);
    return true;
}

// Inject DLL into process
bool InjectDll(HANDLE hProcess, const std::wstring& dllPath) {
    SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DebugLog("VirtualAllocEx failed, error: %d", GetLastError());
        return false;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, &bytesWritten)) {
        DebugLog("WriteProcessMemory failed, error: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        DebugLog("GetProcAddress failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        DebugLog("CreateRemoteThread failed, error: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    DebugLog("DLL injected successfully");
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    DebugLog("ProxifierInjector started with %d args", argc);

    if (argc < 2) {
        DebugLog("No target executable specified");
        std::wcerr << L"Usage: ProxifierInjector <executable> [args...]" << std::endl;
        return 1;
    }

    // The first argument after our exe name is the target exe path
    std::wstring targetExe = argv[1];
    DebugLog("Target exe: %ls", targetExe.c_str());

    // If the target is not an absolute path, search for it in PATH
    if (targetExe.find(L'\\') == std::wstring::npos && targetExe.find(L'/') == std::wstring::npos) {
        wchar_t fullPath[MAX_PATH];
        DWORD result = SearchPathW(NULL, targetExe.c_str(), L".exe", MAX_PATH, fullPath, NULL);
        if (result > 0 && result < MAX_PATH) {
            targetExe = fullPath;
            DebugLog("Resolved path: %ls", targetExe.c_str());
        } else {
            DebugLog("SearchPath failed for: %ls, error: %d", argv[1], GetLastError());
            std::wcerr << L"Error: Cannot find executable: " << argv[1] << std::endl;
            return 1;
        }
    }

    // Build command line from remaining arguments
    std::wstring cmdLine = L"\"" + targetExe + L"\"";
    for (int i = 2; i < argc; i++) {
        cmdLine += L" ";
        cmdLine += argv[i];
    }
    DebugLog("Command line: %ls", cmdLine.c_str());

    // Get DLL path (same directory as this exe)
    std::wstring ownDir = GetOwnDirectory();
#ifdef _WIN64
    std::wstring dllPath = ownDir + L"\\MiniProxifierHook_x64.dll";
#else
    std::wstring dllPath = ownDir + L"\\MiniProxifierHook_x86.dll";
#endif
    DebugLog("DLL path: %ls", dllPath.c_str());

    // Read proxy config from environment or config file
    // For now, hardcode the proxy settings (can be made configurable)
    uint32_t proxyIp = 0;
    uint16_t proxyPort = 0;

    // Try to read from environment variable
    char proxyEnv[256] = {0};
    if (GetEnvironmentVariableA("PROXIFIER_PROXY", proxyEnv, sizeof(proxyEnv)) > 0) {
        // Format: IP:PORT
        char ipStr[64] = {0};
        int port = 0;
        if (sscanf_s(proxyEnv, "%63[^:]:%d", ipStr, (unsigned)sizeof(ipStr), &port) == 2) {
            struct in_addr addr;
            if (inet_pton(AF_INET, ipStr, &addr) == 1) {
                proxyIp = addr.s_addr;
                proxyPort = htons((uint16_t)port);
                DebugLog("Proxy from env: %s:%d", ipStr, port);
            }
        }
    }

    // Default proxy if not set
    if (proxyIp == 0) {
        struct in_addr addr;
        inet_pton(AF_INET, "172.30.156.245", &addr);
        proxyIp = addr.s_addr;
        proxyPort = htons(1081);
        DebugLog("Using default proxy: 172.30.156.245:1081");
    }

    // Create process in suspended state
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    std::wstring mutableCmdLine(cmdLine);
    BOOL created = CreateProcessW(
        targetExe.c_str(),
        &mutableCmdLine[0],
        NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL,
        &si, &pi
    );

    if (!created) {
        DebugLog("CreateProcessW failed, error: %d", GetLastError());
        return 1;
    }

    DebugLog("Process created suspended, PID: %d", pi.dwProcessId);

    // Create shared memory with proxy config
    if (!CreateProxySharedMemory(pi.dwProcessId, proxyIp, proxyPort)) {
        DebugLog("Failed to create shared memory");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Inject DLL
    if (!InjectDll(pi.hProcess, dllPath)) {
        DebugLog("Failed to inject DLL");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Resume the process
    ResumeThread(pi.hThread);
    DebugLog("Process resumed");

    // Wait for process to exit
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLog("Process exited with code: %d", exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exitCode;
}
