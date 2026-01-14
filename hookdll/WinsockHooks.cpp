#include "WinsockHooks.h"
#include "HookManager.h"
#include "Socks5Client.h"
#include "SocketState.h"
#include "Logger.h"
#include <detours/detours.h>
#include <cstdio>
#include <string>

// Helper function to write to temp debug log
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
        snprintf(logPath, MAX_PATH, "%shookdll_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "[WinsockHooks] %s\n", buffer);
            fclose(f);
        }
    }
}

namespace MiniProxifier {

// Original function pointers
int (WINAPI* WinsockHooks::Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
int (WINAPI* WinsockHooks::Real_WSAConnect)(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) = WSAConnect;

// CreateProcess original pointers
BOOL (WINAPI* WinsockHooks::Real_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL (WINAPI* WinsockHooks::Real_CreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;

// ShellExecuteEx original pointers
BOOL (WINAPI* WinsockHooks::Real_ShellExecuteExW)(SHELLEXECUTEINFOW*) = ShellExecuteExW;
BOOL (WINAPI* WinsockHooks::Real_ShellExecuteExA)(SHELLEXECUTEINFOA*) = ShellExecuteExA;

// Get the path of the current DLL
static std::wstring GetCurrentDllPath() {
    wchar_t path[MAX_PATH];
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&GetCurrentDllPath, &hModule);
    if (hModule && GetModuleFileNameW(hModule, path, MAX_PATH) > 0) {
        return path;
    }
    return L"";
}

bool WinsockHooks::AttachHooks() {
    LONG error;

    error = DetourAttach(&(PVOID&)Real_connect, Hooked_connect);
    if (error != NO_ERROR) {
        LOG("Failed to attach connect hook: %ld", error);
        return false;
    }

    error = DetourAttach(&(PVOID&)Real_WSAConnect, Hooked_WSAConnect);
    if (error != NO_ERROR) {
        LOG("Failed to attach WSAConnect hook: %ld", error);
        return false;
    }

    // Hook CreateProcess for child process injection
    error = DetourAttach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
    if (error != NO_ERROR) {
        LOG("Failed to attach CreateProcessW hook: %ld", error);
        return false;
    }

    error = DetourAttach(&(PVOID&)Real_CreateProcessA, Hooked_CreateProcessA);
    if (error != NO_ERROR) {
        LOG("Failed to attach CreateProcessA hook: %ld", error);
        return false;
    }

    // Hook ShellExecuteEx for child process injection
    error = DetourAttach(&(PVOID&)Real_ShellExecuteExW, Hooked_ShellExecuteExW);
    if (error != NO_ERROR) {
        LOG("Failed to attach ShellExecuteExW hook: %ld", error);
        return false;
    }

    error = DetourAttach(&(PVOID&)Real_ShellExecuteExA, Hooked_ShellExecuteExA);
    if (error != NO_ERROR) {
        LOG("Failed to attach ShellExecuteExA hook: %ld", error);
        return false;
    }

    DebugLog("All hooks attached (connect, WSAConnect, CreateProcess, ShellExecuteEx)");
    LOG("Winsock hooks attached successfully");
    return true;
}

bool WinsockHooks::DetachHooks() {
    DetourDetach(&(PVOID&)Real_connect, Hooked_connect);
    DetourDetach(&(PVOID&)Real_WSAConnect, Hooked_WSAConnect);
    DetourDetach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
    DetourDetach(&(PVOID&)Real_CreateProcessA, Hooked_CreateProcessA);
    DetourDetach(&(PVOID&)Real_ShellExecuteExW, Hooked_ShellExecuteExW);
    DetourDetach(&(PVOID&)Real_ShellExecuteExA, Hooked_ShellExecuteExA);
    LOG("Winsock hooks detached");
    return true;
}

int WinsockHooks::ProcessConnection(SOCKET s, const sockaddr* name, int namelen) {
    DebugLog("ProcessConnection called, socket=%llu, family=%d", (unsigned long long)s, name->sa_family);

    // Handle IPv4 connections
    if (name->sa_family == AF_INET) {
        const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(name);
        uint32_t targetIp = addr->sin_addr.s_addr;
        uint16_t targetPort = addr->sin_port;

        // Log the connection attempt
        DebugLog("Intercepted IPv4 connect to %d.%d.%d.%d:%d",
            (targetIp >> 0) & 0xFF,
            (targetIp >> 8) & 0xFF,
            (targetIp >> 16) & 0xFF,
            (targetIp >> 24) & 0xFF,
            ntohs(targetPort));

        // Check if proxy is enabled
        if (!HookManager::IsProxyEnabled()) {
            DebugLog("Proxy disabled, passing through");
            return Real_connect(s, name, namelen);
        }

        // Check if proxy is configured
        if (!Socks5Client::IsProxyConfigured()) {
            DebugLog("No proxy configured, passing through");
            return Real_connect(s, name, namelen);
        }

        // Skip connections to localhost
        if ((targetIp & 0xFF) == 127) {
            DebugLog("Localhost connection, passing through");
            return Real_connect(s, name, namelen);
        }

        DebugLog("Redirecting IPv4 through SOCKS5 proxy...");

        // Set socket to blocking mode for SOCKS5 handshake
        u_long blocking = 0;
        ioctlsocket(s, FIONBIO, &blocking);

        // Connect through SOCKS5 proxy
        bool success = Socks5Client::ConnectThroughProxy(s, targetIp, targetPort);

        if (success) {
            LOG("SOCKS5 connection established successfully (IPv4)");
            return 0;
        } else {
            LOG("SOCKS5 connection failed (IPv4)");
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
    }
    // Handle IPv6 connections
    else if (name->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(name);
        uint16_t targetPort = addr6->sin6_port;

        char ipStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6->sin6_addr, ipStr, sizeof(ipStr));

        DebugLog("Intercepted IPv6 connect to [%s]:%d", ipStr, ntohs(targetPort));

        // Check if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        // If so, we can proxy it as IPv4
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            // Extract the IPv4 address from the last 4 bytes
            uint32_t ipv4Addr;
            memcpy(&ipv4Addr, &addr6->sin6_addr.s6_addr[12], 4);

            DebugLog("IPv4-mapped address detected, treating as IPv4: %d.%d.%d.%d",
                (ipv4Addr >> 0) & 0xFF, (ipv4Addr >> 8) & 0xFF,
                (ipv4Addr >> 16) & 0xFF, (ipv4Addr >> 24) & 0xFF);

            // Check if proxy is enabled
            if (!HookManager::IsProxyEnabled()) {
                DebugLog("Proxy disabled, passing through");
                return Real_connect(s, name, namelen);
            }

            // Check if proxy is configured
            if (!Socks5Client::IsProxyConfigured()) {
                DebugLog("No proxy configured, passing through");
                return Real_connect(s, name, namelen);
            }

            // Skip localhost
            if ((ipv4Addr & 0xFF) == 127) {
                DebugLog("Localhost connection, passing through");
                return Real_connect(s, name, namelen);
            }

            DebugLog("Redirecting IPv4-mapped address through SOCKS5 proxy...");

            // Set socket to blocking mode
            u_long blocking = 0;
            ioctlsocket(s, FIONBIO, &blocking);

            // For IPv4-mapped addresses, use regular IPv4 proxy connection
            bool success = Socks5Client::ConnectThroughProxy(s, ipv4Addr, targetPort);

            if (success) {
                LOG("SOCKS5 connection established successfully (IPv4-mapped)");
                return 0;
            } else {
                LOG("SOCKS5 connection failed (IPv4-mapped)");
                WSASetLastError(WSAECONNREFUSED);
                return SOCKET_ERROR;
            }
        }

        // For pure IPv6 addresses, pass through directly
        // Most SOCKS5 proxies (including v2rayN) don't support IPv6 targets
        DebugLog("Pure IPv6 address, passing through (proxy doesn't support IPv6 targets)");
        return Real_connect(s, name, namelen);
    }
    else {
        // Other address families, pass through
        DebugLog("Unknown address family (%d), passing through", name->sa_family);
        return Real_connect(s, name, namelen);
    }
}

int WINAPI WinsockHooks::Hooked_connect(SOCKET s, const sockaddr* name, int namelen) {
    return ProcessConnection(s, name, namelen);
}

int WINAPI WinsockHooks::Hooked_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    // For WSAConnect, we ignore the extra parameters and use ProcessConnection
    // This is acceptable for most use cases
    return ProcessConnection(s, name, namelen);
}

// Inject DLL into child process
bool WinsockHooks::InjectIntoProcess(HANDLE hProcess, HANDLE hThread, DWORD dwCreationFlags) {
    std::wstring dllPath = GetCurrentDllPath();
    if (dllPath.empty()) {
        DebugLog("InjectIntoProcess: Failed to get DLL path");
        return false;
    }

    DebugLog("InjectIntoProcess: Injecting %ls", dllPath.c_str());

    // Calculate size needed for DLL path
    SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DebugLog("InjectIntoProcess: VirtualAllocEx failed: %d", GetLastError());
        return false;
    }

    // Write DLL path
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, &bytesWritten)) {
        DebugLog("InjectIntoProcess: WriteProcessMemory failed: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        DebugLog("InjectIntoProcess: GetProcAddress failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hRemoteThread) {
        DebugLog("InjectIntoProcess: CreateRemoteThread failed: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Wait for completion (with timeout)
    WaitForSingleObject(hRemoteThread, 5000);
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    DebugLog("InjectIntoProcess: DLL injected successfully");
    return true;
}

// Inject DLL into process by PID (for ShellExecuteEx)
bool WinsockHooks::InjectIntoProcessByPid(DWORD processId) {
    DebugLog("InjectIntoProcessByPid: PID=%d", processId);

    std::wstring dllPath = GetCurrentDllPath();
    if (dllPath.empty()) {
        DebugLog("InjectIntoProcessByPid: Failed to get DLL path");
        return false;
    }

    SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    // Retry logic for processes that may not be fully initialized
    const int maxRetries = 5;
    const int retryDelayMs = 100;

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        // Wait for process to initialize (longer for first attempt, shorter for retries)
        Sleep(attempt == 1 ? 100 : retryDelayMs);

        HANDLE hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE, processId);

        if (!hProcess) {
            DWORD err = GetLastError();
            DebugLog("InjectIntoProcessByPid: OpenProcess failed (attempt %d): %d", attempt, err);
            if (err == ERROR_INVALID_PARAMETER) {
                // Process no longer exists
                return false;
            }
            continue;
        }

        // Note: Protected Process Light (PPL) detection would require newer SDK
        // For now, we rely on VirtualAllocEx failing with ACCESS_DENIED

        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            DWORD err = GetLastError();
            DebugLog("InjectIntoProcessByPid: VirtualAllocEx failed (attempt %d): %d", attempt, err);
            CloseHandle(hProcess);
            if (err == ERROR_ACCESS_DENIED) {
                // May succeed on retry after process initializes
                continue;
            }
            return false;
        }

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, &bytesWritten)) {
            DebugLog("InjectIntoProcessByPid: WriteProcessMemory failed (attempt %d): %d", attempt, GetLastError());
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            continue;
        }

        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibraryAddr) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create shared memory BEFORE starting the remote thread
        // This way the DLL will find its config when it initializes
        HookManager::CreateSharedMemoryForProcess(processId);

        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
        if (!hRemoteThread) {
            DebugLog("InjectIntoProcessByPid: CreateRemoteThread failed (attempt %d): %d", attempt, GetLastError());
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            continue;
        }

        WaitForSingleObject(hRemoteThread, 5000);
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        DebugLog("InjectIntoProcessByPid: DLL injected successfully on attempt %d", attempt);
        return true;
    }

    DebugLog("InjectIntoProcessByPid: All %d attempts failed for PID %d", maxRetries, processId);
    return false;
}

// Hooked CreateProcessW
BOOL WINAPI WinsockHooks::Hooked_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    DebugLog("Hooked_CreateProcessW called");

    // Add CREATE_SUSPENDED to inject before process runs
    DWORD modifiedFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL wasSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

    // Call original CreateProcessW
    BOOL result = Real_CreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, modifiedFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        DebugLog("Child process created: PID=%d", lpProcessInformation->dwProcessId);

        // Create shared memory for the child process BEFORE injecting
        // This way the child's DLL can find its proxy config
        HookManager::CreateSharedMemoryForProcess(lpProcessInformation->dwProcessId);

        // Inject our DLL into the child process
        InjectIntoProcess(lpProcessInformation->hProcess, lpProcessInformation->hThread, dwCreationFlags);

        // Resume if it wasn't originally suspended
        if (!wasSuspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

// Hooked CreateProcessA
BOOL WINAPI WinsockHooks::Hooked_CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    DebugLog("Hooked_CreateProcessA called");

    // Add CREATE_SUSPENDED to inject before process runs
    DWORD modifiedFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL wasSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;

    // Call original CreateProcessA
    BOOL result = Real_CreateProcessA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, modifiedFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        DebugLog("Child process created: PID=%d", lpProcessInformation->dwProcessId);

        // Create shared memory for the child process BEFORE injecting
        // This way the child's DLL can find its proxy config
        HookManager::CreateSharedMemoryForProcess(lpProcessInformation->dwProcessId);

        // Inject our DLL into the child process
        InjectIntoProcess(lpProcessInformation->hProcess, lpProcessInformation->hThread, dwCreationFlags);

        // Resume if it wasn't originally suspended
        if (!wasSuspended) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

// Hooked ShellExecuteExW
BOOL WINAPI WinsockHooks::Hooked_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    DebugLog("Hooked_ShellExecuteExW called");

    // Request process handle so we can inject
    ULONG originalMask = pExecInfo->fMask;
    pExecInfo->fMask |= SEE_MASK_NOCLOSEPROCESS;

    BOOL result = Real_ShellExecuteExW(pExecInfo);

    if (result && pExecInfo->hProcess) {
        DWORD pid = GetProcessId(pExecInfo->hProcess);
        if (pid != 0) {
            DebugLog("ShellExecuteExW child process: PID=%d", pid);
            InjectIntoProcessByPid(pid);
        }

        // Close handle if we added the flag
        if (!(originalMask & SEE_MASK_NOCLOSEPROCESS)) {
            CloseHandle(pExecInfo->hProcess);
            pExecInfo->hProcess = NULL;
        }
    }

    // Restore original mask
    pExecInfo->fMask = originalMask;

    return result;
}

// Hooked ShellExecuteExA
BOOL WINAPI WinsockHooks::Hooked_ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo) {
    DebugLog("Hooked_ShellExecuteExA called");

    // Request process handle so we can inject
    ULONG originalMask = pExecInfo->fMask;
    pExecInfo->fMask |= SEE_MASK_NOCLOSEPROCESS;

    BOOL result = Real_ShellExecuteExA(pExecInfo);

    if (result && pExecInfo->hProcess) {
        DWORD pid = GetProcessId(pExecInfo->hProcess);
        if (pid != 0) {
            DebugLog("ShellExecuteExA child process: PID=%d", pid);
            InjectIntoProcessByPid(pid);
        }

        // Close handle if we added the flag
        if (!(originalMask & SEE_MASK_NOCLOSEPROCESS)) {
            CloseHandle(pExecInfo->hProcess);
            pExecInfo->hProcess = NULL;
        }
    }

    // Restore original mask
    pExecInfo->fMask = originalMask;

    return result;
}

} // namespace MiniProxifier

