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

    DebugLog("All hooks attached (connect, WSAConnect, CreateProcessW, CreateProcessA)");
    LOG("Winsock hooks attached successfully");
    return true;
}

bool WinsockHooks::DetachHooks() {
    DetourDetach(&(PVOID&)Real_connect, Hooked_connect);
    DetourDetach(&(PVOID&)Real_WSAConnect, Hooked_WSAConnect);
    DetourDetach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
    DetourDetach(&(PVOID&)Real_CreateProcessA, Hooked_CreateProcessA);
    LOG("Winsock hooks detached");
    return true;
}

int WinsockHooks::ProcessConnection(SOCKET s, const sockaddr* name, int namelen) {
    DebugLog("ProcessConnection called, socket=%llu", (unsigned long long)s);

    // Only handle IPv4 TCP connections
    if (name->sa_family != AF_INET) {
        DebugLog("Non-IPv4 connection (family=%d), passing through", name->sa_family);
        LOG("Non-IPv4 connection, passing through");
        return Real_connect(s, name, namelen);
    }

    const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(name);
    uint32_t targetIp = addr->sin_addr.s_addr;
    uint16_t targetPort = addr->sin_port;

    // Log the connection attempt
    DebugLog("Intercepted connect to %d.%d.%d.%d:%d",
        (targetIp >> 0) & 0xFF,
        (targetIp >> 8) & 0xFF,
        (targetIp >> 16) & 0xFF,
        (targetIp >> 24) & 0xFF,
        ntohs(targetPort));
    LOG("Intercepted connect to %d.%d.%d.%d:%d",
        (targetIp >> 0) & 0xFF,
        (targetIp >> 8) & 0xFF,
        (targetIp >> 16) & 0xFF,
        (targetIp >> 24) & 0xFF,
        ntohs(targetPort));

    // Check if proxy is configured
    if (!Socks5Client::IsProxyConfigured()) {
        DebugLog("No proxy configured, passing through");
        LOG("No proxy configured, passing through");
        return Real_connect(s, name, namelen);
    }

    // Skip connections to localhost (avoid proxy loop)
    if ((targetIp & 0xFF) == 127) {
        DebugLog("Localhost connection, passing through");
        LOG("Localhost connection, passing through");
        return Real_connect(s, name, namelen);
    }

    DebugLog("Redirecting through SOCKS5 proxy...");

    // Always set socket to blocking mode for SOCKS5 handshake
    // Get current blocking state
    u_long originalMode = 0;
    u_long blocking = 0;

    // Set to blocking mode
    if (ioctlsocket(s, FIONBIO, &blocking) != 0) {
        DebugLog("Warning: Failed to set socket to blocking mode: %d", WSAGetLastError());
    }

    // Connect through SOCKS5 proxy
    bool success = Socks5Client::ConnectThroughProxy(s, targetIp, targetPort);

    // Note: We don't restore non-blocking mode here because the caller
    // may expect a connected socket. If they need non-blocking, they'll set it.

    if (success) {
        LOG("SOCKS5 connection established successfully");
        return 0;
    } else {
        LOG("SOCKS5 connection failed");
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
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

} // namespace MiniProxifier
