#ifndef WINSOCK_HOOKS_H
#define WINSOCK_HOOKS_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>

namespace MiniProxifier {

class WinsockHooks {
public:
    // Attach all Winsock hooks (called within DetourTransaction)
    static bool AttachHooks();

    // Detach all Winsock hooks (called within DetourTransaction)
    static bool DetachHooks();

    // Original function pointers (for calling original implementations)
    static int (WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen);
    static int (WINAPI* Real_WSAConnect)(SOCKET s, const sockaddr* name, int namelen,
        LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

    // CreateProcess hooks for child process injection
    static BOOL (WINAPI* Real_CreateProcessW)(
        LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);
    static BOOL (WINAPI* Real_CreateProcessA)(
        LPCSTR lpApplicationName, LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);

    // ShellExecuteEx hooks for child process injection
    static BOOL (WINAPI* Real_ShellExecuteExW)(SHELLEXECUTEINFOW* pExecInfo);
    static BOOL (WINAPI* Real_ShellExecuteExA)(SHELLEXECUTEINFOA* pExecInfo);

private:
    // Hooked function implementations
    static int WINAPI Hooked_connect(SOCKET s, const sockaddr* name, int namelen);
    static int WINAPI Hooked_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
        LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

    // CreateProcess hooks
    static BOOL WINAPI Hooked_CreateProcessW(
        LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);
    static BOOL WINAPI Hooked_CreateProcessA(
        LPCSTR lpApplicationName, LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);

    // ShellExecuteEx hooks
    static BOOL WINAPI Hooked_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo);
    static BOOL WINAPI Hooked_ShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo);

    // Helper to process connection through SOCKS5
    static int ProcessConnection(SOCKET s, const sockaddr* name, int namelen);

    // Helper to inject DLL into child process
    static bool InjectIntoProcess(HANDLE hProcess, HANDLE hThread, DWORD dwCreationFlags);

    // Helper to inject DLL into process by PID (for ShellExecuteEx)
    static bool InjectIntoProcessByPid(DWORD processId);
};

} // namespace MiniProxifier

#endif // WINSOCK_HOOKS_H
