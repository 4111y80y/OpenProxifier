#ifndef WINSOCK_HOOKS_H
#define WINSOCK_HOOKS_H

#include <winsock2.h>
#include <ws2tcpip.h>

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

private:
    // Hooked function implementations
    static int WINAPI Hooked_connect(SOCKET s, const sockaddr* name, int namelen);
    static int WINAPI Hooked_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
        LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

    // Helper to process connection through SOCKS5
    static int ProcessConnection(SOCKET s, const sockaddr* name, int namelen);
};

} // namespace MiniProxifier

#endif // WINSOCK_HOOKS_H
