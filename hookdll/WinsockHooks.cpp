#include "WinsockHooks.h"
#include "Socks5Client.h"
#include "SocketState.h"
#include "Logger.h"
#include <detours/detours.h>

namespace MiniProxifier {

// Original function pointers
int (WINAPI* WinsockHooks::Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
int (WINAPI* WinsockHooks::Real_WSAConnect)(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) = WSAConnect;

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

    LOG("Winsock hooks attached successfully");
    return true;
}

bool WinsockHooks::DetachHooks() {
    DetourDetach(&(PVOID&)Real_connect, Hooked_connect);
    DetourDetach(&(PVOID&)Real_WSAConnect, Hooked_WSAConnect);
    LOG("Winsock hooks detached");
    return true;
}

int WinsockHooks::ProcessConnection(SOCKET s, const sockaddr* name, int namelen) {
    // Only handle IPv4 TCP connections
    if (name->sa_family != AF_INET) {
        LOG("Non-IPv4 connection, passing through");
        return Real_connect(s, name, namelen);
    }

    const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(name);
    uint32_t targetIp = addr->sin_addr.s_addr;
    uint16_t targetPort = addr->sin_port;

    // Log the connection attempt
    LOG("Intercepted connect to %d.%d.%d.%d:%d",
        (targetIp >> 0) & 0xFF,
        (targetIp >> 8) & 0xFF,
        (targetIp >> 16) & 0xFF,
        (targetIp >> 24) & 0xFF,
        ntohs(targetPort));

    // Check if proxy is configured
    if (!Socks5Client::IsProxyConfigured()) {
        LOG("No proxy configured, passing through");
        return Real_connect(s, name, namelen);
    }

    // Skip connections to localhost (avoid proxy loop)
    if ((targetIp & 0xFF) == 127) {
        LOG("Localhost connection, passing through");
        return Real_connect(s, name, namelen);
    }

    // Get socket blocking mode
    u_long nonBlocking = 0;
    bool wasNonBlocking = SocketStateManager::IsNonBlocking(s);

    // If socket is non-blocking, temporarily make it blocking for SOCKS5 handshake
    if (wasNonBlocking) {
        nonBlocking = 0;
        ioctlsocket(s, FIONBIO, &nonBlocking);
    }

    // Connect through SOCKS5 proxy
    bool success = Socks5Client::ConnectThroughProxy(s, targetIp, targetPort);

    // Restore non-blocking mode if needed
    if (wasNonBlocking) {
        nonBlocking = 1;
        ioctlsocket(s, FIONBIO, &nonBlocking);
    }

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

} // namespace MiniProxifier
