#include "Socks5Client.h"
#include "WinsockHooks.h"
#include "Logger.h"
#include <vector>

// Debug log helper
static void SocksDebugLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA("[SOCKS5] ");
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%shookdll_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "[SOCKS5] %s\n", buffer);
            fclose(f);
        }
    }
}

namespace MiniProxifier {

Socks5Client::ProxyInfo Socks5Client::s_proxyInfo;
bool Socks5Client::s_configured = false;

void Socks5Client::SetProxy(const ProxyInfo& proxy) {
    s_proxyInfo = proxy;
    s_configured = (proxy.serverIp != 0 && proxy.serverPort != 0);

    if (s_configured) {
        LOG("Proxy configured: %d.%d.%d.%d:%d",
            (proxy.serverIp >> 0) & 0xFF,
            (proxy.serverIp >> 8) & 0xFF,
            (proxy.serverIp >> 16) & 0xFF,
            (proxy.serverIp >> 24) & 0xFF,
            ntohs(proxy.serverPort));
    }
}

bool Socks5Client::IsProxyConfigured() {
    return s_configured;
}

bool Socks5Client::ConnectToProxy(SOCKET sock) {
    SocksDebugLog("ConnectToProxy: Connecting to %d.%d.%d.%d:%d",
        (s_proxyInfo.serverIp >> 0) & 0xFF,
        (s_proxyInfo.serverIp >> 8) & 0xFF,
        (s_proxyInfo.serverIp >> 16) & 0xFF,
        (s_proxyInfo.serverIp >> 24) & 0xFF,
        ntohs(s_proxyInfo.serverPort));

    // Check if this is an IPv6 socket by trying to get its address family
    WSAPROTOCOL_INFOW protocolInfo;
    int infoLen = sizeof(protocolInfo);
    bool isIPv6Socket = false;

    if (getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocolInfo, &infoLen) == 0) {
        isIPv6Socket = (protocolInfo.iAddressFamily == AF_INET6);
    }

    int result;

    if (isIPv6Socket) {
        // For IPv6 sockets, use IPv4-mapped IPv6 address
        SocksDebugLog("ConnectToProxy: Using IPv4-mapped IPv6 address for proxy connection");

        sockaddr_in6 proxyAddr6;
        memset(&proxyAddr6, 0, sizeof(proxyAddr6));
        proxyAddr6.sin6_family = AF_INET6;
        proxyAddr6.sin6_port = s_proxyInfo.serverPort;

        // Create IPv4-mapped IPv6 address: ::ffff:a.b.c.d
        proxyAddr6.sin6_addr.s6_addr[10] = 0xFF;
        proxyAddr6.sin6_addr.s6_addr[11] = 0xFF;
        memcpy(&proxyAddr6.sin6_addr.s6_addr[12], &s_proxyInfo.serverIp, 4);

        result = WinsockHooks::Real_connect(sock,
            reinterpret_cast<sockaddr*>(&proxyAddr6), sizeof(proxyAddr6));
    } else {
        // For IPv4 sockets, use normal IPv4 address
        sockaddr_in proxyAddr;
        proxyAddr.sin_family = AF_INET;
        proxyAddr.sin_addr.s_addr = s_proxyInfo.serverIp;
        proxyAddr.sin_port = s_proxyInfo.serverPort;

        result = WinsockHooks::Real_connect(sock,
            reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr));
    }

    if (result == SOCKET_ERROR) {
        SocksDebugLog("ConnectToProxy: Failed to connect to proxy server: %d", WSAGetLastError());
        LOG("Failed to connect to proxy server: %d", WSAGetLastError());
        return false;
    }

    SocksDebugLog("ConnectToProxy: Connected to proxy server successfully");
    return true;
}

bool Socks5Client::DoHandshake(SOCKET sock) {
    SocksDebugLog("DoHandshake: Starting SOCKS5 handshake");
    // SOCKS5 greeting with auth methods:
    // VER(0x05) NMETHODS METHODS...
    // 0x00 = no auth, 0x02 = username/password
    uint8_t greeting[4];
    int greetingLen;

    if (s_proxyInfo.authRequired && !s_proxyInfo.username.empty()) {
        // Offer both no-auth and username/password
        greeting[0] = 0x05;  // VER
        greeting[1] = 0x02;  // NMETHODS
        greeting[2] = 0x00;  // METHOD: no auth
        greeting[3] = 0x02;  // METHOD: username/password
        greetingLen = 4;
        SocksDebugLog("DoHandshake: Offering auth methods: no-auth, username/password");
    } else {
        // Only offer no-auth
        greeting[0] = 0x05;  // VER
        greeting[1] = 0x01;  // NMETHODS
        greeting[2] = 0x00;  // METHOD: no auth
        greetingLen = 3;
        SocksDebugLog("DoHandshake: Offering auth method: no-auth only");
    }

    int sent = send(sock, reinterpret_cast<char*>(greeting), greetingLen, 0);
    if (sent != greetingLen) {
        SocksDebugLog("DoHandshake: Failed to send greeting: %d", WSAGetLastError());
        return false;
    }
    SocksDebugLog("DoHandshake: Greeting sent, waiting for response...");

    // Receive server choice: VER(0x05) METHOD
    uint8_t response[2];
    int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);
    if (received != 2) {
        SocksDebugLog("DoHandshake: Failed to receive response: %d (got %d bytes)", WSAGetLastError(), received);
        return false;
    }

    SocksDebugLog("DoHandshake: Server response: VER=0x%02X METHOD=0x%02X", response[0], response[1]);

    if (response[0] != 0x05) {
        SocksDebugLog("DoHandshake: Invalid SOCKS version: 0x%02X", response[0]);
        return false;
    }

    if (response[1] == 0x00) {
        // No authentication required
        SocksDebugLog("DoHandshake: Handshake successful (no auth)");
        return true;
    } else if (response[1] == 0x02) {
        // Username/password authentication required (RFC 1929)
        LOG("SOCKS5: Server requires username/password auth");
        return DoAuthentication(sock);
    } else if (response[1] == 0xFF) {
        LOG("SOCKS5: No acceptable auth methods");
        return false;
    } else {
        LOG("SOCKS5 auth method not supported: 0x%02X", response[1]);
        return false;
    }
}

bool Socks5Client::DoAuthentication(SOCKET sock) {
    // RFC 1929 Username/Password Authentication
    // Request: VER(0x01) ULEN(1) USERNAME(1-255) PLEN(1) PASSWORD(1-255)

    if (s_proxyInfo.username.empty()) {
        LOG("SOCKS5 auth: No username configured");
        return false;
    }

    size_t ulen = s_proxyInfo.username.length();
    size_t plen = s_proxyInfo.password.length();

    if (ulen > 255 || plen > 255) {
        LOG("SOCKS5 auth: Username or password too long");
        return false;
    }

    // Build auth request
    std::vector<uint8_t> authReq;
    authReq.push_back(0x01);  // VER
    authReq.push_back(static_cast<uint8_t>(ulen));
    authReq.insert(authReq.end(), s_proxyInfo.username.begin(), s_proxyInfo.username.end());
    authReq.push_back(static_cast<uint8_t>(plen));
    authReq.insert(authReq.end(), s_proxyInfo.password.begin(), s_proxyInfo.password.end());

    int sent = send(sock, reinterpret_cast<char*>(authReq.data()),
                    static_cast<int>(authReq.size()), 0);
    if (sent != static_cast<int>(authReq.size())) {
        LOG("Failed to send SOCKS5 auth request: %d", WSAGetLastError());
        return false;
    }

    // Receive auth response: VER(0x01) STATUS
    uint8_t response[2];
    int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);
    if (received != 2) {
        LOG("Failed to receive SOCKS5 auth response: %d", WSAGetLastError());
        return false;
    }

    if (response[0] != 0x01) {
        LOG("Invalid SOCKS5 auth version: 0x%02X", response[0]);
        return false;
    }

    if (response[1] != 0x00) {
        LOG("SOCKS5 authentication failed (status: 0x%02X)", response[1]);
        return false;
    }

    LOG("SOCKS5 authentication successful");
    return true;
}

bool Socks5Client::DoConnect(SOCKET sock, uint32_t targetIp, uint16_t targetPort) {
    // SOCKS5 CONNECT request:
    // VER(0x05) CMD(0x01=CONNECT) RSV(0x00) ATYP(0x01=IPv4) DST.ADDR(4) DST.PORT(2)
    uint8_t request[10];
    request[0] = 0x05;  // VER
    request[1] = 0x01;  // CMD = CONNECT
    request[2] = 0x00;  // RSV
    request[3] = 0x01;  // ATYP = IPv4
    memcpy(&request[4], &targetIp, 4);    // DST.ADDR (already in network byte order)
    memcpy(&request[8], &targetPort, 2);  // DST.PORT (already in network byte order)

    int sent = send(sock, reinterpret_cast<char*>(request), 10, 0);
    if (sent != 10) {
        LOG("Failed to send SOCKS5 CONNECT request: %d", WSAGetLastError());
        return false;
    }

    // Receive response:
    // VER(0x05) REP RSV(0x00) ATYP BND.ADDR BND.PORT
    // Minimum response is 10 bytes (for IPv4)
    uint8_t response[10];
    int received = recv(sock, reinterpret_cast<char*>(response), 10, 0);
    if (received < 10) {
        LOG("Failed to receive SOCKS5 CONNECT response: %d (received %d bytes)",
            WSAGetLastError(), received);
        return false;
    }

    if (response[0] != 0x05) {
        LOG("Invalid SOCKS version in response: 0x%02X", response[0]);
        return false;
    }

    if (response[1] != 0x00) {
        // REP field indicates error
        const char* errorMsg = "Unknown error";
        switch (response[1]) {
            case 0x01: errorMsg = "General SOCKS server failure"; break;
            case 0x02: errorMsg = "Connection not allowed by ruleset"; break;
            case 0x03: errorMsg = "Network unreachable"; break;
            case 0x04: errorMsg = "Host unreachable"; break;
            case 0x05: errorMsg = "Connection refused"; break;
            case 0x06: errorMsg = "TTL expired"; break;
            case 0x07: errorMsg = "Command not supported"; break;
            case 0x08: errorMsg = "Address type not supported"; break;
        }
        LOG("SOCKS5 CONNECT failed: %s (0x%02X)", errorMsg, response[1]);
        return false;
    }

    LOG("SOCKS5 CONNECT successful (IPv4)");
    return true;
}

bool Socks5Client::DoConnectV6(SOCKET sock, const in6_addr& targetIp6, uint16_t targetPort) {
    // SOCKS5 CONNECT request for IPv6:
    // VER(0x05) CMD(0x01=CONNECT) RSV(0x00) ATYP(0x04=IPv6) DST.ADDR(16) DST.PORT(2)
    uint8_t request[22];
    request[0] = 0x05;  // VER
    request[1] = 0x01;  // CMD = CONNECT
    request[2] = 0x00;  // RSV
    request[3] = 0x04;  // ATYP = IPv6
    memcpy(&request[4], &targetIp6, 16);   // DST.ADDR (16 bytes)
    memcpy(&request[20], &targetPort, 2);  // DST.PORT (already in network byte order)

    int sent = send(sock, reinterpret_cast<char*>(request), 22, 0);
    if (sent != 22) {
        LOG("Failed to send SOCKS5 CONNECT request (IPv6): %d", WSAGetLastError());
        return false;
    }

    // Receive response:
    // VER(0x05) REP RSV(0x00) ATYP BND.ADDR BND.PORT
    // For IPv6: 4 + 16 + 2 = 22 bytes
    uint8_t response[22];
    int received = recv(sock, reinterpret_cast<char*>(response), 22, 0);
    if (received < 4) {
        LOG("Failed to receive SOCKS5 CONNECT response (IPv6): %d (received %d bytes)",
            WSAGetLastError(), received);
        return false;
    }

    if (response[0] != 0x05) {
        LOG("Invalid SOCKS version in response: 0x%02X", response[0]);
        return false;
    }

    if (response[1] != 0x00) {
        const char* errorMsg = "Unknown error";
        switch (response[1]) {
            case 0x01: errorMsg = "General SOCKS server failure"; break;
            case 0x02: errorMsg = "Connection not allowed by ruleset"; break;
            case 0x03: errorMsg = "Network unreachable"; break;
            case 0x04: errorMsg = "Host unreachable"; break;
            case 0x05: errorMsg = "Connection refused"; break;
            case 0x06: errorMsg = "TTL expired"; break;
            case 0x07: errorMsg = "Command not supported"; break;
            case 0x08: errorMsg = "Address type not supported"; break;
        }
        LOG("SOCKS5 CONNECT failed (IPv6): %s (0x%02X)", errorMsg, response[1]);
        return false;
    }

    LOG("SOCKS5 CONNECT successful (IPv6)");
    return true;
}

bool Socks5Client::ConnectThroughProxy(SOCKET sock, uint32_t targetIp, uint16_t targetPort) {
    LOG("Connecting through SOCKS5 proxy to %d.%d.%d.%d:%d",
        (targetIp >> 0) & 0xFF,
        (targetIp >> 8) & 0xFF,
        (targetIp >> 16) & 0xFF,
        (targetIp >> 24) & 0xFF,
        ntohs(targetPort));

    // Step 1: Connect to proxy server
    if (!ConnectToProxy(sock)) {
        return false;
    }

    // Step 2: SOCKS5 handshake
    if (!DoHandshake(sock)) {
        return false;
    }

    // Step 3: SOCKS5 CONNECT request
    if (!DoConnect(sock, targetIp, targetPort)) {
        return false;
    }

    return true;
}

bool Socks5Client::ConnectThroughProxyV6(SOCKET sock, const in6_addr& targetIp6, uint16_t targetPort) {
    char ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &targetIp6, ipStr, sizeof(ipStr));
    LOG("Connecting through SOCKS5 proxy to [%s]:%d", ipStr, ntohs(targetPort));

    // Step 1: Connect to proxy server
    if (!ConnectToProxy(sock)) {
        return false;
    }

    // Step 2: SOCKS5 handshake
    if (!DoHandshake(sock)) {
        return false;
    }

    // Step 3: SOCKS5 CONNECT request (IPv6)
    if (!DoConnectV6(sock, targetIp6, targetPort)) {
        return false;
    }

    return true;
}

} // namespace MiniProxifier

