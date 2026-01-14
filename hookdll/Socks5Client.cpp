#include "Socks5Client.h"
#include "WinsockHooks.h"
#include "Logger.h"
#include <vector>

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
    sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = s_proxyInfo.serverIp;
    proxyAddr.sin_port = s_proxyInfo.serverPort;

    // Use Real_connect to avoid infinite recursion
    int result = WinsockHooks::Real_connect(sock,
        reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr));

    if (result == SOCKET_ERROR) {
        LOG("Failed to connect to proxy server: %d", WSAGetLastError());
        return false;
    }

    return true;
}

bool Socks5Client::DoHandshake(SOCKET sock) {
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
        LOG("SOCKS5: Offering auth methods: no-auth, username/password");
    } else {
        // Only offer no-auth
        greeting[0] = 0x05;  // VER
        greeting[1] = 0x01;  // NMETHODS
        greeting[2] = 0x00;  // METHOD: no auth
        greetingLen = 3;
        LOG("SOCKS5: Offering auth method: no-auth only");
    }

    int sent = send(sock, reinterpret_cast<char*>(greeting), greetingLen, 0);
    if (sent != greetingLen) {
        LOG("Failed to send SOCKS5 greeting: %d", WSAGetLastError());
        return false;
    }

    // Receive server choice: VER(0x05) METHOD
    uint8_t response[2];
    int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);
    if (received != 2) {
        LOG("Failed to receive SOCKS5 greeting response: %d", WSAGetLastError());
        return false;
    }

    if (response[0] != 0x05) {
        LOG("Invalid SOCKS version: 0x%02X", response[0]);
        return false;
    }

    if (response[1] == 0x00) {
        // No authentication required
        LOG("SOCKS5 handshake successful (no auth)");
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

    LOG("SOCKS5 CONNECT successful");
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

} // namespace MiniProxifier

