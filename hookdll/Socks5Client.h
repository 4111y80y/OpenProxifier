#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <winsock2.h>
#include <string>
#include <cstdint>

namespace MiniProxifier {

class Socks5Client {
public:
    struct ProxyInfo {
        uint32_t serverIp;      // Proxy server IP (network byte order)
        uint16_t serverPort;    // Proxy server port (network byte order)
        bool authRequired;
        std::string username;
        std::string password;

        ProxyInfo() : serverIp(0), serverPort(0), authRequired(false) {}
    };

    // Set proxy configuration
    static void SetProxy(const ProxyInfo& proxy);

    // Check if proxy is configured
    static bool IsProxyConfigured();

    // Connect through SOCKS5 proxy
    // Returns true on success, false on failure
    static bool ConnectThroughProxy(
        SOCKET sock,
        uint32_t targetIp,      // Target IP (network byte order)
        uint16_t targetPort     // Target port (network byte order)
    );

private:
    // SOCKS5 handshake (supports no-auth and username/password)
    static bool DoHandshake(SOCKET sock);

    // SOCKS5 username/password authentication (RFC 1929)
    static bool DoAuthentication(SOCKET sock);

    // SOCKS5 CONNECT request
    static bool DoConnect(SOCKET sock, uint32_t targetIp, uint16_t targetPort);

    // Connect to proxy server
    static bool ConnectToProxy(SOCKET sock);

    static ProxyInfo s_proxyInfo;
    static bool s_configured;
};

} // namespace MiniProxifier

#endif // SOCKS5_CLIENT_H

