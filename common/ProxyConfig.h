#ifndef PROXY_CONFIG_H
#define PROXY_CONFIG_H

#include <cstdint>
#include <cstring>

#pragma pack(push, 1)

// Proxy configuration structure shared between launcher and hookdll
struct ProxyConfig {
    static constexpr uint32_t MAGIC = 0x50524F58;  // "PROX"
    static constexpr uint32_t VERSION = 2;  // Bumped for enabled field

    uint32_t magic;          // Magic number for validation
    uint32_t version;        // Structure version
    uint32_t proxyIp;        // Proxy server IP (network byte order)
    uint16_t proxyPort;      // Proxy server port (network byte order)
    uint8_t  authRequired;   // Authentication required flag
    uint8_t  enabled;        // Proxy enabled flag (1=enabled, 0=disabled)
    char     username[64];   // Username (if auth required)
    char     password[64];   // Password (if auth required)
    uint32_t flags;          // Additional flags

    ProxyConfig() {
        memset(this, 0, sizeof(ProxyConfig));
        magic = MAGIC;
        version = VERSION;
        enabled = 1;  // Enabled by default
    }

    bool isValid() const {
        return magic == MAGIC && version == VERSION;
    }
};

#pragma pack(pop)

// Shared memory name format: Local\MiniProxifier_<PID>
constexpr const wchar_t* SHARED_MEM_NAME_FORMAT = L"Local\\MiniProxifier_%d";
constexpr size_t SHARED_MEM_SIZE = sizeof(ProxyConfig);

#endif // PROXY_CONFIG_H
