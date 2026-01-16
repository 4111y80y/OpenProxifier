#ifndef SOCKS5_H
#define SOCKS5_H

#include <winsock2.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02

// SOCKS5 connect through proxy (IPv4)
// Returns 0 on success, -1 on error
int Socks5_Connect(SOCKET s, uint32_t dest_ip, uint16_t dest_port,
                   const char* username, const char* password);

// SOCKS5 connect through proxy (IPv6)
// Returns 0 on success, -1 on error
int Socks5_ConnectIPv6(SOCKET s, const uint8_t* dest_ipv6, uint16_t dest_port,
                       const char* username, const char* password);

// HTTP CONNECT through proxy
// Returns 0 on success, -1 on error
int Http_Connect(SOCKET s, uint32_t dest_ip, uint16_t dest_port,
                 const char* username, const char* password);

// Resolve hostname to IP
uint32_t Socks5_ResolveHostname(const char* hostname);

#ifdef __cplusplus
}
#endif

#endif // SOCKS5_H
