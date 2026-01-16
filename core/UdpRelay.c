#include "UdpRelay.h"
#include "Socks5.h"
#include "ProxyEngine.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_UDP_SESSIONS 256
#define UDP_BUFFER_SIZE 65535

// External references
extern char g_proxy_host[256];
extern uint16_t g_proxy_port;
extern char g_proxy_username[64];
extern char g_proxy_password[64];
extern LogCallback g_log_callback;

typedef struct {
    bool active;
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t dest_ip;
    uint8_t dest_ipv6[16];
    uint16_t dest_port;
    bool is_ipv6;
    SOCKET proxy_tcp_socket;    // TCP socket for UDP ASSOCIATE
    SOCKET relay_udp_socket;    // Local UDP socket for relay
    uint32_t relay_ip;          // Proxy's UDP relay IP
    uint16_t relay_port;        // Proxy's UDP relay port
    uint16_t local_port;        // Local port for client
    DWORD last_activity;
} UdpSession;

static UdpSession g_sessions[MAX_UDP_SESSIONS];
static SOCKET g_listen_socket = INVALID_SOCKET;
static HANDLE g_relay_thread = NULL;
static volatile bool g_running = false;
static uint16_t g_local_port = 0;
static CRITICAL_SECTION g_lock;

static void log_message(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

// SOCKS5 UDP request header
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

static int build_udp_header(uint8_t* buf, uint32_t dest_ip, uint16_t dest_port) {
    buf[0] = 0x00;  // RSV
    buf[1] = 0x00;  // RSV
    buf[2] = 0x00;  // FRAG (no fragmentation)
    buf[3] = 0x01;  // ATYP = IPv4
    buf[4] = (dest_ip >> 0) & 0xFF;
    buf[5] = (dest_ip >> 8) & 0xFF;
    buf[6] = (dest_ip >> 16) & 0xFF;
    buf[7] = (dest_ip >> 24) & 0xFF;
    buf[8] = (dest_port >> 8) & 0xFF;
    buf[9] = (dest_port >> 0) & 0xFF;
    return 10;
}

static int build_udp_header_ipv6(uint8_t* buf, const uint8_t* dest_ipv6, uint16_t dest_port) {
    buf[0] = 0x00;  // RSV
    buf[1] = 0x00;  // RSV
    buf[2] = 0x00;  // FRAG
    buf[3] = 0x04;  // ATYP = IPv6
    memcpy(&buf[4], dest_ipv6, 16);
    buf[20] = (dest_port >> 8) & 0xFF;
    buf[21] = (dest_port >> 0) & 0xFF;
    return 22;
}

static int Socks5_UdpAssociate(SOCKET s, uint32_t* relay_ip, uint16_t* relay_port,
                                const char* username, const char* password) {
    unsigned char buf[512];
    int len;
    bool use_auth = (username != NULL && username[0] != '\0');

    // Send greeting
    buf[0] = 0x05;  // SOCKS5
    if (use_auth) {
        buf[1] = 0x02;
        buf[2] = 0x00;
        buf[3] = 0x02;
        if (send(s, (char*)buf, 4, 0) != 4) return -1;
    } else {
        buf[1] = 0x01;
        buf[2] = 0x00;
        if (send(s, (char*)buf, 3, 0) != 3) return -1;
    }

    // Receive method selection
    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != 0x05) return -1;

    // Handle auth
    if (buf[1] == 0x02) {
        if (!use_auth) return -1;
        size_t user_len = strlen(username);
        size_t pass_len = password ? strlen(password) : 0;
        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        if (pass_len > 0) memcpy(&buf[3 + user_len], password, pass_len);
        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len)) return -1;
        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[1] != 0x00) return -1;
    } else if (buf[1] == 0xFF) {
        return -1;
    }

    // Send UDP ASSOCIATE request
    buf[0] = 0x05;  // SOCKS5
    buf[1] = 0x03;  // UDP ASSOCIATE
    buf[2] = 0x00;  // RSV
    buf[3] = 0x01;  // ATYP = IPv4
    buf[4] = 0x00;  // DST.ADDR = 0.0.0.0
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8] = 0x00;  // DST.PORT = 0
    buf[9] = 0x00;

    if (send(s, (char*)buf, 10, 0) != 10) {
        log_message("[UdpRelay] Failed to send UDP ASSOCIATE");
        return -1;
    }

    // Receive reply
    len = recv(s, (char*)buf, 10, 0);
    if (len < 10) {
        log_message("[UdpRelay] Failed to receive UDP ASSOCIATE reply");
        return -1;
    }
    if (buf[0] != 0x05 || buf[1] != 0x00) {
        log_message("[UdpRelay] UDP ASSOCIATE failed: 0x%02X", buf[1]);
        return -1;
    }

    // Parse BND.ADDR and BND.PORT
    if (buf[3] == 0x01) {  // IPv4
        *relay_ip = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
        *relay_port = (buf[8] << 8) | buf[9];
    } else {
        log_message("[UdpRelay] Unsupported relay address type: 0x%02X", buf[3]);
        return -1;
    }

    // If relay IP is 0.0.0.0, use proxy server IP
    if (*relay_ip == 0) {
        *relay_ip = Socks5_ResolveHostname(g_proxy_host);
    }

    return 0;
}

static UdpSession* find_session_by_client(uint32_t client_ip, uint16_t client_port) {
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (g_sessions[i].active &&
            g_sessions[i].client_ip == client_ip &&
            g_sessions[i].client_port == client_port) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

static UdpSession* find_free_session(void) {
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

static DWORD WINAPI UdpRelayThread(LPVOID arg) {
    uint8_t buffer[UDP_BUFFER_SIZE];
    struct sockaddr_in from_addr;
    int from_len;

    log_message("[UdpRelay] Thread started on port %d", g_local_port);

    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_listen_socket, &read_fds);

        // Also add all session relay sockets
        EnterCriticalSection(&g_lock);
        for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
            if (g_sessions[i].active && g_sessions[i].relay_udp_socket != INVALID_SOCKET) {
                FD_SET(g_sessions[i].relay_udp_socket, &read_fds);
            }
        }
        LeaveCriticalSection(&g_lock);

        struct timeval timeout = {1, 0};
        int ret = select(0, &read_fds, NULL, NULL, &timeout);
        if (ret <= 0) continue;

        // Check main listen socket (incoming from clients)
        if (FD_ISSET(g_listen_socket, &read_fds)) {
            from_len = sizeof(from_addr);
            int recv_len = recvfrom(g_listen_socket, (char*)buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&from_addr, &from_len);
            if (recv_len > 0) {
                uint32_t client_ip = from_addr.sin_addr.s_addr;
                uint16_t client_port = ntohs(from_addr.sin_port);

                EnterCriticalSection(&g_lock);
                UdpSession* session = find_session_by_client(client_ip, client_port);
                if (session != NULL && session->relay_udp_socket != INVALID_SOCKET) {
                    // Build SOCKS5 UDP header and forward
                    uint8_t send_buf[UDP_BUFFER_SIZE];
                    int header_len;
                    if (session->is_ipv6) {
                        header_len = build_udp_header_ipv6(send_buf, session->dest_ipv6, session->dest_port);
                    } else {
                        header_len = build_udp_header(send_buf, session->dest_ip, session->dest_port);
                    }
                    memcpy(send_buf + header_len, buffer, recv_len);

                    struct sockaddr_in relay_addr = {0};
                    relay_addr.sin_family = AF_INET;
                    relay_addr.sin_addr.s_addr = session->relay_ip;
                    relay_addr.sin_port = htons(session->relay_port);

                    sendto(session->relay_udp_socket, (char*)send_buf, header_len + recv_len, 0,
                           (struct sockaddr*)&relay_addr, sizeof(relay_addr));
                    session->last_activity = GetTickCount();
                }
                LeaveCriticalSection(&g_lock);
            }
        }

        // Check session relay sockets (incoming from proxy)
        EnterCriticalSection(&g_lock);
        for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
            if (g_sessions[i].active &&
                g_sessions[i].relay_udp_socket != INVALID_SOCKET &&
                FD_ISSET(g_sessions[i].relay_udp_socket, &read_fds)) {

                from_len = sizeof(from_addr);
                int recv_len = recvfrom(g_sessions[i].relay_udp_socket, (char*)buffer, sizeof(buffer), 0,
                                        (struct sockaddr*)&from_addr, &from_len);
                if (recv_len > 10) {
                    // Skip SOCKS5 UDP header (minimum 10 bytes for IPv4)
                    int header_len = 10;
                    if (buffer[3] == 0x04) header_len = 22;  // IPv6
                    else if (buffer[3] == 0x03) header_len = 4 + 1 + buffer[4] + 2;  // Domain

                    if (recv_len > header_len) {
                        // Send back to client
                        struct sockaddr_in client_addr = {0};
                        client_addr.sin_family = AF_INET;
                        client_addr.sin_addr.s_addr = g_sessions[i].client_ip;
                        client_addr.sin_port = htons(g_sessions[i].client_port);

                        sendto(g_listen_socket, (char*)(buffer + header_len), recv_len - header_len, 0,
                               (struct sockaddr*)&client_addr, sizeof(client_addr));
                        g_sessions[i].last_activity = GetTickCount();
                    }
                }
            }
        }
        LeaveCriticalSection(&g_lock);
    }

    log_message("[UdpRelay] Thread stopped");
    return 0;
}

bool UdpRelay_Init(void) {
    InitializeCriticalSection(&g_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
    return true;
}

void UdpRelay_Cleanup(void) {
    UdpRelay_Stop();
    DeleteCriticalSection(&g_lock);
}

bool UdpRelay_Start(uint16_t local_port) {
    if (g_running) return true;

    g_local_port = local_port;

    g_listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_listen_socket == INVALID_SOCKET) {
        log_message("[UdpRelay] Failed to create UDP socket");
        return false;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_port);

    if (bind(g_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_message("[UdpRelay] Failed to bind UDP port %d", local_port);
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        return false;
    }

    g_running = true;
    g_relay_thread = CreateThread(NULL, 0, UdpRelayThread, NULL, 0, NULL);
    if (g_relay_thread == NULL) {
        g_running = false;
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        return false;
    }

    log_message("[UdpRelay] Started on port %d", local_port);
    return true;
}

void UdpRelay_Stop(void) {
    if (!g_running) return;

    g_running = false;

    if (g_listen_socket != INVALID_SOCKET) {
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
    }

    // Close all sessions
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (g_sessions[i].active) {
            if (g_sessions[i].proxy_tcp_socket != INVALID_SOCKET)
                closesocket(g_sessions[i].proxy_tcp_socket);
            if (g_sessions[i].relay_udp_socket != INVALID_SOCKET)
                closesocket(g_sessions[i].relay_udp_socket);
            g_sessions[i].active = false;
        }
    }
    LeaveCriticalSection(&g_lock);

    if (g_relay_thread != NULL) {
        WaitForSingleObject(g_relay_thread, 5000);
        CloseHandle(g_relay_thread);
        g_relay_thread = NULL;
    }

    log_message("[UdpRelay] Stopped");
}

uint16_t UdpRelay_AddSession(uint32_t client_ip, uint16_t client_port,
                              uint32_t dest_ip, uint16_t dest_port) {
    EnterCriticalSection(&g_lock);

    // Check if session already exists
    UdpSession* session = find_session_by_client(client_ip, client_port);
    if (session != NULL) {
        LeaveCriticalSection(&g_lock);
        return g_local_port;
    }

    session = find_free_session();
    if (session == NULL) {
        LeaveCriticalSection(&g_lock);
        log_message("[UdpRelay] No free session slots");
        return 0;
    }

    // Connect to proxy for UDP ASSOCIATE
    uint32_t proxy_ip = Socks5_ResolveHostname(g_proxy_host);
    if (proxy_ip == 0) {
        LeaveCriticalSection(&g_lock);
        log_message("[UdpRelay] Failed to resolve proxy");
        return 0;
    }

    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    struct sockaddr_in proxy_addr = {0};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = proxy_ip;
    proxy_addr.sin_port = htons(g_proxy_port);

    if (connect(tcp_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        log_message("[UdpRelay] Failed to connect to proxy");
        return 0;
    }

    uint32_t relay_ip = 0;
    uint16_t relay_port = 0;
    if (Socks5_UdpAssociate(tcp_sock, &relay_ip, &relay_port, g_proxy_username, g_proxy_password) != 0) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    // Create UDP socket for relay
    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    session->active = true;
    session->client_ip = client_ip;
    session->client_port = client_port;
    session->dest_ip = dest_ip;
    session->dest_port = dest_port;
    session->is_ipv6 = false;
    session->proxy_tcp_socket = tcp_sock;
    session->relay_udp_socket = udp_sock;
    session->relay_ip = relay_ip;
    session->relay_port = relay_port;
    session->local_port = g_local_port;
    session->last_activity = GetTickCount();

    log_message("[UdpRelay] New session: client %d -> relay %d.%d.%d.%d:%d",
        client_port,
        (relay_ip >> 0) & 0xFF, (relay_ip >> 8) & 0xFF,
        (relay_ip >> 16) & 0xFF, (relay_ip >> 24) & 0xFF, relay_port);

    LeaveCriticalSection(&g_lock);
    return g_local_port;
}

uint16_t UdpRelay_AddSessionIPv6(uint32_t client_ip, uint16_t client_port,
                                  const uint8_t* dest_ipv6, uint16_t dest_port) {
    EnterCriticalSection(&g_lock);

    UdpSession* session = find_session_by_client(client_ip, client_port);
    if (session != NULL) {
        LeaveCriticalSection(&g_lock);
        return g_local_port;
    }

    session = find_free_session();
    if (session == NULL) {
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    uint32_t proxy_ip = Socks5_ResolveHostname(g_proxy_host);
    if (proxy_ip == 0) {
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    struct sockaddr_in proxy_addr = {0};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = proxy_ip;
    proxy_addr.sin_port = htons(g_proxy_port);

    if (connect(tcp_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    uint32_t relay_ip = 0;
    uint16_t relay_port = 0;
    if (Socks5_UdpAssociate(tcp_sock, &relay_ip, &relay_port, g_proxy_username, g_proxy_password) != 0) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        closesocket(tcp_sock);
        LeaveCriticalSection(&g_lock);
        return 0;
    }

    session->active = true;
    session->client_ip = client_ip;
    session->client_port = client_port;
    session->dest_ip = 0;
    memcpy(session->dest_ipv6, dest_ipv6, 16);
    session->dest_port = dest_port;
    session->is_ipv6 = true;
    session->proxy_tcp_socket = tcp_sock;
    session->relay_udp_socket = udp_sock;
    session->relay_ip = relay_ip;
    session->relay_port = relay_port;
    session->local_port = g_local_port;
    session->last_activity = GetTickCount();

    LeaveCriticalSection(&g_lock);
    return g_local_port;
}
