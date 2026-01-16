#include "LocalProxy.h"
#include "ConnectionTracker.h"
#include "Socks5.h"
#include "ProxyEngine.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

// External references
extern char g_proxy_host[256];
extern uint16_t g_proxy_port;
extern int g_proxy_type;
extern char g_proxy_username[64];
extern char g_proxy_password[64];
extern LogCallback g_log_callback;

static SOCKET g_listen_socket = INVALID_SOCKET;
static HANDLE g_proxy_thread = NULL;
static volatile bool g_running = false;
static uint16_t g_local_port = 0;

typedef struct {
    SOCKET client_socket;
    uint32_t dest_ip;
    uint16_t dest_port;
} ConnectionContext;

typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TransferContext;

static void log_message(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

static DWORD WINAPI TransferThread(LPVOID arg) {
    TransferContext* ctx = (TransferContext*)arg;
    SOCKET from = ctx->from_socket;
    SOCKET to = ctx->to_socket;
    char buf[8192];
    int len;

    free(ctx);

    while (true) {
        len = recv(from, buf, sizeof(buf), 0);
        if (len <= 0) {
            shutdown(from, SD_RECEIVE);
            shutdown(to, SD_SEND);
            break;
        }

        int sent = 0;
        while (sent < len) {
            int n = send(to, buf + sent, len - sent, 0);
            if (n == SOCKET_ERROR) {
                shutdown(from, SD_BOTH);
                shutdown(to, SD_BOTH);
                return 0;
            }
            sent += n;
        }
    }

    return 0;
}

static DWORD WINAPI ConnectionHandler(LPVOID arg) {
    ConnectionContext* ctx = (ConnectionContext*)arg;
    SOCKET client_sock = ctx->client_socket;
    uint32_t dest_ip = ctx->dest_ip;
    uint16_t dest_port = ctx->dest_port;

    free(ctx);

    // Resolve proxy hostname
    uint32_t proxy_ip = Socks5_ResolveHostname(g_proxy_host);
    if (proxy_ip == 0) {
        log_message("[LocalProxy] Failed to resolve proxy host: %s", g_proxy_host);
        closesocket(client_sock);
        return 0;
    }

    // Connect to proxy
    SOCKET proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock == INVALID_SOCKET) {
        log_message("[LocalProxy] Failed to create proxy socket");
        closesocket(client_sock);
        return 0;
    }

    struct sockaddr_in proxy_addr = {0};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = proxy_ip;
    proxy_addr.sin_port = htons(g_proxy_port);

    if (connect(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        log_message("[LocalProxy] Failed to connect to proxy %s:%d", g_proxy_host, g_proxy_port);
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    // Perform proxy handshake
    int result;
    if (g_proxy_type == PROXY_TYPE_SOCKS5) {
        result = Socks5_Connect(proxy_sock, dest_ip, dest_port,
                               g_proxy_username, g_proxy_password);
    } else {
        result = Http_Connect(proxy_sock, dest_ip, dest_port,
                             g_proxy_username, g_proxy_password);
    }

    if (result != 0) {
        log_message("[LocalProxy] Proxy handshake failed for %d.%d.%d.%d:%d",
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    // Create bidirectional forwarding
    TransferContext* ctx1 = (TransferContext*)malloc(sizeof(TransferContext));
    TransferContext* ctx2 = (TransferContext*)malloc(sizeof(TransferContext));

    if (ctx1 == NULL || ctx2 == NULL) {
        if (ctx1) free(ctx1);
        if (ctx2) free(ctx2);
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    ctx1->from_socket = client_sock;
    ctx1->to_socket = proxy_sock;
    ctx2->from_socket = proxy_sock;
    ctx2->to_socket = client_sock;

    HANDLE thread1 = CreateThread(NULL, 0, TransferThread, ctx1, 0, NULL);
    if (thread1 == NULL) {
        free(ctx1);
        free(ctx2);
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    // Run second transfer in current thread
    TransferThread(ctx2);

    WaitForSingleObject(thread1, INFINITE);
    CloseHandle(thread1);

    closesocket(client_sock);
    closesocket(proxy_sock);

    return 0;
}

static DWORD WINAPI LocalProxyThread(LPVOID arg) {
    log_message("[LocalProxy] Thread started on port %d", g_local_port);

    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_listen_socket, &read_fds);
        struct timeval timeout = {1, 0};

        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(g_listen_socket, (struct sockaddr*)&client_addr, &addr_len);

        if (client_sock == INVALID_SOCKET)
            continue;

        // Get original destination from connection tracker
        uint16_t client_port = ntohs(client_addr.sin_port);
        uint32_t dest_ip;
        uint16_t dest_port;

        log_message("[LocalProxy] Accepted connection from port %d", client_port);

        if (!ConnectionTracker_Get(client_port, &dest_ip, &dest_port)) {
            log_message("[LocalProxy] No tracked connection for port %d", client_port);
            closesocket(client_sock);
            continue;
        }

        // Create connection context
        ConnectionContext* ctx = (ConnectionContext*)malloc(sizeof(ConnectionContext));
        if (ctx == NULL) {
            closesocket(client_sock);
            continue;
        }

        ctx->client_socket = client_sock;
        ctx->dest_ip = dest_ip;
        ctx->dest_port = dest_port;

        // Handle in new thread
        HANDLE conn_thread = CreateThread(NULL, 0, ConnectionHandler, ctx, 0, NULL);
        if (conn_thread == NULL) {
            free(ctx);
            closesocket(client_sock);
            continue;
        }
        CloseHandle(conn_thread);
    }

    log_message("[LocalProxy] Thread stopped");
    return 0;
}

bool LocalProxy_Init(void) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return false;
    }
    return true;
}

void LocalProxy_Cleanup(void) {
    LocalProxy_Stop();
    WSACleanup();
}

bool LocalProxy_Start(uint16_t port) {
    if (g_running) return true;

    g_local_port = port;

    g_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_socket == INVALID_SOCKET) {
        log_message("[LocalProxy] Failed to create listen socket");
        return false;
    }

    int on = 1;
    setsockopt(g_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(g_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_message("[LocalProxy] Failed to bind to port %d", port);
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        return false;
    }

    if (listen(g_listen_socket, 16) == SOCKET_ERROR) {
        log_message("[LocalProxy] Failed to listen");
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        return false;
    }

    g_running = true;
    g_proxy_thread = CreateThread(NULL, 0, LocalProxyThread, NULL, 0, NULL);
    if (g_proxy_thread == NULL) {
        g_running = false;
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        return false;
    }

    log_message("[LocalProxy] Started on port %d", port);
    return true;
}

void LocalProxy_Stop(void) {
    if (!g_running) return;

    g_running = false;

    if (g_listen_socket != INVALID_SOCKET) {
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
    }

    if (g_proxy_thread != NULL) {
        WaitForSingleObject(g_proxy_thread, 5000);
        CloseHandle(g_proxy_thread);
        g_proxy_thread = NULL;
    }

    log_message("[LocalProxy] Stopped");
}
