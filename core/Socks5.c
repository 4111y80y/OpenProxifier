#include "Socks5.h"
#include "ProxyEngine.h"
#include <stdbool.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "ws2_32.lib")

// External log callback
extern LogCallback g_log_callback;

static void socks5_log(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

uint32_t Socks5_ResolveHostname(const char* hostname) {
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // First try to parse as IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) {
        return addr.s_addr;
    }

    // Not an IP address, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET) {
        if (result != NULL)
            freeaddrinfo(result);
        return 0;
    }

    struct sockaddr_in* sa = (struct sockaddr_in*)result->ai_addr;
    uint32_t resolved_ip = sa->sin_addr.s_addr;
    freeaddrinfo(result);

    return resolved_ip;
}

int Socks5_Connect(SOCKET s, uint32_t dest_ip, uint16_t dest_port,
                   const char* username, const char* password) {
    unsigned char buf[512];
    int len;
    bool use_auth = (username != NULL && username[0] != '\0');

    // Send greeting
    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 0x02;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = SOCKS5_AUTH_USERPASS;
        if (send(s, (char*)buf, 4, 0) != 4) {
            socks5_log("[SOCKS5] Failed to send greeting (auth)");
            return -1;
        }
    } else {
        buf[1] = 0x01;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3) {
            socks5_log("[SOCKS5] Failed to send greeting");
            return -1;
        }
    }

    // Receive method selection
    len = recv(s, (char*)buf, 2, 0);
    if (len != 2) {
        socks5_log("[SOCKS5] Failed to receive method selection (len=%d, err=%d)", len, WSAGetLastError());
        return -1;
    }
    if (buf[0] != SOCKS5_VERSION) {
        socks5_log("[SOCKS5] Invalid version: 0x%02X (expected 0x05)", buf[0]);
        return -1;
    }

    // Handle authentication
    if (buf[1] == SOCKS5_AUTH_USERPASS) {
        if (!use_auth) {
            socks5_log("[SOCKS5] Server requires auth but no credentials provided");
            return -1;
        }

        // Send username/password (RFC 1929)
        size_t user_len = strlen(username);
        size_t pass_len = password ? strlen(password) : 0;
        if (user_len > 255 || pass_len > 255) {
            socks5_log("[SOCKS5] Username or password too long");
            return -1;
        }

        buf[0] = 0x01;  // Version of username/password auth
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        if (pass_len > 0) {
            memcpy(&buf[3 + user_len], password, pass_len);
        }

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len)) {
            socks5_log("[SOCKS5] Failed to send credentials");
            return -1;
        }

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00) {
            socks5_log("[SOCKS5] Authentication failed (len=%d, status=0x%02X)", len, len >= 2 ? buf[1] : 0);
            return -1;
        }
    } else if (buf[1] == 0xFF) {
        socks5_log("[SOCKS5] No acceptable auth method");
        return -1;
    } else if (buf[1] != SOCKS5_AUTH_NONE) {
        socks5_log("[SOCKS5] Unsupported auth method: 0x%02X", buf[1]);
        return -1;
    }

    // Send CONNECT request
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;  // Reserved
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = (dest_ip >> 0) & 0xFF;
    buf[5] = (dest_ip >> 8) & 0xFF;
    buf[6] = (dest_ip >> 16) & 0xFF;
    buf[7] = (dest_ip >> 24) & 0xFF;
    buf[8] = (dest_port >> 8) & 0xFF;
    buf[9] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 10, 0) != 10) {
        socks5_log("[SOCKS5] Failed to send CONNECT request");
        return -1;
    }

    // Receive reply
    len = recv(s, (char*)buf, 10, 0);
    if (len < 4) {
        socks5_log("[SOCKS5] Failed to receive CONNECT reply (len=%d, err=%d)", len, WSAGetLastError());
        return -1;
    }
    if (buf[0] != SOCKS5_VERSION) {
        socks5_log("[SOCKS5] Invalid reply version: 0x%02X", buf[0]);
        return -1;
    }
    if (buf[1] != 0x00) {
        const char* err_msg = "Unknown error";
        switch (buf[1]) {
            case 0x01: err_msg = "General failure"; break;
            case 0x02: err_msg = "Connection not allowed"; break;
            case 0x03: err_msg = "Network unreachable"; break;
            case 0x04: err_msg = "Host unreachable"; break;
            case 0x05: err_msg = "Connection refused"; break;
            case 0x06: err_msg = "TTL expired"; break;
            case 0x07: err_msg = "Command not supported"; break;
            case 0x08: err_msg = "Address type not supported"; break;
        }
        socks5_log("[SOCKS5] CONNECT failed: %s (0x%02X)", err_msg, buf[1]);
        return -1;
    }

    return 0;
}

// Base64 encoding for HTTP Basic auth
static void base64_encode(const char* input, char* output, size_t output_size) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strlen(input);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

int Http_Connect(SOCKET s, uint32_t dest_ip, uint16_t dest_port,
                 const char* username, const char* password) {
    char request[1024];
    char response[4096];
    int len;
    bool use_auth = (username != NULL && username[0] != '\0');

    if (use_auth) {
        char credentials[512];
        char encoded[1024];
        snprintf(credentials, sizeof(credentials), "%s:%s", username, password ? password : "");
        base64_encode(credentials, encoded, sizeof(encoded));

        len = snprintf(request, sizeof(request),
            "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            encoded);
    } else {
        len = snprintf(request, sizeof(request),
            "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d:%d\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);
    }

    if (send(s, request, len, 0) != len) {
        socks5_log("[HTTP] Failed to send CONNECT request");
        return -1;
    }

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0) {
        socks5_log("[HTTP] Failed to receive response (len=%d, err=%d)", len, WSAGetLastError());
        return -1;
    }
    response[len] = '\0';

    // Check for HTTP/1.x response
    if (strncmp(response, "HTTP/1.", 7) != 0) {
        socks5_log("[HTTP] Invalid response format");
        return -1;
    }

    // Parse status code
    int status_code = 0;
    char* code_start = strchr(response, ' ');
    if (code_start != NULL) {
        status_code = atoi(code_start + 1);
    }

    if (status_code != 200) {
        socks5_log("[HTTP] CONNECT failed with status %d", status_code);
        return -1;
    }

    return 0;
}

int Socks5_ConnectIPv6(SOCKET s, const uint8_t* dest_ipv6, uint16_t dest_port,
                       const char* username, const char* password) {
    unsigned char buf[512];
    int len;
    bool use_auth = (username != NULL && username[0] != '\0');

    // Send greeting
    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = SOCKS5_AUTH_USERPASS;
        if (send(s, (char*)buf, 4, 0) != 4) {
            socks5_log("[SOCKS5/IPv6] Failed to send greeting (auth)");
            return -1;
        }
    } else {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3) {
            socks5_log("[SOCKS5/IPv6] Failed to send greeting");
            return -1;
        }
    }

    // Receive method selection
    len = recv(s, (char*)buf, 2, 0);
    if (len != 2) {
        socks5_log("[SOCKS5/IPv6] Failed to receive method selection (len=%d, err=%d)", len, WSAGetLastError());
        return -1;
    }
    if (buf[0] != SOCKS5_VERSION) {
        socks5_log("[SOCKS5/IPv6] Invalid version: 0x%02X", buf[0]);
        return -1;
    }

    // Handle authentication
    if (buf[1] == SOCKS5_AUTH_USERPASS) {
        if (!use_auth) {
            socks5_log("[SOCKS5/IPv6] Server requires auth but no credentials provided");
            return -1;
        }

        size_t user_len = strlen(username);
        size_t pass_len = password ? strlen(password) : 0;
        if (user_len > 255 || pass_len > 255) {
            socks5_log("[SOCKS5/IPv6] Username or password too long");
            return -1;
        }

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        if (pass_len > 0) {
            memcpy(&buf[3 + user_len], password, pass_len);
        }

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len)) {
            socks5_log("[SOCKS5/IPv6] Failed to send credentials");
            return -1;
        }

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00) {
            socks5_log("[SOCKS5/IPv6] Authentication failed");
            return -1;
        }
    } else if (buf[1] == 0xFF) {
        socks5_log("[SOCKS5/IPv6] No acceptable auth method");
        return -1;
    } else if (buf[1] != SOCKS5_AUTH_NONE) {
        socks5_log("[SOCKS5/IPv6] Unsupported auth method: 0x%02X", buf[1]);
        return -1;
    }

    // Send CONNECT request with IPv6 address
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;  // Reserved
    buf[3] = SOCKS5_ATYP_IPV6;
    memcpy(&buf[4], dest_ipv6, 16);  // 16 bytes IPv6 address
    buf[20] = (dest_port >> 8) & 0xFF;
    buf[21] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 22, 0) != 22) {
        socks5_log("[SOCKS5/IPv6] Failed to send CONNECT request");
        return -1;
    }

    // Receive reply (IPv6 reply is longer: 4 + 16 + 2 = 22 bytes)
    len = recv(s, (char*)buf, 22, 0);
    if (len < 4) {
        socks5_log("[SOCKS5/IPv6] Failed to receive CONNECT reply (len=%d, err=%d)", len, WSAGetLastError());
        return -1;
    }
    if (buf[0] != SOCKS5_VERSION) {
        socks5_log("[SOCKS5/IPv6] Invalid reply version: 0x%02X", buf[0]);
        return -1;
    }
    if (buf[1] != 0x00) {
        const char* err_msg = "Unknown error";
        switch (buf[1]) {
            case 0x01: err_msg = "General failure"; break;
            case 0x02: err_msg = "Connection not allowed"; break;
            case 0x03: err_msg = "Network unreachable"; break;
            case 0x04: err_msg = "Host unreachable"; break;
            case 0x05: err_msg = "Connection refused"; break;
            case 0x06: err_msg = "TTL expired"; break;
            case 0x07: err_msg = "Command not supported"; break;
            case 0x08: err_msg = "Address type not supported"; break;
        }
        socks5_log("[SOCKS5/IPv6] CONNECT failed: %s (0x%02X)", err_msg, buf[1]);
        return -1;
    }

    return 0;
}
