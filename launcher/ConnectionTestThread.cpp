// -*- coding: utf-8 -*-
#include "ConnectionTestThread.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>

ConnectionTestThread::ConnectionTestThread(const QString& host, int port, bool authRequired,
                                           const QString& username, const QString& password, bool isChinese)
    : m_host(host), m_port(port), m_authRequired(authRequired),
      m_username(username), m_password(password), m_isChinese(isChinese)
{
}

void ConnectionTestThread::run()
{
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Convert host to IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, m_host.toStdString().c_str(), &addr) != 1) {
        QString msg = m_isChinese ? QStringLiteral("[错误] 无效的IP地址") : "[ERROR] Invalid IP address";
        QString statusText = m_isChinese ? QStringLiteral("无效的IP地址") : "Invalid IP address";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        QString msg = m_isChinese ? QStringLiteral("[错误] 创建套接字失败") : "[ERROR] Failed to create socket";
        QString statusText = m_isChinese ? QStringLiteral("套接字错误") : "Socket error";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    // Set socket to non-blocking mode for connect timeout
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    // Connect to proxy server
    sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = addr.s_addr;
    proxyAddr.sin_port = htons(static_cast<uint16_t>(m_port));

    int result = ::connect(sock, reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr));

    // For non-blocking socket, connect returns SOCKET_ERROR with WSAEWOULDBLOCK
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK) {
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 无法连接 %1:%2").arg(m_host).arg(m_port) :
                QString("[ERROR] Cannot connect to %1:%2").arg(m_host).arg(m_port);
            QString statusText = m_isChinese ? QStringLiteral("连接失败") : "Connection failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Wait for connection with 10 second timeout
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        result = select(0, NULL, &writefds, NULL, &timeout);
        if (result == 0) {
            // Timeout
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 连接超时 %1:%2 (10秒)").arg(m_host).arg(m_port) :
                QString("[ERROR] Connection timeout to %1:%2 (10 seconds)").arg(m_host).arg(m_port);
            QString statusText = m_isChinese ? QStringLiteral("连接超时") : "Connection timeout";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        } else if (result == SOCKET_ERROR) {
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 无法连接 %1:%2").arg(m_host).arg(m_port) :
                QString("[ERROR] Cannot connect to %1:%2").arg(m_host).arg(m_port);
            QString statusText = m_isChinese ? QStringLiteral("连接失败") : "Connection failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Check if connection succeeded
        int optval;
        int optlen = sizeof(optval);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
        if (optval != 0) {
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 无法连接 %1:%2").arg(m_host).arg(m_port) :
                QString("[ERROR] Cannot connect to %1:%2").arg(m_host).arg(m_port);
            QString statusText = m_isChinese ? QStringLiteral("连接失败") : "Connection failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }
    }

    // Set socket back to blocking mode
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    // Set timeout for send/recv operations (10 seconds)
    DWORD ioTimeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ioTimeout, sizeof(ioTimeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ioTimeout, sizeof(ioTimeout));

    // SOCKS5 handshake
    uint8_t greeting[4];
    int greetingLen;
    if (m_authRequired) {
        greeting[0] = 0x05;  // VER
        greeting[1] = 0x02;  // NMETHODS
        greeting[2] = 0x00;  // METHOD: no auth
        greeting[3] = 0x02;  // METHOD: username/password
        greetingLen = 4;
    } else {
        greeting[0] = 0x05;  // VER
        greeting[1] = 0x01;  // NMETHODS
        greeting[2] = 0x00;  // METHOD: no auth
        greetingLen = 3;
    }

    int sent = send(sock, reinterpret_cast<char*>(greeting), greetingLen, 0);
    if (sent != greetingLen) {
        closesocket(sock);
        QString msg = m_isChinese ? QStringLiteral("[错误] SOCKS5 握手发送失败") : "[ERROR] SOCKS5 handshake send failed";
        QString statusText = m_isChinese ? QStringLiteral("握手失败") : "Handshake failed";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    // Receive handshake response
    uint8_t response[2];
    int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);

    if (received != 2 || response[0] != 0x05) {
        closesocket(sock);
        QString msg = m_isChinese ? QStringLiteral("[错误] 服务器不是有效的SOCKS5代理") : "[ERROR] Server is not a valid SOCKS5 proxy";
        QString statusText = m_isChinese ? QStringLiteral("非SOCKS5服务器") : "Not a SOCKS5 server";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    // Check server's chosen auth method
    if (response[1] == 0xFF) {
        closesocket(sock);
        QString msg = m_isChinese ? QStringLiteral("[错误] 服务器拒绝了所有认证方式") : "[ERROR] Server rejected all authentication methods";
        QString statusText = m_isChinese ? QStringLiteral("无可用认证方式") : "No acceptable auth";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    // If server requires username/password auth (0x02)
    if (response[1] == 0x02) {
        if (!m_authRequired || m_username.isEmpty()) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 服务器需要认证但未提供") : "[ERROR] Server requires authentication but none provided";
            QString statusText = m_isChinese ? QStringLiteral("服务器需要认证") : "Auth required by server";
            emit testCompleted(false, msg, statusText, "orange");
            WSACleanup();
            return;
        }

        // RFC 1929 Username/Password Authentication
        std::string user = m_username.toStdString();
        std::string pass = m_password.toStdString();

        if (user.length() > 255 || pass.length() > 255) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 用户名或密码过长") : "[ERROR] Credentials too long";
            QString statusText = m_isChinese ? QStringLiteral("凭证过长") : "Credentials too long";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Build auth request: VER(0x01) ULEN USERNAME PLEN PASSWORD
        std::vector<uint8_t> authReq;
        authReq.push_back(0x01);  // VER
        authReq.push_back(static_cast<uint8_t>(user.length()));
        authReq.insert(authReq.end(), user.begin(), user.end());
        authReq.push_back(static_cast<uint8_t>(pass.length()));
        authReq.insert(authReq.end(), pass.begin(), pass.end());

        sent = send(sock, reinterpret_cast<char*>(authReq.data()), static_cast<int>(authReq.size()), 0);
        if (sent != static_cast<int>(authReq.size())) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 认证请求发送失败") : "[ERROR] Auth send failed";
            QString statusText = m_isChinese ? QStringLiteral("认证发送失败") : "Auth send failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Receive auth response: VER(0x01) STATUS
        uint8_t authResponse[2];
        received = recv(sock, reinterpret_cast<char*>(authResponse), 2, 0);
        if (received != 2 || authResponse[0] != 0x01) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 认证响应格式错误") : "[ERROR] Auth response error";
            QString statusText = m_isChinese ? QStringLiteral("认证响应错误") : "Auth response error";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        if (authResponse[1] != 0x00) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 认证失败 - 用户名或密码错误") : "[ERROR] Authentication failed - wrong username or password";
            QString statusText = m_isChinese ? QStringLiteral("认证失败 (密码错误)") : "Auth failed (wrong password)";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }
    } else if (response[1] != 0x00) {
        closesocket(sock);
        QString msg = m_isChinese ?
            QStringLiteral("[错误] 不支持的认证方式: 0x%1").arg(response[1], 2, 16, QChar('0')) :
            QString("[ERROR] Unsupported auth method: 0x%1").arg(response[1], 2, 16, QChar('0'));
        QString statusText = m_isChinese ? QStringLiteral("不支持的认证方式") : "Unsupported auth method";
        emit testCompleted(false, msg, statusText, "red");
        WSACleanup();
        return;
    }

    closesocket(sock);
    WSACleanup();

    // Success!
    QString msg = m_isChinese ?
        QStringLiteral("[成功] SOCKS5 服务器 %1:%2 可达%3").arg(m_host).arg(m_port).arg(m_authRequired ? QStringLiteral(" (已认证)") : "") :
        QString("[SUCCESS] SOCKS5 server %1:%2 is reachable%3").arg(m_host).arg(m_port).arg(m_authRequired ? " (authenticated)" : "");
    QString statusText = m_authRequired ?
        (m_isChinese ? QStringLiteral("已连接 (认证成功)") : "Connected (auth OK)") :
        (m_isChinese ? QStringLiteral("已连接") : "Connected");
    emit testCompleted(true, msg, statusText, "green; font-weight: bold");
}
