#ifndef SOCKET_MAPPER_H
#define SOCKET_MAPPER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <map>
#include <mutex>

namespace MiniProxifier {

// Manages mapping between original IPv6 sockets and replacement IPv4 sockets
// This allows IPv6 connections to go through IPv4-only SOCKS5 proxies
class SocketMapper {
public:
    static SocketMapper& getInstance() {
        static SocketMapper instance;
        return instance;
    }

    // Add a mapping: original IPv6 socket -> replacement IPv4 socket
    void addMapping(SOCKET originalSocket, SOCKET replacementSocket);

    // Remove a mapping (when socket is closed)
    void removeMapping(SOCKET originalSocket);

    // Get the replacement socket for an original socket
    // Returns the original socket if no mapping exists
    SOCKET getReplacementSocket(SOCKET originalSocket);

    // Check if a socket has a mapping
    bool hasMapping(SOCKET originalSocket);

    // Close and remove a mapped socket
    void closeAndRemove(SOCKET originalSocket);

private:
    SocketMapper() = default;
    ~SocketMapper() = default;
    SocketMapper(const SocketMapper&) = delete;
    SocketMapper& operator=(const SocketMapper&) = delete;

    std::map<SOCKET, SOCKET> m_socketMap;
    std::mutex m_mutex;
};

} // namespace MiniProxifier

#endif // SOCKET_MAPPER_H
