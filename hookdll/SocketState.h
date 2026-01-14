#ifndef SOCKET_STATE_H
#define SOCKET_STATE_H

#include <winsock2.h>
#include <unordered_map>
#include <mutex>

namespace MiniProxifier {

// Tracks socket state for proper handling of non-blocking sockets
class SocketStateManager {
public:
    enum class State {
        Initial,           // Initial state
        Connecting,        // Connecting to proxy
        Handshaking,       // SOCKS5 handshake in progress
        Connected,         // Connected through proxy
        Failed             // Connection failed
    };

    struct SocketInfo {
        State state;
        bool isNonBlocking;
        sockaddr_in originalTarget;

        SocketInfo() : state(State::Initial), isNonBlocking(false) {
            memset(&originalTarget, 0, sizeof(originalTarget));
        }
    };

    // Check if a socket is in non-blocking mode
    static bool IsNonBlocking(SOCKET sock) {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_sockets.find(sock);
        if (it != s_sockets.end()) {
            return it->second.isNonBlocking;
        }
        // Default: assume blocking
        return false;
    }

    // Mark a socket as non-blocking
    static void SetNonBlocking(SOCKET sock, bool nonBlocking) {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_sockets[sock].isNonBlocking = nonBlocking;
    }

    // Get socket info
    static SocketInfo* Get(SOCKET sock) {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_sockets.find(sock);
        if (it != s_sockets.end()) {
            return &it->second;
        }
        return nullptr;
    }

    // Remove socket tracking
    static void Remove(SOCKET sock) {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_sockets.erase(sock);
    }

    // Register a new socket
    static void Register(SOCKET sock) {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_sockets[sock] = SocketInfo();
    }

private:
    static std::unordered_map<SOCKET, SocketInfo> s_sockets;
    static std::mutex s_mutex;
};

// Static member definitions
inline std::unordered_map<SOCKET, SocketStateManager::SocketInfo> SocketStateManager::s_sockets;
inline std::mutex SocketStateManager::s_mutex;

} // namespace MiniProxifier

#endif // SOCKET_STATE_H

