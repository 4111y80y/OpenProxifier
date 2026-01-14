#include "SocketMapper.h"
#include <cstdio>

// Debug log helper
static void MapperDebugLog(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA("[SocketMapper] ");
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%shookdll_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "[SocketMapper] %s\n", buffer);
            fclose(f);
        }
    }
}

namespace MiniProxifier {

void SocketMapper::addMapping(SOCKET originalSocket, SOCKET replacementSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_socketMap[originalSocket] = replacementSocket;
    MapperDebugLog("Added mapping: %llu -> %llu", (unsigned long long)originalSocket, (unsigned long long)replacementSocket);
}

void SocketMapper::removeMapping(SOCKET originalSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_socketMap.find(originalSocket);
    if (it != m_socketMap.end()) {
        MapperDebugLog("Removed mapping: %llu", (unsigned long long)originalSocket);
        m_socketMap.erase(it);
    }
}

SOCKET SocketMapper::getReplacementSocket(SOCKET originalSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_socketMap.find(originalSocket);
    if (it != m_socketMap.end()) {
        return it->second;
    }
    return originalSocket;  // Return original if no mapping
}

bool SocketMapper::hasMapping(SOCKET originalSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_socketMap.find(originalSocket) != m_socketMap.end();
}

void SocketMapper::closeAndRemove(SOCKET originalSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_socketMap.find(originalSocket);
    if (it != m_socketMap.end()) {
        SOCKET replacementSocket = it->second;
        MapperDebugLog("Closing replacement socket %llu for original %llu",
            (unsigned long long)replacementSocket, (unsigned long long)originalSocket);
        closesocket(replacementSocket);
        m_socketMap.erase(it);
    }
}

} // namespace MiniProxifier
