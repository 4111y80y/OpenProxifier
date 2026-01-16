#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Connection info structure (supports both IPv4 and IPv6)
typedef struct ConnectionInfo {
    uint16_t src_port;
    uint32_t src_ip;
    uint32_t orig_dest_ip;        // IPv4 destination
    uint8_t orig_dest_ipv6[16];   // IPv6 destination
    uint16_t orig_dest_port;
    bool is_ipv6;
    bool is_tracked;
    struct ConnectionInfo* next;
} ConnectionInfo;

// Initialize and cleanup
void ConnectionTracker_Init(void);
void ConnectionTracker_Cleanup(void);

// Add a connection to track (IPv4)
void ConnectionTracker_Add(uint16_t src_port, uint32_t src_ip,
                           uint32_t dest_ip, uint16_t dest_port);

// Add a connection to track (IPv6)
void ConnectionTracker_AddIPv6(uint16_t src_port, uint32_t src_ip,
                               const uint8_t* dest_ipv6, uint16_t dest_port);

// Get original destination by source port (IPv4)
bool ConnectionTracker_Get(uint16_t src_port, uint32_t* dest_ip, uint16_t* dest_port);

// Get original destination by source port (with IPv6 support)
bool ConnectionTracker_GetEx(uint16_t src_port, uint32_t* dest_ip,
                             uint8_t* dest_ipv6, uint16_t* dest_port, bool* is_ipv6);

// Check if a connection is tracked
bool ConnectionTracker_IsTracked(uint16_t src_port);

// Remove a connection
void ConnectionTracker_Remove(uint16_t src_port);

// Clear all connections
void ConnectionTracker_Clear(void);

#ifdef __cplusplus
}
#endif

#endif // CONNECTION_TRACKER_H
