#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOCAL_TCP_PORT 34010
#define LOCAL_UDP_PORT 34011

// Initialize and cleanup
bool PacketProcessor_Init(void);
void PacketProcessor_Cleanup(void);

// Start/Stop packet processing
bool PacketProcessor_Start(void);
void PacketProcessor_Stop(void);

// Get process ID from TCP connection
DWORD PacketProcessor_GetProcessFromTcp(uint32_t src_ip, uint16_t src_port);

// Get process ID from UDP connection
DWORD PacketProcessor_GetProcessFromUdp(uint32_t src_ip, uint16_t src_port);

// Get process name from PID
bool PacketProcessor_GetProcessName(DWORD pid, char* name, DWORD name_size);

// Check if IP is broadcast/multicast/localhost
bool PacketProcessor_IsBroadcastOrMulticast(uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif // PACKET_PROCESSOR_H
