#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOCAL_TCP_PORT_BASE 34020
#define LOCAL_UDP_PORT_BASE 34021
#define LOCAL_PORT_RANGE 10  // Try up to 10 different ports

// Get current active ports (may differ from base if port was busy)
uint16_t PacketProcessor_GetActiveTcpPort(void);
uint16_t PacketProcessor_GetActiveUdpPort(void);
void PacketProcessor_SetActivePorts(uint16_t tcp_port, uint16_t udp_port);

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
