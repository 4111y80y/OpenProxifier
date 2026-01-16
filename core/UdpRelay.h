#ifndef UDP_RELAY_H
#define UDP_RELAY_H

#include <stdint.h>
#include <stdbool.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize UDP relay system
bool UdpRelay_Init(void);

// Cleanup UDP relay system
void UdpRelay_Cleanup(void);

// Start UDP relay on specified port
bool UdpRelay_Start(uint16_t local_port);

// Stop UDP relay
void UdpRelay_Stop(void);

// Add a UDP session for proxying
// Returns the local relay port to redirect packets to
uint16_t UdpRelay_AddSession(uint32_t client_ip, uint16_t client_port,
                              uint32_t dest_ip, uint16_t dest_port);

// Add IPv6 UDP session
uint16_t UdpRelay_AddSessionIPv6(uint32_t client_ip, uint16_t client_port,
                                  const uint8_t* dest_ipv6, uint16_t dest_port);

#ifdef __cplusplus
}
#endif

#endif // UDP_RELAY_H
