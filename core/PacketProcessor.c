#include "PacketProcessor.h"
#include "ConnectionTracker.h"
#include "RuleEngine.h"
#include "ProxyEngine.h"
#include "ProcessTracker.h"
#include "UdpRelay.h"
#include "../windivert/include/windivert.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAXBUF 0xFFFF

static HANDLE g_windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE g_packet_thread = NULL;
static volatile bool g_running = false;
static DWORD g_current_process_id = 0;

// External references
extern char g_proxy_host[256];
extern uint16_t g_proxy_port;
extern int g_proxy_type;
extern bool g_dns_via_proxy;
extern LogCallback g_log_callback;
extern ConnectionCallback g_connection_callback;

static void log_message(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

bool PacketProcessor_IsBroadcastOrMulticast(uint32_t ip) {
    // Localhost: 127.0.0.0/8
    BYTE first_octet = (ip >> 0) & 0xFF;
    if (first_octet == 127)
        return true;

    // APIPA: 169.254.0.0/16
    BYTE second_octet = (ip >> 8) & 0xFF;
    if (first_octet == 169 && second_octet == 254)
        return true;

    // Broadcast: 255.255.255.255
    if (ip == 0xFFFFFFFF)
        return true;

    // x.x.x.255
    if ((ip & 0xFF000000) == 0xFF000000)
        return true;

    // Multicast: 224.0.0.0 - 239.255.255.255
    if (first_octet >= 224 && first_octet <= 239)
        return true;

    return false;
}

DWORD PacketProcessor_GetProcessFromTcp(uint32_t src_ip, uint16_t src_port) {
    MIB_TCPTABLE_OWNER_PID* tcp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    tcp_table = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
    if (tcp_table == NULL) {
        return 0;
    }

    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tcp_table);
        return 0;
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID* row = &tcp_table->table[i];
        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port) {
            pid = row->dwOwningPid;
            break;
        }
    }

    free(tcp_table);
    return pid;
}

DWORD PacketProcessor_GetProcessFromUdp(uint32_t src_ip, uint16_t src_port) {
    MIB_UDPTABLE_OWNER_PID* udp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    udp_table = (MIB_UDPTABLE_OWNER_PID*)malloc(size);
    if (udp_table == NULL) {
        return 0;
    }

    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(udp_table);
        return 0;
    }

    // First pass: exact match
    for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID* row = &udp_table->table[i];
        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port) {
            pid = row->dwOwningPid;
            break;
        }
    }

    // Second pass: match on 0.0.0.0
    if (pid == 0) {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID* row = &udp_table->table[i];
            if (row->dwLocalAddr == 0 &&
                ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid;
                break;
            }
        }
    }

    free(udp_table);
    return pid;
}

bool PacketProcessor_GetProcessName(DWORD pid, char* name, DWORD name_size) {
    if (pid == 0) return false;

    // System process
    if (pid == 4) {
        strncpy(name, "System", name_size - 1);
        name[name_size - 1] = '\0';
        return true;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    DWORD path_len = name_size;
    if (QueryFullProcessImageNameA(hProcess, 0, name, &path_len)) {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

// Extract filename from path
static const char* extract_filename(const char* path) {
    if (!path) return "";
    const char* last = strrchr(path, '\\');
    if (!last) last = strrchr(path, '/');
    return last ? (last + 1) : path;
}

static DWORD WINAPI PacketProcessorThread(LPVOID arg) {
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    log_message("[PacketProcessor] Thread started (TCP/UDP, IPv4/IPv6)");

    while (g_running) {
        if (!WinDivertRecv(g_windivert_handle, packet, sizeof(packet), &packet_len, &addr)) {
            if (GetLastError() == ERROR_INVALID_HANDLE)
                break;
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL,
            NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        // Determine if IPv4 or IPv6
        bool is_ipv6 = (ipv6_header != NULL);
        bool is_tcp = (tcp_header != NULL);
        bool is_udp = (udp_header != NULL);

        if (!is_ipv6 && ip_header == NULL) {
            // Not a valid IP packet
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        // Only handle outbound packets for monitoring/proxying
        if (!addr.Outbound) {
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        // Extract connection info
        uint16_t src_port = 0, dest_port = 0;
        uint32_t src_ip = 0, dest_ip = 0;
        char dest_ip_str[64] = "";

        if (is_tcp) {
            src_port = ntohs(tcp_header->SrcPort);
            dest_port = ntohs(tcp_header->DstPort);
        } else if (is_udp) {
            src_port = ntohs(udp_header->SrcPort);
            dest_port = ntohs(udp_header->DstPort);
        }

        if (is_ipv6) {
            // Format IPv6 address (simplified)
            uint8_t* v6 = (uint8_t*)&ipv6_header->DstAddr;
            snprintf(dest_ip_str, sizeof(dest_ip_str),
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7],
                v6[8], v6[9], v6[10], v6[11], v6[12], v6[13], v6[14], v6[15]);
            // Use 0 for IPv6 dest_ip (can't fit in uint32_t)
            dest_ip = 0;
        } else {
            src_ip = ip_header->SrcAddr;
            dest_ip = ip_header->DstAddr;
            snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
                (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF);
        }

        // Get process info
        DWORD pid = 0;
        if (is_tcp) {
            pid = PacketProcessor_GetProcessFromTcp(src_ip, src_port);
        } else if (is_udp) {
            pid = PacketProcessor_GetProcessFromUdp(src_ip, src_port);
        }

        char process_name[256] = "";
        PacketProcessor_GetProcessName(pid, process_name, sizeof(process_name));

        // Self-exclusion
        if (pid == g_current_process_id) {
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        // Determine action
        RuleAction action = RULE_ACTION_DIRECT;

        if (!is_ipv6 && dest_ip != 0) {
            // IPv4: full rule matching
            if (dest_port == 53 && !g_dns_via_proxy)
                action = RULE_ACTION_DIRECT;
            else
                action = RuleEngine_Match(process_name, dest_ip, dest_port, is_tcp);

            // Override for broadcast/multicast
            if (action == RULE_ACTION_PROXY && PacketProcessor_IsBroadcastOrMulticast(dest_ip))
                action = RULE_ACTION_DIRECT;

            // No proxy configured
            if (action == RULE_ACTION_PROXY && (g_proxy_host[0] == '\0' || g_proxy_port == 0))
                action = RULE_ACTION_DIRECT;
        } else {
            // IPv6: only DIRECT or BLOCK (no proxy support yet)
            action = RuleEngine_Match(process_name, 0, dest_port, is_tcp);
            if (action == RULE_ACTION_PROXY) {
                action = RULE_ACTION_DIRECT; // IPv6 proxy not supported
            }
        }

        // Connection callback
        if (g_connection_callback != NULL) {
            char status_str[32];
            const char* proto = is_tcp ? "TCP" : "UDP";
            const char* ip_ver = is_ipv6 ? "v6" : "";

            if (action == RULE_ACTION_PROXY) {
                snprintf(status_str, sizeof(status_str), "PROXY/%s%s", proto, ip_ver);
            } else if (action == RULE_ACTION_BLOCK) {
                snprintf(status_str, sizeof(status_str), "BLOCK/%s%s", proto, ip_ver);
            } else {
                snprintf(status_str, sizeof(status_str), "DIRECT/%s%s", proto, ip_ver);
            }

            const char* display_name = extract_filename(process_name);
            g_connection_callback(display_name, pid, dest_ip_str, dest_port, status_str);
        }

        // Apply action
        if (action == RULE_ACTION_BLOCK) {
            continue;  // Drop packet
        }

        if (action == RULE_ACTION_PROXY && is_tcp && !is_ipv6) {
            // IPv4 TCP proxy - redirect to local proxy
            ConnectionTracker_Add(src_port, src_ip, dest_ip, dest_port);

            uint32_t temp = ip_header->DstAddr;
            tcp_header->DstPort = htons(LOCAL_TCP_PORT);
            ip_header->DstAddr = ip_header->SrcAddr;
            ip_header->SrcAddr = temp;
            addr.Outbound = FALSE;

            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        if (action == RULE_ACTION_PROXY && is_udp && !is_ipv6) {
            // IPv4 UDP proxy - redirect to UDP relay
            uint16_t relay_port = UdpRelay_AddSession(src_ip, src_port, dest_ip, dest_port);
            if (relay_port != 0) {
                uint32_t temp = ip_header->DstAddr;
                udp_header->DstPort = htons(relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp;
                addr.Outbound = FALSE;

                WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
                WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }

        // DIRECT - just forward the packet
        WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
    }

    log_message("[PacketProcessor] Thread stopped");
    return 0;
}

bool PacketProcessor_Init(void) {
    g_current_process_id = GetCurrentProcessId();
    ProcessTracker_Init();
    return true;
}

void PacketProcessor_Cleanup(void) {
    PacketProcessor_Stop();
    ProcessTracker_Cleanup();
}

bool PacketProcessor_Start(void) {
    if (g_running) return true;

    char filter[512];
    // Capture both TCP and UDP, IPv4 and IPv6
    snprintf(filter, sizeof(filter),
        "outbound and (tcp or udp)");

    log_message("[PacketProcessor] Opening WinDivert with filter: %s", filter);

    g_windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 123, 0);
    if (g_windivert_handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_message("[PacketProcessor] WinDivertOpen failed: %lu", err);
        return false;
    }

    WinDivertSetParam(g_windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(g_windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    g_running = true;
    g_packet_thread = CreateThread(NULL, 0, PacketProcessorThread, NULL, 0, NULL);
    if (g_packet_thread == NULL) {
        WinDivertClose(g_windivert_handle);
        g_windivert_handle = INVALID_HANDLE_VALUE;
        g_running = false;
        return false;
    }

    log_message("[PacketProcessor] Started successfully");
    return true;
}

void PacketProcessor_Stop(void) {
    if (!g_running) return;

    g_running = false;

    if (g_windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(g_windivert_handle);
        g_windivert_handle = INVALID_HANDLE_VALUE;
    }

    if (g_packet_thread != NULL) {
        WaitForSingleObject(g_packet_thread, 5000);
        CloseHandle(g_packet_thread);
        g_packet_thread = NULL;
    }

    log_message("[PacketProcessor] Stopped");
}
