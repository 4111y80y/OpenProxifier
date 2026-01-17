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
#define PROCESS_CACHE_SIZE 256
#define PROCESS_CACHE_TTL 5000  // 5 seconds TTL
#define CONNECTION_CACHE_SIZE 512
#define CONNECTION_CACHE_TTL 30000  // 30 seconds TTL for connections
#define DECISION_CACHE_SIZE 1024
#define DECISION_CACHE_TTL 60000  // 60 seconds TTL for decisions

// Decision cache values
#define DECISION_UNKNOWN 0
#define DECISION_DIRECT 1
#define DECISION_PROXY 2
#define DECISION_BLOCK 3

// Process name cache entry
typedef struct {
    DWORD pid;
    char name[256];
    DWORD timestamp;
    bool valid;
} ProcessCacheEntry;

// Connection-PID cache entry (to avoid expensive GetExtendedTcpTable calls)
typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t protocol;  // 6=TCP, 17=UDP
    DWORD pid;
    DWORD timestamp;
    bool valid;
} ConnectionCacheEntry;

// Decision cache entry (to skip PID lookup for known connections)
typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint8_t protocol;
    uint8_t decision;  // DECISION_DIRECT, DECISION_PROXY, DECISION_BLOCK
    DWORD timestamp;
    bool valid;
} DecisionCacheEntry;

static ProcessCacheEntry g_process_cache[PROCESS_CACHE_SIZE];
static ConnectionCacheEntry g_connection_cache[CONNECTION_CACHE_SIZE];
static DecisionCacheEntry g_decision_cache[DECISION_CACHE_SIZE];
static CRITICAL_SECTION g_cache_lock;
static bool g_cache_initialized = false;

static HANDLE g_windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE g_packet_thread = NULL;
static volatile bool g_running = false;
static DWORD g_current_process_id = 0;
static uint16_t g_active_tcp_port = LOCAL_TCP_PORT_BASE;
static uint16_t g_active_udp_port = LOCAL_UDP_PORT_BASE;

// External references
extern char g_proxy_host[256];
extern uint16_t g_proxy_port;
extern int g_proxy_type;
extern bool g_dns_via_proxy;
extern LogCallback g_log_callback;
extern ConnectionCallback g_connection_callback;

// Get/Set active ports (used by ProxyEngine)
uint16_t PacketProcessor_GetActiveTcpPort(void) { return g_active_tcp_port; }
uint16_t PacketProcessor_GetActiveUdpPort(void) { return g_active_udp_port; }
void PacketProcessor_SetActivePorts(uint16_t tcp_port, uint16_t udp_port) {
    g_active_tcp_port = tcp_port;
    g_active_udp_port = udp_port;
}

static void log_message(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

// Process cache functions
static void ProcessCache_Init(void) {
    if (g_cache_initialized) return;
    InitializeCriticalSection(&g_cache_lock);
    memset(g_process_cache, 0, sizeof(g_process_cache));
    memset(g_connection_cache, 0, sizeof(g_connection_cache));
    memset(g_decision_cache, 0, sizeof(g_decision_cache));
    g_cache_initialized = true;
}

static void ProcessCache_Cleanup(void) {
    if (!g_cache_initialized) return;
    DeleteCriticalSection(&g_cache_lock);
    g_cache_initialized = false;
}

static bool ProcessCache_Get(DWORD pid, char* name, DWORD name_size) {
    if (!g_cache_initialized || pid == 0) return false;

    DWORD now = GetTickCount();
    bool found = false;

    EnterCriticalSection(&g_cache_lock);

    int hash = pid % PROCESS_CACHE_SIZE;
    for (int i = 0; i < PROCESS_CACHE_SIZE; i++) {
        int idx = (hash + i) % PROCESS_CACHE_SIZE;
        if (g_process_cache[idx].valid && g_process_cache[idx].pid == pid) {
            // Check TTL
            if (now - g_process_cache[idx].timestamp < PROCESS_CACHE_TTL) {
                strncpy(name, g_process_cache[idx].name, name_size - 1);
                name[name_size - 1] = '\0';
                found = true;
            } else {
                // Expired
                g_process_cache[idx].valid = false;
            }
            break;
        }
    }

    LeaveCriticalSection(&g_cache_lock);
    return found;
}

static void ProcessCache_Set(DWORD pid, const char* name) {
    if (!g_cache_initialized || pid == 0) return;

    EnterCriticalSection(&g_cache_lock);

    int hash = pid % PROCESS_CACHE_SIZE;
    int empty_slot = -1;

    for (int i = 0; i < PROCESS_CACHE_SIZE; i++) {
        int idx = (hash + i) % PROCESS_CACHE_SIZE;
        if (g_process_cache[idx].valid && g_process_cache[idx].pid == pid) {
            // Update existing
            strncpy(g_process_cache[idx].name, name, sizeof(g_process_cache[idx].name) - 1);
            g_process_cache[idx].timestamp = GetTickCount();
            LeaveCriticalSection(&g_cache_lock);
            return;
        }
        if (!g_process_cache[idx].valid && empty_slot < 0) {
            empty_slot = idx;
        }
    }

    // Insert new
    if (empty_slot >= 0) {
        g_process_cache[empty_slot].pid = pid;
        strncpy(g_process_cache[empty_slot].name, name, sizeof(g_process_cache[empty_slot].name) - 1);
        g_process_cache[empty_slot].timestamp = GetTickCount();
        g_process_cache[empty_slot].valid = true;
    }

    LeaveCriticalSection(&g_cache_lock);
}

// Connection cache functions (to avoid expensive GetExtendedTcpTable/UdpTable calls)
static DWORD ConnectionCache_Get(uint32_t src_ip, uint16_t src_port, uint8_t protocol) {
    if (!g_cache_initialized) return 0;

    DWORD now = GetTickCount();
    DWORD pid = 0;

    EnterCriticalSection(&g_cache_lock);

    uint32_t hash = (src_ip ^ (src_port << 16) ^ protocol) % CONNECTION_CACHE_SIZE;
    for (int i = 0; i < 8; i++) {  // Linear probing with limited search
        int idx = (hash + i) % CONNECTION_CACHE_SIZE;
        if (g_connection_cache[idx].valid &&
            g_connection_cache[idx].src_ip == src_ip &&
            g_connection_cache[idx].src_port == src_port &&
            g_connection_cache[idx].protocol == protocol) {
            // Check TTL
            if (now - g_connection_cache[idx].timestamp < CONNECTION_CACHE_TTL) {
                pid = g_connection_cache[idx].pid;
            } else {
                // Expired
                g_connection_cache[idx].valid = false;
            }
            break;
        }
    }

    LeaveCriticalSection(&g_cache_lock);
    return pid;
}

static void ConnectionCache_Set(uint32_t src_ip, uint16_t src_port, uint8_t protocol, DWORD pid) {
    if (!g_cache_initialized || pid == 0) return;

    EnterCriticalSection(&g_cache_lock);

    uint32_t hash = (src_ip ^ (src_port << 16) ^ protocol) % CONNECTION_CACHE_SIZE;
    int empty_slot = -1;

    for (int i = 0; i < 8; i++) {
        int idx = (hash + i) % CONNECTION_CACHE_SIZE;
        if (g_connection_cache[idx].valid &&
            g_connection_cache[idx].src_ip == src_ip &&
            g_connection_cache[idx].src_port == src_port &&
            g_connection_cache[idx].protocol == protocol) {
            // Update existing
            g_connection_cache[idx].pid = pid;
            g_connection_cache[idx].timestamp = GetTickCount();
            LeaveCriticalSection(&g_cache_lock);
            return;
        }
        if (!g_connection_cache[idx].valid && empty_slot < 0) {
            empty_slot = idx;
        }
    }

    // Insert new
    if (empty_slot >= 0) {
        g_connection_cache[empty_slot].src_ip = src_ip;
        g_connection_cache[empty_slot].src_port = src_port;
        g_connection_cache[empty_slot].protocol = protocol;
        g_connection_cache[empty_slot].pid = pid;
        g_connection_cache[empty_slot].timestamp = GetTickCount();
        g_connection_cache[empty_slot].valid = true;
    }

    LeaveCriticalSection(&g_cache_lock);
}

// Decision cache functions (to skip expensive processing for known connections)
static uint8_t DecisionCache_Get(uint32_t src_ip, uint16_t src_port,
                                  uint32_t dest_ip, uint16_t dest_port, uint8_t protocol) {
    if (!g_cache_initialized) return DECISION_UNKNOWN;

    DWORD now = GetTickCount();
    uint8_t decision = DECISION_UNKNOWN;

    EnterCriticalSection(&g_cache_lock);

    uint32_t hash = (src_ip ^ src_port ^ dest_ip ^ dest_port ^ protocol) % DECISION_CACHE_SIZE;
    for (int i = 0; i < 8; i++) {
        int idx = (hash + i) % DECISION_CACHE_SIZE;
        if (g_decision_cache[idx].valid &&
            g_decision_cache[idx].src_ip == src_ip &&
            g_decision_cache[idx].src_port == src_port &&
            g_decision_cache[idx].dest_ip == dest_ip &&
            g_decision_cache[idx].dest_port == dest_port &&
            g_decision_cache[idx].protocol == protocol) {
            if (now - g_decision_cache[idx].timestamp < DECISION_CACHE_TTL) {
                decision = g_decision_cache[idx].decision;
            } else {
                g_decision_cache[idx].valid = false;
            }
            break;
        }
    }

    LeaveCriticalSection(&g_cache_lock);
    return decision;
}

static void DecisionCache_Set(uint32_t src_ip, uint16_t src_port,
                               uint32_t dest_ip, uint16_t dest_port,
                               uint8_t protocol, uint8_t decision) {
    if (!g_cache_initialized) return;

    EnterCriticalSection(&g_cache_lock);

    uint32_t hash = (src_ip ^ src_port ^ dest_ip ^ dest_port ^ protocol) % DECISION_CACHE_SIZE;
    int empty_slot = -1;

    for (int i = 0; i < 8; i++) {
        int idx = (hash + i) % DECISION_CACHE_SIZE;
        if (g_decision_cache[idx].valid &&
            g_decision_cache[idx].src_ip == src_ip &&
            g_decision_cache[idx].src_port == src_port &&
            g_decision_cache[idx].dest_ip == dest_ip &&
            g_decision_cache[idx].dest_port == dest_port &&
            g_decision_cache[idx].protocol == protocol) {
            g_decision_cache[idx].decision = decision;
            g_decision_cache[idx].timestamp = GetTickCount();
            LeaveCriticalSection(&g_cache_lock);
            return;
        }
        if (!g_decision_cache[idx].valid && empty_slot < 0) {
            empty_slot = idx;
        }
    }

    if (empty_slot >= 0) {
        g_decision_cache[empty_slot].src_ip = src_ip;
        g_decision_cache[empty_slot].src_port = src_port;
        g_decision_cache[empty_slot].dest_ip = dest_ip;
        g_decision_cache[empty_slot].dest_port = dest_port;
        g_decision_cache[empty_slot].protocol = protocol;
        g_decision_cache[empty_slot].decision = decision;
        g_decision_cache[empty_slot].timestamp = GetTickCount();
        g_decision_cache[empty_slot].valid = true;
    }

    LeaveCriticalSection(&g_cache_lock);
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

    // Retry mechanism for newly started processes
    // TCP table may not be immediately updated when a new process starts
    for (int retry = 0; retry < 3 && pid == 0; retry++) {
        if (retry > 0) {
            Sleep(1);  // Brief delay before retry
        }

        size = 0;
        if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }

        tcp_table = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
        if (tcp_table == NULL) {
            continue;
        }

        if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            free(tcp_table);
            tcp_table = NULL;
            continue;
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
        tcp_table = NULL;
    }

    return pid;
}

DWORD PacketProcessor_GetProcessFromUdp(uint32_t src_ip, uint16_t src_port) {
    MIB_UDPTABLE_OWNER_PID* udp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    // Retry mechanism for newly started processes
    for (int retry = 0; retry < 3 && pid == 0; retry++) {
        if (retry > 0) {
            Sleep(1);  // Brief delay before retry
        }

        size = 0;
        if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                                UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }

        udp_table = (MIB_UDPTABLE_OWNER_PID*)malloc(size);
        if (udp_table == NULL) {
            continue;
        }

        if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET,
                                UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            free(udp_table);
            udp_table = NULL;
            continue;
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
        udp_table = NULL;
    }

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

        // Handle LocalProxy response packets (outbound from local proxy port)
        // These need NAT: change source from LocalProxy to original destination
        if (addr.Outbound && !is_ipv6 && is_tcp && ip_header != NULL && tcp_header != NULL) {
            if (ntohs(tcp_header->SrcPort) == g_active_tcp_port) {
                // This is a response from LocalProxy, need to NAT it back
                uint16_t client_port = ntohs(tcp_header->DstPort);
                uint32_t orig_src_ip;
                uint32_t orig_dest_ip;
                uint16_t orig_dest_port;

                if (ConnectionTracker_GetFull(client_port, &orig_src_ip, &orig_dest_ip, &orig_dest_port)) {
                    // Change source to original destination (spoof response)
                    // Change dest to original client IP
                    ip_header->SrcAddr = orig_dest_ip;
                    ip_header->DstAddr = orig_src_ip;
                    tcp_header->SrcPort = htons(orig_dest_port);

                    WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
                    WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
            }
        }

        // Skip other inbound packets (shouldn't happen with current filter)
        if (!addr.Outbound) {
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        // Extract connection info
        uint16_t src_port = 0, dest_port = 0;
        uint32_t src_ip = 0, dest_ip = 0;

        if (is_tcp) {
            src_port = ntohs(tcp_header->SrcPort);
            dest_port = ntohs(tcp_header->DstPort);
        } else if (is_udp) {
            src_port = ntohs(udp_header->SrcPort);
            dest_port = ntohs(udp_header->DstPort);
        }

        if (!is_ipv6 && ip_header != NULL) {
            src_ip = ip_header->SrcAddr;
            dest_ip = ip_header->DstAddr;

            // ULTRA FAST PATH: Skip broadcast/multicast immediately
            if (PacketProcessor_IsBroadcastOrMulticast(dest_ip)) {
                WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            uint8_t protocol = is_tcp ? 6 : 17;

            // FAST PATH: Check decision cache to skip expensive processing
            uint8_t cached_decision = DecisionCache_Get(src_ip, src_port, dest_ip, dest_port, protocol);
            if (cached_decision == DECISION_DIRECT) {
                WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            // SLOW PATH: Need full processing
            DWORD pid = ConnectionCache_Get(src_ip, src_port, protocol);
            if (pid == 0) {
                if (is_tcp) {
                    pid = PacketProcessor_GetProcessFromTcp(src_ip, src_port);
                } else {
                    pid = PacketProcessor_GetProcessFromUdp(src_ip, src_port);
                }
                if (pid != 0) {
                    ConnectionCache_Set(src_ip, src_port, protocol, pid);
                }
            }

            // Self-exclusion
            if (pid == g_current_process_id) {
                WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            char process_name[256] = "";
            if (!ProcessCache_Get(pid, process_name, sizeof(process_name))) {
                PacketProcessor_GetProcessName(pid, process_name, sizeof(process_name));
                if (process_name[0] != '\0') {
                    ProcessCache_Set(pid, process_name);
                }
            }

            // Determine action
            RuleAction action = RULE_ACTION_DIRECT;
            if (dest_port == 53 && !g_dns_via_proxy) {
                action = RULE_ACTION_DIRECT;
            } else {
                action = RuleEngine_Match(process_name, dest_ip, dest_port, is_tcp);
            }

            // No proxy configured
            if (action == RULE_ACTION_PROXY && (g_proxy_host[0] == '\0' || g_proxy_port == 0)) {
                action = RULE_ACTION_DIRECT;
            }

            // Cache the decision
            uint8_t decision_val = (action == RULE_ACTION_PROXY) ? DECISION_PROXY :
                                   (action == RULE_ACTION_BLOCK) ? DECISION_BLOCK : DECISION_DIRECT;
            DecisionCache_Set(src_ip, src_port, dest_ip, dest_port, protocol, decision_val);

            // Connection callback (only for non-DIRECT to reduce overhead)
            if (g_connection_callback != NULL && action != RULE_ACTION_DIRECT) {
                char dest_ip_str[32];
                snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                    (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
                    (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF);
                const char* status_str = (action == RULE_ACTION_PROXY) ? "PROXY/TCP" : "BLOCK/TCP";
                if (is_udp) status_str = (action == RULE_ACTION_PROXY) ? "PROXY/UDP" : "BLOCK/UDP";
                g_connection_callback(extract_filename(process_name), pid, dest_ip_str, dest_port, status_str);
            }

            // Apply action
            if (action == RULE_ACTION_BLOCK) {
                continue;
            }

            if (action == RULE_ACTION_PROXY && is_tcp) {
                ConnectionTracker_Add(src_port, src_ip, dest_ip, dest_port);
                ip_header->DstAddr = src_ip;
                tcp_header->DstPort = htons(g_active_tcp_port);
                WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
                WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            if (action == RULE_ACTION_PROXY && is_udp) {
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

            // DIRECT - forward packet
            WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        // IPv6 - just forward (no proxy support)
        WinDivertSend(g_windivert_handle, packet, packet_len, NULL, &addr);
    }

    log_message("[PacketProcessor] Thread stopped");
    return 0;
}

bool PacketProcessor_Init(void) {
    g_current_process_id = GetCurrentProcessId();
    ProcessTracker_Init();
    ProcessCache_Init();
    return true;
}

void PacketProcessor_Cleanup(void) {
    PacketProcessor_Stop();
    ProcessTracker_Cleanup();
    ProcessCache_Cleanup();
}

bool PacketProcessor_Start(void) {
    if (g_running) return true;

    char filter[512];
    // Capture TCP/UDP packets using active ports:
    // - Outbound TCP: all except to local proxy port (for redirection)
    // - Outbound UDP: all except to local relay port
    // - Outbound TCP from local proxy: for NAT response (LocalProxy -> client)
    snprintf(filter, sizeof(filter),
        "(outbound and tcp and tcp.DstPort != %d and tcp.SrcPort != %d) or "
        "(outbound and udp and udp.DstPort != %d) or "
        "(outbound and tcp and tcp.SrcPort == %d)",
        g_active_tcp_port, g_active_tcp_port, g_active_udp_port, g_active_tcp_port);

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
