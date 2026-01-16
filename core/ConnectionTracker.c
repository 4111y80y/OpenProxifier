#include "ConnectionTracker.h"
#include <stdlib.h>
#include <string.h>

static ConnectionInfo* g_connection_list = NULL;
static CRITICAL_SECTION g_lock;
static bool g_initialized = false;

void ConnectionTracker_Init(void) {
    if (g_initialized) return;
    InitializeCriticalSection(&g_lock);
    g_connection_list = NULL;
    g_initialized = true;
}

void ConnectionTracker_Cleanup(void) {
    if (!g_initialized) return;
    ConnectionTracker_Clear();
    DeleteCriticalSection(&g_lock);
    g_initialized = false;
}

void ConnectionTracker_Add(uint16_t src_port, uint32_t src_ip,
                           uint32_t dest_ip, uint16_t dest_port) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_lock);

    ConnectionInfo* conn = g_connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            conn->src_ip = src_ip;
            conn->orig_dest_ip = dest_ip;
            conn->orig_dest_port = dest_port;
            conn->is_ipv6 = false;
            conn->is_tracked = true;
            LeaveCriticalSection(&g_lock);
            return;
        }
        conn = conn->next;
    }

    conn = (ConnectionInfo*)malloc(sizeof(ConnectionInfo));
    if (conn == NULL) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    memset(conn->orig_dest_ipv6, 0, 16);
    conn->orig_dest_port = dest_port;
    conn->is_ipv6 = false;
    conn->is_tracked = true;
    conn->next = g_connection_list;
    g_connection_list = conn;

    LeaveCriticalSection(&g_lock);
}

void ConnectionTracker_AddIPv6(uint16_t src_port, uint32_t src_ip,
                               const uint8_t* dest_ipv6, uint16_t dest_port) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_lock);

    ConnectionInfo* conn = g_connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            conn->src_ip = src_ip;
            conn->orig_dest_ip = 0;
            memcpy(conn->orig_dest_ipv6, dest_ipv6, 16);
            conn->orig_dest_port = dest_port;
            conn->is_ipv6 = true;
            conn->is_tracked = true;
            LeaveCriticalSection(&g_lock);
            return;
        }
        conn = conn->next;
    }

    conn = (ConnectionInfo*)malloc(sizeof(ConnectionInfo));
    if (conn == NULL) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = 0;
    memcpy(conn->orig_dest_ipv6, dest_ipv6, 16);
    conn->orig_dest_port = dest_port;
    conn->is_ipv6 = true;
    conn->is_tracked = true;
    conn->next = g_connection_list;
    g_connection_list = conn;

    LeaveCriticalSection(&g_lock);
}

bool ConnectionTracker_Get(uint16_t src_port, uint32_t* dest_ip, uint16_t* dest_port) {
    if (!g_initialized) return false;

    bool found = false;
    EnterCriticalSection(&g_lock);

    ConnectionInfo* conn = g_connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port && !conn->is_ipv6) {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            found = true;
            break;
        }
        conn = conn->next;
    }

    LeaveCriticalSection(&g_lock);
    return found;
}

bool ConnectionTracker_GetEx(uint16_t src_port, uint32_t* dest_ip,
                             uint8_t* dest_ipv6, uint16_t* dest_port, bool* is_ipv6) {
    if (!g_initialized) return false;

    bool found = false;
    EnterCriticalSection(&g_lock);

    ConnectionInfo* conn = g_connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            *is_ipv6 = conn->is_ipv6;
            if (conn->is_ipv6) {
                memcpy(dest_ipv6, conn->orig_dest_ipv6, 16);
            } else {
                *dest_ip = conn->orig_dest_ip;
            }
            *dest_port = conn->orig_dest_port;
            found = true;
            break;
        }
        conn = conn->next;
    }

    LeaveCriticalSection(&g_lock);
    return found;
}

bool ConnectionTracker_IsTracked(uint16_t src_port) {
    if (!g_initialized) return false;

    bool tracked = false;
    EnterCriticalSection(&g_lock);

    ConnectionInfo* conn = g_connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_tracked) {
            tracked = true;
            break;
        }
        conn = conn->next;
    }

    LeaveCriticalSection(&g_lock);
    return tracked;
}

void ConnectionTracker_Remove(uint16_t src_port) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_lock);

    ConnectionInfo** ptr = &g_connection_list;
    while (*ptr != NULL) {
        if ((*ptr)->src_port == src_port) {
            ConnectionInfo* to_free = *ptr;
            *ptr = (*ptr)->next;
            free(to_free);
            break;
        }
        ptr = &(*ptr)->next;
    }

    LeaveCriticalSection(&g_lock);
}

void ConnectionTracker_Clear(void) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_lock);

    while (g_connection_list != NULL) {
        ConnectionInfo* to_free = g_connection_list;
        g_connection_list = g_connection_list->next;
        free(to_free);
    }

    LeaveCriticalSection(&g_lock);
}
