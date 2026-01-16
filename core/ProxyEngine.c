#include "ProxyEngine.h"
#include "PacketProcessor.h"
#include "LocalProxy.h"
#include "ConnectionTracker.h"
#include "RuleEngine.h"
#include "UdpRelay.h"
#include <stdio.h>
#include <string.h>

// Global configuration
char g_proxy_host[256] = "";
uint16_t g_proxy_port = 0;
int g_proxy_type = PROXY_TYPE_SOCKS5;
char g_proxy_username[64] = "";
char g_proxy_password[64] = "";
bool g_dns_via_proxy = true;

// Callbacks
LogCallback g_log_callback = NULL;
ConnectionCallback g_connection_callback = NULL;

static bool g_initialized = false;
static bool g_running = false;
static DWORD g_current_pid = 0;

static void log_message(const char* fmt, ...) {
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    g_log_callback(buffer);
}

bool ProxyEngine_Init(void) {
    if (g_initialized) return true;

    g_current_pid = GetCurrentProcessId();

    ConnectionTracker_Init();
    RuleEngine_Init();
    UdpRelay_Init();

    if (!LocalProxy_Init()) {
        return false;
    }

    if (!PacketProcessor_Init()) {
        LocalProxy_Cleanup();
        return false;
    }

    g_initialized = true;
    log_message("[ProxyEngine] Initialized (PID: %lu)", g_current_pid);
    return true;
}

void ProxyEngine_Cleanup(void) {
    if (!g_initialized) return;

    ProxyEngine_Stop();

    PacketProcessor_Cleanup();
    LocalProxy_Cleanup();
    RuleEngine_Cleanup();
    UdpRelay_Cleanup();
    ConnectionTracker_Cleanup();

    g_initialized = false;
    log_message("[ProxyEngine] Cleanup complete");
}

bool ProxyEngine_SetProxy(ProxyType type, const char* host, uint16_t port,
                          const char* username, const char* password) {
    if (host == NULL || host[0] == '\0' || port == 0) {
        return false;
    }

    strncpy(g_proxy_host, host, sizeof(g_proxy_host) - 1);
    g_proxy_host[sizeof(g_proxy_host) - 1] = '\0';

    g_proxy_port = port;
    g_proxy_type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;

    if (username != NULL && username[0] != '\0') {
        strncpy(g_proxy_username, username, sizeof(g_proxy_username) - 1);
        g_proxy_username[sizeof(g_proxy_username) - 1] = '\0';
    } else {
        g_proxy_username[0] = '\0';
    }

    if (password != NULL && password[0] != '\0') {
        strncpy(g_proxy_password, password, sizeof(g_proxy_password) - 1);
        g_proxy_password[sizeof(g_proxy_password) - 1] = '\0';
    } else {
        g_proxy_password[0] = '\0';
    }

    log_message("[ProxyEngine] Proxy set: %s://%s:%d",
        (g_proxy_type == PROXY_TYPE_HTTP) ? "HTTP" : "SOCKS5",
        g_proxy_host, g_proxy_port);

    return true;
}

void ProxyEngine_SetDnsViaProxy(bool enable) {
    g_dns_via_proxy = enable;
    log_message("[ProxyEngine] DNS via proxy: %s", enable ? "enabled" : "disabled");
}

uint32_t ProxyEngine_AddRule(const char* process, const char* hosts,
                             const char* ports, RuleProtocol proto, RuleAction action) {
    uint32_t rule_id = RuleEngine_AddRule(process, hosts, ports, proto, action);
    if (rule_id > 0) {
        const char* action_str = (action == RULE_ACTION_PROXY) ? "PROXY" :
                                (action == RULE_ACTION_BLOCK) ? "BLOCK" : "DIRECT";
        log_message("[ProxyEngine] Rule added: %s -> %s (ID: %u)", process, action_str, rule_id);
    }
    return rule_id;
}

bool ProxyEngine_RemoveRule(uint32_t rule_id) {
    bool result = RuleEngine_RemoveRule(rule_id);
    if (result) {
        log_message("[ProxyEngine] Rule removed: ID %u", rule_id);
    }
    return result;
}

bool ProxyEngine_EnableRule(uint32_t rule_id, bool enable) {
    bool result = RuleEngine_EnableRule(rule_id, enable);
    if (result) {
        log_message("[ProxyEngine] Rule %u %s", rule_id, enable ? "enabled" : "disabled");
    }
    return result;
}

void ProxyEngine_ClearRules(void) {
    RuleEngine_ClearRules();
    log_message("[ProxyEngine] All rules cleared");
}

bool ProxyEngine_Start(void) {
    if (!g_initialized) {
        if (!ProxyEngine_Init()) {
            return false;
        }
    }

    if (g_running) return true;

    // Start local proxy server
    if (!UdpRelay_Start(LOCAL_UDP_PORT)) {
        log_message("[ProxyEngine] Failed to start UDP relay");
        return false;
    }

    if (!LocalProxy_Start(LOCAL_TCP_PORT)) {
        log_message("[ProxyEngine] Failed to start local proxy");
        return false;
    }

    // Give proxy server time to start
    Sleep(100);

    // Start packet processor
    if (!PacketProcessor_Start()) {
        log_message("[ProxyEngine] Failed to start packet processor");
        LocalProxy_Stop();
    UdpRelay_Stop();
        return false;
    }

    g_running = true;
    log_message("[ProxyEngine] Started successfully");
    log_message("[ProxyEngine] Local relay: 127.0.0.1:%d", LOCAL_TCP_PORT);

    if (g_proxy_host[0] != '\0' && g_proxy_port > 0) {
        log_message("[ProxyEngine] Proxy: %s://%s:%d",
            (g_proxy_type == PROXY_TYPE_HTTP) ? "HTTP" : "SOCKS5",
            g_proxy_host, g_proxy_port);
    } else {
        log_message("[ProxyEngine] Warning: No proxy configured");
    }

    return true;
}

bool ProxyEngine_Stop(void) {
    if (!g_running) return true;

    PacketProcessor_Stop();
    LocalProxy_Stop();
    UdpRelay_Stop();
    ConnectionTracker_Clear();

    g_running = false;
    log_message("[ProxyEngine] Stopped");

    return true;
}

bool ProxyEngine_IsRunning(void) {
    return g_running;
}

void ProxyEngine_SetLogCallback(LogCallback cb) {
    g_log_callback = cb;
}

void ProxyEngine_SetConnectionCallback(ConnectionCallback cb) {
    g_connection_callback = cb;
}

uint32_t ProxyEngine_GetCurrentPid(void) {
    return g_current_pid;
}
