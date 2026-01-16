#ifndef PROXY_ENGINE_H
#define PROXY_ENGINE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Rule action types
typedef enum {
    RULE_ACTION_PROXY = 0,
    RULE_ACTION_DIRECT = 1,
    RULE_ACTION_BLOCK = 2
} RuleAction;

// Rule protocol types
typedef enum {
    RULE_PROTOCOL_TCP = 0,
    RULE_PROTOCOL_UDP = 1,
    RULE_PROTOCOL_BOTH = 2
} RuleProtocol;

// Proxy types
typedef enum {
    PROXY_TYPE_SOCKS5 = 0,
    PROXY_TYPE_HTTP = 1
} ProxyType;

// Callback function types
typedef void (*LogCallback)(const char* message);
typedef void (*ConnectionCallback)(const char* process, uint32_t pid,
                                   const char* dest_ip, uint16_t dest_port,
                                   const char* status);

// Initialize and cleanup
bool ProxyEngine_Init(void);
void ProxyEngine_Cleanup(void);

// Proxy configuration
bool ProxyEngine_SetProxy(ProxyType type, const char* host, uint16_t port,
                          const char* username, const char* password);
void ProxyEngine_SetDnsViaProxy(bool enable);

// Rule management
uint32_t ProxyEngine_AddRule(const char* process, const char* hosts,
                             const char* ports, RuleProtocol proto, RuleAction action);
bool ProxyEngine_RemoveRule(uint32_t rule_id);
bool ProxyEngine_EnableRule(uint32_t rule_id, bool enable);
void ProxyEngine_ClearRules(void);

// Start/Stop engine
bool ProxyEngine_Start(void);
bool ProxyEngine_Stop(void);
bool ProxyEngine_IsRunning(void);

// Callbacks
void ProxyEngine_SetLogCallback(LogCallback cb);
void ProxyEngine_SetConnectionCallback(ConnectionCallback cb);

// Get current process ID (for self-exclusion)
uint32_t ProxyEngine_GetCurrentPid(void);

#ifdef __cplusplus
}
#endif

#endif // PROXY_ENGINE_H
