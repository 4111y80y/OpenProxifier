#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <windows.h>
#include "../core/ProxyEngine.h"

static volatile bool g_running = true;
static int g_verbose = 0;  // 0=only PROXY/BLOCK, 1=all connections

static void log_callback(const char* message) {
    printf("[LOG] %s\n", message);
    fflush(stdout);
}

static void connection_callback(const char* process, uint32_t pid,
                                const char* dest_ip, uint16_t dest_port,
                                const char* status) {
    // Skip DIRECT connections unless verbose mode
    if (g_verbose == 0 && strncmp(status, "DIRECT", 6) == 0) {
        return;
    }

    printf("[CONN] %s (PID:%u) -> %s:%u [%s]\n",
           process, pid, dest_ip, dest_port, status);
    fflush(stdout);
}

static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\n[INFO] Shutting down...\n");
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

static void print_usage(const char* program) {
    printf("\n");
    printf("  OpenProxifier - WinDivert-based transparent proxy\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s [options]\n", program);
    printf("\n");
    printf("Options:\n");
    printf("  --proxy <type://host:port>  Proxy server (e.g., socks5://127.0.0.1:1080)\n");
    printf("  --rule <rule>               Add routing rule\n");
    printf("  --dns-direct                Route DNS queries directly (not via proxy)\n");
    printf("  --verbose                   Show all connections (including DIRECT)\n");
    printf("  -h, --help                  Show this help\n");
    printf("\n");
    printf("Rule format:\n");
    printf("  process:hosts:ports:protocol:action\n");
    printf("    process  - Process name (e.g., chrome.exe, *.exe, *)\n");
    printf("    hosts    - Target IPs (e.g., *, 192.168.*.*)\n");
    printf("    ports    - Target ports (e.g., *, 80, 80;443, 8000-9000)\n");
    printf("    protocol - TCP, UDP, or BOTH\n");
    printf("    action   - PROXY, DIRECT, or BLOCK\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --proxy socks5://127.0.0.1:1080 --rule \"chrome.exe:*:*:TCP:PROXY\"\n", program);
    printf("  %s --proxy socks5://127.0.0.1:1080 --rule \"*:*:*:TCP:PROXY\"\n", program);
    printf("  %s --rule \"malware.exe:*:*:BOTH:BLOCK\"\n", program);
    printf("\n");
}

static int parse_proxy(const char* proxy_str, ProxyType* type, char* host, uint16_t* port,
                       char* username, char* password) {
    // Format: type://user:pass@host:port or type://host:port
    char buffer[512] = "";
    username[0] = '\0';
    password[0] = '\0';

    if (strncmp(proxy_str, "socks5://", 9) == 0) {
        *type = PROXY_TYPE_SOCKS5;
        strncpy(buffer, proxy_str + 9, sizeof(buffer) - 1);
    } else if (strncmp(proxy_str, "http://", 7) == 0) {
        *type = PROXY_TYPE_HTTP;
        strncpy(buffer, proxy_str + 7, sizeof(buffer) - 1);
    } else {
        // Default to SOCKS5
        *type = PROXY_TYPE_SOCKS5;
        strncpy(buffer, proxy_str, sizeof(buffer) - 1);
    }

    // Check for user:pass@host:port format
    char* at_sign = strchr(buffer, '@');
    char* host_part = buffer;

    if (at_sign != NULL) {
        *at_sign = '\0';
        host_part = at_sign + 1;

        // Parse user:pass
        char* colon = strchr(buffer, ':');
        if (colon != NULL) {
            *colon = '\0';
            strncpy(username, buffer, 63);
            strncpy(password, colon + 1, 63);
        } else {
            strncpy(username, buffer, 63);
        }
    }

    // Parse host:port
    char* colon = strrchr(host_part, ':');
    if (colon == NULL) {
        return -1;
    }

    *colon = '\0';
    strncpy(host, host_part, 255);
    *port = (uint16_t)atoi(colon + 1);

    if (*port == 0) {
        return -1;
    }

    return 0;
}

static int parse_rule(const char* rule_str) {
    // Format: process:hosts:ports:protocol:action
    char rule_copy[1024];
    strncpy(rule_copy, rule_str, sizeof(rule_copy) - 1);
    rule_copy[sizeof(rule_copy) - 1] = '\0';

    char* process = strtok(rule_copy, ":");
    char* hosts = strtok(NULL, ":");
    char* ports = strtok(NULL, ":");
    char* protocol_str = strtok(NULL, ":");
    char* action_str = strtok(NULL, ":");

    if (!process || !hosts || !ports || !protocol_str || !action_str) {
        printf("[ERROR] Invalid rule format: %s\n", rule_str);
        return -1;
    }

    RuleProtocol protocol;
    if (_stricmp(protocol_str, "TCP") == 0) {
        protocol = RULE_PROTOCOL_TCP;
    } else if (_stricmp(protocol_str, "UDP") == 0) {
        protocol = RULE_PROTOCOL_UDP;
    } else if (_stricmp(protocol_str, "BOTH") == 0) {
        protocol = RULE_PROTOCOL_BOTH;
    } else {
        printf("[ERROR] Invalid protocol: %s\n", protocol_str);
        return -1;
    }

    RuleAction action;
    if (_stricmp(action_str, "PROXY") == 0) {
        action = RULE_ACTION_PROXY;
    } else if (_stricmp(action_str, "DIRECT") == 0) {
        action = RULE_ACTION_DIRECT;
    } else if (_stricmp(action_str, "BLOCK") == 0) {
        action = RULE_ACTION_BLOCK;
    } else {
        printf("[ERROR] Invalid action: %s\n", action_str);
        return -1;
    }

    uint32_t rule_id = ProxyEngine_AddRule(process, hosts, ports, protocol, action);
    if (rule_id == 0) {
        printf("[ERROR] Failed to add rule\n");
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    // Check for help flag first (before admin check)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Check admin privileges
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    if (!is_admin) {
        printf("[ERROR] This program requires administrator privileges.\n");
        printf("[ERROR] Please run as Administrator.\n");
        return 1;
    }

    // Parse arguments
    ProxyType proxy_type = PROXY_TYPE_SOCKS5;
    char proxy_host[256] = "";
    uint16_t proxy_port = 0;
    char proxy_username[64] = "";
    char proxy_password[64] = "";
    bool dns_via_proxy = true;
    int rule_count = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc) {
            if (parse_proxy(argv[++i], &proxy_type, proxy_host, &proxy_port,
                           proxy_username, proxy_password) != 0) {
                printf("[ERROR] Invalid proxy format: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--dns-direct") == 0) {
            dns_via_proxy = false;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        }
    }

    printf("\n");
    printf("  OpenProxifier - WinDivert Edition\n");
    printf("  ================================\n");
    printf("\n");

    // Initialize engine
    ProxyEngine_SetLogCallback(log_callback);
    ProxyEngine_SetConnectionCallback(connection_callback);

    if (!ProxyEngine_Init()) {
        printf("[ERROR] Failed to initialize ProxyEngine\n");
        return 1;
    }

    // Set proxy
    if (proxy_host[0] != '\0' && proxy_port > 0) {
        const char* user = proxy_username[0] != '\0' ? proxy_username : NULL;
        const char* pass = proxy_password[0] != '\0' ? proxy_password : NULL;
        if (!ProxyEngine_SetProxy(proxy_type, proxy_host, proxy_port, user, pass)) {
            printf("[ERROR] Failed to set proxy\n");
            ProxyEngine_Cleanup();
            return 1;
        }
        if (user) {
            printf("[INFO] Using proxy authentication: %s\n", user);
        }
    }

    ProxyEngine_SetDnsViaProxy(dns_via_proxy);

    // Parse and add rules (second pass)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rule") == 0 && i + 1 < argc) {
            if (parse_rule(argv[++i]) == 0) {
                rule_count++;
            }
        }
    }

    if (rule_count == 0) {
        printf("[WARNING] No rules configured - all traffic will be DIRECT\n");
    }

    // Start engine
    if (!ProxyEngine_Start()) {
        printf("[ERROR] Failed to start ProxyEngine\n");
        ProxyEngine_Cleanup();
        return 1;
    }

    printf("\n");
    printf("[INFO] ProxyEngine running. Press Ctrl+C to stop.\n");
    if (g_verbose == 0) {
        printf("[INFO] Showing PROXY/BLOCK connections only. Use --verbose for all.\n");
    }
    printf("\n");

    // Set console handler
    SetConsoleCtrlHandler(console_handler, TRUE);

    // Main loop
    while (g_running) {
        Sleep(100);
    }

    // Cleanup
    ProxyEngine_Stop();
    ProxyEngine_Cleanup();

    printf("[INFO] Shutdown complete.\n");
    return 0;
}
