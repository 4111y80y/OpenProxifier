#include "RuleEngine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static ProxyRule* g_rules_list = NULL;
static uint32_t g_next_rule_id = 1;
static CRITICAL_SECTION g_lock;
static bool g_initialized = false;

void RuleEngine_Init(void) {
    if (g_initialized) return;
    InitializeCriticalSection(&g_lock);
    g_rules_list = NULL;
    g_next_rule_id = 1;
    g_initialized = true;
}

void RuleEngine_Cleanup(void) {
    if (!g_initialized) return;
    RuleEngine_ClearRules();
    DeleteCriticalSection(&g_lock);
    g_initialized = false;
}

uint32_t RuleEngine_AddRule(const char* process, const char* hosts,
                            const char* ports, RuleProtocol proto, RuleAction action) {
    if (!g_initialized || process == NULL || process[0] == '\0')
        return 0;

    ProxyRule* rule = (ProxyRule*)malloc(sizeof(ProxyRule));
    if (rule == NULL) return 0;

    EnterCriticalSection(&g_lock);

    rule->rule_id = g_next_rule_id++;
    strncpy(rule->process_name, process, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';

    if (hosts && hosts[0] != '\0') {
        strncpy(rule->target_hosts, hosts, MAX_TARGET_HOSTS - 1);
        rule->target_hosts[MAX_TARGET_HOSTS - 1] = '\0';
    } else {
        strcpy(rule->target_hosts, "*");
    }

    if (ports && ports[0] != '\0') {
        strncpy(rule->target_ports, ports, MAX_TARGET_PORTS - 1);
        rule->target_ports[MAX_TARGET_PORTS - 1] = '\0';
    } else {
        strcpy(rule->target_ports, "*");
    }

    rule->protocol = proto;
    rule->action = action;
    rule->enabled = true;
    rule->next = g_rules_list;
    g_rules_list = rule;

    uint32_t id = rule->rule_id;
    LeaveCriticalSection(&g_lock);

    return id;
}

bool RuleEngine_RemoveRule(uint32_t rule_id) {
    if (!g_initialized || rule_id == 0) return false;

    EnterCriticalSection(&g_lock);

    ProxyRule** ptr = &g_rules_list;
    while (*ptr != NULL) {
        if ((*ptr)->rule_id == rule_id) {
            ProxyRule* to_free = *ptr;
            *ptr = (*ptr)->next;
            free(to_free);
            LeaveCriticalSection(&g_lock);
            return true;
        }
        ptr = &(*ptr)->next;
    }

    LeaveCriticalSection(&g_lock);
    return false;
}

bool RuleEngine_EnableRule(uint32_t rule_id, bool enable) {
    if (!g_initialized || rule_id == 0) return false;

    EnterCriticalSection(&g_lock);

    ProxyRule* rule = g_rules_list;
    while (rule != NULL) {
        if (rule->rule_id == rule_id) {
            rule->enabled = enable;
            LeaveCriticalSection(&g_lock);
            return true;
        }
        rule = rule->next;
    }

    LeaveCriticalSection(&g_lock);
    return false;
}

void RuleEngine_ClearRules(void) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_lock);

    while (g_rules_list != NULL) {
        ProxyRule* to_free = g_rules_list;
        g_rules_list = g_rules_list->next;
        free(to_free);
    }

    LeaveCriticalSection(&g_lock);
}

// Extract filename from full path
static const char* extract_filename(const char* path) {
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

bool RuleEngine_MatchProcessPattern(const char* pattern, const char* process_full_path) {
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    // Extract just the filename from the full path
    const char* filename = extract_filename(process_full_path);

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);

    // Check if pattern contains path separators
    bool is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);
    const char* match_target = is_full_path_pattern ? process_full_path : filename;
    size_t target_len = is_full_path_pattern ? strlen(process_full_path) : name_len;

    // Check for * at the end: "fire*"
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        return _strnicmp(pattern, match_target, pattern_len - 1) == 0;
    }

    // Check for * at the beginning: "*.exe"
    if (pattern_len > 1 && pattern[0] == '*') {
        const char* pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len) {
            return _stricmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return false;
    }

    // Check for * in the middle: "fire*.exe"
    const char* star = strchr(pattern, '*');
    if (star != NULL) {
        size_t prefix_len = star - pattern;
        const char* suffix = star + 1;
        size_t suffix_len = strlen(suffix);

        if (_strnicmp(pattern, match_target, prefix_len) != 0)
            return false;

        if (target_len < prefix_len + suffix_len)
            return false;

        return _stricmp(match_target + target_len - suffix_len, suffix) == 0;
    }

    // No *, use case insensitive compare
    return _stricmp(pattern, match_target) == 0;
}

bool RuleEngine_MatchIpPattern(const char* pattern, uint32_t ip) {
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    // Extract 4 octets from IP (little-endian)
    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF;
    ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF;
    ip_octets[3] = (ip >> 24) & 0xFF;

    // Parse pattern
    char pattern_copy[256];
    strncpy(pattern_copy, pattern, sizeof(pattern_copy) - 1);
    pattern_copy[sizeof(pattern_copy) - 1] = '\0';

    char pattern_octets[4][16];
    int octet_count = 0;
    int char_idx = 0;

    for (int i = 0; i <= (int)strlen(pattern_copy) && octet_count < 4; i++) {
        if (pattern_copy[i] == '.' || pattern_copy[i] == '\0') {
            pattern_octets[octet_count][char_idx] = '\0';
            octet_count++;
            char_idx = 0;
            if (pattern_copy[i] == '\0') break;
        } else {
            if (char_idx < 15)
                pattern_octets[octet_count][char_idx++] = pattern_copy[i];
        }
    }

    if (octet_count != 4)
        return false;

    for (int i = 0; i < 4; i++) {
        if (strcmp(pattern_octets[i], "*") == 0)
            continue;
        int pattern_val = atoi(pattern_octets[i]);
        if (pattern_val != ip_octets[i])
            return false;
    }
    return true;
}

bool RuleEngine_MatchPortPattern(const char* pattern, uint16_t port) {
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    // Check for range: "8000-9000"
    char* dash = strchr(pattern, '-');
    if (dash != NULL) {
        int start_port = atoi(pattern);
        int end_port = atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == atoi(pattern));
}

// Match against a list (semicolon or comma separated)
static bool match_process_list(const char* process_list, const char* process_name) {
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0)
        return true;

    size_t len = strlen(process_list) + 1;
    char* list_copy = (char*)malloc(len);
    if (list_copy == NULL) return false;

    strncpy(list_copy, process_list, len);
    bool matched = false;

    char* token = strtok(list_copy, ",;");
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;

        // Remove trailing whitespace
        char* end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        if (RuleEngine_MatchProcessPattern(token, process_name)) {
            matched = true;
            break;
        }
        token = strtok(NULL, ",;");
    }

    free(list_copy);
    return matched;
}

static bool match_ip_list(const char* ip_list, uint32_t ip) {
    if (ip_list == NULL || ip_list[0] == '\0' || strcmp(ip_list, "*") == 0)
        return true;

    size_t len = strlen(ip_list) + 1;
    char* list_copy = (char*)malloc(len);
    if (list_copy == NULL) return false;

    strncpy(list_copy, ip_list, len);
    bool matched = false;

    char* token = strtok(list_copy, ";");
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;
        if (RuleEngine_MatchIpPattern(token, ip)) {
            matched = true;
            break;
        }
        token = strtok(NULL, ";");
    }

    free(list_copy);
    return matched;
}

static bool match_port_list(const char* port_list, uint16_t port) {
    if (port_list == NULL || port_list[0] == '\0' || strcmp(port_list, "*") == 0)
        return true;

    size_t len = strlen(port_list) + 1;
    char* list_copy = (char*)malloc(len);
    if (list_copy == NULL) return false;

    strncpy(list_copy, port_list, len);
    bool matched = false;

    char* token = strtok(list_copy, ",;");
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;
        if (RuleEngine_MatchPortPattern(token, port)) {
            matched = true;
            break;
        }
        token = strtok(NULL, ",;");
    }

    free(list_copy);
    return matched;
}

RuleAction RuleEngine_Match(const char* process_name, uint32_t dest_ip,
                            uint16_t dest_port, bool is_tcp) {
    if (!g_initialized) return RULE_ACTION_DIRECT;

    EnterCriticalSection(&g_lock);

    ProxyRule* rule = g_rules_list;
    ProxyRule* wildcard_rule = NULL;

    while (rule != NULL) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }

        // Check protocol compatibility
        if (rule->protocol != RULE_PROTOCOL_BOTH) {
            if (rule->protocol == RULE_PROTOCOL_TCP && !is_tcp) {
                rule = rule->next;
                continue;
            }
            if (rule->protocol == RULE_PROTOCOL_UDP && is_tcp) {
                rule = rule->next;
                continue;
            }
        }

        // Check if this is a wildcard process rule
        bool is_wildcard_process = (strcmp(rule->process_name, "*") == 0);

        if (is_wildcard_process) {
            bool has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            bool has_port_filter = (strcmp(rule->target_ports, "*") != 0);

            if (has_ip_filter || has_port_filter) {
                if (match_ip_list(rule->target_hosts, dest_ip) &&
                    match_port_list(rule->target_ports, dest_port)) {
                    RuleAction action = rule->action;
                    LeaveCriticalSection(&g_lock);
                    return action;
                }
                rule = rule->next;
                continue;
            }

            // Fully wildcard rule - save for later
            if (wildcard_rule == NULL) {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        // Check if process name matches
        if (match_process_list(rule->process_name, process_name)) {
            if (match_ip_list(rule->target_hosts, dest_ip) &&
                match_port_list(rule->target_ports, dest_port)) {
                RuleAction action = rule->action;
                LeaveCriticalSection(&g_lock);
                return action;
            }
        }

        rule = rule->next;
    }

    // No specific rule matched, use wildcard if available
    if (wildcard_rule != NULL) {
        RuleAction action = wildcard_rule->action;
        LeaveCriticalSection(&g_lock);
        return action;
    }

    LeaveCriticalSection(&g_lock);
    return RULE_ACTION_DIRECT;
}
