#include "ProcessTracker.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TRACKED_PIDS 1024

typedef struct {
    DWORD pid;
    bool active;
} TrackedProcess;

static TrackedProcess g_tracked_pids[MAX_TRACKED_PIDS];
static CRITICAL_SECTION g_tracker_lock;
static bool g_initialized = false;

bool ProcessTracker_Init(void) {
    if (g_initialized) return true;

    InitializeCriticalSection(&g_tracker_lock);
    memset(g_tracked_pids, 0, sizeof(g_tracked_pids));
    g_initialized = true;
    return true;
}

void ProcessTracker_Cleanup(void) {
    if (!g_initialized) return;

    DeleteCriticalSection(&g_tracker_lock);
    g_initialized = false;
}

void ProcessTracker_AddPid(DWORD pid) {
    if (!g_initialized || pid == 0) return;

    EnterCriticalSection(&g_tracker_lock);

    // Check if already tracked
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_tracked_pids[i].active && g_tracked_pids[i].pid == pid) {
            LeaveCriticalSection(&g_tracker_lock);
            return;
        }
    }

    // Find empty slot
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (!g_tracked_pids[i].active) {
            g_tracked_pids[i].pid = pid;
            g_tracked_pids[i].active = true;
            break;
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
}

void ProcessTracker_RemovePid(DWORD pid) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_tracker_lock);

    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_tracked_pids[i].active && g_tracked_pids[i].pid == pid) {
            g_tracked_pids[i].active = false;
            g_tracked_pids[i].pid = 0;
            break;
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
}

bool ProcessTracker_IsPidTracked(DWORD pid) {
    if (!g_initialized || pid == 0) return false;

    bool found = false;
    EnterCriticalSection(&g_tracker_lock);

    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_tracked_pids[i].active && g_tracked_pids[i].pid == pid) {
            found = true;
            break;
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
    return found;
}

DWORD ProcessTracker_GetParentPid(DWORD pid) {
    DWORD parent_pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                parent_pid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return parent_pid;
}

bool ProcessTracker_IsChildOfTracked(DWORD pid) {
    if (!g_initialized || pid == 0) return false;

    // Walk up the process tree (max 10 levels to avoid infinite loops)
    DWORD current_pid = pid;
    for (int depth = 0; depth < 10; depth++) {
        DWORD parent_pid = ProcessTracker_GetParentPid(current_pid);

        if (parent_pid == 0 || parent_pid == current_pid) {
            break;
        }

        if (ProcessTracker_IsPidTracked(parent_pid)) {
            // Parent is tracked, so this child should also be tracked
            ProcessTracker_AddPid(pid);
            return true;
        }

        current_pid = parent_pid;
    }

    return false;
}
