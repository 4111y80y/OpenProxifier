#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

// Initialize process tracker
bool ProcessTracker_Init(void);

// Cleanup process tracker
void ProcessTracker_Cleanup(void);

// Add a PID to tracked list (this process matched a PROXY rule)
void ProcessTracker_AddPid(DWORD pid);

// Remove a PID from tracked list
void ProcessTracker_RemovePid(DWORD pid);

// Check if a PID is directly tracked
bool ProcessTracker_IsPidTracked(DWORD pid);

// Check if a PID's parent is tracked (for child process inheritance)
bool ProcessTracker_IsChildOfTracked(DWORD pid);

// Get parent PID of a process
DWORD ProcessTracker_GetParentPid(DWORD pid);

#endif // PROCESS_TRACKER_H
