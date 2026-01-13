#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QDebug>
#include <QFileInfo>
#include <QCoreApplication>
#include <QDir>
#include <tlhelp32.h>
#include <cstdio>

// Debug log function for process monitor
static void MonitorLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%smonitor_debug.log", tempPath);
        FILE* f = nullptr;
        fopen_s(&f, logPath, "a");
        if (f) {
            fprintf(f, "[Monitor] %s\n", buffer);
            fclose(f);
        }
    }
}

ProcessMonitor::ProcessMonitor(QObject* parent)
    : QObject(parent)
    , m_thread(nullptr)
    , m_running(false)
    , m_proxyIp(0)
    , m_proxyPort(0)
    , m_authRequired(false)
{
}

ProcessMonitor::~ProcessMonitor()
{
    stopMonitoring();
}

void ProcessMonitor::startMonitoring()
{
    MonitorLog("startMonitoring called");

    if (m_running) {
        MonitorLog("Already running, returning");
        return;
    }

    if (m_dllPath.isEmpty()) {
        MonitorLog("DLL path not set");
        emit error("DLL path not set");
        return;
    }

    if (m_targetProcesses.isEmpty()) {
        MonitorLog("No target processes configured");
        emit error("No target processes configured");
        return;
    }

    MonitorLog("Starting monitoring thread with %d targets", m_targetProcesses.size());
    m_running = true;
    m_thread = QThread::create([this]() { onMonitorThread(); });
    m_thread->start();
    emit monitoringStarted();
}

void ProcessMonitor::stopMonitoring()
{
    if (!m_running) {
        return;
    }

    m_running = false;
    if (m_thread) {
        m_thread->quit();
        m_thread->wait(3000);
        delete m_thread;
        m_thread = nullptr;
    }
    m_injectedProcesses.clear();
    emit monitoringStopped();
}

void ProcessMonitor::addTargetProcess(const QString& exeName)
{
    m_targetProcesses.insert(exeName.toLower());
}

void ProcessMonitor::removeTargetProcess(const QString& exeName)
{
    m_targetProcesses.remove(exeName.toLower());
}

void ProcessMonitor::clearTargetProcesses()
{
    m_targetProcesses.clear();
}

void ProcessMonitor::setDllPath(const QString& path)
{
    m_dllPath = path;
}

void ProcessMonitor::setProxyConfig(uint32_t ip, uint16_t port, bool authRequired,
                                   const QString& username, const QString& password)
{
    m_proxyIp = ip;
    m_proxyPort = port;
    m_authRequired = authRequired;
    m_username = username;
    m_password = password;
}

void ProcessMonitor::onMonitorThread()
{
    MonitorLog("Monitoring thread started");
    MonitorLog("Target processes count: %d", m_targetProcesses.size());
    for (const QString& target : m_targetProcesses) {
        MonitorLog("  Target: %s", target.toStdString().c_str());
    }

    while (m_running) {
        // Take a snapshot of all processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            MonitorLog("CreateToolhelp32Snapshot failed");
            Sleep(500);
            continue;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                QString exeName = QString::fromWCharArray(pe32.szExeFile).toLower();
                DWORD pid = pe32.th32ProcessID;

                // Check if this is a target process and not already injected
                if (m_targetProcesses.contains(exeName) &&
                    !m_injectedProcesses.contains(pid)) {

                    MonitorLog("Detected target: %s (PID %d)", exeName.toStdString().c_str(), pid);
                    emit processDetected(exeName, pid);

                    // Try to inject
                    if (injectIntoProcess(pid)) {
                        m_injectedProcesses.insert(pid);
                        emit injectionResult(exeName, pid, true, "Injection successful");
                    } else {
                        emit injectionResult(exeName, pid, false, "Injection failed");
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32) && m_running);
        }

        CloseHandle(hSnapshot);

        // Clean up terminated processes from injected set
        QSet<DWORD> toRemove;
        for (DWORD pid : m_injectedProcesses) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                DWORD exitCode;
                if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    toRemove.insert(pid);
                }
                CloseHandle(hProcess);
            } else {
                toRemove.insert(pid);
            }
        }
        m_injectedProcesses.subtract(toRemove);

        // Poll every 500ms
        Sleep(500);
    }

    qDebug() << "ProcessMonitor: Monitoring thread stopped";
}

bool ProcessMonitor::createProxySharedMemory(DWORD processId)
{
    // Create shared memory for proxy config
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    HANDLE hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        SHARED_MEM_SIZE,
        sharedMemName
    );

    if (!hMapFile) {
        qDebug() << "ProcessMonitor: Failed to create shared memory for PID" << processId;
        return false;
    }

    ProxyConfig* pConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE)
    );

    if (!pConfig) {
        CloseHandle(hMapFile);
        qDebug() << "ProcessMonitor: Failed to map shared memory";
        return false;
    }

    // Fill in config
    memset(pConfig, 0, sizeof(ProxyConfig));
    pConfig->magic = ProxyConfig::MAGIC;
    pConfig->version = ProxyConfig::VERSION;
    pConfig->proxyIp = m_proxyIp;
    pConfig->proxyPort = m_proxyPort;
    pConfig->authRequired = m_authRequired ? 1 : 0;

    if (m_authRequired) {
        strncpy_s(pConfig->username, m_username.toStdString().c_str(), sizeof(pConfig->username) - 1);
        strncpy_s(pConfig->password, m_password.toStdString().c_str(), sizeof(pConfig->password) - 1);
    }

    UnmapViewOfFile(pConfig);
    // Note: We intentionally don't close hMapFile here - it needs to stay open
    // until the target process reads the config

    qDebug() << "ProcessMonitor: Created shared memory for PID" << processId;
    return true;
}

bool ProcessMonitor::injectIntoProcess(DWORD processId)
{
    MonitorLog("injectIntoProcess called for PID %d", processId);

    // First create the shared memory with proxy config
    if (!createProxySharedMemory(processId)) {
        MonitorLog("Failed to create shared memory for PID %d", processId);
        return false;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processId
    );

    if (!hProcess) {
        MonitorLog("Failed to open process %d, error: %d", processId, GetLastError());
        return false;
    }

    // Get DLL path as wide string
    std::wstring dllPathW = m_dllPath.toStdWString();
    SIZE_T pathSize = (dllPathW.length() + 1) * sizeof(wchar_t);

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        qDebug() << "ProcessMonitor: VirtualAllocEx failed";
        CloseHandle(hProcess);
        return false;
    }

    // Write DLL path to target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPathW.c_str(), pathSize, &bytesWritten)) {
        qDebug() << "ProcessMonitor: WriteProcessMemory failed";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!loadLibraryAddr) {
        qDebug() << "ProcessMonitor: GetProcAddress failed";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        qDebug() << "ProcessMonitor: CreateRemoteThread failed, error:" << GetLastError();
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to complete
    WaitForSingleObject(hThread, 5000);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    qDebug() << "ProcessMonitor: Successfully injected into PID" << processId;
    return true;
}
