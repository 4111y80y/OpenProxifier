#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QDebug>
#include <QFileInfo>
#include <QCoreApplication>
#include <QDir>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

// Enable debug privilege for process injection
static bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD error = GetLastError();
    CloseHandle(hToken);

    return result && (error == ERROR_SUCCESS);
}

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

// WMI Event Sink class for receiving process creation events
class ProcessEventSink : public IWbemObjectSink
{
    LONG m_lRef;
    ProcessMonitor* m_pMonitor;

public:
    ProcessEventSink(ProcessMonitor* pMonitor) : m_lRef(0), m_pMonitor(pMonitor) {}
    ~ProcessEventSink() {}

    virtual ULONG STDMETHODCALLTYPE AddRef() {
        return InterlockedIncrement(&m_lRef);
    }

    virtual ULONG STDMETHODCALLTYPE Release() {
        LONG lRef = InterlockedDecrement(&m_lRef);
        if (lRef == 0) delete this;
        return lRef;
    }

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = (IWbemObjectSink*)this;
            AddRef();
            return WBEM_S_NO_ERROR;
        }
        return E_NOINTERFACE;
    }

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray)
    {
        for (LONG i = 0; i < lObjectCount; i++) {
            IWbemClassObject* pObj = apObjArray[i];

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Get process name
            QString processName;
            if (SUCCEEDED(pObj->Get(L"ProcessName", 0, &vtProp, 0, 0))) {
                if (vtProp.vt == VT_BSTR) {
                    processName = QString::fromWCharArray(vtProp.bstrVal);
                }
                VariantClear(&vtProp);
            }

            // Get process ID
            DWORD processId = 0;
            if (SUCCEEDED(pObj->Get(L"ProcessID", 0, &vtProp, 0, 0))) {
                if (vtProp.vt == VT_I4 || vtProp.vt == VT_UI4) {
                    processId = vtProp.ulVal;
                }
                VariantClear(&vtProp);
            }

            MonitorLog("WMI Event: Process %s (PID %d) created",
                      processName.toStdString().c_str(), processId);

            if (!processName.isEmpty() && processId != 0 && m_pMonitor) {
                m_pMonitor->onProcessCreated(processName, processId);
            }
        }
        return WBEM_S_NO_ERROR;
    }

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam)
    {
        return WBEM_S_NO_ERROR;
    }
};

ProcessMonitor::ProcessMonitor(QObject* parent)
    : QObject(parent)
    , m_thread(nullptr)
    , m_running(false)
    , m_proxyIp(0)
    , m_proxyPort(0)
    , m_authRequired(false)
    , m_pLocator(nullptr)
    , m_pServices(nullptr)
    , m_pUnsecApp(nullptr)
    , m_pSink(nullptr)
    , m_pStubUnk(nullptr)
    , m_pStubSink(nullptr)
    , m_wmiInitialized(false)
{
}

ProcessMonitor::~ProcessMonitor()
{
    stopMonitoring();
}

bool ProcessMonitor::initWMI()
{
    if (m_wmiInitialized) return true;

    HRESULT hr;

    // Initialize COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        MonitorLog("CoInitializeEx failed: 0x%08X", hr);
        return false;
    }

    // Set security levels
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        MonitorLog("CoInitializeSecurity failed: 0x%08X", hr);
        return false;
    }

    // Create WMI locator
    hr = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&m_pLocator);

    if (FAILED(hr)) {
        MonitorLog("CoCreateInstance WbemLocator failed: 0x%08X", hr);
        return false;
    }

    // Connect to WMI
    hr = m_pLocator->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &m_pServices);

    if (FAILED(hr)) {
        MonitorLog("ConnectServer failed: 0x%08X", hr);
        m_pLocator->Release();
        m_pLocator = nullptr;
        return false;
    }

    // Set security on proxy
    hr = CoSetProxyBlanket(
        m_pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (FAILED(hr)) {
        MonitorLog("CoSetProxyBlanket failed: 0x%08X", hr);
        m_pServices->Release();
        m_pLocator->Release();
        m_pServices = nullptr;
        m_pLocator = nullptr;
        return false;
    }

    // Create unsecured apartment for async calls
    hr = CoCreateInstance(
        CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER,
        IID_IUnsecuredApartment, (void**)&m_pUnsecApp);

    if (FAILED(hr)) {
        MonitorLog("CoCreateInstance UnsecuredApartment failed: 0x%08X", hr);
        m_pServices->Release();
        m_pLocator->Release();
        m_pServices = nullptr;
        m_pLocator = nullptr;
        return false;
    }

    m_wmiInitialized = true;
    MonitorLog("WMI initialized successfully");
    return true;
}

void ProcessMonitor::cleanupWMI()
{
    MonitorLog("cleanupWMI: starting");
    if (m_pStubSink) {
        MonitorLog("cleanupWMI: canceling async call");
        m_pServices->CancelAsyncCall(m_pStubSink);
        MonitorLog("cleanupWMI: releasing m_pStubSink");
        m_pStubSink->Release();
        m_pStubSink = nullptr;
    }
    if (m_pStubUnk) {
        MonitorLog("cleanupWMI: releasing m_pStubUnk");
        m_pStubUnk->Release();
        m_pStubUnk = nullptr;
    }
    if (m_pSink) {
        MonitorLog("cleanupWMI: releasing m_pSink");
        m_pSink->Release();
        m_pSink = nullptr;
    }
    if (m_pUnsecApp) {
        MonitorLog("cleanupWMI: releasing m_pUnsecApp");
        m_pUnsecApp->Release();
        m_pUnsecApp = nullptr;
    }
    if (m_pServices) {
        MonitorLog("cleanupWMI: releasing m_pServices");
        m_pServices->Release();
        m_pServices = nullptr;
    }
    if (m_pLocator) {
        MonitorLog("cleanupWMI: releasing m_pLocator");
        m_pLocator->Release();
        m_pLocator = nullptr;
    }
    m_wmiInitialized = false;
    MonitorLog("cleanupWMI: done");
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

    // Enable debug privilege for process injection
    if (EnableDebugPrivilege()) {
        MonitorLog("Debug privilege enabled successfully");
    } else {
        MonitorLog("Warning: Failed to enable debug privilege, injection may fail for some processes");
    }

    // First, inject into any already-running target processes
    injectIntoExistingProcesses();

    // Try WMI first
    if (initWMI()) {
        MonitorLog("Using WMI event-based monitoring");

        // Create event sink
        m_pSink = new ProcessEventSink(this);
        m_pSink->AddRef();

        // Create stub sink for async
        HRESULT hr = m_pUnsecApp->CreateObjectStub(m_pSink, &m_pStubUnk);
        if (SUCCEEDED(hr)) {
            hr = m_pStubUnk->QueryInterface(IID_IWbemObjectSink, (void**)&m_pStubSink);
        }

        if (SUCCEEDED(hr)) {
            // Subscribe to process creation events
            hr = m_pServices->ExecNotificationQueryAsync(
                _bstr_t("WQL"),
                _bstr_t("SELECT * FROM Win32_ProcessStartTrace"),
                WBEM_FLAG_SEND_STATUS, NULL, m_pStubSink);

            if (SUCCEEDED(hr)) {
                MonitorLog("WMI event subscription successful");
                m_running = true;
                emit monitoringStarted();
                return;
            } else {
                MonitorLog("ExecNotificationQueryAsync failed: 0x%08X", hr);
                if (hr == WBEM_E_ACCESS_DENIED) {
                    emit error("WMI access denied. Run as Administrator for real-time detection.");
                }
            }
        }

        // WMI subscription failed, cleanup and fall back to polling
        cleanupWMI();
    }

    // Fall back to polling if WMI fails
    MonitorLog("Falling back to polling-based monitoring");
    MonitorLog("Starting monitoring thread with %d targets", m_targetProcesses.size());
    MonitorLog("Note: Polling may miss fast programs. Run as Admin for WMI real-time detection.");

    m_running = true;
    m_thread = QThread::create([this]() { onMonitorThread(); });
    m_thread->start();
    emit monitoringStarted();
}

void ProcessMonitor::stopMonitoring()
{
    MonitorLog("stopMonitoring called");

    if (!m_running) {
        MonitorLog("stopMonitoring: not running, returning");
        return;
    }

    m_running = false;
    MonitorLog("stopMonitoring: set m_running = false");

    // Disable proxy for all injected processes
    MonitorLog("stopMonitoring: disabling proxy for all injected processes");
    disableAllInjectedProcesses();

    // Cleanup WMI
    MonitorLog("stopMonitoring: calling cleanupWMI");
    cleanupWMI();
    MonitorLog("stopMonitoring: cleanupWMI done");

    // Stop polling thread if running
    if (m_thread) {
        MonitorLog("stopMonitoring: stopping polling thread");
        m_thread->quit();
        m_thread->wait(3000);
        delete m_thread;
        m_thread = nullptr;
        MonitorLog("stopMonitoring: polling thread stopped");
    }

    m_injectedProcesses.clear();
    MonitorLog("stopMonitoring: emitting monitoringStopped");
    emit monitoringStopped();
}

void ProcessMonitor::addTargetProcess(const QString& exeName, bool injectNow)
{
    QString lowerName = exeName.toLower();
    m_targetProcesses.insert(lowerName);

    // If monitoring is active and injectNow is true, inject into running instances
    if (injectNow && m_running) {
        injectIntoRunningProcess(exeName);
    }
}

void ProcessMonitor::injectIntoRunningProcess(const QString& exeName)
{
    QString targetName = exeName.toLower();
    MonitorLog("Scanning for running instances of: %s", targetName.toStdString().c_str());

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MonitorLog("Failed to create process snapshot");
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            QString processName = QString::fromWCharArray(pe32.szExeFile).toLower();
            DWORD pid = pe32.th32ProcessID;

            if (processName != targetName) {
                continue;
            }

            if (m_injectedProcesses.contains(pid)) {
                MonitorLog("Process %s (PID %lu) already injected, skipping",
                          processName.toStdString().c_str(), pid);
                continue;
            }

            if (pid == 0 || pid == 4) {
                continue;
            }

            MonitorLog("Found running instance: %s (PID %lu)", processName.toStdString().c_str(), pid);
            emit processDetected(exeName, pid);

            if (createProxySharedMemory(pid)) {
                QString error = injectIntoProcess(pid);
                if (error.isEmpty()) {
                    m_injectedProcesses.insert(pid);
                    emit injectionResult(exeName, pid, true, "");
                    MonitorLog("Successfully injected into %s (PID %lu)", processName.toStdString().c_str(), pid);
                } else {
                    emit injectionResult(exeName, pid, false, error);
                }
            } else {
                emit injectionResult(exeName, pid, false, "Failed to create shared memory");
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
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

void ProcessMonitor::onProcessCreated(const QString& exeName, DWORD processId)
{
    QString lowerName = exeName.toLower();

    // Check if this is a target process
    if (!m_targetProcesses.contains(lowerName)) {
        return;
    }

    // Check if already injected
    if (m_injectedProcesses.contains(processId)) {
        return;
    }

    MonitorLog("Target process detected: %s (PID %d)", exeName.toStdString().c_str(), processId);
    emit processDetected(exeName, processId);

    // Retry injection with delays for processes that may not be fully initialized
    const int maxRetries = 5;
    const int retryDelayMs = 150;
    QString error;

    // Initial delay to let process initialize
    Sleep(100);

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        // Additional delay for retries
        if (attempt > 1) {
            Sleep(retryDelayMs);
            MonitorLog("Retry attempt %d for PID %d", attempt, processId);
        }

        // Check if process still exists
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (!hCheck) {
            MonitorLog("Process %d no longer exists, skipping", processId);
            return;
        }
        CloseHandle(hCheck);

        // Try to suspend for injection
        bool suspended = suspendProcess(processId);
        if (suspended) {
            MonitorLog("Process suspended");
        }

        error = injectIntoProcess(processId);

        if (suspended) {
            resumeProcess(processId);
            MonitorLog("Process resumed");
        }

        if (error.isEmpty()) {
            m_injectedProcesses.insert(processId);
            emit injectionResult(exeName, processId, true, "Injection successful");
            return;
        }

        // If error is not retryable, break immediately
        if (error.contains("32-bit") || error.contains("64-bit")) {
            break;  // Architecture mismatch, don't retry
        }

        // Check if it's ACCESS_DENIED - worth retrying
        if (!error.contains("error 5")) {
            // Other errors may not be worth retrying
            MonitorLog("Non-retryable error: %s", error.toStdString().c_str());
            break;
        }
    }

    // All retries failed - but check if DLL was already injected by parent process hook
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        // Check if our DLL is already loaded
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool alreadyLoaded = false;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            int moduleCount = cbNeeded / sizeof(HMODULE);
            for (int i = 0; i < moduleCount; i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                    QString modName = QString::fromWCharArray(szModName);
                    if (modName.toLower().contains("openproxifierhook")) {
                        alreadyLoaded = true;
                        break;
                    }
                }
            }
        }
        CloseHandle(hProcess);

        if (alreadyLoaded) {
            MonitorLog("VirtualAllocEx failed but DLL already loaded (injected by parent), treating as success");
            m_injectedProcesses.insert(processId);
            emit injectionResult(exeName, processId, true, "Already injected by parent");
            return;
        }
    }

    // All retries failed
    emit injectionResult(exeName, processId, false, error);
}

bool ProcessMonitor::suspendProcess(DWORD processId)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    bool suspended = false;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) != (DWORD)-1) {
                        suspended = true;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return suspended;
}

bool ProcessMonitor::resumeProcess(DWORD processId)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    bool resumed = false;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    resumed = true;
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return resumed;
}

void ProcessMonitor::onMonitorThread()
{
    MonitorLog("Polling monitoring thread started");

    while (m_running) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                QString exeName = QString::fromWCharArray(pe32.szExeFile).toLower();
                DWORD pid = pe32.th32ProcessID;

                if (m_targetProcesses.contains(exeName) &&
                    !m_injectedProcesses.contains(pid)) {

                    MonitorLog("Detected target: %s (PID %d)", exeName.toStdString().c_str(), pid);
                    emit processDetected(exeName, pid);

                    QString error = injectIntoProcess(pid);
                    if (error.isEmpty()) {
                        m_injectedProcesses.insert(pid);
                        emit injectionResult(exeName, pid, true, "Injection successful");
                    } else {
                        emit injectionResult(exeName, pid, false, error);
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32) && m_running);
        }

        CloseHandle(hSnapshot);

        // Cleanup terminated processes
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

        Sleep(100);  // Reduced to 100ms for faster detection
    }

    MonitorLog("Polling monitoring thread stopped");
}

bool ProcessMonitor::createProxySharedMemory(DWORD processId)
{
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    HANDLE hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHARED_MEM_SIZE, sharedMemName);

    if (!hMapFile) {
        MonitorLog("Failed to create shared memory for PID %d", processId);
        return false;
    }

    ProxyConfig* pConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE));

    if (!pConfig) {
        CloseHandle(hMapFile);
        return false;
    }

    memset(pConfig, 0, sizeof(ProxyConfig));
    pConfig->magic = ProxyConfig::MAGIC;
    pConfig->version = ProxyConfig::VERSION;
    pConfig->proxyIp = m_proxyIp;
    pConfig->proxyPort = m_proxyPort;
    pConfig->authRequired = m_authRequired ? 1 : 0;
    pConfig->enabled = 1;  // Enable proxy by default

    if (m_authRequired) {
        strncpy_s(pConfig->username, m_username.toStdString().c_str(), sizeof(pConfig->username) - 1);
        strncpy_s(pConfig->password, m_password.toStdString().c_str(), sizeof(pConfig->password) - 1);
    }

    UnmapViewOfFile(pConfig);
    // Don't close hMapFile - target process needs it

    MonitorLog("Created shared memory for PID %d", processId);
    return true;
}

// Check if the target process already has our DLL loaded
static bool IsAlreadyInjected(HANDLE hProcess, const QString& dllPath) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        int moduleCount = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < moduleCount; i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                QString modName = QString::fromWCharArray(szModName);
                if (modName.toLower().contains("openproxifierhook")) {
                    return true;
                }
            }
        }
    }
    return false;
}

QString ProcessMonitor::injectIntoProcess(DWORD processId)
{
    MonitorLog("injectIntoProcess called for PID %d", processId);

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processId);

    if (!hProcess) {
        DWORD err = GetLastError();
        MonitorLog("Failed to open process %d, error: %d", processId, err);
        return QString("Failed to open process (error %1)").arg(err);
    }

    // Check if already injected (by parent process's CreateProcess hook)
    if (IsAlreadyInjected(hProcess, m_dllPath)) {
        MonitorLog("Process %d already has Hook DLL loaded, skipping", processId);
        CloseHandle(hProcess);
        return QString();  // Return success (empty string)
    }

    // Check if target process architecture matches our DLL
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
#ifdef _WIN64
        // We are 64-bit, target must also be 64-bit (not WOW64)
        if (isWow64) {
            MonitorLog("Skipping 32-bit process %d (we have 64-bit DLL)", processId);
            CloseHandle(hProcess);
            return QString("Target is 32-bit, need 32-bit DLL (build x86 version)");
        }
#else
        // We are 32-bit, target must also be 32-bit (WOW64 on 64-bit Windows, or native 32-bit)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && !isWow64) {
            MonitorLog("Skipping 64-bit process %d (we have 32-bit DLL)", processId);
            CloseHandle(hProcess);
            return QString("Target is 64-bit, need 64-bit DLL (build x64 version)");
        }
#endif
    }

    if (!createProxySharedMemory(processId)) {
        CloseHandle(hProcess);
        return QString("Failed to create shared memory");
    }

    std::wstring dllPathW = m_dllPath.toStdWString();
    SIZE_T pathSize = (dllPathW.length() + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DWORD err = GetLastError();
        MonitorLog("VirtualAllocEx failed for PID %d, error: %d", processId, err);
        CloseHandle(hProcess);
        return QString("VirtualAllocEx failed (error %1)").arg(err);
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPathW.c_str(), pathSize, &bytesWritten)) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return QString("WriteProcessMemory failed (error %1)").arg(err);
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!loadLibraryAddr) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return QString("Failed to get LoadLibraryW address");
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        DWORD err = GetLastError();
        MonitorLog("CreateRemoteThread failed, error: %d", err);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return QString("CreateRemoteThread failed (error %1)").arg(err);
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    MonitorLog("Successfully injected into PID %d", processId);
    return QString();  // Empty string = success
}

void ProcessMonitor::injectIntoExistingProcesses()
{
    MonitorLog("Scanning for existing target processes...");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MonitorLog("Failed to create process snapshot");
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    int injectedCount = 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            QString exeName = QString::fromWCharArray(pe32.szExeFile).toLower();
            DWORD pid = pe32.th32ProcessID;

            // Skip if not a target or already injected
            if (!m_targetProcesses.contains(exeName) ||
                m_injectedProcesses.contains(pid)) {
                continue;
            }

            // Skip system processes (PID 0 and 4)
            if (pid == 0 || pid == 4) {
                continue;
            }

            MonitorLog("Found existing target process: %s (PID %d)", exeName.toStdString().c_str(), pid);
            emit processDetected(exeName, pid);

            QString error = injectIntoProcess(pid);
            if (error.isEmpty()) {
                m_injectedProcesses.insert(pid);
                emit injectionResult(exeName, pid, true, "Injected into existing process");
                injectedCount++;
            } else {
                emit injectionResult(exeName, pid, false, error);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    MonitorLog("Finished scanning. Injected into %d existing processes.", injectedCount);
}

bool ProcessMonitor::setProxyEnabled(DWORD processId, bool enabled)
{
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    HANDLE hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedMemName);
    if (!hMapFile) {
        MonitorLog("setProxyEnabled: Failed to open shared memory for PID %d", processId);
        return false;
    }

    ProxyConfig* pConfig = static_cast<ProxyConfig*>(
        MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE));

    if (!pConfig) {
        MonitorLog("setProxyEnabled: Failed to map shared memory for PID %d", processId);
        CloseHandle(hMapFile);
        return false;
    }

    pConfig->enabled = enabled ? 1 : 0;
    MonitorLog("setProxyEnabled: Set enabled=%d for PID %d", pConfig->enabled, processId);

    UnmapViewOfFile(pConfig);
    CloseHandle(hMapFile);
    return true;
}

void ProcessMonitor::disableAllInjectedProcesses()
{
    MonitorLog("disableAllInjectedProcesses: Disabling %d processes", m_injectedProcesses.size());

    for (DWORD pid : m_injectedProcesses) {
        // Check if process is still running
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            DWORD exitCode;
            if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                setProxyEnabled(pid, false);
            }
            CloseHandle(hProcess);
        }
    }

    MonitorLog("disableAllInjectedProcesses: Done");
}

