#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <QObject>
#include <QSet>
#include <QString>
#include <QThread>
#include <windows.h>

// Forward declarations for WMI
struct IUnknown;
struct IWbemLocator;
struct IWbemServices;
struct IUnsecuredApartment;
struct IWbemObjectSink;

class ProcessMonitor : public QObject
{
    Q_OBJECT

public:
    explicit ProcessMonitor(QObject* parent = nullptr);
    ~ProcessMonitor();

    // Start monitoring for process creation
    void startMonitoring();

    // Stop monitoring
    void stopMonitoring();

    // Add an exe name to monitor (case insensitive)
    void addTargetProcess(const QString& exeName);

    // Remove an exe from the monitor list
    void removeTargetProcess(const QString& exeName);

    // Clear all target processes
    void clearTargetProcesses();

    // Set the DLL path to inject
    void setDllPath(const QString& path);

    // Set proxy configuration
    void setProxyConfig(uint32_t ip, uint16_t port, bool authRequired = false,
                       const QString& username = "", const QString& password = "");

    // Check if monitoring is active
    bool isMonitoring() const { return m_running; }

    // Called by WMI event sink when a process is created
    void onProcessCreated(const QString& exeName, DWORD processId);

signals:
    void processDetected(const QString& exeName, DWORD processId);
    void injectionResult(const QString& exeName, DWORD processId, bool success, const QString& message);
    void monitoringStarted();
    void monitoringStopped();
    void error(const QString& message);

private slots:
    void onMonitorThread();

private:
    bool injectIntoProcess(DWORD processId);
    bool createProxySharedMemory(DWORD processId);
    bool suspendProcess(DWORD processId);
    bool resumeProcess(DWORD processId);
    bool initWMI();
    void cleanupWMI();

    QThread* m_thread;
    volatile bool m_running;
    QSet<QString> m_targetProcesses;  // Lowercase exe names
    QString m_dllPath;

    // Proxy config
    uint32_t m_proxyIp;
    uint16_t m_proxyPort;
    bool m_authRequired;
    QString m_username;
    QString m_password;

    // Track already injected processes
    QSet<DWORD> m_injectedProcesses;

    // WMI objects
    IWbemLocator* m_pLocator;
    IWbemServices* m_pServices;
    IUnsecuredApartment* m_pUnsecApp;
    IWbemObjectSink* m_pSink;
    IUnknown* m_pStubUnk;
    IWbemObjectSink* m_pStubSink;
    bool m_wmiInitialized;
};

#endif // PROCESS_MONITOR_H
