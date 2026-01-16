#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>
#include <QStringList>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class ProcessMonitor;
class ProxyEngineWrapper;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // For single instance support
    void bringToFront();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onAddExeClicked();
    void onRemoveExeClicked();
    void onAuthCheckChanged(int state);

    // Monitoring slots
    void onStartMonitorClicked();
    void onStopMonitorClicked();

    // ProcessMonitor signals (legacy DLL injection mode)
    void onProcessDetected(const QString& exeName, unsigned long processId);
    void onInjectionResult(const QString& exeName, unsigned long processId, bool success, const QString& message);
    void onMonitoringStarted();
    void onMonitoringStopped();
    void onMonitorError(const QString& message);

    // WinDivert mode signals
    void onWinDivertModeChanged(int state);
    void onEngineLogMessage(const QString& message);
    void onEngineConnectionDetected(const QString& process, uint32_t pid,
                                     const QString& destIp, uint16_t destPort,
                                     const QString& status);
    void onEngineStarted();
    void onEngineStopped();
    void onEngineError(const QString& message);

    // Language
    void onLanguageChanged(int index);

    // Server history
    void onServerComboChanged(int index);
    void onSaveServerClicked();
    void onDeleteServerClicked();

    // Server connectivity test
    void onTestServerClicked();
    void onProxySettingsChanged();

    // Launch test app
    void onLaunchTestAppClicked();

    // System tray
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onTrayExitClicked();

private:
    Ui::MainWindow *ui;
    ProcessMonitor* m_monitor;
    ProxyEngineWrapper* m_engine;
    bool m_isChinese;
    QSettings* m_settings;
    bool m_serverConnected;  // Track if server is reachable
    bool m_winDivertMode;    // WinDivert mode flag

    // System tray
    QSystemTrayIcon* m_trayIcon;
    QMenu* m_trayMenu;
    QAction* m_showAction;
    QAction* m_exitAction;
    bool m_forceQuit;  // True when user wants to actually quit

    void updateStatus(const QString& message);
    void appendLog(const QString& message);
    QString tr_log(const QString& en, const QString& zh);  // Translate log messages
    bool validateProxySettings();
    QString getHookDllPath();
    void updateProxyConfig();
    void retranslateUi();
    void setupTrayIcon();

    // WinDivert mode helpers
    void startWinDivertMode();
    void stopWinDivertMode();
    void setupWinDivertConnections();

    // Settings save/load
    void loadSettings();
    void saveSettings();
    void loadServerHistory();
    void saveServerHistory();
};

#endif // MAINWINDOW_H
