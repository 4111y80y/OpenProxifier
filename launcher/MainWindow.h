#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>
#include <QStringList>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class ProcessMonitor;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onAddExeClicked();
    void onRemoveExeClicked();
    void onAuthCheckChanged(int state);

    // Monitoring slots
    void onStartMonitorClicked();
    void onStopMonitorClicked();

    // ProcessMonitor signals
    void onProcessDetected(const QString& exeName, unsigned long processId);
    void onInjectionResult(const QString& exeName, unsigned long processId, bool success, const QString& message);
    void onMonitoringStarted();
    void onMonitoringStopped();
    void onMonitorError(const QString& message);

    // Language
    void onLanguageChanged(int index);

    // Server history
    void onServerComboChanged(int index);
    void onSaveServerClicked();
    void onDeleteServerClicked();

    // Server connectivity test
    void onTestServerClicked();
    void onProxySettingsChanged();

private:
    Ui::MainWindow *ui;
    ProcessMonitor* m_monitor;
    bool m_isChinese;
    QSettings* m_settings;
    bool m_serverConnected;  // Track if server is reachable

    void updateStatus(const QString& message);
    void appendLog(const QString& message);
    QString tr_log(const QString& en, const QString& zh);  // Translate log messages
    bool validateProxySettings();
    QString getHookDllPath();
    void updateProxyConfig();
    void retranslateUi();

    // Settings save/load
    void loadSettings();
    void saveSettings();
    void loadServerHistory();
    void saveServerHistory();
};

#endif // MAINWINDOW_H
