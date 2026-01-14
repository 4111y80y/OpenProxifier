#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

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

private:
    Ui::MainWindow *ui;
    ProcessMonitor* m_monitor;

    void updateStatus(const QString& message);
    void appendLog(const QString& message);
    bool validateProxySettings();
    QString getHookDllPath();
    void updateProxyConfig();
};

#endif // MAINWINDOW_H
