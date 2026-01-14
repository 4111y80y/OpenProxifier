#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_monitor(new ProcessMonitor(this))
{
    ui->setupUi(this);

    // Connect UI signals
    connect(ui->addExeButton, &QPushButton::clicked, this, &MainWindow::onAddExeClicked);
    connect(ui->removeExeButton, &QPushButton::clicked, this, &MainWindow::onRemoveExeClicked);
    connect(ui->authCheckBox, &QCheckBox::stateChanged, this, &MainWindow::onAuthCheckChanged);

    // Connect monitoring buttons
    connect(ui->startMonitorButton, &QPushButton::clicked, this, &MainWindow::onStartMonitorClicked);
    connect(ui->stopMonitorButton, &QPushButton::clicked, this, &MainWindow::onStopMonitorClicked);

    // Connect ProcessMonitor signals
    connect(m_monitor, &ProcessMonitor::processDetected, this, &MainWindow::onProcessDetected);
    connect(m_monitor, &ProcessMonitor::injectionResult, this, &MainWindow::onInjectionResult);
    connect(m_monitor, &ProcessMonitor::monitoringStarted, this, &MainWindow::onMonitoringStarted);
    connect(m_monitor, &ProcessMonitor::monitoringStopped, this, &MainWindow::onMonitoringStopped);
    connect(m_monitor, &ProcessMonitor::error, this, &MainWindow::onMonitorError);

    // Initial state
    ui->usernameEdit->setEnabled(false);
    ui->passwordEdit->setEnabled(false);

    // Set default values
    ui->proxyHostEdit->setText("127.0.0.1");
    ui->proxyPortSpin->setValue(1081);

    // Set DLL path
    QString dllPath = getHookDllPath();
    if (!dllPath.isEmpty()) {
        m_monitor->setDllPath(dllPath);
        appendLog(QString("DLL: %1").arg(dllPath));
    } else {
        appendLog("[ERROR] Hook DLL not found!");
    }

    // Auto-add Antigravity.exe as default target
    ui->exeListWidget->addItem("Antigravity.exe");
    appendLog("Added default target: Antigravity.exe");

    updateStatus("Ready");
}

MainWindow::~MainWindow()
{
    m_monitor->stopMonitoring();
    delete ui;
}

void MainWindow::onAddExeClicked()
{
    QString exeName = ui->exeNameEdit->text().trimmed();
    if (exeName.isEmpty()) {
        return;
    }

    // Ensure it ends with .exe
    if (!exeName.toLower().endsWith(".exe")) {
        exeName += ".exe";
    }

    // Check for duplicates
    for (int i = 0; i < ui->exeListWidget->count(); ++i) {
        if (ui->exeListWidget->item(i)->text().toLower() == exeName.toLower()) {
            QMessageBox::warning(this, "Duplicate", "This executable is already in the list.");
            return;
        }
    }

    ui->exeListWidget->addItem(exeName);
    ui->exeNameEdit->clear();
    appendLog(QString("Added to favorites: %1").arg(exeName));
}

void MainWindow::onRemoveExeClicked()
{
    QListWidgetItem* item = ui->exeListWidget->currentItem();
    if (item) {
        QString exeName = item->text();
        delete ui->exeListWidget->takeItem(ui->exeListWidget->row(item));
        appendLog(QString("Removed from favorites: %1").arg(exeName));
    }
}

void MainWindow::onAuthCheckChanged(int state)
{
    bool enabled = (state == Qt::Checked);
    ui->usernameEdit->setEnabled(enabled);
    ui->passwordEdit->setEnabled(enabled);
}

void MainWindow::onStartMonitorClicked()
{
    if (!validateProxySettings()) {
        return;
    }

    if (ui->exeListWidget->count() == 0) {
        QMessageBox::warning(this, "No Targets", "Please add at least one target executable to monitor.");
        return;
    }

    QString dllPath = getHookDllPath();
    if (dllPath.isEmpty()) {
        QMessageBox::critical(this, "Error", "Hook DLL not found!");
        return;
    }

    // Configure monitor
    m_monitor->setDllPath(dllPath);
    m_monitor->clearTargetProcesses();

    for (int i = 0; i < ui->exeListWidget->count(); ++i) {
        m_monitor->addTargetProcess(ui->exeListWidget->item(i)->text());
    }

    // Set proxy config
    updateProxyConfig();

    // Start monitoring
    m_monitor->startMonitoring();
}

void MainWindow::onStopMonitorClicked()
{
    m_monitor->stopMonitoring();
}

void MainWindow::onProcessDetected(const QString& exeName, unsigned long processId)
{
    appendLog(QString("[DETECTED] %1 (PID: %2)").arg(exeName).arg(processId));
}

void MainWindow::onInjectionResult(const QString& exeName, unsigned long processId, bool success, const QString& message)
{
    if (success) {
        appendLog(QString("[SUCCESS] Injected into %1 (PID: %2)").arg(exeName).arg(processId));
    } else {
        appendLog(QString("[FAILED] %1 (PID: %2): %3").arg(exeName).arg(processId).arg(message));
    }
}

void MainWindow::onMonitoringStarted()
{
    ui->startMonitorButton->setEnabled(false);
    ui->stopMonitorButton->setEnabled(true);
    ui->proxyGroup->setEnabled(false);
    // Don't disable targetGroup entirely - stopMonitorButton is inside it
    ui->exeNameEdit->setEnabled(false);
    ui->addExeButton->setEnabled(false);
    ui->removeExeButton->setEnabled(false);
    ui->exeListWidget->setEnabled(false);
    updateStatus("Monitoring...");
    appendLog("[INFO] Monitoring started - waiting for target processes...");
}

void MainWindow::onMonitoringStopped()
{
    ui->startMonitorButton->setEnabled(true);
    ui->stopMonitorButton->setEnabled(false);
    ui->proxyGroup->setEnabled(true);
    // Re-enable targetGroup controls
    ui->exeNameEdit->setEnabled(true);
    ui->addExeButton->setEnabled(true);
    ui->removeExeButton->setEnabled(true);
    ui->exeListWidget->setEnabled(true);
    updateStatus("Ready");
    appendLog("[INFO] Monitoring stopped");
}

void MainWindow::onMonitorError(const QString& message)
{
    appendLog(QString("[ERROR] %1").arg(message));
    QMessageBox::critical(this, "Error", message);
}

void MainWindow::updateStatus(const QString& message)
{
    ui->statusLabel->setText("Status: " + message);
}

void MainWindow::appendLog(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    ui->logTextEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
}

bool MainWindow::validateProxySettings()
{
    if (ui->proxyHostEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Please enter proxy server address.");
        return false;
    }

    // Validate IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, ui->proxyHostEdit->text().toStdString().c_str(), &addr) != 1) {
        QMessageBox::warning(this, "Validation Error", "Invalid proxy IP address.");
        return false;
    }

    if (ui->authCheckBox->isChecked()) {
        if (ui->usernameEdit->text().isEmpty()) {
            QMessageBox::warning(this, "Validation Error", "Please enter username for authentication.");
            return false;
        }
    }

    return true;
}

QString MainWindow::getHookDllPath()
{
    QString appDir = QCoreApplication::applicationDirPath();

#ifdef _WIN64
    QString dllName = "MiniProxifierHook_x64.dll";
#else
    QString dllName = "MiniProxifierHook_x86.dll";
#endif

    QString dllPath = QDir(appDir).filePath(dllName);

    if (QFile::exists(dllPath)) {
        return dllPath;
    }

    return QString();
}

void MainWindow::updateProxyConfig()
{
    QString proxyHost = ui->proxyHostEdit->text();
    int proxyPort = ui->proxyPortSpin->value();

    struct in_addr addr;
    inet_pton(AF_INET, proxyHost.toStdString().c_str(), &addr);

    m_monitor->setProxyConfig(
        addr.s_addr,
        htons(static_cast<uint16_t>(proxyPort)),
        ui->authCheckBox->isChecked(),
        ui->usernameEdit->text(),
        ui->passwordEdit->text()
    );
}
