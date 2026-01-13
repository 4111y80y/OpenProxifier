#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <QFileDialog>
#include <QProcess>
#include <QStandardPaths>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>

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

    // Connect launch option buttons
    connect(ui->browseButton, &QPushButton::clicked, this, &MainWindow::onBrowseClicked);
    connect(ui->launchButton, &QPushButton::clicked, this, &MainWindow::onLaunchClicked);
    connect(ui->createShortcutButton, &QPushButton::clicked, this, &MainWindow::onCreateShortcutClicked);

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
    ui->proxyHostEdit->setText("172.30.156.245");
    ui->proxyPortSpin->setValue(1081);

    // Set DLL path
    QString dllPath = getHookDllPath();
    if (!dllPath.isEmpty()) {
        m_monitor->setDllPath(dllPath);
        appendLog(QString("DLL: %1").arg(dllPath));
    } else {
        appendLog("[ERROR] Hook DLL not found!");
    }

    // Check injector
    QString injectorPath = getInjectorPath();
    if (!injectorPath.isEmpty()) {
        appendLog(QString("Injector: %1").arg(injectorPath));
    } else {
        appendLog("[ERROR] ProxifierInjector not found!");
    }

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

void MainWindow::onBrowseClicked()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,
        "Select Executable",
        QString(),
        "Executables (*.exe);;All Files (*.*)"
    );

    if (!fileName.isEmpty()) {
        ui->exePathEdit->setText(fileName);
    }
}

void MainWindow::onLaunchClicked()
{
    if (!validateProxySettings()) {
        return;
    }

    QString exePath = ui->exePathEdit->text().trimmed();
    if (exePath.isEmpty()) {
        QMessageBox::warning(this, "No Executable", "Please select an executable to launch.");
        return;
    }

    QString injectorPath = getInjectorPath();
    if (injectorPath.isEmpty()) {
        QMessageBox::critical(this, "Error", "ProxifierInjector not found!");
        return;
    }

    // Save proxy settings to environment variable
    saveProxyToEnv();

    // Build arguments
    QStringList args;
    args << exePath;

    QString userArgs = ui->argsEdit->text().trimmed();
    if (!userArgs.isEmpty()) {
        args << userArgs.split(' ', Qt::SkipEmptyParts);
    }

    appendLog(QString("[LAUNCH] %1 %2").arg(exePath).arg(userArgs));

    // Start the process
    QProcess* process = new QProcess(this);
    process->setProgram(injectorPath);
    process->setArguments(args);

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this, process, exePath](int exitCode, QProcess::ExitStatus) {
        appendLog(QString("[EXIT] %1 exited with code %2").arg(QFileInfo(exePath).fileName()).arg(exitCode));
        process->deleteLater();
    });

    process->start();

    if (process->waitForStarted(3000)) {
        appendLog(QString("[SUCCESS] Launched %1 through proxy").arg(QFileInfo(exePath).fileName()));
        updateStatus("Program launched");
    } else {
        appendLog(QString("[ERROR] Failed to launch: %1").arg(process->errorString()));
        QMessageBox::critical(this, "Launch Failed", process->errorString());
    }
}

void MainWindow::onCreateShortcutClicked()
{
    QString exePath = ui->exePathEdit->text().trimmed();
    if (exePath.isEmpty()) {
        QMessageBox::warning(this, "No Executable", "Please select an executable first.");
        return;
    }

    if (!validateProxySettings()) {
        return;
    }

    QString injectorPath = getInjectorPath();
    if (injectorPath.isEmpty()) {
        QMessageBox::critical(this, "Error", "ProxifierInjector not found!");
        return;
    }

    // Get executable name for shortcut
    QFileInfo fileInfo(exePath);
    QString exeName = fileInfo.completeBaseName();

    // Get desktop path
    QString desktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    QString shortcutPath = QDir(desktopPath).filePath(QString("Proxified %1.lnk").arg(exeName));

    // Build proxy environment string
    QString proxyEnv = QString("%1:%2")
        .arg(ui->proxyHostEdit->text())
        .arg(ui->proxyPortSpin->value());

    // Create shortcut using PowerShell
    QString psScript = QString(
        "$ws = New-Object -ComObject WScript.Shell; "
        "$s = $ws.CreateShortcut('%1'); "
        "$s.TargetPath = '%2'; "
        "$s.Arguments = '\"%3\"'; "
        "$s.WorkingDirectory = '%4'; "
        "$s.Description = 'Launches %5 through SOCKS5 proxy'; "
        "$s.Save()"
    ).arg(shortcutPath.replace("/", "\\"))
     .arg(injectorPath.replace("/", "\\"))
     .arg(exePath.replace("/", "\\"))
     .arg(fileInfo.absolutePath().replace("/", "\\"))
     .arg(exeName);

    QProcess ps;
    ps.start("powershell", QStringList() << "-Command" << psScript);
    ps.waitForFinished(5000);

    if (QFile::exists(shortcutPath)) {
        appendLog(QString("[SUCCESS] Created shortcut: %1").arg(shortcutPath));
        QMessageBox::information(this, "Shortcut Created",
            QString("Desktop shortcut created:\n%1\n\n"
                    "Note: Set PROXIFIER_PROXY=%2 environment variable "
                    "or the default proxy will be used.")
            .arg(shortcutPath).arg(proxyEnv));
        updateStatus("Shortcut created");
    } else {
        appendLog("[ERROR] Failed to create shortcut");
        QMessageBox::critical(this, "Error", "Failed to create shortcut.");
    }
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
    ui->proxyGroup->setEnabled(false);
    ui->targetGroup->setEnabled(false);
    updateStatus("Monitoring...");
    appendLog("[INFO] Monitoring started - waiting for target processes...");
}

void MainWindow::onMonitoringStopped()
{
    ui->proxyGroup->setEnabled(true);
    ui->targetGroup->setEnabled(true);
    updateStatus("Stopped");
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

QString MainWindow::getInjectorPath()
{
    QString appDir = QCoreApplication::applicationDirPath();

#ifdef _WIN64
    QString injectorName = "ProxifierInjector_x64.exe";
#else
    QString injectorName = "ProxifierInjector_x86.exe";
#endif

    QString injectorPath = QDir(appDir).filePath(injectorName);

    if (QFile::exists(injectorPath)) {
        return injectorPath;
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

void MainWindow::saveProxyToEnv()
{
    QString proxyValue = QString("%1:%2")
        .arg(ui->proxyHostEdit->text())
        .arg(ui->proxyPortSpin->value());

    SetEnvironmentVariableA("PROXIFIER_PROXY", proxyValue.toStdString().c_str());
    appendLog(QString("[INFO] Set PROXIFIER_PROXY=%1").arg(proxyValue));
}
