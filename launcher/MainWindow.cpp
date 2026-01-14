#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <QLocale>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_monitor(new ProcessMonitor(this))
    , m_isChinese(false)
{
    ui->setupUi(this);

    // Setup language selector
    ui->languageCombo->addItem("English", "en");
    ui->languageCombo->addItem(QString::fromUtf8("\344\270\255\346\226\207"), "zh");  // UTF-8 encoded Chinese chars

    // Detect system language
    QString sysLang = QLocale::system().name();
    if (sysLang.startsWith("zh")) {
        ui->languageCombo->setCurrentIndex(1);
        m_isChinese = true;
    } else {
        ui->languageCombo->setCurrentIndex(0);
        m_isChinese = false;
    }

    connect(ui->languageCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onLanguageChanged);

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
    appendLog(m_isChinese ? QString::fromUtf8("\345\267\262\346\267\273\345\212\240\351\273\230\350\256\244\347\233\256\346\240\207: Antigravity.exe")
                          : "Added default target: Antigravity.exe");

    // Apply initial language
    retranslateUi();

    updateStatus(m_isChinese ? QString::fromUtf8("\345\260\261\347\273\252") : "Ready");
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

void MainWindow::onLanguageChanged(int index)
{
    m_isChinese = (index == 1);
    retranslateUi();
    appendLog(m_isChinese ? QString::fromUtf8("\350\257\255\350\250\200\345\267\262\345\210\207\346\215\242\344\270\272\344\270\255\346\226\207")
                          : "Language changed to English");
}

void MainWindow::retranslateUi()
{
    if (m_isChinese) {
        // Chinese translations
        setWindowTitle("OpenProxifier");
        ui->proxyGroup->setTitle(QString::fromUtf8("SOCKS5 \344\273\243\347\220\206\350\256\276\347\275\256"));
        ui->hostLabel->setText(QString::fromUtf8("\346\234\215\345\212\241\345\231\250:"));
        ui->portLabel->setText(QString::fromUtf8("\347\253\257\345\217\243:"));
        ui->authCheckBox->setText(QString::fromUtf8("\351\234\200\350\246\201\350\272\253\344\273\275\351\252\214\350\257\201"));
        ui->userLabel->setText(QString::fromUtf8("\347\224\250\346\210\267\345\220\215:"));
        ui->passLabel->setText(QString::fromUtf8("\345\257\206\347\240\201:"));
        ui->targetGroup->setTitle(QString::fromUtf8("\347\233\256\346\240\207\350\277\233\347\250\213 (\350\207\252\345\212\250\347\233\221\346\216\247)"));
        ui->exeNameEdit->setPlaceholderText(QString::fromUtf8("\350\276\223\345\205\245\347\250\213\345\272\217\345\220\215 (\344\276\213\345\246\202: curl.exe)"));
        ui->addExeButton->setText(QString::fromUtf8("\346\267\273\345\212\240"));
        ui->removeExeButton->setText(QString::fromUtf8("\345\210\240\351\231\244"));
        ui->startMonitorButton->setText(QString::fromUtf8("\345\274\200\345\247\213\347\233\221\346\216\247"));
        ui->stopMonitorButton->setText(QString::fromUtf8("\345\201\234\346\255\242\347\233\221\346\216\247"));
        ui->startMonitorButton->setToolTip(QString::fromUtf8("\347\233\221\346\216\247\347\263\273\347\273\237\344\270\255\347\232\204\347\233\256\346\240\207\350\277\233\347\250\213\345\271\266\350\207\252\345\212\250\346\263\250\345\205\245"));
        ui->logGroup->setTitle(QString::fromUtf8("\346\264\273\345\212\250\346\227\245\345\277\227"));
    } else {
        // English translations
        setWindowTitle("OpenProxifier");
        ui->proxyGroup->setTitle("SOCKS5 Proxy Settings");
        ui->hostLabel->setText("Server:");
        ui->portLabel->setText("Port:");
        ui->authCheckBox->setText("Require Authentication");
        ui->userLabel->setText("Username:");
        ui->passLabel->setText("Password:");
        ui->targetGroup->setTitle("Target Processes (Auto-Monitor)");
        ui->exeNameEdit->setPlaceholderText("Enter exe name (e.g., curl.exe)");
        ui->addExeButton->setText("Add");
        ui->removeExeButton->setText("Remove");
        ui->startMonitorButton->setText("Start Monitoring");
        ui->stopMonitorButton->setText("Stop Monitoring");
        ui->startMonitorButton->setToolTip("Monitor system for target processes and auto-inject");
        ui->logGroup->setTitle("Activity Log");
    }
}
