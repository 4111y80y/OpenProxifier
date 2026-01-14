#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "ProcessMonitor.h"
#include "ProxyConfig.h"
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <QLocale>
#include <QTimer>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_monitor(new ProcessMonitor(this))
    , m_isChinese(false)
    , m_settings(new QSettings("OpenProxifier", "MiniProxifier", this))
    , m_serverConnected(false)
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

    // Connect server history buttons
    connect(ui->saveServerButton, &QPushButton::clicked, this, &MainWindow::onSaveServerClicked);
    connect(ui->deleteServerButton, &QPushButton::clicked, this, &MainWindow::onDeleteServerClicked);
    connect(ui->serverHistoryCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onServerComboChanged);

    // Connect test server button
    connect(ui->testServerButton, &QPushButton::clicked, this, &MainWindow::onTestServerClicked);

    // Connect proxy settings change signals for auto-test
    connect(ui->proxyHostEdit, &QLineEdit::textChanged, this, &MainWindow::onProxySettingsChanged);
    connect(ui->proxyPortSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &MainWindow::onProxySettingsChanged);

    // Connect ProcessMonitor signals
    connect(m_monitor, &ProcessMonitor::processDetected, this, &MainWindow::onProcessDetected);
    connect(m_monitor, &ProcessMonitor::injectionResult, this, &MainWindow::onInjectionResult);
    connect(m_monitor, &ProcessMonitor::monitoringStarted, this, &MainWindow::onMonitoringStarted);
    connect(m_monitor, &ProcessMonitor::monitoringStopped, this, &MainWindow::onMonitoringStopped);
    connect(m_monitor, &ProcessMonitor::error, this, &MainWindow::onMonitorError);

    // Initial state
    ui->usernameEdit->setEnabled(false);
    ui->passwordEdit->setEnabled(false);
    ui->startMonitorButton->setEnabled(false);  // Disabled until connection tested

    // Set default values
    ui->proxyHostEdit->setText("127.0.0.1");
    ui->proxyPortSpin->setValue(1081);

    // Set DLL path
    QString dllPath = getHookDllPath();
    if (!dllPath.isEmpty()) {
        m_monitor->setDllPath(dllPath);
        appendLog(QString("DLL: %1").arg(dllPath));
    } else {
        appendLog(tr_log("[ERROR] Hook DLL not found!", "[ERROR] Hook DLL not found!"));
    }

    // Load settings (includes server history and target list)
    loadSettings();

    // Auto-add Antigravity.exe as default target if list is empty
    if (ui->exeListWidget->count() == 0) {
        ui->exeListWidget->addItem("Antigravity.exe");
        appendLog(tr_log("Added default target: Antigravity.exe",
                         QString::fromUtf8("\345\267\262\346\267\273\345\212\240\351\273\230\350\256\244\347\233\256\346\240\207: Antigravity.exe")));
    }

    // Apply initial language
    retranslateUi();

    // Initial connection status
    ui->connectionStatusLabel->setText(tr_log("Not tested", QString::fromUtf8("\346\234\252\346\265\213\350\257\225")));
    ui->connectionStatusLabel->setStyleSheet("color: gray;");

    updateStatus(tr_log("Ready", QString::fromUtf8("\345\260\261\347\273\252")));

    // Auto-test connection on startup, then auto-start if enabled
    QTimer::singleShot(500, this, [this]() {
        onTestServerClicked();
        if (m_serverConnected && ui->autoStartCheckBox->isChecked()) {
            onStartMonitorClicked();
        }
    });
}

MainWindow::~MainWindow()
{
    saveSettings();
    m_monitor->stopMonitoring();
    delete ui;
}

void MainWindow::loadSettings()
{
    // Load language setting
    QString lang = m_settings->value("language", "").toString();
    if (lang == "zh") {
        ui->languageCombo->setCurrentIndex(1);
        m_isChinese = true;
    } else if (lang == "en") {
        ui->languageCombo->setCurrentIndex(0);
        m_isChinese = false;
    }

    // Load auto-start setting
    ui->autoStartCheckBox->setChecked(m_settings->value("autoStart", false).toBool());

    // Load server history
    loadServerHistory();

    // Load target processes
    QStringList targets = m_settings->value("targetProcesses").toStringList();
    for (const QString& target : targets) {
        ui->exeListWidget->addItem(target);
    }

    // Load last used proxy settings
    QString lastHost = m_settings->value("lastProxyHost", "127.0.0.1").toString();
    int lastPort = m_settings->value("lastProxyPort", 1081).toInt();
    bool lastAuth = m_settings->value("lastAuthRequired", false).toBool();
    QString lastUser = m_settings->value("lastUsername", "").toString();
    QString lastPass = m_settings->value("lastPassword", "").toString();

    ui->proxyHostEdit->setText(lastHost);
    ui->proxyPortSpin->setValue(lastPort);
    ui->authCheckBox->setChecked(lastAuth);
    ui->usernameEdit->setText(lastUser);
    ui->passwordEdit->setText(lastPass);
}

void MainWindow::saveSettings()
{
    // Save language setting
    m_settings->setValue("language", m_isChinese ? "zh" : "en");

    // Save auto-start setting
    m_settings->setValue("autoStart", ui->autoStartCheckBox->isChecked());

    // Save server history
    saveServerHistory();

    // Save target processes
    QStringList targets;
    for (int i = 0; i < ui->exeListWidget->count(); ++i) {
        targets.append(ui->exeListWidget->item(i)->text());
    }
    m_settings->setValue("targetProcesses", targets);

    // Save last used proxy settings
    m_settings->setValue("lastProxyHost", ui->proxyHostEdit->text());
    m_settings->setValue("lastProxyPort", ui->proxyPortSpin->value());
    m_settings->setValue("lastAuthRequired", ui->authCheckBox->isChecked());
    m_settings->setValue("lastUsername", ui->usernameEdit->text());
    m_settings->setValue("lastPassword", ui->passwordEdit->text());
}

void MainWindow::loadServerHistory()
{
    ui->serverHistoryCombo->clear();
    ui->serverHistoryCombo->addItem(tr_log("-- Select saved server --",
                                           QString::fromUtf8("-- \351\200\211\346\213\251\345\267\262\344\277\235\345\255\230\347\232\204\346\234\215\345\212\241\345\231\250 --")));

    int count = m_settings->beginReadArray("serverHistory");
    for (int i = 0; i < count; ++i) {
        m_settings->setArrayIndex(i);
        QString name = m_settings->value("name").toString();
        QString host = m_settings->value("host").toString();
        int port = m_settings->value("port").toInt();
        bool auth = m_settings->value("auth").toBool();
        QString user = m_settings->value("user").toString();
        QString pass = m_settings->value("pass").toString();

        QString displayName = name.isEmpty() ? QString("%1:%2").arg(host).arg(port) : name;

        // Store full info in item data
        QVariantMap data;
        data["host"] = host;
        data["port"] = port;
        data["auth"] = auth;
        data["user"] = user;
        data["pass"] = pass;

        ui->serverHistoryCombo->addItem(displayName, data);
    }
    m_settings->endArray();
}

void MainWindow::saveServerHistory()
{
    m_settings->beginWriteArray("serverHistory");
    for (int i = 1; i < ui->serverHistoryCombo->count(); ++i) {  // Skip first item (placeholder)
        m_settings->setArrayIndex(i - 1);
        QVariantMap data = ui->serverHistoryCombo->itemData(i).toMap();
        m_settings->setValue("name", ui->serverHistoryCombo->itemText(i));
        m_settings->setValue("host", data["host"].toString());
        m_settings->setValue("port", data["port"].toInt());
        m_settings->setValue("auth", data["auth"].toBool());
        m_settings->setValue("user", data["user"].toString());
        m_settings->setValue("pass", data["pass"].toString());
    }
    m_settings->endArray();
}

void MainWindow::onServerComboChanged(int index)
{
    if (index <= 0) return;  // Skip placeholder

    QVariantMap data = ui->serverHistoryCombo->itemData(index).toMap();
    if (data.isEmpty()) return;

    ui->proxyHostEdit->setText(data["host"].toString());
    ui->proxyPortSpin->setValue(data["port"].toInt());
    ui->authCheckBox->setChecked(data["auth"].toBool());
    ui->usernameEdit->setText(data["user"].toString());
    ui->passwordEdit->setText(data["pass"].toString());

    appendLog(tr_log(QString("Loaded server: %1").arg(ui->serverHistoryCombo->currentText()),
                     QString::fromUtf8("\345\267\262\345\212\240\350\275\275\346\234\215\345\212\241\345\231\250: %1").arg(ui->serverHistoryCombo->currentText())));
}

void MainWindow::onSaveServerClicked()
{
    QString host = ui->proxyHostEdit->text().trimmed();
    if (host.isEmpty()) {
        QMessageBox::warning(this,
            tr_log("Error", QString::fromUtf8("\351\224\231\350\257\257")),
            tr_log("Please enter a server address first.",
                   QString::fromUtf8("\350\257\267\345\205\210\350\276\223\345\205\245\346\234\215\345\212\241\345\231\250\345\234\260\345\235\200\343\200\202")));
        return;
    }

    int port = ui->proxyPortSpin->value();
    QString displayName = QString("%1:%2").arg(host).arg(port);

    // Check for duplicates
    for (int i = 1; i < ui->serverHistoryCombo->count(); ++i) {
        if (ui->serverHistoryCombo->itemText(i) == displayName) {
            // Update existing entry
            QVariantMap data;
            data["host"] = host;
            data["port"] = port;
            data["auth"] = ui->authCheckBox->isChecked();
            data["user"] = ui->usernameEdit->text();
            data["pass"] = ui->passwordEdit->text();
            ui->serverHistoryCombo->setItemData(i, data);

            appendLog(tr_log(QString("Updated server: %1").arg(displayName),
                             QString::fromUtf8("\345\267\262\346\233\264\346\226\260\346\234\215\345\212\241\345\231\250: %1").arg(displayName)));
            return;
        }
    }

    // Add new entry
    QVariantMap data;
    data["host"] = host;
    data["port"] = port;
    data["auth"] = ui->authCheckBox->isChecked();
    data["user"] = ui->usernameEdit->text();
    data["pass"] = ui->passwordEdit->text();

    ui->serverHistoryCombo->addItem(displayName, data);
    ui->serverHistoryCombo->setCurrentIndex(ui->serverHistoryCombo->count() - 1);

    appendLog(tr_log(QString("Saved server: %1").arg(displayName),
                     QString::fromUtf8("\345\267\262\344\277\235\345\255\230\346\234\215\345\212\241\345\231\250: %1").arg(displayName)));
}

void MainWindow::onDeleteServerClicked()
{
    int index = ui->serverHistoryCombo->currentIndex();
    if (index <= 0) {
        QMessageBox::warning(this,
            tr_log("Error", QString::fromUtf8("\351\224\231\350\257\257")),
            tr_log("Please select a saved server to delete.",
                   QString::fromUtf8("\350\257\267\351\200\211\346\213\251\350\246\201\345\210\240\351\231\244\347\232\204\346\234\215\345\212\241\345\231\250\343\200\202")));
        return;
    }

    QString name = ui->serverHistoryCombo->currentText();
    ui->serverHistoryCombo->removeItem(index);

    appendLog(tr_log(QString("Deleted server: %1").arg(name),
                     QString::fromUtf8("\345\267\262\345\210\240\351\231\244\346\234\215\345\212\241\345\231\250: %1").arg(name)));
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
            QMessageBox::warning(this,
                tr_log("Duplicate", QString::fromUtf8("\351\207\215\345\244\215")),
                tr_log("This executable is already in the list.",
                       QString::fromUtf8("\350\257\245\347\250\213\345\272\217\345\267\262\345\234\250\345\210\227\350\241\250\344\270\255\343\200\202")));
            return;
        }
    }

    ui->exeListWidget->addItem(exeName);
    ui->exeNameEdit->clear();
    appendLog(tr_log(QString("Added target: %1").arg(exeName),
                     QString::fromUtf8("\345\267\262\346\267\273\345\212\240\347\233\256\346\240\207: %1").arg(exeName)));
}

void MainWindow::onRemoveExeClicked()
{
    QListWidgetItem* item = ui->exeListWidget->currentItem();
    if (item) {
        QString exeName = item->text();
        delete ui->exeListWidget->takeItem(ui->exeListWidget->row(item));
        appendLog(tr_log(QString("Removed target: %1").arg(exeName),
                         QString::fromUtf8("\345\267\262\345\210\240\351\231\244\347\233\256\346\240\207: %1").arg(exeName)));
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
        QMessageBox::warning(this,
            tr_log("No Targets", QString::fromUtf8("\346\227\240\347\233\256\346\240\207")),
            tr_log("Please add at least one target executable to monitor.",
                   QString::fromUtf8("\350\257\267\350\207\263\345\260\221\346\267\273\345\212\240\344\270\200\344\270\252\347\233\256\346\240\207\347\250\213\345\272\217\343\200\202")));
        return;
    }

    QString dllPath = getHookDllPath();
    if (dllPath.isEmpty()) {
        QMessageBox::critical(this,
            tr_log("Error", QString::fromUtf8("\351\224\231\350\257\257")),
            tr_log("Hook DLL not found!", QString::fromUtf8("Hook DLL \346\234\252\346\211\276\345\210\260!")));
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
    appendLog(tr_log(QString("[DETECTED] %1 (PID: %2)").arg(exeName).arg(processId),
                     QString::fromUtf8("[\346\243\200\346\265\213\345\210\260] %1 (PID: %2)").arg(exeName).arg(processId)));
}

void MainWindow::onInjectionResult(const QString& exeName, unsigned long processId, bool success, const QString& message)
{
    if (success) {
        appendLog(tr_log(QString("[SUCCESS] Injected into %1 (PID: %2)").arg(exeName).arg(processId),
                         QString::fromUtf8("[\346\210\220\345\212\237] \345\267\262\346\263\250\345\205\245 %1 (PID: %2)").arg(exeName).arg(processId)));
    } else {
        appendLog(tr_log(QString("[FAILED] %1 (PID: %2): %3").arg(exeName).arg(processId).arg(message),
                         QString::fromUtf8("[\345\244\261\350\264\245] %1 (PID: %2): %3").arg(exeName).arg(processId).arg(message)));
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
    ui->autoStartCheckBox->setEnabled(false);
    updateStatus(tr_log("Monitoring...", QString::fromUtf8("\347\233\221\346\216\247\344\270\255...")));
    appendLog(tr_log("[INFO] Monitoring started - waiting for target processes...",
                     QString::fromUtf8("[\344\277\241\346\201\257] \347\233\221\346\216\247\345\267\262\345\220\257\345\212\250 - \347\255\211\345\276\205\347\233\256\346\240\207\350\277\233\347\250\213...")));
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
    ui->autoStartCheckBox->setEnabled(true);
    updateStatus(tr_log("Ready", QString::fromUtf8("\345\260\261\347\273\252")));
    appendLog(tr_log("[INFO] Monitoring stopped",
                     QString::fromUtf8("[\344\277\241\346\201\257] \347\233\221\346\216\247\345\267\262\345\201\234\346\255\242")));
}

void MainWindow::onMonitorError(const QString& message)
{
    appendLog(QString("[ERROR] %1").arg(message));
    QMessageBox::critical(this,
        tr_log("Error", QString::fromUtf8("\351\224\231\350\257\257")),
        message);
}

void MainWindow::updateStatus(const QString& message)
{
    ui->statusLabel->setText(tr_log("Status: ", QString::fromUtf8("\347\212\266\346\200\201: ")) + message);
}

void MainWindow::appendLog(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    ui->logTextEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
}

QString MainWindow::tr_log(const QString& en, const QString& zh)
{
    return m_isChinese ? zh : en;
}

bool MainWindow::validateProxySettings()
{
    if (ui->proxyHostEdit->text().isEmpty()) {
        QMessageBox::warning(this,
            tr_log("Validation Error", QString::fromUtf8("\351\252\214\350\257\201\351\224\231\350\257\257")),
            tr_log("Please enter proxy server address.",
                   QString::fromUtf8("\350\257\267\350\276\223\345\205\245\344\273\243\347\220\206\346\234\215\345\212\241\345\231\250\345\234\260\345\235\200\343\200\202")));
        return false;
    }

    // Validate IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, ui->proxyHostEdit->text().toStdString().c_str(), &addr) != 1) {
        QMessageBox::warning(this,
            tr_log("Validation Error", QString::fromUtf8("\351\252\214\350\257\201\351\224\231\350\257\257")),
            tr_log("Invalid proxy IP address.",
                   QString::fromUtf8("\346\227\240\346\225\210\347\232\204\344\273\243\347\220\206IP\345\234\260\345\235\200\343\200\202")));
        return false;
    }

    if (ui->authCheckBox->isChecked()) {
        if (ui->usernameEdit->text().isEmpty()) {
            QMessageBox::warning(this,
                tr_log("Validation Error", QString::fromUtf8("\351\252\214\350\257\201\351\224\231\350\257\257")),
                tr_log("Please enter username for authentication.",
                       QString::fromUtf8("\350\257\267\350\276\223\345\205\245\350\256\244\350\257\201\347\224\250\346\210\267\345\220\215\343\200\202")));
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
    appendLog(tr_log("Language changed to English",
                     QString::fromUtf8("\350\257\255\350\250\200\345\267\262\345\210\207\346\215\242\344\270\272\344\270\255\346\226\207")));
}

void MainWindow::retranslateUi()
{
    if (m_isChinese) {
        // Chinese translations
        setWindowTitle("OpenProxifier");
        ui->proxyGroup->setTitle(QString::fromUtf8("SOCKS5 \344\273\243\347\220\206\350\256\276\347\275\256"));
        ui->historyLabel->setText(QString::fromUtf8("\345\216\206\345\217\262:"));
        ui->saveServerButton->setText(QString::fromUtf8("\344\277\235\345\255\230"));
        ui->deleteServerButton->setText(QString::fromUtf8("\345\210\240\351\231\244"));
        ui->hostLabel->setText(QString::fromUtf8("\346\234\215\345\212\241\345\231\250:"));
        ui->portLabel->setText(QString::fromUtf8("\347\253\257\345\217\243:"));
        ui->authCheckBox->setText(QString::fromUtf8("\351\234\200\350\246\201\350\272\253\344\273\275\351\252\214\350\257\201"));
        ui->userLabel->setText(QString::fromUtf8("\347\224\250\346\210\267\345\220\215:"));
        ui->passLabel->setText(QString::fromUtf8("\345\257\206\347\240\201:"));
        ui->targetGroup->setTitle(QString::fromUtf8("\347\233\256\346\240\207\350\277\233\347\250\213 (\350\207\252\345\212\250\347\233\221\346\216\247)"));
        ui->exeNameEdit->setPlaceholderText(QString::fromUtf8("\350\276\223\345\205\245\347\250\213\345\272\217\345\220\215 (\344\276\213\345\246\202: Antigravity.exe)"));
        ui->addExeButton->setText(QString::fromUtf8("\346\267\273\345\212\240"));
        ui->removeExeButton->setText(QString::fromUtf8("\345\210\240\351\231\244"));
        ui->autoStartCheckBox->setText(QString::fromUtf8("\345\220\257\345\212\250\346\227\266\350\207\252\345\212\250\345\274\200\345\247\213\347\233\221\346\216\247"));
        ui->startMonitorButton->setText(QString::fromUtf8("\345\274\200\345\247\213\347\233\221\346\216\247"));
        ui->stopMonitorButton->setText(QString::fromUtf8("\345\201\234\346\255\242\347\233\221\346\216\247"));
        ui->startMonitorButton->setToolTip(QString::fromUtf8("\347\233\221\346\216\247\347\263\273\347\273\237\344\270\255\347\232\204\347\233\256\346\240\207\350\277\233\347\250\213\345\271\266\350\207\252\345\212\250\346\263\250\345\205\245"));
        ui->logGroup->setTitle(QString::fromUtf8("\346\264\273\345\212\250\346\227\245\345\277\227"));
        ui->testServerButton->setText(QString::fromUtf8("\346\265\213\350\257\225\350\277\236\346\216\245"));

        // Update status if not monitoring
        if (!m_monitor->isMonitoring()) {
            updateStatus(QString::fromUtf8("\345\260\261\347\273\252"));
        } else {
            updateStatus(QString::fromUtf8("\347\233\221\346\216\247\344\270\255..."));
        }

        // Update server history combo placeholder
        if (ui->serverHistoryCombo->count() > 0) {
            ui->serverHistoryCombo->setItemText(0, QString::fromUtf8("-- \351\200\211\346\213\251\345\267\262\344\277\235\345\255\230\347\232\204\346\234\215\345\212\241\345\231\250 --"));
        }
    } else {
        // English translations
        setWindowTitle("OpenProxifier");
        ui->proxyGroup->setTitle("SOCKS5 Proxy Settings");
        ui->historyLabel->setText("History:");
        ui->saveServerButton->setText("Save");
        ui->deleteServerButton->setText("Delete");
        ui->hostLabel->setText("Server:");
        ui->portLabel->setText("Port:");
        ui->authCheckBox->setText("Require Authentication");
        ui->userLabel->setText("Username:");
        ui->passLabel->setText("Password:");
        ui->targetGroup->setTitle("Target Processes (Auto-Monitor)");
        ui->exeNameEdit->setPlaceholderText("Enter exe name (e.g., Antigravity.exe)");
        ui->addExeButton->setText("Add");
        ui->removeExeButton->setText("Remove");
        ui->autoStartCheckBox->setText("Auto-start monitoring on launch");
        ui->startMonitorButton->setText("Start Monitoring");
        ui->stopMonitorButton->setText("Stop Monitoring");
        ui->startMonitorButton->setToolTip("Monitor system for target processes and auto-inject");
        ui->logGroup->setTitle("Activity Log");
        ui->testServerButton->setText("Test Connection");

        // Update status if not monitoring
        if (!m_monitor->isMonitoring()) {
            updateStatus("Ready");
        } else {
            updateStatus("Monitoring...");
        }

        // Update server history combo placeholder
        if (ui->serverHistoryCombo->count() > 0) {
            ui->serverHistoryCombo->setItemText(0, "-- Select saved server --");
        }
    }
}

void MainWindow::onTestServerClicked()
{
    QString host = ui->proxyHostEdit->text().trimmed();
    if (host.isEmpty()) {
        ui->connectionStatusLabel->setText(tr_log("Please enter server address",
                                                   QString::fromUtf8("\350\257\267\350\276\223\345\205\245\346\234\215\345\212\241\345\231\250\345\234\260\345\235\200")));
        ui->connectionStatusLabel->setStyleSheet("color: orange;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        return;
    }

    // Validate IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, host.toStdString().c_str(), &addr) != 1) {
        ui->connectionStatusLabel->setText(tr_log("Invalid IP address",
                                                   QString::fromUtf8("\346\227\240\346\225\210\347\232\204IP\345\234\260\345\235\200")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        return;
    }

    int port = ui->proxyPortSpin->value();

    // Show testing status
    ui->connectionStatusLabel->setText(tr_log("Testing...", QString::fromUtf8("\346\265\213\350\257\225\344\270\255...")));
    ui->connectionStatusLabel->setStyleSheet("color: blue;");
    ui->testServerButton->setEnabled(false);
    QCoreApplication::processEvents();

    appendLog(tr_log(QString("Testing connection to %1:%2...").arg(host).arg(port),
                     QString::fromUtf8("\346\265\213\350\257\225\350\277\236\346\216\245 %1:%2...").arg(host).arg(port)));

    // Initialize Winsock if needed
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        ui->connectionStatusLabel->setText(tr_log("Socket error",
                                                   QString::fromUtf8("\345\245\227\346\216\245\345\255\227\351\224\231\350\257\257")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        ui->testServerButton->setEnabled(true);
        appendLog(tr_log("[ERROR] Failed to create socket",
                         QString::fromUtf8("[ERROR] \345\210\233\345\273\272\345\245\227\346\216\245\345\255\227\345\244\261\350\264\245")));
        return;
    }

    // Set timeout (3 seconds)
    DWORD timeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // Connect to proxy server
    sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = addr.s_addr;
    proxyAddr.sin_port = htons(static_cast<uint16_t>(port));

    int result = ::connect(sock, reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr));
    if (result == SOCKET_ERROR) {
        closesocket(sock);
        ui->connectionStatusLabel->setText(tr_log("Connection failed",
                                                   QString::fromUtf8("\350\277\236\346\216\245\345\244\261\350\264\245")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        ui->testServerButton->setEnabled(true);
        appendLog(tr_log(QString("[ERROR] Cannot connect to %1:%2").arg(host).arg(port),
                         QString::fromUtf8("[ERROR] \346\227\240\346\263\225\350\277\236\346\216\245 %1:%2").arg(host).arg(port)));
        return;
    }

    // Try SOCKS5 handshake
    uint8_t greeting[3] = {0x05, 0x01, 0x00};  // SOCKS5, 1 method, no auth
    int sent = send(sock, reinterpret_cast<char*>(greeting), 3, 0);
    if (sent != 3) {
        closesocket(sock);
        ui->connectionStatusLabel->setText(tr_log("Handshake failed",
                                                   QString::fromUtf8("\346\217\241\346\211\213\345\244\261\350\264\245")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        ui->testServerButton->setEnabled(true);
        appendLog(tr_log("[ERROR] SOCKS5 handshake send failed",
                         QString::fromUtf8("[ERROR] SOCKS5 \346\217\241\346\211\213\345\217\221\351\200\201\345\244\261\350\264\245")));
        return;
    }

    // Receive response
    uint8_t response[2];
    int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);
    closesocket(sock);

    if (received != 2 || response[0] != 0x05) {
        ui->connectionStatusLabel->setText(tr_log("Not a SOCKS5 server",
                                                   QString::fromUtf8("\351\235\236SOCKS5\346\234\215\345\212\241\345\231\250")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        ui->testServerButton->setEnabled(true);
        appendLog(tr_log("[ERROR] Server is not a valid SOCKS5 proxy",
                         QString::fromUtf8("[ERROR] \346\234\215\345\212\241\345\231\250\344\270\215\346\230\257\346\234\211\346\225\210\347\232\204SOCKS5\344\273\243\347\220\206")));
        return;
    }

    // Success!
    ui->connectionStatusLabel->setText(tr_log("Connected", QString::fromUtf8("\345\267\262\350\277\236\346\216\245")));
    ui->connectionStatusLabel->setStyleSheet("color: green; font-weight: bold;");
    m_serverConnected = true;
    ui->startMonitorButton->setEnabled(true);
    ui->testServerButton->setEnabled(true);
    appendLog(tr_log(QString("[SUCCESS] SOCKS5 server %1:%2 is reachable").arg(host).arg(port),
                     QString::fromUtf8("[\346\210\220\345\212\237] SOCKS5 \346\234\215\345\212\241\345\231\250 %1:%2 \345\217\257\350\276\276").arg(host).arg(port)));
}

void MainWindow::onProxySettingsChanged()
{
    // When proxy settings change, mark as untested and disable monitoring
    m_serverConnected = false;
    ui->startMonitorButton->setEnabled(false);
    ui->connectionStatusLabel->setText(tr_log("Not tested", QString::fromUtf8("\346\234\252\346\265\213\350\257\225")));
    ui->connectionStatusLabel->setStyleSheet("color: gray;");
}
