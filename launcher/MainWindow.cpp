// -*- coding: utf-8 -*-
#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "ProcessMonitor.h"
#include "ProxyEngineWrapper.h"
#include "ProxyConfig.h"
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <QDateTime>
#include <QLocale>
#include <QTimer>
#include <QProcess>
#include <QApplication>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>

// Connection test thread class
class ConnectionTestThread : public QThread
{
    Q_OBJECT

public:
    ConnectionTestThread(const QString& host, int port, bool authRequired,
                         const QString& username, const QString& password, bool isChinese)
        : m_host(host), m_port(port), m_authRequired(authRequired),
          m_username(username), m_password(password), m_isChinese(isChinese) {}

signals:
    void testCompleted(bool success, const QString& message, const QString& statusText, const QString& statusColor);

protected:
    void run() override
    {
        // Initialize Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        // Convert host to IP address
        struct in_addr addr;
        if (inet_pton(AF_INET, m_host.toStdString().c_str(), &addr) != 1) {
            QString msg = m_isChinese ? QStringLiteral("[错误] 无效的IP地址") : "[ERROR] Invalid IP address";
            QString statusText = m_isChinese ? QStringLiteral("无效的IP地址") : "Invalid IP address";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Create socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            QString msg = m_isChinese ? QStringLiteral("[错误] 创建套接字失败") : "[ERROR] Failed to create socket";
            QString statusText = m_isChinese ? QStringLiteral("套接字错误") : "Socket error";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Set timeout (10 seconds)
        DWORD timeout = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        // Connect to proxy server
        sockaddr_in proxyAddr;
        proxyAddr.sin_family = AF_INET;
        proxyAddr.sin_addr.s_addr = addr.s_addr;
        proxyAddr.sin_port = htons(static_cast<uint16_t>(m_port));

        int result = ::connect(sock, reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr));
        if (result == SOCKET_ERROR) {
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 无法连接 %1:%2").arg(m_host).arg(m_port) :
                QString("[ERROR] Cannot connect to %1:%2").arg(m_host).arg(m_port);
            QString statusText = m_isChinese ? QStringLiteral("连接失败") : "Connection failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // SOCKS5 handshake
        uint8_t greeting[4];
        int greetingLen;
        if (m_authRequired) {
            greeting[0] = 0x05;  // VER
            greeting[1] = 0x02;  // NMETHODS
            greeting[2] = 0x00;  // METHOD: no auth
            greeting[3] = 0x02;  // METHOD: username/password
            greetingLen = 4;
        } else {
            greeting[0] = 0x05;  // VER
            greeting[1] = 0x01;  // NMETHODS
            greeting[2] = 0x00;  // METHOD: no auth
            greetingLen = 3;
        }

        int sent = send(sock, reinterpret_cast<char*>(greeting), greetingLen, 0);
        if (sent != greetingLen) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] SOCKS5 握手发送失败") : "[ERROR] SOCKS5 handshake send failed";
            QString statusText = m_isChinese ? QStringLiteral("握手失败") : "Handshake failed";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Receive handshake response
        uint8_t response[2];
        int received = recv(sock, reinterpret_cast<char*>(response), 2, 0);

        if (received != 2 || response[0] != 0x05) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 服务器不是有效的SOCKS5代理") : "[ERROR] Server is not a valid SOCKS5 proxy";
            QString statusText = m_isChinese ? QStringLiteral("非SOCKS5服务器") : "Not a SOCKS5 server";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // Check server's chosen auth method
        if (response[1] == 0xFF) {
            closesocket(sock);
            QString msg = m_isChinese ? QStringLiteral("[错误] 服务器拒绝了所有认证方式") : "[ERROR] Server rejected all authentication methods";
            QString statusText = m_isChinese ? QStringLiteral("无可用认证方式") : "No acceptable auth";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        // If server requires username/password auth (0x02)
        if (response[1] == 0x02) {
            if (!m_authRequired || m_username.isEmpty()) {
                closesocket(sock);
                QString msg = m_isChinese ? QStringLiteral("[错误] 服务器需要认证但未提供") : "[ERROR] Server requires authentication but none provided";
                QString statusText = m_isChinese ? QStringLiteral("服务器需要认证") : "Auth required by server";
                emit testCompleted(false, msg, statusText, "orange");
                WSACleanup();
                return;
            }

            // RFC 1929 Username/Password Authentication
            std::string user = m_username.toStdString();
            std::string pass = m_password.toStdString();

            if (user.length() > 255 || pass.length() > 255) {
                closesocket(sock);
                QString msg = m_isChinese ? QStringLiteral("[错误] 用户名或密码过长") : "[ERROR] Credentials too long";
                QString statusText = m_isChinese ? QStringLiteral("凭证过长") : "Credentials too long";
                emit testCompleted(false, msg, statusText, "red");
                WSACleanup();
                return;
            }

            // Build auth request: VER(0x01) ULEN USERNAME PLEN PASSWORD
            std::vector<uint8_t> authReq;
            authReq.push_back(0x01);  // VER
            authReq.push_back(static_cast<uint8_t>(user.length()));
            authReq.insert(authReq.end(), user.begin(), user.end());
            authReq.push_back(static_cast<uint8_t>(pass.length()));
            authReq.insert(authReq.end(), pass.begin(), pass.end());

            sent = send(sock, reinterpret_cast<char*>(authReq.data()), static_cast<int>(authReq.size()), 0);
            if (sent != static_cast<int>(authReq.size())) {
                closesocket(sock);
                QString msg = m_isChinese ? QStringLiteral("[错误] 认证请求发送失败") : "[ERROR] Auth send failed";
                QString statusText = m_isChinese ? QStringLiteral("认证发送失败") : "Auth send failed";
                emit testCompleted(false, msg, statusText, "red");
                WSACleanup();
                return;
            }

            // Receive auth response: VER(0x01) STATUS
            uint8_t authResponse[2];
            received = recv(sock, reinterpret_cast<char*>(authResponse), 2, 0);
            if (received != 2 || authResponse[0] != 0x01) {
                closesocket(sock);
                QString msg = m_isChinese ? QStringLiteral("[错误] 认证响应格式错误") : "[ERROR] Auth response error";
                QString statusText = m_isChinese ? QStringLiteral("认证响应错误") : "Auth response error";
                emit testCompleted(false, msg, statusText, "red");
                WSACleanup();
                return;
            }

            if (authResponse[1] != 0x00) {
                closesocket(sock);
                QString msg = m_isChinese ? QStringLiteral("[错误] 认证失败 - 用户名或密码错误") : "[ERROR] Authentication failed - wrong username or password";
                QString statusText = m_isChinese ? QStringLiteral("认证失败 (密码错误)") : "Auth failed (wrong password)";
                emit testCompleted(false, msg, statusText, "red");
                WSACleanup();
                return;
            }
        } else if (response[1] != 0x00) {
            closesocket(sock);
            QString msg = m_isChinese ?
                QStringLiteral("[错误] 不支持的认证方式: 0x%1").arg(response[1], 2, 16, QChar('0')) :
                QString("[ERROR] Unsupported auth method: 0x%1").arg(response[1], 2, 16, QChar('0'));
            QString statusText = m_isChinese ? QStringLiteral("不支持的认证方式") : "Unsupported auth method";
            emit testCompleted(false, msg, statusText, "red");
            WSACleanup();
            return;
        }

        closesocket(sock);
        WSACleanup();

        // Success!
        QString msg = m_isChinese ?
            QStringLiteral("[成功] SOCKS5 服务器 %1:%2 可达%3").arg(m_host).arg(m_port).arg(m_authRequired ? QStringLiteral(" (已认证)") : "") :
            QString("[SUCCESS] SOCKS5 server %1:%2 is reachable%3").arg(m_host).arg(m_port).arg(m_authRequired ? " (authenticated)" : "");
        QString statusText = m_authRequired ?
            (m_isChinese ? QStringLiteral("已连接 (认证成功)") : "Connected (auth OK)") :
            (m_isChinese ? QStringLiteral("已连接") : "Connected");
        emit testCompleted(true, msg, statusText, "green; font-weight: bold");
    }

private:
    QString m_host;
    int m_port;
    bool m_authRequired;
    QString m_username;
    QString m_password;
    bool m_isChinese;
};


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_monitor(new ProcessMonitor(this))
    , m_engine(nullptr)
    , m_isChinese(false)
    , m_settings(new QSettings("OpenProxifier", "MiniProxifier", this))
    , m_serverConnected(false)
    , m_winDivertMode(true)  // Default to WinDivert mode
    , m_testThread(nullptr)
    , m_trayIcon(nullptr)
    , m_trayMenu(nullptr)
    , m_showAction(nullptr)
    , m_exitAction(nullptr)
    , m_forceQuit(false)
{
    ui->setupUi(this);

    // Setup system tray
    setupTrayIcon();

    // Setup WinDivert engine connections
    setupWinDivertConnections();

    // Setup language selector
    ui->languageCombo->addItem("English", "en");
    ui->languageCombo->addItem(QStringLiteral("中文"), "zh");

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

    // Connect launch test app button
    connect(ui->launchTestAppButton, &QPushButton::clicked, this, &MainWindow::onLaunchTestAppClicked);

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
        appendLog("[ERROR] Hook DLL not found!");
    }

    // Load settings (includes server history and target list)
    loadSettings();

    // Auto-add ProxyTestApp.exe as default target if list is empty
    if (ui->exeListWidget->count() == 0) {
        ui->exeListWidget->addItem("ProxyTestApp.exe");
        appendLog(tr_log("Added default target: ProxyTestApp.exe",
                         QStringLiteral("已添加默认目标: ProxyTestApp.exe")));
    }

    // Apply initial language
    retranslateUi();

    // Initial connection status
    ui->connectionStatusLabel->setText(tr_log("Not tested", QStringLiteral("未测试")));
    ui->connectionStatusLabel->setStyleSheet("color: gray;");

    updateStatus(tr_log("Ready", QStringLiteral("就绪")));

    // Only auto-test and auto-start if autoStart is enabled
    // Don't auto-test on startup - user's machine may not have our default proxy
    if (ui->autoStartCheckBox->isChecked()) {
        QTimer::singleShot(500, this, [this]() {
            onTestServerClicked();
            if (m_serverConnected) {
                onStartMonitorClicked();
            } else {
                appendLog(tr_log("[WARNING] Auto-start failed: SOCKS5 server unreachable",
                                 QStringLiteral("[警告] 自动启动失败: SOCKS5 服务器不可达")));
            }
        });
    }
}

MainWindow::~MainWindow()
{
    // Clean up test thread
    if (m_testThread) {
        if (m_testThread->isRunning()) {
            m_testThread->wait(2000);  // Wait up to 2 seconds
            if (m_testThread->isRunning()) {
                m_testThread->terminate();
                m_testThread->wait();
            }
        }
        delete m_testThread;
        m_testThread = nullptr;
    }

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

    // Ensure settings are written to disk
    m_settings->sync();
}

void MainWindow::loadServerHistory()
{
    ui->serverHistoryCombo->clear();
    ui->serverHistoryCombo->addItem(tr_log("-- Select saved server --",
                                           QStringLiteral("-- 选择已保存的服务器 --")));

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

    // If monitoring is active, stop it first
    if (m_winDivertMode) {
        stopWinDivertMode();
        appendLog(tr_log("Monitoring stopped due to server change.",
                         QStringLiteral("因切换服务器，监控已停止。")));
    } else if (m_monitor->isMonitoring()) {
        m_monitor->stopMonitoring();
        appendLog(tr_log("Monitoring stopped due to server change.",
                         QStringLiteral("因切换服务器，监控已停止。")));
    }

    // Reset connection state - need to re-test
    m_serverConnected = false;
    ui->startMonitorButton->setEnabled(false);

    QVariantMap data = ui->serverHistoryCombo->itemData(index).toMap();
    if (data.isEmpty()) return;

    ui->proxyHostEdit->setText(data["host"].toString());
    ui->proxyPortSpin->setValue(data["port"].toInt());
    ui->authCheckBox->setChecked(data["auth"].toBool());
    ui->usernameEdit->setText(data["user"].toString());
    ui->passwordEdit->setText(data["pass"].toString());

    appendLog(tr_log(QString("Loaded server: %1").arg(ui->serverHistoryCombo->currentText()),
                     QStringLiteral("已加载服务器: %1").arg(ui->serverHistoryCombo->currentText())));
}

void MainWindow::onSaveServerClicked()
{
    QString host = ui->proxyHostEdit->text().trimmed();
    if (host.isEmpty()) {
        QMessageBox::warning(this,
            tr_log("Error", QStringLiteral("错误")),
            tr_log("Please enter a server address first.",
                   QStringLiteral("请先输入服务器地址。")));
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
                             QStringLiteral("已更新服务器: %1").arg(displayName)));
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
                     QStringLiteral("已保存服务器: %1").arg(displayName)));
}

void MainWindow::onDeleteServerClicked()
{
    int index = ui->serverHistoryCombo->currentIndex();
    if (index <= 0) {
        QMessageBox::warning(this,
            tr_log("Error", QStringLiteral("错误")),
            tr_log("Please select a saved server to delete.",
                   QStringLiteral("请选择要删除的服务器。")));
        return;
    }

    QString name = ui->serverHistoryCombo->currentText();
    ui->serverHistoryCombo->removeItem(index);

    appendLog(tr_log(QString("Deleted server: %1").arg(name),
                     QStringLiteral("已删除服务器: %1").arg(name)));
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
                tr_log("Duplicate", QStringLiteral("重复")),
                tr_log("This executable is already in the list.",
                       QStringLiteral("该程序已在列表中。")));
            return;
        }
    }

    ui->exeListWidget->addItem(exeName);
    ui->exeNameEdit->clear();

    // If monitoring is active, add to monitor and inject immediately
    if (m_monitor->isMonitoring()) {
        m_monitor->addTargetProcess(exeName, true);  // true = inject into running instances now
        appendLog(tr_log(QString("Added target: %1 (scanning for running instances...)").arg(exeName),
                         QStringLiteral("已添加目标: %1 (正在扫描运行中的实例...)").arg(exeName)));
    } else {
        appendLog(tr_log(QString("Added target: %1").arg(exeName),
                         QStringLiteral("已添加目标: %1").arg(exeName)));
    }

    // Save settings immediately
    saveSettings();
}

void MainWindow::onRemoveExeClicked()
{
    QListWidgetItem* item = ui->exeListWidget->currentItem();
    if (item) {
        QString exeName = item->text();
        delete ui->exeListWidget->takeItem(ui->exeListWidget->row(item));

        // If monitoring is active, remove from monitor too
        if (m_monitor->isMonitoring()) {
            m_monitor->removeTargetProcess(exeName);
        }

        appendLog(tr_log(QString("Removed target: %1").arg(exeName),
                         QStringLiteral("已删除目标: %1").arg(exeName)));

        // Save settings immediately
        saveSettings();
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

    // Test connection first before starting monitoring
    if (!m_serverConnected) {
        appendLog(tr_log("Testing connection before starting...",
                         QStringLiteral("启动前测试连接...")));
        onTestServerClicked();

        // Check if connection succeeded
        if (!m_serverConnected) {
            QMessageBox::warning(this,
                tr_log("Connection Failed", QStringLiteral("连接失败")),
                tr_log("Cannot start monitoring: SOCKS5 proxy server is unreachable. Please check your proxy settings and try again.",
                       QStringLiteral("无法启动监控: SOCKS5 代理服务器不可达。请检查代理设置后重试。")));
            return;
        }
    }

    // Use WinDivert mode by default (system-wide packet interception)
    if (m_winDivertMode) {
        startWinDivertMode();
        return;
    }

    // Legacy DLL injection mode
    if (ui->exeListWidget->count() == 0) {
        QMessageBox::warning(this,
            tr_log("No Targets", QStringLiteral("无目标")),
            tr_log("Please add at least one target executable to monitor.",
                   QStringLiteral("请至少添加一个目标程序。")));
        return;
    }

    QString dllPath = getHookDllPath();
    if (dllPath.isEmpty()) {
        QMessageBox::critical(this,
            tr_log("Error", QStringLiteral("错误")),
            tr_log("Hook DLL not found!", QStringLiteral("Hook DLL 未找到!")));
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
    if (m_winDivertMode) {
        stopWinDivertMode();
    } else {
        m_monitor->stopMonitoring();
    }
}

void MainWindow::onProcessDetected(const QString& exeName, unsigned long processId)
{
    appendLog(tr_log(QString("[DETECTED] %1 (PID: %2)").arg(exeName).arg(processId),
                     QStringLiteral("[检测到] %1 (PID: %2)").arg(exeName).arg(processId)));
}

void MainWindow::onInjectionResult(const QString& exeName, unsigned long processId, bool success, const QString& message)
{
    if (success) {
        appendLog(tr_log(QString("[SUCCESS] Injected into %1 (PID: %2)").arg(exeName).arg(processId),
                         QStringLiteral("[成功] 已注入 %1 (PID: %2)").arg(exeName).arg(processId)));
    } else {
        appendLog(tr_log(QString("[FAILED] %1 (PID: %2): %3").arg(exeName).arg(processId).arg(message),
                         QStringLiteral("[失败] %1 (PID: %2): %3").arg(exeName).arg(processId).arg(message)));
    }
}

void MainWindow::onMonitoringStarted()
{
    ui->startMonitorButton->setEnabled(false);
    ui->stopMonitorButton->setEnabled(true);
    ui->proxyGroup->setEnabled(false);
    // Keep add/remove functionality enabled during monitoring
    ui->exeNameEdit->setEnabled(true);
    ui->addExeButton->setEnabled(true);
    ui->removeExeButton->setEnabled(true);
    ui->exeListWidget->setEnabled(true);
    ui->autoStartCheckBox->setEnabled(false);
    updateStatus(tr_log("Monitoring...", QStringLiteral("监控中...")));
    appendLog(tr_log("[INFO] Monitoring started - waiting for target processes...",
                     QStringLiteral("[信息] 监控已启动 - 等待目标进程...")));
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
    updateStatus(tr_log("Ready", QStringLiteral("就绪")));
    appendLog(tr_log("[INFO] Monitoring stopped",
                     QStringLiteral("[信息] 监控已停止")));
}

void MainWindow::onMonitorError(const QString& message)
{
    appendLog(QString("[ERROR] %1").arg(message));
    QMessageBox::critical(this,
        tr_log("Error", QStringLiteral("错误")),
        message);
}

void MainWindow::updateStatus(const QString& message)
{
    ui->statusLabel->setText(tr_log("Status: ", QStringLiteral("状态: ")) + message);
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
            tr_log("Validation Error", QStringLiteral("验证错误")),
            tr_log("Please enter proxy server address.",
                   QStringLiteral("请输入代理服务器地址。")));
        return false;
    }

    // Validate IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, ui->proxyHostEdit->text().toStdString().c_str(), &addr) != 1) {
        QMessageBox::warning(this,
            tr_log("Validation Error", QStringLiteral("验证错误")),
            tr_log("Invalid proxy IP address.",
                   QStringLiteral("无效的代理IP地址。")));
        return false;
    }

    if (ui->authCheckBox->isChecked()) {
        if (ui->usernameEdit->text().isEmpty()) {
            QMessageBox::warning(this,
                tr_log("Validation Error", QStringLiteral("验证错误")),
                tr_log("Please enter username for authentication.",
                       QStringLiteral("请输入认证用户名。")));
            return false;
        }
    }

    return true;
}

QString MainWindow::getHookDllPath()
{
    QString appDir = QCoreApplication::applicationDirPath();

#ifdef _WIN64
    QString dllName = "OpenProxifierHook_x64.dll";
#else
    QString dllName = "OpenProxifierHook_x86.dll";
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
                     QStringLiteral("语言已切换为中文")));
}

void MainWindow::retranslateUi()
{
    if (m_isChinese) {
        // Chinese translations
        setWindowTitle("OpenProxifier");
        ui->proxyGroup->setTitle(QStringLiteral("SOCKS5 代理设置"));
        ui->historyLabel->setText(QStringLiteral("历史:"));
        ui->saveServerButton->setText(QStringLiteral("保存"));
        ui->deleteServerButton->setText(QStringLiteral("删除"));
        ui->hostLabel->setText(QStringLiteral("服务器:"));
        ui->portLabel->setText(QStringLiteral("端口:"));
        ui->authCheckBox->setText(QStringLiteral("需要身份验证"));
        ui->userLabel->setText(QStringLiteral("用户名:"));
        ui->passLabel->setText(QStringLiteral("密码:"));
        ui->targetGroup->setTitle(QStringLiteral("目标进程 (自动监控)"));
        ui->exeNameEdit->setPlaceholderText(QStringLiteral("输入程序名 (例如: ProxyTestApp.exe)"));
        ui->addExeButton->setText(QStringLiteral("添加"));
        ui->removeExeButton->setText(QStringLiteral("删除"));
        ui->autoStartCheckBox->setText(QStringLiteral("启动时自动开始监控"));
        ui->startMonitorButton->setText(QStringLiteral("开始监控"));
        ui->stopMonitorButton->setText(QStringLiteral("停止监控"));
        ui->startMonitorButton->setToolTip(QStringLiteral("监控系统中的目标进程并自动注入"));
        ui->logGroup->setTitle(QStringLiteral("活动日志"));
        ui->testServerButton->setText(QStringLiteral("测试连接"));
        ui->launchTestAppButton->setText(QStringLiteral("启动测试程序"));

        // Update status if not monitoring
        if (!m_monitor->isMonitoring()) {
            updateStatus(QStringLiteral("就绪"));
        } else {
            updateStatus(QStringLiteral("监控中..."));
        }

        // Update server history combo placeholder
        if (ui->serverHistoryCombo->count() > 0) {
            ui->serverHistoryCombo->setItemText(0, QStringLiteral("-- 选择已保存的服务器 --"));
        }

        // Update tray menu
        if (m_showAction) {
            m_showAction->setText(QStringLiteral("显示"));
        }
        if (m_exitAction) {
            m_exitAction->setText(QStringLiteral("退出"));
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
        ui->exeNameEdit->setPlaceholderText("Enter exe name (e.g., ProxyTestApp.exe)");
        ui->addExeButton->setText("Add");
        ui->removeExeButton->setText("Remove");
        ui->autoStartCheckBox->setText("Auto-start monitoring on launch");
        ui->startMonitorButton->setText("Start Monitoring");
        ui->stopMonitorButton->setText("Stop Monitoring");
        ui->startMonitorButton->setToolTip("Monitor system for target processes and auto-inject");
        ui->logGroup->setTitle("Activity Log");
        ui->testServerButton->setText("Test Connection");
        ui->launchTestAppButton->setText("Launch Test App");

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

        // Update tray menu
        if (m_showAction) {
            m_showAction->setText("Show");
        }
        if (m_exitAction) {
            m_exitAction->setText("Exit");
        }
    }
}

void MainWindow::onTestServerClicked()
{
    // If a test is already running, ignore
    if (m_testThread && m_testThread->isRunning()) {
        return;
    }

    QString host = ui->proxyHostEdit->text().trimmed();
    if (host.isEmpty()) {
        ui->connectionStatusLabel->setText(tr_log("Please enter server address",
                                                   QStringLiteral("请输入服务器地址")));
        ui->connectionStatusLabel->setStyleSheet("color: orange;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        return;
    }

    // Basic validation
    struct in_addr addr;
    if (inet_pton(AF_INET, host.toStdString().c_str(), &addr) != 1) {
        ui->connectionStatusLabel->setText(tr_log("Invalid IP address",
                                                   QStringLiteral("无效的IP地址")));
        ui->connectionStatusLabel->setStyleSheet("color: red;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        return;
    }

    bool authRequired = ui->authCheckBox->isChecked();
    QString username = ui->usernameEdit->text();
    QString password = ui->passwordEdit->text();

    if (authRequired && username.isEmpty()) {
        ui->connectionStatusLabel->setText(tr_log("Username required",
                                                   QStringLiteral("需要用户名")));
        ui->connectionStatusLabel->setStyleSheet("color: orange;");
        m_serverConnected = false;
        ui->startMonitorButton->setEnabled(false);
        return;
    }

    int port = ui->proxyPortSpin->value();

    // Show testing status
    ui->connectionStatusLabel->setText(tr_log("Testing...", QStringLiteral("测试中...")));
    ui->connectionStatusLabel->setStyleSheet("color: blue;");
    ui->testServerButton->setEnabled(false);

    appendLog(tr_log(QString("Testing connection to %1:%2%3...").arg(host).arg(port).arg(authRequired ? " (with auth)" : ""),
                     QStringLiteral("测试连接 %1:%2%3...").arg(host).arg(port).arg(authRequired ? QStringLiteral(" (带认证)") : "")));

    // Clean up old thread if exists
    if (m_testThread) {
        delete m_testThread;
        m_testThread = nullptr;
    }

    // Create and start test thread
    m_testThread = new ConnectionTestThread(host, port, authRequired, username, password, m_isChinese);
    connect(m_testThread, &ConnectionTestThread::testCompleted,
            this, &MainWindow::onTestCompleted, Qt::QueuedConnection);
    connect(m_testThread, &ConnectionTestThread::finished,
            m_testThread, &QObject::deleteLater);
    m_testThread->start();
}

void MainWindow::onTestCompleted(bool success, const QString& message, const QString& statusText, const QString& statusColor)
{
    // Update connection status
    m_serverConnected = success;
    ui->connectionStatusLabel->setText(statusText);
    ui->connectionStatusLabel->setStyleSheet(QString("color: %1;").arg(statusColor));

    // Log the result
    appendLog(message);

    // Re-enable test button
    ui->testServerButton->setEnabled(true);

    // Enable/disable monitoring button based on connection success
    bool isCurrentlyMonitoring = (m_engine && m_engine->isRunning()) || m_monitor->isMonitoring();
    if (!isCurrentlyMonitoring) {
        ui->startMonitorButton->setEnabled(success);
    }
}

void MainWindow::onProxySettingsChanged()
{
    // If monitoring is active, stop it first
    if (m_winDivertMode) {
        stopWinDivertMode();
        appendLog(tr_log("Monitoring stopped due to proxy settings change.",
                         QStringLiteral("因代理设置更改，监控已停止。")));
    } else if (m_monitor->isMonitoring()) {
        m_monitor->stopMonitoring();
        appendLog(tr_log("Monitoring stopped due to proxy settings change.",
                         QStringLiteral("因代理设置更改，监控已停止。")));
    }

    // When proxy settings change, mark as untested and disable monitoring
    m_serverConnected = false;
    ui->startMonitorButton->setEnabled(false);
    ui->connectionStatusLabel->setText(tr_log("Not tested", QStringLiteral("未测试")));
    ui->connectionStatusLabel->setStyleSheet("color: gray;");
}

void MainWindow::onLaunchTestAppClicked()
{
    QString appDir = QCoreApplication::applicationDirPath();
    QString testAppPath = QDir(appDir).filePath("ProxyTestApp.exe");

    if (!QFile::exists(testAppPath)) {
        QMessageBox::warning(this,
            tr_log("Error", QStringLiteral("错误")),
            tr_log("ProxyTestApp.exe not found in application directory.",
                   QStringLiteral("在程序目录中未找到 ProxyTestApp.exe。")));
        return;
    }

    QProcess::startDetached(testAppPath, QStringList());
    appendLog(tr_log("Launched ProxyTestApp.exe",
                     QStringLiteral("已启动 ProxyTestApp.exe")));
}

void MainWindow::setupTrayIcon()
{
    // Create tray icon
    m_trayIcon = new QSystemTrayIcon(this);
    m_trayIcon->setIcon(QIcon(":/app_icon.png"));
    m_trayIcon->setToolTip("OpenProxifier");

    // Create tray menu
    m_trayMenu = new QMenu(this);
    m_showAction = m_trayMenu->addAction(tr_log("Show", QStringLiteral("显示")));
    m_trayMenu->addSeparator();
    m_exitAction = m_trayMenu->addAction(tr_log("Exit", QStringLiteral("退出")));

    m_trayIcon->setContextMenu(m_trayMenu);

    // Connect signals
    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);
    connect(m_showAction, &QAction::triggered, this, &MainWindow::bringToFront);
    connect(m_exitAction, &QAction::triggered, this, &MainWindow::onTrayExitClicked);

    m_trayIcon->show();

    // Set window icon
    setWindowIcon(QIcon(":/app_icon.png"));
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_forceQuit) {
        event->accept();
    } else {
        hide();
        m_trayIcon->showMessage(
            tr_log("OpenProxifier", QStringLiteral("OpenProxifier")),
            tr_log("Application minimized to system tray (bottom-right corner). Right-click tray icon to exit.",
                   QStringLiteral("程序已最小化到系统托盘（右下角）。右键点击托盘图标可退出。")),
            QSystemTrayIcon::Information,
            3000
        );
        event->ignore();
    }
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick ||
        reason == QSystemTrayIcon::Trigger) {
        // Toggle show/hide
        if (isVisible() && !isMinimized()) {
            hide();
        } else {
            bringToFront();
        }
    }
}

void MainWindow::onTrayExitClicked()
{
    m_forceQuit = true;
    // Stop monitoring before exit
    if (m_winDivertMode) {
        stopWinDivertMode();
    } else {
        m_monitor->stopMonitoring();
    }
    saveSettings();
    QApplication::quit();
}

void MainWindow::bringToFront()
{
    show();
    setWindowState(windowState() & ~Qt::WindowMinimized);
    activateWindow();
    raise();
}

// ============================================
// WinDivert Mode Implementation
// ============================================

void MainWindow::setupWinDivertConnections()
{
    m_engine = ProxyEngineWrapper::instance();

    connect(m_engine, &ProxyEngineWrapper::logMessage,
            this, &MainWindow::onEngineLogMessage);
    connect(m_engine, &ProxyEngineWrapper::connectionDetected,
            this, &MainWindow::onEngineConnectionDetected);
    connect(m_engine, &ProxyEngineWrapper::engineStarted,
            this, &MainWindow::onEngineStarted);
    connect(m_engine, &ProxyEngineWrapper::engineStopped,
            this, &MainWindow::onEngineStopped);
    connect(m_engine, &ProxyEngineWrapper::error,
            this, &MainWindow::onEngineError);
}

void MainWindow::onWinDivertModeChanged(int state)
{
    m_winDivertMode = (state == Qt::Checked);
    appendLog(tr_log(
        m_winDivertMode ? "Switched to WinDivert mode (system-wide)" : "Switched to DLL injection mode (per-process)",
        m_winDivertMode ? QStringLiteral("已切换到 WinDivert 模式 (系统级)") : QStringLiteral("已切换到 DLL 注入模式 (进程级)")
    ));
}

void MainWindow::onEngineLogMessage(const QString& message)
{
    appendLog(message);
}

void MainWindow::onEngineConnectionDetected(const QString& process, uint32_t pid,
                                             const QString& destIp, uint16_t destPort,
                                             const QString& status)
{
    // Skip DIRECT connections to reduce log noise
    if (status.startsWith("DIRECT")) {
        return;
    }

    QString msg = QString("[%1] %2 (PID:%3) -> %4:%5 [%6]")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(process)
        .arg(pid)
        .arg(destIp)
        .arg(destPort)
        .arg(status);
    appendLog(msg);
}

void MainWindow::onEngineStarted()
{
    ui->startMonitorButton->setEnabled(false);
    ui->stopMonitorButton->setEnabled(true);
    updateStatus(tr_log("WinDivert engine running", QStringLiteral("WinDivert 引擎运行中")));
    appendLog(tr_log("[SUCCESS] WinDivert engine started", QStringLiteral("[成功] WinDivert 引擎已启动")));
}

void MainWindow::onEngineStopped()
{
    ui->startMonitorButton->setEnabled(true);
    ui->stopMonitorButton->setEnabled(false);
    updateStatus(tr_log("Stopped", QStringLiteral("已停止")));
    appendLog(tr_log("[INFO] WinDivert engine stopped", QStringLiteral("[信息] WinDivert 引擎已停止")));
}

void MainWindow::onEngineError(const QString& message)
{
    appendLog(QString("[ERROR] %1").arg(message));
    QMessageBox::critical(this,
        tr_log("Engine Error", QStringLiteral("引擎错误")),
        message);
}

void MainWindow::startWinDivertMode()
{
    if (!m_engine) {
        m_engine = ProxyEngineWrapper::instance();
        setupWinDivertConnections();
    }

    // Initialize engine
    if (!m_engine->init()) {
        return;
    }

    // Set proxy configuration
    QString host = ui->proxyHostEdit->text().trimmed();
    int port = ui->proxyPortSpin->value();
    QString username = ui->authCheckBox->isChecked() ? ui->usernameEdit->text() : QString();
    QString password = ui->authCheckBox->isChecked() ? ui->passwordEdit->text() : QString();

    if (!m_engine->setProxy(PROXY_TYPE_SOCKS5, host, port, username, password)) {
        return;
    }

    // Clear existing rules and add new ones based on exe list
    m_engine->clearRules();

    if (ui->exeListWidget->count() == 0) {
        // No specific targets, proxy all traffic
        m_engine->addRule("*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY);
        appendLog(tr_log("[INFO] No specific targets, proxying all traffic",
                         QStringLiteral("[信息] 未指定目标程序，代理所有流量")));
    } else {
        // Add rules for each target process
        for (int i = 0; i < ui->exeListWidget->count(); ++i) {
            QString exeName = ui->exeListWidget->item(i)->text();
            m_engine->addRule(exeName, "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY);
        }
    }

    // Start engine
    m_engine->start();
}

void MainWindow::stopWinDivertMode()
{
    if (m_engine && m_engine->isRunning()) {
        m_engine->stop();
    }
}

// Include moc for embedded Q_OBJECT class (ConnectionTestThread)
#include "MainWindow.moc"
