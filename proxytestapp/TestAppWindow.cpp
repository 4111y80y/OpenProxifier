// -*- coding: utf-8 -*-
#include "TestAppWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkProxy>
#include <QLocale>

TestAppWindow::TestAppWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_autoCheckTimer(new QTimer(this))
    , m_requestPending(false)
    , m_isChinese(false)
    , m_autoCheckEnabled(true)
{
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
    setMinimumSize(420, 350);

    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    mainLayout->setSpacing(10);

    m_ipGroup = new QGroupBox("Current IP Address", this);
    QVBoxLayout* ipLayout = new QVBoxLayout(m_ipGroup);

    m_ipLabel = new QLabel("Starting...", this);
    m_ipLabel->setAlignment(Qt::AlignCenter);
    m_ipLabel->setStyleSheet("font-size: 18px; font-weight: bold; padding: 20px;");
    ipLayout->addWidget(m_ipLabel);

    m_toggleButton = new QPushButton("Stop Auto-Check", this);
    m_toggleButton->setMinimumHeight(40);
    ipLayout->addWidget(m_toggleButton);
    mainLayout->addWidget(m_ipGroup);

    m_logGroup = new QGroupBox("Log", this);
    QVBoxLayout* logLayout = new QVBoxLayout(m_logGroup);
    m_logEdit = new QTextEdit(this);
    m_logEdit->setReadOnly(true);
    m_logEdit->setMinimumHeight(100);
    logLayout->addWidget(m_logEdit);
    mainLayout->addWidget(m_logGroup);

    QHBoxLayout* bottomLayout = new QHBoxLayout();
    bottomLayout->addStretch();
    m_languageCombo = new QComboBox(this);
    m_languageCombo->addItem("English", "en");
    m_languageCombo->addItem(QStringLiteral("中文"), "zh");
    m_languageCombo->setMinimumWidth(80);
    bottomLayout->addWidget(m_languageCombo);
    mainLayout->addLayout(bottomLayout);

    QString sysLang = QLocale::system().name();
    if (sysLang.startsWith("zh")) {
        m_languageCombo->setCurrentIndex(1);
        m_isChinese = true;
    } else {
        m_languageCombo->setCurrentIndex(0);
        m_isChinese = false;
    }

    connect(m_toggleButton, &QPushButton::clicked, this, &TestAppWindow::onToggleAutoCheck);
    connect(m_networkManager, &QNetworkAccessManager::finished, this, &TestAppWindow::onNetworkReply);
    connect(m_autoCheckTimer, &QTimer::timeout, this, &TestAppWindow::onAutoCheck);
    connect(m_languageCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TestAppWindow::onLanguageChanged);

    retranslateUi();
    updateToggleButton();
    
    appendLog(tr_log("ProxyTestApp started. Auto-checking IP every 5 seconds.",
                     QStringLiteral("ProxyTestApp 已启动。每5秒自动检查IP。")));
    appendLog(tr_log("If proxied via OpenProxifier, you will see VPN IP.",
                     QStringLiteral("如果通过 OpenProxifier 代理，您将看到 VPN IP。")));
    
    m_autoCheckTimer->start(5000);
    doCheckIp();
}

TestAppWindow::~TestAppWindow() {}

void TestAppWindow::onLanguageChanged(int index)
{
    m_isChinese = (index == 1);
    retranslateUi();
    updateToggleButton();
}

void TestAppWindow::retranslateUi()
{
    if (m_isChinese) {
        setWindowTitle(QStringLiteral("ProxyTestApp - IP 检查器"));
        m_ipGroup->setTitle(QStringLiteral("当前 IP 地址"));
        m_logGroup->setTitle(QStringLiteral("日志"));
    } else {
        setWindowTitle("ProxyTestApp - IP Checker");
        m_ipGroup->setTitle("Current IP Address");
        m_logGroup->setTitle("Log");
    }
}

void TestAppWindow::updateToggleButton()
{
    if (m_autoCheckEnabled) {
        m_toggleButton->setText(tr_log("Stop Auto-Check", QStringLiteral("停止自动检查")));
        m_toggleButton->setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; font-weight: bold; font-size: 14px; }"
            "QPushButton:hover { background-color: #da190b; }"
        );
    } else {
        m_toggleButton->setText(tr_log("Start Auto-Check", QStringLiteral("开始自动检查")));
        m_toggleButton->setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; font-size: 14px; }"
            "QPushButton:hover { background-color: #45a049; }"
        );
    }
}

QString TestAppWindow::tr_log(const QString& en, const QString& zh)
{
    return m_isChinese ? zh : en;
}

void TestAppWindow::onAutoCheck()
{
    if (!m_requestPending && m_autoCheckEnabled) {
        doCheckIp();
    }
}

void TestAppWindow::onToggleAutoCheck()
{
    m_autoCheckEnabled = !m_autoCheckEnabled;
    updateToggleButton();
    
    if (m_autoCheckEnabled) {
        appendLog(tr_log("Auto-check enabled (every 5 seconds)",
                         QStringLiteral("自动检查已开启 (每5秒)")));
        if (!m_requestPending) {
            doCheckIp();
        }
    } else {
        appendLog(tr_log("Auto-check disabled",
                         QStringLiteral("自动检查已关闭")));
    }
}

void TestAppWindow::doCheckIp()
{
    m_requestPending = true;
    appendLog(tr_log("Checking IP...", QStringLiteral("正在检查 IP...")));

    QNetworkRequest request(QUrl("http://httpbin.org/ip"));
    request.setHeader(QNetworkRequest::UserAgentHeader, "ProxyTestApp/1.0");
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setRawHeader("Connection", "close");
    m_networkManager->get(request);
}

void TestAppWindow::onNetworkReply(QNetworkReply* reply)
{
    m_requestPending = false;

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            QString origin = obj["origin"].toString();
            if (!origin.isEmpty()) {
                m_ipLabel->setText(origin);
                m_ipLabel->setStyleSheet("font-size: 24px; font-weight: bold; padding: 20px; color: #4CAF50;");
                appendLog(QString("IP: %1").arg(origin));
            } else {
                m_ipLabel->setText(tr_log("Parse error", QStringLiteral("解析错误")));
                appendLog(tr_log("[ERROR] Could not parse IP", QStringLiteral("[错误] 无法解析 IP")));
            }
        } else {
            m_ipLabel->setText(tr_log("Invalid response", QStringLiteral("无效响应")));
            appendLog(tr_log("[ERROR] Invalid JSON", QStringLiteral("[错误] 无效的 JSON")));
        }
    } else {
        QString errorMsg = reply->errorString();
        m_ipLabel->setText(tr_log("Error", QStringLiteral("错误")));
        m_ipLabel->setStyleSheet("font-size: 18px; font-weight: bold; padding: 20px; color: #f44336;");
        appendLog(QString("[ERROR] %1").arg(errorMsg));
    }
    reply->deleteLater();
}

void TestAppWindow::appendLog(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    m_logEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
}