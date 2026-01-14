#include "AntigravityWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkProxy>

AntigravityWindow::AntigravityWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_autoCheckTimer(new QTimer(this))
    , m_requestPending(false)
{
    // Disable system proxy - only use proxy when injected by MiniProxifier
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);

    setWindowTitle("Antigravity - IP Checker (Auto: 5s)");
    setMinimumSize(400, 300);

    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    mainLayout->setSpacing(10);

    // IP Display Group
    QGroupBox* ipGroup = new QGroupBox("Current IP Address", this);
    QVBoxLayout* ipLayout = new QVBoxLayout(ipGroup);

    m_ipLabel = new QLabel("Starting...", this);
    m_ipLabel->setAlignment(Qt::AlignCenter);
    m_ipLabel->setStyleSheet("font-size: 18px; font-weight: bold; padding: 20px;");
    ipLayout->addWidget(m_ipLabel);

    m_checkButton = new QPushButton("Check Now", this);
    m_checkButton->setMinimumHeight(40);
    m_checkButton->setStyleSheet(
        "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; font-size: 14px; }"
        "QPushButton:hover { background-color: #45a049; }"
        "QPushButton:disabled { background-color: #cccccc; }"
    );
    ipLayout->addWidget(m_checkButton);

    mainLayout->addWidget(ipGroup);

    // Log Group
    QGroupBox* logGroup = new QGroupBox("Log", this);
    QVBoxLayout* logLayout = new QVBoxLayout(logGroup);

    m_logEdit = new QTextEdit(this);
    m_logEdit->setReadOnly(true);
    m_logEdit->setMinimumHeight(100);
    logLayout->addWidget(m_logEdit);

    mainLayout->addWidget(logGroup);

    // Connect signals
    connect(m_checkButton, &QPushButton::clicked, this, &AntigravityWindow::onCheckIpClicked);
    connect(m_networkManager, &QNetworkAccessManager::finished, this, &AntigravityWindow::onNetworkReply);
    connect(m_autoCheckTimer, &QTimer::timeout, this, &AntigravityWindow::onAutoCheck);

    appendLog("Antigravity started. Auto-checking IP every 5 seconds.");
    appendLog("If proxied via MiniProxifier, you will see VPN IP.");

    // Start auto-check timer (5 seconds)
    m_autoCheckTimer->start(5000);

    // Do first check immediately
    doCheckIp();
}

AntigravityWindow::~AntigravityWindow()
{
}

void AntigravityWindow::onAutoCheck()
{
    if (!m_requestPending) {
        doCheckIp();
    }
}

void AntigravityWindow::onCheckIpClicked()
{
    if (!m_requestPending) {
        doCheckIp();
    }
}

void AntigravityWindow::doCheckIp()
{
    m_requestPending = true;
    m_checkButton->setEnabled(false);
    m_checkButton->setText("Checking...");
    appendLog("Checking IP...");

    QNetworkRequest request(QUrl("http://httpbin.org/ip"));
    request.setHeader(QNetworkRequest::UserAgentHeader, "Antigravity/1.0");
    // Disable connection caching - force new connection each time
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setRawHeader("Connection", "close");
    m_networkManager->get(request);
}

void AntigravityWindow::onNetworkReply(QNetworkReply* reply)
{
    m_requestPending = false;
    m_checkButton->setEnabled(true);
    m_checkButton->setText("Check Now");

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();

        // Parse JSON response
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            QString origin = obj["origin"].toString();
            if (!origin.isEmpty()) {
                m_ipLabel->setText(origin);
                m_ipLabel->setStyleSheet("font-size: 24px; font-weight: bold; padding: 20px; color: #4CAF50;");
                appendLog(QString("IP: %1").arg(origin));
            } else {
                m_ipLabel->setText("Parse error");
                appendLog("[ERROR] Could not parse IP");
            }
        } else {
            m_ipLabel->setText("Invalid response");
            appendLog("[ERROR] Invalid JSON");
        }
    } else {
        QString errorMsg = reply->errorString();
        m_ipLabel->setText("Error");
        m_ipLabel->setStyleSheet("font-size: 18px; font-weight: bold; padding: 20px; color: #f44336;");
        appendLog(QString("[ERROR] %1").arg(errorMsg));
    }

    reply->deleteLater();
}

void AntigravityWindow::appendLog(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    m_logEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
}
