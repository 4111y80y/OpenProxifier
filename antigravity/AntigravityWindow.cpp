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
{
    // Disable system proxy - only use proxy when injected by MiniProxifier
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
    setWindowTitle("Antigravity - IP Checker");
    setMinimumSize(400, 300);

    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    mainLayout->setSpacing(10);

    // IP Display Group
    QGroupBox* ipGroup = new QGroupBox("Current IP Address", this);
    QVBoxLayout* ipLayout = new QVBoxLayout(ipGroup);

    m_ipLabel = new QLabel("Click 'Check IP' to detect your IP address", this);
    m_ipLabel->setAlignment(Qt::AlignCenter);
    m_ipLabel->setStyleSheet("font-size: 18px; font-weight: bold; padding: 20px;");
    ipLayout->addWidget(m_ipLabel);

    m_checkButton = new QPushButton("Check IP", this);
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

    appendLog("Antigravity started. Click 'Check IP' to test proxy.");
    appendLog("If proxied, you should see the VPN/proxy IP.");
    appendLog("If not proxied, you will see your real IP.");
}

AntigravityWindow::~AntigravityWindow()
{
}

void AntigravityWindow::onCheckIpClicked()
{
    m_checkButton->setEnabled(false);
    m_checkButton->setText("Checking...");
    m_ipLabel->setText("Connecting to httpbin.org...");
    appendLog("Sending request to http://httpbin.org/ip ...");

    QNetworkRequest request(QUrl("http://httpbin.org/ip"));
    request.setHeader(QNetworkRequest::UserAgentHeader, "Antigravity/1.0");
    m_networkManager->get(request);
}

void AntigravityWindow::onNetworkReply(QNetworkReply* reply)
{
    m_checkButton->setEnabled(true);
    m_checkButton->setText("Check IP");

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray data = reply->readAll();
        appendLog(QString("Response: %1").arg(QString::fromUtf8(data).trimmed()));

        // Parse JSON response
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            QString origin = obj["origin"].toString();
            if (!origin.isEmpty()) {
                m_ipLabel->setText(origin);
                m_ipLabel->setStyleSheet("font-size: 24px; font-weight: bold; padding: 20px; color: #4CAF50;");
                appendLog(QString("[SUCCESS] Your IP: %1").arg(origin));
            } else {
                m_ipLabel->setText("Could not parse IP");
                appendLog("[ERROR] Could not parse IP from response");
            }
        } else {
            m_ipLabel->setText("Invalid response");
            appendLog("[ERROR] Invalid JSON response");
        }
    } else {
        QString errorMsg = reply->errorString();
        m_ipLabel->setText("Error: " + errorMsg);
        m_ipLabel->setStyleSheet("font-size: 14px; font-weight: bold; padding: 20px; color: #f44336;");
        appendLog(QString("[ERROR] Network error: %1").arg(errorMsg));
    }

    reply->deleteLater();
}

void AntigravityWindow::appendLog(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    m_logEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
}
