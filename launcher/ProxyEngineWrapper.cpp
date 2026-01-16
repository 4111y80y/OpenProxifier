#include "ProxyEngineWrapper.h"
#include <QCoreApplication>

ProxyEngineWrapper* ProxyEngineWrapper::s_instance = nullptr;

ProxyEngineWrapper* ProxyEngineWrapper::instance()
{
    if (!s_instance) {
        s_instance = new ProxyEngineWrapper(qApp);
    }
    return s_instance;
}

ProxyEngineWrapper::ProxyEngineWrapper(QObject* parent)
    : QObject(parent)
    , m_initialized(false)
    , m_running(false)
    , m_proxyPort(0)
    , m_proxyType(PROXY_TYPE_SOCKS5)
{
}

ProxyEngineWrapper::~ProxyEngineWrapper()
{
    if (m_running) {
        stop();
    }
    if (m_initialized) {
        cleanup();
    }
    s_instance = nullptr;
}

void ProxyEngineWrapper::staticLogCallback(const char* message)
{
    if (s_instance) {
        QString msg = QString::fromUtf8(message);
        // Use QueuedConnection to ensure thread safety
        QMetaObject::invokeMethod(s_instance, [msg]() {
            emit s_instance->logMessage(msg);
        }, Qt::QueuedConnection);
    }
}

void ProxyEngineWrapper::staticConnectionCallback(const char* process, uint32_t pid,
                                                   const char* dest_ip, uint16_t dest_port,
                                                   const char* status)
{
    if (s_instance) {
        QString proc = QString::fromUtf8(process);
        QString ip = QString::fromUtf8(dest_ip);
        QString stat = QString::fromUtf8(status);
        QMetaObject::invokeMethod(s_instance, [proc, pid, ip, dest_port, stat]() {
            emit s_instance->connectionDetected(proc, pid, ip, dest_port, stat);
        }, Qt::QueuedConnection);
    }
}

bool ProxyEngineWrapper::init()
{
    if (m_initialized) {
        return true;
    }

    // Set callbacks before init
    ProxyEngine_SetLogCallback(staticLogCallback);
    ProxyEngine_SetConnectionCallback(staticConnectionCallback);

    if (!ProxyEngine_Init()) {
        emit error("Failed to initialize ProxyEngine");
        return false;
    }

    m_initialized = true;
    return true;
}

void ProxyEngineWrapper::cleanup()
{
    if (!m_initialized) {
        return;
    }

    if (m_running) {
        stop();
    }

    ProxyEngine_Cleanup();
    m_initialized = false;
}

bool ProxyEngineWrapper::setProxy(ProxyType type, const QString& host, uint16_t port,
                                   const QString& username, const QString& password)
{
    if (host.isEmpty() || port == 0) {
        emit error("Invalid proxy settings");
        return false;
    }

    const char* user = username.isEmpty() ? nullptr : username.toUtf8().constData();
    const char* pass = password.isEmpty() ? nullptr : password.toUtf8().constData();

    // Store proxy info for getter
    QByteArray hostBytes = host.toUtf8();
    QByteArray userBytes = username.toUtf8();
    QByteArray passBytes = password.toUtf8();

    if (!ProxyEngine_SetProxy(type, hostBytes.constData(), port,
                               userBytes.isEmpty() ? nullptr : userBytes.constData(),
                               passBytes.isEmpty() ? nullptr : passBytes.constData())) {
        emit error("Failed to set proxy");
        return false;
    }

    m_proxyHost = host;
    m_proxyPort = port;
    m_proxyType = type;

    return true;
}

void ProxyEngineWrapper::setDnsViaProxy(bool enable)
{
    ProxyEngine_SetDnsViaProxy(enable);
}

uint32_t ProxyEngineWrapper::addRule(const QString& process, const QString& hosts,
                                      const QString& ports, RuleProtocol proto, RuleAction action)
{
    QByteArray processBytes = process.toUtf8();
    QByteArray hostsBytes = hosts.toUtf8();
    QByteArray portsBytes = ports.toUtf8();

    uint32_t ruleId = ProxyEngine_AddRule(
        processBytes.constData(),
        hostsBytes.constData(),
        portsBytes.constData(),
        proto, action);

    if (ruleId > 0) {
        ProxyRule rule;
        rule.id = ruleId;
        rule.process = process;
        rule.hosts = hosts;
        rule.ports = ports;
        rule.protocol = proto;
        rule.action = action;
        rule.enabled = true;
        m_rules.append(rule);
    }

    return ruleId;
}

bool ProxyEngineWrapper::removeRule(uint32_t ruleId)
{
    if (ProxyEngine_RemoveRule(ruleId)) {
        for (int i = 0; i < m_rules.size(); ++i) {
            if (m_rules[i].id == ruleId) {
                m_rules.removeAt(i);
                break;
            }
        }
        return true;
    }
    return false;
}

bool ProxyEngineWrapper::enableRule(uint32_t ruleId, bool enable)
{
    if (ProxyEngine_EnableRule(ruleId, enable)) {
        for (int i = 0; i < m_rules.size(); ++i) {
            if (m_rules[i].id == ruleId) {
                m_rules[i].enabled = enable;
                break;
            }
        }
        return true;
    }
    return false;
}

void ProxyEngineWrapper::clearRules()
{
    ProxyEngine_ClearRules();
    m_rules.clear();
}

bool ProxyEngineWrapper::start()
{
    if (!m_initialized) {
        if (!init()) {
            return false;
        }
    }

    if (m_running) {
        return true;
    }

    if (!ProxyEngine_Start()) {
        emit error("Failed to start ProxyEngine");
        return false;
    }

    m_running = true;
    emit engineStarted();
    return true;
}

bool ProxyEngineWrapper::stop()
{
    if (!m_running) {
        return true;
    }

    if (!ProxyEngine_Stop()) {
        emit error("Failed to stop ProxyEngine");
        return false;
    }

    m_running = false;
    emit engineStopped();
    return true;
}

bool ProxyEngineWrapper::isRunning() const
{
    return m_running && ProxyEngine_IsRunning();
}
