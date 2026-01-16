#ifndef PROXYENGINEWRAPPER_H
#define PROXYENGINEWRAPPER_H

#include <QObject>
#include <QString>
#include <QList>

// Forward declaration for C API
extern "C" {
#include "../core/ProxyEngine.h"
}

struct ProxyRule {
    uint32_t id;
    QString process;
    QString hosts;
    QString ports;
    RuleProtocol protocol;
    RuleAction action;
    bool enabled;
};

class ProxyEngineWrapper : public QObject
{
    Q_OBJECT

public:
    static ProxyEngineWrapper* instance();

    // Initialize and cleanup
    bool init();
    void cleanup();

    // Proxy configuration
    bool setProxy(ProxyType type, const QString& host, uint16_t port,
                  const QString& username = QString(), const QString& password = QString());
    void setDnsViaProxy(bool enable);

    // Rule management
    uint32_t addRule(const QString& process, const QString& hosts,
                     const QString& ports, RuleProtocol proto, RuleAction action);
    bool removeRule(uint32_t ruleId);
    bool enableRule(uint32_t ruleId, bool enable);
    void clearRules();
    QList<ProxyRule> getRules() const { return m_rules; }

    // Start/Stop
    bool start();
    bool stop();
    bool isRunning() const;

    // Getters
    QString proxyHost() const { return m_proxyHost; }
    uint16_t proxyPort() const { return m_proxyPort; }
    ProxyType proxyType() const { return m_proxyType; }

signals:
    void logMessage(const QString& message);
    void connectionDetected(const QString& process, uint32_t pid,
                            const QString& destIp, uint16_t destPort,
                            const QString& status);
    void engineStarted();
    void engineStopped();
    void error(const QString& message);

private:
    explicit ProxyEngineWrapper(QObject* parent = nullptr);
    ~ProxyEngineWrapper();

    static ProxyEngineWrapper* s_instance;
    static void staticLogCallback(const char* message);
    static void staticConnectionCallback(const char* process, uint32_t pid,
                                         const char* dest_ip, uint16_t dest_port,
                                         const char* status);

    bool m_initialized;
    bool m_running;
    QString m_proxyHost;
    uint16_t m_proxyPort;
    ProxyType m_proxyType;
    QList<ProxyRule> m_rules;
};

#endif // PROXYENGINEWRAPPER_H
