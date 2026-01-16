#ifndef CONNECTIONTESTTHREAD_H
#define CONNECTIONTESTTHREAD_H

#include <QThread>
#include <QString>

class ConnectionTestThread : public QThread
{
    Q_OBJECT

public:
    ConnectionTestThread(const QString& host, int port, bool authRequired,
                         const QString& username, const QString& password, bool isChinese);

signals:
    void testCompleted(bool success, const QString& message, const QString& statusText, const QString& statusColor);

protected:
    void run() override;

private:
    QString m_host;
    int m_port;
    bool m_authRequired;
    QString m_username;
    QString m_password;
    bool m_isChinese;
};

#endif // CONNECTIONTESTTHREAD_H
