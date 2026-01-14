#ifndef ANTIGRAVITYWINDOW_H
#define ANTIGRAVITYWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>

class AntigravityWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit AntigravityWindow(QWidget *parent = nullptr);
    ~AntigravityWindow();

private slots:
    void onCheckIpClicked();
    void onNetworkReply(QNetworkReply* reply);
    void onAutoCheck();

private:
    QLabel* m_ipLabel;
    QPushButton* m_checkButton;
    QTextEdit* m_logEdit;
    QNetworkAccessManager* m_networkManager;
    QTimer* m_autoCheckTimer;
    bool m_requestPending;

    void appendLog(const QString& message);
    void doCheckIp();
};

#endif // ANTIGRAVITYWINDOW_H
