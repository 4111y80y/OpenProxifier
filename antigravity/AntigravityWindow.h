#ifndef ANTIGRAVITYWINDOW_H
#define ANTIGRAVITYWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class AntigravityWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit AntigravityWindow(QWidget *parent = nullptr);
    ~AntigravityWindow();

private slots:
    void onCheckIpClicked();
    void onNetworkReply(QNetworkReply* reply);

private:
    QLabel* m_ipLabel;
    QPushButton* m_checkButton;
    QTextEdit* m_logEdit;
    QNetworkAccessManager* m_networkManager;

    void appendLog(const QString& message);
};

#endif // ANTIGRAVITYWINDOW_H
