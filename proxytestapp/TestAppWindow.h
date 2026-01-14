#ifndef TESTAPPWINDOW_H
#define TESTAPPWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QComboBox>
#include <QGroupBox>

class TestAppWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit TestAppWindow(QWidget *parent = nullptr);
    ~TestAppWindow();

private slots:
    void onCheckIpClicked();
    void onNetworkReply(QNetworkReply* reply);
    void onAutoCheck();
    void onLanguageChanged(int index);

private:
    QLabel* m_ipLabel;
    QPushButton* m_checkButton;
    QTextEdit* m_logEdit;
    QNetworkAccessManager* m_networkManager;
    QTimer* m_autoCheckTimer;
    QComboBox* m_languageCombo;
    QGroupBox* m_ipGroup;
    QGroupBox* m_logGroup;
    bool m_requestPending;
    bool m_isChinese;

    void appendLog(const QString& message);
    void doCheckIp();
    void retranslateUi();
    QString tr_log(const QString& en, const QString& zh);
};

#endif // TESTAPPWINDOW_H
