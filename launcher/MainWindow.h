#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onBrowseClicked();
    void onLaunchClicked();
    void onAuthCheckChanged(int state);

private:
    Ui::MainWindow *ui;

    void updateStatus(const QString& message);
    bool validateInput();
    QString getHookDllPath();
};

#endif // MAINWINDOW_H
