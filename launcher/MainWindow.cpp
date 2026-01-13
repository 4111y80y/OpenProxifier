#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "Injector.h"
#include "ProxyConfig.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QCoreApplication>
#include <winsock2.h>
#include <ws2tcpip.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Connect signals
    connect(ui->browseButton, &QPushButton::clicked, this, &MainWindow::onBrowseClicked);
    connect(ui->launchButton, &QPushButton::clicked, this, &MainWindow::onLaunchClicked);
    connect(ui->authCheckBox, &QCheckBox::stateChanged, this, &MainWindow::onAuthCheckChanged);

    // Initial state
    ui->usernameEdit->setEnabled(false);
    ui->passwordEdit->setEnabled(false);

    // Set default values
    ui->exePathEdit->setText("C:\\Windows\\System32\\cmd.exe");
    ui->proxyHostEdit->setText("127.0.0.1");
    ui->proxyPortSpin->setValue(1081);
    ui->cmdLineEdit->setText("/k curl https://only-111033-113-74-8-82.nstool.321fenx.com/info.js?referer=https://nstool.netease.com/info.js");

    updateStatus("Ready");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onBrowseClicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select Executable", "", "Executable Files (*.exe);;All Files (*)");

    if (!fileName.isEmpty()) {
        ui->exePathEdit->setText(fileName);
    }
}

void MainWindow::onLaunchClicked()
{
    if (!validateInput()) {
        return;
    }

    QString exePath = ui->exePathEdit->text();
    QString cmdLine = ui->cmdLineEdit->text();
    QString proxyHost = ui->proxyHostEdit->text();
    int proxyPort = ui->proxyPortSpin->value();

    // Get hook DLL path
    QString dllPath = getHookDllPath();
    if (dllPath.isEmpty()) {
        QMessageBox::critical(this, "Error", "Hook DLL not found!");
        return;
    }

    // Debug: Show DLL path
    updateStatus(QString("DLL: %1").arg(dllPath));

    updateStatus("Launching process...");

    // Prepare proxy config
    ProxyConfig config;

    // Convert proxy host to IP
    struct in_addr addr;
    if (inet_pton(AF_INET, proxyHost.toStdString().c_str(), &addr) != 1) {
        QMessageBox::critical(this, "Error", "Invalid proxy IP address");
        return;
    }
    config.proxyIp = addr.s_addr;
    config.proxyPort = htons(static_cast<uint16_t>(proxyPort));

    // Authentication (if enabled)
    if (ui->authCheckBox->isChecked()) {
        config.authRequired = 1;
        strncpy_s(config.username, ui->usernameEdit->text().toStdString().c_str(), sizeof(config.username) - 1);
        strncpy_s(config.password, ui->passwordEdit->text().toStdString().c_str(), sizeof(config.password) - 1);
    }

    // Launch and inject
    Injector::InjectResult result = Injector::LaunchAndInject(
        exePath.toStdWString(),
        dllPath.toStdWString(),
        cmdLine.toStdWString(),
        config
    );

    if (result.success) {
        updateStatus(QString("Process launched successfully (PID: %1)").arg(result.processId));
        QMessageBox::information(this, "Success",
            QString("Process launched with proxy.\nPID: %1").arg(result.processId));
    } else {
        updateStatus("Launch failed");
        QMessageBox::critical(this, "Error",
            QString("Failed to launch process:\n%1").arg(QString::fromStdWString(result.errorMessage)));
    }
}

void MainWindow::onAuthCheckChanged(int state)
{
    bool enabled = (state == Qt::Checked);
    ui->usernameEdit->setEnabled(enabled);
    ui->passwordEdit->setEnabled(enabled);
}

void MainWindow::updateStatus(const QString& message)
{
    ui->statusLabel->setText("Status: " + message);
}

bool MainWindow::validateInput()
{
    if (ui->exePathEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Please select an executable file.");
        return false;
    }

    if (!QFile::exists(ui->exePathEdit->text())) {
        QMessageBox::warning(this, "Validation Error", "Selected executable file does not exist.");
        return false;
    }

    if (ui->proxyHostEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Please enter proxy server address.");
        return false;
    }

    if (ui->authCheckBox->isChecked()) {
        if (ui->usernameEdit->text().isEmpty()) {
            QMessageBox::warning(this, "Validation Error", "Please enter username for authentication.");
            return false;
        }
    }

    return true;
}

QString MainWindow::getHookDllPath()
{
    QString appDir = QCoreApplication::applicationDirPath();

    // Determine architecture suffix based on current process
#ifdef _WIN64
    QString dllName = "MiniProxifierHook_x64.dll";
#else
    QString dllName = "MiniProxifierHook_x86.dll";
#endif

    QString dllPath = QDir(appDir).filePath(dllName);

    if (QFile::exists(dllPath)) {
        return dllPath;
    }

    return QString();
}
