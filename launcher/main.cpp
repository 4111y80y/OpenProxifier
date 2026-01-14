#include <QApplication>
#include <QSharedMemory>
#include <QLocalServer>
#include <QLocalSocket>
#include "MainWindow.h"
#include <windows.h>

static const char* MUTEX_NAME = "Global\\OpenProxifier_SingleInstance";
static const char* SERVER_NAME = "OpenProxifier_IPC";

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("MiniProxifier");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("OpenProxifier");

    // Check for existing instance using Windows Mutex
    HANDLE hMutex = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    DWORD lastError = GetLastError();

    if (lastError == ERROR_ALREADY_EXISTS) {
        // Another instance is running, notify it to show
        QLocalSocket socket;
        socket.connectToServer(SERVER_NAME);
        if (socket.waitForConnected(1000)) {
            socket.write("show");
            socket.flush();
            socket.waitForBytesWritten(1000);
            socket.disconnectFromServer();
        }
        CloseHandle(hMutex);
        return 0;
    }

    // Create local server to receive messages from other instances
    QLocalServer server;
    QLocalServer::removeServer(SERVER_NAME);
    server.listen(SERVER_NAME);

    MainWindow window;
    window.show();

    // Connect server to bring window to front
    QObject::connect(&server, &QLocalServer::newConnection, [&]() {
        QLocalSocket* clientSocket = server.nextPendingConnection();
        if (clientSocket) {
            clientSocket->waitForReadyRead(1000);
            QByteArray data = clientSocket->readAll();
            if (data == "show") {
                window.bringToFront();
            }
            clientSocket->disconnectFromServer();
            clientSocket->deleteLater();
        }
    });

    int result = app.exec();

    CloseHandle(hMutex);
    return result;
}
