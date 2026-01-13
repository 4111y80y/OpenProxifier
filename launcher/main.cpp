#include <QApplication>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("MiniProxifier");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("OpenProxifier");

    MainWindow window;
    window.show();

    return app.exec();
}
