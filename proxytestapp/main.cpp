#include <QApplication>
#include "TestAppWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("ProxyTestApp");

    TestAppWindow window;
    window.show();

    return app.exec();
}
