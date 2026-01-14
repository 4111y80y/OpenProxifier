#include <QApplication>
#include "AntigravityWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Antigravity");

    AntigravityWindow window;
    window.show();

    return app.exec();
}
