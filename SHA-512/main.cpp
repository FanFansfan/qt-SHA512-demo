#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <sha.h>

int main(int argc, char *argv[])
{
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    QGuiApplication app(argc, argv);

    sha sha512;
    //sha512.test();
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("sha", &sha512);
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
