#include "mainwindow.h"

#include <QApplication>

#include <QMessageBox>
#include "cipher.h"

void testAES()
{
    qDebug() << "Testing AES...";
    Cipher cWrapper;
    QString passphrase = "password";
    QByteArray plain = "This is a test string!";

    QByteArray encryped = cWrapper.encryptAES(passphrase.toUtf8(), plain);

    qDebug() << plain;
    qDebug() << encryped.toBase64();
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    testAES();

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        auto choice = QMessageBox::critical(nullptr, QObject::tr("Systray"),
                                            QObject::tr("I couldn't detect any system tray on this system."),
                                            QMessageBox::Close | QMessageBox::Ignore);
        if (choice == QMessageBox::Close)
            return 1;
        // Otherwise "lurk": if a system tray is started later, the icon will appear.
    }
    QApplication::setQuitOnLastWindowClosed(false);

    MainWindow w;
    w.setWindowIcon(QIcon(":/Resources/RSA.svg"));
    w.show();
    return a.exec();
}
