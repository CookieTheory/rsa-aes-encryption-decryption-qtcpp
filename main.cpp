#include "mainwindow.h"

#include <QApplication>

#include <QMessageBox>
#include "cipher.h"

//testing
#include <QFileDialog>

bool readFile(QString filename, QByteArray &data)
{
    QFile f(filename);

    if(!f.open(QFile::ReadOnly))
    {
        qCritical() << "Could not open" << filename;
        return false;
    }

    data = f.readAll();
    f.close();
    return true;
}

bool writeFile(QString filename, QByteArray &data)
{
    QFile f(filename);
    if(!f.open(QFile::WriteOnly))
    {
        qCritical() << "Could not open" << filename;
        return false;
    }

    f.write(data);
    f.close();
    return true;
}

bool encryptCombined()
{
    Cipher cWrapper;

    //Encrypt AES key
    EVP_PKEY* publicKey = cWrapper.getPublicKey(QFileDialog::getOpenFileName(NULL, "Open public key to test encryption", QDir::homePath()));

    QByteArray passphrase = cWrapper.randomBytes(8).toBase64();
    QByteArray encryptedKey = cWrapper.encryptRSA(publicKey, passphrase);

    qDebug() << "Encrypted AES key = " << encryptedKey.toBase64();

    //Encrypt the data
    QByteArray plain = "Hello world this is plain text!";
    QByteArray encrypted = cWrapper.encryptAES(passphrase, plain);

    QString filename = "test.enc";
    QFile f(filename);
    if(!f.open(QFile::WriteOnly))
    {
        qCritical() << "Could not open" << filename;
        return false;
    }

    qDebug() << "Encrypted Key Len: " << encryptedKey.length();

    QByteArray encryptedData;
    encryptedData.append(encryptedKey);
    encryptedData.append(encrypted);
    f.write(encryptedData);
    f.close();

    qDebug() << "Encryption Finished!";

    cWrapper.freeEVPKey(publicKey);

    return true;
}

bool decryptCombined()
{
    Cipher cWrapper;
    QByteArray data;

    if(!readFile("test.enc", data))
    {
        qCritical() << "Could not open test.enc";
        return false;
    }

    //Load the encrypted key from the file
    QByteArray header("Salted__");
    int pos = data.indexOf(header);
    if(pos == -1)
    {
        qCritical () << "Could not find the beginning of the encrypted file";
        return false;
    }

    qDebug() << header << " found at" << pos;

    QByteArray encryptedKey = data.mid(0,pos);
    QByteArray encrypted = data.mid(pos);

    //Decrypt the AES key

    EVP_PKEY* privateKey = cWrapper.getPrivateKey(QFileDialog::getOpenFileName(NULL, "Open private key to test decryption", QDir::homePath()));
    QByteArray passphrase = cWrapper.decryptRSA(privateKey, encryptedKey);
    cWrapper.freeEVPKey(privateKey);

    qDebug() << "Passphrase = " << passphrase;

    //Decrypt the data
    QByteArray plain = cWrapper.decryptAES(passphrase, encrypted);

    writeFile("test.txt", plain);

    qDebug() << "Finished Decrypting!";

    return true;
}

void testAES()
{
    qDebug() << "Testing AES...";
    Cipher cWrapper;
    QString passphrase = "password";
    QByteArray plain = "This is a test string!";

    QByteArray encrypted = cWrapper.encryptAES(passphrase.toUtf8(), plain);
    QByteArray decrypted = cWrapper.decryptAES(passphrase.toUtf8(), encrypted);

    qDebug() << plain;
    qDebug() << encrypted.toBase64();
    qDebug() << decrypted;
}

void testCombined()
{
    if(encryptCombined()) decryptCombined();
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    //testAES();
    //testCombined();

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
