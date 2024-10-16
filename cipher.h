#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <QDebug>
#include <QFile>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/decoder.h>

#define PADDING RSA_PKCS1_PADDING

class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(QObject *parent = nullptr);
    ~Cipher();

    RSA *getPublicKey(QByteArray &data);
    RSA *getPublicKey(QString filename);

    RSA *getPrivateKey(QByteArray &data);
    RSA *getPrivateKey(QString filename);

    QByteArray encryptRSA(RSA *key, QByteArray &data);

    QByteArray decryptRSA(RSA *key, QByteArray &data);

    QByteArray randomBytes(int size);

    void freeRSAKey(RSA *key);

signals:

private:

    void initialize();

    void finalize();

    QByteArray readFile(QString filename);

    void writeFile(QString filename, QByteArray &data);
};

#endif // CIPHER_H
