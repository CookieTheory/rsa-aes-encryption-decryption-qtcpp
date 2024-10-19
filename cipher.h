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

    EVP_PKEY *getPublicKey(QByteArray &data);
    EVP_PKEY *getPublicKey(QString filename);

    EVP_PKEY *getPrivateKey(QByteArray &data);
    EVP_PKEY *getPrivateKey(QString filename);

    QByteArray encryptRSA(EVP_PKEY *key, QByteArray &data);

    QByteArray decryptRSA(EVP_PKEY *key, QByteArray &data);

    void freeEVPKey(EVP_PKEY *key);

signals:

private:

    void initialize();

    void finalize();

    QByteArray readFile(QString filename);

    void writeFile(QString filename, QByteArray &data);
};

#endif // CIPHER_H
