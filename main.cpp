#include "mainwindow.h"
#include "cipher.h"

#include <QApplication>

QByteArray getPublicKey()
{
    QByteArray testPublicKey;

    testPublicKey.append("-----BEGIN PUBLIC KEY-----\n");
    testPublicKey.append("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCW/6+rGK1pMT0WGCezxnIdwdVz\n");
    testPublicKey.append("yQzDGDQp4QTme+REC4MJX4o786opLWpXw6yO91HufII7LUgJw3UPPRn+OmSx51gT\n");
    testPublicKey.append("HpSgWI31ue+ihwyyHxpyOUJpyYpmAdlcv/kyEUCeJKqrrdaL6huSUjTZnsJ8ElrN\n");
    testPublicKey.append("8K5Xk7H74qINV16uewIDAQAB\n");
    testPublicKey.append("-----END PUBLIC KEY-----");

    return testPublicKey;
}

QByteArray getPrivateKey()
{
    QByteArray testPrivateKey;

    testPrivateKey.append("-----BEGIN RSA PRIVATE KEY-----\n");
    testPrivateKey.append("MIICXgIBAAKBgQCW/6+rGK1pMT0WGCezxnIdwdVzyQzDGDQp4QTme+REC4MJX4o7\n");
    testPrivateKey.append("86opLWpXw6yO91HufII7LUgJw3UPPRn+OmSx51gTHpSgWI31ue+ihwyyHxpyOUJp\n");
    testPrivateKey.append("yYpmAdlcv/kyEUCeJKqrrdaL6huSUjTZnsJ8ElrN8K5Xk7H74qINV16uewIDAQAB\n");
    testPrivateKey.append("AoGAQ4yig4IIoZRbZXTs3emax2EdIi0Avo4nV8zIKmumFCKqPhk1d9hrePxOJHDu\n");
    testPrivateKey.append("0w4k4vFkOSDqpyN/TI/i/u4UeSm9SY4TF5qcMh3xus0wDF219PUBJm9ZfpCxXQiw\n");
    testPrivateKey.append("Pkq6+mpHi34XbGZ+kk2qN3uvgWEa/hQECeicWLhq7TFyMfECQQDHhBFiYS8K/m7H\n");
    testPrivateKey.append("GwCHEODDjhUJr4R+A9P0ms7hYocA7cEyJKVEMBoc+QmzDATAYr0z713mE3qyMO+5\n");
    testPrivateKey.append("K5Cx1cdXAkEAwb9WAMH3aLxijZPagR6/wZ7jGzpKNpZbwWruh8zm3kvv/T8f4L6T\n");
    testPrivateKey.append("NcTMlpkGjbxPrBqEo8cdzh3/1+kauXvPfQJBAJAY1YltUVGqY43P9biXOw5h/tXI\n");
    testPrivateKey.append("+3McBqhiasqjo4fLL76scuRlrWaBgzzakE/2wFnTJsk2BmbOK0VcrpuSH+8CQQCy\n");
    testPrivateKey.append("EG+ycpI4KCtLgz+mu+Pwx15if8gFM1tRAD4JgUANvizqy0E5BO221RBSuIFVcmSn\n");
    testPrivateKey.append("ABg3jaDO9rNUdGCjaC7hAkEApW8R1yCgCWmEVHiy9ezCHsacX+dI+lYXsdOdbtj8\n");
    testPrivateKey.append("xfAP3Dx08z1NnDMkHbWcVU4dEbKQJSNkeVD2H4RbyclPIg==\n");
    testPrivateKey.append("-----END RSA PRIVATE KEY-----");

    return testPrivateKey;
}

void testRSA(){
    qDebug() << "Loading keys...";
    QByteArray testPrivateKey = getPrivateKey();
    QByteArray testPublicKey = getPublicKey();

    Cipher cWrapper;
    RSA* publickey = cWrapper.getPublicKey(testPublicKey);
    RSA* privatekey = cWrapper.getPrivateKey(testPrivateKey);

    QByteArray plain = "This is a text string";
    QByteArray encrypted = cWrapper.encryptRSA(publickey, plain);
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);


    qDebug() << plain;
    qDebug() << encrypted.toBase64();
    qDebug() << decrypted;

    cWrapper.freeRSAKey(publickey);
    cWrapper.freeRSAKey(privatekey);
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    qDebug() << "HEEEEEEEEY";
    testRSA();
    MainWindow w;
    w.show();
    return a.exec();
}
