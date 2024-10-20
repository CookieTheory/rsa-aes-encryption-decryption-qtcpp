#include "mainwindow.h"
#include "cipher.h"
#include "./ui_mainwindow.h"
#include <QFileDialog>

#define FILEFILTERS "Text Files (*.txt) ;; All Files (*.*) ;; XML Files (*.xml)";
#define KEYFILTERS "Text Files (*.txt) ;; All Files (*.*) ;; XML Files (*.xml)";

QByteArray getPublicKey()
{
    QByteArray testPublicKey;

    testPublicKey.append("-----BEGIN PUBLIC KEY-----\n");
    testPublicKey.append("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmh45sQUgX9viTr2LEy0/\n");
    testPublicKey.append("vDELiJzUrZWNAGXgWsZXybydIhhLk0EcmPuP52l9ijS4xo0OVYQemDlf24nieSps\n");
    testPublicKey.append("YTIpl6x92ltCvo5ot38QyYbRiD8Yr8/7lcd7UYc4pwlk1NjSwr0l0gpjK9yYooUc\n");
    testPublicKey.append("cl6a/QkoldN3b5WlJWZH0KnI2Y6naB3eeC0Uv1gI9Ivn0bPaQqUXi/SZ2WOjUrEd\n");
    testPublicKey.append("w1S01Nj/mMrQpanNyh1HUXD7fez2PtoAqmmxXiP0huRWL3/zLqFekINsFOdCIECQ\n");
    testPublicKey.append("9GdwhgZzWhC9CUynbAdWgjgubJEF+tQq3FIROmz0lqxbimzcuysR6MBJYeGJXFJo\n");
    testPublicKey.append("UQfEfYlWvBLM4chPi+QqsL5YjSCZQcEUc0Ye/w3WT+KNlUmpJhLatRTAip2eTi+I\n");
    testPublicKey.append("IeAtsxm0V3oD/BzANA3olcLY3mIsleiEkdtIawBO+xCiapsTaOARi8WNQvho4Ci/\n");
    testPublicKey.append("ujKPO8KYHq5PFZr1MA9lOryKrJLmVAqnqjkn8ycoL0Q1OXjMAPUxt0DHZDJPBsth\n");
    testPublicKey.append("8gN1Gz+F/MV2fdB4Tc+MUBhT2FaaZM5K6f6L+EQDC+V6r+1q1uRXSylJQfCsl2ER\n");
    testPublicKey.append("Bl3eKg8JgLggkaRaXDHhspvjRTtyta1zypsipmDuqLRx0S1L2YAuscmr0FWDA8zI\n");
    testPublicKey.append("ZsOrVp+KeRsMHBdDa0eedvECAwEAAQ==\n");
    testPublicKey.append("-----END PUBLIC KEY-----");

    return testPublicKey;
}

QByteArray getPrivateKey()
{
    QByteArray testPrivateKey;

    testPrivateKey.append("-----BEGIN RSA PRIVATE KEY-----\n");
    testPrivateKey.append("MIIJKAIBAAKCAgEAmh45sQUgX9viTr2LEy0/vDELiJzUrZWNAGXgWsZXybydIhhL\n");
    testPrivateKey.append("k0EcmPuP52l9ijS4xo0OVYQemDlf24nieSpsYTIpl6x92ltCvo5ot38QyYbRiD8Y\n");
    testPrivateKey.append("r8/7lcd7UYc4pwlk1NjSwr0l0gpjK9yYooUccl6a/QkoldN3b5WlJWZH0KnI2Y6n\n");
    testPrivateKey.append("aB3eeC0Uv1gI9Ivn0bPaQqUXi/SZ2WOjUrEdw1S01Nj/mMrQpanNyh1HUXD7fez2\n");
    testPrivateKey.append("PtoAqmmxXiP0huRWL3/zLqFekINsFOdCIECQ9GdwhgZzWhC9CUynbAdWgjgubJEF\n");
    testPrivateKey.append("+tQq3FIROmz0lqxbimzcuysR6MBJYeGJXFJoUQfEfYlWvBLM4chPi+QqsL5YjSCZ\n");
    testPrivateKey.append("QcEUc0Ye/w3WT+KNlUmpJhLatRTAip2eTi+IIeAtsxm0V3oD/BzANA3olcLY3mIs\n");
    testPrivateKey.append("leiEkdtIawBO+xCiapsTaOARi8WNQvho4Ci/ujKPO8KYHq5PFZr1MA9lOryKrJLm\n");
    testPrivateKey.append("VAqnqjkn8ycoL0Q1OXjMAPUxt0DHZDJPBsth8gN1Gz+F/MV2fdB4Tc+MUBhT2Faa\n");
    testPrivateKey.append("ZM5K6f6L+EQDC+V6r+1q1uRXSylJQfCsl2ERBl3eKg8JgLggkaRaXDHhspvjRTty\n");
    testPrivateKey.append("ta1zypsipmDuqLRx0S1L2YAuscmr0FWDA8zIZsOrVp+KeRsMHBdDa0eedvECAwEA\n");
    testPrivateKey.append("AQKCAgAmmhF7LDyKpgmODV2rRPckzOgFpLqEa+PwSJQkSG+uoOZ+prUvQezGyKOn\n");
    testPrivateKey.append("o72FA2WQnb4MX1ZGbIB8/ZFTJfQVeDoAunyfV6JlFkhWRaZPw8vxo1QsnRx3zIov\n");
    testPrivateKey.append("xn3DINA3m8NWcYfqjx192/gDJPIWF2ocnNGkjV3p/gJqVq8ALbaX/2og4vJZCXmb\n");
    testPrivateKey.append("35IGppA+7xxo+u7l6DMsxw8eZCx/Q1UzxtJmU85k4B4iVKkLVhA330ViQrpN9MEv\n");
    testPrivateKey.append("QjQ6ITERHqwrbtG/wpsstSvT5jgob0w41Z7I3U5r6N46abAaV7YRDVYBGGlP2+Ji\n");
    testPrivateKey.append("zu2IW81l45R58PTAZoE62gHMtPtZghOiuSbVyVNKth5j4LEP0OXXzBEprOBBsS1u\n");
    testPrivateKey.append("OWUEHeGHjzlLT4gy3ot9U0eMJLEsb7C7NtXnVJNEGAv4KEw1zgtyatVOU5kKGEKm\n");
    testPrivateKey.append("A9rBqjBP8eMPA/8MGCXYjwhQkEMHe/eM0+bXb0hb1/YYgcX1fFyyg91ZpHFU64CI\n");
    testPrivateKey.append("4MsMJXVK0sf7s9d3ExDBy2CtOXGGJEwFJbtQlICejf4jsHl8TWcPJtl1Hrb4NdJx\n");
    testPrivateKey.append("9gIT55DOpfzOwSG7e7p2Ghq09EyeKd47blz9tuc94G37kdc7Gj7ZUHXf8MUXccgQ\n");
    testPrivateKey.append("iDjMxn1VIdG90gu/P+UTyHxjQyxVYpj/PbF2dzqRoCymPU9CwQKCAQEA++5TIgaW\n");
    testPrivateKey.append("k5CEE4ReF0jU9D1ybuJ9o3krXmQfcdl8ZQakPJtskEFXhJ4svEAv5TAl0mYdd78f\n");
    testPrivateKey.append("DAmSFhSuOiuOFWX6R+s1qH5Yi8+sde0kZoE7xxpgSAK8r+iBu1c0SXkqq5OuBCML\n");
    testPrivateKey.append("DNWDTixWX88Q/FnHA6+bo7DeCJDdxh4ubXRDMPRhXccGQdCPtD1kyDdRqOyK+pM+\n");
    testPrivateKey.append("NJMvDtSYabXOaZ9P4Shw1/EqANFvVm0tzCr+Or/kEywgSiWsqAMLigFcPMC855et\n");
    testPrivateKey.append("tjqNS82x/j7NrBaQ9Ja1sCpozFQYQZLHH66YkYg9BrzICNdF116GCkHHvti3XwoT\n");
    testPrivateKey.append("Fm6I/6D6cCS1aQKCAQEAnJt3osEfBbroRAljrnTWkMw6HtoQDKvBpwW5vwbkkaqa\n");
    testPrivateKey.append("BDKZgss7zYMzftJcS1o6dBlaaGCjvBYx5JvEpD6QhiTsBUyiKHwpafjvWLrNfspE\n");
    testPrivateKey.append("ZLrnFBJ88KbpXh4rby58NFtwHv+jK3OQtEb2ugs8AhBB3EHw8GhTv5f/al3IgAU4\n");
    testPrivateKey.append("F6u66uGXvRNrNIdek1nLKoMtGfm18cuSBpuGogimSWwlTdazSP1dCn27P2YVl9uN\n");
    testPrivateKey.append("GTdzyvA89IlwoCfuY01yWjAy3UwM/jv3mAp5RAu+YJJGVt98sk2S64abt6DMNfS2\n");
    testPrivateKey.append("Jlj9j0USSqB8/m2rUjajhuoUiO6ADT1CU8g05K1cSQKCAQBdpmhM27oZvLz8LFZ1\n");
    testPrivateKey.append("vWM8L6NcSOF/ZUmT2xA9WCV/wIpI5VXkAgYwjEQA7rNfNRi6L6+AlhFKfjxJ7QIf\n");
    testPrivateKey.append("KZW1qqTxGyRlMCJmRprLc432dM/t4YYs/qd5lKq1I2OSdHJCObGUZBp1eOFIq/6n\n");
    testPrivateKey.append("uueLhywN2Le4j8TZ1lA6l3mWwoM/rXiMTbGrwYXJ8JCIRNgcPWIkZ5vWG2iA0NKf\n");
    testPrivateKey.append("aTAD327oOgpIm6OLjk8fB5LgtJKw8CguYFbYeUzHX+poML1C8DrItH+kn/tqVFp4\n");
    testPrivateKey.append("MoxuDi1wXp3HkNxIKHKj3ZYb1uFsKALXgFGzx6J0vvSA15cTAKiZsbsKuag/rm2q\n");
    testPrivateKey.append("RlsRAoIBABaOMbHoPK6Xl+JMs+WpgEnEkE5nO86HYlHK+lCwDnWIa7xVCVUULl3Q\n");
    testPrivateKey.append("GreWVqKnsSmNiT7lRE/Ppon1gWHifPBFGxU8T1KjZ1eS+e3+oaA0Q5t6a9OxQftr\n");
    testPrivateKey.append("Hstmbv0JZewoi0J7sSWN9HZyjhCHk7H8Y2/0s138uKssmiXYsgr2NXj7S+WObktW\n");
    testPrivateKey.append("I6eiI5X3ZdKOqA1IsNLNbg+zkLV/p2uFvu2yEYpeq2raZwCflFaV0YGjQfMlnLHf\n");
    testPrivateKey.append("pa/7cFMvEVw5+ulyjaCERInKYGLTiizghG74qz4G/DUd4wmUiDTxNNbbFFHxMcw7\n");
    testPrivateKey.append("xyTh6L3jjrPcvO5n41uEyivE9xFEgrkCggEBAI5MZHG0WlOrpZTBeVXtW7Qa9B0Y\n");
    testPrivateKey.append("5YsJfSXtcQSdcPiJc+VI4gqfW41IimmjBGwv/yIGdM0Wu7wLlRhP6bC8tNiYb3a8\n");
    testPrivateKey.append("Ww1h8EGi9sFlAt8nmhR0ung5abY9dvxVz5oeNLZxz6s0lBayc+iwqrNbaZkf6+tz\n");
    testPrivateKey.append("XY8nAi2S6YCfAgOw2hAinqQ1GzxTuIELoDxEGkh391Qpndu9q5hvjtQ4KbcSinSV\n");
    testPrivateKey.append("7uoYtKzIavSsFXGAjXuZPnm+QTubUI5lNp6tOAemUm7Im0t4+hUcuY40LMmV+kfI\n");
    testPrivateKey.append("YHN/aP3S7GuhdQ9qCCklphqZvaKtjL8hPAgK4Kp/ag5f/6hbAfL+d+yGZwU=\n");
    testPrivateKey.append("-----END RSA PRIVATE KEY-----\n");

    return testPrivateKey;
}

QByteArray keyBuffer;

void testRSA(){
    qDebug() << "Loading keys...";
    QByteArray testPrivateKey = getPrivateKey();
    QByteArray testPublicKey = getPublicKey();

    Cipher cWrapper;
    EVP_PKEY* publickey = cWrapper.getPublicKey(testPublicKey);
    EVP_PKEY* privatekey = cWrapper.getPrivateKey(testPrivateKey);

    QByteArray plain = "This is a text string";
    QByteArray encrypted = cWrapper.encryptRSA(publickey, plain);
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);


    qDebug() << plain;
    qDebug() << encrypted.toBase64();
    qDebug() << decrypted;

    cWrapper.freeEVPKey(publickey);
    cWrapper.freeEVPKey(privatekey);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    Cipher cWrapper;
    QString filters = FILEFILTERS;
    QString fp = QFileDialog::getOpenFileName(this, "Open file to encrypt", QDir::homePath(), filters);
    QByteArray data = cWrapper.readFile(fp);
    ui->plainTextEdit->setPlainText(QString::fromUtf8(data));
}


void MainWindow::on_pushButton_2_clicked()
{
    qDebug() << "Loading keys...";
    //QByteArray testPublicKey = getPublicKey();
    Cipher cWrapper;
    QByteArray key;
    if(!keyBuffer.isNull()){
        key = keyBuffer;
    } else key = getPublicKey();
    EVP_PKEY* publickey = cWrapper.getPublicKey(key);
    QByteArray data = ui->plainTextEdit->toPlainText().toUtf8();
    qDebug() << "Encrypting...";
    QByteArray ed = cWrapper.encryptRSA(publickey, data).toBase64();
    cWrapper.freeEVPKey(publickey);
    ui->plainTextEdit_3->setPlainText(QString::fromUtf8(ed, ed.length()));
}


void MainWindow::on_pushButton_3_clicked()
{
    qDebug() << "Loading keys...";
    QByteArray testPrivateKey = getPrivateKey();
    Cipher cWrapper;
    EVP_PKEY* privatekey = cWrapper.getPrivateKey(testPrivateKey);
    QByteArray data = ui->plainTextEdit->toPlainText().toUtf8();
    QByteArray encrypted = QByteArray::fromBase64(data);
    qDebug() << encrypted;
    qDebug() << "Decrypting...";
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);
    qDebug() << decrypted;
    cWrapper.freeEVPKey(privatekey);
    ui->plainTextEdit_3->setPlainText(QString::fromUtf8(decrypted));
}

void MainWindow::on_pushButton_4_clicked()
{
    Cipher cWrapper;
    QString filters = KEYFILTERS;
    QString fp = QFileDialog::getOpenFileName(this, "Open public or private key", QDir::homePath(), filters);
    ui->textBrowser->setPlainText(fp);
    QByteArray data = cWrapper.readFile(fp);
    keyBuffer = data;
}


void MainWindow::on_pushButton_5_clicked()
{
    keyBuffer = NULL;
    ui->textBrowser->setPlainText("");
}

