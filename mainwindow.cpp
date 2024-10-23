#include "mainwindow.h"
#include "cipher.h"
#include "./ui_mainwindow.h"
#include <fstream>
#include <QFileDialog>

#define FILEFILTERS "Text Files (*.txt) ;; All Files (*) ;; XML Files (*.xml)"
#define KEYFILTERS "Pem Files (*.pem);;Text Files (*.txt);;All Files(*)"

QByteArray keyBuffer;

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
    Cipher cWrapper;
    QByteArray key;
    if(!keyBuffer.isNull()){
        key = keyBuffer;
    } else qWarning() << "keyBuffer is empty...";
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
    Cipher cWrapper;
    QByteArray key;
    if(!keyBuffer.isNull()){
        key = keyBuffer;
    } else qWarning() << "keyBuffer is empty...";
    EVP_PKEY* privatekey = cWrapper.getPrivateKey(key);
    QByteArray data = ui->plainTextEdit->toPlainText().toUtf8();
    QByteArray encrypted = QByteArray::fromBase64(data);
    qDebug() << encrypted.toBase64();
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


void MainWindow::on_pushButton_6_clicked()
{
    Cipher cWrapper;
    EVP_PKEY *rsaKeyPair = cWrapper.createRSAKeyPair();
    QString fpPub = QFileDialog::getSaveFileName(this, "Choose save location for public key", QDir::homePath(), KEYFILTERS);
    if (fpPub.isEmpty()) return;

    BIO *bioPub = BIO_new_file(fpPub.toStdString().c_str(), "w");
    if (PEM_write_bio_PUBKEY(bioPub, rsaKeyPair) == 0) {
        qDebug() << "Error writing public key to file.";
    }

    QString fpPriv = QFileDialog::getSaveFileName(this, "Choose save location for private key", QDir::homePath(), KEYFILTERS);
    if (fpPriv.isEmpty()) return;

    BIO *bioPriv = BIO_new_file(fpPriv.toStdString().c_str(), "w");
    if (PEM_write_bio_PrivateKey(bioPriv, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
        qDebug() << "Error writing private key to file.";
    }

    BIO_free(bioPub);
    BIO_free(bioPriv);
    EVP_PKEY_free(rsaKeyPair);
}

