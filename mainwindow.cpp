#include "mainwindow.h"
#include "basiccustomdialog.h"
#include "cipher.h"
#include "./ui_mainwindow.h"
#include <QFileDialog>

#ifndef QT_NO_SYSTEMTRAYICON
#include <QMenu>

#define FILEFILTERS "Text Files (*.txt);;All Files (*.*);;XML Files (*.xml)"
#define KEYFILTERS "Pem Files (*.pem);;Text Files (*.txt);;All Files(*.*)"
#define DEFAULTKEYFILTER "Pem Files (*.pem)"
#define DEFAULTFILEFILTER "Text Files (*.txt)"

QByteArray keyBuffer;
QByteArray AESBuffer;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    createActions();
    createTrayIcon();
    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::iconActivated);
    setIcon(QIcon(":/Resources/RSA.svg"));

    trayIcon->show();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setIcon(QIcon icon)
{
    trayIcon->setIcon(icon);
}

void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        this->showNormal();
        break;
    default:
        ;
    }
}

void MainWindow::on_button_openFile_clicked()
{
    Cipher cWrapper;
    QString fp = QFileDialog::getOpenFileName(this, "Open file to encrypt", QDir::homePath(), FILEFILTERS);
    QByteArray data = cWrapper.readFile(fp);
    ui->textEdit_input->setPlainText(QString::fromUtf8(data));
}

void MainWindow::on_button_encrypt_clicked()
{
    Cipher cWrapper;
    QByteArray key;
    if(!keyBuffer.isNull()){
        key = keyBuffer;
    }
    else {
        BasicCustomDialog dialog(this, "Error", "No key selected");
        dialog.exec();
    }
    EVP_PKEY* publickey = cWrapper.getPublicKey(key);
    QByteArray data = ui->textEdit_input->toPlainText().toUtf8();
    QByteArray ed = cWrapper.encryptRSA(publickey, data).toBase64();
    qDebug() << "encrypted: " + ed;
    cWrapper.freeEVPKey(publickey);
    ui->textEdit_output->setPlainText(QString::fromUtf8(ed, ed.length()));
}

void MainWindow::on_button_decrypt_clicked()
{
    Cipher cWrapper;
    QByteArray key;
    if(!keyBuffer.isNull()){
        key = keyBuffer;
    }
    else {
        BasicCustomDialog dialog(this, "Error", "No key selected");
        dialog.exec();
    }
    qDebug() << "keyBuffer: " + keyBuffer;
    EVP_PKEY* privatekey = cWrapper.getPrivateKey(key);
    QByteArray data = ui->textEdit_input->toPlainText().toUtf8();
    qDebug() << "encrypted base 64:" + data;
    QByteArray encrypted = QByteArray::fromBase64(data);
    qDebug() << "encrypted raw:" + encrypted;
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);
    qDebug() << "decrypted :" + QString::fromUtf8(decrypted);
    ui->textEdit_output->setPlainText(QString::fromUtf8(decrypted));
    cWrapper.freeEVPKey(privatekey);
}

void MainWindow::on_button_loadKey_clicked()
{
    Cipher cWrapper;
    QString fp = QFileDialog::getOpenFileName(this, "Open public or private key", QDir::homePath(), KEYFILTERS);
    ui->textBrowser_keyPath->setPlainText(fp);
    QByteArray data = cWrapper.readFile(fp);
    keyBuffer = data;
}

void MainWindow::on_button_deleteKey_clicked()
{
    keyBuffer = NULL;
    ui->textBrowser_keyPath->setPlainText("");
}

void MainWindow::on_button_keyGeneration_clicked()
{
    Cipher cWrapper;
    QString selectedFilter = DEFAULTKEYFILTER;
    QString filterHumanReadable;
    EVP_PKEY *rsaKeyPair = cWrapper.createRSAKeyPair(ui->comboBox_keySize->currentText().toInt());
    QString fpPub = QFileDialog::getSaveFileName(this, "Choose save location for public key", QDir::homePath(), KEYFILTERS, &selectedFilter);
    if (fpPub.isEmpty()) return;
    filterHumanReadable = selectedFilter.split("*").constLast().split(")").constFirst();
    if (fpPub.split(".").length() < 2) fpPub.append(filterHumanReadable);

    BIO *bioPub = BIO_new_file(fpPub.toStdString().c_str(), "w");
    if (PEM_write_bio_PUBKEY(bioPub, rsaKeyPair) == 0) {
        qWarning() << "Error writing public key to file.";
    }

    QString fpPriv = QFileDialog::getSaveFileName(this, "Choose save location for private key", QDir::homePath(), KEYFILTERS, &selectedFilter);
    if (fpPriv.isEmpty()) return;
    filterHumanReadable = selectedFilter.split("*").constLast().split(")").constFirst();
    if (fpPriv.split(".").length() < 2) fpPriv.append(filterHumanReadable);

    BIO *bioPriv = BIO_new_file(fpPriv.toStdString().c_str(), "w");
    if (PEM_write_bio_PrivateKey(bioPriv, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
        qWarning() << "Error writing private key to file.";
    }

    BIO_free(bioPub);
    BIO_free(bioPriv);
    EVP_PKEY_free(rsaKeyPair);
}

void MainWindow::on_button_saveFile_clicked()
{
    Cipher cWrapper;
    QByteArray data = ui->textEdit_output->toPlainText().toUtf8();
    if(data.isEmpty()) return;
    QString selectedFilter = DEFAULTFILEFILTER;
    QString filterHumanReadable;
    QString saveFile = QFileDialog::getSaveFileName(this, "Save as...", QDir::homePath(), FILEFILTERS, &selectedFilter);
    if (saveFile.isEmpty()) return;
    filterHumanReadable = selectedFilter.split("*").constLast().split(")").constFirst();
    if (saveFile.split(".").length() < 2) saveFile.append(filterHumanReadable);
    cWrapper.writeFile(saveFile, data);
}

void MainWindow::createActions()
{
    minimizeAction = new QAction(tr("Mi&nimize"), this);
    connect(minimizeAction, &QAction::triggered, this, &QWidget::hide);

    maximizeAction = new QAction(tr("Ma&ximize"), this);
    connect(maximizeAction, &QAction::triggered, this, &QWidget::showMaximized);

    restoreAction = new QAction(tr("&Restore"), this);
    connect(restoreAction, &QAction::triggered, this, &QWidget::showNormal);

    quitAction = new QAction(tr("&Quit"), this);
    connect(quitAction, &QAction::triggered, qApp, &QCoreApplication::quit);
}

void MainWindow::createTrayIcon()
{
    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(minimizeAction);
    trayIconMenu->addAction(maximizeAction);
    trayIconMenu->addAction(restoreAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);
}

/**
 * @chapter AES Encryption/Decryption
 */

void MainWindow::on_button_openFileAES_clicked()
{
    Cipher cWrapper;
    QString fp = QFileDialog::getOpenFileName(this, "Open file to encrypt", QDir::homePath(), FILEFILTERS);
    QByteArray data = cWrapper.readFile(fp);
    ui->textEdit_input_AES->setPlainText(QString::fromUtf8(data));
}

#endif

void MainWindow::on_button_loadKeyAES_clicked()
{
    Cipher cWrapper;
    QString fp = QFileDialog::getOpenFileName(this, "Open AES key", QDir::homePath(), KEYFILTERS);
    ui->textBrowser_keyPathAES->setPlainText(fp);
    QByteArray data = cWrapper.readFile(fp);
    AESBuffer = data;
}


void MainWindow::on_button_saveFileAES_clicked()
{
    Cipher cWrapper;
    QByteArray data = ui->textEdit_output_AES->toPlainText().toUtf8();
    if(data.isEmpty()) return;
    QString selectedFilter = DEFAULTFILEFILTER;
    QString filterHumanReadable;
    QString saveFile = QFileDialog::getSaveFileName(this, "Save as...", QDir::homePath(), FILEFILTERS, &selectedFilter);
    if (saveFile.isEmpty()) return;
    filterHumanReadable = selectedFilter.split("*").constLast().split(")").constFirst();
    if (saveFile.split(".").length() < 2) saveFile.append(filterHumanReadable);
    cWrapper.writeFile(saveFile, data);
}


void MainWindow::on_button_encryptAES_clicked()
{
    Cipher cWrapper;
    QByteArray key;
    if(!AESBuffer.isNull()){
        key = AESBuffer;
    }
    else key = cWrapper.randomBytes(8).toBase64();
    QByteArray data = ui->textEdit_input_AES->toPlainText().toUtf8();
    QByteArray encrypted = cWrapper.encryptAES(key, data).toBase64();

    QByteArray ed;
    ed.append(key);
    ed.append(encrypted);

    ui->textEdit_output_AES->setPlainText(QString::fromUtf8(ed, ed.length()));
}

