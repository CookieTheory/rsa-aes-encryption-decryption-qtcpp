#include "mainwindow.h"
#include "basiccustomdialog.h"
#include "cipher.h"
#include "./ui_mainwindow.h"
#include <QFileDialog>

#ifndef QT_NO_SYSTEMTRAYICON
#include <QMenu>

#define FILEFILTERS "Text Files (*.txt) ;; All Files (*) ;; XML Files (*.xml)"
#define KEYFILTERS "Pem Files (*.pem);;Text Files (*.txt);;All Files(*)"

QByteArray keyBuffer;

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
    EVP_PKEY* privatekey = cWrapper.getPrivateKey(key);
    QByteArray data = ui->textEdit_input->toPlainText().toUtf8();
    QByteArray encrypted = QByteArray::fromBase64(data);
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);
    cWrapper.freeEVPKey(privatekey);
    ui->textEdit_output->setPlainText(QString::fromUtf8(decrypted));
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
    EVP_PKEY *rsaKeyPair = cWrapper.createRSAKeyPair(ui->comboBox_keySize->currentText().toInt());
    QString fpPub = QFileDialog::getSaveFileName(this, "Choose save location for public key", QDir::homePath(), KEYFILTERS);
    if (fpPub.isEmpty()) return;
    if (fpPub.split(".").length() < 2) fpPub.append(".pem");

    BIO *bioPub = BIO_new_file(fpPub.toStdString().c_str(), "w");
    if (PEM_write_bio_PUBKEY(bioPub, rsaKeyPair) == 0) {
        qWarning() << "Error writing public key to file.";
    }

    QString fpPriv = QFileDialog::getSaveFileName(this, "Choose save location for private key", QDir::homePath(), KEYFILTERS);
    if (fpPriv.isEmpty()) return;
    if (fpPriv.split(".").length() < 2) fpPriv.append(".pem");

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
    QString saveFile = QFileDialog::getSaveFileName(this, "Save as...", QDir::homePath(), FILEFILTERS);
    if (saveFile.isEmpty()) return;
    if (saveFile.split(".").length() < 2) saveFile.append(".txt");
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

#endif

