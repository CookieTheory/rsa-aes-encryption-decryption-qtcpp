#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QSystemTrayIcon>

#ifndef QT_NO_SYSTEMTRAYICON

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void setIcon(QIcon icon);
    void iconActivated(QSystemTrayIcon::ActivationReason reason);

    void on_button_openFile_clicked();

    void on_button_encrypt_clicked();

    void on_button_decrypt_clicked();

    void on_button_loadKey_clicked();

    void on_button_deleteKey_clicked();

    void on_button_keyGeneration_clicked();

    void on_button_saveFile_clicked();

    void on_button_openFileAES_clicked();

    void on_button_loadKeyAES_clicked();

    void on_button_saveFileAES_clicked();

    void on_button_encryptAES_clicked();

    void on_button_decryptAES_clicked();

    void on_button_keyGenerationAES_clicked();

    void on_button_combinedOpenFile_clicked();

    void on_button_combinedLoadKey_clicked();

    void on_button_combinedDeleteKey_clicked();

    void on_combinedEncryptButton_clicked();

    void on_combinedDecryptbutton_clicked();

private:
    Ui::MainWindow *ui;

    void createActions();
    void createTrayIcon();

    QAction *minimizeAction;
    QAction *maximizeAction;
    QAction *restoreAction;
    QAction *quitAction;

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
};
#endif // QT_NO_SYSTEMTRAYICON
#endif // MAINWINDOW_H
