#ifndef BASICCUSTOMDIALOG_H
#define BASICCUSTOMDIALOG_H

#include <QDialog>

namespace Ui {
class BasicCustomDialog;
}

class BasicCustomDialog : public QDialog
{
    Q_OBJECT

public:
    explicit BasicCustomDialog(QWidget *parent = nullptr);
    BasicCustomDialog(QWidget *parent = nullptr, QString title = "Default title", QString text = "Default text");
    ~BasicCustomDialog();
    void changeText(QString text);

private:
    Ui::BasicCustomDialog *ui;
};

#endif // BASICCUSTOMDIALOG_H
