#include "basiccustomdialog.h"
#include "ui_basiccustomdialog.h"

BasicCustomDialog::BasicCustomDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::BasicCustomDialog)
{
    ui->setupUi(this);
}

BasicCustomDialog::BasicCustomDialog(QWidget *parent, QString title, QString text)
    : QDialog(parent)
    , ui(new Ui::BasicCustomDialog)
{
    ui->setupUi(this);
    this->setWindowTitle(title);
    ui->label->setText(text);
}

BasicCustomDialog::~BasicCustomDialog()
{
    delete ui;
}

void BasicCustomDialog::changeText(QString text)
{
    ui->label->setText(text);
}

