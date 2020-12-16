#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>

namespace Ui {
class MainWidget;
}

class MainWidget : public QWidget {
  Q_OBJECT

 public:
  explicit MainWidget(QWidget *parent = 0);
  ~MainWidget();

 private slots:
  void OnBtnBrower();
  void OnBtnEncrypt();
  void OnBtnDecrypt();
  void OnBtnVerifyPIN();
  void OnBtnChangePIN();
  void OnBtnUpdateIndex();
  void OnBtnUpdateBrowser();

 private:
  void UpdateSenderLabel();
  void UpdateComboBox();

  void MsgBox(const QString& msg);

 private:
  Ui::MainWidget *ui;
};

#endif // MAINWIDGET_H
