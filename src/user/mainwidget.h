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

 private:
  void UpdateSenderLabel();
  void UpdateComboBox();

 private:
  Ui::MainWidget *ui;
};

#endif // MAINWIDGET_H
