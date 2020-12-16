#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>
#include <memory>

class LocalAuth;

namespace Ui {
class MainWidget;
}

class MainWidget : public QWidget {
  Q_OBJECT

 public:
  explicit MainWidget(QWidget *parent = 0);
  ~MainWidget();

 private slots:
  void OnMainPageRefresh();
  void OnBtnSetPIN();
  void OnBtnVerifyPIN();
  void OnBtnChangePIN();

 private:
  void showEvent(QShowEvent* event) override;

 private:
  void UpdateComboBox();
  void UpdatePinPage();

  void MsgBox(const QString& msg);
 private:
  std::unique_ptr<LocalAuth> local_auth_;

 private:
  Ui::MainWidget *ui;
};

#endif // MAINWIDGET_H
