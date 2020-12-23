#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>
#include <thread>

namespace Ui {
class MainWidget;
}

class MainWidget : public QWidget {
  Q_OBJECT

 public:
  explicit MainWidget(QWidget *parent = 0);
  ~MainWidget();

 signals:
  void DeviceMonitor();

 private slots:
  void OnBtnBrower();
  void OnBtnEncrypt();
  void OnBtnDecrypt();
  void OnBtnVerifyPIN();
  void OnBtnChangePIN();
  void OnBtnUpdateIndex();
  void OnBtnUpdateBrowser();
  void OnDeviceMonitor();

 private:
  void UpdateSenderLabel();
  void UpdateComboBox();

  void MsgBox(const QString& msg);

  QString GetInfoFromErrCode(int ec);

  void StartDeviceMonitor();
  void StopDeviceMonitor();

 private:
  Ui::MainWidget *ui;
  std::thread thread_device_monitor_;
  bool quit_ = false;
};

#endif // MAINWIDGET_H
