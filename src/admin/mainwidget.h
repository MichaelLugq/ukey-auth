#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>
#include <memory>
#include <thread>

class LocalAuth;

namespace Ui {
class MainWidget;
}

class MainWidget : public QWidget {
  Q_OBJECT

 public:
  explicit MainWidget(QWidget *parent = 0);
  ~MainWidget();

 signals:
  void DeviceMonitor(int insert);

 private slots:
  void OnMainPageRefresh();
  void OnBtnSetPIN();
  void OnBtnVerifyPIN();
  void OnBtnChangePIN();
  void OnDeviceMonitor(int insert);

 private:
  void showEvent(QShowEvent* event) override;

 private:
  void UpdateComboBox();
  void UpdatePinPage();

  void MsgBox(const QString& msg);

  QString GetInfoFromErrCode(int ec);

  void StartDeviceMonitor();
  void StopDeviceMonitor();

 private:
  std::unique_ptr<LocalAuth> local_auth_;

 private:
  Ui::MainWidget *ui;
  std::thread thread_device_monitor_;
  bool quit_ = false;
};

#endif // MAINWIDGET_H
