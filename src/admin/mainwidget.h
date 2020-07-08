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
  void OnRefresh();
  void OnBtnSetPIN();
  void OnBtnVerifyPIN();
  void OnBtnChangePIN();

 private:
  void showEvent(QShowEvent* event) override;

 private:
  void UpdateComboBox();

 private:
  Ui::MainWidget *ui;
};

#endif // MAINWIDGET_H
