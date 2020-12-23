#include "mainwidget.h"

#include "consts.h"
#include "single_process_instance.h"

#include <QApplication>
#include <QTranslator>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  SingleProcessInstance inst(kUserInstanceName, "Qt5QWindowIcon", "”√ªßv1.0");
  if (inst.Opened()) {
    return 0;
  }

  QTranslator translator;
  if (translator.load(":/translations/user_zh-cn.qm")) {
    app.installTranslator(&translator);
  } else {}

  MainWidget w;
  w.show();
  return app.exec();
}
