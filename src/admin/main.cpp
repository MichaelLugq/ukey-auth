#include "mainwidget.h"

#include "consts.h"
#include "single_process_instance.h"

#include <QApplication>
#include <QTranslator>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  SingleProcessInstance inst(kAdminInstanceName, "Qt5QWindowIcon", "π‹¿Ì‘±v1.0");
  if (inst.Opened()) {
    return 0;
  }

  QTranslator translator;
  if (translator.load(":/translations/admin_zh-cn.qm")) {
    app.installTranslator(&translator);
  } else {}

  MainWidget w;
  w.show();

  return app.exec();
}
