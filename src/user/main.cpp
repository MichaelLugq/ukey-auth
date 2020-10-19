#include "mainwidget.h"
#include <QApplication>
#include <QTranslator>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  QTranslator translator;
  if (translator.load(":/translations/user_zh-cn.qm")) {
    app.installTranslator(&translator);
  } else {}

  MainWidget w;
  w.show();
  return app.exec();
}
