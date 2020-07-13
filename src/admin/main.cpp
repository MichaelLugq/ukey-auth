#include "mainwidget.h"
#include <QApplication>
#include <QTranslator>
#include <filesystem>

namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  auto current_path = fs::current_path();
  auto qm_path = current_path.parent_path().append("admin_zh-cn.qm");

  QTranslator translator;
  bool b = translator.load(QString::fromStdString(qm_path.string()));
  if (b) {
    app.installTranslator(&translator);
  }

  MainWidget w;
  w.show();

  return app.exec();
}
