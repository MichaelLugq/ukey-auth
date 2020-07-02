#include "mainwidget.h"
#include "ui_mainwidget.h"

#include "consts.h"
#include "utils.h"
#include "crypto.h"

#include "secret.pb.h"
#include "index.pb.h"

#include <QMessageBox>

#include <ctime>
#include <cassert>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

static const int kPageGenerateIndex = 0;
static const int kPageOperatorIndex = 1;

void MsgBox(const QString& msg) {
  QMessageBox msgBox;
  msgBox.setText(msg);
  msgBox.exec();
}

MainWidget::MainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::MainWidget) {
  ui->setupUi(this);

  this->setFixedSize(600, 450);

  ui->edit_index->hide();

  ui->comboBox->setEditable(false);

  UpdateComboBox();

  // 密钥对文件检查
  {
    // 检查密钥对文件是否存在
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    // 存在：直接跳转；不存在：不跳转
    ui->stackedWidget->setCurrentIndex(input ? kPageOperatorIndex : kPageGenerateIndex);
    ui->btn_gen->setEnabled(!input);
  }

  connect(ui->btn_gen, &QPushButton::clicked, this, [&]() {
    // 置灰，防止重复点击
    ui->btn_gen->setEnabled(false);

    // 生成密钥对
    int ec;
    std::vector<SM2KeyPair> keys;
    {
      for (int i = 0; i < kSM2KeyPairCount; ++i) {
        SM2KeyPair keypair;
        ec = GenSM2KeyPair(keypair);
        if (0 != ec) {
          return ec;
        }
        keys.emplace_back(std::move(keypair));
      }
    }

    // 写入文件
    proto::SecretInfo secrets;
    {
      for (auto& key : keys) {
        auto kp = secrets.add_keypair();
        kp->set_pub_key(key.pub_key.data(), key.pub_key.size());
        kp->set_priv_key(key.priv_key.data(), key.priv_key.size());
      }

      std::fstream output("secret.db", std::ios::out | std::ios::trunc | std::ios::binary);
      if (!secrets.SerializeToOstream(&output)) {
        MsgBox("Failed to generate key pairs.");
      } else {
        ui->stackedWidget->setCurrentIndex(kPageOperatorIndex);
      }
    }
  });

  connect(ui->btn_write, &QPushButton::clicked, this, [&]() {
    // 置灰
    ui->btn_write->setEnabled(false);
    auto set_enabled = [&](BYTE*) { ui->btn_write->setEnabled(true); };
    std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

    // 检查name是否为空
    QString name = ui->edit_name->text();
    if (name.isEmpty()) {
      MsgBox("Please input the user name.");
      return;
    }

    // 检查index.db是否存在，如果存在则读取
    proto::IndexInfo indexs;
    {
      std::fstream input("index.db", std::ios::in | std::ios::binary);
      if (input) {
        if (!indexs.ParseFromIstream(&input)) {
          MsgBox("index file exists, but failed to read");
          return;
        }
      }
    }

    // 检查name是否重名
    {
      bool dup_name = false;
      for (int i = 0; i < indexs.index_size(); ++i) {
        if (name.toStdString() == indexs.index(i).name()) {
          dup_name = true;
        }
      }
      if (dup_name) {
        MsgBox("duplication of name");
        return;
      }
    }

    // 读取所有公私钥：从中获取指定索引的密钥对、所有公钥
    proto::SecretInfo secrets;
    std::vector<SM2KeyPair> keys;
    {
      std::fstream input("secret.db", std::ios::in | std::ios::binary);
      if (!input) {
        MsgBox("Failed to get key pairs");
        return;
      } else if (!secrets.ParseFromIstream(&input)) {
        MsgBox("Failed to parse secret.db");
        return;
      }
      for (int i = 0; i < secrets.keypair_size(); ++i) {
        SM2KeyPair key;
        key.pub_key.assign(secrets.keypair(i).pub_key().begin(), secrets.keypair(i).pub_key().end());
        key.priv_key.assign(secrets.keypair(i).priv_key().begin(), secrets.keypair(i).priv_key().end());
        keys.emplace_back(std::move(key));
      }
    }

    // 设置、验证PIN
    {
      std::vector<BYTE> password(6, '0');
      int ec = SetPIN(password);
      if (0 != ec) {
        MsgBox("Failed to set PIN");
        return;
      }
      ec = VerifyPIN(password);
      if (0 != ec) {
        MsgBox("Failed to verify PIN");
        return;
      }
    }

    // 导入指定索引的密钥对到USB Key
    int current_index = indexs.index_size();
    {
      if (current_index >= keys.size()) {
        MsgBox("There is not enough key pairs");
        return;
      }
      int ec = ImportKeyPairToUKey(keys[current_index]);
      if (ec != 0) {
        MsgBox("Failed to import key pair");
        return;
      }
    }

    // 导入所有公钥
    {
      std::vector<BYTE> pubs;
      for (auto& key : keys) {
        pubs.insert(pubs.begin(), key.pub_key.begin(), key.pub_key.end());
      }
      assert(pubs.size() % 4096 == 0);

      int ec = WriteToUKey(kPublicKeyStartPosition, pubs);
      if (ec != 0) {
        MsgBox("Failed to import public key to USB Key");
        return;
      }

      // Test: read public keys
      std::vector<BYTE> test_pub;
      ULONG sector_read = kSM2KeyPairCount * 64 / 4096;
      ec = ReadFromUKey(kPublicKeyStartPosition, sector_read, test_pub);
      if (ec != 0) {
        MsgBox("Failed to read public key from USB Key");
        return;
      }
    }

    // 导入身份信息（name + index）,可作为是否已经下发的标记

    // 写入index.db
    {
      auto added = indexs.add_index();
      added->set_name(name.toStdString());
      added->set_index(current_index);

      std::fstream output("index.db", std::ios::out | std::ios::trunc | std::ios::binary);
      if (!indexs.SerializeToOstream(&output)) {
        MsgBox("Failed to write index.db");
        return;
      }
    }

    // 从index.db读取信息到comboBox
    {
      ui->comboBox->clear();
      QStringList list;
      for (int i = 0; i < indexs.index_size(); ++i) {
        list.push_back(QString::fromStdString(indexs.index(i).name()));
      }
      ui->comboBox->addItems(list);
    }

    //
    MsgBox("Success");
  });

  connect(ui->btn_download, &QPushButton::clicked, this, [&]() {
    // 置灰
    ui->btn_download->setEnabled(false);
    auto set_enabled = [&](BYTE*) { ui->btn_download->setEnabled(true); };
    std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

    // 检查index.db是否存在，如果存在则读取，不存在则提示错误
  });
}

MainWidget::~MainWidget() {
  delete ui;
}

void MainWidget::OnCurrentChanged(int index) {
  if (index == kPageGenerateIndex) {
    //
  } else if (index == kPageOperatorIndex) {
    //
  }
}

void MainWidget::UpdateComboBox() {
  // 检查index.db是否存在，如果存在则读取，并显示在comboBox控件
  proto::IndexInfo indexs;
  {
    std::fstream input("index.db", std::ios::in | std::ios::binary);
    if (input) {
      if (!indexs.ParseFromIstream(&input)) {
        MsgBox("index file exists, but failed to read");
        return;
      }
    }
  }

  // 从index.db读取信息到comboBox
  {
    ui->comboBox->clear();
    QStringList list;
    for (int i = 0; i < indexs.index_size(); ++i) {
      list.push_back(QString::fromStdString(indexs.index(i).name()));
    }
    ui->comboBox->addItems(list);
  }
}
