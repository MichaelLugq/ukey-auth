#include "mainwidget.h"
#include "ui_mainwidget.h"

#include "consts.h"
#include "utils.h"
#include "crypto.h"
#include "proto.h"
#include "local_auth.h"

#include "secret.pb.h"
#include "index.pb.h"

#include <QMessageBox>

#include <ctime>
#include <cassert>
#include <fstream>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

static const int kPagePINIndex = 0;
static const int kPageGenerateIndex = 1;
static const int kPageOperatorIndex = 2;

#define SetDisable(btn)                                          \
  btn->setEnabled(false);                                        \
  auto set_enabled = [&](BYTE*) { btn->setEnabled(true); };      \
  std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

void MsgBox(const QString& msg) {
  QMessageBox msgBox;
  msgBox.setText(msg);
  msgBox.exec();
}

MainWidget::MainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::MainWidget),
  local_auth_(new LocalAuth()) {
  ui->setupUi(this);

  this->setFixedSize(500, 100);
  this->setWindowTitle(tr("Administrator"));

  ui->label_pin->setText(tr("Please input the PIN"));
  ui->label_change_pin->setText(tr("The new PIN"));

  ui->comboBox->setEditable(false);

  ui->stackedWidget->setCurrentIndex(kPagePINIndex);

  UpdatePinPage();
  UpdateComboBox();

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
          MsgBox(tr("Failed to generate key pair"));
          return;
        }
        keys.emplace_back(std::move(keypair));
      }
    }

    // 写入文件
    if (WriteSecrets(keys) != kSuccess) {
      MsgBox(tr("Failed to generate key pairs."));
      return;
    } else {
      ui->stackedWidget->setCurrentIndex(kPageOperatorIndex);
      this->setFixedSize(600, 350);
    }

    // 读取文件
    std::vector<SM2KeyPair> copy_keys;
    if (ReadSecrets(copy_keys) != kSuccess) {
      MsgBox(tr("Failed to read key pairs."));
      return;
    } else {
      assert(copy_keys.size() == keys.size());
    }
  });

  connect(ui->btn_add, &QPushButton::clicked, this, [&]() {
    // 置灰
    SetDisable(ui->btn_add);

    // 检查name是否为空
    std::string name = ui->edit_name->text().toUtf8().data();
    if (name.empty()) {
      MsgBox(tr("Please input the user name."));
      return;
    }

    // 检查是否空的USB Key，非空直接提示并返回
    {
      proto::NameIndex usrindex;
      auto ec = ReadUserIndex(usrindex);
      if (ec != kNoWrittenFlag) {
        // TODO: MsgBox(ec.msg());
        MsgBox(tr("Has been written"));
        return;
      }
    }

    // 检查index.db是否存在，如果存在则读取
    proto::IndexInfo indexs;
    {
      int ec = ReadLocalIndexs(indexs);
      if (ec == kNoIndexDB) {
      } else if (ec != kSuccess) {
        MsgBox(tr("index file exists, but failed to read"));
        return;
      }
    }

    // 检查name是否重名
    {
      bool dup_name = false;
      for (int i = 0; i < indexs.index_size(); ++i) {
        if (name == indexs.index(i).name()) {
          dup_name = true;
        }
      }
      if (dup_name) {
        MsgBox(tr("duplication of name"));
        return;
      }
    }

    // 读取所有公私钥：从中获取指定索引的密钥对、所有公钥
    std::vector<SM2KeyPair> keys;
    {
      int ec = ReadSecrets(keys);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read secret.db"));
        return;
      }
    }

    // 设置、验证PIN
    {
      std::vector<BYTE> password(6, '0');
      int ec = SetPIN(password);
      if (0 != ec) {
        MsgBox(tr("Failed to set PIN"));
        return;
      }
      ec = VerifyPIN(password);
      if (0 != ec) {
        MsgBox(tr("Failed to verify PIN"));
        return;
      }
    }

    // 导入指定索引的密钥对到USB Key
    int current_index = indexs.index_size();
    {
      if (current_index >= keys.size()) {
        MsgBox(tr("There is not enough key pairs"));
        return;
      }
      int ec = ImportKeyPairToUKey(keys[current_index]);
      if (ec != 0) {
        MsgBox(tr("Failed to import key pair"));
        return;
      }
    }

    // 导入所有公钥
    {
      int ec = WritePublicKeysToUKey(keys);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to import public key to USB Key"));
        return;
      }

      // Test: read public keys
      std::vector <std::vector<BYTE>> test_pubs;
      ec = ReadPublicKeysFromUKey(test_pubs);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read public key from USB Key"));
        return;
      }
    }

    // 更新indexs
    {
      auto added = indexs.add_index();
      added->set_name(name);
      added->set_index(current_index);
    }

    // 导入身份信息（name + index）,可作为是否已经下发的标记
    {
      // 本地用户（写）
      {
        proto::NameIndex usrindex;
        usrindex.set_name(name);
        usrindex.set_index(current_index);
        int ec = WriteUserIndex(usrindex);
        if (ec != kSuccess) {
          MsgBox(tr("Failed to write user index"));
          return;
        }
      }

      // 本地用户（读）
      {
        proto::NameIndex usrindex;
        int ec = ReadUserIndex(usrindex);
        if (ec != kSuccess) {
          MsgBox(tr("Failed to read user index"));
          return;
        }
        assert(name == usrindex.name());
        assert(current_index == usrindex.index());
      }

      // 其他用户（写）
      {
        int ec = WriteOthersIndex(indexs);
        if (ec != 0) {
          MsgBox(tr("Failed to write other users data to USB Key"));
          return;
        }
      }

      // 其他用户（读）
      {
        proto::IndexInfo infos;
        if (ReadOthersIndex(infos) != kSuccess) {
          MsgBox(tr("Failed to parse other users data from stream"));
          return;
        }

        assert(infos.index_size() == indexs.index_size());
      }
    }

    // 写入index.db
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox(tr("Failed to write index.db"));
        return;
      }
    }

    // 重新加载
    UpdateComboBox();

    //
    MsgBox(tr("Success"));
  });

  connect(ui->btn_delete, &QPushButton::clicked, this, [&]() {
    // 置灰
    SetDisable(ui->btn_delete);

    // 检查是否对应的USB Key
    std::string name;
    proto::NameIndex usrindex;
    {
      int ec = ReadUserIndex(usrindex);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read user index"));
        return;
      }
      name = usrindex.name();
    }

    // TODO：提示是否删除USB Key中的用户

    // 删除: 删除用户、清空公钥、清空自身公私钥
    {
      int ec = ClearUserIndex();
      if (ec != kSuccess) {
        MsgBox(tr("Failed to clear user index"));
        return;
      }
      // TODO: 清空公钥
      // TODO: 清空自身公私钥
    }

    // 读取index.db
    proto::IndexInfo indexs;
    {
      int ec;
      ec = ReadLocalIndexs(indexs);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read local indexs"));
        return;
      }
    }

    // 从index.db中删除此条记录
    {
      bool found = false;
      for (auto it = indexs.mutable_index()->begin(); it != indexs.mutable_index()->end(); ++it) {
        if (it->name() == name) {
          indexs.mutable_index()->erase(it);
          found = true;
          break;
        }
      }
      if (!found) {
        MsgBox("Cannot find the name to delete");
        return;
      }
    }

    // 写回
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox("Failed to write index.db");
        return;
      }
    }

    // 重新加载
    UpdateComboBox();

    MsgBox(tr("Success"));
  });

  connect(ui->btn_update, &QPushButton::clicked, this, [&]() {
    // 置灰
    SetDisable(ui->btn_update);

    std::string new_name = ui->edit_name->text().toUtf8().data();

    // 检查是否对应的USB Key
    proto::NameIndex usrindex;
    {
      int ec = ReadUserIndex(usrindex);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read user index"));
        return;
      }
    }

    // 提示是否更新USB Key中的用户

    // 检查name是否为空
    if (new_name.empty()) {
      MsgBox(tr("Please input the user name."));
      return;
    }

    // 检查index.db是否存在，如果存在则读取
    proto::IndexInfo indexs;
    {
      int ec;
      ec = ReadLocalIndexs(indexs);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read local indexs"));
        return;
      }
    }

    // 检查name是否重名
    {
      bool dup_name = false;
      for (int i = 0; i < indexs.index_size(); ++i) {
        if (new_name == indexs.index(i).name()) {
          dup_name = true;
        }
      }
      if (dup_name) {
        MsgBox(tr("duplication of name"));
        return;
      }
    }

    // 重命名
    {
      bool found = false;
      for (int i = 0; i < indexs.index_size(); ++i) {
        if (indexs.index(i).name() == usrindex.name()) {
          indexs.mutable_index(i)->set_name(new_name);
          found = true;
        }
      }
      if (!found) {
        MsgBox(tr("Cannot find the name to delete"));
        return;
      }

      usrindex.set_name(new_name);
      int ec = WriteUserIndex(usrindex);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to write user information to USB Key"));
        return;
      }
    }

    // 写回
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox(tr("Failed to write index.db"));
        return;
      }
    }

    // 重新加载
    UpdateComboBox();

    MsgBox(tr("Success"));
  });

  connect(ui->btn_download, &QPushButton::clicked, this, [&]() {
    // 置灰
    SetDisable(ui->btn_download);

    // 检查index.db是否存在，如果存在则读取，不存在则提示错误

    // index.db另存为
  });

  connect(ui->btn_refresh, &QPushButton::clicked, this, &MainWidget::OnMainPageRefresh);

  connect(ui->btn_add, &QPushButton::clicked, this, &MainWidget::OnMainPageRefresh);

  connect(ui->btn_delete, &QPushButton::clicked, this, &MainWidget::OnMainPageRefresh);

  connect(ui->btn_update, &QPushButton::clicked, this, &MainWidget::OnMainPageRefresh);

  connect(ui->btn_set_pin, &QPushButton::clicked, this, &MainWidget::OnBtnSetPIN);

  connect(ui->btn_verify_pin, &QPushButton::clicked, this, &MainWidget::OnBtnVerifyPIN);

  connect(ui->btn_change_pin, &QPushButton::clicked, this, &MainWidget::OnBtnChangePIN);
}

MainWidget::~MainWidget() {
  delete ui;
}

void MainWidget::OnMainPageRefresh() {
  proto::NameIndex index;
  int ec = ReadUserIndex(index);
  if (ec == kNoDevice) {
    ui->label_user->setText(tr("No device"));
  } else if (ec == kTooManyDevice) {
    ui->label_user->setText(tr("Too many devices"));
  } else if (ec == kNoWrittenFlag) {
    ui->label_user->setText(tr("No user information"));
  } else if (ec == kSuccess) {
    ui->label_user->setText(tr("The user is ") + QString::fromStdString(index.name()));
    // 设置管理员权限
    auto ec = SetAdminPIN(std::vector<BYTE>(6, '0'));
    if (ec != kSuccess) {
      MsgBox(tr("Failed to set administrator's PIN"));
    }
  } else {
    ui->label_user->setText(tr("Unknown error"));
  }
}

void MainWidget::OnBtnSetPIN() {
  std::string pwd = ui->edit_pin->text().toStdString();
  if (pwd.empty()) {
    MsgBox(tr("Please input the password"));
    return;
  }
  auto ec = local_auth_->SetPassword(pwd);
  if (ec != kSuccess) {
    MsgBox(tr("Failed to set password"));
    return;
  }

  MsgBox(tr("Success"));

  UpdatePinPage();
}

void MainWidget::OnBtnVerifyPIN() {
  std::string pwd = ui->edit_pin->text().toStdString();
  if (pwd.empty()) {
    MsgBox(tr("Please input the password"));
    return;
  }
  auto ec = local_auth_->VerifyPassword(pwd);
  if (ec != kSuccess) {
    MsgBox(tr("Password is not match"));
    return;
  }
  OnMainPageRefresh();
  // 检查密钥对文件是否存在。存在：直接跳转；不存在：不跳转
  {
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    ui->stackedWidget->setCurrentIndex(input ? kPageOperatorIndex : kPageGenerateIndex);
    ui->btn_gen->setEnabled(!input);
    if (input) {
      this->setFixedSize(600, 350);
    }
  }
}

void MainWidget::OnBtnChangePIN() {
  std::string pwd = ui->edit_pin->text().toStdString();
  std::string new_pwd = ui->edit_new_pin->text().toStdString();
  if (pwd.empty()) {
    MsgBox(tr("Please input the password"));
    return;
  }
  if (new_pwd.empty()) {
    MsgBox(tr("Please input the new password"));
    return;
  }
  auto ec = local_auth_->ChangePassword(pwd, new_pwd);
  if (ec != kSuccess) {
    MsgBox(tr("Failed to change the password"));
    return;
  }

  MsgBox(tr("Success"));
  OnMainPageRefresh();
  // 检查密钥对文件是否存在。存在：直接跳转；不存在：不跳转
  {
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    ui->stackedWidget->setCurrentIndex(input ? kPageOperatorIndex : kPageGenerateIndex);
    ui->btn_gen->setEnabled(!input);
  }
}

void MainWidget::showEvent(QShowEvent* event) {
  auto index = ui->stackedWidget->currentIndex();
  if (index == kPageOperatorIndex) {
    OnMainPageRefresh();
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
      const auto& name = QString::fromStdString(indexs.index(i).name());
      const auto& index = QString::fromStdString(std::to_string(indexs.index(i).index()));
      list.push_back(name/* + ":" + index*/);
    }
    ui->comboBox->addItems(list);
  }
}

void MainWidget::UpdatePinPage() {
  bool exitst = local_auth_->HavePassword();
  ui->btn_set_pin->setVisible(!exitst);
  ui->btn_verify_pin->setVisible(exitst);
  ui->btn_change_pin->setVisible(exitst);
  ui->edit_new_pin->setVisible(exitst);

  ui->label_change_pin->setVisible(exitst);
  if (exitst) {
    ui->label_pin->setText(tr("PIN"));
  }
}
