#include "mainwidget.h"
#include "ui_mainwidget.h"

#include "consts.h"
#include "utils.h"
#include "crypto.h"
#include "proto.h"

#include "secret.pb.h"
#include "index.pb.h"

#include <QMessageBox>

#include <ctime>
#include <cassert>
#include <fstream>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

static const int kPageGenerateIndex = 0;
static const int kPageOperatorIndex = 1;

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
  ui(new Ui::MainWidget) {
  ui->setupUi(this);

  this->setFixedSize(600, 450);
  this->setWindowTitle("Administrator");

  ui->comboBox->setEditable(false);

  UpdateComboBox();

  // �����Կ���ļ��Ƿ���ڡ����ڣ�ֱ����ת�������ڣ�����ת
  {
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    ui->stackedWidget->setCurrentIndex(input ? kPageOperatorIndex : kPageGenerateIndex);
    ui->btn_gen->setEnabled(!input);
  }

  connect(ui->btn_gen, &QPushButton::clicked, this, [&]() {
    // �ûң���ֹ�ظ����
    ui->btn_gen->setEnabled(false);

    // ������Կ��
    int ec;
    std::vector<SM2KeyPair> keys;
    {
      for (int i = 0; i < kSM2KeyPairCount; ++i) {
        SM2KeyPair keypair;
        ec = GenSM2KeyPair(keypair);
        if (0 != ec) {
          MsgBox("Failed to generate key pair");
          return;
        }
        keys.emplace_back(std::move(keypair));
      }
    }

    // д���ļ�
    if (WriteSecrets(keys) != kSuccess) {
      MsgBox(tr("Failed to generate key pairs."));
      return;
    } else {
      ui->stackedWidget->setCurrentIndex(kPageOperatorIndex);
    }

    // ��ȡ�ļ�
    std::vector<SM2KeyPair> copy_keys;
    if (ReadSecrets(copy_keys) != kSuccess) {
      MsgBox(tr("Failed to read key pairs."));
      return;
    } else {
      assert(copy_keys.size() == keys.size());
    }
  });

  connect(ui->btn_add, &QPushButton::clicked, this, [&]() {
    // �û�
    SetDisable(ui->btn_add);

    // ����Ƿ�յ�USB Key���ǿ�ֱ����ʾ������
    {
      proto::NameIndex usrindex;
      auto ec = ReadUserIndex(usrindex);
      if (ec != kNoWrittenFlag) {
        MsgBox(tr("Has been written"));
        return;
      }
    }

    // ���name�Ƿ�Ϊ��
    QString name = ui->edit_name->text();
    if (name.isEmpty()) {
      MsgBox(tr("Please input the user name."));
      return;
    }

    // ���index.db�Ƿ���ڣ�����������ȡ
    proto::IndexInfo indexs;
    {
      int ec = ReadLocalIndexs(indexs);
      if (ec == kNoIndexDB) {
      } else if (ec != kSuccess) {
        MsgBox(tr("index file exists, but failed to read"));
        return;
      }
    }

    // ���name�Ƿ�����
    {
      bool dup_name = false;
      for (int i = 0; i < indexs.index_size(); ++i) {
        if (name.toStdString() == indexs.index(i).name()) {
          dup_name = true;
        }
      }
      if (dup_name) {
        MsgBox(tr("duplication of name"));
        return;
      }
    }

    // ��ȡ���й�˽Կ�����л�ȡָ����������Կ�ԡ����й�Կ
    std::vector<SM2KeyPair> keys;
    {
      int ec = ReadSecrets(keys);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read secret.db"));
        return;
      }
    }

    // ���á���֤PIN
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

    // ����ָ����������Կ�Ե�USB Key
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

    // �������й�Կ
    {
      std::vector<BYTE> pubs;
      for (auto& key : keys) {
        pubs.insert(pubs.begin(), key.pub_key.begin(), key.pub_key.end());
      }
      assert(pubs.size() % 4096 == 0);

      int sector_offset = kPublicKeyStartPosition;
      int ec = WriteToUKey(sector_offset, pubs);
      if (ec != 0) {
        MsgBox("Failed to import public key to USB Key");
        return;
      }

      // Test: read public keys
      std::vector<BYTE> test_pub;
      sector_offset = kPublicKeyStartPosition;
      ULONG sector_read = kSM2KeyPairCount * 64 / 4096;
      ec = ReadFromUKey(sector_offset, sector_read, test_pub);
      if (ec != 0) {
        MsgBox("Failed to read public key from USB Key");
        return;
      }
    }

    // ����indexs
    {
      auto added = indexs.add_index();
      added->set_name(name.toStdString());
      added->set_index(current_index);
    }

    // ���������Ϣ��name + index��,����Ϊ�Ƿ��Ѿ��·��ı��
    {
      // �����û���д��
      {
        proto::NameIndex usrindex;
        usrindex.set_name(name.toStdString());
        usrindex.set_index(current_index);
        int ec = WriteUserIndex(usrindex);
        if (ec != kSuccess) {
          MsgBox(tr("Failed to write user index"));
          return;
        }
      }

      // �����û�������
      {
        proto::NameIndex usrindex;
        int ec = ReadUserIndex(usrindex);
        if (ec != kSuccess) {
          MsgBox(tr("Failed to read user index"));
          return;
        }
        assert(name.toStdString() == usrindex.name());
        assert(current_index == usrindex.index());
      }

      // �����û���д��
      {
        int ec = WriteOthersIndex(indexs);
        if (ec != 0) {
          MsgBox(tr("Failed to write other users data to USB Key"));
          return;
        }
      }

      // �����û�������
      {
        proto::IndexInfo infos;
        if (ReadOthersIndex(infos) != kSuccess) {
          MsgBox(tr("Failed to parse other users data from stream"));
          return;
        }

        assert(infos.index_size() == indexs.index_size());
      }
    }

    // д��index.db
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox("Failed to write index.db");
        return;
      }
    }

    // ���¼���
    UpdateComboBox();

    //
    MsgBox("Success");
  });

  connect(ui->btn_delete, &QPushButton::clicked, this, [&]() {
    // �û�
    SetDisable(ui->btn_delete);

    // ����Ƿ��Ӧ��USB Key
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

    // TODO����ʾ�Ƿ�ɾ��USB Key�е��û�

    // ɾ��: ɾ���û�����չ�Կ���������˽Կ
    {
      int ec = ClearUserIndex();
      if (ec != kSuccess) {
        MsgBox(tr("Failed to clear user index"));
        return;
      }
      // TODO: ��չ�Կ
      // TODO: �������˽Կ
    }

    // ��ȡindex.db
    proto::IndexInfo indexs;
    {
      int ec;
      ec = ReadLocalIndexs(indexs);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read local indexs"));
        return;
      }
    }

    // ��index.db��ɾ��������¼
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

    // д��
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox("Failed to write index.db");
        return;
      }
    }

    // ���¼���
    UpdateComboBox();

    MsgBox("Success");
  });

  connect(ui->btn_update, &QPushButton::clicked, this, [&]() {
    // �û�
    SetDisable(ui->btn_update);

    std::string new_name = ui->edit_name->text().toStdString();

    // ����Ƿ��Ӧ��USB Key
    proto::NameIndex usrindex;
    {
      int ec = ReadUserIndex(usrindex);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read user index"));
        return;
      }
    }

    // ��ʾ�Ƿ����USB Key�е��û�

    // ���name�Ƿ�Ϊ��
    if (new_name.empty()) {
      MsgBox(tr("Please input the user name."));
      return;
    }

    // ���index.db�Ƿ���ڣ�����������ȡ
    proto::IndexInfo indexs;
    {
      int ec;
      ec = ReadLocalIndexs(indexs);
      if (ec != kSuccess) {
        MsgBox(tr("Failed to read local indexs"));
        return;
      }
    }

    // ���name�Ƿ�����
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

    // ������
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

    // д��
    {
      if (WriteLocalIndexs(indexs) != kSuccess) {
        MsgBox("Failed to write index.db");
        return;
      }
    }

    // ���¼���
    UpdateComboBox();

    MsgBox("Success");
  });

  connect(ui->btn_download, &QPushButton::clicked, this, [&]() {
    // �û�
    ui->btn_download->setEnabled(false);
    auto set_enabled = [&](BYTE*) { ui->btn_download->setEnabled(true); };
    std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

    // ���index.db�Ƿ���ڣ�����������ȡ������������ʾ����

    // index.db���Ϊ
  });

  connect(ui->btn_refresh, &QPushButton::clicked, this, &MainWidget::OnRefresh);
  connect(ui->btn_add, &QPushButton::clicked, this, &MainWidget::OnRefresh);
  connect(ui->btn_delete, &QPushButton::clicked, this, &MainWidget::OnRefresh);
  connect(ui->btn_update, &QPushButton::clicked, this, &MainWidget::OnRefresh);
}

MainWidget::~MainWidget() {
  delete ui;
}

void MainWidget::OnRefresh() {
  proto::NameIndex index;
  int ec = ReadUserIndex(index);
  if (ec == kNoDevice) {
    ui->label_user->setText(tr("No device"));
  } else if (ec != kSuccess) {
    ui->label_user->setText(tr("No user information"));
  } else {
    ui->label_user->setText(tr("The user is ") + QString::fromStdString(index.name()));
  }
}

void MainWidget::showEvent(QShowEvent* event) {
  auto index = ui->stackedWidget->currentIndex();
  if (index == kPageOperatorIndex) {
    OnRefresh();
  }
}

void MainWidget::UpdateComboBox() {
  // ���index.db�Ƿ���ڣ�����������ȡ������ʾ��comboBox�ؼ�
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

  // ��index.db��ȡ��Ϣ��comboBox
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
