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

  // ��Կ���ļ����
  {
    // �����Կ���ļ��Ƿ����
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    // ���ڣ�ֱ����ת�������ڣ�����ת
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
          return ec;
        }
        keys.emplace_back(std::move(keypair));
      }
    }

    // д���ļ�
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
    // �û�
    ui->btn_write->setEnabled(false);
    auto set_enabled = [&](BYTE*) { ui->btn_write->setEnabled(true); };
    std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

    // ���name�Ƿ�Ϊ��
    QString name = ui->edit_name->text();
    if (name.isEmpty()) {
      MsgBox("Please input the user name.");
      return;
    }

    // ���index.db�Ƿ���ڣ�����������ȡ
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

    // ���name�Ƿ�����
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

    // ��ȡ���й�˽Կ�����л�ȡָ����������Կ�ԡ����й�Կ
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

    // ���������Ϣ��name + index��,����Ϊ�Ƿ��Ѿ��·��ı��

    // д��index.db
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

    // ��index.db��ȡ��Ϣ��comboBox
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
    // �û�
    ui->btn_download->setEnabled(false);
    auto set_enabled = [&](BYTE*) { ui->btn_download->setEnabled(true); };
    std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

    // ���index.db�Ƿ���ڣ�����������ȡ������������ʾ����
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
      list.push_back(QString::fromStdString(indexs.index(i).name()));
    }
    ui->comboBox->addItems(list);
  }
}
