#include "mainwidget.h"
#include "ui_mainwidget.h"

#include "consts.h"
#include "utils.h"
#include "crypto.h"
#include "proto.h"

#include "secret.pb.h"
#include "index.pb.h"

#include <QMessageBox>
#include <QFileDialog>

#include <ctime>
#include <cassert>
#include <fstream>
#include <filesystem>
#include <sstream>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

namespace fs = std::filesystem;

#define SetDisable(btn)                                          \
  btn->setEnabled(false);                                        \
  auto set_enabled = [&](BYTE*) { btn->setEnabled(true); };      \
  std::unique_ptr<BYTE, decltype(set_enabled)> ptr((BYTE*)1, set_enabled);

// 每次读取的大小
static const int kReadSize = 16;/*1024 * 1024 * 10;*/

// 检查是否可以正常解密
static const std::string kCheckFlag = "1234567890123456";

// 索引所在数据区域
static const std::string kIndexFlag = "index";

// 已经加密的标记
static const std::string kEncryptFlag = "enc_";

// iv
static const std::vector<unsigned char> kIV(16, 0);

// lambda
static auto lm = [](char* p) { delete[] p; };

//
static const int kPagePINIndex = 0;

//
static const int kPageOpIndex = 1;

MainWidget::MainWidget(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::MainWidget) {
  ui->setupUi(this);

  this->setFixedSize(500, 180);
  this->setWindowTitle(tr("User"));

  ui->comboBox->setEditable(false);
  ui->edit_path->setEnabled(false);
  ui->edit_update_path->setEnabled(false);

  ui->stackedWidget->setCurrentIndex(kPagePINIndex);

  connect(ui->btn_brower, &QPushButton::clicked, this, &MainWidget::OnBtnBrower);
  connect(ui->btn_encrypt, &QPushButton::clicked, this, &MainWidget::OnBtnEncrypt);
  connect(ui->btn_decrypt, &QPushButton::clicked, this, &MainWidget::OnBtnDecrypt);
  connect(ui->btn_verify_pin, &QPushButton::clicked, this, &MainWidget::OnBtnVerifyPIN);
  connect(ui->btn_change_pin, &QPushButton::clicked, this, &MainWidget::OnBtnChangePIN);
  connect(ui->btn_update, &QPushButton::clicked, this, &MainWidget::OnBtnUpdateIndex);
  connect(ui->btn_update_browser, &QPushButton::clicked, this, &MainWidget::OnBtnUpdateBrowser);

  UpdateSenderLabel();
}

MainWidget::~MainWidget() {
  delete ui;
}

void MainWidget::OnBtnBrower() {
  QString path = QFileDialog::getOpenFileName(this, tr("Open File"));
  ui->edit_path->setText(path);
}

void MainWidget::OnBtnEncrypt() {
  int ec;

  std::string file_path = ui->edit_path->text().toLocal8Bit().data();
  if (file_path.empty()) {
    MsgBox(tr("Please input the file to encrypt"));
    return;
  }

  auto file_size = fs::file_size(file_path);
  if (file_size <= 0) {
    MsgBox(tr("Empty file"));
    return;
  }

  // 发送者索引
  int sender_index = ui->label_sender->property(kIndexFlag.c_str()).toInt();
  if (sender_index < 0 || sender_index >= kSM2KeyPairCount) {
    MsgBox(tr("Invalid sender index"));
    return;
  }

  // 获取接收者的公钥索引
  int receiver_index = -1;
  std::string current_name = ui->comboBox->currentText().toUtf8().data();
  {
    proto::IndexInfo indexs;
    ec = ReadOthersIndex(indexs);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to read users information"));
      return;
    }

    bool found = false;
    for (int i = 0; i < indexs.index_size(); ++i) {
      if (indexs.index(i).name() == current_name) {
        receiver_index = indexs.index(i).index();
        found = true;
        break;
      }
    }
    if (!found) {
      MsgBox(tr("Cannot find the receiver"));
      return;
    }
  }

  // 获取指定公钥
  std::vector<BYTE> receiver_pubkey;
  {
    std::vector<std::vector<BYTE>> pubkeys;
    ec = ReadPublicKeysFromUKey(pubkeys);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to read public keys"));
      return;
    }

    if (static_cast<int>(pubkeys.size()) < receiver_index + 1) {
      MsgBox(tr("Failed to read receiver's public key"));
      return;
    } else {
      receiver_pubkey = pubkeys[receiver_index];
    }
  }

  // 生成随机密钥
  std::vector<BYTE> random;
  {
    ec = GenRandom(random, kSM4KeySize);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to generate SM4 key"));
      return;
    }
  }

  // 公钥加密随机密钥
  std::vector<BYTE> enc_random;
  {
    ec = SM2Encrypt(receiver_pubkey, random, enc_random);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to encrypt SM4 key"));
      return;
    }
  }

  // 获取加密文件路径：文件名 + sender + receiver + time
  std::string enc_path;
  {
    std::string sender = ui->label_sender->text().toLocal8Bit().data();
    std::string receiver = ui->comboBox->currentText().toLocal8Bit().data();;
    std::string timestr = TimeString();
    fs::path path(file_path);
    fs::path parent_path = path.parent_path();
    fs::path extension = path.extension();
    fs::path stem = path.stem();
    parent_path /= fs::path(stem.string() + "-(" + sender + " to " + receiver + ")-" + TimeString() +
                            extension.string());
    parent_path.make_preferred();
    enc_path = parent_path.string();
  }

  EVP_CIPHER_CTX *ctx;
  int once_len;
  {
    if (!(ctx = EVP_CIPHER_CTX_new())) {
      MsgBox(tr("Failed to create cipher context"));
      return;
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, random.data(), kIV.data())) {
      MsgBox(tr("Failed to initialize cipher context"));
      return;
    }
  }

  // 文件最开始写入加密后的随机密钥，(发送者，文件大小)，文件的hash
  std::ifstream infile(file_path, std::ios::in | std::ios::binary);
  std::ofstream outfile(enc_path, std::ios::out | std::ios::binary);
  {
    // 标记是否为加密文件
    outfile.write(kEncryptFlag.data(), kEncryptFlag.size());
    // 接收者公钥索引
    outfile.write((char*)&receiver_index, sizeof(int));
    // 发送者公钥索引
    outfile.write((char*)&sender_index, sizeof(int));
    // 公钥加密后的随机密钥
    outfile.write((char*)enc_random.data(), enc_random.size());
    // 加密标记
    std::unique_ptr<char, decltype(lm)> enc_buf(new char[kCheckFlag.size() + kSM4KeySize], lm);
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)enc_buf.get(), &once_len,
                               (unsigned char*)kCheckFlag.data(), kCheckFlag.size())) {
      MsgBox(tr("Failed to encrypt data"));
      return;
    }
    outfile.write(enc_buf.get(), once_len);
  }

  // 加密。加密的同时写入文件，并更新进度
  {
    std::unique_ptr<char, decltype(lm)> buf(new char[kReadSize], lm);
    std::unique_ptr<char, decltype(lm)> enc_buf(new char[kReadSize + kSM4KeySize], lm);
    while (!infile.eof()) {
      auto readlen = infile.read(buf.get(), kReadSize).gcount();
      if (!readlen) {
        break;
      }
      if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)enc_buf.get(), &once_len,
                                 (unsigned char*)buf.get(), readlen)) {
        MsgBox(tr("Failed to encrypt data"));
        return;
      }
      outfile.write(enc_buf.get(), once_len);
    }
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)enc_buf.get(), &once_len)) {
      MsgBox(tr("Failed to encrypt data"));
      return;
    }
    if (once_len > 0) {
      outfile.write(enc_buf.get(), once_len);
    }
  }

  MsgBox(tr("Success to encrypt, store to ") + QString::fromLocal8Bit(enc_path.data()));
}

void MainWidget::OnBtnDecrypt() {
  int ec;

  std::string file_path = ui->edit_path->text().toLocal8Bit().data();
  if (file_path.empty()) {
    MsgBox(tr("Invalid file path"));
    return;
  }

  auto file_size = fs::file_size(file_path);
  if (file_size <= 0) {
    MsgBox(tr("Empty file"));
    return;
  }

  // 解密初始化
  EVP_CIPHER_CTX *ctx;
  int once_len = 16;
  {
    if (!(ctx = EVP_CIPHER_CTX_new())) {
      MsgBox(tr("Failed to create cipher context"));
      return;
    }
  }

  std::ifstream infile(file_path, std::ios::in | std::ios::binary);
  std::string encrypt_flag(kEncryptFlag.size(), 0);
  std::string check_flag(kCheckFlag.size(), 0);
  std::string enc_check_flag(kCheckFlag.size(), 0);
  int sender_index = -1;
  int receiver_index = -1;
  std::vector<BYTE> enc_random(kSM4KeySize + 96, 0);
  std::vector<BYTE> random(kSM4KeySize);
  {
    // 标记是否为加密文件
    infile.read(encrypt_flag.data(), encrypt_flag.size());
    // 接收者公钥索引
    infile.read((char*)&receiver_index, sizeof(int));
    // 发送者公钥索引
    infile.read((char*)&sender_index, sizeof(int));
    // 公钥加密后的随机密钥
    infile.read((char*)enc_random.data(), enc_random.size());
    // 公钥解密出随机密钥
    ec = SM2Decrypt(enc_random, random);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to decrypt random key"));
      return;
    }
    // 解密出随机密钥
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, random.data(), kIV.data())) {
      MsgBox(tr("Failed to initialize decrypt context"));
      return;
    }
    // 加密标记
    infile.read(enc_check_flag.data(), enc_check_flag.size());
    //
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)check_flag.data(), &once_len,
                               (unsigned char*)enc_check_flag.data(), enc_check_flag.size())) {
      MsgBox(tr("Failed to decrypt data"));
      return;
    }
  }

  // 检查公钥是否符合，不符合直接不解密
  {
    if (encrypt_flag != kEncryptFlag) {
      MsgBox(tr("Not encrypted file"));
      return;
    }

    if (check_flag != kCheckFlag) {
      MsgBox(tr("Failed to decrypt the file, please be sure if it is a file sent to yourself"));
      return;
    }

    if (sender_index < 0 || sender_index > kSM2KeyPairCount) {
      MsgBox(tr("Invalid sender index"));
      return;
    }
    if (receiver_index < 0 || receiver_index > kSM2KeyPairCount) {
      MsgBox(tr("Invalid sender index"));
      return;
    }
  }

  std::string dec_path;
  {
    fs::path original(file_path);
    std::string file_name = original.stem().string() + "-decrypt" + original.extension().string();
    original.replace_filename(file_name);
    dec_path = original.string();
  }

  // 解密
  {
    std::ofstream outfile(dec_path, std::ios::out | std::ios::binary);
    std::unique_ptr<char, decltype(lm)> buf(new char[kReadSize], lm);
    std::unique_ptr<char, decltype(lm)> dec_buf(new char[kReadSize + 16], lm);
    bool once_flag = true;
    while (!infile.eof()) {
      auto readlen = infile.read(buf.get(), kReadSize).gcount();
      if (!readlen) {
        break;
      }
      if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)dec_buf.get(), &once_len,
                                 (unsigned char*)buf.get(), readlen)) {
        MsgBox(tr("Failed to SM4 decrypt"));
        return;
      }
      if (once_flag) {
        once_flag = false;
        continue;
      }
      outfile.write(dec_buf.get(), once_len);
    }
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)dec_buf.get(), &once_len)) {
      MsgBox(tr("Failed to SM4 decrypt"));
      return;
    }
    if (once_len > 0) {
      outfile.write(dec_buf.get(), once_len);
    }
  }

  MsgBox(tr("Success to decrypt, store to ") + QString::fromLocal8Bit(dec_path.data()));
}

void MainWidget::OnBtnVerifyPIN() {
  std::string pwd = ui->edit_pin->text().toStdString();
  if (pwd.empty()) {
    MsgBox(tr("Please input the password"));
    return;
  }
  int ec = VerifyPIN(std::vector<BYTE>(pwd.begin(), pwd.end()));
  if (ec <= kNoDevice && ec >= kErrConnect) {
    MsgBox(GetInfoFromErrCode(ec));
    return;
  } else if (ec != kSuccess) {
    MsgBox(tr("Failed to verify PIN"));
    return;
  }

  UpdateSenderLabel();
  UpdateComboBox();
  ui->stackedWidget->setCurrentIndex(kPageOpIndex);
  this->setFixedSize(600, 400);
}

void MainWidget::OnBtnChangePIN() {
  std::string pwd = ui->edit_old_pin->text().toStdString();
  if (pwd.empty()) {
    MsgBox(tr("Please input the password"));
    return;
  }

  std::string new_pwd = ui->edit_new_pin->text().toStdString();
  if (new_pwd.empty()) {
    MsgBox(tr("Please input the new password"));
    return;
  }

  int ec = ChangePIN(std::vector<BYTE>(pwd.begin(), pwd.end()),
                     std::vector<BYTE>(new_pwd.begin(), new_pwd.end()));
  if (ec <= kNoDevice && ec >= kErrConnect) {
    MsgBox(GetInfoFromErrCode(ec));
    return;
  } else if (ec != kSuccess) {
    MsgBox(tr("Failed to change PIN"));
    return;
  }

  UpdateSenderLabel();
  UpdateComboBox();

  MsgBox(tr("Success"));
}

void MainWidget::OnBtnUpdateIndex() {
  {
    //std::string path = QFileDialog::getOpenFileName(this, tr("Open File")).toLocal8Bit().data();
    std::string path = ui->edit_update_path->text().toLocal8Bit().data();
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input) {
      MsgBox(tr("Failed to read file"));
      return;
    }
    proto::IndexInfo indexs;
    if (!indexs.ParseFromIstream(&input)) {
      MsgBox(tr("Failed to parse file"));
      return;
    }
    // 写入USB Key
    auto ec = WriteOthersIndex(indexs);
    if (ec <= kNoDevice && ec >= kErrConnect) {
      MsgBox(GetInfoFromErrCode(ec));
      return;
    } else if (ec != kSuccess) {
      MsgBox(tr("Failed to write information to USB Key"));
      return;
    }
  }
  UpdateComboBox();
  MsgBox(tr("Success"));
}

void MainWidget::OnBtnUpdateBrowser() {
  ui->edit_update_path->setText(QFileDialog::getOpenFileName(this, tr("Open File")));
}

void MainWidget::UpdateSenderLabel() {
  proto::NameIndex index;
  int ec = ReadUserIndex(index);
  if (ec != kSuccess) {
    ui->edit_account->setText(tr("No device is found"));
    ui->label_sender->setText(tr("Cannot get sender"));
    ui->label_sender->setProperty(kIndexFlag.c_str(), QVariant(-1));
  } else {
    ui->edit_account->setText(QString::fromStdString(index.name()));
    ui->label_sender->setText(QString::fromStdString(index.name()));
    ui->label_sender->setProperty(kIndexFlag.c_str(), QVariant(index.index()));
  }
}

void MainWidget::UpdateComboBox() {
  // 检查index.db是否存在，如果存在则读取，并显示在comboBox控件
  proto::IndexInfo indexs;
  {
    auto ec = ReadOthersIndex(indexs);
    if (ec != kSuccess) {
      MsgBox(tr("Failed to read other user's information from USB Key"));
      return;
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

void MainWidget::MsgBox(const QString& msg) {
  QMessageBox msgBox(this);
  msgBox.setWindowTitle(tr("Tip"));
  msgBox.setText(msg);
  msgBox.exec();
}

QString MainWidget::GetInfoFromErrCode(int ec) {
  switch (ec) {
  case kNoDevice:
    return tr("Device not found");
  case kTooManyDevice:
    return tr("Too many device, please insert one only");
  case kErrConnect:
    return tr("Failed to connect device");
  default:
    return tr("Unknown error");
  }
}