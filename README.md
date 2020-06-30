# 基于安全信息编码的智能制造安全保障技术的罐体自动化生产线

## 软件组成

1. 软件包括两个客户端：发行者客户端（管理员）、使用者客户端（普通用户）；

2. 发行者：生成密钥对，整理用户信息，建立 **用户:公钥** 的对应关系；

3. 使用者：导入发行者下发的 **用户:公钥** 对应关系；
4. 发行者不需要USB Key；只负责管理其他的USB Key；
5. 使用者客户端写入普通用户Key的CDROM区；
6. 发行者生成密钥对后，最后一个密钥对，作为根证书的私钥；
7. **用户:公钥**：即索引+用户名即可；因为公钥一定是按照顺序排列的；

## 工作流程

1. 发行者生成n+1个密钥对，加密存储到配置文件；此操作只允许执行一次，防止重复生成；最后一个密钥对用于签名验签；发行者的密码加密随机密钥，随机密钥加密密钥对；
2. 发行者插入一个USB Key，填入姓名，软件自动建立索引（编号），导入公私钥，写入n个公钥；并往用户、索引、公钥的关系文件插入一行；
3. 发行者把用户、索引、公钥的关系文件，发给各用户；
4. 用户导入用户、索引、公钥的关系文件；
5. 用户A发送数据给用户B时，生成一个随机密钥，并用B的公钥进行对随机密钥加密（通过姓名或者索引找到公钥），使用随机密钥加密数据，并把加密后的随机密钥+加密后的数据一起写入一个文件，发送给B；用户B使用自己的私钥解密出随机密钥，使用随机密钥解密出数据。

## 发行者功能

1. 安装客户端
2. 生成用于加密密钥对的随机密钥
3. 生成n个密钥对，生成根证书，使用随机密钥加密存储到本地
4. 下发单个密钥对、所有公钥、根证书到USB Key（密钥对、公钥的顺序必须一致）
5. 用户姓名+索引信息 写入到关系文件
6. 最终的关系文件发给每个用户

## 使用者功能

1. 安装客户端
2. 导入（更新）关系文件
3. A发送文件给B：选择B的姓名，软件以此找到B的公钥；产生随机密钥；对称加密数据；非对称加密随机密钥；加密的随机密钥+加密的数据写入文件
4. B接收到A的文件：私钥非对称解密出随机密钥；随机密钥解密出数据；

## 开发事项

1. 基于CMake、vcpkg、Qt；
2. 开发环境为vs2017；
3. U03的通信库u03-ukey作为第三方库；