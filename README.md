## OpenSSL 自签名证书创建

> 除非先前将自签名证书导入浏览器，否则不会向任何第三方验证自签名证书。如果需要更高的安全性，则应使用由证书颁发机构（CA）签名的证书。

我们基于以下步骤创建自己的CA和签名证书

1. 创建自己的权限（即成为CA）
2. 为服务器创建证书签名请求（CSR）
3. 使用CA密钥对服务器的CSR进行签名
4. 在服务器上安装服务器证书
5. 在客户端上安装CA证书

## 大致的步骤

1. Using the x509 module
openssl x509 ...
...

2. Using the req module
openssl req ...

3. Using the ca module
openssl ca ...
...

## 创建CA Certificate

```
// 基于config生成CA证书
$ cd ca_cert
$ openssl req -x509 -config ../openssl-ca.cnf -nodes -newkey rsa:2048 -days 3650 \
    -keyout cakey.pem -out cacert.pem

// 检测生成的CA证书
$ openssl x509  -in cacert.pem -noout -text
```

## 创建CSR(证书请求)

先回到根目录，在csr目录中，执行下列操作：

```
// 方式1，基于openssl-server.cnf证书请求模板配置文件, 创建预申请的服务器证书请求
$ cd ./sign_csr/
$ openssl req -config openssl-server.cnf -newkey rsa:2048 -nodes -keyout server-key.pem -out server-csr.pem

// 方式2，直接快速创建服务器证书请求（配置中以及有很多基本信息的配置了，比如信息摘要摘要算法等）
$ openssl req -newkey rsa:2048 -nodes -keyout ./sign_csr/server-key.pem -out ./sign_csr/server-csr.pem \
    -subj "/C=CN/ST=GD/L=ShenZhen/O=GlobaleGrow Inc./OU=Tech Development./CN=TK Server Development/emailAddress=tkstorm1988@gmail.com" \
    -reqexts SAN -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=IP:127.0.0.1,DNS:localhost,DNS:www.tkstorm.cc,DNS:tkstorm.cc,DNS:::1"))

// 查看生成的证书请求
$ openssl req -in ./server-csr.pem -text -noout
```

### SAN部分的信息
```
X509v3 Subject Alternative Name:
    DNS:tkstorm.cc, DNS:www.tkstorm.cc, DNS:mail.tkstorm.cc
```

## 利用CA签发CSR

### 初始化相关文件

回到ca配置文件所在目录：

```
$ touch ./db/db.txt

$ echo '01' > ./db/serial.txt

// 证书生成的目录
$ mkdir sign_cert
```

### 证书签发

基于配置文件`openssl-ca.cnf`（其中已设定了CA证书+私钥等信息），选择签发策略，对创建的证书请求进行证书签发

```
// 签发服务器证书
$ openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -infiles ./sign_csr/server-csr.pem

// 查看证书
openssl x509 -in ./sign_cert/02.pem -text -noout
```

## 项目目录
一切就绪后，目录如下
```
/data/github.com/ss-cert on  master! ⌚ 13:13:13
$ tree
.
├── README.md
├── ca_cert
│   ├── cacert.pem
│   └── cakey.pem
├── db
│   ├── db.txt
│   ├── db.txt.attr
│   ├── db.txt.old
│   ├── serial.txt
│   └── serial.txt.old
├── openssl-ca.cnf  ---- ca sign config file
├── sign_cert
│   └── 01.pem      ---- new signed certificates
└── sign_csr
    ├── openssl-server.cnf  ---- server sign request config file 
    ├── server-csr.pem
    └── server-key.pem
```

## 更多细节

参考 https://tkstorm.com/openssl-usages
