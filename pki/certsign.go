package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/tkstorm/ss-cert/pki/internal/cert"
	"io/ioutil"
	"log"
	"os"
)

// 服务端基于客户端发送的CSR请求，签发一份服务端TLS证书
func main() {
	// 1. client: 初始化CSR的申请者的公钥和私钥
	srvPub, srvPriv, err := cert.ECPubKey()
	if err != nil {
		log.Fatal("failed to generate srv keypair:", err)
	}
	// 2. client: 创建一个证书请求
	srvCsrDER, err := cert.CSR(srvPriv)
	if err != nil {
		log.Fatal("failed to generate csr:", err)
	}

	// 3. server: 准备利用CA签发证书请求，生成一个服务端的证书(先校验证书请求，再签发)
	srvCsr, err := x509.ParseCertificateRequest(srvCsrDER)
	if err != nil {
		log.Fatal("failed to parse the request CSR file:", err)
	}
	if err := srvCsr.CheckSignature(); err != nil {
		log.Fatal("failed to check signature for the request CSR file:", err)
	}

	// 4. server: 校验通过，将ca证书和私钥拿出来，签发服务端证书请求
	//caCert := cert.New()
	//caPub, caKey, err := cert.RSAPubKey(1024)
	//if err != nil {
	//	log.Fatal("failed to generate ca keypair:", err)
	//}
	//caCertPEM, caKeyPEM := cert.GenerateRSA(caCert, caCert, caPub, caKey)

	// 4. 读取PEM格式的CA证书&私钥，解析成DER格式，用于服务端证书签发
	caCertPEM, err := ioutil.ReadFile(os.Getenv("CA_CERT"))
	if err != nil {
		log.Fatal("failed to read ca cert:", err)
	}
	caKeyPEM, err := ioutil.ReadFile(os.Getenv("CA_KEY"))
	if err != nil {
		log.Fatal("failed to read ca key:", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCertDER, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatal("failed to parse ca cert:", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)

	// 4. 基于服务端的CSR证书请求，结合签发信息生成证书签发模板
	certTmpl := cert.NewSrvFromCSR(srvCsr)

	// 5. CA签发，生SRV
	srvCertDER, err := x509.CreateCertificate(rand.Reader, certTmpl, caCertDER, srvPub, caKey)
	if err != nil {
		log.Fatal("failed to create srv cert:", err)
	}

	// 6. PEM格式的SRV生成
	srvPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   srvCertDER,
	})

	fmt.Printf("%s", srvPEM)
}
