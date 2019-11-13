package main

import (
	"crypto/tls"
	"fmt"
	"github.com/tkstorm/ss-cert/pki/internal/cert"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// 初始化一个自签名的CA，利用CA签发一个支持多DNS名称的服务端证书，并创建一个HTTPS服务
func main() {
	// ca证书初始化
	caCert := cert.New()

	// 生成RSA私钥&自签名证书
	caPub, caKey, err := cert.RSAPubKey(1024)
	if err != nil {
		log.Fatal("failed to generate keypair:", err)
	}
	caCertPEM, caKeyPEM := cert.GenerateRSA(caCert, caCert, caPub, caKey)
	fmt.Printf("%s%s\n", caCertPEM, caKeyPEM)
	ioutil.WriteFile("/tmp/cacert.pem", caCertPEM, 0644)

	// 利用ca证书+证书私钥，签发一份服务器证书
	dnsNames := []string{
		"localhost",
		"tkstorm.com",
		"a.tkstorm.com",
		"b.tkstorm.com",
		"example.cn",
		"a.example.cn",
	}
	certPEM, keyPEM := cert.DNSNames(caCert, caKey, dnsNames)
	fmt.Printf("%s%s\n", certPEM, keyPEM)

	// 加载PEM格式服务器证书和私钥，用于TLS认证 - 开启HTTPS功能
	srvTLSCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal("failed to parse key pair:", err)
	}

	// 初始化HTTPS服务器
	httpdSrv := &http.Server{
		Addr:              ":8443",
		Handler:           nil,
		TLSConfig:         &tls.Config{
			Certificates: []tls.Certificate{
				srvTLSCert,
			},
		},
		ReadTimeout:       3*time.Second,
		ReadHeaderTimeout: 2*time.Second,
		WriteTimeout:      5*time.Second,
		IdleTimeout:       60*time.Second,
	}
	httpdSrv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "You're using https!")
	})
	log.Fatal(httpdSrv.ListenAndServeTLS("",""))
}