package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

//DNSNames 针对多SNI模式，支持多域名证书的签发
func DNSNames(caCert *x509.Certificate, caKey crypto.PrivateKey, names []string) (srvCertPEM, srvKeyPEM []byte){
	srvPub, srvPriv, err := RSAPubKey(2048)
	if err != nil {
		log.Fatal("key generate fail:", err)
	}

	srvTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-server"},
		SerialNumber: big.NewInt(2045),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 利用CA证书+CA证书私钥，按照证书模板，利用服务端提供的公钥，签发一份服务端使用的证书
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, srvPub, caKey)
	if err != nil {
		log.Fatal("server cert create fail:", err)
	}

	// 将服务端私钥转DER格式
	srvPrivDER := x509.MarshalPKCS1PrivateKey(srvPriv.(*rsa.PrivateKey))

	// 将服务端私钥和证书转成PEM格式
	srvCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   srvCertDER,
	})
	srvKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   srvPrivDER,
	})

	return
}
