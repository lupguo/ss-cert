package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

//Generate 生成PEM格式的自签名证书PKI套件(支持RSA和ECDSA生成私钥)
// 生成ECDSA自签名证书秘钥套件:
// 		1. 基于EC椭圆算法生成EC公私钥对
//		2. 基于证书模板、x509 ca证书、证书公钥、私钥，创建一个X.509v3，格式为ASN.1(DER)格式的签名证书
//		3. 将crypto.PrivateKey私钥转换成DER格式的证书私钥
//		4. 将证书和证书私钥转换成PEM格式返回
//	openssl x509证书查看:
//		$ cat|openssl x509 -text -noout
//	openssl 证书校验:
//		$ openssl verify -verbose -CAfile /tmp/ca.cert /tmp/ca.cert
//		/tmp/ca.cert: OK
func GenerateRSA(certTmpl, caCert *x509.Certificate, pub, priv interface{}) (certPEM, privPEM []byte) {
	// 基于模板，签发DER格式证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, certTmpl, caCert, pub, priv)
	if err != nil {
		log.Fatal("failed to create x509 self-signed certificate:", err)
	}
	// 转换成PKCS1#1格式, ASN.1(DER)格式的证书私钥
	caPrivDER := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))

	// 将证书和对应的私钥编码成PEM格式
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   caCertDER,
	})
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   caPrivDER,
	})
	return certPEM, privPEM
}

//GenerateEC 生成PEM格式证书，但私钥为EC算法私钥
func GenerateEC(certTmpl, caCert *x509.Certificate, pub, priv interface{}) (certPEM, privPEM []byte) {
	// 基于模板，签发DER格式证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, certTmpl, caCert, pub, priv)
	if err != nil {
		log.Fatal("failed to create x509 self-signed certificate:", err)
	}
	// 将EC格式的caPriv私钥，转换成ASN.1(DER)格式的证书私钥
	caPrivDER, err := x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))

	// 将证书和对应的私钥编码成PEM格式
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   caCertDER,
	})
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   caPrivDER,
	})
	return
}

//New 初始化CA证书
func New() *x509.Certificate {
	caCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SELF-CA",
		},
		SerialNumber:          big.NewInt(1988),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	return caCert
}

//NewSrvFromCSR 基于证书请求创建一个服务器端证书模板
func NewSrvFromCSR(csr *x509.CertificateRequest) *x509.Certificate {
	cert := &x509.Certificate{
		// 来至CSR配置的证书请求信息(SAN相关信息)
		Subject:     csr.Subject,
		IPAddresses: csr.IPAddresses,
		DNSNames:    csr.DNSNames,

		// 用于扩展CSR的
		SerialNumber: big.NewInt(1988),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return cert
}

//RSAPubKey 生成RSA公钥和私钥
func RSAPubKey(bits int) (pub crypto.PublicKey, priv crypto.PrivateKey, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return key.Public(), key, err
}

//ECPubKey 生成ecdsa私钥和配对公钥
func ECPubKey() (pub crypto.PublicKey, priv crypto.PrivateKey, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.Public(), key, err
}
