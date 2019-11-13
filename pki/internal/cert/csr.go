package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
)

//CSR 客户端生成一份证书签发请求
func CSR(priv crypto.PrivateKey) (csrDER []byte, err error) {
	// 证书模板
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"GlobaleGrow", "IT Department"},
			OrganizationalUnit: []string{"Gopher"},
			Locality:           []string{"ShenZhen", "NanShan"},
			Province:           []string{"GuangDong"},
			StreetAddress:      []string{"Dong Bin Road"},
			PostalCode:         []string{"5180000"},
			SerialNumber:       "",
			CommonName:         "X-Group",
			Names:              nil,
			ExtraNames:         nil,
		},
		Extensions:      nil,
		ExtraExtensions: nil,
		DNSNames: []string{
			"tkstorm.com",
			"archstat.com",
			"es.tkstorm.com",
		},
		EmailAddresses: []string{"tkstorm1988@gmail.com"},
	}

	// 生成一份证书签发请求
	return x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
}
