package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// 添加受信任的自签名CA证书，发起一个HTTPS请求
func main() {
	// 生成的自签名CA证书读取
	caCertPEM, err := ioutil.ReadFile("/tmp/cacert.pem")
	if err != nil {
		log.Fatal("The added CA certificate does not exist.", err)
	}

	// 配置客户端信任CA
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	// 初始化一个http客户端，发起一个https请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}
	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Fatal("http client request fail:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("resp read fail:", err)
		}
		fmt.Printf("read %d byte, content: %s\n", len(bodyBytes), bodyBytes)
	}
}
