package tls

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/ultramesh/flato-msp-cert/primitives/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"testing"
)

/*
this test can also be used as a demo for guomi https
*/

type handler struct{}

func (h handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	_, err := res.Write([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
}

func TestHTTPS(t *testing.T) {
	t.Parallel()
	ca := `-----BEGIN CERTIFICATE-----
MIIB5DCCAYmgAwIBAgIBATAKBggqhkjOPQQDAjBMMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRYwFAYDVQQDEw1oeXBlcmNoYWluLmNuMRAwDgYDVQQqEwdEZXZlbG9wMQsw
CQYDVQQGEwJaSDAgFw0xODA3MzAwNDE1MzFaGA8yMTE4MDcwNjA1MTUzMVowTDET
MBEGA1UEChMKSHlwZXJjaGFpbjEWMBQGA1UEAxMNaHlwZXJjaGFpbi5jbjEQMA4G
A1UEKhMHRGV2ZWxvcDELMAkGA1UEBhMCWkgwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAASHyLeSBwZapw/lL8j27csajqbjGFXvXawdT+i4T3nc2H4fKDqtUNru8cPI
kyvHbMo6aJbyJ4X7NzuUv2y6FJe9o1owWDAOBgNVHQ8BAf8EBAMCAgQwJgYDVR0l
BB8wHQYIKwYBBQUHAwIGCCsGAQUFBwMBBgIqAwYDgQsBMA8GA1UdEwEB/wQFMAMB
Af8wDQYDVR0OBAYEBAECAwQwCgYIKoZIzj0EAwIDSQAwRgIhAMXfzpN+SF4MIi3a
QbSpd2IT4T3/PTQ/Gm+iwGH8SVLYAiEAi4/IL1eiOh3TTuyJnAoEYZ1OUtGt2Fbg
Niv2S3xpQK4=
-----END CERTIFICATE-----`
	cert := `-----BEGIN CERTIFICATE-----
MIIB+jCCAaGgAwIBAgIBATAKBggqhkjOPQQDAjBMMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRYwFAYDVQQDEw1oeXBlcmNoYWluLmNuMRAwDgYDVQQqEwdEZXZlbG9wMQsw
CQYDVQQGEwJaSDAgFw0xODA3MzAwNDE2NThaGA8yMTE4MDcwNjA1MTY1OFowTDET
MBEGA1UEChMKSHlwZXJjaGFpbjEWMBQGA1UEAxMNaHlwZXJjaGFpbi5jbjEQMA4G
A1UEKhMHRGV2ZWxvcDELMAkGA1UEBhMCWkgwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATVLH/Bj7S2NlEvwDm0Ien2w9vftt0J0lfdpJ00w+4u8oVSnre6PWRZTYHs
RCvPf9OLUTpAWNpRiLQzpg2qEqbzo3IwcDAOBgNVHQ8BAf8EBAMCAgQwJgYDVR0l
BB8wHQYIKwYBBQUHAwIGCCsGAQUFBwMBBgIqAwYDgQsBMA8GA1UdEwEB/wQFMAMB
Af8wDQYDVR0OBAYEBAECAwQwFgYDKlYBBA9oeXBlY2hhaW5fZWNlcnQwCgYIKoZI
zj0EAwIDRwAwRAIgD8L9G2vW9roVBoz/c4E6/Tp/Wcgcqzylyo0XyqGNpb4CICwZ
UM4lBK3GL/iawgY6aBZL/iEDkfsK7yKji9ZfEtYu
-----END CERTIFICATE-----
`
	priv := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK23xzva2xwfDLFXGtTLJHrVidTIJyIA4+GLYGjGVk5AoAoGCCqGSM49
AwEHoUQDQgAE1Sx/wY+0tjZRL8A5tCHp9sPb37bdCdJX3aSdNMPuLvKFUp63uj1k
WU2B7EQrz3/Ti1E6QFjaUYi0M6YNqhKm8w==
-----END EC PRIVATE KEY-----`
	tempPath := os.TempDir()
	cf, err := os.OpenFile(path.Join(tempPath, "cert.cert"),
		os.O_CREATE|os.O_RDWR, 0777)
	assert.Nil(t, err)
	_, _ = cf.Write([]byte(cert))
	_ = cf.Close()

	cf, err = os.OpenFile(path.Join(tempPath, "cert.priv"),
		os.O_CREATE|os.O_RDWR, 0777)
	assert.Nil(t, err)
	_, _ = cf.Write([]byte(priv))
	_ = cf.Close()
	// test

	tcpListener, err := net.Listen("tcp", "127.0.0.1:32465")
	assert.Nil(t, err)

	certPair, err := LoadX509KeyPair(path.Join(tempPath, "cert.cert"),
		path.Join(tempPath, "cert.priv"))
	assert.Nil(t, err)

	tlsConfig := &Config{
		Certificates: []Certificate{certPair},
	}

	//core function
	tlsListener := NewListener(tcpListener, tlsConfig)

	server := &http.Server{
		Handler: new(handler),
	}
	go func() {
		err = server.Serve(tlsListener)
		if err != nil {
			log.Fatal(err)
		}
	}()

	tcpDialer := &net.Dialer{}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca))
	tlsConn, err := DialWithDialer(tcpDialer, "tcp", "127.0.0.1:32465",
		&Config{
			ServerName: "hyperchain.cn",
			RootCAs:    pool,
		})
	if err != nil {
		fmt.Println("test tcpDial: " + err.Error())
		t.Fail()
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
	}

	//!!!!Key point:
	// The following request can only write http, not write https
	rep, err := httpClient.Get("http://127.0.0.1:32465")
	if err != nil {
		fmt.Println("test tls read: " + err.Error())
		t.Fail()
	}
	buf, err := ioutil.ReadAll(rep.Body)
	if err != nil {
		fmt.Println("test tls read: " + err.Error())
		t.Fail()
	}
	assert.Equal(t, []byte("hello"), buf)
}
