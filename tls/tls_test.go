// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/ultramesh/flato-msp-cert/primitives"
	gmx509 "github.com/ultramesh/flato-msp-cert/primitives/x509"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
`

// keyPEM is the same as rsaKeyPEM, but declares itself as just
// "PRIVATE KEY", not "RSA PRIVATE KEY".  https://golang.org/issue/4477
var keyPEM = `-----BEGIN PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END PRIVATE KEY-----
`

//curve is secp512
var ecdsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----
`

var ecdsaKeyPEM = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC PRIVATE KEY-----
`
var secp256k1CertPem = `-----BEGIN CERTIFICATE-----
MIIB1DCCAYCgAwIBAgIBATAKBggqhkjOPQQDAjAzMQwwCgYDVQQKEwNkZXYxFjAU
BgNVBAMTDWh5cGVyY2hhaW4uY24xCzAJBgNVBAYTAlpIMCAXDTIwMDMxODEyMDQw
NVoYDzIxMjAwMjIzMTMwNDA1WjBDMQwwCgYDVQQKEwNkZXYxFjAUBgNVBAMTDWh5
cGVyY2hhaW4uY24xCzAJBgNVBAYTAlpIMQ4wDAYDVQQqEwVyY2VydDBWMBAGByqG
SM49AgEGBSuBBAAKA0IABBgIHMmrLmoMKCMVR50ap/lavp5pefAWTj77Pg8ArPwu
+R+TMHggMIU4jz9cFgpY/OdsWi9Iqm4TgzzFC9c7NAijdjB0MA4GA1UdDwEB/wQE
AwIChDAmBgNVHSUEHzAdBggrBgEFBQcDAgYIKwYBBQUHAwEGAioDBgOBCwEwDAYD
VR0TAQH/BAIwADANBgNVHQ4EBgQEAQIDBDAPBgNVHSMECDAGgAQBAgMEMAwGAypW
AQQFcmNlcnQwCgYIKoZIzj0EAwIDQgAWzGBAS5FWD+p8HDCK35vvHxPj+OraH3EO
ztw2EsM2zi4Mr+mwMyOkJ8ORuGbHEGGMSwqS+uEuOjR9Ds8yKnCdAA==
-----END CERTIFICATE-----
`
var secp256k1KeyPem = `
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIGaw5w8i1TC0MqhonR/ReBfhKOgqjaqlji6ZkLLjbD6voAcGBSuBBAAK
oUQDQgAEGAgcyasuagwoIxVHnRqn+Vq+nml58BZOPvs+DwCs/C75H5MweCAwhTiP
P1wWClj852xaL0iqbhODPMUL1zs0CA==
-----END EC PRIVATE KEY-----
`
var sm2CertPem = `-----BEGIN CERTIFICATE-----
MIIB5jCCAY2gAwIBAgIBATAKBggqgRzPVQGDdTBOMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5jbjELMAkGA1UEBhMCWkgxDjAM
BgNVBCoTBWVjZXJ0MCAXDTIwMDMxODAxNDQxM1oYDzIxMjAwMjIzMDI0NDEzWjBO
MRMwEQYDVQQKEwpIeXBlcmNoYWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5j
bjELMAkGA1UEBhMCWkgxDjAMBgNVBCoTBWVjZXJ0MFkwEwYHKoZIzj0CAQYIKoEc
z1UBgi0DQgAEUHz09LByI4IJbg5AruKdR6+qJwWV7PQhJicnvjtOlrZU6q08qicg
vYGSqJCU9zuNpQADjodhWSbByautDEg+pqNaMFgwDgYDVR0PAQH/BAQDAgKEMCYG
A1UdJQQfMB0GCCsGAQUFBwMCBggrBgEFBQcDAQYCKgMGA4ELATAPBgNVHRMBAf8E
BTADAQH/MA0GA1UdDgQGBAQBAgMEMAoGCCqBHM9VAYN1A0cAMEQCIHaMnRSYoPDh
oSvnukP86EKd5EutcFpNneluAr3wYi8IAiBrfXy0mD+WLB2QSTNEQQvwNb8kJJs6
VM4iJS6Dkpz7AQ==
-----END CERTIFICATE-----
`

var sm2KeyPem = `-----BEGIN EC PRIVATE KEY-----
MHgCAQECIQCpMnEYWMpmoJFidYwYdUsKUqdKYY2UYrETZ06AtK/mU6AKBggqgRzP
VQGCLaFEA0IABFB89PSwciOCCW4OQK7inUevqicFlez0ISYnJ747Tpa2VOqtPKon
IL2BkqiQlPc7jaUAA46HYVkmwcmrrQxIPqY=
-----END EC PRIVATE KEY-----
`
var keyPairTests = []struct {
	algo string
	cert string
	key  string
}{
	{"ECDSA", ecdsaCertPEM, ecdsaKeyPEM},
	{"RSA", rsaCertPEM, rsaKeyPEM},
	{"secp256k1", secp256k1CertPem, secp256k1KeyPem},
	{"sm2", sm2CertPem, sm2KeyPem},
	{"RSA-untyped", rsaCertPEM, keyPEM}, // golang.org/issue/4477
}

func TestX509KeyPair(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairTests {
		pem = []byte(test.cert + test.key)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s cert followed by %s key: %s", test.algo, test.algo, err)
		}
		pem = []byte(test.key + test.cert)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s key followed by %s cert: %s", test.algo, test.algo, err)
		}
	}
}

func TestX509KeyPairErrors(t *testing.T) {
	_, err := X509KeyPair([]byte(rsaKeyPEM), []byte(rsaCertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when arguments were switched")
	}
	if subStr := "been switched"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when switching arguments to X509KeyPair, but the error was %q", subStr, err)
	}

	_, err = X509KeyPair([]byte(rsaCertPEM), []byte(rsaCertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were certificates")
	}
	if subStr := "certificate"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were certificates, but the error was %q", subStr, err)
	}

	const nonsensePEM = `
-----BEGIN NONSENSE-----
Zm9vZm9vZm9v
-----END NONSENSE-----
`

	if _, err = X509KeyPair([]byte(nonsensePEM), []byte(nonsensePEM)); err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were nonsense")
	}
	if subStr := "NONSENSE"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were nonsense, but the error was %q", subStr, err)
	}
}

func TestX509MixedKeyPair(t *testing.T) {
	if _, err := X509KeyPair([]byte(rsaCertPEM), []byte(ecdsaKeyPEM)); err == nil {
		t.Error("Load of RSA certificate succeeded with ECDSA private key")
	}
	if _, err := X509KeyPair([]byte(ecdsaCertPEM), []byte(rsaKeyPEM)); err == nil {
		t.Error("Load of ECDSA certificate succeeded with RSA private key")
	}
	if _, err := X509KeyPair([]byte(secp256k1CertPem), []byte(ecdsaKeyPEM)); err == nil {
		t.Error("Load of secp256k1 certificate succeeded with p512 private key")
	}
	if _, err := X509KeyPair([]byte(sm2CertPem), []byte(ecdsaKeyPEM)); err == nil {
		t.Error("Load of sm2 certificate succeeded with p512 private key")
	}
}

func newLocalListener(t testing.TB) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestDialTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	listener := newLocalListener(t)

	addr := listener.Addr().String()
	defer func() { _ = listener.Close() }()

	complete := make(chan bool)
	defer close(complete)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		<-complete
		_ = conn.Close()
	}()

	dialer := &net.Dialer{
		Timeout: 10 * time.Millisecond,
	}

	var err error
	if _, err = DialWithDialer(dialer, "tcp", addr, nil); err == nil {
		t.Fatal("DialWithTimeout completed successfully")
	}

	if !isTimeoutError(err) {
		t.Errorf("resulting error not a timeout: %v\nType %T: %#v", err, err, err)
	}
}

func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// tests that Conn.Read returns (non-zero, io.EOF) instead of
// (non-zero, nil) when a Close (alertCloseNotify) is sitting right
// behind the application data in the buffer.
func TestConnReadNonzeroAndEOF(t *testing.T) {
	// This test is racy: it assumes that after a write to a
	// localhost TCP connection, the peer TCP connection can
	// immediately read it. Because it's racy, we skip this test
	// in short mode, and then retry it several times with an
	// increasing sleep in between our final write (via srv.Close
	// below) and the following read.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	var err error
	for delay := time.Millisecond; delay <= 64*time.Millisecond; delay *= 2 {
		if err = testConnReadNonzeroAndEOF(t, delay); err == nil {
			return
		}
	}
	t.Error(err)
}

func testConnReadNonzeroAndEOF(t *testing.T, delay time.Duration) error {
	ln := newLocalListener(t)
	defer func() { _ = ln.Close() }()

	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	clientConfig := testConfig.Clone()
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	srv := <-srvCh
	if srv == nil {
		return serr
	}

	buf := make([]byte, 6)

	_, _ = srv.Write([]byte("foobar"))
	n, err := conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		return fmt.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
	}

	_, _ = srv.Write([]byte("abcdef"))
	_ = srv.Close()
	time.Sleep(delay)
	n, err = conn.Read(buf)
	if n != 6 || string(buf) != "abcdef" {
		return fmt.Errorf("Read = %d, buf= %q; want 6, abcdef", n, buf)
	}
	if err != io.EOF {
		return fmt.Errorf("Second Read error = %v; want io.EOF", err)
	}
	return nil
}

func TestTLSUniqueMatches(t *testing.T) {
	ln := newLocalListener(t)
	defer func() { _ = ln.Close() }()

	serverTLSUniques := make(chan []byte)
	go func() {
		for i := 0; i < 2; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			serverConfig := testConfig.Clone()
			srv := Server(sconn, serverConfig)
			if err := srv.Handshake(); err != nil {
				t.Error(err)
				return
			}
			serverTLSUniques <- srv.ConnectionState().TLSUnique
		}
	}()

	clientConfig := testConfig.Clone()
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.ConnectionState().TLSUnique, <-serverTLSUniques) {
		t.Error("client and server channel bindings differ")
	}
	_ = conn.Close()

	conn, err = Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if !conn.ConnectionState().DidResume {
		t.Error("second session did not use resumption")
	}
	if !bytes.Equal(conn.ConnectionState().TLSUnique, <-serverTLSUniques) {
		t.Error("client and server channel bindings differ when session resumption is used")
	}
}
func newHTTPServer(serverIP string) *http.Server {

	http.HandleFunc(serverIP, func(w http.ResponseWriter, r *http.Request) { fmt.Println("receive ") })
	server := &http.Server{Addr: serverIP, Handler: nil}

	return server
}
func TestVerifyHostname(t *testing.T) {
	//todo: fix
	t.Skip("ci")
	rand.Seed(time.Now().Unix())
	serverIP := "localhost:" + strconv.Itoa(rand.Int()%1000+8000)
	server := newHTTPServer(serverIP)
	defer func() { _ = server.Close() }()
	go func() {
		err := server.ListenAndServeTLS("./testdata/localhost.crt", "./testdata/localhost.key")
		if err != http.ErrServerClosed {
			fmt.Println("err ", err)
		}
	}()
	bs, _ := ioutil.ReadFile("./testdata/localhost.crt")
	cp := gmx509.NewCertPool()
	root, _ := primitives.ParseCertificate(bs)
	cp.AddCert(root)
	c, err := Dial("tcp", serverIP, &Config{RootCAs: cp})
	if err != nil {
		t.Fatal(err)
	}
	if verr := c.VerifyHostname("localhost"); verr != nil {
		t.Fatalf("verify www.baidu.com: %v", verr)
	}

	c, err = Dial("tcp", serverIP, &Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHostname("localhost"); err == nil {
		t.Fatalf("verify www.baidu.com succeeded with InsecureSkipVerify=true")
	}
}

func TestVerifyHostnameResumed(t *testing.T) {
	//todo: fix
	t.Skip("ci")
	rand.Seed(time.Now().Unix() + 1)
	serverIP := "localhost:" + strconv.Itoa(rand.Int()%1000+8000)
	server := newHTTPServer(serverIP)
	defer func() { _ = server.Close() }()
	go func() {
		err := server.ListenAndServeTLS("./testdata/localhost.crt", "./testdata/localhost.key")
		if err != http.ErrServerClosed {
			fmt.Println("err ", err)
		}
	}()
	bs, _ := ioutil.ReadFile("./testdata/localhost.crt")
	cp := gmx509.NewCertPool()
	root, _ := primitives.ParseCertificate(bs)
	cp.AddCert(root)
	config := &Config{
		ClientSessionCache: NewLRUClientSessionCache(32),
		RootCAs:            cp,
	}
	for i := 0; i < 2; i++ {
		c, err := Dial("tcp", serverIP, config)
		if err != nil {
			t.Fatalf("Dial #%d: %v", i, err)
		}
		cs := c.ConnectionState()
		if i > 0 && !cs.DidResume {
			t.Fatalf("Subsequent connection unexpectedly didn't resume")
		}
		if cs.VerifiedChains == nil {
			t.Fatalf("Dial #%d: cs.VerifiedChains == nil", i)
		}
		if err := c.VerifyHostname("localhost"); err != nil {
			t.Fatalf("verify www.baidu.com #%d: %v", i, err)
		}
		_ = c.Close()
	}
}

func TestConnCloseBreakingWrite(t *testing.T) {
	ln := newLocalListener(t)
	defer func() { _ = ln.Close() }()

	srvCh := make(chan *Conn, 1)
	var serr error
	var sconn net.Conn
	go func() {
		var err error
		sconn, err = ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	cconn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cconn.Close() }()

	conn := &changeImplConn{
		Conn: cconn,
	}

	clientConfig := testConfig.Clone()
	tconn := Client(conn, clientConfig)
	if herr := tconn.Handshake(); herr != nil {
		t.Fatal(herr)
	}

	srv := <-srvCh
	if srv == nil {
		t.Fatal(serr)
	}
	defer func() { _ = sconn.Close() }()

	connClosed := make(chan struct{})
	conn.closeFunc = func() error {
		close(connClosed)
		return nil
	}

	inWrite := make(chan bool, 1)
	var errConnClosed = errors.New("conn closed for test")
	conn.writeFunc = func(p []byte) (n int, err error) {
		inWrite <- true
		<-connClosed
		return 0, errConnClosed
	}

	closeReturned := make(chan bool, 1)
	go func() {
		<-inWrite
		_ = tconn.Close() // test that this doesn't block forever.
		closeReturned <- true
	}()

	_, err = tconn.Write([]byte("foo"))
	if err != errConnClosed {
		t.Errorf("Write error = %v; want errConnClosed", err)
	}

	<-closeReturned
	if err := tconn.Close(); err != errClosed {
		t.Errorf("Close error = %v; want errClosed", err)
	}
}

func TestConnCloseWrite(t *testing.T) {
	ln := newLocalListener(t)
	defer func() { _ = ln.Close() }()

	clientDoneChan := make(chan struct{})

	serverCloseWrite := func() error {
		sconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		defer func() { _ = sconn.Close() }()

		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if herr := srv.Handshake(); herr != nil {
			return fmt.Errorf("handshake: %v", herr)
		}
		defer func() { _ = srv.Close() }()

		data, err := ioutil.ReadAll(srv)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			return fmt.Errorf("Read data = %q; want nothing", data)
		}

		if err := srv.CloseWrite(); err != nil {
			return fmt.Errorf("server CloseWrite: %v", err)
		}

		// Wait for clientCloseWrite to finish, so we know we
		// tested the CloseWrite before we defer the
		// sconn.Close above, which would also cause the
		// client to unblock like CloseWrite.
		<-clientDoneChan
		return nil
	}

	clientCloseWrite := func() error {
		defer close(clientDoneChan)

		clientConfig := testConfig.Clone()
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			return err
		}
		if herr := conn.Handshake(); herr != nil {
			return herr
		}
		defer func() { _ = conn.Close() }()

		if cerr := conn.CloseWrite(); cerr != nil {
			return fmt.Errorf("client CloseWrite: %v", cerr)
		}

		if _, werr := conn.Write([]byte{0}); werr != errShutdown {
			return fmt.Errorf("CloseWrite error = %v; want errShutdown", werr)
		}

		data, err := ioutil.ReadAll(conn)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			return fmt.Errorf("Read data = %q; want nothing", data)
		}
		return nil
	}

	errChan := make(chan error, 2)

	go func() { errChan <- serverCloseWrite() }()
	go func() { errChan <- clientCloseWrite() }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("deadlock")
		}
	}

	// Also test CloseWrite being called before the handshake is
	// finished:
	{
		ln2 := newLocalListener(t)
		defer func() { _ = ln2.Close() }()

		netConn, err := net.Dial("tcp", ln2.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = netConn.Close() }()
		conn := Client(netConn, testConfig.Clone())

		if err := conn.CloseWrite(); err != errEarlyCloseWrite {
			t.Errorf("CloseWrite error = %v; want errEarlyCloseWrite", err)
		}
	}
}

func TestWarningAlertFlood(t *testing.T) {
	ln := newLocalListener(t)
	defer func() { _ = ln.Close() }()

	server := func() error {
		sconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		defer func() { _ = sconn.Close() }()

		serverConfig := testConfig.Clone()
		srv := Server(sconn, serverConfig)
		if herr := srv.Handshake(); herr != nil {
			return fmt.Errorf("handshake: %v", herr)
		}
		defer func() { _ = srv.Close() }()

		_, err = ioutil.ReadAll(srv)
		if err == nil {
			return errors.New("unexpected lack of error from server")
		}
		const expected = "too many warn"
		if str := err.Error(); !strings.Contains(str, expected) {
			return fmt.Errorf("expected error containing %q, but saw: %s", expected, str)
		}

		return nil
	}

	errChan := make(chan error, 1)
	go func() { errChan <- server() }()

	clientConfig := testConfig.Clone()
	conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxWarnAlertCount+1; i++ {
		_ = conn.sendAlert(alertNoRenegotiation)
	}

	if err := <-errChan; err != nil {
		t.Fatal(err)
	}
}

func TestCloneFuncFields(t *testing.T) {
	const expectedCount = 5
	called := 0

	c1 := Config{
		Time: func() time.Time {
			called |= 1 << 0
			return time.Time{}
		},
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			called |= 1 << 1
			return nil, nil
		},
		GetClientCertificate: func(*CertificateRequestInfo) (*Certificate, error) {
			called |= 1 << 2
			return nil, nil
		},
		GetConfigForClient: func(*ClientHelloInfo) (*Config, error) {
			called |= 1 << 3
			return nil, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*gmx509.Certificate) error {
			called |= 1 << 4
			return nil
		},
	}

	c2 := c1.Clone()

	c2.Time()
	_, _ = c2.GetCertificate(nil)
	_, _ = c2.GetClientCertificate(nil)
	_, _ = c2.GetConfigForClient(nil)
	_ = c2.VerifyPeerCertificate(nil, nil)

	if called != (1<<expectedCount)-1 {
		t.Fatalf("expected %d calls but saw calls %b", expectedCount, called)
	}
}

func TestCloneNonFuncFields(t *testing.T) {
	var c1 Config
	v := reflect.ValueOf(&c1).Elem()

	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			// unexported field; not cloned.
			continue
		}

		// testing/quick can't handle functions or interfaces and so
		// isn't used here.
		switch fn := typ.Field(i).Name; fn {
		case "Rand":
			f.Set(reflect.ValueOf(io.Reader(os.Stdin)))
		case "Time", "GetCertificate", "GetConfigForClient", "VerifyPeerCertificate", "GetClientCertificate":
			// DeepEqual can't compare functions. If you add a
			// function field to this list, you must also change
			// TestCloneFuncFields to ensure that the func field is
			// cloned.
		case "Certificates":
			f.Set(reflect.ValueOf([]Certificate{
				{Certificate: [][]byte{{'b'}}},
			}))
		case "NameToCertificate":
			f.Set(reflect.ValueOf(map[string]*Certificate{"a": nil}))
		case "RootCAs", "ClientCAs":
			f.Set(reflect.ValueOf(gmx509.NewCertPool()))
		case "ClientSessionCache":
			f.Set(reflect.ValueOf(NewLRUClientSessionCache(10)))
		case "KeyLogWriter":
			f.Set(reflect.ValueOf(io.Writer(os.Stdout)))
		case "NextProtos":
			f.Set(reflect.ValueOf([]string{"a", "b"}))
		case "ServerName":
			f.Set(reflect.ValueOf("b"))
		case "ClientAuth":
			f.Set(reflect.ValueOf(VerifyClientCertIfGiven))
		case "InsecureSkipVerify", "SessionTicketsDisabled", "DynamicRecordSizingDisabled", "PreferServerCipherSuites":
			f.Set(reflect.ValueOf(true))
		case "MinVersion", "MaxVersion":
			f.Set(reflect.ValueOf(uint16(VersionTLS12)))
		case "SessionTicketKey":
			f.Set(reflect.ValueOf([32]byte{}))
		case "CipherSuites":
			f.Set(reflect.ValueOf([]uint16{1, 2}))
		case "CurvePreferences":
			f.Set(reflect.ValueOf([]CurveID{CurveP256}))
		case "Renegotiation":
			f.Set(reflect.ValueOf(RenegotiateOnceAsClient))
		default:
			t.Errorf("all fields must be accounted for, but saw unknown field %q", fn)
		}
	}

	c2 := c1.Clone()
	// DeepEqual also compares unexported fields, thus c2 needs to have run
	// serverInit in order to be DeepEqual to c1. Cloning it and discarding
	// the result is sufficient.
	c2.Clone()

	if !reflect.DeepEqual(&c1, c2) {
		t.Errorf("clone failed to copy a field")
	}
}

// changeImplConn is a net.Conn which can change its Write and Close
// methods.
type changeImplConn struct {
	net.Conn
	writeFunc func([]byte) (int, error)
	closeFunc func() error
}

func (w *changeImplConn) Write(p []byte) (n int, err error) {
	if w.writeFunc != nil {
		return w.writeFunc(p)
	}
	return w.Conn.Write(p)
}

func (w *changeImplConn) Close() error {
	if w.closeFunc != nil {
		return w.closeFunc()
	}
	return w.Conn.Close()
}

func throughput(b *testing.B, totalBytes int64, dynamicRecordSizingDisabled bool) {
	ln := newLocalListener(b)
	defer func() { _ = ln.Close() }()

	N := b.N

	// Less than 64KB because Windows appears to use a TCP rwin < 64KB.
	// See Issue #15899.
	const bufsize = 32 << 10

	go func() {
		buf := make([]byte, bufsize)
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := testConfig.Clone()
			serverConfig.CipherSuites = nil // the defaults may prefer faster ciphers
			serverConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
			srv := Server(sconn, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			if _, err := io.CopyBuffer(srv, srv, buf); err != nil {
				panic(fmt.Errorf("copy buffer: %v", err))
			}
		}
	}()

	b.SetBytes(totalBytes)
	clientConfig := testConfig.Clone()
	clientConfig.CipherSuites = nil // the defaults may prefer faster ciphers
	clientConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled

	buf := make([]byte, bufsize)
	chunks := int(math.Ceil(float64(totalBytes) / float64(len(buf))))
	for i := 0; i < N; i++ {
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			b.Fatal(err)
		}
		for j := 0; j < chunks; j++ {
			_, err := conn.Write(buf)
			if err != nil {
				b.Fatal(err)
			}
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				b.Fatal(err)
			}
		}
		_ = conn.Close()
	}
}

func BenchmarkThroughput(b *testing.B) {
	for _, mode := range []string{"Max", "Dynamic"} {
		for size := 1; size <= 64; size <<= 1 {
			name := fmt.Sprintf("%sPacket/%dMB", mode, size)
			b.Run(name, func(b *testing.B) {
				throughput(b, int64(size<<20), mode == "Max")
			})
		}
	}
}

type slowConn struct {
	net.Conn
	bps int
}

func (c *slowConn) Write(p []byte) (int, error) {
	if c.bps == 0 {
		panic("too slow")
	}
	t0 := time.Now()
	wrote := 0
	for wrote < len(p) {
		time.Sleep(100 * time.Microsecond)
		allowed := int(time.Since(t0).Seconds()*float64(c.bps)) / 8
		if allowed > len(p) {
			allowed = len(p)
		}
		if wrote < allowed {
			n, err := c.Conn.Write(p[wrote:allowed])
			wrote += n
			if err != nil {
				return wrote, err
			}
		}
	}
	return len(p), nil
}

func latency(b *testing.B, bps int, dynamicRecordSizingDisabled bool) {
	ln := newLocalListener(b)
	defer func() { _ = ln.Close() }()

	N := b.N

	go func() {
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := testConfig.Clone()
			serverConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled
			srv := Server(&slowConn{sconn, bps}, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			_, _ = io.Copy(srv, srv)
		}
	}()

	clientConfig := testConfig.Clone()
	clientConfig.DynamicRecordSizingDisabled = dynamicRecordSizingDisabled

	buf := make([]byte, 16384)
	peek := make([]byte, 1)

	for i := 0; i < N; i++ {
		conn, derr := Dial("tcp", ln.Addr().String(), clientConfig)
		if derr != nil {
			b.Fatal(derr)
		}
		// make sure we're connected and previous connection has stopped
		if _, w1err := conn.Write(buf[:1]); w1err != nil {
			b.Fatal(w1err)
		}
		if _, r1err := io.ReadFull(conn, peek); r1err != nil {
			b.Fatal(r1err)
		}
		if _, w2err := conn.Write(buf); w2err != nil {
			b.Fatal(w2err)
		}
		if _, r2err := io.ReadFull(conn, peek); r2err != nil {
			b.Fatal(r2err)
		}
		_ = conn.Close()
	}
}

func BenchmarkLatency(b *testing.B) {
	for _, mode := range []string{"Max", "Dynamic"} {
		for _, kbps := range []int{200, 500, 1000, 2000, 5000} {
			name := fmt.Sprintf("%sPacket/%dkbps", mode, kbps)
			b.Run(name, func(b *testing.B) {
				latency(b, kbps*1000, mode == "Max")
			})
		}
	}
}

func TestConnectionStateMarshal(t *testing.T) {
	cs := &ConnectionState{}
	_, err := json.Marshal(cs)
	if err != nil {
		t.Errorf("json.Marshal failed on ConnectionState: %v", err)
	}
}

func TestGuomi(t *testing.T) {
	caFile, _ := ioutil.ReadFile("./testdata/root_guomi.ca")
	ca, _ := primitives.ParseCertificate(caFile)
	root := gmx509.NewCertPool()
	root.AddCert(ca)

	certc, err := LoadX509KeyPair("./testdata/subcert_guomi.cert", "./testdata/subcert_guomi.priv")
	assert.Nil(t, err)
	certs, err := LoadX509KeyPair("./testdata/subcert_guomi.cert", "./testdata/subcert_guomi.priv")
	assert.Nil(t, err)

	cConn, sConn := net.Pipe()

	c := Client(cConn, &Config{RootCAs: root, Certificates: []Certificate{certc}, InsecureSkipVerify: true})
	s := Server(sConn, &Config{ClientCAs: root, ClientAuth: RequireAndVerifyClientCert, Certificates: []Certificate{certs}})

	ch := make(chan string)
	go func() {
		buf, _ := ioutil.ReadAll(s)
		ch <- string(buf)
	}()

	go func() {
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	str := <-ch
	assert.Equal(t, "hello", str)
	assert.Equal(t, uint16(0xe011), c.cipherSuite)

}
func TestSecp256k1(t *testing.T) {
	caFile, _ := ioutil.ReadFile("./testdata/root_secp256k1.cert")
	ca, _ := primitives.ParseCertificate(caFile)
	root := gmx509.NewCertPool()
	root.AddCert(ca)

	certc, err := LoadX509KeyPair("./testdata/subcert_secp256k1_1.cert", "./testdata/subcert_secp256k1_1.priv")
	assert.Nil(t, err)
	certs, err := LoadX509KeyPair("./testdata/subcert_secp256k1_2.cert", "./testdata/subcert_secp256k1_2.priv")
	assert.Nil(t, err)

	cConn, sConn := net.Pipe()

	c := Client(cConn, &Config{RootCAs: root, Certificates: []Certificate{certc}, InsecureSkipVerify: true})
	s := Server(sConn, &Config{ClientCAs: root, ClientAuth: RequireAndVerifyClientCert, Certificates: []Certificate{certs}})

	ch := make(chan string)
	go func() {
		buf, _ := ioutil.ReadAll(s)
		ch <- string(buf)
	}()

	go func() {
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	str := <-ch
	assert.Equal(t, "hello", str)
	assert.Equal(t, uint16(0xc02b), c.cipherSuite)

}

func TestListen(t *testing.T) {
	certPair, err := LoadX509KeyPair("./testdata/cert.cert",
		"./testdata/cert.priv")
	assert.Nil(t, err)

	tlsConfig := &Config{
		Certificates: []Certificate{certPair},
	}
	_, err = Listen("tcp", "127.0.0.1", tlsConfig)
	assert.NotNil(t, err)
	time := timeoutError{}
	ss := time.Error()
	fmt.Println(ss)
	time.Temporary()
}
