package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeCertificate(t *testing.T, template, signer *x509.Certificate, signerKey ed25519.PrivateKey) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		signer, signerKey = template, private
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, public, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, private
}

func testPEM(t *testing.T, dir, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerTrustAndMutualTLS(t *testing.T) {
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, caKey := makeCertificate(t, caTemplate, nil, nil)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test server"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	serverDER, serverKey := makeCertificate(t, leaf, ca, caKey)
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf.SerialNumber = big.NewInt(3)
	leaf.Subject.CommonName = "probe"
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientDER, clientKey := makeCertificate(t, leaf, ca, caKey)
	clientCert := tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey}
	config := configForTest(t)
	dir := t.TempDir()
	config.TLSCert = testPEM(t, dir, "server.crt", "CERTIFICATE", serverDER)
	config.TLSKey = testPEM(t, dir, "server.key", "PRIVATE KEY", serverKeyDER)
	config.ClientCA = testPEM(t, dir, "ca.crt", "CERTIFICATE", caDER)
	settings, err := config.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	try := func(roots *x509.CertPool, certs []tls.Certificate, serverName string, wantSuccess bool) {
		t.Helper()
		serverSide, clientSide := net.Pipe()
		defer serverSide.Close()
		defer clientSide.Close()
		deadline := time.Now().Add(3 * time.Second)
		if err := serverSide.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if err := clientSide.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		server := tls.Server(serverSide, settings)
		client := tls.Client(clientSide, &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: certs, ServerName: serverName,
		})
		result := make(chan error, 1)
		go func() { result <- server.Handshake() }()
		clientErr := client.Handshake()
		serverErr := <-result
		if success := clientErr == nil && serverErr == nil; success != wantSuccess {
			t.Fatalf("unexpected handshake success %v with client error %v and server error %v", success, clientErr, serverErr)
		}
	}
	try(roots, []tls.Certificate{clientCert}, "localhost", true)
	try(roots, nil, "localhost", false)
	try(roots, []tls.Certificate{clientCert}, "untrusted.example", false)
	try(x509.NewCertPool(), []tls.Certificate{clientCert}, "localhost", false)
}
