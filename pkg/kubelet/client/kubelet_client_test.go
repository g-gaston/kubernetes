/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestMakeTransportInvalid(t *testing.T) {
	testCases := []struct {
		name   string
		config *KubeletClientConfig
	}{
		{
			name: "invalid certs and key path",
			config: &KubeletClientConfig{
				TLSClientConfig: KubeletTLSConfig{
					CertFile: "../../client/testdata/mycertinvalid.cer",
					KeyFile:  "../../client/testdata/mycertinvalid.key",
					CAFile:   "../../client/testdata/myCA.cer",
				},
			},
		},
		{
			name: "validate serving cert CN without node name",
			config: &KubeletClientConfig{
				TLSClientConfig: KubeletTLSConfig{
					CertFile:                 "../../client/testdata/mycertvalid.cer",
					KeyFile:                  "../../client/testdata/mycertvalid.key",
					CAFile:                   "../../client/testdata/myCA.cer",
					ValidateNodeNameInCertCN: true,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := MakeTransport(tc.config)
			if err == nil {
				t.Errorf("Expected an error")
			}
			if rt != nil {
				t.Error("rt should be nil as we provided invalid cert file")
			}
		})
	}
}

func TestMakeTransportValid(t *testing.T) {
	config := &KubeletClientConfig{
		Port: 1234,
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertvalid.cer",
			// TLS Configuration
			KeyFile: "../../client/testdata/mycertvalid.key",
			// TLS Configuration
			CAFile: "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeTransport(config)
	if err != nil {
		t.Errorf("Not expecting an error %#v", err)
	}
	if rt == nil {
		t.Error("rt should not be nil")
	}
}

func TestMakeInsecureTransport(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	testURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(testURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatal(err)
	}

	config := &KubeletClientConfig{
		Port: uint(port),
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertvalid.cer",
			// TLS Configuration
			KeyFile: "../../client/testdata/mycertvalid.key",
			// TLS Configuration
			CAFile: "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeInsecureTransport(config)
	if err != nil {
		t.Errorf("Not expecting an error #%v", err)
	}
	if rt == nil {
		t.Error("rt should not be nil")
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		dump, err := httputil.DumpResponse(response, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal(string(dump))
	}
}

func TestMakeTransportForNodeWithServingCertCNValidation(t *testing.T) {
	nodeName := "my-node-1"
	kubeletServer := newKubeletServer(t, nodeName)

	testCases := []struct {
		name       string
		nodeName   string
		validateCN bool
		expectErr  string
	}{
		{
			name:       "valid cert",
			nodeName:   nodeName,
			validateCN: true,
		},
		{
			name:       "invalid cert without validation",
			nodeName:   "my-node-2",
			validateCN: false,
		},
		{
			name:       "invalid cert with validation",
			nodeName:   "my-node-2",
			validateCN: true,
			expectErr:  "kubelet serving cert CN system:node:my-node-1 doesn't match expected system:node:my-node-2",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &KubeletClientConfigForNode{
				NodeName: tc.nodeName,
				KubeletClientConfig: KubeletClientConfig{
					Port: uint(kubeletServer.port),
					TLSClientConfig: KubeletTLSConfig{
						CertFile:                 "../../client/testdata/mycertvalid.cer",
						KeyFile:                  "../../client/testdata/mycertvalid.key",
						CAFile:                   kubeletServer.caFilePath,
						ValidateNodeNameInCertCN: tc.validateCN,
					},
				},
			}

			rt, err := MakeTransportForNode(config)
			if err != nil {
				t.Errorf("Failed building transport #%v", err)
			}
			if rt == nil {
				t.Error("Transport roundtripper should not be nil")
			}

			req, err := http.NewRequest(http.MethodGet, kubeletServer.server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := rt.RoundTrip(req)
			if err != nil && tc.expectErr == "" {
				t.Fatalf("Roundtrip failed: %s", err)
			}
			if err != nil && tc.expectErr != err.Error() {
				t.Fatalf("Expected error [%s], got: %s", tc.expectErr, err)
			}

			if err == nil && tc.expectErr != "" {
				t.Fatalf("Expected error [%s] but got success", err)
			}

			if err == nil && response.StatusCode != http.StatusOK {
				dump, err := httputil.DumpResponse(response, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatal(string(dump))
			}
		})
	}
}

type fakeKubeletServer struct {
	server     *httptest.Server
	port       uint64
	nodeName   string
	ca         *certificate
	caFilePath string
	serverCert *certificate
}

func newKubeletServer(tb testing.TB, nodeName string) *fakeKubeletServer {
	ca, err := createCA()
	if err != nil {
		tb.Fatal(err)
	}
	servingCert, err := createServingCert(ca.cert, ca.key, nodeName)
	if err != nil {
		tb.Fatal(err)
	}

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cert, err := tls.X509KeyPair(servingCert.certPEM, servingCert.keyPEM)
	if err != nil {
		tb.Fatal(err)
	}

	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	testServer.StartTLS()
	tb.Cleanup(func() {
		testServer.Close()
	})

	testURL, err := url.Parse(testServer.URL)
	if err != nil {
		tb.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(testURL.Host)
	if err != nil {
		tb.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		tb.Fatal(err)
	}

	caPath := "test.ca"
	if err = os.WriteFile(caPath, ca.certPEM, 0o644); err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		if err := os.Remove(caPath); err != nil {
			tb.Errorf("failed to remove test.ca: %v", err)
		}
	})

	return &fakeKubeletServer{
		server:     testServer,
		port:       port,
		nodeName:   nodeName,
		ca:         ca,
		caFilePath: caPath,
		serverCert: servingCert,
	}
}

type certificate struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
	keyPEM  []byte
}

func createCA() (*certificate, error) {
	now := time.Now()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key for CA: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number for CA: %w", err)
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kubernetes",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0), // 1 year
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	return &certificate{
		certPEM: caPEM.Bytes(),
		cert:    ca,
		key:     privateKey,
		keyPEM:  keyPEM.Bytes(),
	}, nil
}

func createServingCert(ca *x509.Certificate, caPrivKey any, nodeName string) (*certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key for certificate: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number for certificate: %w", err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "system:node:" + nodeName,
			Organization: []string{
				"system:nodes",
			},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0), // 1 years
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	return &certificate{
		certPEM: certPEM.Bytes(),
		cert:    cert,
		key:     privateKey,
		keyPEM:  keyPEM.Bytes(),
	}, nil
}
