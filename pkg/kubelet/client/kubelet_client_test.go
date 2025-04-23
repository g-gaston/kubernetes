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
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/util/cert"
	"k8s.io/kubernetes/test/utils"
)

func TestMakeTransportInvalid(t *testing.T) {
	config := &KubeletClientConfig{
		// Invalid certificate and key path
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertinvalid.cer",
			KeyFile:  "../../client/testdata/mycertinvalid.key",
			CAFile:   "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeTransport(config)
	if err == nil {
		t.Errorf("Expected an error")
	}
	if rt != nil {
		t.Error("rt should be nil as we provided invalid cert file")
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

func TestValidateNodeName(t *testing.T) {
	caCert, caKey := createCA(t)
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, utils.EncodeCertPEM(caCert), 0o644); err != nil {
		t.Fatal(err)
	}

	kubeletServerNode1 := newKubeletServer(t, "my-node-1", caCert, caKey)
	kubeletServerNode2 := newKubeletServer(t, "my-node-2", caCert, caKey)

	baseKubeletClientConfig := KubeletClientConfig{
		TLSClientConfig: KubeletTLSConfig{
			CAFile: caPath,
		},
		PreferredAddressTypes: []string{
			string(corev1.NodeInternalIP),
		},
	}

	// TODO test with multiple nodes and with connection re-use

	testCases := []struct {
		name             string
		kubeletServer    *fakeKubeletServer
		nodeName         types.NodeName
		validateNodeName bool
		expectErr        string
	}{
		{
			name:             "valid cert",
			nodeName:         "my-node-1",
			kubeletServer:    kubeletServerNode1,
			validateNodeName: true,
		},
		{
			name:             "invalid cert without validation",
			nodeName:         "my-node-1",
			kubeletServer:    kubeletServerNode2,
			validateNodeName: false,
		},
		{
			name:             "invalid cert with validation",
			nodeName:         "my-node-1",
			kubeletServer:    kubeletServerNode2,
			validateNodeName: true,
			expectErr:        `invalid node name; expected "system:node:my-node-1", got "system:node:my-node-2"`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nodeGetter := NodeGetterFunc(func(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Node, error) {
				return &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeInternalIP,
								Address: tc.kubeletServer.host,
							},
						},
						DaemonEndpoints: corev1.NodeDaemonEndpoints{
							KubeletEndpoint: corev1.DaemonEndpoint{
								Port: int32(tc.kubeletServer.port),
							},
						},
					},
				}, nil
			})

			kubeletClientConfig := baseKubeletClientConfig
			kubeletClientConfig.TLSClientConfig.ValidateNodeName = tc.validateNodeName

			connectionInfoGetter, err := NewNodeConnectionInfoGetter(nodeGetter, kubeletClientConfig)
			if err != nil {
				t.Fatal(err)
			}

			nodeInfo, err := connectionInfoGetter.GetConnectionInfo(t.Context(), tc.nodeName)
			if err != nil {
				t.Fatal(err)
			}

			err = makeRequestToNode(t, nodeInfo)
			if got := errString(err); tc.expectErr != got {
				t.Fatalf("expected error %q but got %v", tc.expectErr, err)
			}
		})
	}
}

func makeRequestToNode(t *testing.T, nodeInfo *ConnectionInfo) error {
	url := &url.URL{
		Scheme: nodeInfo.Scheme,
		Host:   net.JoinHostPort(nodeInfo.Hostname, nodeInfo.Port),
	}

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	response, err := nodeInfo.Transport.RoundTrip(req)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		dump, err := httputil.DumpResponse(response, true)
		if err != nil {
			return err
		}
		return fmt.Errorf("expected status code %d but got %d: %s", http.StatusOK, response.StatusCode, string(dump))
	}

	return nil
}

func TestValidateNodeNameWithConnectionReuse(t *testing.T) {
	caCert, caKey := createCA(t)
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, utils.EncodeCertPEM(caCert), 0o644); err != nil {
		t.Fatal(err)
	}

	kubeletServerNode1 := newKubeletServer(t, "my-node-1", caCert, caKey)

	nodeGetter := NodeGetterFunc(func(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Node, error) {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{
						Type:    corev1.NodeInternalIP,
						Address: kubeletServerNode1.host,
					},
				},
				DaemonEndpoints: corev1.NodeDaemonEndpoints{
					KubeletEndpoint: corev1.DaemonEndpoint{
						Port: int32(kubeletServerNode1.port),
					},
				},
			},
		}, nil
	})

	kubeletClientConfig := KubeletClientConfig{
		TLSClientConfig: KubeletTLSConfig{
			CAFile:           caPath,
			ValidateNodeName: true,
		},
		PreferredAddressTypes: []string{
			string(corev1.NodeInternalIP),
		},
	}

	connectionInfoGetter, err := NewNodeConnectionInfoGetter(nodeGetter, kubeletClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("connecting to the right node", func(t *testing.T) {
		nodeInfo, err := connectionInfoGetter.GetConnectionInfo(t.Context(), "my-node-1")
		if err != nil {
			t.Fatal(err)
		}

		// this should succeed because we are using the right node name
		if err := makeRequestToNode(t, nodeInfo); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("connecting to the wrong node", func(t *testing.T) {
		nodeInfo, err := connectionInfoGetter.GetConnectionInfo(t.Context(), "my-node-2")
		if err != nil {
			t.Fatal(err)
		}

		// this should fail because we are using the wrong node name
		// the connection should not be reused even if the destination IP is the same
		// which should re-run the cert validation
		err = makeRequestToNode(t, nodeInfo)
		if err == nil {
			t.Fatal("expected error but got nil")
		}

		if errString(err) != `invalid node name; expected "system:node:my-node-2", got "system:node:my-node-1"` {
			t.Fatalf("expected error %q but got %v", `invalid node name; expected "system:node:my-node-2", got "system:node:my-node-1"`, err)
		}
	})

	t.Run("reusing the connection to the right node", func(t *testing.T) {
		nodeInfo, err := connectionInfoGetter.GetConnectionInfo(t.Context(), "my-node-1")
		if err != nil {
			t.Fatal(err)
		}

		// this should succeed because we are using the right node name
		// and the connection should be reused
		if err := makeRequestToNode(t, nodeInfo); err != nil {
			t.Fatal(err)
		}
	})
}

type fakeKubeletServer struct {
	server   *httptest.Server
	port     uint64
	nodeName string
	host     string
}

func newKubeletServer(tb testing.TB, nodeName string, signingCert *x509.Certificate, signingKey crypto.Signer) *fakeKubeletServer {
	servingCert := createServingCert(tb, signingCert, signingKey, nodeName)

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	testServer.EnableHTTP2 = true // TODO test both with http1 and http2

	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{servingCert},
	}

	testServer.StartTLS()
	tb.Cleanup(testServer.Close)

	testURL, err := url.Parse(testServer.URL)
	if err != nil {
		tb.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(testURL.Host)
	if err != nil {
		tb.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		tb.Fatal(err)
	}

	return &fakeKubeletServer{
		server:   testServer,
		port:     port,
		nodeName: nodeName,
		host:     host,
	}
}

func createCA(tb testing.TB) (*x509.Certificate, crypto.Signer) {
	tb.Helper()

	signingKey, err := utils.NewPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}

	signingCert, err := cert.NewSelfSignedCACert(cert.Config{CommonName: "e2e-server-cert-ca"}, signingKey)
	if err != nil {
		tb.Fatal(err)
	}

	return signingCert, signingKey
}

func createServingCert(tb testing.TB, signingCert *x509.Certificate, signingKey crypto.Signer, nodeName string) tls.Certificate {
	tb.Helper()

	key, err := utils.NewPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}

	signedCert, err := utils.NewSignedCert(
		&cert.Config{
			CommonName: "system:node:" + nodeName,
			Organization: []string{
				user.NodesGroup,
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames: cert.AltNames{
				IPs: []net.IP{net.ParseIP("127.0.0.1")},
			},
		},
		key, signingCert, signingKey,
	)
	if err != nil {
		tb.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{signedCert.Raw},
		PrivateKey:  key,
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
