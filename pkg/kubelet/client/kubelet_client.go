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
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/server/egressselector"
	"k8s.io/client-go/transport"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
)

// KubeletClientConfig defines config parameters for the kubelet client
type KubeletClientConfig struct {
	// Port specifies the default port - used if no information about Kubelet port can be found in Node.NodeStatus.DaemonEndpoints.
	Port uint

	// ReadOnlyPort specifies the Port for ReadOnly communications.
	ReadOnlyPort uint

	// PreferredAddressTypes - used to select an address from Node.NodeStatus.Addresses
	PreferredAddressTypes []string

	// TLSClientConfig contains settings to enable transport layer security
	TLSClientConfig KubeletTLSConfig

	// HTTPTimeout is used by the client to timeout http requests to Kubelet.
	HTTPTimeout time.Duration

	// Lookup will give us a dialer if the egress selector is configured for it
	Lookup egressselector.Lookup
}

// KubeletClientConfigForNode defines config parameters for the kubelet client for a specific node.
type KubeletClientConfigForNode struct {
	KubeletClientConfig

	// NodeName is the name of the node the client will connect to.
	// This is optional.
	NodeName string
}

type KubeletTLSConfig struct {
	// Server requires TLS client certificate authentication
	CertFile string
	// Server requires TLS client certificate authentication
	KeyFile string
	// Trusted root certificates for server
	CAFile string
	// ValidateNodeNameInCertCN specifies whether the kubelet
	// client should validate the node name in the kubelet
	//  server certificate common name.
	ValidateNodeNameInCertCN bool
}

// ConnectionInfo provides the information needed to connect to a kubelet
type ConnectionInfo struct {
	Scheme                         string
	Hostname                       string
	Port                           string
	Transport                      http.RoundTripper
	InsecureSkipTLSVerifyTransport http.RoundTripper
}

// ConnectionInfoGetter provides ConnectionInfo for the kubelet running on a named node
type ConnectionInfoGetter interface {
	GetConnectionInfo(ctx context.Context, nodeName types.NodeName) (*ConnectionInfo, error)
}

// MakeTransport creates a secure RoundTripper for HTTP Transport.
func MakeTransport(config *KubeletClientConfig) (http.RoundTripper, error) {
	return makeTransport(&KubeletClientConfigForNode{KubeletClientConfig: *config}, false)
}

// MakeInsecureTransport creates an insecure RoundTripper for HTTP Transport.
func MakeInsecureTransport(config *KubeletClientConfig) (http.RoundTripper, error) {
	return makeTransport(&KubeletClientConfigForNode{KubeletClientConfig: *config}, true)
}

// MakeTransportForNode creates a secure RoundTripper for HTTP Transport to connect to a specific Node.
func MakeTransportForNode(config *KubeletClientConfigForNode) (http.RoundTripper, error) {
	return makeTransport(config, false)
}

// makeTransport creates a RoundTripper for HTTP Transport.
func makeTransport(config *KubeletClientConfigForNode, insecureSkipTLSVerify bool) (http.RoundTripper, error) {
	if config.TLSClientConfig.ValidateNodeNameInCertCN && config.NodeName == "" {
		return nil, fmt.Errorf("kubelet client config NodeName must be set when ValidateNodeNameInCertCN is true")
	}

	// do the insecureSkipTLSVerify on the pre-transport *before* we go get a potentially cached connection.
	// transportConfig always produces a new struct pointer.
	transportConfig := config.transportConfig()
	if insecureSkipTLSVerify {
		transportConfig.TLS.Insecure = true
		transportConfig.TLS.CAFile = "" // we are only using files so we can ignore CAData
	}

	if config.Lookup != nil {
		// Assuming EgressSelector if SSHTunnel is not turned on.
		// We will not get a dialer if egress selector is disabled.
		networkContext := egressselector.Cluster.AsNetworkContext()
		dialer, err := config.Lookup(networkContext)
		if err != nil {
			return nil, fmt.Errorf("failed to get context dialer for 'cluster': got %v", err)
		}
		if dialer != nil {
			transportConfig.DialHolder = &transport.DialHolder{Dial: dialer}
		}
	}
	return transport.New(transportConfig)
}

// transportConfig converts a client config to an appropriate transport config.
func (c *KubeletClientConfigForNode) transportConfig() *transport.Config {
	cfg := &transport.Config{
		TLS: transport.TLSConfig{
			CAFile:   c.TLSClientConfig.CAFile,
			CertFile: c.TLSClientConfig.CertFile,
			KeyFile:  c.TLSClientConfig.KeyFile,
			// transport.loadTLSFiles would set this to true because we are only using files
			// it is clearer to set it explicitly here so we remember that this is happening
			ReloadTLSFiles: true,
		},
	}
	if !cfg.HasCA() {
		cfg.TLS.Insecure = true
	}

	if c.TLSClientConfig.ValidateNodeNameInCertCN && c.NodeName != "" {
		// TODO(gaslor): if we want transport to cache the round tripper,
		// we need to cache the holder and reuse it.
		cfg.TLS.VerifyPeerCertificateHolder = &transport.VerifyPeerCertificateHolder{
			VerifyPeerCertificate: []func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error{
				validateNodeNameInCertCN(c.NodeName),
			},
		}
	}

	return cfg
}

// NodeGetter defines an interface for looking up a node by name
type NodeGetter interface {
	Get(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error)
}

// NodeGetterFunc allows implementing NodeGetter with a function
type NodeGetterFunc func(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error)

// Get fetches information via NodeGetterFunc.
func (f NodeGetterFunc) Get(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error) {
	return f(ctx, name, options)
}

// NodeConnectionInfoGetter obtains connection info from the status of a Node API object
type NodeConnectionInfoGetter struct {
	// nodes is used to look up Node objects
	nodes NodeGetter
	// scheme is the scheme to use to connect to all kubelets
	scheme string
	// config defines config parameters for the kubelet client.
	config KubeletClientConfig
	// insecureSkipTLSVerifyTransport is the transport to use if the kube-apiserver wants to skip verifying the TLS certificate of the kubelet
	insecureSkipTLSVerifyTransport http.RoundTripper
	// preferredAddressTypes specifies the preferred order to use to find a node address
	preferredAddressTypes []v1.NodeAddressType
}

// NewNodeConnectionInfoGetter creates a new NodeConnectionInfoGetter.
func NewNodeConnectionInfoGetter(nodes NodeGetter, config KubeletClientConfig) (ConnectionInfoGetter, error) {
	insecureSkipTLSVerifyTransport, err := MakeInsecureTransport(&config)
	if err != nil {
		return nil, err
	}

	types := []v1.NodeAddressType{}
	for _, t := range config.PreferredAddressTypes {
		types = append(types, v1.NodeAddressType(t))
	}

	return &NodeConnectionInfoGetter{
		nodes:                          nodes,
		scheme:                         "https",
		config:                         config,
		insecureSkipTLSVerifyTransport: insecureSkipTLSVerifyTransport,

		preferredAddressTypes: types,
	}, nil
}

// GetConnectionInfo retrieves connection info from the status of a Node API object.
func (k *NodeConnectionInfoGetter) GetConnectionInfo(ctx context.Context, nodeName types.NodeName) (*ConnectionInfo, error) {
	node, err := k.nodes.Get(ctx, string(nodeName), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Find a kubelet-reported address, using preferred address type
	host, err := nodeutil.GetPreferredNodeAddress(node, k.preferredAddressTypes)
	if err != nil {
		return nil, err
	}

	// Use the kubelet-reported port, if present
	port := int(node.Status.DaemonEndpoints.KubeletEndpoint.Port)
	if port <= 0 {
		port = int(k.config.Port)
	}

	transport, err := MakeTransportForNode(&KubeletClientConfigForNode{k.config, string(nodeName)})
	if err != nil {
		return nil, err
	}

	return &ConnectionInfo{
		Scheme:                         k.scheme,
		Hostname:                       host,
		Port:                           strconv.Itoa(port),
		Transport:                      transport,
		InsecureSkipTLSVerifyTransport: k.insecureSkipTLSVerifyTransport,
	}, nil
}

func validateNodeNameInCertCN(nodeName string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	expectedCN := "system:node:" + nodeName
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, chain := range verifiedChains {
			first := chain[0]
			if first == nil || len(first.Subject.Organization) == 0 {
				continue
			}
			if first.Subject.Organization[0] != "system:nodes" {
				continue
			}

			if first.Subject.CommonName != expectedCN {
				return fmt.Errorf("kubelet serving cert CN %s doesn't match expected %s", first.Subject.CommonName, expectedCN)
			}

			return nil
		}

		return errors.New("didn't find any valid kubelet serving cert in the verified certificates chains")
	}
}
