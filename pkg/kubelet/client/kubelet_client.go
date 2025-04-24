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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
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

type KubeletTLSConfig struct {
	// Server requires TLS client certificate authentication
	CertFile string
	// Server requires TLS client certificate authentication
	KeyFile string
	// Trusted root certificates for server
	CAFile string
	// Check that the kubelet's serving certificate common name matches the name of the kubelet
	ValidateNodeName bool
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
	return makeTransport(config, false)
}

// MakeInsecureTransport creates an insecure RoundTripper for HTTP Transport.
func MakeInsecureTransport(config *KubeletClientConfig) (http.RoundTripper, error) {
	return makeTransport(config, true)
}

// makeTransport creates a RoundTripper for HTTP Transport.
func makeTransport(config *KubeletClientConfig, insecureSkipTLSVerify bool) (http.RoundTripper, error) {
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
func (c *KubeletClientConfig) transportConfig() *transport.Config {
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
	// defaultPort is the port to use if no Kubelet endpoint port is recorded in the node status
	defaultPort int
	// transport is the transport to use to send a request to all kubelets
	transport http.RoundTripper
	// check that the kubelet's serving certificate common name matches the name of the kubelet
	validateNodeName bool
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

	b := &transportBuilder{
		nodes:                 nodes,
		config:                &config,
		preferredAddressTypes: types,
	}

	transport, err := b.build()
	if err != nil {
		return nil, err
	}

	return &NodeConnectionInfoGetter{
		nodes:                          nodes,
		scheme:                         "https",
		defaultPort:                    int(config.Port),
		transport:                      transport,
		validateNodeName:               config.TLSClientConfig.ValidateNodeName,
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

	// Use the kubelet-reported port, if present
	port := int(node.Status.DaemonEndpoints.KubeletEndpoint.Port)
	if port <= 0 {
		port = k.defaultPort
	}

	// if we validate the node name, we use the node name as the host
	// so the connection gets keyed in the cache by the node name
	// otherwise we use the preferred node address
	host := string(nodeName)
	if !k.validateNodeName {
		host, err = nodeutil.GetPreferredNodeAddress(node, k.preferredAddressTypes)
		if err != nil {
			return nil, err
		}
	}

	return &ConnectionInfo{
		Scheme:                         k.scheme,
		Hostname:                       host,
		Port:                           strconv.Itoa(port),
		Transport:                      k.transport,
		InsecureSkipTLSVerifyTransport: k.insecureSkipTLSVerifyTransport,
	}, nil
}

type transportBuilder struct {
	nodes                 NodeGetter
	preferredAddressTypes []v1.NodeAddressType
	config                *KubeletClientConfig
}

// build creates a RoundTripper for HTTP Transport.
func (t *transportBuilder) build() (http.RoundTripper, error) {
	transportConfig := t.config.transportConfig()

	if t.config.Lookup != nil {
		// Assuming EgressSelector if SSHTunnel is not turned on.
		// We will not get a dialer if egress selector is disabled.
		networkContext := egressselector.Cluster.AsNetworkContext()
		dialer, err := t.config.Lookup(networkContext)
		if err != nil {
			return nil, fmt.Errorf("failed to get context dialer for 'cluster': got %v", err)
		}
		if dialer != nil {
			transportConfig.DialHolder = &transport.DialHolder{Dial: dialer}
		}
	}

	if t.config.TLSClientConfig.ValidateNodeName {
		transportConfig.DialHolder = &transport.DialHolder{
			DialWithTLS: func(ctx context.Context, tlsConfig *tls.Config, network, addr string) (net.Conn, error) {
				// If we have a customer dialer for egress selector, we use it to first obtain the connection
				// and then we add TLS to it.
				// If not, we use a default net dialer.
				netDial := transportConfig.DialHolder.Dial
				if netDial == nil {
					netDial = (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext
				}

				tlsDialer := newTLSDialerForNode(t.nodes, t.preferredAddressTypes, netDial, tlsConfig)
				return tlsDialer.dial(ctx, network, addr)
			},
		}
	}
	return transport.New(transportConfig)
}

func newTLSDialerForNode(nodes NodeGetter, preferredAddressTypes []v1.NodeAddressType, netDial dialer, config *tls.Config) *tlsDialerForNode {
	return &tlsDialerForNode{
		tlsDialer:             *newTLSDialer(netDial, config),
		nodes:                 nodes,
		preferredAddressTypes: preferredAddressTypes,
	}
}

type tlsDialerForNode struct {
	tlsDialer
	nodes                 NodeGetter
	preferredAddressTypes []v1.NodeAddressType
}

// dial opens a TLS connection to a node and validates that the CN of the server certificate
// matches the node name and that the node is in the nodes group.
// addr is expected to be in the format "node-name:port".
func (t *tlsDialerForNode) dial(ctx context.Context, network, addr string) (*tls.Conn, error) {
	nodeName, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	host, err := t.getNodeHost(ctx, nodeName)
	if err != nil {
		return nil, err
	}

	tlsConn, err := t.tlsDialer.dial(ctx, network, net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	if !cs.HandshakeComplete {
		return nil, fmt.Errorf("invalid connection state; handshake not complete")
	}
	leaf := cs.PeerCertificates[0]
	if expectedNodeName := "system:node:" + string(nodeName); leaf.Subject.CommonName != expectedNodeName {
		return nil, fmt.Errorf("invalid node name; expected %q, got %q", expectedNodeName, leaf.Subject.CommonName)
	}
	if !slices.Contains(leaf.Subject.Organization, user.NodesGroup) {
		return nil, fmt.Errorf("invalid node groups; expected to include %q, got %q", user.NodesGroup, leaf.Subject.Organization)
	}

	return tlsConn, nil
}

func (t *tlsDialerForNode) getNodeHost(ctx context.Context, nodeName string) (string, error) {
	node, err := t.nodes.Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	// Find a kubelet-reported address, using preferred address type
	host, err := nodeutil.GetPreferredNodeAddress(node, t.preferredAddressTypes)
	if err != nil {
		return "", err
	}

	return host, nil
}

func newTLSDialer(netDial dialer, config *tls.Config) *tlsDialer {
	return &tlsDialer{
		netDial: netDial,
		config:  config,
	}
}

type tlsDialer struct {
	netDial dialer
	config  *tls.Config
}

type dialer func(ctx context.Context, network string, address string) (net.Conn, error)

// dial gets a connection throught the net dialer and then adds TLS to it.
func (t *tlsDialer) dial(ctx context.Context, network, addr string) (*tls.Conn, error) {
	rawConn, err := t.netDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if t.config.ServerName == "" {
		t.config.ServerName = hostname
	}

	conn := tls.Client(rawConn, t.config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}
