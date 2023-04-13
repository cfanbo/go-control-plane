// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package example

import (
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
)

const (
	ClusterName  = "example_proxy_cluster"
	RouteName    = "sxf_local_route"
	ListenerName = "listener_0"
	ListenerPort = 10000
	UpstreamHost = "www.baidu.com"
	UpstreamPort = 80
)

func makeCluster2(clusterName string, upstreamHost string, upstreamPort uint32) *cluster.Cluster {
	sni := "blog.haohtml.com"
	tlsContext := &tlsv3.UpstreamTlsContext{
		//CommonTlsContext: &tlsv3.CommonTlsContext{
		//	TlsParams: &tlsv3.TlsParameters{
		//		CipherSuites: []string{
		//			"ECDHE-ECDSA-AES256-GCM-SHA384",
		//			"ECDHE-RSA-AES256-GCM-SHA384",
		//			"ECDHE-ECDSA-AES128-GCM-SHA256",
		//			"ECDHE-RSA-AES128-GCM-SHA256",
		//			"ECDHE-ECDSA-CHACHA20-POLY1305",
		//			"ECDHE-RSA-CHACHA20-POLY1305",
		//			"ECDHE-ECDSA-AES128-SHA",
		//			"ECDHE-RSA-AES128-SHA",
		//			"AES128-GCM-SHA256",
		//			"AES128-SHA",
		//			"ECDHE-ECDSA-AES256-SHA",
		//			"ECDHE-RSA-AES256-SHA",
		//			"AES256-GCM-SHA384",
		//			"AES256-SHA",
		//		},
		//		EcdhCurves: []string{
		//			"X25519",
		//			"P-256",
		//		},
		//	},
		//	ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
		//		ValidationContext: &tlsv3.CertificateValidationContext{
		//			TrustedCa: &core.DataSource{
		//				Specifier: &core.DataSource_EnvironmentVariable{EnvironmentVariable: "a"},
		//			},
		//			TrustChainVerification: tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED,
		//			MatchTypedSubjectAltNames: []*tlsv3.SubjectAltNameMatcher{
		//				{
		//					SanType: tlsv3.SubjectAltNameMatcher_DNS,
		//					Matcher: &matcherv3.StringMatcher{
		//						MatchPattern: &matcherv3.StringMatcher_Exact{
		//							Exact: sni,
		//						},
		//					},
		//				},
		//			},
		//		},
		//	},
		//	AlpnProtocols: []string{
		//		"h2",
		//		"http/1.1",
		//	},
		//},
		Sni: sni,
	}

	tlsConfig := new(anypb.Any)
	_ = anypb.MarshalFrom(tlsConfig, tlsContext, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})

	c := &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint2(clusterName, upstreamHost, upstreamPort),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
		TransportSocketMatches: []*cluster.Cluster_TransportSocketMatch{
			{
				Name:  "tls_name",
				Match: nil,
				TransportSocket: &core.TransportSocket{
					Name: "tls",
					ConfigType: &core.TransportSocket_TypedConfig{
						TypedConfig: tlsConfig,
					},
				},
			},
		},
	}
	if err := c.Validate(); err != nil {
		print(err)
	}

	return c
}

func makeCluster(clusterName string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint(clusterName),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func makeEndpoint(clusterName string) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  UpstreamHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: UpstreamPort,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeEndpoint2(clusterName, upstreamHost string, upstreamPort uint32) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  upstreamHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: upstreamPort,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeRoute(routeName string, clusterName string) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []*route.VirtualHost{{
			Name:    "local_service",
			Domains: []string{"*"},
			Routes: []*route.Route{{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: clusterName,
						},
						HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
							HostRewriteLiteral: UpstreamHost,
						},
					},
				},
			}},
		}},
	}
}

func makeRouteNew(name string, path string, clusterName string, upstreamHost string) *route.Route {
	return &route.Route{
		Name: name,
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: path,
			},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: clusterName,
				},
				HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
					HostRewriteLiteral: upstreamHost,
				},
			},
		},
	}
}

func makeVirtualHost(name string, domains []string, routes []*route.Route) *route.VirtualHost {
	return &route.VirtualHost{
		Name:    name,
		Domains: domains,
		Routes:  routes,
	}
}

func makeRouteConfiguration(name string, virtualHost []*route.VirtualHost) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHost,
	}
}

//
//func makeRoute2(routeName string, clusterName string, upstreamHost string) *route.RouteConfiguration {
//	return &route.RouteConfiguration{
//		Name: routeName,
//		VirtualHosts: []*route.VirtualHost{
//			{
//				Name:    "local_service_A",
//				Domains: []string{"a.test.cn:10000"},
//				Routes: []*route.Route{{
//					Match: &route.RouteMatch{
//						PathSpecifier: &route.RouteMatch_Prefix{
//							Prefix: "/",
//						},
//					},
//					Action: &route.Route_Route{
//						Route: &route.RouteAction{
//							ClusterSpecifier: &route.RouteAction_Cluster{
//								Cluster: clusterName,
//							},
//							HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
//								HostRewriteLiteral: upstreamHost,
//							},
//						},
//					},
//				},
//					{
//						Match: &route.RouteMatch{
//							PathSpecifier: &route.RouteMatch_Path{
//								Path: "/duty",
//							},
//						},
//						Action: &route.Route_Route{
//							Route: &route.RouteAction{
//								ClusterSpecifier: &route.RouteAction_Cluster{
//									Cluster: clusterName,
//								},
//								HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
//									HostRewriteLiteral: UpstreamHost,
//								},
//							},
//						},
//					},
//				},
//			},
//			{
//				Name:    "local_service_B",
//				Domains: []string{"b.test.cn:10000"},
//				Routes: []*route.Route{{
//					Match: &route.RouteMatch{
//						PathSpecifier: &route.RouteMatch_Prefix{
//							Prefix: "/",
//						},
//					},
//					Action: &route.Route_Route{
//						Route: &route.RouteAction{
//							ClusterSpecifier: &route.RouteAction_Cluster{
//								Cluster: clusterName,
//							},
//							HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
//								HostRewriteLiteral: UpstreamHost,
//							},
//						},
//					},
//				}},
//			},
//		},
//	}
//}

func makeHTTPListener(listenerName string, route string) *listener.Listener {
	routerConfig, _ := anypb.New(&router.Router{})
	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: route,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		}},
	}
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: ListenerPort,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

func GenerateSnapshot() *cache.Snapshot {
	var routes []*route.Route
	routes = append(routes, makeRouteNew("blog_root", "/", "blog", "blog.haohtml.com"))
	var vhosts []*route.VirtualHost
	vhosts = append(vhosts, makeVirtualHost("blog_vhost", []string{"c.test.cn:10000"}, routes))

	snap, _ := cache.NewSnapshot("1",
		map[resource.Type][]types.Resource{
			resource.ClusterType:  {makeCluster2("blog", "blog.haohtml.com", 443)},
			resource.RouteType:    {makeRouteConfiguration("blog_route_config", vhosts)}, //makeRoute(RouteName, ClusterName),
			resource.ListenerType: {makeHTTPListener(ListenerName, "blog_route_config")},
		},
	)
	return snap
}
