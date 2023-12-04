// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package transform

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/beyla/flows/transform/kubernetes"
	"github.com/grafana/beyla/pkg/beyla/flows/transform/netdb"
)

func log() *slog.Logger { return slog.With("component", "transform.Network") }

func Network(cfg *NetworkTransformConfig) (node.MiddleFunc[[]map[string]interface{}, []map[string]interface{}], error) {
	nt, err := newTransformNetwork(cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating network transformer: %w", err)
	}
	return func(in <-chan []map[string]interface{}, out chan<- []map[string]interface{}) {
		log().Debug("starting network transformation loop")
		for flows := range in {
			for _, flow := range flows {
				nt.transform(flow)
			}
			out <- flows
		}
		log().Debug("stopping network transformation loop")
	}, nil
}

type networkTransformer struct {
	kube     kubernetes.KubeData
	cfg      *NetworkTransformConfig
	svcNames *netdb.ServiceNames
}

func (n *networkTransformer) transform(outputEntry map[string]interface{}) {

	// TODO: for efficiency and maintainability, maybe each case in the switch below should be an individual implementation of Transformer
	for _, rule := range n.cfg.Rules {
		switch rule.Type {
		case "add_service":
			protocol := fmt.Sprintf("%v", outputEntry[rule.Parameters])
			portNumber, err := strconv.Atoi(fmt.Sprintf("%v", outputEntry[rule.Input]))
			if err != nil {
				log().Error("Can't convert port to int", "port", outputEntry[rule.Input], "error", err)
				continue
			}
			var serviceName string
			protocolAsNumber, err := strconv.Atoi(protocol)
			if err == nil {
				// protocol has been submitted as number
				serviceName = n.svcNames.ByPortAndProtocolNumber(portNumber, protocolAsNumber)
			} else {
				// protocol has been submitted as any string
				serviceName = n.svcNames.ByPortAndProtocolName(portNumber, protocol)
			}
			if serviceName == "" {
				if err != nil {
					log().Debug("Can't find service name for port and protocol",
						"port", outputEntry[rule.Input], "protocol", protocol, "error", err)
					continue
				}
			}
			outputEntry[rule.Output] = serviceName
		case "add_kubernetes":
			kubeInfo, err := n.kube.GetInfo(fmt.Sprintf("%s", outputEntry[rule.Input]))
			if err != nil {
				log().Debug("Can't find kubernetes info for IP", "ip", outputEntry[rule.Input], "error", err)
				continue
			}
			outputEntry[rule.Output+"_Namespace"] = kubeInfo.Namespace
			outputEntry[rule.Output+"_Name"] = kubeInfo.Name
			outputEntry[rule.Output+"_Type"] = kubeInfo.Type
			outputEntry[rule.Output+"_OwnerName"] = kubeInfo.Owner.Name
			outputEntry[rule.Output+"_OwnerType"] = kubeInfo.Owner.Type
			if rule.Parameters != "" {
				for labelKey, labelValue := range kubeInfo.Labels {
					outputEntry[rule.Parameters+"_"+labelKey] = labelValue
				}
			}
			if kubeInfo.HostIP != "" {
				outputEntry[rule.Output+"_HostIP"] = kubeInfo.HostIP
				if kubeInfo.HostName != "" {
					outputEntry[rule.Output+"_HostName"] = kubeInfo.HostName
				}
			}
		default:
			// TODO: this should be verified at instantiation time
			panic(fmt.Sprintf("unknown type %s for transform.Network rule: %v", rule.Type, rule))
		}
	}
}

// newTransformNetwork create a new transform
func newTransformNetwork(cfg *NetworkTransformConfig) (*networkTransformer, error) {
	nt := networkTransformer{cfg: cfg}
	err := nt.kube.InitFromConfig(cfg.KubeConfigPath)
	if err != nil {
		return nil, err
	}
	/*
		TODO: fix kubernetes failing because /etc/protocols not found

		pFilename, sFilename := cfg.GetServiceFiles()
		protos, err := os.Open(pFilename)
		if err != nil {
			return nil, fmt.Errorf("opening protocols file %q: %w", pFilename, err)
		}
		defer protos.Close()
		services, err := os.Open(sFilename)
		if err != nil {
			return nil, fmt.Errorf("opening services file %q: %w", sFilename, err)
		}
		defer services.Close()
		nt.svcNames, err = netdb.LoadServicesDB(protos, services)
		if err != nil {
			return nil, err
		}
	*/
	return &nt, nil
}