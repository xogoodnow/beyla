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

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/flow"
	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

const (
	listenPoll       = "poll"
	listenWatch      = "watch"
	directionIngress = "ingress"
	directionEgress  = "egress"
	directionBoth    = "both"

	ipTypeAny  = "any"
	ipTypeIPV4 = "ipv4"
	ipTypeIPV6 = "ipv6"

	ipIfaceExternal    = "external"
	ipIfaceLocal       = "local"
	ipIfaceNamedPrefix = "name:"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.Flows")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept flows.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

// Flows reporting agent
type Flows struct {
	cfg     *beyla.Config
	ctxInfo *global.ContextInfo

	// input data providers
	registerer *ifaces.Registerer
	filter     interfaceFilter
	ebpf       ebpfFlowFetcher

	// processing nodes to be wired in the buildPipeline method
	mapTracer *flow.MapTracer
	rbTracer  *flow.RingBufTracer

	// elements used to decorate flows with extra information
	interfaceNamer flow.InterfaceNamer
	agentIP        net.IP

	status Status
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer
	Register(iface ifaces.Interface) error

	LookupAndDeleteMap() map[ebpf.NetFlowId][]ebpf.NetFlowMetrics
	ReadRingBuf() (ringbuf.Record, error)
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(ctxInfo *global.ContextInfo, cfg *beyla.Config) (*Flows, error) {
	alog := alog()
	alog.Info("initializing Flows agent")

	// configure informer for new interfaces
	var informer ifaces.Informer
	switch cfg.NetworkFlows.ListenInterfaces {
	case listenPoll:
		alog.Debug("listening for new interfaces: use polling",
			"period", cfg.NetworkFlows.ListenPollPeriod)
		informer = ifaces.NewPoller(cfg.NetworkFlows.ListenPollPeriod, cfg.ChannelBufferLen)
	case listenWatch:
		alog.Debug("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.ChannelBufferLen)
	default:
		alog.Warn("wrong interface listen method. Using file watcher as default",
			"providedValue", cfg.NetworkFlows.ListenInterfaces)
		informer = ifaces.NewWatcher(cfg.ChannelBufferLen)
	}

	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(&cfg.NetworkFlows)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	var fetcher ebpfFlowFetcher

	switch cfg.NetworkFlows.Source {
	case beyla.EbpfSourceSock:
		alog.Info("using socket filter for collecting network events")
		fetcher, err = ebpf.NewSockFlowFetcher(cfg.NetworkFlows.Sampling, cfg.NetworkFlows.CacheMaxFlows)
		if err != nil {
			return nil, err
		}
	case beyla.EbpfSourceTC:
		alog.Info("using kernel Traffic Control for collecting network events")
		ingress, egress := flowDirections(&cfg.NetworkFlows)
		fetcher, err = ebpf.NewFlowFetcher(cfg.NetworkFlows.Sampling, cfg.NetworkFlows.CacheMaxFlows, ingress, egress)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown network configuration eBPF source specified, allowed options are [tc, socket_filter]")
	}

	return flowsAgent(ctxInfo, cfg, informer, fetcher, agentIP)
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(
	ctxInfo *global.ContextInfo,
	cfg *beyla.Config,
	informer ifaces.Informer,
	fetcher ebpfFlowFetcher,
	agentIP net.IP,
) (*Flows, error) {
	// configure allow/deny interfaces filter
	filter, err := initInterfaceFilter(cfg.NetworkFlows.Interfaces, cfg.NetworkFlows.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	registerer := ifaces.NewRegisterer(informer, cfg.ChannelBufferLen)

	interfaceNamer := func(ifIndex int) string {
		iface, ok := registerer.IfaceNameForIndex(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	mapTracer := flow.NewMapTracer(fetcher, cfg.NetworkFlows.CacheActiveTimeout)
	rbTracer := flow.NewRingBufTracer(fetcher, mapTracer, cfg.NetworkFlows.CacheActiveTimeout)
	return &Flows{
		ctxInfo:        ctxInfo,
		ebpf:           fetcher,
		registerer:     registerer,
		filter:         filter,
		cfg:            cfg,
		mapTracer:      mapTracer,
		rbTracer:       rbTracer,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
	}, nil
}

func flowDirections(cfg *beyla.NetworkConfig) (ingress, egress bool) {
	switch cfg.Direction {
	case directionIngress:
		return true, false
	case directionEgress:
		return false, true
	case directionBoth:
		return true, true
	default:
		alog().Warn("unknown DIRECTION. Tracing both ingress and egress traffic",
			"direction", cfg.Direction)
		return true, true
	}
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog := alog()
	f.status = StatusStarting
	alog.Info("starting Flows agent")
	graph, err := f.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	graph.Start()

	f.status = StatusStarted
	alog.Info("Flows agent successfully started")
	<-ctx.Done()

	f.status = StatusStopping
	alog.Info("stopping Flows agent")
	if err := f.ebpf.Close(); err != nil {
		alog.Warn("eBPF resources not correctly closed", "error", err)
	}

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()

	f.status = StatusStopped
	alog.Info("Flows agent stopped")
	return nil
}

func (f *Flows) Status() Status {
	return f.status
}

// interfacesManager uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
// TODO: consider move this method and "onInterfaceAdded" to another type
func (f *Flows) interfacesManager(ctx context.Context) error {
	slog := alog().With("function", "interfacesManager")

	ebpfcommon.StartTCMonitorLoop(ctx, f.registerer, f.onInterfaceAdded, slog)

	return nil
}

func (f *Flows) onInterfaceAdded(iface ifaces.Interface) {
	alog := alog().With("interface", iface)
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !f.filter.Allowed(iface.Name) {
		alog.Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	alog.Info("interface detected. Registering flow ebpfFetcher")
	if err := f.ebpf.Register(iface); err != nil {
		alog.Warn("can't register flow ebpfFetcher. Ignoring", "error", err)
		return
	}
}
