package transform

import (
	"bytes"
	"net"
	"time"

	"github.com/gavv/monotime"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/secexec"
)

type SecurityEvent struct {
	Op         string    `json:"operation"`
	Pid        uint32    `json:"pid"`
	Tid        uint32    `json:"tid"`
	Ppid       uint32    `json:"ppid"`
	UID        uint32    `json:"uid"`
	Auid       uint32    `json:"auid"`
	NsPid      uint32    `json:"namespaced_pid"`
	NsPpid     uint32    `json:"namespaced_ppid"`
	PidNsID    uint32    `json:"process_namespace_id"`
	EventTS    time.Time `json:"event_time"`
	CapEff     uint64    `json:"subjective_capabilities_effective"`
	CapInh     uint64    `json:"subjective_capabilities_inherited"`
	CapPerm    uint64    `json:"subjective_capabilities_permitted"`
	CgrpID     uint32    `json:"cgroup_id"`
	NetNs      uint32    `json:"network_namespace_id"`
	CgrpName   string    `json:"cgroup_name"`
	Comm       string    `json:"command"`
	Filename   string    `json:"filename"`
	Buf        string    `json:"payload"`
	Type       int       `json:"protocol"`
	LocalIP    string    `json:"local_ip"`
	LocalPort  uint32    `json:"local_port"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort uint32    `json:"remote_port"`
}

func ReadSecurityEvent(in <-chan []interface{}, out chan<- []SecurityEvent) {
	for traces := range in {
		spans := make([]SecurityEvent, 0, len(traces))
		for i := range traces {
			v := traces[i]

			switch t := v.(type) {
			case secexec.BPFSecEvent:
				spans = append(spans, toSecEvent(&t))
			}
		}
		out <- spans
	}
}

func cStrToString(b []byte) string {
	l := bytes.IndexByte(b[:], 0)
	if l < 0 {
		l = len(b)
	}

	return string(b[:l])
}

func opName(op uint8) string {
	switch op {
	case 1:
		return "OP_EXECVE"
	case 2:
		return "OP_EXECVEAT"
	case 3:
		return "OP_PROG_EXIT"
	case 4:
		return "OP_NET_SERVER"
	case 5:
		return "OP_NET_CLIENT"
	case 6:
		return "OP_FORK"
	case 7:
		return "OP_RENAME"
	case 8:
		return "OP_RENAMEAT"
	case 9:
		return "UNLINK"
	case 10:
		return "UNLINKAT"
	case 11:
		return "OP_CREAT"
	case 12:
		return "OP_OPEN"
	case 13:
		return "OP_OPENAT"
	}

	return "OP_UNKNOWN"
}

func toSecEvent(e *secexec.BPFSecEvent) SecurityEvent {

	if e.Meta.Op == 4 || e.Meta.Op == 5 {
		return toSecNetEvent(e)
	}

	now := time.Now()
	monoNow := monotime.Now()
	tsDelta := monoNow - time.Duration(e.Meta.TimeNs)

	r := SecurityEvent{
		Op:       opName(e.Meta.Op),
		Pid:      e.Meta.Pid,
		Tid:      e.Meta.Tid,
		Ppid:     e.Meta.Ppid,
		UID:      e.Meta.Uid,
		Auid:     e.Meta.Auid,
		NsPid:    e.Meta.NsPid,
		NsPpid:   e.Meta.NsPpid,
		PidNsID:  e.Meta.PidNsId,
		EventTS:  now.Add(-tsDelta),
		CapEff:   e.Meta.CapEff,
		CapInh:   e.Meta.CapInh,
		CapPerm:  e.Meta.CapPerm,
		CgrpID:   e.Meta.CgrpId,
		NetNs:    e.Meta.NetNs,
		CgrpName: cStrToString(e.Meta.CgrpName[:]),
		Comm:     cStrToString(e.Meta.Comm[:]),
		Filename: cStrToString(e.Filename[:]),
		Buf:      cStrToString(e.Buf[:]),
	}

	return r
}

func toSecNetEvent(e *secexec.BPFSecEvent) SecurityEvent {
	now := time.Now()
	monoNow := monotime.Now()
	tsDelta := monoNow - time.Duration(e.Meta.TimeNs)

	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, e.Conn.S_addr[:])
	copy(dst, e.Conn.D_addr[:])
	srcPort := e.Conn.S_port
	dstPort := e.Conn.D_port

	if (e.Meta.Op == 4 && dstPort > srcPort) ||
		(e.Meta.Op == 5 && srcPort < dstPort) { // server call but we sorted the ips
		tmp := src
		src = dst
		dst = tmp

		tmpP := srcPort
		srcPort = dstPort
		dstPort = tmpP
	}

	r := SecurityEvent{
		Op:         opName(e.Meta.Op),
		Pid:        e.Meta.Pid,
		Tid:        e.Meta.Tid,
		Ppid:       e.Meta.Ppid,
		UID:        e.Meta.Uid,
		Auid:       e.Meta.Auid,
		NsPid:      e.Meta.NsPid,
		NsPpid:     e.Meta.NsPpid,
		PidNsID:    e.Meta.PidNsId,
		EventTS:    now.Add(-tsDelta),
		CapEff:     e.Meta.CapEff,
		CapInh:     e.Meta.CapInh,
		CapPerm:    e.Meta.CapPerm,
		CgrpID:     e.Meta.CgrpId,
		NetNs:      e.Meta.NetNs,
		CgrpName:   cStrToString(e.Meta.CgrpName[:]),
		Comm:       cStrToString(e.Meta.Comm[:]),
		Type:       int(e.Type),
		LocalIP:    src.String(),
		RemoteIP:   dst.String(),
		LocalPort:  uint32(srcPort),
		RemotePort: uint32(dstPort),
	}

	return r
}
