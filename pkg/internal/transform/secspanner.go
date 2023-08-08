package transform

import (
	"bytes"
	"time"

	"github.com/gavv/monotime"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/secexec"
)

type SecurityEvent struct {
	Op       string    `json:"operation"`
	Pid      uint32    `json:"pid"`
	Tid      uint32    `json:"tid"`
	Ppid     uint32    `json:"ppid"`
	UID      uint32    `json:"uid"`
	Auid     uint32    `json:"auid"`
	NsPid    uint32    `json:"namespaced_pid"`
	NsPpid   uint32    `json:"namespaced_ppid"`
	PidNsID  uint32    `json:"process_namespace_id"`
	EventTS  time.Time `json:"event_time"`
	CapEff   uint64    `json:"subjective_capabilities_effective"`
	CapInh   uint64    `json:"subjective_capabilities_inherited"`
	CapPerm  uint64    `json:"subjective_capabilities_permitted"`
	CgrpID   uint32    `json:"cgroup_id"`
	NetNs    uint32    `json:"network_namespace_id"`
	CgrpName string    `json:"cgroup_name"`
	Comm     string    `json:"command"`
	Filename string    `json:"filename"`
	Buf      string    `json:"payload"`
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
	}

	return "OP_UNKNOWN"
}

func toSecEvent(e *secexec.BPFSecEvent) SecurityEvent {
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
