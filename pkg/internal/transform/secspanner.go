package transform

import (
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/secexec"
)

type SecurityEvent secexec.BPFSecEvent

func ReadSecurityEvent(in <-chan []interface{}, out chan<- []SecurityEvent) {
	for traces := range in {
		spans := make([]SecurityEvent, 0, len(traces))
		for i := range traces {
			v := traces[i]

			switch t := v.(type) {
			case secexec.BPFSecEvent:
				spans = append(spans, (SecurityEvent)(t))
			}
		}
		out <- spans
	}
}
