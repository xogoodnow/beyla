// Package debug provides some export nodes that are aimed basically at debugging/testing
package sec

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/gavv/monotime"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/transform"
)

type SecurityEnabled bool

func (p SecurityEnabled) Enabled() bool {
	return bool(p)
}

func LoggerNode(_ context.Context, _ SecurityEnabled) (node.TerminalFunc[[]transform.SecurityEvent], error) {
	return func(input <-chan []transform.SecurityEvent) {
		for events := range input {
			for i := range events {
				e := events[i]
				now := time.Now()
				monoNow := monotime.Now()
				tsDelta := monoNow - time.Duration(e.Meta.TimeNs)

				commLen := bytes.IndexByte(e.Meta.Comm[:], 0)
				if commLen < 0 {
					commLen = len(e.Meta.Comm)
				}
				fmt.Printf("%s comm=[%s]\n",
					(now.Add(-tsDelta)).Format("2006-01-02 15:04:05.12345"),
					string(e.Meta.Comm[:commLen]),
				)
			}
		}
	}, nil
}
