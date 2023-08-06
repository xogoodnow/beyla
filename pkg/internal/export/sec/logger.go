// Package debug provides some export nodes that are aimed basically at debugging/testing
package sec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/transform"
)

type SecurityEnabled bool

func (p SecurityEnabled) Enabled() bool {
	return bool(p)
}

var log = slog.With("component", "sec.logger")

func LoggerNode(_ context.Context, _ SecurityEnabled) (node.TerminalFunc[[]transform.SecurityEvent], error) {
	return func(input <-chan []transform.SecurityEvent) {

		file, err := os.OpenFile("/var/log/beyla_sec.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error("Error opening log file:", err)
			return
		}
		defer file.Close()

		for events := range input {
			for i := range events {
				e := events[i]
				jsonBytes, err := json.Marshal(e)
				if err != nil {
					log.Error("Error encoding JSON:", err)
					return
				}

				jsonBytes = append(jsonBytes, '\n')

				fmt.Printf("%s\n", jsonBytes)
				if _, err := file.Write(jsonBytes); err != nil {
					log.Error("Error writing to log file:", err)
					return
				}
			}
		}
	}, nil
}
