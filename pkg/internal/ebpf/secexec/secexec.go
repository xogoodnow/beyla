package secexec

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/exp/slog"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/exec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/goexec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/imetrics"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type sec_event -target amd64,arm64 bpf ../../../../bpf/sec_exec.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type sec_event -target amd64,arm64 bpf_debug ../../../../bpf/sec_exec.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	Cfg        *ebpfcommon.TracerConfig
	Metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

type BPFSecEvent bpfSecEvent

func logger() *slog.Logger {
	return slog.With("component", "secexec.Tracer")
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.Cfg.BpfDebug {
		loader = loadBpf_debug
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	return nil
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	/*return map[string]ebpfcommon.FunctionPrograms{
		"sys_enter_execve": {
			Type:  "syscalls",
			Start: p.bpfObjects.SyscallEnterExecve,
		},
		"sys_enter_execveat": {
			Type:  "syscalls",
			Start: p.bpfObjects.SyscallEnterExecveat,
		},
	}*/

	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	kprobes := map[string]ebpfcommon.FunctionPrograms{
		"do_task_dead": {
			Required: true,
			Start:    p.bpfObjects.KprobeDoTaskDead,
		},
		"wake_up_new_task": {
			Required: true,
			Start:    p.bpfObjects.KprobeWakeUpNewTask,
		},
		"sys_execve": {
			Required: true,
			Start:    p.bpfObjects.KprobeSysExecve,
		},
		"sys_execveat": {
			Required: true,
			Start:    p.bpfObjects.KprobeSysExecveat,
		},
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sys_rename": {
			Required: true,
			End:      p.bpfObjects.KprobeSysRename,
		},
		"sys_renameat": {
			Required: true,
			End:      p.bpfObjects.KprobeSysRenameat,
		},
		"sys_unlink": {
			Required: true,
			End:      p.bpfObjects.KprobeSysUnlink,
		},
		"sys_unlinkat": {
			Required: true,
			End:      p.bpfObjects.KprobeSysUnlinkat,
		},
		"sock_alloc": {
			Required: true,
			End:      p.bpfObjects.KretprobeSockAlloc,
		},
		"tcp_rcv_established": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRcvEstablished,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysConnect,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpConnect,
		},
	}

	return kprobes
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.SocketHttpFilter}
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []any) {
	ebpfcommon.ForwardRingbuf(
		p.Cfg, logger(), p.bpfObjects.Events, p.toSecEvent,
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) toSecEvent(record *ringbuf.Record) (any, error) {
	var event BPFSecEvent

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return event, err
	}

	return event, nil
}
