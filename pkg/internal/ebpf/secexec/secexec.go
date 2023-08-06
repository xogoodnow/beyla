package secexec

import (
	"context"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/exp/slog"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/exec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/goexec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/imetrics"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/sec_exec.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/sec_exec.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	Cfg        *ebpfcommon.TracerConfig
	Metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

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

func (p *Tracer) Syscalls() map[string]ebpfcommon.FunctionPrograms {
	return map[string]ebpfcommon.FunctionPrograms{
		"sys_enter_execve": {
			Start: p.bpfObjects.SyscallEnterExecve,
		},
		"sys_enter_execveat": {
			Start: p.bpfObjects.SyscallEnterExecveat,
		},
	}
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	kprobes := map[string]ebpfcommon.FunctionPrograms{
		"do_task_dead": {
			Required: true,
			Start:    p.bpfObjects.KprobeDoTaskDead,
		},
	}

	return kprobes
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []any) {
	ebpfcommon.ForwardRingbuf(
		p.Cfg, logger(), p.bpfObjects.Events, p.toRequestTrace,
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) toRequestTrace(_ *ringbuf.Record) (any, error) {
	return nil, nil
}
