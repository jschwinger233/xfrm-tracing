package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"gopkg.in/yaml.v2"
)

var (
	pcapFilter string

	XfrmStatNames = make(map[uint8]string)
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event bpf bpf.c -- -I./headers

type XfrmIncContext struct {
	Address       uint64 `yaml:"address"`
	Register      string `yaml:"register"`
	XfrmStatIndex uint8  `yaml:"xfrm_stat_index"`
}

func main() {
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %s\n", err)
	}

	// Load KprobeXfrmStatisticsSeqShow
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)

	}

	// Get net->mib.xfrm_statistics
	kp, err := link.Kprobe("xfrm_statistics_seq_show", objs.KprobeXfrmStatisticsSeqShow, nil)
	if err != nil {
		log.Fatalf("Failed to attach xfrm_statistics_seq_show: %s\n", err)
	}
	triggerXfrmStatisticsSeqShow := make(chan struct{})
	go func() {
		<-triggerXfrmStatisticsSeqShow
		content, err := ioutil.ReadFile("/proc/net/xfrm_stat")
		if err != nil {
			log.Fatalf("Failed to read /proc/net/xfrm_stat: %s\n", err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		idx := uint8(0)
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) != 2 {
				continue
			}
			idx++
			XfrmStatNames[idx] = parts[0]
		}
	}()
	perfReader, err := perf.NewReader(objs.PerfOutput, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %s\n", err)
	}
	close(triggerXfrmStatisticsSeqShow)
	record, err := perfReader.Read()
	if err != nil {
		log.Fatalf("Failed to read perf event: %s\n", err)
	}
	var xfrmStatistics uint64
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &xfrmStatistics); err != nil {
		log.Fatalf("Failed to parse perf event: %s\n", err)
	}
	fmt.Printf("xfrmStatistics: %x\n", xfrmStatistics)
	kp.Close()
	objs.Close()

	// Rewrite config and reload
	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": struct {
			XfrmStatistics uint64
		}{
			XfrmStatistics: xfrmStatistics,
		},
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %s\n", err)
	}
	objs = bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)

	}

	// Attach kprobes
	fileContent, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to read file: %s\n", err)
	}
	xfrmIncCtx := []XfrmIncContext{}
	xfrmIncMap := make(map[uint64]XfrmIncContext)
	if err := yaml.Unmarshal(fileContent, &xfrmIncCtx); err != nil {
		log.Fatalf("Failed to unmarshal yaml: %s\n", err)
	}
	attachCnt := 0
	for _, xCtx := range xfrmIncCtx {
		objs.IncContext.Put(xCtx.Address, idxOfPtRegs(xCtx.Register))
		ksym, offset := addr2ksym(xCtx.Address)
		kp, err := link.Kprobe(ksym, objs.KprobeXfrmIncStats, &link.KprobeOptions{Offset: offset})
		if err != nil {
			fmt.Printf("Failed to attach %s: %s\n", ksym, err)
			continue
		}
		defer kp.Close()

		attachCnt++
		xfrmIncMap[xCtx.Address] = xCtx
	}
	fmt.Printf("Attached %d/%d kprobes\n", attachCnt, len(xfrmIncCtx))

	// Attach ip_rcv
	kp, err = link.Kprobe("ip_rcv", objs.KprobeIpRcv, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe to ip_rcv: %s\n", err)
	}
	defer kp.Close()
	krp, err := link.Kretprobe("ip_rcv", objs.KretprobeIpRcv, nil)
	if err != nil {
		log.Fatalf("Failed to attach kretprobe to ip_rcv: %s\n", err)
	}
	defer krp.Close()

	// Poll ringbuf events
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	println("tracing...")

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Printf("Failed to open ringbuf: %+v", err)
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Failed to read ringbuf: %+v", err)
			continue
		}

		var event bpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse ringbuf event: %+v", err)
			continue
		}

		xCtx, ok := xfrmIncMap[event.Pc]
		if !ok {
			log.Printf("Failed to find xfrm_inc_stats context for address: %x\n", event.Pc)
		}
		fmt.Printf("%s++: mark=%d if=%d %s\n",
			XfrmStatNames[xCtx.XfrmStatIndex],
			event.Mark,
			event.Ifindex,
			sprintfPacket(event.Payload[:]))

		var stack [50]uint64
		if err := objs.Stacks.Lookup(&event.StackId, &stack); err == nil {
			for _, ip := range stack {
				if ip > 0 {
					ksym, off := addr2ksym(ip)
					fmt.Printf("\t%s+%d\n", ksym, off)
				}
			}
		}
	}

}

func idxOfPtRegs(reg string) uint8 {
	switch reg {
	case "r15":
		return 0
	case "r14":
		return 1
	case "r13":
		return 2
	case "r12":
		return 3
	case "rbp":
		return 4
	case "rbx":
		return 5
	case "r11":
		return 6
	case "r10":
		return 7
	case "r9":
		return 8
	case "r8":
		return 9
	case "rax":
		return 10
	case "rcx":
		return 11
	case "rdx":
		return 12
	case "rsi":
		return 13
	case "rdi":
		return 14
	case "orig_rax":
		return 15
	case "rip":
		return 16
	case "cs":
		return 17
	case "eflags":
		return 18
	case "rsp":
		return 19
	case "ss":
		return 20
	}
	log.Fatalf("Unknown register: %s\n", reg)
	return 0
}

func addr2ksym(addr uint64) (ksym string, offset uint64) {
	sym := NearestSymbol(addr)
	return sym.Name, addr - sym.Addr
}

/*
Todo:
1. output ifname
2. output pcap file
3. output bt
4. translate xfrm_stat_index to name
5. monitor ip-xfrm and tc
6. test on eks
*/
