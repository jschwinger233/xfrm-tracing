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
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/elastic/go-sysinfo"
	"gopkg.in/yaml.v2"
)

var (
	pcapFilter string

	XfrmStatNames = make(map[uint8]string)
)

const absoluteTS string = "15:04:05.000"

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

	// Generate if need
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if _, err := os.Stat(os.Args[1]); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Dumping xfrm_inc contexts to %s\n", os.Args[1])
		if err := dumpXfrmIncContexts(ctx, os.Args[1]); err != nil {
			log.Fatalf("Failed to dump xfrm_inc contexts: %s\n", err)
		}
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
		regIdx, err := idxOfPtRegs(xCtx.Register)
		if err != nil {
			fmt.Printf("Skip %+v: %+v\n", xCtx, err)
			continue
		}
		objs.IncContext.Put(xCtx.Address, regIdx)
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
	fmt.Printf("Attached %d/%d xfrm kprobes\n", attachCnt, len(xfrmIncCtx))

	// Attach kfree_skbmem
	kp, err = link.Kprobe("kfree_skbmem", objs.KprobeKfreeSkbmem, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe to kfree_skbmem: %s\n", err)
	}
	defer kp.Close()
	krp, err := link.Kretprobe("kfree_skbmem", objs.KretprobeKfreeSkbmem, nil)
	if err != nil {
		log.Fatalf("Failed to attach kretprobe to kfree_skbmem: %s\n", err)
	}
	defer krp.Close()

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}
	funcs, err := GetFuncs(btfSpec)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}
	delete(funcs, "kfree_skbmem")

	for fn, pos := range funcs {
		var kp link.Link
		switch pos {
		case 1:
			kp, err = link.Kprobe(fn, objs.KprobeSkb1, nil)
		case 2:
			kp, err = link.Kprobe(fn, objs.KprobeSkb2, nil)
		case 3:
			kp, err = link.Kprobe(fn, objs.KprobeSkb3, nil)
		case 4:
			kp, err = link.Kprobe(fn, objs.KprobeSkb4, nil)
		case 5:
			kp, err = link.Kprobe(fn, objs.KprobeSkb5, nil)
		}
		if err != nil {
			log.Printf("Failed to attach kprobe to %s: %+v\n", fn, err)
			continue
		}
		defer kp.Close()
	}
	fmt.Printf("Attached %d skb-accepting functions\n", len(funcs))

	println("tracing...")

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go monitorTc(ctx, wg)
	go monitorIpX(ctx, wg)

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Printf("Failed to open ringbuf: %+v", err)
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	host, err := sysinfo.Host()
	if err != nil {
		log.Fatalf("Failed to get host info: %s", err)
		return
	}
	bootTime := host.Info().BootTime

	events := map[uint64][]bpfEvent{}
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

		if event.XfrmIncStackId != 0 {
			for _, ev := range events[event.Skb] {
				fmt.Printf("%s %x %24s mark=0x%x if=%d(%s) proto=0x%x netns=%d len=%d %s\n",
					bootTime.Add(time.Duration(ev.Ts)).Format(absoluteTS),
					ev.Skb,
					Ksym(ev.Pc),
					ev.Mark,
					ev.Ifindex, ifname(ev.Ifindex),
					ev.Protocol,
					ev.Netns,
					ev.Len,
					sprintfPacket(ev.Payload[:]))
			}

			xCtx, ok := xfrmIncMap[event.Pc]
			if !ok {
				log.Printf("Failed to find xfrm_inc_stats context for address: %x\n", event.Pc)
			}
			fmt.Printf("%s %x %24s mark=0x%x if=%d(%s) proto=0x%x netns=%d len=%d %s\n",
				bootTime.Add(time.Duration(event.Ts)).Format(absoluteTS),
				event.Skb,
				"++"+XfrmStatNames[xCtx.XfrmStatIndex],
				event.Mark,
				event.Ifindex, ifname(event.Ifindex),
				event.Protocol,
				event.Netns,
				event.Len,
				sprintfPacket(event.Payload[:]))

			var stack [50]uint64
			if err := objs.Stacks.Lookup(&event.XfrmIncStackId, &stack); err == nil {
				for _, ip := range stack {
					if ip > 0 {
						ksym, off := addr2ksym(ip)
						fmt.Printf("\t%s+%d\n", ksym, off)
					}
				}
			}
			delete(events, event.Skb)
		} else if Ksym(event.Pc) == "kfree_skbmem" {
			delete(events, event.Skb)
		} else {
			events[event.Skb] = append(events[event.Skb], event)
		}
	}

	wg.Wait()
}
