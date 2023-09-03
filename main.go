package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"gopkg.in/yaml.v2"
)

var (
	pcapFilter string

	pwruBuf     = make(map[string][]string)
	skbConsumed = make(map[string]bool)
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf bpf.c -- -I./headers

type XfrmIncContext struct {
	Address       uint64 `yaml:"address"`
	Register      string `yaml:"register"`
	XfrmStatIndex uint8  `yaml:"xfrm_stat_index"`
}

func main() {
	objs := bpfObjects{}
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	if err := loadBpfObjects(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)

	}
	defer objs.Close()

	// Get net->mib.xfrm_statistics
	kp, err := link.Kprobe("xfrm_statistics_seq_show", objs.KprobeXfrmStatisticsSeqShow, nil)
	if err != nil {
		log.Fatalf("Failed to attach xfrm_statistics_seq_show: %s\n", err)
	}
	triggerXfrmStatisticsSeqShow := make(chan struct{})
	go func() {
		<-triggerXfrmStatisticsSeqShow
		ioutil.ReadFile("/proc/net/xfrm_stat")
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

	_s := make(chan os.Signal, 1)
	signal.Notify(_s, os.Interrupt, os.Kill)
	<-_s

	return

	fileContent, err := ioutil.ReadFile("xfrm_inc_kprobe.yaml")
	if err != nil {
		log.Fatalf("Failed to read file: %s\n", err)
	}

	xfrmIncCtx := []XfrmIncContext{}
	if err := yaml.Unmarshal(fileContent, &objs.SavedXfrmMib); err != nil {
		log.Fatalf("Failed to unmarshal yaml: %s\n", err)
	}

	for _, ctx := range xfrmIncCtx {
		objs.IncContext.Put(ctx.Address, idxOfPtRegs(ctx.Register))
		ksym, offset := addr2ksym(ctx.Address)
		kp, err := link.Kprobe(ksym, objs.KprobeXfrmIncStats, &link.KprobeOptions{Offset: offset})
		if err != nil {
			log.Fatalf("Failed to attach %s: %s\n", ksym, err)
		}
		defer kp.Close()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	println("tracing...")
	<-sigs
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
