package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/btf"
)

func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func GetFuncs(spec *btf.Spec) (map[string]int, error) {
	funcs := map[string]int{}

	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", spec.Iterate()}}

	for _, it := range iters {
		for it.iter.Next() {
			typ := it.iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			availableFnName := fnName
			if it.kmod != "" {
				availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
			}
			if _, ok := availableFuncs[availableFnName]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i <= 5 {
							name := fnName
							funcs[name] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}

func idxOfPtRegs(reg string) (uint8, error) {
	switch reg {
	case "r15":
		return 0, nil
	case "r14":
		return 1, nil
	case "r13":
		return 2, nil
	case "r12":
		return 3, nil
	case "rbp":
		return 4, nil
	case "rbx":
		return 5, nil
	case "r11":
		return 6, nil
	case "r10":
		return 7, nil
	case "r9":
		return 8, nil
	case "r8":
		return 9, nil
	case "rax":
		return 10, nil
	case "rcx":
		return 11, nil
	case "rdx":
		return 12, nil
	case "rsi":
		return 13, nil
	case "rdi":
		return 14, nil
	case "orig_rax":
		return 15, nil
	case "rip":
		return 16, nil
	case "cs":
		return 17, nil
	case "eflags":
		return 18, nil
	case "rsp":
		return 19, nil
	case "ss":
		return 20, nil
	}
	return 0, fmt.Errorf("Unknown register: %s", reg)
}

func addr2ksym(addr uint64) (ksym string, offset uint64) {
	sym := NearestSymbol(addr)
	return sym.Name, addr - sym.Addr
}

func ifname(ifindex uint32) string {
	ifname := "unknown"
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err == nil {
		ifname = iface.Name
	}
	return ifname
}
