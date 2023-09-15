package main

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

var Pat *regexp.Regexp
var Tmpl string

func init() {
	Pat = regexp.MustCompile(`0x(?P<address>[0-9a-f]+):\s+incq\s+%gs:0x(?P<offset>[0-9a-f]+)\(%(?P<reg>[a-z]+)\)`)

	Tmpl = `
- address: %d # 0x%x
  register: %s
  xfrm_stat_index: %d # 0x%x`
}

func dumpXfrmIncContexts(ctx context.Context, filename string) (err error) {
	bin, err := os.Open("/proc/kcore")
	if err != nil {
		return
	}
	defer bin.Close()
	elfFile, err := elf.NewFile(bin)
	if err != nil {
		return
	}
	ranges := map[*elf.Prog][2]uint64{}
	for _, ksym := range kallsyms {
		if ksym.Type != "t" {
			continue
		}
		for _, prog := range elfFile.Progs {
			if prog.Vaddr <= ksym.Addr && prog.Vaddr+prog.Memsz >= ksym.Addr {
				r, ok := ranges[prog]
				if !ok {
					ranges[prog] = [2]uint64{ksym.Addr, ksym.Addr + 10000}
				} else if r[0] > ksym.Addr {
					ranges[prog] = [2]uint64{ksym.Addr, r[1]}
				} else if r[1] < ksym.Addr+10000 {
					ranges[prog] = [2]uint64{r[0], ksym.Addr + 10000}
				}
				break
			}
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	for prog, r := range ranges {
		bytes := make([]byte, r[1]-r[0])
		if _, err = bin.ReadAt(bytes, int64(prog.Off+r[0]-prog.Vaddr)); err != nil {
			return
		}
		offset := uint64(0)
		for {
			inst, err := x86asm.Decode(bytes, 64)
			if err != nil {
				inst = x86asm.Inst{Len: 1}
			}

			if x86asm.Prefix(bytes[0]) == x86asm.PrefixGS && inst.Op == x86asm.INC {
				mem, ok := inst.Args[0].(x86asm.Mem)
				if ok && mem.Disp/8*8 == mem.Disp && mem.Disp > 0 && mem.Disp <= 28*8 {
					addr := r[0] + offset
					reg := strings.ToLower(mem.Base.String())
					fmt.Fprintf(file, Tmpl, addr, addr, reg, mem.Disp/8, mem.Disp)
				}
			}
			bytes = bytes[inst.Len:]
			offset += uint64(inst.Len)
			if len(bytes) == 0 {
				break
			}
		}

	}

	return
}
