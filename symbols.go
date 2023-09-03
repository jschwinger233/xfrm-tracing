package main

import (
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

type Symbol struct {
	Name string
	Addr uint64
}

var kallsyms []Symbol
var kallsymsByName map[string]Symbol = make(map[string]Symbol)

func init() {
	readKallsyms()
}

func readKallsyms() {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		name := parts[2]
		kallsyms = append(kallsyms, Symbol{name, addr})
		kallsymsByName[name] = Symbol{name, addr}
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func RefreshKallsyms() {
	readKallsyms()
}

func NearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx]
	}
	return kallsyms[idx-1]
}

func Kaddr(sym string) uint64 {
	return kallsymsByName[sym].Addr
}
