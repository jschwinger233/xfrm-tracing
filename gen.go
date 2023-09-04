package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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
	start, last := FirstKsym().Addr, LastKsym().Addr
	gdbcmd := fmt.Sprintf("x/%di %d", last-start, start)
	command := exec.CommandContext(ctx, "gdb", "-ex", gdbcmd, "-ex", "q", "/proc/kcore", "/proc/kcore")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return
	}
	if err = command.Start(); err != nil {
		return
	}
	defer command.Wait()

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		matches := Pat.FindStringSubmatch(scanner.Text())
		if len(matches) == 0 {
			continue
		}
		address := matches[Pat.SubexpIndex("address")]
		offset := matches[Pat.SubexpIndex("offset")]
		reg := matches[Pat.SubexpIndex("reg")]
		addr, err := strconv.ParseUint(address, 16, 64)
		if err != nil {
			log.Fatalf("Failed to parse address %s: %v", address, err)
		}
		off, err := strconv.ParseUint(offset, 16, 64)
		if err != nil {
			log.Fatalf("Failed to parse offset %s: %v", offset, err)
		}
		if off/8*8 != off || off > 28*8 {
			continue
		}
		fmt.Fprintf(file, Tmpl, addr, addr, reg, off/8, off)
	}
	return scanner.Err()
}
