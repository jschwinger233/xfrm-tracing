package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sync"
)

func monitorTc(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := monitor(ctx, []string{"tc", "monitor"}); err != nil {
		fmt.Printf("tc: %+v\n", err)
	}
}

func monitorIpX(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := monitor(ctx, []string{"ip", "xfrm", "monitor", "SA", "policy"}); err != nil {
		fmt.Printf("ip-xfrm: %+v\n", err)
	}
}

func monitor(ctx context.Context, cmd []string) (err error) {
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return
	}
	if err = command.Start(); err != nil {
		return
	}

	defer command.Wait()
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		fmt.Printf("%s\n", scanner.Text())
	}
	return scanner.Err()
}
