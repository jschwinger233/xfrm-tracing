package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

func monitorTc(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := monitor(ctx, []string{"tc", "monitor"}); err != nil {
		fmt.Printf("tc: %+v\n", err)
	}
}

func monitorIpX(ctx context.Context, wg *sync.WaitGroup) {
	policy, err := exec.Command("ip", "xfrm", "policy").Output()
	if err != nil {
		log.Fatalf("Failed to get policy: %v", err)
	}
	fmt.Printf("init policy: \n%s\n", string(policy))

	state, err := exec.Command("ip", "xfrm", "state").Output()
	if err != nil {
		log.Fatalf("Failed to get state: %v", err)
	}
	fmt.Printf("init state: \n%s\n", string(state))

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
		fmt.Printf("%s\t%s\n", time.Now().String(), scanner.Text())
	}
	return scanner.Err()
}
